// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <kernel/bitcoinkernel_wrapper.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/fs.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <vector>

namespace {

std::string RandomSuffix()
{
    const std::string chars{"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    static std::random_device rd;
    static std::default_random_engine dre{rd()};
    static std::uniform_int_distribution<> distribution(0, static_cast<int>(chars.size() - 1));
    std::string out;
    out.reserve(16);
    for (int i{0}; i < 16; ++i) {
        out += chars[distribution(dre)];
    }
    return out;
}

struct TestDirectory {
    fs::path m_directory;
    explicit TestDirectory(std::string directory_name)
        : m_directory{fs::path{fs::temp_directory_path()} / fs::u8path(directory_name + "_" + RandomSuffix())}
    {
        fs::create_directories(m_directory);
    }
    ~TestDirectory() { fs::remove_all(m_directory); }
};

class TestKernelNotifications : public btck::KernelNotifications
{
public:
    void HeaderTipHandler(btck::SynchronizationState, int64_t, int64_t timestamp, bool) override
    {
        BOOST_CHECK_GT(timestamp, 0);
    }
};

class CaptureValidationInterface : public btck::ValidationInterface
{
public:
    std::optional<btck::ValidationMode> m_mode;
    std::optional<btck::BlockValidationResult> m_result;

    void BlockChecked(btck::Block, btck::BlockValidationStateView state) override
    {
        m_mode = state.GetValidationMode();
        m_result = state.GetBlockValidationResult();
    }
};

btck::Context CreateRegtestContext(std::shared_ptr<TestKernelNotifications> notifications,
                                   std::shared_ptr<CaptureValidationInterface> validation_interface = nullptr)
{
    btck::ContextOptions options{};
    btck::ChainParams params{btck::ChainType::REGTEST};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    if (validation_interface) {
        options.SetValidationInterface(validation_interface);
    }
    return btck::Context{options};
}

CBlockHeader MineRegtestHeader(const uint256& prev_hash, uint32_t n_time, uint32_t n_bits, const Consensus::Params& consensus)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256{};
    header.nTime = n_time;
    header.nBits = n_bits;
    header.nNonce = 0;
    while (!CheckProofOfWork(header.GetHash(), header.nBits, consensus)) {
        ++header.nNonce;
    }
    return header;
}

btck::BlockHeader ToKernelHeader(const CBlockHeader& header)
{
    DataStream ss{};
    ss << header;
    return btck::BlockHeader{std::span<const std::byte>{ss.data(), ss.size()}};
}

void RequireKernelHeader(btck::ChainMan& chainman, const CBlockHeader& header)
{
    const btck::BlockValidationState state{chainman.ProcessBlockHeader(ToKernelHeader(header))};
    BOOST_REQUIRE(state.GetValidationMode() == btck::ValidationMode::VALID);
    BOOST_REQUIRE(state.GetBlockValidationResult() == btck::BlockValidationResult::UNSET);
}

std::unique_ptr<btck::ChainMan> CreateChainMan(TestDirectory& test_directory, btck::Context& context)
{
    btck::ChainstateManagerOptions chainman_opts{context, PathToString(test_directory.m_directory), PathToString(test_directory.m_directory / "blocks")};
    chainman_opts.UpdateChainstateDbInMemory(true);
    return std::make_unique<btck::ChainMan>(context, chainman_opts);
}

std::vector<std::byte> ScriptBytes(const CScript& script)
{
    std::vector<std::byte> out(script.size());
    std::transform(script.begin(), script.end(), out.begin(), [](uint8_t c) { return std::byte{c}; });
    return out;
}

class FixedCoinFetcher : public btck::CoinFetcher
{
    btck::ScriptPubkey m_script;
    int64_t m_amount;
    uint32_t m_height;

public:
    FixedCoinFetcher(btck::ScriptPubkey script, int64_t amount, uint32_t height)
        : m_script{std::move(script)}, m_amount{amount}, m_height{height} {}

    std::optional<btck::Coin> FetchCoin(btck::OutPointView) override
    {
        btck::TransactionOutput output{m_script, m_amount};
        return btck::Coin{output, m_height, /*is_coinbase=*/false};
    }
};

bool InputsFailedLegacySigops(const TxValidationState& state, bool inputs_ok)
{
    return !inputs_ok && state.GetResult() == TxValidationResult::TX_CONSENSUS && state.GetRejectReason() == "bad-txns-legacy-sigops";
}

/** Dual channel. CheckSigopsBIP54 is false iff enforcing CheckTxInputs fails with bad-txns-legacy-sigops. */
void CheckViewSigops(const CTransaction& tx, const CScript& script_pubkey, const COutPoint& prevout, CAmount value, int spend_height, bool expect_within_limit)
{
    CCoinsViewCache view{&CoinsViewEmpty::Get()};
    view.AddCoin(prevout, ::Coin{{value, script_pubkey}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false}, /*possible_overwrite=*/false);

    const bool sigops_ok{Consensus::CheckSigopsBIP54(tx, view)};
    BOOST_CHECK_EQUAL(sigops_ok, expect_within_limit);

    TxValidationState state;
    CAmount txfee{0};
    const bool inputs_ok{Consensus::CheckTxInputs(tx, state, view, spend_height, txfee, /*enforce_bip54=*/true)};
    BOOST_REQUIRE_EQUAL(sigops_ok, !InputsFailedLegacySigops(state, inputs_ok));
    BOOST_CHECK_EQUAL(inputs_ok, expect_within_limit);
}

void CheckKernelAgrees(bool view_within_limit, bool kernel_ok, btck::BlockValidationResult kernel_result)
{
    const bool kernel_consensus_reject{!kernel_ok && kernel_result == btck::BlockValidationResult::CONSENSUS};
    if (!view_within_limit) {
        BOOST_REQUIRE_MESSAGE(kernel_consensus_reject, "View rejects BIP54 sigops but validate_block accepted. enforce_bip54 missing on the kernel path.");
    } else {
        BOOST_REQUIRE_MESSAGE(kernel_ok && kernel_result == btck::BlockValidationResult::UNSET,
                              "View accepts BIP54 sigops but validate_block rejected. kernel_result=" + std::to_string(static_cast<uint32_t>(kernel_result)));
    }
}

CBlock MinedCoinbaseBlock(const uint256& prev_hash, uint32_t n_time, uint32_t n_bits, int height,
                          uint32_t n_lock_time, uint32_t n_sequence, const CScript& script_pub_key,
                          const Consensus::Params& consensus)
{
    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = prev_hash;
    block.nTime = n_time;
    block.nBits = n_bits;
    block.nNonce = 0;

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    // BIP34 height prefix. Pad so coinbase stays off BIP54's exact 64-byte ban
    // (height<<OP_0 is 63 bytes for heights 1-16, then 64 from height 17).
    coinbase.vin[0].scriptSig = CScript() << height << OP_0 << OP_0 << OP_0;
    coinbase.vin[0].nSequence = n_sequence;
    coinbase.vout.emplace_back(50 * COIN, script_pub_key);
    coinbase.nLockTime = n_lock_time;

    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
        ++block.nNonce;
    }
    return block;
}

btck::Block ToKernelBlock(const CBlock& block)
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(block);
    return btck::Block{std::span<const std::byte>{ss.data(), ss.size()}};
}

} // namespace

BOOST_AUTO_TEST_CASE(btck_validate_block_bip54_sigops_follow_coin)
{
    const COutPoint prevout{Txid::FromUint256(uint256::ONE), 0};
    const CAmount value{1 * COIN};
    constexpr int spend_height{1};

    CScript bomb;
    for (unsigned i{0}; i < MAX_TX_BIP54_SIGOPS + 1; ++i) {
        bomb << OP_CHECKSIG;
    }
    // OP_TRUE is 0 sigops and leaves true on the stack. Empty scriptPubKey is 0
    // sigops too but script execution fails. validate_block runs scripts.
    const CScript under_limit{CScript() << OP_TRUE};

    CMutableTransaction spend;
    spend.vin.emplace_back(prevout);
    spend.vout.emplace_back(value - 1000, CScript() << OP_TRUE);
    const CTransaction spend_tx{spend};
    BOOST_REQUIRE(!spend_tx.IsCoinBase());

    auto test_directory{TestDirectory{"bip54_fetchcoin_test_bitcoin_kernel"}};
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{CreateRegtestContext(notifications)};
    auto chainman{CreateChainMan(test_directory, context)};

    const auto genesis{chainman->GetChain().GetByHeight(0)};
    const auto prev_bytes{genesis.GetHash().ToBytes()};
    uint256 prev_hash;
    std::memcpy(prev_hash.begin(), prev_bytes.data(), prev_bytes.size());

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = prev_hash;
    block.nTime = genesis.GetHeader().Timestamp() + 600;
    block.nBits = genesis.GetHeader().Bits();
    block.nNonce = 0;

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    // BIP34 height prefix. Extra byte so scriptSig size is at least 2 (bad-cb-length).
    coinbase.vin[0].scriptSig = CScript() << spend_height << OP_0;
    coinbase.vin[0].nSequence = 0;
    coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    coinbase.nLockTime = static_cast<uint32_t>(spend_height - 1);

    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.vtx.push_back(MakeTransactionRef(spend_tx));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const auto params{CChainParams::RegTest()};
    while (!CheckProofOfWork(block.GetHash(), block.nBits, params->GetConsensus())) {
        ++block.nNonce;
    }

    DataStream ss{};
    ss << TX_WITH_WITNESS(block);
    btck::Block kblock{std::span<const std::byte>{ss.data(), ss.size()}};

    const btck::BlockValidationState header_state{chainman->ProcessBlockHeader(kblock.GetHeader())};
    BOOST_REQUIRE(header_state.GetValidationMode() == btck::ValidationMode::VALID);
    const btck::BlockTreeEntry entry{*chainman->GetBlockTreeEntry(kblock.GetHash())};

    const int64_t kernel_value{value};
    FixedCoinFetcher fetcher_a{btck::ScriptPubkey{ScriptBytes(bomb)}, kernel_value, /*height=*/1};
    FixedCoinFetcher fetcher_b{btck::ScriptPubkey{ScriptBytes(under_limit)}, kernel_value, /*height=*/1};

    CheckViewSigops(spend_tx, under_limit, prevout, value, spend_height, /*expect_within_limit=*/true);
    btck::BlockValidationState state_b;
    const bool ok_b{chainman->ValidateBlock(kblock, entry, fetcher_b, state_b)};
    CheckKernelAgrees(/*view_within_limit=*/true, ok_b, state_b.GetBlockValidationResult());

    CheckViewSigops(spend_tx, bomb, prevout, value, spend_height, /*expect_within_limit=*/false);
    btck::BlockValidationState state_a;
    const bool ok_a{chainman->ValidateBlock(kblock, entry, fetcher_a, state_a)};
    CheckKernelAgrees(/*view_within_limit=*/false, ok_a, state_a.GetBlockValidationResult());
}

/**
 * BIP54 doors on the kernel C API. Block::Check is CheckBlock (context free) and accepts a 64 byte tx.
 * ProcessBlock runs ContextualCheckBlock and rejects size 64. ProcessBlockHeader enforces timewarp
 * at prev minus MAX_TIMEWARP_BIP54. Equality passes. One second earlier is INVALID_HEADER.
 */
BOOST_AUTO_TEST_CASE(btck_process_block_bip54_doors)
{
    const auto params{CChainParams::RegTest()};
    const auto& consensus{params->GetConsensus()};
    const CBlock& genesis{params->GenesisBlock()};
    const int dai{static_cast<int>(consensus.DifficultyAdjustmentInterval())};
    BOOST_REQUIRE_EQUAL(dai, 144);
    BOOST_REQUIRE(consensus.fPowNoRetargeting);

    CMutableTransaction tx64;
    tx64.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx64.vout.emplace_back(0, CScript{} << OP_0 << OP_1 << OP_2 << OP_4);
    BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(tx64)), INVALID_TX_NONWITNESS_SIZE);

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = genesis.GetHash();
    block.nTime = genesis.nTime + 600;
    block.nBits = genesis.nBits;
    block.nNonce = 0;

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase.vin[0].nSequence = 0;
    coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    coinbase.nLockTime = 0;

    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.vtx.push_back(MakeTransactionRef(tx64));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
        ++block.nNonce;
    }

    DataStream ss{};
    ss << TX_WITH_WITNESS(block);
    btck::Block kblock{std::span<const std::byte>{ss.data(), ss.size()}};

    {
        auto test_directory{TestDirectory{"bip54_process_block_txsize"}};
        auto notifications{std::make_shared<TestKernelNotifications>()};
        auto capture{std::make_shared<CaptureValidationInterface>()};
        auto context{CreateRegtestContext(notifications, capture)};
        auto chainman{CreateChainMan(test_directory, context)};

        btck::ChainParams kparams{btck::ChainType::REGTEST};
        btck::BlockValidationState check_state;
        BOOST_CHECK(kblock.Check(kparams.GetConsensusParams(), btck::BlockCheckFlags::ALL, check_state));
        BOOST_CHECK(check_state.GetValidationMode() == btck::ValidationMode::VALID);

        bool new_block{false};
        BOOST_CHECK(!chainman->ProcessBlock(kblock, &new_block));
        BOOST_REQUIRE(capture->m_mode.has_value());
        BOOST_CHECK(*capture->m_mode == btck::ValidationMode::INVALID);
        BOOST_CHECK(*capture->m_result == btck::BlockValidationResult::CONSENSUS);
    }

    constexpr int64_t jump{100'000};
    const int last_of_period1{dai - 1};
    std::vector<CBlockHeader> prefix;
    prefix.reserve(last_of_period1);
    uint256 prev_hash{genesis.GetHash()};
    for (int height{1}; height <= last_of_period1; ++height) {
        int64_t t{genesis.nTime + static_cast<int64_t>(height) * consensus.nPowTargetSpacing};
        if (height == last_of_period1) t += jump;
        prefix.push_back(MineRegtestHeader(prev_hash, static_cast<uint32_t>(t), genesis.nBits, consensus));
        prev_hash = prefix.back().GetHash();
    }
    const int64_t prev_time{prefix.back().nTime};
    const auto timewarp_eq{MineRegtestHeader(prefix.back().GetHash(), static_cast<uint32_t>(prev_time - MAX_TIMEWARP_BIP54), genesis.nBits, consensus)};
    const auto timewarp_fail{MineRegtestHeader(prefix.back().GetHash(), static_cast<uint32_t>(prev_time - MAX_TIMEWARP_BIP54 - 1), genesis.nBits, consensus)};

    auto test_directory{TestDirectory{"bip54_process_block_timewarp"}};
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{CreateRegtestContext(notifications)};
    auto chainman{CreateChainMan(test_directory, context)};
    for (const auto& header : prefix) {
        RequireKernelHeader(*chainman, header);
    }

    const btck::BlockValidationState eq_state{chainman->ProcessBlockHeader(ToKernelHeader(timewarp_eq))};
    BOOST_CHECK(eq_state.GetValidationMode() == btck::ValidationMode::VALID);
    BOOST_CHECK(eq_state.GetBlockValidationResult() == btck::BlockValidationResult::UNSET);

    const btck::BlockValidationState fail_state{chainman->ProcessBlockHeader(ToKernelHeader(timewarp_fail))};
    BOOST_CHECK(fail_state.GetValidationMode() == btck::ValidationMode::INVALID);
    BOOST_CHECK(fail_state.GetBlockValidationResult() == btck::BlockValidationResult::INVALID_HEADER);
}

/**
 * BIP54 coinbase locktime and sequence on kernel ProcessBlock.
 * ProcessBlock runs ContextualCheckBlock. C API has no reject reason string.
 * CONSENSUS here. C++ AcceptBlock twin bip54_coinbase_lock_door has the reason.
 * Kernel chainman cannot flip versionbits. Inactive path is C++ only.
 * Height 1 legal accepts. Wrong locktime at height 1 is bad-txns-nonfinal first,
 * so reject pins use height 2.
 */
BOOST_AUTO_TEST_CASE(btck_process_block_bip54_coinbase_lock)
{
    const auto params{CChainParams::RegTest()};
    const auto& consensus{params->GetConsensus()};
    const CBlock& genesis{params->GenesisBlock()};
    const CScript spk{CScript() << OP_TRUE};

    auto test_directory{TestDirectory{"bip54_process_block_coinbase_lock"}};
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto capture{std::make_shared<CaptureValidationInterface>()};
    auto context{CreateRegtestContext(notifications, capture)};
    auto chainman{CreateChainMan(test_directory, context)};

    const auto height1{MinedCoinbaseBlock(genesis.GetHash(), genesis.nTime + 600, genesis.nBits, /*height=*/1,
                                          /*n_lock_time=*/0, /*n_sequence=*/0, spk, consensus)};
    bool new_block{false};
    BOOST_CHECK(chainman->ProcessBlock(ToKernelBlock(height1), &new_block));
    BOOST_REQUIRE(capture->m_mode.has_value());
    BOOST_CHECK(*capture->m_mode == btck::ValidationMode::VALID);

    const auto height2_lock_wrong{MinedCoinbaseBlock(height1.GetHash(), height1.nTime + 600, genesis.nBits, /*height=*/2,
                                                     /*n_lock_time=*/0, /*n_sequence=*/0, spk, consensus)};
    capture->m_mode.reset();
    capture->m_result.reset();
    BOOST_CHECK(!chainman->ProcessBlock(ToKernelBlock(height2_lock_wrong), &new_block));
    BOOST_REQUIRE(capture->m_mode.has_value());
    BOOST_CHECK(*capture->m_mode == btck::ValidationMode::INVALID);
    BOOST_CHECK(*capture->m_result == btck::BlockValidationResult::CONSENSUS);

    const auto height2_seq_final{MinedCoinbaseBlock(height1.GetHash(), height1.nTime + 600, genesis.nBits, /*height=*/2,
                                                    /*n_lock_time=*/1, CTxIn::SEQUENCE_FINAL, spk, consensus)};
    capture->m_mode.reset();
    capture->m_result.reset();
    BOOST_CHECK(!chainman->ProcessBlock(ToKernelBlock(height2_seq_final), &new_block));
    BOOST_REQUIRE(capture->m_mode.has_value());
    BOOST_CHECK(*capture->m_mode == btck::ValidationMode::INVALID);
    BOOST_CHECK(*capture->m_result == btck::BlockValidationResult::CONSENSUS);
}
