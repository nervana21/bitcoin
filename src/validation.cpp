// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <checkqueue.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <flatfile.h>
#include <hash.h>
#include <kernel/chainparams.h>
#include <kernel/coinsstore.h>
#include <kernel/coinstats.h>
#include <kernel/disconnected_transactions.h>
#include <kernel/error.h>
#include <kernel/legacy_leveldb.h>
#include <kernel/mempool_entry.h>
#include <kernel/messagestartchars.h>
#include <kernel/notifications_interface.h>
#include <kernel/types.h>
#include <kernel/warning.h>
#include <logging/timer.h>
#include <node/blockstorage.h>
#include <kernel/utxo_snapshot.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <signet.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <undo.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/hasher.h>
#include <util/log.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadpool.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <deque>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

#define LOG_REQUIRE_CONTEXT true
using kernel::AbortFailure;
using kernel::CCoinsStats;
using kernel::ChainstateRole;
using kernel::CoinStatsHashType;
using kernel::ComputeUTXOStats;
using kernel::FlushResult;
using kernel::Interrupted;
using kernel::InterruptResult;
using kernel::IsInterrupted;
using kernel::Notifications;

using fsbridge::FopenFn;
using kernel::BlockManager;
using kernel::BlockMap;
using kernel::CBlockIndexHeightOnlyComparator;
using kernel::CBlockIndexWorkComparator;
using kernel::SnapshotMetadata;

const std::vector<std::string> CHECKLEVEL_DOC {
    "level 0 reads the blocks from disk",
    "level 1 verifies block validity",
    "level 2 verifies undo data",
    "level 3 checks disconnection of tip blocks",
    "level 4 tries to reconnect the blocks",
    "each level includes the checks of the previous levels",
};

// Return whether the completed full flush should compact chainstate


bool CheckFinalTxAtTip(const CBlockIndex& active_chain_tip, const CTransaction& tx)
{
    AssertLockHeld(cs_main);

    // CheckFinalTxAtTip() uses active_chain_tip.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than active_chain_tip.Height().
    const int nBlockHeight = active_chain_tip.nHeight + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx().
    const int64_t nBlockTime{active_chain_tip.GetMedianTimePast()};

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

namespace {
/**
 * A helper which calculates heights of inputs of a given transaction.
 *
 * @param[in] tip    The current chain tip. If an input belongs to a mempool
 *                   transaction, we assume it will be confirmed in the next block.
 * @param[in] coins  Any CCoinsView that provides access to the relevant coins.
 * @param[in] tx     The transaction being evaluated.
 *
 * @returns A vector of input heights or nullopt, in case of an error.
 */
std::optional<std::vector<int>> CalculatePrevHeights(
    const util::log::Context& log,
    const CBlockIndex& tip,
    const CCoinsView& coins,
    const CTransaction& tx)
{
    std::vector<int> prev_heights;
    prev_heights.resize(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (auto coin{coins.GetCoin(tx.vin[i].prevout)}) {
            prev_heights[i] = coin->nHeight == MEMPOOL_HEIGHT
                              ? tip.nHeight + 1 // Assume all mempool transaction confirm in the next block.
                              : coin->nHeight;
        } else {
            LogWarning(log, "%s: Missing input %d in transaction \'%s\'", __func__, i, tx.GetHash().GetHex());
            return std::nullopt;
        }
    }
    return prev_heights;
}
} // namespace

std::optional<LockPoints> CalculateLockPointsAtTip(
    util::log::Logger* logger,
    CBlockIndex* tip,
    const CCoinsView& coins_view,
    const CTransaction& tx)
{
    assert(tip);

    const util::log::Context log{BCLog::VALIDATION, logger};

    auto prev_heights{CalculatePrevHeights(log, *tip, coins_view, tx)};
    if (!prev_heights.has_value()) return std::nullopt;

    CBlockIndex next_tip;
    next_tip.pprev = tip;
    // When SequenceLocks() is called within ConnectBlock(), the height
    // of the block *being* evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than active_chainstate.m_chain.Height()
    next_tip.nHeight = tip->nHeight + 1;
    const auto [min_height, min_time] = CalculateSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, prev_heights.value(), next_tip);

    // Also store the hash of the block with the highest height of
    // all the blocks which have sequence locked prevouts.
    // This hash needs to still be on the chain
    // for these LockPoint calculations to be valid
    // Note: It is impossible to correctly calculate a maxInputBlock
    // if any of the sequence locked inputs depend on unconfirmed txs,
    // except in the special case where the relative lock time/height
    // is 0, which is equivalent to no sequence lock. Since we assume
    // input height of tip+1 for mempool txs and test the resulting
    // min_height and min_time from CalculateSequenceLocks against tip+1.
    int max_input_height{0};
    for (const int height : prev_heights.value()) {
        // Can ignore mempool inputs since we'll fail if they had non-zero locks
        if (height != next_tip.nHeight) {
            max_input_height = std::max(max_input_height, height);
        }
    }

    // tip->GetAncestor(max_input_height) should never return a nullptr
    // because max_input_height is always less than the tip height.
    // It would, however, be a bad bug to continue execution, since a
    // LockPoints object with the maxInputBlock member set to nullptr
    // signifies no relative lock time.
    return LockPoints{min_height, min_time, Assert(tip->GetAncestor(max_input_height))};
}

bool CheckSequenceLocksAtTip(CBlockIndex* tip,
                             const LockPoints& lock_points)
{
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocksAtTip() uses active_chainstate.m_chain.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than active_chainstate.m_chain.Height()
    index.nHeight = tip->nHeight + 1;

    return EvaluateSequenceLocks(index, {lock_points.height, lock_points.time});
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}


// Lock-free: depends on `m_cached_is_ibd`, which is latched by `UpdateIBDStatus()`.


// Called both upon regular invalid block discovery *and* InvalidateBlock


// Same as InvalidChainFound, above, except not called directly from InvalidateBlock,
// which does its own setBlockIndexCandidates management.


/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and redeclared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks)
{
    if (tx.IsCoinBase()) return true;

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    CSHA256 hasher = validation_cache.ScriptExecutionCacheHasher();
    hasher.Write(UCharCast(tx.GetWitnessHash().begin()), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    if (WITH_LOCK(validation_cache.m_script_execution_cache.m_mutex, return validation_cache.m_script_execution_cache.contains(hashCacheEntry, !cacheFullScriptStore))) {
        return true;
    }

    if (!txdata.m_spent_outputs_ready) {
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(tx.vin.size());

        for (const auto& txin : tx.vin) {
            const COutPoint& prevout = txin.prevout;
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());
            spent_outputs.emplace_back(coin.out);
        }
        txdata.Init(tx, std::move(spent_outputs));
    }
    assert(txdata.m_spent_outputs.size() == tx.vin.size());

    for (unsigned int i = 0; i < tx.vin.size(); i++) {

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(txdata.m_spent_outputs[i], tx, validation_cache.m_signature_cache, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->emplace_back(std::move(check));
        } else if (auto result = check(); result.has_value()) {
            // Tx failures never trigger disconnections/bans.
            // This is so that network splits aren't triggered
            // either due to non-consensus relay policies (such as
            // non-standard DER encodings or non-null dummy
            // arguments) or due to new consensus rules introduced in
            // soft forks.
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("mempool-script-verify-flag-failed (%s)", ScriptErrorString(result->first)), result->second);
            } else {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("block-script-verify-flag-failed (%s)", ScriptErrorString(result->first)), result->second);
            }
        }
    }

    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        LOCK(validation_cache.m_script_execution_cache.m_mutex);
        validation_cache.m_script_execution_cache.insert(hashCacheEntry);
    }

    return true;
}

std::string FatalErrorString(const kernel::FatalError& error)
{
    if (const auto* e{std::get_if<kernel::ActivateBestChainsFailed>(&error)}) return e->error;
    if (const auto* e{std::get_if<kernel::AssumeutxoDataNotFound>(&error)}) {
        return strprintf("Assumeutxo data not found for the given blockhash '%s'.", e->blockhash.ToString());
    }
    if (std::get_if<kernel::BlockDisconnectFailed>(&error)) return "Failed to disconnect block.";
    if (std::get_if<kernel::BlockFileCloseFailed>(&error)) return "Failed to close file when writing block.";
    if (std::get_if<kernel::BlockReadFailed>(&error)) return "Failed to read block.";
    if (std::get_if<kernel::BlockWriteFailed>(&error)) return "Failed to write block.";
    if (std::get_if<kernel::CorruptBlockFound>(&error)) return "Corrupt block found indicating potential hardware failure.";
    if (std::get_if<kernel::DiskSpaceTooLow>(&error)) return "Disk space is too low!";
    if (const auto* e{std::get_if<kernel::SnapshotChainstateDirRemovalFailed>(&error)}) {
        return strprintf("Failed to remove snapshot chainstate dir (%s). Manually remove it before restarting.", fs::PathToString(e->dir));
    }
    if (const auto* e{std::get_if<kernel::SnapshotChainstateRenameFailed>(&error)}) {
        return strprintf("Rename of '%s' -> '%s' failed. Cannot clean up the background chainstate directory.",
                         fs::PathToString(e->old_path), fs::PathToString(e->new_path));
    }
    if (std::get_if<kernel::SnapshotValidationFailed>(&error)) {
        return "Failed to validate the -assumeutxo snapshot state.";
    }
    if (const auto* e{std::get_if<kernel::SystemErrorWhileFlushing>(&error)}) return strprintf("System error while flushing: %s", e->what);
    if (const auto* e{std::get_if<kernel::SystemErrorWhileLoadingExternalBlockFile>(&error)}) {
        return strprintf("System error while loading external block file: %s", e->what);
    }
    if (const auto* e{std::get_if<kernel::SystemErrorWhileSavingBlock>(&error)}) return strprintf("System error while saving block to disk: %s", e->what);
    if (std::get_if<kernel::UndoDataWriteFailed>(&error)) return "Failed to write undo data.";
    if (std::get_if<kernel::UndoFileCloseFailed>(&error)) return "Failed to close block undo file.";
    return {};
}

bool FatalError(Notifications& notifications, BlockValidationState& state, const kernel::FatalError& error)
{
    notifications.fatalError(error);
    return state.Error(FatalErrorString(error));
}

void NotifyFatalAbort(Notifications& notifications, kernel::AbortFailure& abort)
{
    if (abort.fatal && abort.error) {
        notifications.fatalError(*abort.error);
        abort.error.reset();
    }
}

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */


/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */


script_verify_flags GetBlockScriptFlags(const CBlockIndex& block_index, const Consensus::Params& consensusparams, VersionBitsCache& versionbitscache)
{
    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet).
    // Similarly, only one historical block violated the TAPROOT rules on
    // mainnet.
    // For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the two
    // violating blocks.
    script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
    const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
    if (it != consensusparams.script_flag_exceptions.end()) {
        flags = it->second;
    }

    // Enforce the DERSIG (BIP66) rule
    if (DeploymentActiveAt(block_index, consensusparams, versionbitscache, Consensus::DEPLOYMENT_DERSIG)) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Enforce CHECKLOCKTIMEVERIFY (BIP65)
    if (DeploymentActiveAt(block_index, consensusparams, versionbitscache, Consensus::DEPLOYMENT_CLTV)) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Enforce CHECKSEQUENCEVERIFY (BIP112)
    if (DeploymentActiveAt(block_index, consensusparams, versionbitscache, Consensus::DEPLOYMENT_CSV)) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Enforce BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (DeploymentActiveAt(block_index, consensusparams, versionbitscache, Consensus::DEPLOYMENT_SEGWIT)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}


bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    return true;
}

static bool CheckMerkleRoot(const CBlock& block, BlockValidationState& state)
{
    if (block.m_checked_merkle_root) return true;

    bool mutated;
    uint256 merkle_root = BlockMerkleRoot(block, &mutated);
    if (block.hashMerkleRoot != merkle_root) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txnmrklroot",
            /*debug_message=*/"hashMerkleRoot mismatch");
    }

    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txns-duplicate",
            /*debug_message=*/"duplicate transaction");
    }

    block.m_checked_merkle_root = true;
    return true;
}

/** CheckWitnessMalleation performs checks for block malleation with regard to
 * its witnesses.
 *
 * Note: If the witness commitment is expected (i.e. `expect_witness_commitment
 * = true`), then the block is required to have at least one transaction and the
 * first transaction needs to have at least one input. */
static bool CheckWitnessMalleation(const CBlock& block, bool expect_witness_commitment, BlockValidationState& state)
{
    if (expect_witness_commitment) {
        if (block.m_checked_witness_commitment) return true;

        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != NO_WITNESS_COMMITMENT) {
            assert(!block.vtx.empty() && !block.vtx[0]->vin.empty());
            const auto& witness_stack{block.vtx[0]->vin[0].scriptWitness.stack};

            if (witness_stack.size() != 1 || witness_stack[0].size() != 32) {
                return state.Invalid(
                    /*result=*/BlockValidationResult::BLOCK_MUTATED,
                    /*reject_reason=*/"bad-witness-nonce-size",
                    /*debug_message=*/strprintf("%s : invalid witness reserved value size", __func__));
            }

            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            uint256 hash_witness = BlockWitnessMerkleRoot(block);

            CHash256().Write(hash_witness).Write(witness_stack[0]).Finalize(hash_witness);
            if (memcmp(hash_witness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.Invalid(
                    /*result=*/BlockValidationResult::BLOCK_MUTATED,
                    /*reject_reason=*/"bad-witness-merkle-match",
                    /*debug_message=*/strprintf("%s : witness merkle commitment mismatch", __func__));
            }

            block.m_checked_witness_commitment = true;
            return true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    for (const auto& tx : block.vtx) {
        if (tx->HasWitness()) {
            return state.Invalid(
                /*result=*/BlockValidationResult::BLOCK_MUTATED,
                /*reject_reason=*/"unexpected-witness",
                /*debug_message=*/strprintf("%s : unexpected witness data found", __func__));
        }
    }

    return true;
}

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Signet only: check block solution
    if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
    }

    // Check the merkle root.
    if (fCheckMerkleRoot && !CheckMerkleRoot(block, state)) {
        return false;
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");

    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
        }
    }
    // This underestimates the number of sigops, because unlike ConnectBlock it
    // does not count witness and p2sh sigops.
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}


bool HasValidProofOfWork(std::span<const CBlockHeader> headers, const Consensus::Params& consensusParams)
{
    return std::ranges::all_of(headers,
                               [&](const auto& header) { return CheckProofOfWork(header.GetHash(), header.nBits, consensusParams); });
}

bool IsBlockMutated(util::log::Logger* logger, const CBlock& block, bool check_witness_root)
{
    util::log::Context log{BCLog::VALIDATION, logger};
    BlockValidationState state;
    if (!CheckMerkleRoot(block, state)) {
        LogDebug(log, "Block mutated: %s\n", state.ToString());
        return true;
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        // Consider the block mutated if any transaction is 64 bytes in size (see 3.1
        // in "Weaknesses in Bitcoin’s Merkle Root Construction":
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20190225/a27d8837/attachment-0001.pdf).
        //
        // Note: This is not a consensus change as this only applies to blocks that
        // don't have a coinbase transaction and would therefore already be invalid.
        return std::any_of(block.vtx.begin(), block.vtx.end(),
                           [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
    } else {
        // Theoretically it is still possible for a block with a 64 byte
        // coinbase transaction to be mutated but we neglect that possibility
        // here as it requires at least 224 bits of work.
    }

    if (!CheckWitnessMalleation(block, check_witness_root, state)) {
        LogDebug(log, "Block mutated: %s\n", state.ToString());
        return true;
    }

    return false;
}

arith_uint256 CalculateClaimedHeadersWork(std::span<const CBlockHeader> headers)
{
    arith_uint256 total_work{0};
    for (const CBlockHeader& header : headers) {
        total_work += GetBlockProof(header);
    }
    return total_work;
}

bool ContextualCheckBlockHeader(
        const CBlockHeader& block,
        BlockValidationState& state,
        const Consensus::Params& consensusParams,
        VersionBitsCache& versionbitscache,
        const CBlockIndex* pindexPrev,
        NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Testnet4 and regtest only: Check timestamp against prev for difficulty-adjustment
    // blocks to prevent timewarp attacks (see https://github.com/bitcoin/bitcoin/pull/15482).
    if (consensusParams.enforce_BIP94) {
        // Check timestamp for the first block of each difficulty adjustment
        // interval, except the genesis block.
        if (nHeight % consensusParams.DifficultyAdjustmentInterval() == 0) {
            if (block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP) {
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-timewarp-attack", "block's timestamp is too early on diff adjustment block");
            }
        }
    }

    // Check timestamp
    if (block.Time() > now + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
    }

    // Reject blocks with outdated version
    if ((block.nVersion < 2 && DeploymentActiveAfter(pindexPrev, consensusParams, versionbitscache, Consensus::DEPLOYMENT_HEIGHTINCB)) ||
        (block.nVersion < 3 && DeploymentActiveAfter(pindexPrev, consensusParams, versionbitscache, Consensus::DEPLOYMENT_DERSIG)) ||
        (block.nVersion < 4 && DeploymentActiveAfter(pindexPrev, consensusParams, versionbitscache, Consensus::DEPLOYMENT_CLTV))) {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));
    }

    return true;
}

bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& params, VersionBitsCache& versionbitscache, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Enforce BIP113 (Median Time Past).
    bool enforce_locktime_median_time_past{false};
    if (DeploymentActiveAfter(pindexPrev, params, versionbitscache, Consensus::DEPLOYMENT_CSV)) {
        assert(pindexPrev != nullptr);
        enforce_locktime_median_time_past = true;
    }

    const int64_t nLockTimeCutoff{enforce_locktime_median_time_past ?
                                      pindexPrev->GetMedianTimePast() :
                                      block.GetBlockTime()};

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (DeploymentActiveAfter(pindexPrev, params, versionbitscache, Consensus::DEPLOYMENT_HEIGHTINCB))
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    if (!CheckWitnessMalleation(block, DeploymentActiveAfter(pindexPrev, params, versionbitscache, Consensus::DEPLOYMENT_SEGWIT), state)) {
        return false;
    }

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    return true;
}


FlushResult<void, BlockValidationState> TestBlockValidity(
    Chainstate& chainstate,
    const CBlock& block,
    const bool check_pow,
    const bool check_merkle_root)
{
    // Lock must be held throughout this function for two reasons:
    // 1. We don't want the tip to change during several of the validation steps
    // 2. To prevent a CheckBlock() race condition for fChecked, see ProcessNewBlock()
    AssertLockHeld(chainstate.m_chainman.GetMutex());

    FlushResult<void, BlockValidationState> result;
    BlockValidationState state;
    CBlockIndex* tip{Assert(chainstate.m_chain.Tip())};

    if (block.hashPrevBlock != *Assert(tip->phashBlock)) {
        state.Invalid({}, "inconclusive-not-best-prevblk");
        result.update({util::Error{}, std::move(state)});
        return result;
    }

    // For signets CheckBlock() verifies the challenge iff fCheckPow is set.
    if (!CheckBlock(block, state, chainstate.m_chainparams.GetConsensus(), /*fCheckPow=*/check_pow, /*fCheckMerkleRoot=*/check_merkle_root)) {
        // This should never happen, but belt-and-suspenders don't approve the
        // block if it does.
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        result.update({util::Error{}, std::move(state)});
        return result;
    }

    /**
     * At this point ProcessNewBlock would call AcceptBlock(), but we
     * don't want to store the block or its header. Run individual checks
     * instead:
     * - skip AcceptBlockHeader() because:
     *   - we don't want to update the block index
     *   - we do not care about duplicates
     *   - we already ran CheckBlockHeader() via CheckBlock()
     *   - we already checked for prev-blk-not-found
     *   - we know the tip is valid, so no need to check bad-prevblk
     * - we already ran CheckBlock()
     * - do run ContextualCheckBlockHeader()
     * - do run ContextualCheckBlock()
     */

    if (!ContextualCheckBlockHeader(block, state, chainstate.m_chainparams.GetConsensus(), chainstate.m_versionbitscache, tip, chainstate.m_chainman.Now())) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        result.update({util::Error{}, std::move(state)});
        return result;
    }

    if (!ContextualCheckBlock(block, state, chainstate.m_chainparams.GetConsensus(), chainstate.m_versionbitscache, tip)) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        result.update({util::Error{}, std::move(state)});
        return result;
    }

    // We don't want ConnectBlock to update the actual chainstate, so create
    // a cache on top of it, along with a dummy block index.
    CBlockIndex index_dummy{block};
    uint256 block_hash(block.GetHash());
    index_dummy.pprev = tip;
    index_dummy.nHeight = tip->nHeight + 1;
    index_dummy.phashBlock = &block_hash;
    CCoinsViewCache view_dummy(&chainstate.CoinsTip());

    // Set fJustCheck to true in order to update, and not clear, validation caches.
    if(!(chainstate.ConnectBlock(block, state, &index_dummy, view_dummy, /*fJustCheck=*/true) >> result)) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        result.update({util::Error{}, std::move(state)});
        return result;
    }

    // Ensure no check returned successfully while also setting an invalid state.
    if (!state.IsValid()) NONFATAL_UNREACHABLE();

    return result;
}

/* This function is called from the RPC code for pruneblockchain */
FlushResult<void, AbortFailure> PruneBlockFilesManual(Chainstate& active_chainstate, int nManualPruneHeight)
{
    const util::log::Context& log{active_chainstate.m_log};
    BlockValidationState state;
    FlushResult<void, AbortFailure> result{active_chainstate.FlushStateToDisk(
            state, FlushStateMode::NONE, nManualPruneHeight)};
    NotifyFatalAbort(active_chainstate.m_chainman.GetNotifications(), result);
    if (!result) {
        auto error{Untranslated(strprintf("Failed to flush state after manual prune (%s)", state.ToString()))};
        LogWarning(log, "%s", error.original);
        result.update(util::Error{std::move(error)});
    }
    return result;
}


CVerifyDB::CVerifyDB(Notifications& notifications)
    : m_notifications{notifications}
{
    m_notifications.progress(_("Verifying blocks…"), 0, false);
}

CVerifyDB::~CVerifyDB()
{
    m_notifications.progress(bilingual_str{}, 100, false);
}

FlushResult<VerifyDBResult> CVerifyDB::VerifyDB(
    Chainstate& chainstate,
    const Consensus::Params& consensus_params,
    CCoinsView& coinsview,
    int nCheckLevel, int nCheckDepth)
{
    AssertLockHeld(cs_main);
    const util::log::Context& log{chainstate.m_log};
    FlushResult<VerifyDBResult> result;

    if (chainstate.m_chain.Tip() == nullptr || chainstate.m_chain.Tip()->pprev == nullptr) {
        return result;
    }

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainstate.m_chain.Height()) {
        nCheckDepth = chainstate.m_chain.Height();
    }
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogInfo(log, "Verifying last %i blocks at level %i", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(&coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;
    bool skipped_no_block_data{false};
    bool skipped_l3_checks{false};
    LogInfo(log, "Verification progress: 0%%");

    const bool is_snapshot_cs{chainstate.m_from_snapshot_blockhash};

    for (pindex = chainstate.m_chain.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogInfo(log, "Verification progress: %d%%", percentageDone);
            reportDone = percentageDone / 10;
        }
        m_notifications.progress(_("Verifying blocks…"), percentageDone, false);
        if (pindex->nHeight <= chainstate.m_chain.Height() - nCheckDepth) {
            break;
        }
        if ((chainstate.m_blockman.IsPruneMode() || is_snapshot_cs) && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning or running under an assumeutxo snapshot, only go
            // back as far as we have data.
            LogInfo(log, "Block verification stopping at height %d (no data). This could be due to pruning or use of an assumeutxo snapshot.", pindex->nHeight);
            skipped_no_block_data = true;
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
            auto error{Untranslated(strprintf("Verification error: ReadBlock failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString()))};
            LogError(log, "%s", error.original);
            result.update(util::Error{std::move(error)});
            return result;
        }
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, consensus_params)) {
            auto error{Untranslated(strprintf("Verification error: found bad block at %d, hash=%s (%s)",
                      pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString()))};
            LogError(log, "%s", error.original);
            result.update(util::Error{std::move(error)});
            return result;
        }
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!chainstate.m_blockman.ReadBlockUndo(undo, *pindex)) {
                    auto error{Untranslated(strprintf("Verification error: found bad undo data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString()))};
                    LogError(log, "%s", error.original);
                    result.update(util::Error{std::move(error)});
                    return result;
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        size_t curr_coins_usage = coins.DynamicMemoryUsage() + chainstate.CoinsTip().DynamicMemoryUsage();

        if (nCheckLevel >= 3) {
            if (curr_coins_usage <= chainstate.m_coinstip_cache_size_bytes) {
                assert(coins.GetBestBlock() == pindex->GetBlockHash());
                DisconnectResult res = chainstate.DisconnectBlock(block, pindex, coins);
                if (res == DISCONNECT_FAILED) {
                    auto error{Untranslated(strprintf("Verification error: irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString()))};
                    LogError(log, "%s", error.original);
                    result.update(util::Error{std::move(error)});
                    return result;
                }
                if (res == DISCONNECT_UNCLEAN) {
                    nGoodTransactions = 0;
                    pindexFailure = pindex;
                } else {
                    nGoodTransactions += block.vtx.size();
                }
            } else {
                skipped_l3_checks = true;
            }
        }
        if (chainstate.m_interrupt) {
            result.update(Interrupted{});
            return result;
        }
    }
    if (pindexFailure) {
        auto error{Untranslated(strprintf("Verification error: coin database inconsistencies found (last %i blocks, %i good transactions before that)", chainstate.m_chain.Height() - pindexFailure->nHeight + 1, nGoodTransactions))};
        LogError(log, "%s", error.original);
        result.update(util::Error{std::move(error)});
        return result;
    }
    if (skipped_l3_checks) {
        LogWarning(log, "Skipped verification of level >=3 (insufficient database cache size). Consider increasing -dbcache.");
    }

    // store block count as we move pindex at check level >= 4
    int block_count = chainstate.m_chain.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4 && !skipped_l3_checks) {
        while (pindex != chainstate.m_chain.Tip()) {
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone / 10) {
                // report every 10% step
                LogInfo(log, "Verification progress: %d%%", percentageDone);
                reportDone = percentageDone / 10;
            }
            m_notifications.progress(_("Verifying blocks…"), percentageDone, false);
            pindex = chainstate.m_chain.Next(*pindex);
            CBlock block;
            if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
                auto error{Untranslated(strprintf("Verification error: ReadBlock failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString()))};
                LogError(log, "%s", error.original);
                result.update(util::Error{std::move(error)});
                return result;
            }
            if (!(chainstate.ConnectBlock(block, state, pindex, coins) >> result)) {
                auto error{Untranslated(strprintf("Verification error: found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString()))};
                LogError(log, "%s", error.original);
                result.update(util::Error{std::move(error)});
                return result;
            }
            if (chainstate.m_interrupt) {
                result.update(Interrupted{});
                return result;
            }
        }
    }

    LogInfo(log, "Verification: checked last %i blocks at level %i", block_count, nCheckLevel);
    if (nCheckLevel >= 3 && !skipped_l3_checks) {
        LogInfo(log, "Verification: no coin database inconsistencies (%i transactions)", nGoodTransactions);
    }

    if (skipped_l3_checks) {
        result.update(SkippedL3Checks{});
    } else if (skipped_no_block_data) {
        result.update(SkippedMissingBlocks{});
    }
    return result;
}


kernel::ChainstateManager::~ChainstateManager()
{
    LOCK(::cs_main);

    m_versionbitscache.Clear();
    kernel::UnregisterValidationMutexOwner(this);
}


bool IsBIP30Repeat(const CBlockIndex& block_index)
{
    return (block_index.nHeight==91842 && block_index.GetBlockHash() == uint256{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"}) ||
           (block_index.nHeight==91880 && block_index.GetBlockHash() == uint256{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"});
}

bool IsBIP30Unspendable(const uint256& block_hash, int block_height)
{
    return (block_height==91722 && block_hash == uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}) ||
           (block_height==91812 && block_hash == uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"});
}


