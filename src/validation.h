// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_H
#define BITCOIN_VALIDATION_H

#include <arith_uint256.h>
#include <attributes.h>
#include <chain.h>
#include <checkqueue.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <deploymentstatus.h>
#include <kernel/chain.h>
#include <kernel/chainparams.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/cs_main.h> // IWYU pragma: export
#include <kernel/error.h>
#include <kernel/result.h>
#include <kernel/blockstorage.h>
#include <kernel/chainstatemanager.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/verify_flags.h>
#include <sync.h>
#include <txdb.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/hasher.h>
#include <util/log.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>
#include <versionbits.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

struct ChainTxData;
struct PrecomputedTransactionData;
struct LockPoints;
struct AssumeutxoData;
namespace kernel {
struct ChainstateRole;
class SnapshotMetadata;
class Chainstate;
class ChainstateManager;
} // namespace kernel
namespace Consensus {
struct Params;
} // namespace Consensus
namespace util {
class SignalInterrupt;
} // namespace util


//! Re-export engine types at global scope for existing call sites and free
//! functions in this header. Canonical home is kernel:: (see chainstatemanager.h).
using kernel::FlushStateMode;
using kernel::FlushStateModeNames;
using kernel::CoinsViews;
using kernel::CoinsCacheSizeState;
using kernel::LargeCoinsCacheThreshold;
using kernel::Assumeutxo;
using kernel::ChainStats;
using kernel::Chainstate;
using kernel::SnapshotCompletionResult;
using kernel::ChainstateManager;
using kernel::DisconnectResult;
using kernel::DISCONNECT_OK;
using kernel::DISCONNECT_UNCLEAN;
using kernel::DISCONNECT_FAILED;
using kernel::ConnectedBlock;
using kernel::CScriptCheck;
using kernel::ValidationCache;

/** Block files containing a block-height within MIN_BLOCKS_TO_KEEP of ActiveChain().Tip() will not be pruned. */
inline constexpr unsigned int MIN_BLOCKS_TO_KEEP = 288;
inline constexpr signed int DEFAULT_CHECKBLOCKS = 6;
inline constexpr int DEFAULT_CHECKLEVEL{3};
// Require that user allocate at least 550 MiB for block & undo files (blk???.dat and rev???.dat)
// At 1MB per block, 288 blocks = 288MB.
// Add 15% for Undo data = 331MB
// Add 20% for Orphan block rate = 397MB
// We want the low water mark after pruning to be at least 397 MB and since we prune in
// full block file chunks, we need the high water mark which triggers the prune to be
// one 128MB block file + added 15% undo data = 147MB greater for a total of 545MB
// Setting the target to >= 550 MiB will make it likely we can respect the target.
inline constexpr uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES{550_MiB};

/** Fake height value used in Coin to signify they are only in the memory pool (since 0.8) */
inline constexpr uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

/** Maximum number of dedicated script-checking threads allowed */
inline constexpr int MAX_SCRIPTCHECK_THREADS{15};

/** Maximum number of dedicated threads allowed for prefetching block input prevouts */
inline constexpr int32_t MAX_PREVOUTFETCH_THREADS{16};

/** Current sync state passed to tip changed callbacks. */
enum class SynchronizationState {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT
};

/** Documentation for argument 'checklevel'. */
extern const std::vector<std::string> CHECKLEVEL_DOC;

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

//! Reject reason for the errors reported through BlockValidationState::Error(),
//! which submitblock and submitheader surface. Empty for the errors that are
//! only reported through Notifications::fatalError(). This is not a user-facing
//! message: building and translating that is the application's job, see
//! node/kernel_notifications.cpp.
std::string FatalErrorString(const kernel::FatalError& error);

bool FatalError(kernel::Notifications& notifications, BlockValidationState& state, const kernel::FatalError& error);

/** Prune block files up to a given height */
[[nodiscard]] kernel::FlushResult<void, kernel::AbortFailure> PruneBlockFilesManual(Chainstate& active_chainstate, int nManualPruneHeight);

/**
 * Check if transaction will be final in the next block to be created.
 */
bool CheckFinalTxAtTip(const CBlockIndex& active_chain_tip, const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/**
 * Calculate LockPoints required to check if transaction will be BIP68 final in the next block
 * to be created on top of tip.
 *
 * @param[in]   tip             Chain tip for which tx sequence locks are calculated. For
 *                              example, the tip of the current active chain.
 * @param[in]   coins_view      Any CCoinsView that provides access to the relevant coins for
 *                              checking sequence locks. For example, it can be a CCoinsViewCache
 *                              that isn't connected to anything but contains all the relevant
 *                              coins, or a CCoinsViewMemPool that is connected to the
 *                              mempool and chainstate UTXO set. In the latter case, the caller
 *                              is responsible for holding the appropriate locks to ensure that
 *                              calls to GetCoin() return correct coins.
 * @param[in]   tx              The transaction being evaluated.
 *
 * @returns The resulting height and time calculated and the hash of the block needed for
 *          calculation, or std::nullopt if there is an error.
 */
std::optional<LockPoints> CalculateLockPointsAtTip(
    util::log::Logger* logger,
    CBlockIndex* tip,
    const CCoinsView& coins_view,
    const CTransaction& tx);

/**
 * Check if transaction will be BIP68 final in the next block to be created on top of tip.
 * @param[in]   tip             Chain tip to check tx sequence locks against. For example,
 *                              the tip of the current active chain.
 * @param[in]   lock_points     LockPoints containing the height and time at which this
 *                              transaction is final.
 * Simulates calling SequenceLocks() with data from the tip passed in.
 * The LockPoints should not be considered valid if CheckSequenceLocksAtTip returns false.
 */
bool CheckSequenceLocksAtTip(CBlockIndex* tip,
                             const LockPoints& lock_points);


/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true);
bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 *
 *  NOTE: failing to check the header's height against the last checkpoint's opened a DoS vector between
 *  v0.12 and v0.15 (when no additional protection was in place) whereby an attacker could unboundedly
 *  grow our in-memory block index. See https://bitcoincore.org/en/2024/07/03/disclose-header-spam.
 */
bool ContextualCheckBlockHeader(
    const CBlockHeader& block,
    BlockValidationState& state,
    const Consensus::Params& consensusParams,
    VersionBitsCache& versionbitscache,
    const CBlockIndex* pindexPrev,
    NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);


/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& params, VersionBitsCache& versionbitscache, const CBlockIndex* pindexPrev);

/**
 * Verify a block, including transactions.
 *
 * @param[in]   block       The block we want to process. Must connect to the
 *                          current tip.
 * @param[in]   chainstate  The chainstate to connect to.
 * @param[in]   check_pow   perform proof-of-work check, nBits in the header
 *                          is always checked
 * @param[in]   check_merkle_root check the merkle root
 *
 * @return Valid or Invalid state. This doesn't currently return an Error state,
 *         and shouldn't unless there is something wrong with the existing
 *         chainstate. (This is different from functions like AcceptBlock which
 *         can fail trying to save new data.)
 *
 * For signets the challenge verification is skipped when check_pow is false.
 */
kernel::FlushResult<void, BlockValidationState> TestBlockValidity(
    Chainstate& chainstate,
    const CBlock& block,
    bool check_pow,
    bool check_merkle_root) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Check that the proof of work on each blockheader matches the value in nBits */
bool HasValidProofOfWork(std::span<const CBlockHeader> headers, const Consensus::Params& consensusParams);

/** Check if a block has been mutated (with respect to its merkle root and witness commitments). */
bool IsBlockMutated(util::log::Logger* logger, const CBlock& block, bool check_witness_root);

/** Return the sum of the claimed work on a given set of headers. No verification of PoW is done. */
arith_uint256 CalculateClaimedHeadersWork(std::span<const CBlockHeader> headers);

struct VerifySuccess{};
struct SkippedL3Checks{};
struct SkippedMissingBlocks{};
using VerifyDBResult = std::variant<VerifySuccess, kernel::Interrupted, SkippedL3Checks, SkippedMissingBlocks>;

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
private:
    kernel::Notifications& m_notifications;

public:
    explicit CVerifyDB(kernel::Notifications& notifications);
    ~CVerifyDB();
    [[nodiscard]] kernel::FlushResult<VerifyDBResult> VerifyDB(
        Chainstate& chainstate,
        const Consensus::Params& consensus_params,
        CCoinsView& coinsview,
        int nCheckLevel,
        int nCheckDepth) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};




bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks = nullptr);

/** Deployment* info via ChainstateManager */
template<typename DEP>
bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache, DEP dep)
{
    return DeploymentActiveAfter(pindexPrev, params, dep, versionbitscache);
}

template<typename DEP>
bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, VersionBitsCache& versionbitscache, DEP dep)
{
    return DeploymentActiveAt(index, params, dep, versionbitscache);
}

template<typename DEP>
bool DeploymentEnabled(const Consensus::Params& params, DEP dep)
{
    return DeploymentEnabled(params, dep);
}

/** Identifies blocks that overwrote an existing coinbase output in the UTXO set (see BIP30) */
bool IsBIP30Repeat(const CBlockIndex& block_index);

/** Identifies blocks which coinbase output was subsequently overwritten in the UTXO set (see BIP30) */
bool IsBIP30Unspendable(const uint256& block_hash, int block_height);

// Returns the script flags which should be checked for a given block
script_verify_flags GetBlockScriptFlags(const CBlockIndex& block_index, const Consensus::Params& consensusparams, VersionBitsCache& versionbitscache);

#endif // BITCOIN_VALIDATION_H
