// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_H

#include <kernel/cs_main.h>
#include <memory>
#include <net.h>
#include <uint256.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <vector>

class CBlockIndex;
class ChainstateManager;
class CTxMemPool;
class PartiallyDownloadedBlock;

/** Default time during which a peer must stall block download progress before being disconnected. */
static constexpr auto BLOCK_STALLING_TIMEOUT_DEFAULT{2s};
/** Size of the "block download window": how far ahead of our current height do we fetch? */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Minimum blocks required to signal NODE_NETWORK_LIMITED */
static const unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;

namespace node {

class BlockDownloadManagerImpl;

struct BlockDownloadOptions {
    /** Reference to ChainstateManager for chain state access and LookupBlockIndex. */
    ChainstateManager& m_chainman;
};

/** Blocks that are in flight, and that are in the queue to be downloaded. */
struct QueuedBlock {
    /** BlockIndex. We must have this since we only request blocks when we've already validated the header. */
    const CBlockIndex* pindex;
    /** Optional, used for CMPCTBLOCK downloads */
    std::unique_ptr<PartiallyDownloadedBlock> partialBlock;
};

struct BlockDownloadConnectionInfo {
    /** Whether this is an inbound peer. */
    bool m_is_inbound;
    /** Whether this peer is preferred for download. */
    bool m_preferred_download;
    /** Whether this peer can serve witness data (NODE_WITNESS). */
    bool m_can_serve_witnesses;
    /** Whether this peer can only serve limited recent blocks (pruned). */
    bool m_is_limited_peer;
};

class BlockDownloadManager {
    const std::unique_ptr<BlockDownloadManagerImpl> m_impl;

public:
    explicit BlockDownloadManager(const BlockDownloadOptions& options);
    ~BlockDownloadManager();

    /** Register a new peer for block download tracking. */
    void ConnectedPeer(NodeId nodeid, const BlockDownloadConnectionInfo& info) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Clean up all block download state for a disconnected peer. */
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Have we requested this block from any peer? */
    bool IsBlockRequested(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Have we requested this block from an outbound peer? */
    bool IsBlockRequestedFromOutbound(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Remove this block from our tracked requested blocks.
     *  If from_peer is set, only remove the block if it is in flight from that peer. */
    void RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Mark a block as in flight from a given peer.
     *  Returns false (still setting pit) if the block was already in flight from the same peer.
     *  pit is only valid while cs_main is held. */
    bool BlockRequested(NodeId nodeid, const CBlockIndex& block,
                        std::list<QueuedBlock>::iterator** pit = nullptr,
                        CTxMemPool* mempool = nullptr) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Check whether the tip might be stale based on last update time and in-flight state. */
    bool TipMayBeStale(std::chrono::seconds now, int64_t n_pow_target_spacing) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Record that the tip was updated. */
    void SetLastTipUpdate(std::chrono::seconds time);

    /** Get the last tip update time. */
    std::chrono::seconds GetLastTipUpdate() const;

    /** Check whether the last unknown block a peer advertised is not yet known. */
    void ProcessBlockAvailability(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Update tracking information about which blocks a peer is assumed to have. */
    void UpdateBlockAvailability(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Calculate which blocks to download from a given peer, given our current tip.
     *  Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks.
     *  Sets nodeStaller to a stalling peer NodeId if applicable, or -1. */
    void FindNextBlocksToDownload(NodeId nodeid, unsigned int count,
                                  std::vector<const CBlockIndex*>& vBlocks,
                                  NodeId& nodeStaller) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Request blocks for the background chainstate, if one is in use. */
    void TryDownloadingHistoricalBlocks(NodeId nodeid, unsigned int count,
                                        std::vector<const CBlockIndex*>& vBlocks,
                                        const CBlockIndex* from_tip,
                                        const CBlockIndex* target_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the best known block for a peer (or nullptr). */
    const CBlockIndex* GetBestKnownBlock(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the best header we have sent a peer (or nullptr). */
    const CBlockIndex* GetBestHeaderSent(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Set the best header we have sent a peer. */
    void SetBestHeaderSent(NodeId nodeid, const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the last common block with a peer (or nullptr). */
    const CBlockIndex* GetLastCommonBlock(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get whether we have started syncing headers with this peer. */
    bool GetSyncStarted(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Mark that we've started syncing headers with this peer, updating the global counter. */
    void SetSyncStarted(NodeId nodeid, bool started) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the global number of peers with sync started. */
    int GetNumSyncStarted() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the stalling timeout for blocks. */
    std::chrono::seconds GetBlockStallingTimeout() const;

    /** Atomically compare-and-exchange the stalling timeout.
     *  Returns true on success (value was expected, now set to desired). */
    bool CompareExchangeBlockStallingTimeout(std::chrono::seconds& expected, std::chrono::seconds desired);

    /** Get the number of preferred download peers. */
    int GetNumPreferredDownload() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the number of peers we are downloading blocks from. */
    int GetPeersDownloadingFrom() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Whether blocks are in flight from any peer. */
    bool HasBlocksInFlight() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get total number of blocks in flight (across all hashes and peers). */
    size_t GetTotalBlocksInFlight() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H
