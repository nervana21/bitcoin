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
#include <cstdint>
#include <list>
#include <optional>

class CBlockIndex;
class ChainstateManager;
class CTxMemPool;
class PartiallyDownloadedBlock;

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
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H
