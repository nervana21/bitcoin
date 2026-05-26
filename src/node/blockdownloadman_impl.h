// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

#include <node/blockdownloadman.h>

#include <kernel/cs_main.h>
#include <uint256.h>

class CBlockIndex;

#include <atomic>
#include <chrono>
#include <list>
#include <map>
#include <optional>
#include <vector>

class CChain;

namespace node {

class BlockDownloadManagerImpl {
public:
    BlockDownloadOptions m_opts;

    struct PeerBlockDownloadState {
        BlockDownloadConnectionInfo m_connection_info;
        const CBlockIndex* pindexBestKnownBlock{nullptr};
        const CBlockIndex* pindexLastCommonBlock{nullptr};
        uint256 hashLastUnknownBlock{};
        bool fSyncStarted{false};
        std::list<QueuedBlock> vBlocksInFlight;
        std::chrono::microseconds m_downloading_since{0us};
        std::chrono::microseconds m_stalling_since{0us};
        bool fPreferredDownload{false};

        explicit PeerBlockDownloadState(const BlockDownloadConnectionInfo& info)
            : m_connection_info{info} {}
    };

    std::map<NodeId, PeerBlockDownloadState> m_peer_info GUARDED_BY(::cs_main);

    using BlockDownloadMap = std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>>;
    BlockDownloadMap mapBlocksInFlight GUARDED_BY(::cs_main);

    int nSyncStarted GUARDED_BY(::cs_main){0};

    int m_num_preferred_download_peers GUARDED_BY(::cs_main){0};

    int m_peers_downloading_from GUARDED_BY(::cs_main){0};

    std::atomic<std::chrono::seconds> m_last_tip_update{0s};

    explicit BlockDownloadManagerImpl(const BlockDownloadOptions& options)
        : m_opts{options} {}

    void ConnectedPeer(NodeId nodeid, const BlockDownloadConnectionInfo& info) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void DisconnectedPeer(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    bool IsBlockRequested(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    bool IsBlockRequestedFromOutbound(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    bool BlockRequested(NodeId nodeid, const CBlockIndex& block,
                        std::list<QueuedBlock>::iterator** pit,
                        CTxMemPool* mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    bool TipMayBeStale(std::chrono::seconds now, int64_t n_pow_target_spacing) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void ProcessBlockAvailability(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void UpdateBlockAvailability(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void FindNextBlocks(std::vector<const CBlockIndex*>& vBlocks,
                        NodeId nodeid,
                        PeerBlockDownloadState& state,
                        const CBlockIndex* pindexWalk,
                        unsigned int count, int nWindowEnd,
                        const CChain* activeChain = nullptr,
                        NodeId* nodeStaller = nullptr) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void FindNextBlocksToDownload(NodeId nodeid, unsigned int count,
                                  std::vector<const CBlockIndex*>& vBlocks,
                                  NodeId& nodeStaller) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void TryDownloadingHistoricalBlocks(NodeId nodeid, unsigned int count,
                                        std::vector<const CBlockIndex*>& vBlocks,
                                        const CBlockIndex* from_tip,
                                        const CBlockIndex* target_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    PeerBlockDownloadState* GetPeerState(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    const PeerBlockDownloadState* GetPeerState(NodeId nodeid) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
