// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockdownloadman.h>
#include <node/blockdownloadman_impl.h>

#include <blockencodings.h>
#include <chain.h>
#include <node/blockstorage.h>
#include <util/check.h>
#include <validation.h>
#include <txmempool.h>
#include <util/time.h>

namespace node {

namespace {
/** Mirrors net_processing.h; moved here with block-download state. */
constexpr unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK{3};

BlockDownloadManagerImpl::PeerBlockDownloadState* GetPeerState(BlockDownloadManagerImpl& man, NodeId nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    auto it = man.m_peer_info.find(nodeid);
    return it == man.m_peer_info.end() ? nullptr : &it->second;
}
} // namespace

BlockDownloadManager::BlockDownloadManager(const BlockDownloadOptions& options)
    : m_impl{std::make_unique<BlockDownloadManagerImpl>(options)}
{}

BlockDownloadManager::~BlockDownloadManager() = default;

void BlockDownloadManager::ConnectedPeer(NodeId nodeid, const BlockDownloadConnectionInfo& info)
{
    m_impl->ConnectedPeer(nodeid, info);
}

void BlockDownloadManagerImpl::ConnectedPeer(NodeId nodeid, const BlockDownloadConnectionInfo& info)
{
    auto [it, inserted] = m_peer_info.try_emplace(nodeid, info);
    auto& state = it->second;
    if (!inserted) {
        // Re-registration: update connection info.
        state.m_connection_info = info;
    }
    // Set preferred download flag and update counter (handles both first
    // registration and re-registration).
    if (info.m_preferred_download && !state.fPreferredDownload) {
        state.fPreferredDownload = true;
        m_num_preferred_download_peers++;
    }
}

void BlockDownloadManager::DisconnectedPeer(NodeId nodeid)
{
    m_impl->DisconnectedPeer(nodeid);
}

void BlockDownloadManagerImpl::DisconnectedPeer(NodeId nodeid)
{
    auto it = m_peer_info.find(nodeid);
    if (it == m_peer_info.end()) return;

    auto& state = it->second;

    if (state.fSyncStarted) {
        nSyncStarted--;
    }

    // Remove all in-flight block entries for this peer from the global map.
    for (const QueuedBlock& entry : state.vBlocksInFlight) {
        auto range = mapBlocksInFlight.equal_range(entry.pindex->GetBlockHash());
        while (range.first != range.second) {
            auto [node_id, list_it] = range.first->second;
            if (node_id != nodeid) {
                range.first++;
            } else {
                range.first = mapBlocksInFlight.erase(range.first);
            }
        }
    }

    m_num_preferred_download_peers -= state.fPreferredDownload;
    m_peers_downloading_from -= (!state.vBlocksInFlight.empty());
    assert(m_peers_downloading_from >= 0);

    m_peer_info.erase(it);
}

bool BlockDownloadManager::IsBlockRequested(const uint256& hash) const
{
    return m_impl->IsBlockRequested(hash);
}

bool BlockDownloadManagerImpl::IsBlockRequested(const uint256& hash) const
{
    return mapBlocksInFlight.contains(hash);
}

bool BlockDownloadManager::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    return m_impl->IsBlockRequestedFromOutbound(hash);
}

bool BlockDownloadManagerImpl::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        const auto [nodeid, block_it]{range.first->second};
        const auto it = m_peer_info.find(nodeid);
        if (it != m_peer_info.end() && !it->second.m_connection_info.m_is_inbound) return true;
    }
    return false;
}

void BlockDownloadManager::RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer)
{
    m_impl->RemoveBlockRequest(hash, from_peer);
}

void BlockDownloadManagerImpl::RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer)
{
    auto range = mapBlocksInFlight.equal_range(hash);
    if (range.first == range.second) {
        // Block was not requested from any peer
        return;
    }

    // We should not have requested too many of this block
    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    while (range.first != range.second) {
        const auto& [node_id, list_it]{range.first->second};

        if (from_peer && *from_peer != node_id) {
            range.first++;
            continue;
        }

        auto* state = Assert(GetPeerState(*this, node_id));

        if (state->vBlocksInFlight.begin() == list_it) {
            // First block on the queue was received, update the start download time for the next one
            state->m_downloading_since = std::max(state->m_downloading_since, GetTime<std::chrono::microseconds>());
        }
        state->vBlocksInFlight.erase(list_it);

        if (state->vBlocksInFlight.empty()) {
            // Last validated block on the queue for this peer was received.
            m_peers_downloading_from--;
        }
        state->m_stalling_since = 0us;

        range.first = mapBlocksInFlight.erase(range.first);
    }
}

bool BlockDownloadManager::BlockRequested(NodeId nodeid, const CBlockIndex& block,
                                          std::list<QueuedBlock>::iterator** pit,
                                          CTxMemPool* mempool)
{
    return m_impl->BlockRequested(nodeid, block, pit, mempool);
}

bool BlockDownloadManagerImpl::BlockRequested(NodeId nodeid, const CBlockIndex& block,
                                              std::list<QueuedBlock>::iterator** pit,
                                              CTxMemPool* mempool)
{
    const uint256& hash{block.GetBlockHash()};

    auto* state = Assert(GetPeerState(*this, nodeid));

    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    // Short-circuit most stuff in case it is from the same node
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        if (range.first->second.first == nodeid) {
            if (pit) {
                *pit = &range.first->second.second;
            }
            return false;
        }
    }

    // Make sure it's not being fetched already from same peer.
    RemoveBlockRequest(hash, nodeid);

    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(),
            {&block, std::unique_ptr<PartiallyDownloadedBlock>(pit ? new PartiallyDownloadedBlock(mempool) : nullptr)});
    if (state->vBlocksInFlight.size() == 1) {
        // We're starting a block download (batch) from this peer.
        state->m_downloading_since = GetTime<std::chrono::microseconds>();
        m_peers_downloading_from++;
    }
    auto itInFlight = mapBlocksInFlight.insert(std::make_pair(hash, std::make_pair(nodeid, it)));
    if (pit) {
        *pit = &itInFlight->second.second;
    }
    return true;
}

bool BlockDownloadManager::TipMayBeStale(std::chrono::seconds now, int64_t n_pow_target_spacing)
{
    return m_impl->TipMayBeStale(now, n_pow_target_spacing);
}

bool BlockDownloadManagerImpl::TipMayBeStale(std::chrono::seconds now, int64_t n_pow_target_spacing)
{
    if (m_last_tip_update.load() == 0s) {
        m_last_tip_update = now;
        return false;
    }
    return m_last_tip_update.load() < now - std::chrono::seconds{n_pow_target_spacing * 3} && mapBlocksInFlight.empty();
}

void BlockDownloadManager::SetLastTipUpdate(std::chrono::seconds time)
{
    m_impl->m_last_tip_update = time;
}

std::chrono::seconds BlockDownloadManager::GetLastTipUpdate() const
{
    return m_impl->m_last_tip_update.load();
}

void BlockDownloadManager::ProcessBlockAvailability(NodeId nodeid)
{
    m_impl->ProcessBlockAvailability(nodeid);
}

void BlockDownloadManagerImpl::ProcessBlockAvailability(NodeId nodeid)
{
    auto* state = Assert(GetPeerState(*this, nodeid));

    if (!state->hashLastUnknownBlock.IsNull()) {
        const CBlockIndex* pindex = m_opts.m_chainman.m_blockman.LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->nChainWork > 0) {
            if (state->pindexBestKnownBlock == nullptr || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

void BlockDownloadManager::UpdateBlockAvailability(NodeId nodeid, const uint256& hash)
{
    m_impl->UpdateBlockAvailability(nodeid, hash);
}

void BlockDownloadManagerImpl::UpdateBlockAvailability(NodeId nodeid, const uint256& hash)
{
    auto* state = Assert(GetPeerState(*this, nodeid));

    ProcessBlockAvailability(nodeid);

    const CBlockIndex* pindex = m_opts.m_chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex && pindex->nChainWork > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == nullptr || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
            state->pindexBestKnownBlock = pindex;
        }
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

} // namespace node
