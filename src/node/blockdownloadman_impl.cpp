// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockdownloadman.h>
#include <node/blockdownloadman_impl.h>

#include <util/check.h>

namespace node {

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

} // namespace node
