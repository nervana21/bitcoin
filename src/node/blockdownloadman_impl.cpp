// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockdownloadman.h>
#include <node/blockdownloadman_impl.h>

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

} // namespace node
