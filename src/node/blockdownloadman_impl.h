// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H

#include <node/blockdownloadman.h>

#include <kernel/cs_main.h>

#include <map>

namespace node {

class BlockDownloadManagerImpl {
public:
    BlockDownloadOptions m_opts;

    struct PeerBlockDownloadState {
        BlockDownloadConnectionInfo m_connection_info;
        bool fPreferredDownload{false};

        explicit PeerBlockDownloadState(const BlockDownloadConnectionInfo& info)
            : m_connection_info{info} {}
    };

    std::map<NodeId, PeerBlockDownloadState> m_peer_info GUARDED_BY(::cs_main);

    int m_num_preferred_download_peers GUARDED_BY(::cs_main){0};

    explicit BlockDownloadManagerImpl(const BlockDownloadOptions& options)
        : m_opts{options} {}

    void ConnectedPeer(NodeId nodeid, const BlockDownloadConnectionInfo& info) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_IMPL_H
