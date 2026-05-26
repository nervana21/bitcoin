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

} // namespace node
