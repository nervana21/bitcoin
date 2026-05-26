// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADMAN_H
#define BITCOIN_NODE_BLOCKDOWNLOADMAN_H

#include <memory>

namespace node {

class BlockDownloadManagerImpl;

class BlockDownloadManager {
    const std::unique_ptr<BlockDownloadManagerImpl> m_impl;

public:
    ~BlockDownloadManager();
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADMAN_H
