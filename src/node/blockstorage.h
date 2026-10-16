// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKSTORAGE_H
#define BITCOIN_NODE_BLOCKSTORAGE_H

//! Compatibility shim: BlockManager lives in kernel. Existing node::
//! qualified names and `#include <node/blockstorage.h>` keep working.
#include <kernel/blockstorage.h>

namespace node {
using kernel::BLOCKFILE_CHUNK_SIZE;
using kernel::UNDOFILE_CHUNK_SIZE;
using kernel::MAX_BLOCKFILE_SIZE;
using kernel::STORAGE_HEADER_BYTES;
using kernel::UNDO_DATA_DISK_OVERHEAD;
using kernel::BlockMap;
using kernel::BlockfileType;
using kernel::BlockfileCursor;
using kernel::CBlockIndexWorkComparator;
using kernel::CBlockIndexHeightOnlyComparator;
using kernel::PruneLockInfo;
using kernel::BlockManager;
using kernel::ImportBlocks;
} // namespace node

#endif // BITCOIN_NODE_BLOCKSTORAGE_H
