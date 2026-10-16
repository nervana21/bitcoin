// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_UTXO_SNAPSHOT_H
#define BITCOIN_NODE_UTXO_SNAPSHOT_H

//! Compatibility shim: assumeutxo snapshot helpers live in kernel.
#include <kernel/utxo_snapshot.h>

namespace node {
using kernel::SnapshotMetadata;
using kernel::SNAPSHOT_BLOCKHASH_FILENAME;
using kernel::SNAPSHOT_CHAINSTATE_SUFFIX;
using kernel::WriteSnapshotBaseBlockhash;
using kernel::ReadSnapshotBaseBlockhash;
using kernel::FindAssumeutxoChainstateDir;
} // namespace node

#endif // BITCOIN_NODE_UTXO_SNAPSHOT_H
