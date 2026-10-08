// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKTREE_MIGRATION_H
#define BITCOIN_NODE_BLOCKTREE_MIGRATION_H

#include <util/fs.h>

namespace Consensus {
struct Params;
}
namespace util {
class SignalInterrupt;
namespace log {
class Logger;
}
} // namespace util

namespace node {

/**
 * If block_tree_dir still holds a legacy LevelDB index (CURRENT marker), migrate
 * its contents into BlockTreeStore and remove the LevelDB files.
 *
 * Lives only in bitcoin_node (links LevelDB). Call from bitcoind init before
 * constructing ChainstateManager / BlockManager. Kernel consumers and
 * bitcoin-chainstate do not call this; they refuse leftover LevelDB indexes
 * unless wipe/reindex removes the files first.
 *
 * No-op when CURRENT is absent, or when wipe_block_tree_data is set (BlockManager
 * removes legacy files on open). Throws kernel::BlockTreeStoreError on failure
 * or when asked to migrate a read-only tree.
 */
void MaybeMigrateLegacyBlockTree(
    util::log::Logger& logger,
    const fs::path& block_tree_dir,
    const Consensus::Params& consensus_params,
    const util::SignalInterrupt& interrupt,
    bool wipe_block_tree_data,
    bool read_only);

} // namespace node

#endif // BITCOIN_NODE_BLOCKTREE_MIGRATION_H
