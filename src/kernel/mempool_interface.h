// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
#define BITCOIN_KERNEL_MEMPOOL_INTERFACE_H

#include <kernel/mempool_entry.h>
#include <kernel/result.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlock;
class Chainstate;
class CCoinsViewCache;
class CTransaction;

namespace kernel {

/**
 * A base class defining functions for notifying about certain kernel
 * events.
 */
class Mempool
{
public:
    virtual ~Mempool() = default;

    virtual void removeRecursive(const CTransaction& tx) {}
    virtual std::vector<RemovedMempoolTransactionInfo> removeForBlock(const CBlock& block) { return {}; }
    virtual size_t measureExternalDynamicMemoryUsage() { return 0; }
    virtual void addTransactionsUpdated(uint32_t n) {}
    virtual void check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) {}
    virtual bool empty() { return true; }
    virtual size_t maxSizeBytes() { return 0; }
    //! Drop any transactions saved from a previous reorg and start a new queue.
    virtual void ResetDisconnectedTransactions() {}
    //! Save block transactions so they can be restored after a reorg. Empty when no pool is plugged in.
    virtual std::vector<CTransactionRef> AddDisconnectedTransactions(const std::vector<CTransactionRef>&) { return {}; }
    //! Drop saved transactions that the new chain already confirms.
    virtual void RemoveDisconnectedForBlock(const std::vector<CTransactionRef>&) {}
    //! Re-add or erase the saved transactions. The base implementation has no queue.
    virtual kernel::FlushResult<> MaybeUpdateMempoolForReorg(Chainstate&, bool) { return {}; }
    virtual void BeginChainstateUpdate() {}
    virtual void EndChainstateUpdate() {}
};

} // namespace kernel

#endif // BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
