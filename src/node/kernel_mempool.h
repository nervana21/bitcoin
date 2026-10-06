// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_KERNEL_MEMPOOL_H
#define BITCOIN_NODE_KERNEL_MEMPOOL_H

#include <kernel/mempool_interface.h>

#include <kernel/disconnected_transactions.h>

#include <cstddef>
#include <cstdint>
#include <memory>

class CBlock;
class Chainstate;
class CCoinsViewCache;
class CTransaction;
class CTxMemPool;
class DisconnectedBlockTransactions;

namespace node {

class KernelMempool: public kernel::Mempool
{
public:
    explicit KernelMempool(CTxMemPool& mempool)
        : m_mempool{mempool} {}
    ~KernelMempool() override;

    void removeRecursive(const CTransaction& tx) override;
    std::vector<RemovedMempoolTransactionInfo> removeForBlock(const CBlock& block) override;
    size_t measureExternalDynamicMemoryUsage() override;
    void addTransactionsUpdated(uint32_t n) override;
    void check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) override;
    bool empty() override;
    size_t maxSizeBytes() override;
    void ResetDisconnectedTransactions() override;
    std::vector<CTransactionRef> AddDisconnectedTransactions(const std::vector<CTransactionRef>& vtx) override;
    void RemoveDisconnectedForBlock(const std::vector<CTransactionRef>& vtx) override;
    kernel::FlushResult<> MaybeUpdateMempoolForReorg(Chainstate& active_chainstate, bool fAddToMempool) override;
    void BeginChainstateUpdate() override;
    void EndChainstateUpdate() override;

private:
    CTxMemPool& m_mempool;
    //! Transactions from blocks disconnected during the current reorg. Node-only.
    std::unique_ptr<DisconnectedBlockTransactions> m_disconnected;
};

} // namespace node

#endif // BITCOIN_NODE_KERNEL_MEMPOOL_H
