// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_mempool.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <cstddef>
#include <cstdint>

class CCoinsViewCache;

namespace node {

KernelMempool::~KernelMempool()
{
    if (m_disconnected) m_disconnected->clear();
}

void KernelMempool::removeRecursive(const CTransaction& tx)
{
    LOCK(m_mempool.cs);
    m_mempool.removeRecursive(tx, MemPoolRemovalReason::REORG);
}

std::vector<RemovedMempoolTransactionInfo> KernelMempool::removeForBlock(const CBlock& block)
{
    LOCK(m_mempool.cs);
    return m_mempool.removeForBlock(block.vtx);
}

size_t KernelMempool::measureExternalDynamicMemoryUsage()
{
    return m_mempool.DynamicMemoryUsage();
}

void KernelMempool::addTransactionsUpdated(uint32_t n)
{
    m_mempool.AddTransactionsUpdated(n);
}

void KernelMempool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight)
{
    LOCK(::cs_main);
    m_mempool.check(active_coins_tip, spendheight);
}

bool KernelMempool::empty()
{
    return m_mempool.size() == 0;
}

size_t KernelMempool::maxSizeBytes()
{
    return static_cast<size_t>(m_mempool.m_opts.max_size_bytes);
}

void KernelMempool::ResetDisconnectedTransactions()
{
    if (m_disconnected) m_disconnected->clear();
    m_disconnected = std::make_unique<DisconnectedBlockTransactions>(MAX_DISCONNECTED_TX_POOL_BYTES);
}

std::vector<CTransactionRef> KernelMempool::AddDisconnectedTransactions(const std::vector<CTransactionRef>& vtx)
{
    if (!m_disconnected) ResetDisconnectedTransactions();
    return m_disconnected->AddTransactionsFromBlock(vtx);
}

void KernelMempool::RemoveDisconnectedForBlock(const std::vector<CTransactionRef>& vtx)
{
    if (!m_disconnected) return;
    m_disconnected->removeForBlock(vtx);
}

kernel::FlushResult<> KernelMempool::MaybeUpdateMempoolForReorg(Chainstate& active_chainstate, bool fAddToMempool)
{
    if (!m_disconnected) return {};
    LOCK(::cs_main);
    LOCK(m_mempool.cs);
    // take() inside CTxMemPool::MaybeUpdateMempoolForReorg empties the queue.
    return m_mempool.MaybeUpdateMempoolForReorg(active_chainstate, *m_disconnected, fAddToMempool);
}

void KernelMempool::BeginChainstateUpdate()
{
    m_mempool.Lock();
}

void KernelMempool::EndChainstateUpdate()
{
    m_mempool.Unlock();
}

} // namespace node
