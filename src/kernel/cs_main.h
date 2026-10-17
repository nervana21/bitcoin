// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CS_MAIN_H
#define BITCOIN_KERNEL_CS_MAIN_H

#include <sync.h>

/**
 * Process-wide validation mutex (Plato Ideal: published lock protocol).
 *
 * Storage is process-wide for Clang TSA / LOCK(cs_main) compatibility.
 * ChainstateManager is the sole logical owner: it binds `GetMutex()` to this
 * object via a reference member and registers itself so a second manager in
 * the same process Asserts. Physical per-instance storage (multi-engine in one
 * process) remains a later product step.
 *
 * ## What it guards
 * - Block index / BlockManager metadata used for validation
 * - Chainstate tip, coins views/caches, assumeutxo dual-chainstate pointers
 * - Validation caches and related chainstate fields marked GUARDED_BY(::cs_main)
 *
 * ## What it does not guard alone
 * - Policy mempool contents: CTxMemPool::cs (see that class). Mempool updates that
 *   touch the UTXO view still take cs_main as well (e.g. AcceptToMemoryPool).
 * - Long CPU work that must not starve other threads: release cs_main first.
 *   Example: MaybeValidateSnapshot hashes the UTXO set LOCKS_EXCLUDED(::cs_main).
 * - ActivateBestChain: LOCKS_EXCLUDED(::cs_main); it takes the lock in short steps.
 *
 * ## Nesting / ordering
 * - Prefer annotations on each API (EXCLUSIVE_LOCKS_REQUIRED / LOCKS_EXCLUDED).
 * - Do not hold cs_main across ValidationInterface callbacks that may re-enter
 *   ActivateBestChain (deadlock risk).
 * - Node index restart / service changes after assumeutxo
 *   (Options::target_block_reached) must run without cs_main.
 *
 * ## External (C API) consumers
 * - Prefer btck_* entry points; they take and release locks internally.
 * - Do not assume a second ChainstateManager in-process gets an independent lock
 *   while this global remains.
 */
extern RecursiveMutex cs_main;

namespace kernel {
/** Register the sole ChainstateManager that owns the process validation mutex. */
void RegisterValidationMutexOwner(const void* owner);
/** Clear registration when that ChainstateManager is destroyed. */
void UnregisterValidationMutexOwner(const void* owner);
} // namespace kernel

#endif // BITCOIN_KERNEL_CS_MAIN_H
