// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/cs_main.h>

#include <util/check.h>

#include <atomic>

RecursiveMutex cs_main;

namespace kernel {
namespace {
std::atomic<const void*> g_validation_mutex_owner{nullptr};
} // namespace

void RegisterValidationMutexOwner(const void* owner)
{
    const void* expected{nullptr};
    Assert(g_validation_mutex_owner.compare_exchange_strong(expected, owner));
}

void UnregisterValidationMutexOwner(const void* owner)
{
    Assert(g_validation_mutex_owner.load() == owner);
    g_validation_mutex_owner.store(nullptr);
}
} // namespace kernel
