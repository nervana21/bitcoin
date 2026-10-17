// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_RESULT_H
#define BITCOIN_KERNEL_RESULT_H

#include <kernel/error.h>

#include <util/messages.h>
#include <util/result.h>

#include <optional>

//! @file Kernel result types for use with util::Result.
//!
//! Currently, many kernel functions trigger flushes and node shutdowns at low
//! levels deep within the code. This can make it hard to reason about when a
//! particular kernel function call might trigger a flush or shutdown.
//!
//! Ideally, low level functions would not trigger flushes and shutdowns at all,
//! but would just return information so higher level code can determine when to
//! flush and shut down. Progress toward that: AcceptBlock no longer flushes
//! (MaybePruneBlockFilesAfterAccept); tip/connect paths use
//! MaybeFlushChainstateIfNeeded / MaybeFlushChainstatePeriodic on
//! ChainstateManager; flush and engine helpers record AbortFailure without
//! notifying. API boundaries call NotifyFatalAbort (clears payload). Meantime,
//! FlushStatus and AbortFailure mark which calls can flush or abort.

namespace kernel {
//! Result type for functions that might trigger flushes, indicating whether
//! flushes were skipped, performed successfully, or failed.
enum class FlushStatus { SKIPPED, SUCCESS, FAILURE };

//! Result type for functions that might trigger fatal errors and need to abort
//! the node. `error` carries the typed fatal so callers can NotifyFatalAbort
//! without the deep layer calling Notifications::fatalError itself.
struct AbortFailure {
    bool fatal{false};
    std::optional<FatalError> error{};
};

template <typename SuccessType = void, typename FailureType = void>
using FlushResult = util::Result<SuccessType, FailureType, FlushStatus>;
} // namespace kernel

namespace util {
template<>
struct ResultTraits<kernel::FlushStatus>
{
    static void update(kernel::FlushStatus& dst, kernel::FlushStatus&& src)
    {
        using kernel::FlushStatus;
        if (dst == FlushStatus::FAILURE || src == FlushStatus::FAILURE) {
            dst = FlushStatus::FAILURE;
        } else if (dst == FlushStatus::SUCCESS || src == FlushStatus::SUCCESS) {
            dst = FlushStatus::SUCCESS;
        } else {
            dst = FlushStatus::SKIPPED;
        }
    }
};

template<>
struct ResultTraits<kernel::AbortFailure>
{
    static void update(kernel::AbortFailure& dst, kernel::AbortFailure&& src)
    {
        dst.fatal |= src.fatal;
        if (src.error) dst.error = std::move(src.error);
    }
};
} // namespace util

#endif // BITCOIN_KERNEL_RESULT_H
