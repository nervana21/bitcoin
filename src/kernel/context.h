// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CONTEXT_H
#define BITCOIN_KERNEL_CONTEXT_H

namespace kernel {
//! Thin C++ context for internal bitcoin_kernel / node wiring (sha256 self-check
//! and related init). Opaque handle state for external consumers lives in the
//! C API's `btck_Context` (see bitcoinkernel.h / bitcoinkernel.cpp). Keep this
//! struct simple; complex state belongs on unique_ptr members or on btck_Context.
//!
//! Layers are intentional: `kernel::Context` = in-process C++ link; `btck_Context`
//! = stable-ish FFI boundary. Do not merge them without a versioned plan.
struct Context {
    Context();
};
} // namespace kernel

#endif // BITCOIN_KERNEL_CONTEXT_H
