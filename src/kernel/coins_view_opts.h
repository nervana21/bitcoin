// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_COINS_VIEW_OPTS_H
#define BITCOIN_KERNEL_COINS_VIEW_OPTS_H

#include <kernel/caches.h>

#include <cstdint>

//! User-controlled coins-view performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    uint64_t batch_write_bytes{DEFAULT_DB_CACHE_BATCH};
    //! If non-zero, randomly exit when the database is flushed with (1/ratio) probability.
    int simulate_crash_ratio{0};
};

#endif // BITCOIN_KERNEL_COINS_VIEW_OPTS_H
