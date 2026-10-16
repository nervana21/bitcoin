// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_DB_OPTIONS_H
#define BITCOIN_KERNEL_DB_OPTIONS_H

//! User-controlled store performance and debug options shared by kernel
//! consumers. Kept free of LevelDB types so kernel opts headers do not pull
//! dbwrapper / leveldb.
struct DBOptions {
    //! Compact the store on startup when the backend supports it.
    bool force_compact = false;
};

#endif // BITCOIN_KERNEL_DB_OPTIONS_H
