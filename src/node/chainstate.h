// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_H
#define BITCOIN_NODE_CHAINSTATE_H

//! Compatibility shim: chainstate load helpers live in kernel.
#include <kernel/chainstate.h>

namespace node {
using kernel::ChainstateLoadOptions;
using kernel::ChainstateLoadError;
using kernel::LoadChainstate;
using kernel::VerifyLoadedChainstate;
} // namespace node

#endif // BITCOIN_NODE_CHAINSTATE_H
