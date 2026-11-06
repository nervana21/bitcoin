// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SCRIPT_VERIFY_H
#define BITCOIN_CONSENSUS_SCRIPT_VERIFY_H

#include <script/interpreter.h>
#include <script/verify_flags.h>

/** Set of script verify flags that may be enforced at the consensus level
 *  (for some combination of chain params and chain state).
 */
inline constexpr script_verify_flags CONSENSUS_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_NONE
    | SCRIPT_VERIFY_P2SH
    | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_TAPROOT
    | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_NULLDUMMY
};

#endif // BITCOIN_CONSENSUS_SCRIPT_VERIFY_H
