# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Kernel-safe utilities. Higher helpers (sock, asmap, bip32, …) live in
# bitcoin_common / bitcoin_node so check-deps can forbid kernel use.
add_library(bitcoin_util STATIC EXCLUDE_FROM_ALL
  chaintype.cpp
  check.cpp
  exception.cpp
  expected.cpp
  fees.cpp
  feefrac.cpp
  fs.cpp
  fs_helpers.cpp
  hasher.cpp
  messages.cpp
  moneystr.cpp
  rbf.cpp
  serfloat.cpp
  signalinterrupt.cpp
  strencodings.cpp
  syserror.cpp
  thread.cpp
  threadnames.cpp
  time.cpp
  time_nondet.cpp
  tokenpipe.cpp
  ../logging.cpp
  ../random.cpp
  ../randomenv.cpp
  ../streams.cpp
  ../sync.cpp
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:bcrypt>
)
