#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license.

"""
Legacy LevelDB coverage for abort-on-UTXO-deserialize (see master
feature_utxo_abort_on_error).

With kernel::CoinsStore, coin records are checksummed and applied during
Load() at open. GetCoin is an in-memory map lookup, so the old plyvel
tamper path (lazy deserialize during ConnectBlock) no longer exists.
Corrupt coins.dat fails open instead; feature_init.py covers that.

Skip until a CoinsStore-shaped way to exercise CCoinsViewErrorCatcher
during block connection exists.
"""

from test_framework.test_framework import BitcoinTestFramework, SkipTest


class UTXOAbortOnErrorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        raise SkipTest(
            "CoinsStore loads coins at open; LevelDB lazy-deserialize abort path is gone"
        )

    def run_test(self):
        pass


if __name__ == '__main__':
    UTXOAbortOnErrorTest(__file__).main()
