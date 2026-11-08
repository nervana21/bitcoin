#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that it's not possible to start a second bitcoind instance using the same datadir or wallet,
or to run bitcoin-chainstate on the blocksdir of a running bitcoind.

The bitcoin-chainstate case proves BlockManager's blocksdir lock also stops the
kernel tool from opening the same blocks tree while bitcoind holds it.
"""
import random
import string
# Used to spawn bitcoin-chainstate as a child process in the blocksdir lock check.
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import (
    BITCOIN_PID_FILENAME_DEFAULT,
    ErrorMatch,
)
# Compare the child process exit code to the expected failure value 1.
from test_framework.util import assert_equal

class FilelockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.uses_wallet = None

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=None)
        self.nodes[0].start()
        self.nodes[0].wait_for_rpc_connection()

    def run_test(self):
        datadir = self.nodes[0].chain_path
        blocksdir = self.nodes[0].blocks_path
        self.log.info(f"Using datadir {datadir}")
        self.log.info(f"Using blocksdir {blocksdir}")

        self.log.info("Check that we can't start a second bitcoind instance using the same datadir")
        expected_msg = f"Error: Cannot obtain a lock on directory {datadir}. {self.config['environment']['CLIENT_NAME']} is probably already running."
        self.nodes[1].assert_start_raises_init_error(extra_args=[f'-datadir={self.nodes[0].datadir_path}', '-noserver'], expected_msg=expected_msg)

        self.log.info("Check that we can't start a second bitcoind instance using the same blocksdir")
        expected_msg = f"Error: Cannot obtain a lock on directory {blocksdir}. {self.config['environment']['CLIENT_NAME']} is probably already running."
        self.nodes[1].assert_start_raises_init_error(extra_args=[f'-blocksdir={self.nodes[0].datadir_path}', '-noserver'], expected_msg=expected_msg)

        self.log.info("Check that cookie and PID file are not deleted when attempting to start a second bitcoind using the same datadir/blocksdir")
        cookie_file = datadir / ".cookie"
        assert cookie_file.exists()  # should not be deleted during the second bitcoind instance shutdown
        pid_file = datadir / BITCOIN_PID_FILENAME_DEFAULT
        assert pid_file.exists()

        if self.is_wallet_compiled():
            wallet_name = ''.join([random.choice(string.ascii_lowercase) for _ in range(6)])
            self.nodes[0].createwallet(wallet_name=wallet_name)
            wallet_dir = self.nodes[0].wallets_path
            self.log.info("Check that we can't start a second bitcoind instance using the same wallet")
            expected_msg = f"Error: SQLiteDatabase: Unable to obtain an exclusive lock on the database, is it being used by another instance of {self.config['environment']['CLIENT_NAME']}?"
            self.nodes[1].assert_start_raises_init_error(extra_args=[f'-walletdir={wallet_dir}', f'-wallet={wallet_name}', '-noserver'], expected_msg=expected_msg, match=ErrorMatch.PARTIAL_REGEX)

        # Only run this check when the bitcoin-chainstate binary was built.
        if self.is_bitcoin_chainstate_compiled():
            # Tell the log what we are about to prove.
            self.log.info("Check that bitcoin-chainstate can't use the blocksdir of a running bitcoind")

            # Pick a fresh directory that will hold node1's block files.
            blocksdir_root = self.nodes[1].datadir_path / "blocksdir"
            # Create that directory on disk so -blocksdir can point at it.
            blocksdir_root.mkdir()

            # Start node1 with its blocks stored under blocksdir_root.
            # While node1 runs, BlockManager holds a lock on that blocks tree.
            node1_blocksdir_arg = f"-blocksdir={blocksdir_root}"
            self.start_node(1, extra_args=[node1_blocksdir_arg])

            # bitcoin-chainstate treats its datadir argument as a datadir, then
            # uses <datadir>/blocks as its blocksdir.
            # Pointing that datadir at blocksdir_root/<chain> means chainstate
            # sees node1's block files, with an empty block index of its own.
            chainstate_datadir = blocksdir_root / self.chain

            # The blocks subdirectory chainstate will try to lock.
            chainstate_blocks_path = chainstate_datadir / "blocks"

            # Build the argv for bitcoin-chainstate (path to the binary first).
            chainstate_argv = self.get_binaries().chainstate_argv()
            # Force regtest so the binary matches this test's chain.
            chainstate_argv_with_args = chainstate_argv + ["-regtest", chainstate_datadir]

            # Scale the short timeout by the test's timeout_factor for slow hosts.
            chainstate_timeout_seconds = 5 * self.options.timeout_factor

            # Run bitcoin-chainstate as a child process. Capture stdout/stderr as text.
            # Empty stdin: the tool may read stdin for block hex; we give it nothing.
            result = subprocess.run(
                chainstate_argv_with_args,
                input="",
                capture_output=True,
                text=True,
                timeout=chainstate_timeout_seconds,
            )

            # Lock failure must make the process exit with status 1.
            assert_equal(result.returncode, 1)

            # stdout must name the blocks path it could not lock.
            expected_lock_snippet = f"Cannot obtain a lock on directory {chainstate_blocks_path}."
            assert expected_lock_snippet in result.stdout

if __name__ == '__main__':
    FilelockTest(__file__).main()
