#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""GETBLOCKTXN must not crash when ReadBlock fails (e.g. bad merkle on disk).

Mine smallest chain where a non-tip block is still in GETBLOCKTXN range
(height >= tip - 10): tip 11, corrupt height 1. -checkblocks=1 skips it at
startup. Clean chain + -blocksxor=0 so blk records are raw regtest magic.
"""

from test_framework.messages import (
    MAGIC_BYTES,
    BlockTransactionsRequest,
    msg_getblocktxn,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def corrupt_chain_height_block_in_blocksdir(blocks_dir, chain_height):
    """Flip merkle byte at chain height (walk all blk*.dat; height 0 = genesis)."""
    regtest_magic = MAGIC_BYTES["regtest"]
    blk_paths = sorted(blocks_dir.glob("blk*.dat"))
    assert blk_paths, f"no blk*.dat under {blocks_dir}"
    height = 0
    for blk_path in blk_paths:
        data = bytearray(blk_path.read_bytes())
        pos = 0
        while pos + 8 <= len(data):
            magic = bytes(data[pos : pos + 4])
            blksize = int.from_bytes(data[pos + 4 : pos + 8], "little")
            assert_equal(magic, regtest_magic)
            assert blksize >= 80, f"bogus block size {blksize} at {blk_path}:{pos}"
            record_end = pos + 8 + blksize
            assert record_end <= len(data), f"truncated record at {blk_path}:{pos}"
            if height == chain_height:
                flip_at = pos + 8 + 36  # first byte of hashMerkleRoot
                data[flip_at] ^= 0xFF
                blk_path.write_bytes(data)
                return
            height += 1
            pos = record_end
    raise AssertionError(f"height {chain_height} not found under {blocks_dir}")


class P2PConn(P2PInterface):
    pass


class GetBlockTxnCorruptBlkfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True  # no cache xor.dat vs -blocksxor=0 clash
        self.extra_args = [[
            "-checkblocks=1",
            "-checklevel=0",
            "-blocksxor=0",
        ]]

    def run_test(self):
        node = self.nodes[0]
        # tip 11 ⇒ height 1 is oldest in GETBLOCKTXN window (>= tip - 10)
        self.generate(node, 11)
        tip_height = node.getblockcount()
        assert_equal(tip_height, 11)
        corrupt_height = tip_height - 10
        assert_equal(corrupt_height, 1)
        bad_hash = node.getblockhash(corrupt_height)

        self.stop_node(0)
        corrupt_chain_height_block_in_blocksdir(node.blocks_path, corrupt_height)

        self.start_node(0, extra_args=self.extra_args[0])
        assert_equal(node.getblockcount(), tip_height)
        peer = node.add_p2p_connection(P2PConn())
        msg = msg_getblocktxn()
        msg.block_txn_request = BlockTransactionsRequest(int(bad_hash, 16), [0])
        with node.assert_debug_log(
                expected_msgs=["GetHash() doesn't match index"],
                timeout=10):
            peer.send_and_ping(msg)


if __name__ == "__main__":
    GetBlockTxnCorruptBlkfileTest(__file__).main()
