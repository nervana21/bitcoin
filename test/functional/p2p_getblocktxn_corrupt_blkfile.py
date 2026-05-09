#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""GETBLOCKTXN must not crash when ReadBlock fails (e.g. bad merkle on disk).

Build a tip past MAX_GETBLOCKTXN_DEPTH, corrupt the oldest in-window block on
disk (same blk*.dat + MAGIC_BYTES + util_xor pattern as feature_reindex),
restart with -checkblocks=1 so startup skips it, then send GETBLOCKTXN.
"""

from test_framework.messages import (
    MAGIC_BYTES,
    BlockTransactionsRequest,
    msg_getblocktxn,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    util_xor,
)

# Mirror p2p_compactblocks.py / net_processing MAX_BLOCKTXN_DEPTH.
MAX_GETBLOCKTXN_DEPTH = 10


def corrupt_block_merkle_at_height(blocks_dir, xor_key, height):
    """Flip first hashMerkleRoot byte at chain height (0 = genesis).

    Walks blk*.dat like feature_reindex out_of_order: decode with util_xor,
    find regtest magic records, mutate, write xor'd bytes back.
    """
    magic = MAGIC_BYTES["regtest"]
    blk_paths = sorted(blocks_dir.glob("blk*.dat"))
    assert blk_paths, f"no blk*.dat under {blocks_dir}"
    n = 0
    for path in blk_paths:
        data = bytearray(util_xor(path.read_bytes(), xor_key, offset=0))
        pos = 0
        while pos + 8 <= len(data):
            assert_equal(bytes(data[pos : pos + 4]), magic)
            size = int.from_bytes(data[pos + 4 : pos + 8], "little")
            assert size >= 80, f"bogus block size {size} at {path}:{pos}"
            end = pos + 8 + size
            assert end <= len(data), f"truncated record at {path}:{pos}"
            if n == height:
                data[pos + 8 + 36] ^= 0xFF  # hashMerkleRoot
                path.write_bytes(util_xor(bytes(data), xor_key, offset=0))
                return
            n += 1
            pos = end
    raise AssertionError(f"height {height} not found under {blocks_dir}")


class GetBlockTxnCorruptBlkfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-checkblocks=1", "-checklevel=0"]]

    def run_test(self):
        node = self.nodes[0]
        # tip = depth+1 ⇒ height 1 is oldest still served via GETBLOCKTXN
        self.generate(node, MAX_GETBLOCKTXN_DEPTH + 1)
        tip = node.getblockcount()
        corrupt_height = tip - MAX_GETBLOCKTXN_DEPTH
        bad_hash = node.getblockhash(corrupt_height)

        self.stop_node(0)
        corrupt_block_merkle_at_height(node.blocks_path, node.read_xor_key(), corrupt_height)

        self.start_node(0, extra_args=self.extra_args[0])
        assert_equal(node.getblockcount(), tip)

        peer = node.add_p2p_connection(P2PInterface())
        msg = msg_getblocktxn()
        msg.block_txn_request = BlockTransactionsRequest(int(bad_hash, 16), [0])
        # Merkle flip fails CheckProofOfWork ("Errors in block header") before
        # the expected-hash check. Either way ReadBlock returns false; the
        # property under test is the GETBLOCKTXN early return (no abort).
        with node.assert_debug_log(
                expected_msgs=["ReadBlock failed", "not sending GETBLOCKTXN reply"],
                timeout=10):
            peer.send_and_ping(msg)


if __name__ == "__main__":
    GetBlockTxnCorruptBlkfileTest(__file__).main()
