#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test GETBLOCKTXN does not abort when ReadBlock fails.

- Start a single node and generate past GETBLOCKTXN depth.
- Stop, corrupt an in-window block merkle root on disk.
- Restart with -checkblocks=1 so startup skips it.
- Send GETBLOCKTXN
- Verify ReadBlock failure is logged and the peer is disconnected.
"""
from test_framework.messages import BlockTransactionsRequest, msg_getblocktxn
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework

MAX_BLOCKTXN_DEPTH = 10
MERKLE_ROOT_OFFSET = 4 + 32 # nVersion + hashPrevBlock

class GetBlockTxnCorruptBlkfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-checkblocks=1", "-blocksxor=0"]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, MAX_BLOCKTXN_DEPTH + 1)
        corrupt_height = node.getblockcount() - MAX_BLOCKTXN_DEPTH
        corrupt_hash = node.getblockhash(corrupt_height)
        block_bytes = bytes.fromhex(node.getblock(corrupt_hash, False))

        self.stop_node(0)
        path = node.blocks_path / "blk00000.dat"
        data = bytearray(path.read_bytes())
        pos = data.find(block_bytes)
        assert pos >= 0
        data[pos + MERKLE_ROOT_OFFSET] ^= 0xFF
        path.write_bytes(data)

        self.start_node(0, extra_args=self.extra_args[0])
        peer = node.add_p2p_connection(P2PInterface())
        msg = msg_getblocktxn()
        corrupt = int(corrupt_hash, 16) # convert hex string to int
        msg.block_txn_request = BlockTransactionsRequest(corrupt, [0])
        with node.assert_debug_log(["Cannot load block from disk"], timeout=10):
            peer.send_without_ping(msg)
            peer.wait_for_disconnect()

if __name__ == "__main__":
    GetBlockTxnCorruptBlkfileTest(__file__).main()
