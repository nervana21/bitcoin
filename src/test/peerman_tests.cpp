// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <net.h>
#include <net_processing.h>
#include <node/block_template_manager.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using kernel::AbortFailure;
using kernel::FlushResult;

static CService TestPeerIp(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(node::NodeContext& node, FakeNodeClock& clock, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    clock.set(block_time); // update time so the block is created with it
    auto& block_template_manager{*Assert(node.block_template_manager)};
    auto block_template{block_template_manager.CreateNewTemplate({})};
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->block};
    while (!CheckProofOfWork(block.GetHash(), block.nBits, node.chainman->GetConsensus())) ++block.nNonce;
    block.fChecked = true; // little speedup
    clock.set(curr_time); // process block at current time
    FlushResult<void, AbortFailure> process_result;
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr, process_result));
    Assert(process_result);
    node.validation_signals->SyncWithValidationInterfaceQueue(); // drain events queue
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    FakeNodeClock clock{};
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    clock.set(std::chrono::seconds{tip_block_time + 1}); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we disallow limited peers connections when we are further than the limited peers safety window
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * 2};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1) * 10 minutes ahead the tip's time.
    mineBlock(m_node, clock, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, clock, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    clock += std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(peerman_getdata_tests, TestChain100Setup)

static bool OutboundHasBlock(CNode& peer)
{
    LOCK(peer.cs_vSend);
    for (const auto& msg : peer.vSendMsg) {
        if (msg.m_type == NetMsgType::BLOCK) return true;
    }
    const auto& [to_send, _more, msg_type]{peer.m_transport->GetBytesToSend(false)};
    return !to_send.empty() && msg_type == NetMsgType::BLOCK;
}

static void RequestBlock(ConnmanTestMsg& connman, CNode& peer, const uint256& hash)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    std::vector<CInv> inv;
    inv.emplace_back(MSG_WITNESS_BLOCK, hash);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::GETDATA, inv)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
}

// NewPoWValidBlock publishes m_most_recent_block before BLOCK_HAVE_DATA.
// ProcessGetBlockData must still serve tip getdata from that cache.
BOOST_AUTO_TEST_CASE(getdata_serves_recent_block_without_have_data)
{
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    PeerManager& peerman{*m_node.peerman};
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    if (chainman.IsInitialBlockDownload()) {
        chainman.JumpOutOfIbd();
    }

    m_node.validation_signals->RegisterValidationInterface(&peerman);

    CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    // Two tips so NewPoWValidBlock must advance m_highest_fast_announce and
    // refresh m_most_recent_block for the final tip.
    (void)CreateAndProcessBlock({}, script_pub_key);
    std::shared_ptr<const CBlock> tip_block{
        std::make_shared<const CBlock>(CreateAndProcessBlock({}, script_pub_key))};

    CBlockIndex* tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(tip);
    BOOST_REQUIRE(tip->GetBlockHash() == tip_block->GetHash());
    CBlockIndex* parent{tip->pprev};
    BOOST_REQUIRE(parent);
    const uint256 tip_hash{tip->GetBlockHash()};
    const uint256 parent_hash{parent->GetBlockHash()};

    CAddress addr{TestPeerIp(0xa0b0c001), NODE_NONE};
    NodeId id{0};
    CNode peer{id++,
               /*sock=*/nullptr,
               addr,
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               CAddress(),
               /*addrNameIn=*/"",
               ConnectionType::INBOUND,
               /*inbound_onion=*/false,
               /*network_key=*/0};

    LOCK(NetEventsInterface::g_msgproc_mutex);
    connman.Handshake(
        /*node=*/peer,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);
    connman.FlushSendBuffer(peer);

    // Harness control. Disk serve must work while HAVE_DATA is still set.
    RequestBlock(connman, peer, tip_hash);
    BOOST_REQUIRE(OutboundHasBlock(peer));
    connman.FlushSendBuffer(peer);

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(tip->nStatus & BLOCK_HAVE_DATA);
        BOOST_REQUIRE(parent->nStatus & BLOCK_HAVE_DATA);
        tip->nStatus &= ~BLOCK_HAVE_DATA;
        parent->nStatus &= ~BLOCK_HAVE_DATA;
    }

    // Tip must still be served from m_most_recent_block.
    RequestBlock(connman, peer, tip_hash);
    BOOST_CHECK(OutboundHasBlock(peer));
    connman.FlushSendBuffer(peer);

    // Parent is not the recent cache entry.
    RequestBlock(connman, peer, parent_hash);
    BOOST_CHECK(!OutboundHasBlock(peer));

    peerman.FinalizeNode(peer);
    m_node.validation_signals->UnregisterValidationInterface(&peerman);
}

BOOST_AUTO_TEST_SUITE_END()
