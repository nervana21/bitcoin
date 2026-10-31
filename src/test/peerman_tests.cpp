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
#include <script/solver.h>
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
#include <vector>

// Build a fake peer network address from a raw IPv4 integer.
static CService ip(uint32_t i)
{
    // Hold the IPv4 address bytes in the OS shape.
    struct in_addr s;
    // Store the caller number as the address.
    s.s_addr = i;
    // Wrap those bytes as a Bitcoin Core network address object.
    CNetAddr net_addr{s};
    // Use the default P2P port for this chain (regtest here).
    const uint16_t default_port{Params().GetDefaultPort()};
    // Pair address plus port into a full service endpoint.
    CService service{net_addr, default_port};
    return service;
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
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
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

// Look at what this peer is about to send. Return true if a BLOCK is queued.
static bool OutboundHasBlock(CNode& peer)
{
    // Protect the send queues while we read them.
    LOCK(peer.cs_vSend);
    // First check messages already sitting in the high level send list.
    for (const auto& msg : peer.vSendMsg) {
        // Compare the message type string to the BLOCK command name.
        const bool is_block_message{msg.m_type == NetMsgType::BLOCK};
        if (is_block_message) {
            // Found a full block reply waiting in vSendMsg.
            return true;
        }
    }
    // Next ask the transport layer what bytes are ready for the socket.
    // Pass false so we do not pretend a next message is already queued.
    const Transport::BytesToSend bytes_to_send{peer.m_transport->GetBytesToSend(false)};
    // First tuple field is the byte span that would go out next.
    const std::span<const uint8_t> to_send{std::get<0>(bytes_to_send)};
    // Third tuple field is the message type name for those bytes.
    const std::string& msg_type{std::get<2>(bytes_to_send)};
    // Empty span means nothing is ready to send from the transport.
    const bool has_bytes{!to_send.empty()};
    if (!has_bytes) {
        return false;
    }
    // Bytes exist. Only count them as a block when the type name matches BLOCK.
    const bool transport_has_block{msg_type == NetMsgType::BLOCK};
    if (!transport_has_block) {
        return false;
    }
    return true;
}

// Feed one getdata for hash. Check whether a BLOCK reply appears. Then clear the send buffer.
static void CheckGetdataBlock(ConnmanTestMsg& connman, CNode& peer, const uint256& hash, bool expect_block)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    // Build an inventory entry that asks for a witness block by this hash.
    CInv block_inv{MSG_WITNESS_BLOCK, hash};
    // Put that single inventory into a vector (getdata carries a list).
    std::vector<CInv> inv_list;
    inv_list.push_back(block_inv);
    // Serialize a getdata net message that holds that inventory list.
    CSerializedNetMsg getdata_msg{NetMsg::Make(NetMsgType::GETDATA, inv_list)};
    // Deliver the message into the peer as if it arrived on the wire.
    const bool received{connman.ReceiveMsgFrom(peer, std::move(getdata_msg))};
    // The test harness must accept the injected message.
    BOOST_REQUIRE(received);
    // Allow sending so ProcessMessagesOnce is free to push a reply.
    peer.fPauseSend = false;
    // Run one receive or process step so PeerManager can handle getdata.
    (void)connman.ProcessMessagesOnce(peer);
    // Inspect the outbound path for a BLOCK reply.
    const bool saw_block{OutboundHasBlock(peer)};
    // Compare what we saw to what this call site expected.
    BOOST_CHECK_EQUAL(saw_block, expect_block);
    // Drop any leftover outbound bytes so the next check starts clean.
    connman.FlushSendBuffer(peer);
}

// Prove tip getdata still works when BLOCK_HAVE_DATA is cleared.
// The bytes must come from m_most_recent_block.
// A parent hash that is not that cache entry must be refused.
BOOST_FIXTURE_TEST_CASE(getdata_serves_recent_block_without_have_data, TestChain100Setup)
{
    // Use the test connman helpers (handshake, inject messages, flush).
    ConnmanTestMsg& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    // PeerManager owns ProcessGetBlockData and the recent block cache.
    PeerManager& peerman{*m_node.peerman};
    // Cast so we can call JumpOutOfIbd on the test chainstate manager.
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    // IBD blocks some serving paths. Leave IBD if the fixture still thinks we are syncing.
    const bool still_in_ibd{chainman.IsInitialBlockDownload()};
    if (still_in_ibd) {
        chainman.JumpOutOfIbd();
    }

    // TestingSetup does not register peerman on the validation signals bus.
    // NewPoWValidBlock must run so m_most_recent_block gets filled.
    m_node.validation_signals->RegisterValidationInterface(&peerman);

    // Coinbase payout script for the blocks we are about to mine.
    const CPubKey coinbase_pubkey{coinbaseKey.GetPubKey()};
    const CScript scriptPubKey{GetScriptForRawPubKey(coinbase_pubkey)};
    // Mine two blocks past the fixture tip.
    // The second NewPoWValidBlock advances m_highest_fast_announce
    // and refreshes m_most_recent_block onto the final tip.
    const std::vector<CMutableTransaction> no_extra_txs{};
    (void)CreateAndProcessBlock(no_extra_txs, scriptPubKey);
    // Mine the tip we will request over getdata.
    const CBlock tip_block{CreateAndProcessBlock(no_extra_txs, scriptPubKey)};
    // Remember that tip block hash for later getdata calls.
    const uint256 tip_hash{tip_block.GetHash()};

    // Read the active tip pointer under cs_main.
    CBlockIndex* tip{nullptr};
    {
        LOCK(::cs_main);
        tip = m_node.chainman->ActiveChain().Tip();
    }
    // The chain must have a tip after mining.
    BOOST_REQUIRE(tip);
    // That tip index must match the hash we just mined.
    const uint256 tip_index_hash{tip->GetBlockHash()};
    BOOST_REQUIRE(tip_index_hash == tip_hash);
    // Parent is the previous block index. We will request it as a negative control.
    CBlockIndex* parent{tip->pprev};
    BOOST_REQUIRE(parent);
    // Cache the parent hash so we can ask for it after clearing HAVE_DATA.
    const uint256 parent_hash{parent->GetBlockHash()};

    // Build a fake inbound peer address on 160.176.192.1.
    const CService peer_service{ip(0xa0b0c001)};
    const CAddress peer_address{peer_service, NODE_NONE};
    // Empty address used for the local-side constructor argument.
    const CAddress empty_address{};
    // Construct a peer object that Handshake can mark as connected.
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               peer_address,
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               empty_address,
               /*addrNameIn=*/"",
               ConnectionType::INBOUND,
               /*inbound_onion=*/false,
               /*network_key=*/0};

    // Message processing requires this mutex (same as production PeerManager paths).
    LOCK(NetEventsInterface::g_msgproc_mutex);
    // Services we advertise and expect. Full blocks plus witness.
    const ServiceFlags network_and_witness{ServiceFlags(NODE_NETWORK | NODE_WITNESS)};
    // Complete the version handshake so getdata is processed as a real peer.
    connman.Handshake(
        /*node=*/peer,
        /*successfully_connected=*/true,
        /*remote_services=*/network_and_witness,
        /*local_services=*/network_and_witness,
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);
    // Clear handshake traffic so OutboundHasBlock only sees later replies.
    connman.FlushSendBuffer(peer);

    // Baseline. Tip must be served while HAVE_DATA is still set (recent cache path).
    CheckGetdataBlock(connman, peer, tip_hash, /*expect_block=*/true);

    {
        // Mutate index status bits under cs_main.
        LOCK(::cs_main);
        // Confirm both indexes currently claim disk data.
        const uint32_t tip_have_data_bits{tip->nStatus & BLOCK_HAVE_DATA};
        const uint32_t parent_have_data_bits{parent->nStatus & BLOCK_HAVE_DATA};
        BOOST_REQUIRE(tip_have_data_bits != 0);
        BOOST_REQUIRE(parent_have_data_bits != 0);
        // Clear HAVE_DATA on the tip so disk lookup would fail.
        tip->nStatus = tip->nStatus & ~BLOCK_HAVE_DATA;
        // Clear HAVE_DATA on the parent the same way.
        parent->nStatus = parent->nStatus & ~BLOCK_HAVE_DATA;
    }

    // Tip must still be served from m_most_recent_block after the clear.
    CheckGetdataBlock(connman, peer, tip_hash, /*expect_block=*/true);
    // Parent is not the recent cache entry. Request must not produce a BLOCK.
    CheckGetdataBlock(connman, peer, parent_hash, /*expect_block=*/false);

    // Tear down the peer the same way production does on disconnect.
    peerman.FinalizeNode(peer);
    // Stop delivering validation callbacks to peerman for this test.
    m_node.validation_signals->UnregisterValidationInterface(&peerman);
}

BOOST_AUTO_TEST_SUITE_END()
