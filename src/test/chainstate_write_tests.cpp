// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// CBlockIndex / BLOCK_HAVE_DATA live in chain.h. The prune test clears that status bit in memory.
#include <chain.h>
// FlatFilePos names a (file number, byte offset) inside blk/rev flat files.
#include <flatfile.h>
#include <node/blockstorage.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <txdb.h>
#include <util/fs.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>

using kernel::ChainstateRole;

// Taken from validation.cpp
static constexpr auto DATABASE_WRITE_INTERVAL_MIN{50min};
static constexpr auto DATABASE_WRITE_INTERVAL_MAX{70min};

// Make opening `file` as a regular file fail on the next flush.
// Old code deleted the blk file forever. This keeps a .bak copy so a later RestoreFile can undo the sabotage.
static void InjectFileOpenFailure(const fs::path& file)
{
    // Move the real blk/rev bytes aside under file.bak.
    const fs::path backup_path{file + ".bak"};
    fs::rename(file, backup_path);
    // Put a directory where the file path was. open() then fails because the path is a directory, not a file.
    Assert(fs::create_directory(file));
}

// Undo InjectFileOpenFailure: remove the decoy directory and put the real file back.
static void RestoreFile(const fs::path& file)
{
    // Remove the empty directory that blocked file opens.
    Assert(fs::remove(file));
    // Rename file.bak back to the original path so FlushStateToDisk can open the blk file again.
    const fs::path backup_path{file + ".bak"};
    fs::rename(backup_path, file);
}

// Regtest chain with pruning on. -prune=1 enables prune mode. -fastprune shrinks prune thresholds so tests finish fast.
// Commit 1 made these extra_args actually reach BlockManager via ApplyArgsManOptions.
struct ManualPruneSetup : public TestChain100Setup {
    ManualPruneSetup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-prune=1", "-fastprune"}}} {}
};

BOOST_AUTO_TEST_SUITE(chainstate_write_tests)

BOOST_FIXTURE_TEST_CASE(chainstate_write_interval, TestingSetup)
{
    struct TestSubscriber final : CValidationInterface {
        bool m_did_flush{false};
        void ChainStateFlushed(const ChainstateRole&, const CBlockLocator&) override
        {
            m_did_flush = true;
        }
    };

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};
    FakeNodeClock clock{};

    // The first periodic flush sets m_next_write and does not flush
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    clock += DATABASE_WRITE_INTERVAL_MIN - 1min;
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    clock += DATABASE_WRITE_INTERVAL_MAX;
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(sub->m_did_flush);
}

// Test that we do PERIODIC flushes inside ActivateBestChain.
// This is necessary for reindex-chainstate to be able to periodically flush
// before reaching chain tip.
BOOST_FIXTURE_TEST_CASE(write_during_multiblock_activation, TestChain100Setup)
{
    struct TestSubscriber final : CValidationInterface
    {
        const CBlockIndex* m_tip{nullptr};
        const CBlockIndex* m_flushed_at_block{nullptr};
        void ChainStateFlushed(const ChainstateRole&, const CBlockLocator&) override
        {
            m_flushed_at_block = m_tip;
        }
        void UpdatedBlockTip(const CBlockIndex* block_index, const CBlockIndex*, bool) override {
            m_tip = block_index;
        }
    };

    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};

    // Pop two blocks from the tip
    const CBlockIndex* tip{chainstate.m_chain.Tip()};
    CBlockIndex* second_from_tip{tip->pprev};

    {
        LOCK2(m_node.chainman->GetMutex(), chainstate.MempoolMutex());
        chainstate.DisconnectTip(state_dummy, nullptr);
        chainstate.DisconnectTip(state_dummy, nullptr);
    }

    BOOST_CHECK_EQUAL(second_from_tip->pprev, chainstate.m_chain.Tip());

    // Set m_next_write to current time
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::FORCE_FLUSH);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), second_from_tip->pprev);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    // The next call to a PERIODIC write will flush
    m_clock += DATABASE_WRITE_INTERVAL_MAX;

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // ActivateBestChain back to tip
    chainstate.ActivateBestChain(state_dummy, nullptr);
    BOOST_CHECK_EQUAL(tip, chainstate.m_chain.Tip());
    // Check that we flushed inside ActivateBestChain while we were at the
    // second block from tip, since FlushStateToDisk is called with PERIODIC
    // inside the outer loop.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(sub->m_flushed_at_block, second_from_tip);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), second_from_tip);
}

BOOST_FIXTURE_TEST_CASE(chainstate_flush_failure_boundary, TestChain100Setup)
{
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state{};

    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH) && state.IsValid());
    auto* old_flushed{WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock())};

    mineBlocks(1);
    auto* new_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE_NE(old_flushed, new_tip);
    // Path of the blk*.dat that holds new_tip. Sabotage this path so the next flush cannot open it.
    const auto blk_file{WITH_LOCK(::cs_main, return chainstate.m_blockman.GetBlockPosFilename(new_tip->GetBlockPos()))};
    InjectFileOpenFailure(blk_file);

    ASSERT_DEBUG_LOG("Flushing block file to disk failed");
    bool flushed{chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH)};
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
    BOOST_CHECK(!flushed && state.IsError());
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), old_flushed);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.CoinsDB().GetBestBlock()) == old_flushed->GetBlockHash());
    node::CBlockFileInfo file_info;
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_blockman.m_block_tree_db->ReadBlockFileInfo(new_tip->nFile, file_info)));
    BOOST_CHECK_EQUAL(file_info.nHeightLast, old_flushed->nHeight);

    // Put the real blk file back, then prove a later FORCE_FLUSH writes the work the failed flush skipped.
    RestoreFile(blk_file);
    // Clear the Error from the failed flush so the next call starts clean.
    state = {};
    BOOST_CHECK(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    BOOST_CHECK(state.IsValid());
    // Chain tip and coins tip catch up to new_tip after the successful retry.
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainstate.GetLastFlushedBlock()), new_tip);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.CoinsDB().GetBestBlock()) == new_tip->GetBlockHash());
    // On-disk block file info now includes new_tip height (it stayed at old_flushed height after the failure).
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainstate.m_blockman.m_block_tree_db->ReadBlockFileInfo(new_tip->nFile, file_info)));
    BOOST_CHECK_EQUAL(file_info.nHeightLast, new_tip->nHeight);
}

// Characterize the bug this PR fixes: a prune flush can mark files pruned in memory, fail before the block-index write,
// then a later successful flush can write the pruned metadata and still leave blk/rev files on disk until the next startup.
BOOST_FIXTURE_TEST_CASE(prune_flush_failure, ManualPruneSetup)
{
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    auto& blockman{chainstate.m_blockman};
    BlockValidationState state{};
    // Commit 1 is why IsPruneMode() is true here (extra_args reached BlockManager).
    BOOST_REQUIRE(blockman.IsPruneMode());

    // Grow the chain until tip lives in blk00001.dat (file number 1). File 0 is then a candidate to prune.
    while (WITH_LOCK(::cs_main, return chainstate.m_chain.Tip()->nFile) == 0) {
        mineBlocks(1);
    }
    // Last height still stored in file 0. Manual prune will ask to prune through this height.
    const int prune_height{WITH_LOCK(::cs_main, return static_cast<int>(blockman.GetBlockFileInfo(0)->nHeightLast))};
    const int tip_height{WITH_LOCK(::cs_main, return chainstate.m_chain.Height())};
    // Keep at least MIN_BLOCKS_TO_KEEP blocks after prune_height so pruning file 0 is allowed.
    const int blocks_needed_after_prune{prune_height + static_cast<int>(MIN_BLOCKS_TO_KEEP) - tip_height};
    mineBlocks(blocks_needed_after_prune);

    // Baseline flush so coins/block index match tip before we sabotage.
    BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    const auto* flushed_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    // Remember on-disk size of file 0 before prune marks it empty in memory.
    const auto pruned_size{WITH_LOCK(::cs_main, return blockman.GetBlockFileInfo(0)->nSize)};
    // Paths of the blk/rev pair for file 0. The bug leaves these files present after a retried flush.
    const auto pruned_blk_file{blockman.GetBlockPosFilename(FlatFilePos{0, 0})};
    const fs::path pruned_rev_file{pruned_blk_file.parent_path() / "rev00000.dat"};

    // One more block so there is new tip work to flush. Sabotage that tip's blk file so FlushStateToDisk fails mid-prune.
    mineBlocks(1);
    const auto tip_blk_file{WITH_LOCK(::cs_main, return blockman.GetBlockPosFilename(chainstate.m_chain.Tip()->GetBlockPos()))};
    InjectFileOpenFailure(tip_blk_file);

    ASSERT_DEBUG_LOG("Flushing block file to disk failed");
    // FlushStateMode::NONE + prune_height = manual prune path. Failure happens while flushing the tip blk file,
    // after PruneOneBlockFile has already zeroed file 0 in memory and cleared BLOCK_HAVE_DATA.
    BOOST_CHECK(!chainstate.FlushStateToDisk(state, FlushStateMode::NONE, prune_height));
    BOOST_CHECK(state.IsError());
    {
        LOCK(::cs_main);
        // In-memory file 0 already looks pruned (sizes cleared).
        BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0)->nSize, 0U);
        BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0)->nUndoSize, 0U);
        for (int height{0}; height <= prune_height; ++height) {
            BOOST_CHECK(!(chainstate.m_chain[height]->nStatus & BLOCK_HAVE_DATA));
        }
    }
    // The "we have ever pruned" flag was written early, before the failing block-file flush returned.
    bool have_pruned{false};
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return blockman.m_block_tree_db->ReadFlag("prunedblockfiles", have_pruned)));
    BOOST_CHECK(have_pruned);
    // But the block-index DB still has the old non-zero size for file 0: the write that would record prune never ran.
    node::CBlockFileInfo file_info;
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return blockman.m_block_tree_db->ReadBlockFileInfo(0, file_info)));
    BOOST_CHECK_EQUAL(file_info.nSize, pruned_size);
    // Coins tip stayed at the pre-failure flushed tip (the failed flush did not advance coins).
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainstate.CoinsDB().GetBestBlock()) == flushed_tip->GetBlockHash());
    // Critically: blk00000.dat and rev00000.dat are still on disk after the failed prune flush.
    BOOST_CHECK(fs::exists(pruned_blk_file));
    BOOST_CHECK(fs::exists(pruned_rev_file));

    // Undo sabotage and FORCE_FLUSH. The retried flush writes pruned file 0 to the index and then unlinks the files.
    RestoreFile(tip_blk_file);
    state = {};
    BOOST_CHECK(chainstate.FlushStateToDisk(state, FlushStateMode::FORCE_FLUSH));
    BOOST_REQUIRE(WITH_LOCK(::cs_main, return blockman.m_block_tree_db->ReadBlockFileInfo(0, file_info)));
    BOOST_CHECK_EQUAL(file_info.nSize, 0U);
    // Fix landed: after a successful later flush, the pruned blk/rev files are gone (not only marked pruned in the index).
    BOOST_CHECK(!fs::exists(pruned_blk_file));
    BOOST_CHECK(!fs::exists(pruned_rev_file));
}

BOOST_AUTO_TEST_SUITE_END()
