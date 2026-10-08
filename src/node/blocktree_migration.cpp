// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blocktree_migration.h>

#include <chain.h>
#include <consensus/params.h>
#include <dbwrapper.h>
#include <kernel/blocktreestorage.h>
#include <kernel/cs_main.h>
#include <kernel/legacy_leveldb.h>
#include <pow.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/hasher.h>
#include <util/log.h>
#include <util/signalinterrupt.h>

#include <exception>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

//! Read-only access to a legacy LevelDB blocks/index for migration into BlockTreeStore.
class BlockTreeDB : public CDBWrapper
{
public:
    using CDBWrapper::CDBWrapper;

    bool ReadBlockFileInfo(int nFile, kernel::CBlockFileInfo& info)
    {
        return Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
    }

    bool ReadLastBlockFile(int& nFile)
    {
        return Read(DB_LAST_BLOCK, nFile);
    }

    void ReadReindexing(bool& fReindexing)
    {
        fReindexing = Exists(DB_REINDEX_FLAG);
    }

    bool ReadFlag(const std::string& name, bool& fValue)
    {
        uint8_t ch;
        if (!Read(std::make_pair(DB_FLAG, name), ch)) {
            return false;
        }
        fValue = ch == uint8_t{'1'};
        return true;
    }

    bool LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex, const util::SignalInterrupt& interrupt)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        AssertLockHeld(::cs_main);
        std::unique_ptr<CDBIterator> pcursor(NewIterator());
        pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

        while (pcursor->Valid()) {
            if (interrupt) return false;
            std::pair<uint8_t, uint256> key;
            if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
                CDiskBlockIndex diskindex;
                if (pcursor->GetValue(diskindex)) {
                    CBlockIndex* pindexNew = insertBlockIndex(diskindex.ConstructBlockHash());
                    pindexNew->pprev = insertBlockIndex(diskindex.hashPrev);
                    pindexNew->nHeight = diskindex.nHeight;
                    pindexNew->nFile = diskindex.nFile;
                    pindexNew->nDataPos = diskindex.nDataPos;
                    pindexNew->nUndoPos = diskindex.nUndoPos;
                    pindexNew->nVersion = diskindex.nVersion;
                    pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                    pindexNew->nTime = diskindex.nTime;
                    pindexNew->nBits = diskindex.nBits;
                    pindexNew->nNonce = diskindex.nNonce;
                    pindexNew->nStatus = diskindex.nStatus;
                    pindexNew->nTx = diskindex.nTx;

                    if (!CheckProofOfWork(pindexNew->GetBlockHash(), pindexNew->nBits, consensusParams)) {
                        LogError(m_log, "%s: CheckProofOfWork failed: %s\n", __func__, pindexNew->ToString());
                        return false;
                    }

                    pcursor->Next();
                } else {
                    LogError(m_log, "%s: failed to read value\n", __func__);
                    return false;
                }
            } else {
                break;
            }
        }

        return true;
    }

private:
    static constexpr uint8_t DB_BLOCK_FILES{'f'};
    static constexpr uint8_t DB_BLOCK_INDEX{'b'};
    static constexpr uint8_t DB_FLAG{'F'};
    static constexpr uint8_t DB_REINDEX_FLAG{'R'};
    static constexpr uint8_t DB_LAST_BLOCK{'l'};
};

} // namespace

namespace node {

void MaybeMigrateLegacyBlockTree(
    util::log::Logger& logger,
    const fs::path& block_tree_dir,
    const Consensus::Params& consensus_params,
    const util::SignalInterrupt& interrupt,
    bool wipe_block_tree_data,
    bool read_only)
{
    const util::log::Context log{BCLog::BLOCKSTORAGE, &logger};
    const bool legacy{fs::exists(block_tree_dir / "CURRENT")};
    if (!legacy) return;

    if (read_only) {
        throw kernel::BlockTreeStoreError("Refusing to migrate or wipe a block tree opened read-only");
    }

    // -reindex / wipe: BlockManager removes LevelDB files when opening.
    if (wipe_block_tree_data) return;

    LOCK(::cs_main);

    auto cleanup_leveldb{[&]() {
        if (!kernel::RemoveLegacyLevelDBFiles(block_tree_dir)) {
            throw kernel::BlockTreeStoreError(strprintf(
                "Failed to remove legacy leveldb block tree db at %s",
                fs::PathToString(block_tree_dir)));
        }
        if (fs::exists(block_tree_dir / "CURRENT")) {
            throw kernel::BlockTreeStoreError(strprintf(
                "Legacy leveldb block tree db marker still exists at %s",
                fs::PathToString(block_tree_dir / "CURRENT")));
        }
    }};

    std::vector<std::pair<int, kernel::CBlockFileInfo>> files;
    int max_blockfile_num{0};
    bool reindexing{false};
    bool pruned_block_files{false};
    std::unordered_map<uint256, CBlockIndex, BlockHasher> migration_index;

    {
        LogInfo(log, "Migrating leveldb block tree db to new block tree store.");
        auto insert_block_index{[&](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) -> CBlockIndex* {
            if (hash.IsNull()) return nullptr;
            const auto [mi, inserted]{migration_index.try_emplace(hash)};
            CBlockIndex* pindex{&mi->second};
            if (inserted) pindex->phashBlock = &mi->first;
            return pindex;
        }};
        try {
            DBParams params{};
            params.path = block_tree_dir;
            auto block_tree_db{std::make_unique<BlockTreeDB>(logger, params)};
            LogInfo(log, "   Reading data from existing leveldb block tree db...");
            if (!block_tree_db->ReadLastBlockFile(max_blockfile_num)) {
                throw std::runtime_error("Failed to read last block file.");
            }
            files.reserve(max_blockfile_num + 1);
            for (int i{0}; i <= max_blockfile_num; ++i) {
                kernel::CBlockFileInfo info;
                if (!block_tree_db->ReadBlockFileInfo(i, info)) {
                    throw std::runtime_error(strprintf("Failed to read block file info for file %d", i));
                }
                files.emplace_back(i, info);
            }

            if (!block_tree_db->LoadBlockIndexGuts(consensus_params, insert_block_index, interrupt)) {
                throw std::runtime_error("Failed to load block index guts");
            }
            block_tree_db->ReadReindexing(reindexing);
            block_tree_db->ReadFlag("prunedblockfiles", pruned_block_files);
        } catch (const std::exception& e) {
            throw kernel::BlockTreeStoreError(strprintf("Failed to read existing leveldb block tree data: %s", e.what()));
        }
    }

    {
        // Cleanup a potentially previously failed migration by setting wipe_data
        LogInfo(log, "   Writing data back to a new block tree store, reindexing: %d, pruned: %d", reindexing, pruned_block_files);
        auto block_tree_store{std::make_unique<kernel::BlockTreeStore>(block_tree_dir, kernel::BlockTreeStore::OpenMode::WIPE)};
        block_tree_store->WritePruned(pruned_block_files);
        block_tree_store->WriteReindexing(reindexing);

        std::vector<std::pair<int, const kernel::CBlockFileInfo*>> dump_files;
        dump_files.reserve(files.size());
        for (auto& file : files) {
            dump_files.emplace_back(file.first, &file.second);
        }
        std::vector<CBlockIndex*> dump_blockindexes;
        dump_blockindexes.reserve(migration_index.size());
        for (auto& pair : migration_index) {
            dump_blockindexes.push_back(&pair.second);
        }

        block_tree_store->WriteBatchSync(dump_files, dump_blockindexes);
    }

    // Re-open to ensure that the migration was successful before deleting LevelDB files.
    kernel::BlockTreeStore{block_tree_dir};
    cleanup_leveldb();

    LogInfo(log, "   Successfully migrated the leveldb block tree db to new block tree store.");
}

} // namespace node
