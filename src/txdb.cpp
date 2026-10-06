// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <dbwrapper.h>
#include <kernel/coinsstore.h>
#include <logging/timer.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/log.h>
#include <util/threadnames.h>
#include <util/vector.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <future>
#include <iterator>
#include <utility>

#define LOG_REQUIRE_CONTEXT true

static constexpr size_t WARN_FLUSH_COINS_COUNT{10'000'000};

bool CCoinsViewDB::NeedsUpgrade()
{
    return m_db->NeedsUpgrade();
}

CCoinsViewDB::CCoinsViewDB(util::log::Logger& logger, DBParams db_params, CoinsViewOptions options) :
    m_log{BCLog::COINDB, &logger},
    m_db_params{std::move(db_params)},
    m_options{std::move(options)}
{
    const auto mode{m_db_params.memory_only ? kernel::CoinsStore::Mode::MEMORY
                    : m_db_params.wipe_data  ? kernel::CoinsStore::Mode::WIPE
                                             : kernel::CoinsStore::Mode::WRITE};
    try {
        m_db = std::make_unique<kernel::CoinsStore>(m_db_params.path, mode);
    } catch (const kernel::CoinsStoreError& err) {
        throw dbwrapper_error{err.what()};
    }
}

CCoinsViewDB::~CCoinsViewDB()
{
    if (m_compaction.valid()) {
        if (m_compaction.wait_for(std::chrono::seconds{0}) != std::future_status::ready) {
            LogInfo(m_log, "Waiting for background chainstate compaction of %s", fs::PathToString(m_db_params.path));
        }
        m_compaction.wait();
    }
}

void CCoinsViewDB::ResizeCache(size_t)
{
    // The coins store has no separate cache to resize.
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    try {
        auto coin{m_db->GetCoin(outpoint)};
        if (!coin) return std::nullopt;
        Assert(!coin->IsSpent());
        return coin;
    } catch (const kernel::CoinsStoreError& err) {
        throw dbwrapper_error{strprintf("Coin DB read failure: %s", err.what())};
    }
}

std::optional<Coin> CCoinsViewDB::PeekCoin(const COutPoint& outpoint) const
{
    return GetCoin(outpoint);
}

bool CCoinsViewDB::HaveCoin(const COutPoint& outpoint) const
{
    return m_db->HaveCoin(outpoint);
}

uint256 CCoinsViewDB::GetBestBlock() const
{
    return m_db->GetBestBlock();
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const
{
    return m_db->GetHeadBlocks();
}

void CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256& block_hash)
{
    size_t count = 0;
    const size_t dirty_count{cursor.GetDirtyCount()};
    assert(!block_hash.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != block_hash) {
                LogError(m_log, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == block_hash);
            old_tip = old_heads[1];
        }
    }

    if (dirty_count > WARN_FLUSH_COINS_COUNT) LogWarning(m_log, "Flushing large (%d entries) UTXO set to disk, it may take several minutes", dirty_count);
    LOG_TIME_MILLIS_WITH_CATEGORY(strprintf("write coins cache to disk (%d out of %d cached coins)",
        dirty_count, cursor.GetTotalCount()), BCLog::BENCH);

    // Mark the store as being in the middle of a transition from old_tip to block_hash.
    {
        kernel::CoinsStore::Batch marker;
        marker.erase_best = true;
        marker.heads = Vector(block_hash, old_tip);
        m_db->Commit(marker);
    }

    kernel::CoinsStore::Batch batch;
    size_t batch_bytes{0};
    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            if (it->second.coin.IsSpent()) {
                batch.coins.emplace_back(it->first, std::nullopt);
                // Tombstone only. Coin::Serialize asserts on spent coins.
                batch_bytes += sizeof(uint256) + 8;
            } else {
                batch.coins.emplace_back(it->first, it->second.coin);
                batch_bytes += GetSerializeSize(it->second.coin) + sizeof(uint256);
            }
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch_bytes > m_options.batch_write_bytes) {
            LogDebug(m_log, "Writing partial batch of %.2f MiB\n", batch_bytes / double(1_MiB));
            m_db->Commit(batch);
            batch = {};
            batch_bytes = 0;
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogError(m_log, "Simulating a crash. Goodbye.");
                    _Exit(0);
                }
            }
        }
    }

    // Mark the store as consistent with block_hash again.
    batch.erase_heads = true;
    batch.best = block_hash;

    LogDebug(m_log, "Writing final batch of %.2f MiB\n", batch_bytes / double(1_MiB));
    m_db->Commit(batch);
    LogDebug(m_log, "Committed %u changed transaction outputs (out of %u) to coin database...", (unsigned int)dirty_count, (unsigned int)count);
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize();
}

std::optional<std::string> CCoinsViewDB::GetDBProperty(const std::string&)
{
    return std::nullopt;
}

std::shared_future<void> CCoinsViewDB::CompactFullAsync()
{
    AssertLockHeld(::cs_main);
    if (m_compaction.valid()) return m_compaction;
    std::promise<void> done;
    done.set_value();
    m_compaction = done.get_future().share();
    return m_compaction;
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    CCoinsViewDBCursor(std::vector<std::pair<COutPoint, Coin>> coins_in, const uint256& in_block_hash)
        : CCoinsViewCursor(in_block_hash), coins{std::move(coins_in)} {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::vector<std::pair<COutPoint, Coin>> coins;
    size_t index{0};
};

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    return std::make_unique<CCoinsViewDBCursor>(m_db->ListCoins(), GetBestBlock());
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    if (!Valid()) return false;
    key = coins[index].first;
    return true;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    if (!Valid()) return false;
    coin = coins[index].second;
    return true;
}

bool CCoinsViewDBCursor::Valid() const
{
    return index < coins.size();
}

void CCoinsViewDBCursor::Next()
{
    if (Valid()) ++index;
}
