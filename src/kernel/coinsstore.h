// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_COINSSTORE_H
#define BITCOIN_KERNEL_COINSSTORE_H

#include <coins.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

class COutPoint;

namespace kernel {

//! One writer, many readers. File layout matches the block tree store.
//! magic, version, then records of value plus checksum, plus a write-ahead log.
class CoinsStoreError : public std::runtime_error
{
public:
    explicit CoinsStoreError(const std::string& msg) : std::runtime_error(msg) {}
};

class CoinsStore
{
public:
    enum class Mode {
        WRITE,
        WIPE,
        READ,
        MEMORY,
    };

    //! One durable batch. nullopt coin erases that outpoint.
    struct Batch {
        bool erase_best{false};
        bool erase_heads{false};
        std::optional<uint256> best;
        std::optional<std::vector<uint256>> heads;
        std::vector<std::pair<COutPoint, std::optional<Coin>>> coins;
    };

    CoinsStore(const fs::path& path, Mode mode);
    ~CoinsStore();

    //! Remove store files under dir (data, log, lock files). Does not remove the directory.
    static void RemoveFiles(const fs::path& dir);

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool HaveCoin(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint256 GetBestBlock() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::vector<uint256> GetHeadBlocks() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool NeedsUpgrade() const { return m_needs_upgrade; }
    size_t EstimateSize() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::vector<std::pair<COutPoint, Coin>> ListCoins() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void Commit(const Batch& batch) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    fs::path m_dir;
    fs::path m_data_path;
    fs::path m_log_path;
    fs::path m_log_flag_path;
    Mode m_mode;
    bool m_needs_upgrade{false};
    struct WriterLockHolder;
    std::unique_ptr<WriterLockHolder> m_writer_lock;
    mutable Mutex m_mutex;
    std::map<COutPoint, Coin> m_coins GUARDED_BY(m_mutex);
    uint256 m_best GUARDED_BY(m_mutex);
    std::vector<uint256> m_heads GUARDED_BY(m_mutex);

    void ApplyMemory(const Batch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Load() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ApplyLog() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void CheckWrite() const;
};

} // namespace kernel

#endif // BITCOIN_KERNEL_COINSSTORE_H
