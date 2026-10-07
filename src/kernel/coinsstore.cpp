// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/coinsstore.h>

#include <crc32c/include/crc32c/crc32c.h>
#include <crypto/common.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <span>
#include <system_error>
#include <utility>

namespace kernel {
namespace {

using Checksum = uint32_t;
using FilePosition = int64_t;

// Same framing as the block tree store: magic, version, records, checksum, log, flag.
inline constexpr uint32_t COINS_FILE_MAGIC{0x6f69e5c0};
inline constexpr uint32_t COINS_FILE_VERSION{1};
inline constexpr int64_t COINS_FILE_DATA_START{8};
inline constexpr const char* COINS_FILE_NAME{"coins.dat"};

inline constexpr uint32_t COINS_LOG_MAGIC{0xa0346f91};
inline constexpr uint32_t COINS_LOG_VERSION{1};
inline constexpr const char* COINS_LOG_NAME{"log.dat"};
inline constexpr const char* COINS_LOG_FLAG_NAME{"log_flag.dat"};

enum class RecordType : uint8_t {
    COIN = 1,
    TOMBSTONE = 2,
    BEST = 3,
    HEADS = 4,
};

class AccessLock
{
    fs::path m_dir;

public:
    explicit AccessLock(const fs::path& dir) : m_dir{dir}
    {
        switch (util::LockDirectory(m_dir, ".lock")) {
        case util::LockResult::Success:
            return;
        case util::LockResult::ErrorWrite:
            throw CoinsStoreError(strprintf("Cannot create lock file in %s", fs::PathToString(m_dir)));
        case util::LockResult::ErrorLock:
            throw CoinsStoreError(strprintf("Timed out waiting for the coins store in %s.", fs::PathToString(m_dir)));
        }
        assert(false);
    }

    ~AccessLock() { UnlockDirectory(m_dir, ".lock"); }

    AccessLock(const AccessLock&) = delete;
    AccessLock& operator=(const AccessLock&) = delete;
};

static Checksum ExtendChecksum(Checksum checksum, std::span<const std::byte> value_data, FilePosition position)
{
    checksum = crc32c::Extend(checksum, UCharCast(value_data.data()), value_data.size());
    std::array<std::byte, sizeof(FilePosition)> position_bytes;
    WriteLE64(UCharCast(position_bytes.data()), static_cast<uint64_t>(position));
    return crc32c::Extend(checksum, UCharCast(position_bytes.data()), position_bytes.size());
}

static Checksum SingleChecksum(std::span<const std::byte> value_data, FilePosition position)
{
    return ExtendChecksum(0, value_data, position);
}

static AutoFile OpenFile(const fs::path& path, const std::string& mode)
{
    AutoFile file{fsbridge::fopen(path, mode.c_str())};
    if (file.IsNull()) {
        throw CoinsStoreError(strprintf("Unable to open file %s", fs::PathToString(path)));
    }
    return AutoFile{file.release()};
}

static void WriteMagicAndVersion(AutoFile& file, uint32_t magic, uint32_t version)
{
    file << magic;
    file << version;
}

static void CreateDataFile(const fs::path& path)
{
    auto file{OpenFile(path, "wb")};
    WriteMagicAndVersion(file, COINS_FILE_MAGIC, COINS_FILE_VERSION);
    if (!file.Commit() || file.fclose() != 0) {
        throw CoinsStoreError(strprintf("Failed to write file %s", fs::PathToString(path)));
    }
}

static AutoFile OpenFileAndVerifyHeader(const fs::path& path, uint32_t magic_expected, uint32_t version_expected, const std::string& mode)
{
    auto file{OpenFile(path, mode)};
    if (auto magic{ser_readdata32(file)}; magic != magic_expected) {
        throw CoinsStoreError(strprintf("Invalid magic in %s: 0x%08x (expected: 0x%08x)", fs::PathToString(path), magic, magic_expected));
    }
    if (auto version{ser_readdata32(file)}; version != version_expected) {
        throw CoinsStoreError(strprintf("Invalid version in %s: 0x%08x (expected: 0x%08x)", fs::PathToString(path), version, version_expected));
    }
    return AutoFile{file.release()};
}

struct DiskRecord {
    std::vector<std::byte> payload;
    FilePosition position{0};
};

static std::vector<std::byte> ToBytes(const DataStream& stream)
{
    return {stream.data(), stream.data() + stream.size()};
}

static DataStream PayloadFor(const std::pair<COutPoint, std::optional<Coin>>& change)
{
    DataStream stream{};
    uint32_t n{change.first.n};
    if (!change.second) {
        stream << static_cast<uint8_t>(RecordType::TOMBSTONE);
        stream << change.first.hash;
        stream << VARINT(n);
    } else {
        stream << static_cast<uint8_t>(RecordType::COIN);
        stream << change.first.hash;
        stream << VARINT(n);
        stream << *change.second;
    }
    return stream;
}

static void ApplyPayload(std::map<COutPoint, Coin>& coins, uint256& best, std::vector<uint256>& heads, std::span<const std::byte> payload)
{
    DataStream stream{payload};
    uint8_t raw_type{0};
    stream >> raw_type;
    const auto type{static_cast<RecordType>(raw_type)};
    switch (type) {
    case RecordType::COIN: {
        COutPoint outpoint;
        stream >> outpoint.hash;
        stream >> VARINT(outpoint.n);
        Coin coin;
        stream >> coin;
        coins.insert_or_assign(std::move(outpoint), std::move(coin));
        return;
    }
    case RecordType::TOMBSTONE: {
        COutPoint outpoint;
        stream >> outpoint.hash;
        stream >> VARINT(outpoint.n);
        coins.erase(outpoint);
        return;
    }
    case RecordType::BEST:
        stream >> best;
        return;
    case RecordType::HEADS:
        stream >> heads;
        return;
    }
    throw CoinsStoreError(strprintf("Unrecognized coins record type (%u)", raw_type));
}

} // namespace

struct CoinsStore::WriterLockHolder {
    fs::path m_dir;

    explicit WriterLockHolder(const fs::path& dir) : m_dir{dir}
    {
        switch (util::LockDirectory(m_dir, ".writer-lock")) {
        case util::LockResult::Success:
            return;
        case util::LockResult::ErrorWrite:
            throw CoinsStoreError(strprintf("Cannot create writer-lock file in %s", fs::PathToString(m_dir)));
        case util::LockResult::ErrorLock:
            throw CoinsStoreError(strprintf("Another process is already writing the coins store in %s.", fs::PathToString(m_dir)));
        }
        assert(false);
    }

    ~WriterLockHolder() { UnlockDirectory(m_dir, ".writer-lock"); }

    WriterLockHolder(const WriterLockHolder&) = delete;
    WriterLockHolder& operator=(const WriterLockHolder&) = delete;
};

CoinsStore::CoinsStore(const fs::path& path, Mode mode)
    : m_dir{path},
      m_data_path{path / COINS_FILE_NAME},
      m_log_path{path / COINS_LOG_NAME},
      m_log_flag_path{path / COINS_LOG_FLAG_NAME},
      m_mode{mode}
{
    if (m_mode == Mode::MEMORY) return;

    const bool legacy{fs::exists(m_dir / "CURRENT") && !fs::exists(m_data_path)};
    if (legacy && m_mode != Mode::WIPE) {
        m_needs_upgrade = true;
        return;
    }

    if (m_mode == Mode::READ) {
        LOCK(m_mutex);
        if (fs::exists(m_data_path)) Load();
        return;
    }

    if (m_mode == Mode::WIPE) {
        RemoveFiles(m_dir);
    }
    fs::create_directories(m_dir);
    m_writer_lock = std::make_unique<WriterLockHolder>(m_dir);

    LOCK(m_mutex);
    if (!fs::exists(m_data_path)) {
        CreateDataFile(m_data_path);
    }
    ApplyLog();
    Load();
}

CoinsStore::~CoinsStore() = default;

void CoinsStore::RemoveFiles(const fs::path& dir)
{
    std::error_code ec;
    fs::remove(dir / COINS_FILE_NAME, ec);
    fs::remove(dir / COINS_LOG_NAME, ec);
    fs::remove(dir / COINS_LOG_FLAG_NAME, ec);
    fs::remove(dir / ".lock", ec);
    fs::remove(dir / ".writer-lock", ec);
}

void CoinsStore::CheckWrite() const
{
    if (m_needs_upgrade) {
        throw CoinsStoreError("Unsupported chainstate database format");
    }
    if (m_mode == Mode::READ) {
        throw std::logic_error("Coins store writes are disabled when opened in read mode");
    }
}

std::optional<Coin> CoinsStore::GetCoin(const COutPoint& outpoint) const
{
    LOCK(m_mutex);
    const auto it{m_coins.find(outpoint)};
    if (it == m_coins.end()) return std::nullopt;
    return it->second;
}

bool CoinsStore::HaveCoin(const COutPoint& outpoint) const
{
    LOCK(m_mutex);
    return m_coins.contains(outpoint);
}

uint256 CoinsStore::GetBestBlock() const
{
    LOCK(m_mutex);
    return m_best;
}

std::vector<uint256> CoinsStore::GetHeadBlocks() const
{
    LOCK(m_mutex);
    return m_heads;
}

size_t CoinsStore::EstimateSize() const
{
    if (m_mode == Mode::MEMORY || !fs::exists(m_data_path)) {
        LOCK(m_mutex);
        return m_coins.size();
    }
    std::error_code ec;
    const auto size{fs::file_size(m_data_path, ec)};
    return ec ? 0 : static_cast<size_t>(size);
}

std::vector<std::pair<COutPoint, Coin>> CoinsStore::ListCoins() const
{
    LOCK(m_mutex);
    return {m_coins.begin(), m_coins.end()};
}

void CoinsStore::ApplyMemory(const Batch& batch)
{
    if (batch.erase_best) m_best.SetNull();
    if (batch.erase_heads) m_heads.clear();
    if (batch.heads) {
        m_heads = *batch.heads;
        m_best.SetNull();
    }
    if (batch.best) {
        m_best = *batch.best;
        m_heads.clear();
    }
    for (const auto& change : batch.coins) {
        if (!change.second) {
            m_coins.erase(change.first);
        } else {
            m_coins.insert_or_assign(change.first, *change.second);
        }
    }
}

void CoinsStore::Load()
{
    AccessLock access{m_dir};
    auto file{OpenFileAndVerifyHeader(m_data_path, COINS_FILE_MAGIC, COINS_FILE_VERSION, "rb")};
    file.seek(0, SEEK_END);
    const FilePosition end{file.tell()};
    file.seek(COINS_FILE_DATA_START, SEEK_SET);
    m_coins.clear();
    m_best.SetNull();
    m_heads.clear();
    while (file.tell() < end) {
        uint32_t payload_size{0};
        file >> payload_size;
        const FilePosition position{file.tell()};
        if (position + static_cast<FilePosition>(payload_size) + static_cast<FilePosition>(sizeof(Checksum)) > end) {
            throw CoinsStoreError("Torn coins record");
        }
        std::vector<std::byte> payload(payload_size);
        file.read(payload);
        Checksum checksum{0};
        file >> checksum;
        if (SingleChecksum(payload, position) != checksum) {
            throw CoinsStoreError("Coins record failed integrity check");
        }
        ApplyPayload(m_coins, m_best, m_heads, payload);
    }
}

void CoinsStore::ApplyLog()
{
    if (!fs::exists(m_log_flag_path)) {
        std::error_code ec;
        fs::remove(m_log_path, ec);
        return;
    }
    AccessLock access{m_dir};
    auto log_file{OpenFileAndVerifyHeader(m_log_path, COINS_LOG_MAGIC, COINS_LOG_VERSION, "rb")};
    uint64_t count{0};
    log_file >> count;
    auto data{OpenFileAndVerifyHeader(m_data_path, COINS_FILE_MAGIC, COINS_FILE_VERSION, "rb+")};
    data.seek(0, SEEK_END);
    Checksum rolling{0};
    for (uint64_t i{0}; i < count; ++i) {
        uint32_t payload_size{0};
        log_file >> payload_size;
        std::vector<std::byte> payload(payload_size);
        log_file.read(payload);
        FilePosition position{0};
        Checksum checksum{0};
        log_file >> position;
        log_file >> checksum;
        if (SingleChecksum(payload, position) != checksum) {
            throw CoinsStoreError("Coins log record failed integrity check");
        }
        rolling = ExtendChecksum(rolling, payload, position);
        if (data.tell() != position - static_cast<FilePosition>(sizeof(uint32_t))) {
            throw CoinsStoreError("Coins log position does not match the data file");
        }
        data << payload_size;
        data.write(payload);
        data << checksum;
    }
    Checksum stored_rolling{0};
    log_file >> stored_rolling;
    if (stored_rolling != rolling) {
        throw CoinsStoreError("Coins log rolling checksum mismatch");
    }
    if (!data.Commit() || data.fclose() != 0) {
        throw CoinsStoreError("Failed to commit coins data file");
    }
    std::error_code ec;
    fs::remove(m_log_flag_path, ec);
    fs::remove(m_log_path, ec);
    DirectoryCommit(m_dir);
}

void CoinsStore::Commit(const Batch& batch)
{
    LOCK(m_mutex);
    if (m_mode == Mode::MEMORY) {
        ApplyMemory(batch);
        return;
    }
    CheckWrite();

    std::vector<DataStream> payloads;
    if (batch.erase_best || batch.erase_heads || batch.best || batch.heads) {
        if (batch.erase_best) {
            DataStream stream{};
            stream << static_cast<uint8_t>(RecordType::BEST);
            stream << uint256{};
            payloads.push_back(std::move(stream));
        }
        if (batch.erase_heads) {
            DataStream stream{};
            stream << static_cast<uint8_t>(RecordType::HEADS);
            stream << std::vector<uint256>{};
            payloads.push_back(std::move(stream));
        }
        if (batch.heads) {
            DataStream stream{};
            stream << static_cast<uint8_t>(RecordType::HEADS);
            stream << *batch.heads;
            payloads.push_back(std::move(stream));
        }
        if (batch.best) {
            DataStream stream{};
            stream << static_cast<uint8_t>(RecordType::BEST);
            stream << *batch.best;
            payloads.push_back(std::move(stream));
        }
    }
    for (const auto& change : batch.coins) {
        payloads.push_back(PayloadFor(change));
    }
    if (payloads.empty()) return;

    auto sizing{OpenFileAndVerifyHeader(m_data_path, COINS_FILE_MAGIC, COINS_FILE_VERSION, "rb")};
    sizing.seek(0, SEEK_END);
    FilePosition cursor{sizing.tell()};
    if (sizing.fclose() != 0) {
        throw CoinsStoreError("Failed to close coins data file");
    }

    auto log_file{OpenFile(m_log_path, "wb")};
    WriteMagicAndVersion(log_file, COINS_LOG_MAGIC, COINS_LOG_VERSION);
    log_file << static_cast<uint64_t>(payloads.size());
    Checksum rolling{0};
    for (const auto& payload_stream : payloads) {
        const std::vector<std::byte> payload{ToBytes(payload_stream)};
        const uint32_t payload_size{static_cast<uint32_t>(payload.size())};
        const FilePosition position{cursor + static_cast<FilePosition>(sizeof(uint32_t))};
        const Checksum checksum{SingleChecksum(payload, position)};
        rolling = ExtendChecksum(rolling, payload, position);
        log_file << payload_size;
        log_file.write(payload);
        log_file << position;
        log_file << checksum;
        cursor = position + static_cast<FilePosition>(payload.size()) + static_cast<FilePosition>(sizeof(Checksum));
    }
    log_file << rolling;
    if (!log_file.Commit() || log_file.fclose() != 0) {
        throw CoinsStoreError("Failed to commit coins log");
    }
    {
        auto flag{OpenFile(m_log_flag_path, "wb")};
        if (flag.fclose() != 0) {
            throw CoinsStoreError("Failed to create coins log flag");
        }
    }
    DirectoryCommit(m_dir);
    ApplyLog();
    ApplyMemory(batch);
}

} // namespace kernel
