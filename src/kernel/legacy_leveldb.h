// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_LEGACY_LEVELDB_H
#define BITCOIN_KERNEL_LEGACY_LEVELDB_H

#include <util/fs.h>

#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace kernel {

//! File names leveldb::DestroyDB deletes. CURRENT, LOCK, LOG, LOG.old,
//! MANIFEST-<digits>, <digits>.log, <digits>.sst, <digits>.ldb, <digits>.dbtmp.
inline bool IsLegacyLevelDBFileName(std::string_view name)
{
    if (name == "CURRENT" || name == "LOCK" || name == "LOG" || name == "LOG.old") {
        return true;
    }
    constexpr std::string_view manifest{"MANIFEST-"};
    if (name.starts_with(manifest)) {
        const std::string_view rest{name.substr(manifest.size())};
        if (rest.empty()) return false;
        for (const char c : rest) {
            if (c < '0' || c > '9') return false;
        }
        return true;
    }
    std::size_t i{0};
    while (i < name.size() && name[i] >= '0' && name[i] <= '9') ++i;
    if (i == 0) return false;
    const std::string_view suffix{name.substr(i)};
    return suffix == ".log" || suffix == ".sst" || suffix == ".ldb" || suffix == ".dbtmp";
}

//! Delete legacy LevelDB files in dir. Does not remove dir or any other name.
//! The kernel does not link leveldb, so this does not take the LevelDB LOCK.
//! Returns false if a matching file cannot be removed.
inline bool RemoveLegacyLevelDBFiles(const fs::path& dir)
{
    std::error_code ec;
    std::vector<fs::path> files;
    for (fs::directory_iterator it{dir, ec}; !ec && it != fs::directory_iterator(); it.increment(ec)) {
        std::error_code stat_ec;
        const bool regular{it->is_regular_file(stat_ec)};
        if (stat_ec) return false;
        if (!regular) continue;
        if (!IsLegacyLevelDBFileName(fs::PathToString(it->path().filename()))) continue;
        files.push_back(it->path());
    }
    if (ec && ec != std::errc::no_such_file_or_directory) return false;
    if (ec) return files.empty();

    for (const fs::path& file : files) {
        fs::remove(file, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) return false;
        ec.clear();
    }
    return true;
}

} // namespace kernel

#endif // BITCOIN_KERNEL_LEGACY_LEVELDB_H
