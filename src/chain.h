// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include <arith_uint256.h>
#include <consensus/params.h>
#include <flatfile.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/**
 * Maximum amount of time that a block timestamp is allowed to exceed the
 * current time before the block will be accepted.
 */
inline constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/**
 * Timestamp window used as a grace period by code that compares external
 * timestamps (such as timestamps passed to RPCs, or wallet key creation times)
 * to block timestamps. This should be set at least as high as
 * MAX_FUTURE_BLOCK_TIME.
 */
inline constexpr int64_t TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME;
//! Init values for CBlockIndex nSequenceId when loaded from disk
inline constexpr int32_t SEQ_ID_BEST_CHAIN_FROM_DISK = 0;
inline constexpr int32_t SEQ_ID_INIT_FROM_DISK = 1;

enum BlockStatus : uint32_t {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Reserved (was BLOCK_VALID_HEADER).
    BLOCK_VALID_RESERVED     =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS.
     *
     * If a block's validity is at least VALID_TRANSACTIONS, CBlockIndex::nTx will be set. If a block and all previous
     * blocks back to the genesis block or an assumeutxo snapshot block are at least VALID_TRANSACTIONS,
     * CBlockIndex::m_chain_tx_count will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all previous blocks back to the genesis block or an assumeutxo snapshot block are at least VALID_CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all previous blocks back to the genesis block or an assumeutxo snapshot block
    //! are at least VALID_SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_RESERVED | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //!< full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //!< Unused flag that was previously set when descending from failed block

    BLOCK_OPT_WITNESS        =   128, //!< block data in blk*.dat was received with a witness-enforcing client

    BLOCK_STATUS_RESERVED    =   256, //!< Unused flag that was previously set on assumeutxo snapshot blocks and their
                                      //!< ancestors before they were validated, and unset when they were validated.
};

/**
 * Word published to readers that do not hold cs_main.
 * Loads acquire. Stores and bit updates release via compare-exchange.
 */
class BlockStatusWord
{
    std::atomic<uint32_t> m_bits{0};

public:
    BlockStatusWord() noexcept = default;
    BlockStatusWord(uint32_t bits) noexcept : m_bits{bits} {}
    BlockStatusWord(const BlockStatusWord& other) noexcept
        : m_bits{other.m_bits.load(std::memory_order_acquire)} {}
    BlockStatusWord& operator=(const BlockStatusWord& other) noexcept
    {
        return *this = static_cast<uint32_t>(other);
    }
    BlockStatusWord(BlockStatusWord&&) = delete;
    BlockStatusWord& operator=(BlockStatusWord&&) = delete;

    operator uint32_t() const noexcept { return m_bits.load(std::memory_order_acquire); }

    BlockStatusWord& operator=(uint32_t bits) noexcept
    {
        m_bits.store(bits, std::memory_order_release);
        return *this;
    }

    BlockStatusWord& operator|=(uint32_t bits) noexcept
    {
        uint32_t current{m_bits.load(std::memory_order_relaxed)};
        while (!m_bits.compare_exchange_weak(current, current | bits, std::memory_order_release, std::memory_order_relaxed)) {
        }
        return *this;
    }

    BlockStatusWord& operator&=(uint32_t bits) noexcept
    {
        uint32_t current{m_bits.load(std::memory_order_relaxed)};
        while (!m_bits.compare_exchange_weak(current, current & bits, std::memory_order_release, std::memory_order_relaxed)) {
        }
        return *this;
    }

    template <typename Fn>
    void Transform(Fn&& fn) noexcept
    {
        uint32_t current{m_bits.load(std::memory_order_relaxed)};
        while (!m_bits.compare_exchange_weak(current, fn(current), std::memory_order_release, std::memory_order_relaxed)) {
        }
    }

    friend bool operator==(const BlockStatusWord& a, const BlockStatusWord& b) noexcept
    {
        return static_cast<uint32_t>(a) == static_cast<uint32_t>(b);
    }
    friend bool operator==(const BlockStatusWord& a, uint32_t b) noexcept { return static_cast<uint32_t>(a) == b; }
    friend bool operator==(uint32_t a, const BlockStatusWord& b) noexcept { return a == static_cast<uint32_t>(b); }
};

/** Relaxed word. Published by a later release store on BlockStatusWord. */
template <typename T>
class PublishedWord
{
    std::atomic<T> m_value{};

public:
    PublishedWord() noexcept = default;
    PublishedWord(T value) noexcept : m_value{value} {}
    PublishedWord(const PublishedWord& other) noexcept
        : m_value{other.m_value.load(std::memory_order_relaxed)} {}
    PublishedWord& operator=(const PublishedWord& other) noexcept
    {
        return *this = static_cast<T>(other);
    }
    PublishedWord(PublishedWord&&) = delete;
    PublishedWord& operator=(PublishedWord&&) = delete;

    operator T() const noexcept { return m_value.load(std::memory_order_relaxed); }
    PublishedWord& operator=(T value) noexcept
    {
        m_value.store(value, std::memory_order_relaxed);
        return *this;
    }

    friend bool operator==(const PublishedWord& a, const PublishedWord& b) noexcept
    {
        return static_cast<T>(a) == static_cast<T>(b);
    }
    friend bool operator==(const PublishedWord& a, T b) noexcept { return static_cast<T>(a) == b; }
    friend bool operator==(T a, const PublishedWord& b) noexcept { return a == static_cast<T>(b); }
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256* phashBlock{nullptr};

    //! pointer to the index of the predecessor of this block
    CBlockIndex* pprev{nullptr};

    //! pointer to the index of some further predecessor of this block
    CBlockIndex* pskip{nullptr};

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight{0};

    //! Which # file this block is stored in (blk?????.dat).
    //! Write this, nDataPos, and nUndoPos before releasing the matching nStatus bits.
    //! Clear the nStatus bits before reusing these positions.
    PublishedWord<int> nFile{0};

    //! Byte offset within blk?????.dat where this block's data is stored
    PublishedWord<unsigned int> nDataPos{0};

    //! Byte offset within rev?????.dat where this block's undo data is stored
    PublishedWord<unsigned int> nUndoPos{0};

    //! Sentinel for an unset header pos
    static constexpr int64_t UNSET_HEADER_POS{-1};

    //! (memory only) Byte offset within headers.dat where this class' data is stored
    int64_t header_pos GUARDED_BY(::cs_main){UNSET_HEADER_POS};

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    arith_uint256 nChainWork{};

    //! Number of transactions in this block. This will be nonzero if the block
    //! reached the VALID_TRANSACTIONS level, and zero otherwise.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx{0};

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero if this block and all previous blocks back
    //! to the genesis block or an assumeutxo snapshot block have reached the
    //! VALID_TRANSACTIONS level.
    uint64_t m_chain_tx_count{0};

    //! Verification status of this block. See enum BlockStatus.
    //! Readers acquire-load. Writers release-store. File positions are published
    //! by the BLOCK_HAVE_DATA and BLOCK_HAVE_UNDO bits.
    //!
    //! Note: this value is modified to show BLOCK_OPT_WITNESS during UTXO snapshot
    //! load to avoid a spurious startup failure requiring -reindex.
    //! @sa NeedsRedownload
    //! @sa ActivateSnapshot
    BlockStatusWord nStatus{0};

    //! block header
    int32_t nVersion{0};
    uint256 hashMerkleRoot{};
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    //! Initialized to SEQ_ID_INIT_FROM_DISK{1} when loading blocks from disk, except for blocks
    //! belonging to the best chain which overwrite it to SEQ_ID_BEST_CHAIN_FROM_DISK{0}.
    int32_t nSequenceId{SEQ_ID_INIT_FROM_DISK};

    //! (memory only) Maximum nTime in the chain up to and including this block.
    unsigned int nTimeMax{0};

    explicit CBlockIndex(const CBlockHeader& block)
        : nVersion{block.nVersion},
          hashMerkleRoot{block.hashMerkleRoot},
          nTime{block.nTime},
          nBits{block.nBits},
          nNonce{block.nNonce}
    {
    }

    FlatFilePos GetBlockPos() const
    {
        FlatFilePos ret;
        // Acquire nStatus first so the position read sees the published values.
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos = nDataPos;
        }
        return ret;
    }

    FlatFilePos GetUndoPos() const
    {
        FlatFilePos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        assert(phashBlock != nullptr);
        return *phashBlock;
    }

    /**
     * Check whether this block and all previous blocks back to the genesis block or an assumeutxo snapshot block have
     * reached VALID_TRANSACTIONS and had transactions downloaded (and stored to disk) at some point.
     *
     * Does not imply the transactions are consensus-valid (ConnectTip might fail)
     * Does not imply the transactions are still stored on disk. (IsBlockPruned might return true)
     *
     * Note that this will be true for the snapshot base block, if one is loaded, since its m_chain_tx_count value will have
     * been set manually based on the related AssumeutxoData entry.
     */
    bool HaveNumChainTxs() const { return m_chain_tx_count != 0; }

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    int64_t GetBlockTimeMax() const
    {
        return (int64_t)nTimeMax;
    }

    static constexpr int nMedianTimeSpan = 11;

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin) / 2];
    }

    std::string ToString() const;

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        const uint32_t status{nStatus};
        if (status & BLOCK_FAILED_VALID) {
            return false;
        }
        return (status & BLOCK_VALID_MASK) >= nUpTo;
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    //! Other status bits are left in place. BLOCK_FAILED_VALID blocks a raise.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        bool raised{false};
        nStatus.Transform([&](uint32_t status) {
            raised = false;
            if (status & BLOCK_FAILED_VALID) return status;
            if ((status & BLOCK_VALID_MASK) >= nUpTo) return status;
            raised = true;
            return (status & ~BLOCK_VALID_MASK) | static_cast<uint32_t>(nUpTo);
        });
        return raised;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;

    CBlockIndex() = default;
    ~CBlockIndex() = default;

protected:
    //! CBlockIndex should not allow public copy construction because equality
    //! comparison via pointer is very common throughout the codebase, making
    //! use of copy a footgun. Also, use of copies do not have the benefit
    //! of simplifying lifetime considerations due to attributes like pprev and
    //! pskip, which are at risk of becoming dangling pointers in a copied
    //! instance.
    //!
    //! We declare these protected instead of simply deleting them so that
    //! CDiskBlockIndex can reuse copy construction.
    CBlockIndex(const CBlockIndex&) = default;
    CBlockIndex& operator=(const CBlockIndex&) = delete;
    CBlockIndex(CBlockIndex&&) = delete;
    CBlockIndex& operator=(CBlockIndex&&) = delete;
};

/** Compute how much work an nBits value corresponds to. */
arith_uint256 GetBitsProof(uint32_t bits);

/** Compute how much work a block index entry corresponds to. */
inline arith_uint256 GetBlockProof(const CBlockIndex& block) { return GetBitsProof(block.nBits); }

/** Compute how much work a block header corresponds to. */
inline arith_uint256 GetBlockProof(const CBlockHeader& header) { return GetBitsProof(header.nBits); }

/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params&);
/** Find the forking point between two chain tips. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb);


/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
    /** Historically CBlockLocator's version field has been written to disk
     * streams as the client version, but the value has never been used.
     *
     * Hard-code to the highest client version ever written.
     * SerParams can be used if the field requires any meaning in the future.
     **/
    static constexpr int DUMMY_VERSION = 259900;

public:
    uint256 hashPrev;

    CDiskBlockIndex()
    {
        hashPrev = uint256();
    }

    explicit CDiskBlockIndex(const CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
    }

    SERIALIZE_METHODS(CDiskBlockIndex, obj)
    {
        LOCK(::cs_main);
        int _nVersion = DUMMY_VERSION;
        READWRITE(VARINT_MODE(_nVersion, VarIntMode::NONNEGATIVE_SIGNED));

        READWRITE(VARINT_MODE(obj.nHeight, VarIntMode::NONNEGATIVE_SIGNED));
        uint32_t nStatus{obj.nStatus};
        READWRITE(VARINT(nStatus));
        SER_READ(obj, obj.nStatus = nStatus);
        READWRITE(VARINT(obj.nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) {
            int nFile{obj.nFile};
            READWRITE(VARINT_MODE(nFile, VarIntMode::NONNEGATIVE_SIGNED));
            SER_READ(obj, obj.nFile = nFile);
        }
        if (nStatus & BLOCK_HAVE_DATA) {
            unsigned int nDataPos{obj.nDataPos};
            READWRITE(VARINT(nDataPos));
            SER_READ(obj, obj.nDataPos = nDataPos);
        }
        if (nStatus & BLOCK_HAVE_UNDO) {
            unsigned int nUndoPos{obj.nUndoPos};
            READWRITE(VARINT(nUndoPos));
            SER_READ(obj, obj.nUndoPos = nUndoPos);
        }

        // block header
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrev);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);
    }

    uint256 ConstructBlockHash() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block.GetHash();
    }

    uint256 GetBlockHash() = delete;
    std::string ToString() = delete;
};

/** A wrapper for creating a constant-sized serialization without varint encoding */
struct DiskBlockIndexWrapper : CDiskBlockIndex {
    static constexpr size_t SERIALIZED_SIZE{104};

    DiskBlockIndexWrapper() = default;

    explicit DiskBlockIndexWrapper(const CDiskBlockIndex* pindex) : CDiskBlockIndex(*pindex)
    {
    }

    SERIALIZE_METHODS(DiskBlockIndexWrapper, obj)
    {
        LOCK(::cs_main);
        uint32_t nStatus{obj.nStatus};
        int nFile{obj.nFile};
        unsigned int nDataPos{obj.nDataPos};
        unsigned int nUndoPos{obj.nUndoPos};
        READWRITE(obj.nHeight, nStatus, obj.nTx, nFile, nDataPos, nUndoPos);
        SER_READ(obj, obj.nStatus = nStatus);
        SER_READ(obj, obj.nFile = nFile);
        SER_READ(obj, obj.nDataPos = nDataPos);
        SER_READ(obj, obj.nUndoPos = nUndoPos);
        // block header
        READWRITE(obj.nVersion, obj.hashPrev, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }
};

/** An in-memory indexed chain of blocks.
 *
 * Copies share the block list until a write. A copy is a snapshot: later
 * SetTip calls on the original do not change the copy. Readers copy the
 * chain, then walk the snapshot without holding the writer lock.
 */
class CChain
{
private:
    mutable Mutex m_mutex;
    //! Published block list. Replaced, not edited, on SetTip.
    std::shared_ptr<const std::vector<CBlockIndex*>> m_blocks{std::make_shared<const std::vector<CBlockIndex*>>()};

    std::shared_ptr<const std::vector<CBlockIndex*>> Load() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_blocks;
    }

public:
    CChain() = default;
    CChain(const CChain& other) EXCLUSIVE_LOCKS_REQUIRED(!other.m_mutex) : m_blocks{other.Load()} {}
    CChain& operator=(const CChain& other) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex, !other.m_mutex)
    {
        if (this == &other) return *this;
        auto blocks{other.Load()};
        LOCK(m_mutex);
        m_blocks = std::move(blocks);
        return *this;
    }

    /** Returns the index entry for the genesis block of this chain, or nullptr if none. */
    CBlockIndex* Genesis() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const auto blocks{Load()};
        return blocks->empty() ? nullptr : blocks->front();
    }

    /** Returns the index entry for the tip of this chain, or nullptr if none. */
    CBlockIndex* Tip() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const auto blocks{Load()};
        return blocks->empty() ? nullptr : blocks->back();
    }

    /** Returns the index entry at a particular height in this chain, or nullptr if no such height exists. */
    CBlockIndex* operator[](int nHeight) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const auto blocks{Load()};
        if (nHeight < 0 || nHeight >= (int)blocks->size())
            return nullptr;
        return (*blocks)[nHeight];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        return (*this)[index.nHeight] == &index;
    }

    /** Find the successor of a block in this chain, or nullptr if the given index is not found or is the tip. */
    CBlockIndex* Next(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        if (Contains(index))
            return (*this)[index.nHeight + 1];
        else
            return nullptr;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        return int(Load()->size()) - 1;
    }

    /** Check whether this chain's tip exists, has enough work, and is recent. */
    bool IsTipRecent(const arith_uint256& min_chain_work, std::chrono::seconds max_tip_age, NodeClock::time_point now) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const auto tip{Tip()};
        // Use seconds precision: if max_tip_age is very large (e.g. INT64_MAX),
        // subtracting it from a nanosecond time_point would overflow int64.
        return tip &&
               tip->nChainWork >= min_chain_work &&
               tip->Time() >= std::chrono::time_point_cast<std::chrono::seconds>(now) - max_tip_age;
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex* FindFork(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Find the earliest block with timestamp equal or greater than the given time and height equal or greater than the given height. */
    CBlockIndex* FindEarliestAtLeast(int64_t nTime, int height) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

/** Get a locator for a block index entry. */
CBlockLocator GetLocator(const CBlockIndex* index);

/** Construct a list of hash entries to put in a locator.  */
std::vector<uint256> LocatorEntries(const CBlockIndex* index);

#endif // BITCOIN_CHAIN_H
