#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

extern "C" {
#include "esp_heap_caps.h"
}

// PSRAM-only keyed table, no entry limit, never throws; caller locks; pointers valid until next upsert/clear.
template <typename V>
class PsramTable {
    static_assert(std::is_trivially_copyable<V>::value, "PsramTable payload must be trivially copyable");

public:
    struct Entry {
        uint64_t key;
        uint32_t firstMs;
        uint32_t lastMs;
        V val;
    };
    using EvictFn = void (*)(const Entry &, void *ctx);

    static constexpr uint32_t kBlockShift = 9;
    static constexpr uint32_t kBlockLen = 1u << kBlockShift;
    static constexpr uint32_t kMinSlots = 1024;
    static constexpr size_t kMinReserve = 512 * 1024;

    PsramTable() = default;
    PsramTable(const PsramTable &) = delete;
    PsramTable &operator=(const PsramTable &) = delete;
    ~PsramTable() { release(); }

    void setEvictHook(EvictFn fn, void *ctx) { evictFn_ = fn; evictCtx_ = ctx; }
    // PSRAM this table leaves free; a larger value makes it yield memory before tables with smaller ones.
    void setReserve(size_t bytes) { reserve_ = bytes; }
    size_t reserve() const { return reserve_ ? reserve_ : defaultReserve(); }

    void clear() {
        release();
        inserted_.store(0, std::memory_order_relaxed);
        evicted_ = 0;
        allocFail_ = 0;
    }

    size_t size() const { return count_; }
    uint32_t inserted() const { return inserted_.load(std::memory_order_relaxed); }
    uint32_t evicted() const { return evicted_; }
    uint32_t allocFailures() const { return allocFail_; }
    size_t bytesUsed() const {
        return (size_t)nBlocks_ * kBlockLen * sizeof(Entry) + (size_t)slots_ * sizeof(uint32_t) +
               (size_t)blocksCap_ * sizeof(Entry *);
    }

    Entry &at(size_t i) const { return blocks_[i >> kBlockShift][i & (kBlockLen - 1)]; }

    Entry *find(uint64_t key) const {
        if (!slots_) {
            for (size_t i = 0; i < count_; i++)
                if (at(i).key == key) return &at(i);
            return nullptr;
        }
        const uint32_t mask = slots_ - 1;
        for (uint32_t i = hash(key) & mask;; i = (i + 1) & mask) {
            const uint32_t v = index_[i];
            if (v == 0) return nullptr;
            Entry &e = at(v - 1);
            if (e.key == key) return &e;
        }
    }

    // nullptr only when PSRAM cannot hold one entry even after eviction.
    Entry *upsert(uint64_t key, uint32_t now, bool *isNew) {
        *isNew = false;
        if (Entry *e = find(key)) {
            e->lastMs = now;
            return e;
        }
        if (!ensureRoom(now)) {
            allocFail_++;
            return nullptr;
        }
        const uint32_t idx = (uint32_t)count_++;
        Entry &e = at(idx);
        memset(&e, 0, sizeof(e));
        e.key = key;
        e.firstMs = now;
        e.lastMs = now;
        indexInsert(key, idx);
        inserted_.fetch_add(1, std::memory_order_relaxed);
        *isNew = true;
        return &e;
    }

    // Frees the lookup index; find() falls back to a scan and the next upsert rebuilds it.
    void releaseIndex() {
        if (index_) heap_caps_free(index_);
        index_ = nullptr;
        slots_ = 0;
    }

    // Drops the last k entries without the hook and gives whole blocks past the new end back to the heap.
    void popBack(size_t k) {
        count_ = k >= count_ ? 0 : count_ - k;
        if (count_ == 0) {
            release();
            return;
        }
        const uint32_t keep = (uint32_t)((count_ + kBlockLen - 1) >> kBlockShift);
        while (nBlocks_ > keep) heap_caps_free(blocks_[--nBlocks_]);
        fitIndex();
    }

    static size_t reserveBytes() { return reserveFraction(8, kMinReserve); }
    static size_t defaultReserve() { return reserveBytes(); }
    static size_t reserveFraction(size_t divisor, size_t floor) {
        const size_t r = heap_caps_get_total_size(MALLOC_CAP_SPIRAM) / divisor;
        return r < floor ? floor : r;
    }

private:
    static uint32_t hash(uint64_t k) {
        k ^= k >> 33;
        k *= 0xff51afd7ed558ccdULL;
        k ^= k >> 33;
        k *= 0xc4ceb9fe1a85ec53ULL;
        k ^= k >> 33;
        return (uint32_t)k;
    }

    void *psramAlloc(size_t bytes) const {
        if (heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) < bytes) return nullptr;
        if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < bytes + reserve()) return nullptr;
        return heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }

    void release() {
        for (uint32_t b = 0; b < nBlocks_; b++) heap_caps_free(blocks_[b]);
        if (blocks_) heap_caps_free(blocks_);
        if (index_) heap_caps_free(index_);
        blocks_ = nullptr;
        index_ = nullptr;
        nBlocks_ = blocksCap_ = slots_ = 0;
        count_ = 0;
    }

    void indexInsert(uint64_t key, uint32_t idx) {
        const uint32_t mask = slots_ - 1;
        uint32_t i = hash(key) & mask;
        while (index_[i] != 0) i = (i + 1) & mask;
        index_[i] = idx + 1;
    }

    bool addBlock() {
        if (nBlocks_ == blocksCap_) {
            const uint32_t cap = blocksCap_ ? blocksCap_ * 2 : 16;
            Entry **nb = static_cast<Entry **>(psramAlloc(cap * sizeof(Entry *)));
            if (!nb) return false;
            if (blocks_) {
                memcpy(nb, blocks_, nBlocks_ * sizeof(Entry *));
                heap_caps_free(blocks_);
            }
            blocks_ = nb;
            blocksCap_ = cap;
        }
        Entry *blk = static_cast<Entry *>(psramAlloc(kBlockLen * sizeof(Entry)));
        if (!blk) return false;
        blocks_[nBlocks_++] = blk;
        return true;
    }

    bool growIndex() {
        uint32_t ns = slots_ ? slots_ * 2 : kMinSlots;
        while (ns && (size_t)ns < (count_ + 1) * 2) ns <<= 1;
        if (ns <= slots_) return false;
        uint32_t *ni = static_cast<uint32_t *>(psramAlloc((size_t)ns * sizeof(uint32_t)));
        if (!ni) return false;
        if (index_) heap_caps_free(index_);
        index_ = ni;
        slots_ = ns;
        rebuildIndex();
        return true;
    }

    // Shrinks an index that is 4x or more oversized; frees first so the net change is always a release.
    void fitIndex() {
        if (!index_) return;
        uint32_t ns = kMinSlots;
        while ((size_t)ns < (count_ + 1) * 2) ns <<= 1;
        if (slots_ >= ns * 4) {
            heap_caps_free(index_);
            index_ = static_cast<uint32_t *>(heap_caps_malloc((size_t)ns * sizeof(uint32_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
            slots_ = index_ ? ns : 0;
        }
        rebuildIndex();
    }

    void rebuildIndex() {
        if (!index_) return;
        memset(index_, 0, (size_t)slots_ * sizeof(uint32_t));
        for (uint32_t i = 0; i < count_; i++) indexInsert(at(i).key, i);
    }

    bool ensureRoom(uint32_t now) {
        for (int attempt = 0; attempt < 2; attempt++) {
            bool ok = true;
            if (count_ + 1 > (size_t)nBlocks_ * kBlockLen) ok = addBlock();
            if (ok && (count_ + 1) * 2 > slots_) ok = growIndex();
            if (ok) return true;
            if (count_ == 0 || evictOldest(now) == 0) return false;
        }
        return false;
    }

    // Drops about the oldest eighth by last-seen age via a 64-bucket histogram; no extra memory.
    size_t evictOldest(uint32_t now) {
        const uint32_t n = (uint32_t)count_;
        const uint32_t target = n / 8 ? n / 8 : 1;
        uint32_t minAge = UINT32_MAX, maxAge = 0;
        for (uint32_t i = 0; i < n; i++) {
            const uint32_t a = now - at(i).lastMs;
            if (a < minAge) minAge = a;
            if (a > maxAge) maxAge = a;
        }
        const uint64_t span = (uint64_t)(maxAge - minAge) + 1;
        auto bucketOf = [&](uint32_t i) -> uint32_t {
            return (uint32_t)((uint64_t)(now - at(i).lastMs - minAge) * 64 / span);
        };
        uint32_t hist[64] = {0};
        for (uint32_t i = 0; i < n; i++) hist[bucketOf(i)]++;
        uint32_t cut = 64, acc = 0;
        while (cut > 0 && acc < target) acc += hist[--cut];
        uint32_t takeAtCut = target - (acc - hist[cut]);

        uint32_t w = 0;
        size_t dropped = 0;
        for (uint32_t r = 0; r < n; r++) {
            const uint32_t b = bucketOf(r);
            bool drop = b > cut;
            if (b == cut && takeAtCut) {
                drop = true;
                takeAtCut--;
            }
            if (drop) {
                if (evictFn_) evictFn_(at(r), evictCtx_);
                dropped++;
                continue;
            }
            if (w != r) at(w) = at(r);
            w++;
        }
        count_ = w;
        evicted_ += (uint32_t)dropped;
        const uint32_t keep = (uint32_t)(count_ >> kBlockShift) + 1;
        while (nBlocks_ > keep) heap_caps_free(blocks_[--nBlocks_]);
        fitIndex();
        return dropped;
    }

    Entry **blocks_ = nullptr;
    uint32_t *index_ = nullptr;
    uint32_t nBlocks_ = 0;
    uint32_t blocksCap_ = 0;
    uint32_t slots_ = 0;
    size_t count_ = 0;
    std::atomic<uint32_t> inserted_{0};
    uint32_t evicted_ = 0;
    uint32_t allocFail_ = 0;
    size_t reserve_ = 0;
    EvictFn evictFn_ = nullptr;
    void *evictCtx_ = nullptr;
};
