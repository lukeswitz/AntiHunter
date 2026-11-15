#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
#include "esp_heap_caps.h"
}

// Fixed-size cuckoo filter in PSRAM: 64-bit key membership in constant memory, ~3% false positive near capacity, no false negatives.
class CuckooFilter {
public:
    static constexpr uint32_t kSlots = 4;
    static constexpr uint32_t kMaxKicks = 500;

    bool reserve(uint32_t buckets) {
        if (buckets_) return true;
        uint32_t b = 1;
        while (b < buckets) b <<= 1;
        void *p = heap_caps_malloc((size_t)b * kSlots, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!p) return false;
        table_ = static_cast<uint8_t *>(p);
        memset(table_, 0, (size_t)b * kSlots);
        buckets_ = b;
        mask_ = b - 1;
        count_ = 0;
        return true;
    }

    void clear() {
        if (table_) memset(table_, 0, (size_t)buckets_ * kSlots);
        count_ = 0;
    }

    size_t count() const { return count_; }
    size_t bytes() const { return (size_t)buckets_ * kSlots; }

    bool contains(uint64_t key) const {
        if (!table_) return false;
        const uint8_t fp = fingerprint(key);
        const uint32_t i1 = index1(key);
        const uint32_t i2 = alt(i1, fp);
        return hasFp(i1, fp) || hasFp(i2, fp);
    }

    // Inserts key if absent; true if newly added, false if already present or on a rare table-full failure (counted as present so it is not recounted).
    bool insertIfNew(uint64_t key) {
        if (!table_) return false;
        if (contains(key)) return false;
        uint8_t fp = fingerprint(key);
        uint32_t i = index1(key);
        if (addTo(i, fp) || addTo(alt(i, fp), fp)) { count_++; return true; }
        uint32_t rng = (uint32_t)mix(key) | 1u;
        for (uint32_t n = 0; n < kMaxKicks; n++) {
            const uint32_t slot = rng & (kSlots - 1);
            rng = rng * 1664525u + 1013904223u;
            uint8_t *cell = &table_[(size_t)i * kSlots + slot];
            const uint8_t evicted = *cell;
            *cell = fp;
            fp = evicted;
            i = alt(i, fp);
            if (addTo(i, fp)) { count_++; return true; }
        }
        return false;
    }

private:
    static uint64_t mix(uint64_t k) {
        k ^= k >> 33;
        k *= 0xff51afd7ed558ccdULL;
        k ^= k >> 33;
        k *= 0xc4ceb9fe1a85ec53ULL;
        k ^= k >> 33;
        return k;
    }
    static uint8_t fingerprint(uint64_t key) {
        const uint8_t f = (uint8_t)(mix(key) >> 56);
        return f ? f : 1;
    }
    uint32_t index1(uint64_t key) const { return (uint32_t)(mix(key)) & mask_; }
    uint32_t alt(uint32_t i, uint8_t fp) const { return (i ^ (uint32_t)(mix(fp) & mask_)) & mask_; }
    bool hasFp(uint32_t i, uint8_t fp) const {
        const uint8_t *b = &table_[(size_t)i * kSlots];
        for (uint32_t s = 0; s < kSlots; s++) if (b[s] == fp) return true;
        return false;
    }
    bool addTo(uint32_t i, uint8_t fp) {
        uint8_t *b = &table_[(size_t)i * kSlots];
        for (uint32_t s = 0; s < kSlots; s++) if (b[s] == 0) { b[s] = fp; return true; }
        return false;
    }

    uint8_t *table_ = nullptr;
    uint32_t buckets_ = 0;
    uint32_t mask_ = 0;
    size_t count_ = 0;
};
