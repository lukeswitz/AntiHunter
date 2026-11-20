#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>

struct StubMultiHeap {
    uint8_t *base;
    std::map<size_t, size_t> freeRanges;
    std::map<size_t, size_t> used;
};
typedef StubMultiHeap *multi_heap_handle_t;

inline size_t g_regionBudget = 0;
inline size_t g_regionUsed = 0;
inline size_t g_regionMinFree = SIZE_MAX;

inline multi_heap_handle_t multi_heap_register(void *start, size_t size)
{
    auto *h = new StubMultiHeap{static_cast<uint8_t *>(start), {}, {}};
    h->freeRanges[0] = size;
    return h;
}

inline void multi_heap_set_lock(multi_heap_handle_t, void *) {}

inline void *multi_heap_malloc(multi_heap_handle_t h, size_t n)
{
    n = (n + 15) & ~(size_t)15;
    if (n == 0 || g_regionUsed + n > g_regionBudget) return nullptr;
    for (auto it = h->freeRanges.begin(); it != h->freeRanges.end(); ++it) {
        if (it->second < n) continue;
        const size_t off = it->first, len = it->second;
        h->freeRanges.erase(it);
        if (len > n) h->freeRanges[off + n] = len - n;
        h->used[off] = n;
        g_regionUsed += n;
        if (g_regionBudget - g_regionUsed < g_regionMinFree) g_regionMinFree = g_regionBudget - g_regionUsed;
        return h->base + off;
    }
    return nullptr;
}

inline void multi_heap_free(multi_heap_handle_t h, void *p)
{
    if (!p) return;
    const size_t off = static_cast<size_t>(static_cast<uint8_t *>(p) - h->base);
    auto u = h->used.find(off);
    if (u == h->used.end()) return;
    size_t start = off, len = u->second;
    g_regionUsed -= len;
    h->used.erase(u);
    auto next = h->freeRanges.find(start + len);
    if (next != h->freeRanges.end()) {
        len += next->second;
        h->freeRanges.erase(next);
    }
    auto prev = h->freeRanges.lower_bound(start);
    if (prev != h->freeRanges.begin()) {
        --prev;
        if (prev->first + prev->second == start) {
            start = prev->first;
            len += prev->second;
            h->freeRanges.erase(prev);
        }
    }
    h->freeRanges[start] = len;
}

inline size_t multi_heap_free_size(multi_heap_handle_t) { return g_regionBudget - g_regionUsed; }
inline size_t multi_heap_minimum_free_size(multi_heap_handle_t) { return g_regionMinFree; }
