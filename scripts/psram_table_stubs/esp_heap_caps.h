#pragma once

#include <cstddef>
#include <cstdlib>

#define MALLOC_CAP_8BIT (1u << 2)
#define MALLOC_CAP_SPIRAM (1u << 10)

inline size_t g_psramTotal = 0;
inline size_t g_psramUsed = 0;
inline size_t g_psramPeak = 0;

inline void *heap_caps_malloc(size_t n, unsigned)
{
    if (g_psramUsed + n > g_psramTotal) return nullptr;
    size_t *h = static_cast<size_t *>(std::malloc(n + 16));
    if (!h) return nullptr;
    *h = n;
    g_psramUsed += n;
    if (g_psramUsed > g_psramPeak) g_psramPeak = g_psramUsed;
    return reinterpret_cast<char *>(h) + 16;
}

inline void heap_caps_free(void *p)
{
    if (!p) return;
    size_t *h = reinterpret_cast<size_t *>(static_cast<char *>(p) - 16);
    g_psramUsed -= *h;
    std::free(h);
}

inline size_t heap_caps_get_free_size(unsigned) { return g_psramTotal - g_psramUsed; }
inline size_t heap_caps_get_largest_free_block(unsigned) { return g_psramTotal - g_psramUsed; }
inline size_t heap_caps_get_total_size(unsigned) { return g_psramTotal; }
