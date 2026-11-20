#pragma once

#include <cstddef>
#include <cstdint>

// Erases about the oldest eighth of a map by last-seen age, calling onEvict before each erase; no allocation.
template <class Map, class LastSeenOf, class OnEvict>
size_t shedOldestEighth(Map &m, uint32_t now, LastSeenOf lastSeenOf, OnEvict onEvict)
{
    const size_t n = m.size();
    if (n == 0) return 0;
    const size_t target = n / 8 ? n / 8 : 1;
    uint32_t minAge = UINT32_MAX, maxAge = 0;
    for (const auto &kv : m) {
        const uint32_t a = now - lastSeenOf(kv.second);
        if (a < minAge) minAge = a;
        if (a > maxAge) maxAge = a;
    }
    const uint64_t span = (uint64_t)(maxAge - minAge) + 1;
    auto bucketOf = [&](const typename Map::mapped_type &v) -> uint32_t {
        return (uint32_t)((uint64_t)(now - lastSeenOf(v) - minAge) * 64 / span);
    };
    size_t hist[64] = {0};
    for (const auto &kv : m) hist[bucketOf(kv.second)]++;
    uint32_t cut = 64;
    size_t acc = 0;
    while (cut > 0 && acc < target) acc += hist[--cut];
    size_t takeAtCut = target - (acc - hist[cut]);
    size_t dropped = 0;
    for (auto it = m.begin(); it != m.end();) {
        const uint32_t b = bucketOf(it->second);
        bool drop = b > cut;
        if (b == cut && takeAtCut) {
            drop = true;
            takeAtCut--;
        }
        if (!drop) {
            ++it;
            continue;
        }
        onEvict(*it);
        it = m.erase(it);
        dropped++;
    }
    return dropped;
}
