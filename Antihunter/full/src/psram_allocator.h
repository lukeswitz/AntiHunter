#pragma once

#include <Arduino.h>
#include <cstddef>
#include <limits>
#include <new>

#include "cache_heap.h"

extern "C" {
#include "esp_heap_caps.h"
}

// Heavy allocs -> PSRAM (both boards); C5 needs custom_sdkconfig WiFi/LWIP-internal + reserve; ISR queues internal (scanner.h)
#ifdef ARDUINO_XIAO_ESP32C5
#define AH_ALLOC_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#else
#define AH_ALLOC_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#endif

// InCache: records go to the cache region; callers make room with cacheHeapMakeRoom before inserting.
template <typename T, bool InCache>
struct PsramAllocatorBase {
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    PsramAllocatorBase() noexcept = default;
    template <typename U>
    explicit PsramAllocatorBase(const PsramAllocatorBase<U, InCache>&) noexcept {}

    // cppcheck-suppress unusedFunction // STL allocator API, called via PsramMap/Vec/Set template instantiation
    static T* allocate(size_type n) {
        if (n == 0) return nullptr;
        if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        void* p = InCache ? cacheHeapAlloc(n * sizeof(T)) : nullptr;
        if (!p) p = heap_caps_malloc(n * sizeof(T), AH_ALLOC_CAPS);
        if (!p && !InCache) {
            p = heap_caps_malloc(n * sizeof(T), MALLOC_CAP_DEFAULT);
        }
        if (!p) throw std::bad_alloc();
        return static_cast<T*>(p);
    }

    // cppcheck-suppress unusedFunction // STL allocator API, called via container template instantiation
    static void deallocate(T* p, size_type) noexcept {
        if (InCache) cacheHeapRelease(p);
        else if (p) heap_caps_free(p);
    }

    template <typename U>
    struct rebind {
        using other = PsramAllocatorBase<U, InCache>;
    };
};

template <typename T>
using PsramAllocator = PsramAllocatorBase<T, false>;
template <typename T>
using CacheAllocator = PsramAllocatorBase<T, true>;

template <typename T, typename U, bool C>
bool operator==(const PsramAllocatorBase<T, C>&, const PsramAllocatorBase<U, C>&) noexcept { return true; }

template <typename T, typename U, bool C>
bool operator!=(const PsramAllocatorBase<T, C>&, const PsramAllocatorBase<U, C>&) noexcept { return false; }
