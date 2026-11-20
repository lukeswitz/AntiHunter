#include "cache_heap.h"

#include <atomic>
#include <cstdint>

#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "multi_heap.h"

namespace {

struct Shedder {
    const void *owner;
    CacheShedFn fn;
    void *ctx;
};

constexpr size_t kMaxShedders = 16;
portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
multi_heap_handle_t s_heap = nullptr;
uint8_t *s_base = nullptr;
size_t s_size = 0;
Shedder s_shedders[kMaxShedders];
std::atomic<size_t> s_shedderCount{0};
std::atomic<void *> s_shedTask{nullptr};

bool inRegion(const void *p)
{
    const uint8_t *b = static_cast<const uint8_t *>(p);
    return s_base && b >= s_base && b < s_base + s_size;
}

}  // namespace

bool cacheHeapInit(size_t systemBytes)
{
    if (s_heap) return true;
    const size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if (largest <= systemBytes) return false;
    const size_t bytes = (largest - systemBytes) & ~(size_t)15;
    void *block = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!block) return false;
    multi_heap_handle_t h = multi_heap_register(block, bytes);
    if (!h) {
        heap_caps_free(block);
        return false;
    }
    multi_heap_set_lock(h, &s_lock);
    s_base = static_cast<uint8_t *>(block);
    s_size = bytes;
    s_heap = h;
    heap_caps_monitor_local_minimum_free_size_start();
    return true;
}

void *cacheHeapAlloc(size_t bytes)
{
    if (!s_heap) return heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return multi_heap_malloc(s_heap, bytes);
}

void cacheHeapRelease(void *p)
{
    if (!p) return;
    if (inRegion(p))
        multi_heap_free(s_heap, p);
    else
        heap_caps_free(p);
}

size_t cacheHeapSize() { return s_size; }
size_t cacheHeapFreeBytes() { return s_heap ? multi_heap_free_size(s_heap) : 0; }
size_t cacheHeapMinFreeBytes() { return s_heap ? multi_heap_minimum_free_size(s_heap) : 0; }
size_t cacheHeapSystemMinFreeBytes() { return heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM); }

void cacheHeapAddShedder(const void *owner, CacheShedFn fn, void *ctx)
{
    const size_t n = s_shedderCount.load();
    for (size_t i = 0; i < n; i++)
        if (s_shedders[i].owner == owner) return;
    if (n >= kMaxShedders) return;
    s_shedders[n] = {owner, fn, ctx};
    s_shedderCount.store(n + 1);
}

size_t cacheHeapShedOthers(const void *owner)
{
    void *me = xTaskGetCurrentTaskHandle();
    void *idle = nullptr;
    if (!s_shedTask.compare_exchange_strong(idle, me)) return 0;
    size_t freed = 0;
    const size_t n = s_shedderCount.load();
    for (size_t i = 0; i < n; i++)
        if (s_shedders[i].owner != owner) freed += s_shedders[i].fn(s_shedders[i].ctx);
    s_shedTask.store(nullptr);
    return freed;
}

bool cacheHeapMakeRoom(size_t bytes, const void *owner, CacheShedFn shedSelf, void *ctx)
{
    for (;;) {
        void *p = cacheHeapAlloc(bytes);
        if (p) {
            cacheHeapRelease(p);
            return true;
        }
        size_t freed = cacheHeapShedOthers(owner);
        if (shedSelf) freed += shedSelf(ctx);
        if (freed == 0) return false;
    }
}
