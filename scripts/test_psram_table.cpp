#include <cassert>
#include <cstdio>
#include <map>
#include <random>
#include <unordered_set>

#include "cache_heap.h"
#include "cache_shed.h"
#include "esp_heap_caps.h"
#include "multi_heap.h"
#include "psram_table.h"

struct Payload {
    uint32_t a;
    char name[32];
};

static int failures = 0;
#define CHECK(c)                                                         \
    do {                                                                 \
        if (!(c)) {                                                      \
            std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c);      \
            failures++;                                                  \
        }                                                                \
    } while (0)

static std::unordered_set<uint64_t> *g_ref = nullptr;
static uint32_t g_hookCalls = 0;

static void onEvict(const PsramTable<Payload>::Entry &e, void *)
{
    g_hookCalls++;
    if (g_ref) g_ref->erase(e.key);
}

template <typename T>
static bool consistent(const T &t)
{
    for (size_t i = 0; i < t.size(); i++) {
        auto *e = t.find(t.at(i).key);
        if (e != &t.at(i)) return false;
    }
    return true;
}

static void testUnboundedInsert()
{
    g_regionBudget = 256u * 1024 * 1024;
    PsramTable<Payload> t;
    const uint32_t N = 200000;
    for (uint32_t i = 0; i < N; i++) {
        bool isNew = false;
        auto *e = t.upsert(0x100000000ULL + i, i, &isNew);
        CHECK(e && isNew);
        if (e) e->val.a = i;
    }
    CHECK(t.size() == N);
    CHECK(t.inserted() == N);
    CHECK(t.evicted() == 0);
    for (uint32_t i = 0; i < N; i += 997) {
        auto *e = t.find(0x100000000ULL + i);
        CHECK(e && e->val.a == i);
    }
    bool isNew = true;
    auto *dup = t.upsert(0x100000000ULL + 5, N + 1, &isNew);
    CHECK(dup && !isNew && dup->lastMs == N + 1);
    CHECK(t.size() == N);
    CHECK(t.find(0xDEADBEEFULL) == nullptr);
    CHECK(consistent(t));
    t.clear();
    CHECK(t.size() == 0 && g_regionUsed == 0);
}

static void testEvictionWhenRegionFull()
{
    g_regionBudget = 1536u * 1024;
    std::unordered_set<uint64_t> ref;
    g_ref = &ref;
    g_hookCalls = 0;
    PsramTable<Payload> t;
    t.setEvictHook(onEvict, nullptr);
    std::mt19937_64 rng(42);
    uint32_t now = 1000;
    uint32_t nulls = 0;
    for (uint32_t i = 0; i < 300000; i++) {
        now += 3;
        const uint64_t key = rng() & 0xFFFFFFFFFFFFULL;
        bool isNew = false;
        auto *e = t.upsert(key, now, &isNew);
        if (!e) {
            nulls++;
            continue;
        }
        if (isNew) ref.insert(key);
        CHECK(g_regionUsed <= g_regionBudget);
    }
    CHECK(nulls == 0);
    CHECK(t.evicted() > 0);
    CHECK(t.evicted() == g_hookCalls);
    CHECK(t.size() == ref.size());
    CHECK(t.inserted() == t.size() + t.evicted());
    for (uint64_t k : ref) CHECK(t.find(k) != nullptr);
    CHECK(consistent(t));
    std::printf("  region full: held=%zu evicted=%u used=%zu budget=%zu\n", t.size(), t.evicted(), g_regionUsed,
                g_regionBudget);
    g_ref = nullptr;
    t.clear();
    CHECK(g_regionUsed == 0);
}

static void testOutlierAgeEvictsOnlyAnEighth()
{
    g_regionBudget = 600u * 1024;
    PsramTable<Payload> t;
    bool isNew = false;
    t.upsert(1, 0, &isNew);
    uint64_t k = 2;
    for (;;) {
        const uint32_t before = t.evicted();
        t.upsert(k++, 4000000000u, &isNew);
        if (t.evicted() != before) {
            const size_t held = t.size();
            const uint32_t dropped = t.evicted() - before;
            CHECK(t.find(1) == nullptr);
            CHECK(dropped <= (held + dropped) / 8 + 1);
            CHECK(held > 0);
            std::printf("  outlier: dropped=%u of %zu\n", dropped, held + dropped);
            break;
        }
        CHECK(k < 10000000);
        if (k >= 10000000) break;
    }
    CHECK(consistent(t));
    t.clear();
}

static void testEmptyRegion()
{
    g_regionBudget = 0;
    PsramTable<Payload> t;
    bool isNew = true;
    CHECK(t.upsert(7, 1, &isNew) == nullptr);
    CHECK(!isNew && t.allocFailures() == 1 && t.size() == 0);
}

static void testWrapAges()
{
    g_regionBudget = 300u * 1024;
    PsramTable<Payload> t;
    bool isNew = false;
    uint32_t now = 0xFFFFFF00u;
    uint64_t k = 1;
    while (t.evicted() == 0) {
        now += 1;
        t.upsert(k++, now, &isNew);
    }
    CHECK(t.find(k - 1) != nullptr);
    CHECK(t.find(1) == nullptr);
    CHECK(consistent(t));
    t.clear();
}

static PsramTable<Payload> *g_durable = nullptr;
static std::unordered_set<uint64_t> *g_sd = nullptr;
static uint32_t g_durableNow = 0;

static void durableToSd(const PsramTable<Payload>::Entry &e, void *)
{
    if (g_sd) g_sd->insert(e.key);
}

static void workingToDurable(const PsramTable<Payload>::Entry &e, void *)
{
    bool isNew = false;
    if (g_durable && !g_durable->upsert(e.key, e.lastMs, &isNew) && g_sd) g_sd->insert(e.key);
}

static size_t shedDurable(void *)
{
    return g_durable ? g_durable->shed(g_durableNow) : 0;
}

// A full region makes the other registered caches give memory back; every key ends up in RAM or on "SD".
static void testOtherCachesShedAndNothingIsLost()
{
    g_regionBudget = 4u * 1024 * 1024;
    PsramTable<Payload> durable;
    PsramTable<Payload> working;
    std::unordered_set<uint64_t> sd;
    durable.setEvictHook(durableToSd, nullptr);
    working.setEvictHook(workingToDurable, nullptr);
    g_durable = &durable;
    g_sd = &sd;
    cacheHeapAddShedder(&durable, shedDurable, nullptr);

    bool isNew = false;
    const uint32_t D = 20000;
    for (uint32_t i = 0; i < D; i++) CHECK(durable.upsert(0x7000000000ULL + i, i, &isNew) != nullptr);
    g_durableNow = D;
    const size_t durableBefore = durable.size();

    const uint32_t N = 46000;
    for (uint32_t i = 0; i < N; i++) CHECK(working.upsert(0x5000000000ULL + i, D + i, &isNew) != nullptr);
    CHECK(durable.size() < durableBefore);
    CHECK(!sd.empty());

    working.releaseIndex();
    while (working.size()) {
        const size_t n = working.size();
        const size_t start = (n - 1) & ~(size_t)(PsramTable<Payload>::kBlockLen - 1);
        for (size_t i = start; i < n; i++) workingToDurable(working.at(i), nullptr);
        working.popBack(n - start);
    }
    size_t lost = 0;
    for (uint32_t i = 0; i < D; i++)
        if (!durable.find(0x7000000000ULL + i) && !sd.count(0x7000000000ULL + i)) lost++;
    for (uint32_t i = 0; i < N; i++)
        if (!durable.find(0x5000000000ULL + i) && !sd.count(0x5000000000ULL + i)) lost++;
    CHECK(lost == 0);
    CHECK(consistent(durable));
    std::printf("  shed others: durable %zu -> held %zu, on sd %zu, lost %zu\n", durableBefore, durable.size(),
                sd.size(), lost);
    g_durable = nullptr;
    g_sd = nullptr;
    working.clear();
    durable.clear();
    CHECK(g_regionUsed == 0);
}

static size_t g_nestedResult = 99;
static size_t nestedShedder(void *)
{
    g_nestedResult = cacheHeapShedOthers(nullptr);
    return 0;
}

static void testShedIsNotReentrant()
{
    static int owner;
    cacheHeapAddShedder(&owner, nestedShedder, nullptr);
    cacheHeapShedOthers(nullptr);
    CHECK(g_nestedResult == 0);
}

static void testMakeRoomShedsSelfThenGivesUp()
{
    g_regionBudget = 64u * 1024;
    std::map<uint32_t, uint32_t> m;
    std::unordered_set<uint32_t> moved;
    struct Ctx {
        std::map<uint32_t, uint32_t> *m;
        std::unordered_set<uint32_t> *moved;
    } ctx{&m, &moved};
    auto shedSelf = [](void *c) -> size_t {
        auto *x = static_cast<Ctx *>(c);
        return shedOldestEighth(*x->m, 100000u, [](uint32_t seen) { return seen; },
                                [x](const std::pair<const uint32_t, uint32_t> &kv) { x->moved->insert(kv.first); });
    };
    void *held = cacheHeapAlloc(60u * 1024);
    CHECK(held != nullptr);
    for (uint32_t i = 0; i < 64; i++) m[i] = i;
    static int self;
    CHECK(cacheHeapMakeRoom(8u * 1024, &self, shedSelf, &ctx) == false);
    CHECK(m.empty());
    CHECK(moved.size() == 64);
    cacheHeapRelease(held);
    CHECK(cacheHeapMakeRoom(8u * 1024, &self, shedSelf, &ctx) == true);
    CHECK(g_regionUsed == 0);
}

static void testShedOldestEighthTakesTheOldest()
{
    std::map<uint32_t, uint32_t> m;
    for (uint32_t i = 0; i < 800; i++) m[i] = 1000 + i;
    std::unordered_set<uint32_t> moved;
    const size_t n = shedOldestEighth(m, 5000u, [](uint32_t seen) { return seen; },
                                      [&](const std::pair<const uint32_t, uint32_t> &kv) { moved.insert(kv.first); });
    CHECK(n == 100);
    CHECK(m.size() == 700);
    for (uint32_t i = 0; i < 100; i++) CHECK(moved.count(i) == 1);
    for (uint32_t i = 100; i < 800; i++) CHECK(m.count(i) == 1);
}

static void testIndexReleaseAndRegrow()
{
    g_regionBudget = 64u * 1024 * 1024;
    PsramTable<Payload> t;
    bool isNew = false;
    for (uint64_t k = 1; k <= 10000; k++) t.upsert(k, 1, &isNew);
    t.releaseIndex();
    CHECK(t.find(5000) != nullptr);
    CHECK(t.find(20000) == nullptr);
    auto *e = t.upsert(5000, 2, &isNew);
    CHECK(e && !isNew && t.size() == 10000);
    e = t.upsert(20000, 2, &isNew);
    CHECK(e && isNew && t.size() == 10001);
    CHECK(consistent(t));
    t.popBack(5001);
    CHECK(t.size() == 5000 && t.find(4999) && !t.find(5001));
    CHECK(consistent(t));
    t.clear();
    CHECK(g_regionUsed == 0);
}

int main()
{
    g_psramTotal = 512u * 1024 * 1024;
    CHECK(cacheHeapInit(1024 * 1024));
    CHECK(cacheHeapSize() > 0);
    testIndexReleaseAndRegrow();
    testUnboundedInsert();
    testEvictionWhenRegionFull();
    testOutlierAgeEvictsOnlyAnEighth();
    testEmptyRegion();
    testWrapAges();
    testShedOldestEighthTakesTheOldest();
    testMakeRoomShedsSelfThenGivesUp();
    testOtherCachesShedAndNothingIsLost();
    testShedIsNotReentrant();
    if (failures) {
        std::printf("psram_table: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("psram_table: all tests passed\n");
    return 0;
}
