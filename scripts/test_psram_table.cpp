#include <cassert>
#include <cstdio>
#include <random>
#include <unordered_set>

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
    g_psramTotal = 256u * 1024 * 1024;
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
    CHECK(t.size() == 0 && g_psramUsed == 0);
}

static void testEvictionUnderPressure()
{
    g_psramTotal = 512u * 1024 + 1536u * 1024;
    g_psramPeak = 0;
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
        CHECK(g_psramUsed <= g_psramTotal - t.reserve() + 4096);
    }
    CHECK(nulls == 0);
    CHECK(t.evicted() > 0);
    CHECK(t.evicted() == g_hookCalls);
    CHECK(t.size() == ref.size());
    CHECK(t.inserted() == t.size() + t.evicted());
    for (uint64_t k : ref) CHECK(t.find(k) != nullptr);
    CHECK(consistent(t));
    std::printf("  pressure: held=%zu evicted=%u peak=%zu budget=%zu\n", t.size(), t.evicted(), g_psramPeak,
                g_psramTotal);
    g_ref = nullptr;
    t.clear();
    CHECK(g_psramUsed == 0);
}

static void testOutlierAgeEvictsOnlyAnEighth()
{
    g_psramTotal = 512u * 1024 + 600u * 1024;
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

static void testNoPsram()
{
    g_psramTotal = 0;
    g_psramUsed = 0;
    PsramTable<Payload> t;
    bool isNew = true;
    CHECK(t.upsert(7, 1, &isNew) == nullptr);
    CHECK(!isNew && t.allocFailures() == 1 && t.size() == 0);
}

static void testWrapAges()
{
    g_psramTotal = 512u * 1024 + 300u * 1024;
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
static void spillToDurable(const PsramTable<Payload>::Entry &e, void *)
{
    bool isNew = false;
    if (g_durable) g_durable->upsert(e.key, e.lastMs, &isNew);
}

static void testWorkingTableYieldsToDurable()
{
    g_psramTotal = 4u * 1024 * 1024;
    g_psramUsed = 0;
    PsramTable<Payload> durable;
    PsramTable<Payload> working;
    working.setReserve(PsramTable<Payload>::reserveFraction(2, 1024 * 1024));
    working.setEvictHook(spillToDurable, nullptr);
    g_durable = &durable;
    const uint32_t N = 46000;
    bool isNew = false;
    for (uint32_t i = 0; i < N; i++) CHECK(working.upsert(0x5000000000ULL + i, i, &isNew) != nullptr);
    const size_t workingHeld = working.size();
    const uint32_t workingEvicted = working.evicted();
    working.releaseIndex();
    while (working.size()) {
        const size_t n = working.size();
        const size_t start = (n - 1) & ~(size_t)(PsramTable<Payload>::kBlockLen - 1);
        for (size_t i = start; i < n; i++) durable.upsert(working.at(i).key, working.at(i).lastMs, &isNew);
        working.popBack(n - start);
    }
    CHECK(workingEvicted > 0);
    CHECK(workingHeld < N);
    CHECK(durable.evicted() == 0);
    CHECK(durable.size() == N);
    CHECK(consistent(durable));
    std::printf("  priority: working held=%zu evicted=%u durable=%zu\n", workingHeld, workingEvicted,
                durable.size());
    g_durable = nullptr;
    working.clear();
    durable.clear();
    CHECK(g_psramUsed == 0);
}

static void testIndexReleaseAndRegrow()
{
    g_psramTotal = 64u * 1024 * 1024;
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
    CHECK(g_psramUsed == 0);
}

int main()
{
    testIndexReleaseAndRegrow();
    testWorkingTableYieldsToDurable();
    testUnboundedInsert();
    testEvictionUnderPressure();
    testOutlierAgeEvictsOnlyAnEighth();
    testNoPsram();
    testWrapAges();
    if (failures) {
        std::printf("psram_table: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("psram_table: all tests passed\n");
    return 0;
}
