#include <cstdio>
#include <cstdint>

#include "cuckoo_filter.h"

static int failures = 0;
#define CHECK(c)                                                         \
    do {                                                                 \
        if (!(c)) {                                                      \
            std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c);      \
            failures++;                                                  \
        }                                                                \
    } while (0)

static uint64_t key(uint32_t i, uint64_t tag) { return tag | ((uint64_t)i * 2654435761ULL & 0xFFFFFFFFFFULL); }

int main()
{
    g_psramTotal = 8u << 20;
    {
        CuckooFilter cf;
        CHECK(cf.reserve(65536));
        CHECK(cf.bytes() == 256 * 1024);

        const uint32_t N = 200000;
        uint32_t added = 0, missing = 0, recounted = 0, fp = 0;
        for (uint32_t i = 0; i < N; i++) added += cf.insertIfNew(key(i, 0x020000000000ULL));
        for (uint32_t i = 0; i < N; i++) missing += !cf.contains(key(i, 0x020000000000ULL));
        for (uint32_t i = 0; i < N; i++) recounted += cf.insertIfNew(key(i, 0x020000000000ULL));
        for (uint32_t i = 0; i < N; i++) fp += cf.contains(key(i, 0x040000000000ULL));
        std::printf("added=%u/%u missing=%u recounted=%u fp=%.2f%%\n", added, N, missing, recounted, 100.0 * fp / N);
        CHECK(missing == 0);
        CHECK(recounted == 0);
        CHECK(added == cf.count());
        CHECK(added >= N * 0.98);
        CHECK(100.0 * fp / N < 5.0);

        cf.clear();
        CHECK(cf.count() == 0);
        CHECK(!cf.contains(key(1, 0x020000000000ULL)));
    }
    CHECK(g_psramUsed == 0);
    for (int i = 0; i < 64; i++) {
        CuckooFilter tmp;
        CHECK(tmp.reserve(65536));
    }
    CHECK(g_psramUsed == 0);

    std::printf("%s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
