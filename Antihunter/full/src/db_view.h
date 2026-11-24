#pragma once
#include <Arduino.h>
#include <SD.h>
#include <esp_heap_caps.h>
#include <algorithm>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>
#include "cache_heap.h"
#include "scanner.h"
#include "sd_store.h"

String sanitizeAscii(const char *s, size_t maxLen);

struct DbSortKey {
    uint32_t rec;
    int64_t num;
    char str[33];
};

inline bool dbEpochOk(uint32_t t) { return t > 946684800u; }

inline void dbLower(const char *s, char *out, size_t cap)
{
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) out[i] = (char)tolower((unsigned char)s[i]);
    out[i] = '\0';
}

inline bool dbHas(const char *hay, const char *ql)
{
    char low[64];
    dbLower(hay, low, sizeof(low));
    return strstr(low, ql) != nullptr;
}

inline bool dbRangeOk(const DbView &v, uint32_t first, uint32_t last)
{
    if (!v.rangeFrom && !v.rangeTo) return true;
    uint32_t lo = dbEpochOk(first) ? first : 0, hi = dbEpochOk(last) ? last : 0;
    if (!lo && !hi) return false;
    if (!lo) lo = hi;
    if (!hi) hi = lo;
    return hi >= v.rangeFrom && lo <= v.rangeTo;
}

// Same filter as sanitizeAscii, into a caller buffer, so a scan allocates nothing per record.
inline void dbSanitize(const char *s, size_t maxLen, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < maxLen && s[i] && o + 1 < cap; i++) {
        const unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c <= 0x7E && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&') out[o++] = (char)c;
    }
    out[o] = '\0';
}

inline uint64_t dbHash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 1099511628211ULL;
    return h;
}

template <typename E>
bool dbMatchCommon(const E &e, const char *ql, const char *vend, const char *nm)
{
    if (dbHas(e.mac, ql) || dbHas(vend, ql) || dbHas(nm, ql)) return true;
    if (dbHas(e.isBLE ? "true" : "false", ql) || dbHas(e.isRandomized ? "true" : "false", ql)) return true;
    if (!strpbrk(ql, "-0123456789")) return false;
    const long nums[] = {(long)e.bestRssi, (long)e.channel, (long)e.sessionCount, (long)e.totalSeen,
                         (long)e.firstEpoch, (long)e.lastEpoch};
    char num[16];
    for (long n : nums) {
        snprintf(num, sizeof(num), "%ld", n);
        if (strstr(num, ql)) return true;
    }
    return false;
}

template <typename E>
bool dbKeyCommon(const E &e, uint8_t sort, const char *vend, const char *nm, DbSortKey &k)
{
    k.num = 0;
    k.str[0] = '\0';
    switch (sort) {
    case 0: dbLower(e.mac, k.str, sizeof(k.str)); return true;
    case 1: k.num = e.isBLE; return true;
    case 2: dbLower(vend, k.str, sizeof(k.str)); return true;
    case 3: dbLower(nm, k.str, sizeof(k.str)); return true;
    case 4: k.num = e.bestRssi; return true;
    case 5: k.num = e.channel; return true;
    case 6: k.num = e.sessionCount; return true;
    case 7: k.num = e.totalSeen; return true;
    case 8: k.num = e.firstEpoch; return true;
    case 9: k.num = e.lastEpoch; return true;
    default: return false;
    }
}

// Sorted record numbers for one view (sort, order, search, range), kept in the cache region between pages.
struct DbIndex {
    String key;
    uint32_t gen = UINT32_MAX;
    uint32_t *recs = nullptr;
    uint32_t count = 0;
    uint32_t first = 0;
    uint32_t last = 0;
    String top;
    bool built() const { return gen != UINT32_MAX; }
    void reset()
    {
        cacheHeapRelease(recs);
        recs = nullptr;
        count = 0;
        first = last = 0;
        key = "";
        top = "";
        gen = UINT32_MAX;
    }
};

inline String dbViewKey(const DbView &v)
{
    return String(v.sort) + '|' + String(v.asc ? 1 : 0) + '|' + String(v.rangeFrom) + '|' + String(v.rangeTo) + '|' + v.q;
}

inline bool dbIndexStale(const DbIndex &ix, const DbView &v) { return v.fresh || !ix.built() || ix.key != dbViewKey(v); }

// Space-saving top-k counter: fixed memory, exact while there are at most 64 distinct values.
struct DbTopK {
    struct Slot {
        uint64_t h;
        uint32_t c;
        char name[33];
    };
    Slot s[64];
    uint8_t n = 0;
    void add(const char *name)
    {
        if (!name[0]) return;
        const uint64_t h = dbHash(name);
        uint8_t minI = 0;
        for (uint8_t i = 0; i < n; i++) {
            if (s[i].h == h) {
                s[i].c++;
                return;
            }
            if (s[i].c < s[minI].c) minI = i;
        }
        Slot *t;
        if (n < 64) {
            t = &s[n++];
            t->c = 1;
        } else {
            t = &s[minI];
            t->c++;
        }
        t->h = h;
        strncpy(t->name, name, sizeof(t->name) - 1);
        t->name[sizeof(t->name) - 1] = '\0';
    }
    String json() const
    {
        uint8_t idx[64];
        for (uint8_t i = 0; i < n; i++) idx[i] = i;
        std::sort(idx, idx + n, [this](uint8_t a, uint8_t b) { return s[a].c > s[b].c; });
        String out = "[";
        for (uint8_t i = 0; i < n && i < 3; i++) {
            if (i) out += ',';
            out += "[\"";
            for (const char *p = s[idx[i]].name; *p; p++) {
                if (*p == '"' || *p == '\\') out += '\\';
                if ((unsigned char)*p >= 0x20) out += *p;
            }
            out += "\"," + String(s[idx[i]].c) + "]";
        }
        return out + "]";
    }
};

// One SD pass builds the sorted index; the sort keys live only while sorting, then only 4 bytes per row remain.
template <typename E, typename ScanAll, typename KeyFor, typename Match>
bool dbBuildIndex(DbIndex &ix, const DbView &v, uint32_t gen, size_t maxRecs, bool strSort, ScanAll scanAll, KeyFor keyFor,
                  Match matches)
{
    ix.reset();
    char ql[65];
    dbLower(v.q.c_str(), ql, sizeof(ql));
    DbSortKey *ent = maxRecs ? static_cast<DbSortKey *>(cacheHeapAlloc(maxRecs * sizeof(DbSortKey))) : nullptr;
    if (maxRecs && !ent) return false;
    size_t n = 0;
    uint32_t firstLo = UINT32_MAX, lastHi = 0;
    std::unique_ptr<DbTopK> vendorTop(new (std::nothrow) DbTopK());
    if (!vendorTop) {
        cacheHeapRelease(ent);
        return false;
    }
    DbTopK &vendors = *vendorTop;
    char vs[sizeof(E::vendor) + 1], ns[sizeof(E::name) + 1];
    const bool ok = scanAll([&](const E &e, uint32_t rec) {
        if (n >= maxRecs || !dbRangeOk(v, e.firstEpoch, e.lastEpoch)) return;
        dbSanitize(e.vendor, sizeof(e.vendor), vs, sizeof(vs));
        dbSanitize(e.name, sizeof(e.name), ns, sizeof(ns));
        if (ql[0] && !matches(e, ql, vs, ns)) return;
        const uint32_t lo = dbEpochOk(e.firstEpoch) ? e.firstEpoch : (dbEpochOk(e.lastEpoch) ? e.lastEpoch : 0);
        const uint32_t hi = dbEpochOk(e.lastEpoch) ? e.lastEpoch : lo;
        if (lo && lo < firstLo) firstLo = lo;
        if (hi > lastHi) lastHi = hi;
        vendors.add(vs);
        DbSortKey &k = ent[n++];
        k.rec = rec;
        keyFor(e, v.sort, vs, ns, k);
    });
    if (!ok) {
        cacheHeapRelease(ent);
        return false;
    }
    const bool asc = v.asc;
    std::sort(ent, ent + n, [strSort, asc](const DbSortKey &a, const DbSortKey &b) {
        if (strSort) {
            const int c = strcmp(a.str, b.str);
            if (c) return asc ? c < 0 : c > 0;
        } else if (a.num != b.num) {
            return asc ? a.num < b.num : a.num > b.num;
        }
        return a.rec > b.rec;
    });
    ix.recs = n ? static_cast<uint32_t *>(cacheHeapAlloc(n * sizeof(uint32_t))) : nullptr;
    if (n && !ix.recs) {
        cacheHeapRelease(ent);
        return false;
    }
    for (size_t i = 0; i < n; i++) ix.recs[i] = ent[i].rec;
    cacheHeapRelease(ent);
    ix.count = (uint32_t)n;
    ix.first = firstLo == UINT32_MAX ? 0 : firstLo;
    ix.last = lastHi;
    ix.top = vendors.json();
    ix.key = dbViewKey(v);
    ix.gen = gen;
    return true;
}

template <typename E, typename ReadRecs, typename FmtRow>
void dbServeIndex(const DbIndex &ix, DbView &v, ReadRecs readRecs, FmtRow fmtRow)
{
    v.out = "{\"total\":" + String(ix.count) + ",\"first\":" + String(ix.first) + ",\"last\":" + String(ix.last) +
            ",\"top\":" + ix.top + ",\"rows\":[";
    const uint32_t from = v.off < ix.count ? v.off : ix.count;
    const uint32_t to = from + v.lim < ix.count ? from + v.lim : ix.count;
    std::vector<E> rows(to - from);
    if (to > from && readRecs(ix.recs + from, to - from, rows.data())) {
        std::vector<char> line(700);
        for (size_t i = 0; i < rows.size(); i++) {
            const size_t len = fmtRow(rows[i], i == 0, line.data(), line.size());
            v.out.concat(line.data(), len);
        }
    }
    v.out += "]}";
}

// Rebuilds the index when the view or the SD file changed, then answers the page from it.
template <typename E, typename ScanAll, typename ReadRecs, typename FmtRow, typename KeyFor, typename Match>
void dbIndexedView(DbIndex &ix, DbView &v, uint32_t gen, size_t maxRecs, bool strSort, ScanAll scanAll, ReadRecs readRecs,
                   FmtRow fmtRow, KeyFor keyFor, Match matches)
{
    if (dbIndexStale(ix, v) || ix.gen != gen) {
        if (!dbBuildIndex<E>(ix, v, gen, maxRecs, strSort, scanAll, keyFor, matches)) {
            ix.reset();
            v.out = "{\"error\":\"Not enough memory or SD read failed\"}";
            return;
        }
    }
    dbServeIndex<E>(ix, v, readRecs, fmtRow);
}

// Reads a fixed-record SD file in 256-record blocks (about 1 MB/s on the S3), taking the lock per block only.
template <typename E, typename Lock, typename F>
bool dbScanFile(const char *path, Lock &mtx, std::atomic<int> &streams, F fn, size_t kBlkRecs = 256)
{
    const size_t R = sizeof(E);
    size_t end;
    {
        std::lock_guard<Lock> lock(mtx);
        end = SafeSD::exists(path) ? SafeSD::size(path) : 0;
        streams++;
    }
    uint8_t *blk = static_cast<uint8_t *>(heap_caps_malloc(kBlkRecs * R, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    bool ok = blk != nullptr;
    uint32_t rec = 0;
    for (size_t cur = 0; ok && cur + R <= end;) {
        size_t want = end - cur;
        if (want > kBlkRecs * R) want = kBlkRecs * R;
        want -= want % R;
        size_t got = 0;
        {
            std::lock_guard<Lock> lock(mtx);
            File f = SafeSD::open(path, FILE_READ);
            if (f && f.seek(cur)) got = SafeSD::read(f, blk, want);
            if (f) f.close();
        }
        got -= got % R;
        if (got < R) {
            ok = false;
            break;
        }
        for (size_t o = 0; o < got; o += R, rec++) {
            E e;
            memcpy(&e, blk + o, R);
            e.mac[17] = '\0';
            fn(e, rec);
        }
        cur += got;
    }
    heap_caps_free(blk);
    streams--;
    return ok;
}

template <typename E, typename Lock>
bool dbReadRecs(const char *path, Lock &mtx, const uint32_t *recs, size_t n, E *out)
{
    std::vector<uint16_t> order(n);
    for (size_t i = 0; i < n; i++) order[i] = (uint16_t)i;
    std::sort(order.begin(), order.end(), [recs](uint16_t a, uint16_t b) { return recs[a] < recs[b]; });
    std::lock_guard<Lock> lock(mtx);
    File f = SafeSD::open(path, FILE_READ);
    if (!f) return false;
    bool ok = true;
    for (size_t j = 0; j < n && ok; j++) {
        const size_t i = order[j];
        ok = f.seek((size_t)recs[i] * sizeof(E)) &&
             SafeSD::read(f, reinterpret_cast<uint8_t *>(&out[i]), sizeof(E)) == sizeof(E);
        out[i].mac[17] = '\0';
    }
    f.close();
    return ok;
}
