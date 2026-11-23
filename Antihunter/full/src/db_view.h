#pragma once
#include <Arduino.h>
#include <SD.h>
#include <esp_heap_caps.h>
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "scanner.h"
#include "scanner_internal.h"
#include "sd_store.h"

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

template <typename E>
bool dbMatchCommon(const E &e, const char *ql, const String &vend, const String &nm)
{
    if (dbHas(e.mac, ql) || dbHas(vend.c_str(), ql) || dbHas(nm.c_str(), ql)) return true;
    if (dbHas(e.isBLE ? "true" : "false", ql) || dbHas(e.isRandomized ? "true" : "false", ql)) return true;
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
bool dbKeyCommon(const E &e, uint8_t sort, const String &vend, const String &nm, DbSortKey &k)
{
    k.num = 0;
    k.str[0] = '\0';
    switch (sort) {
    case 0: dbLower(e.mac, k.str, sizeof(k.str)); return true;
    case 1: k.num = e.isBLE; return true;
    case 2: dbLower(vend.c_str(), k.str, sizeof(k.str)); return true;
    case 3: dbLower(nm.c_str(), k.str, sizeof(k.str)); return true;
    case 4: k.num = e.bestRssi; return true;
    case 5: k.num = e.channel; return true;
    case 6: k.num = e.sessionCount; return true;
    case 7: k.num = e.totalSeen; return true;
    case 8: k.num = e.firstEpoch; return true;
    case 9: k.num = e.lastEpoch; return true;
    default: return false;
    }
}

// One SD pass: filter, keep the off+lim best rows in a bounded heap, total and summary; then read back only the page.
template <typename E, typename ScanAll, typename ReadRecs, typename FmtRow, typename KeyFor, typename Match>
void dbPageView(DbView &v, bool strSort, ScanAll scanAll, ReadRecs readRecs, FmtRow fmtRow, KeyFor keyFor, Match matches)
{
    char ql[65];
    dbLower(v.q.c_str(), ql, sizeof(ql));
    const bool asc = v.asc;
    auto before = [strSort, asc](const DbSortKey &a, const DbSortKey &b) {
        if (strSort) {
            const int c = strcmp(a.str, b.str);
            if (c) return asc ? c < 0 : c > 0;
        } else if (a.num != b.num) {
            return asc ? a.num < b.num : a.num > b.num;
        }
        return a.rec > b.rec;
    };
    const size_t keep = (size_t)v.off + v.lim;
    std::vector<DbSortKey> heap;
    uint32_t total = 0, firstLo = UINT32_MAX, lastHi = 0;
    std::map<std::string, uint32_t> vendors;

    const bool ok = scanAll([&](const E &e, uint32_t rec) {
        if (!dbRangeOk(v, e.firstEpoch, e.lastEpoch)) return;
        const String vend = sanitizeAscii(e.vendor, sizeof(e.vendor));
        const String nm = sanitizeAscii(e.name, sizeof(e.name));
        if (ql[0] && !matches(e, ql, vend, nm)) return;
        total++;
        const uint32_t lo = dbEpochOk(e.firstEpoch) ? e.firstEpoch : (dbEpochOk(e.lastEpoch) ? e.lastEpoch : 0);
        const uint32_t hi = dbEpochOk(e.lastEpoch) ? e.lastEpoch : lo;
        if (lo && lo < firstLo) firstLo = lo;
        if (hi > lastHi) lastHi = hi;
        if (vend.length()) vendors[std::string(vend.c_str())]++;
        DbSortKey k;
        k.rec = rec;
        keyFor(e, v.sort, vend, nm, k);
        if (heap.size() < keep) {
            heap.push_back(k);
            std::push_heap(heap.begin(), heap.end(), before);
        } else if (before(k, heap.front())) {
            std::pop_heap(heap.begin(), heap.end(), before);
            heap.back() = k;
            std::push_heap(heap.begin(), heap.end(), before);
        }
    });
    if (!ok) {
        v.out = "{\"error\":\"SD read failed\"}";
        return;
    }

    std::sort_heap(heap.begin(), heap.end(), before);
    std::vector<uint32_t> recs;
    for (size_t i = v.off; i < heap.size(); i++) recs.push_back(heap[i].rec);
    std::vector<std::pair<std::string, uint32_t>> top(vendors.begin(), vendors.end());
    std::sort(top.begin(), top.end(), [](const std::pair<std::string, uint32_t> &a, const std::pair<std::string, uint32_t> &b) {
        return a.second > b.second;
    });
    if (top.size() > 3) top.resize(3);
    v.out = "{\"total\":" + String(total) + ",\"first\":" + String(firstLo == UINT32_MAX ? 0 : firstLo) +
            ",\"last\":" + String(lastHi) + ",\"top\":[";
    for (size_t i = 0; i < top.size(); i++) {
        if (i) v.out += ',';
        v.out += "[\"" + String(top[i].first.c_str()) + "\"," + String(top[i].second) + "]";
    }
    v.out += "],\"rows\":[";
    std::vector<E> rows(recs.size());
    if (!recs.empty() && readRecs(recs.data(), recs.size(), rows.data())) {
        std::vector<char> line(700);
        for (size_t i = 0; i < rows.size(); i++) {
            const size_t len = fmtRow(rows[i], i == 0, line.data(), line.size());
            v.out.concat(line.data(), len);
        }
    }
    v.out += "]}";
}

// Reads a fixed-record SD file in 64-record blocks, taking the lock per block only.
template <typename E, typename Lock, typename F>
bool dbScanFile(const char *path, Lock &mtx, std::atomic<int> &streams, F fn)
{
    const size_t R = sizeof(E);
    size_t end;
    {
        std::lock_guard<Lock> lock(mtx);
        end = SafeSD::exists(path) ? SafeSD::size(path) : 0;
        streams++;
    }
    const size_t kBlkRecs = 64;
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
    std::lock_guard<Lock> lock(mtx);
    File f = SafeSD::open(path, FILE_READ);
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        ok = f.seek((size_t)recs[i] * sizeof(E)) &&
             SafeSD::read(f, reinterpret_cast<uint8_t *>(&out[i]), sizeof(E)) == sizeof(E);
        out[i].mac[17] = '\0';
    }
    f.close();
    return ok;
}
