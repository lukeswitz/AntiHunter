#include "log_view.h"
#include <ArduinoJson.h>
#include <SD.h>
#include <algorithm>
#include <map>
#include <string>
#include "db_view.h"
#include "scanner.h"
#include "sd_store.h"

const char *logViewPath(const String &id)
{
    static const char *const kLogs[][2] = {
        {"probes", "/probes.jsonl"},
        {"deauth", "/deauth.jsonl"},
        {"drones", "/drones.jsonl"},
        {"vibrations", "/vibrations.jsonl"},
        {"incidents", "/incidents.jsonl"},
    };
    for (const auto &l : kLogs) {
        if (id == l[0]) return l[1];
    }
    return nullptr;
}

struct LogKey {
    uint32_t off;
    uint32_t i;
    double num;
    uint16_t len;
    bool isNum;
};
typedef char LogStrKey[24];

static String logFieldText(JsonVariantConst v, const String &key, JsonObjectConst row)
{
    if (key == "_type") return row["disassoc"].as<bool>() ? "DISASSOC" : "DEAUTH";
    if (v.isNull()) return "";
    if (v.is<const char *>()) return String(v.as<const char *>());
    if (v.is<bool>()) return v.as<bool>() ? "true" : "false";
    if (v.is<JsonArrayConst>()) {
        String s;
        for (JsonVariantConst x : v.as<JsonArrayConst>()) {
            if (s.length()) s += ',';
            s += logFieldText(x, "", JsonObjectConst());
        }
        return s;
    }
    String s;
    serializeJson(v, s);
    return s;
}

static uint32_t logRowEpoch(JsonObjectConst row)
{
    static const char *const kTimeKeys[] = {"first", "t", "timestamp", "epoch", "last"};
    for (const char *k : kTimeKeys) {
        JsonVariantConst v = row[k];
        if (v.is<double>() && dbEpochOk((uint32_t)v.as<double>())) return (uint32_t)v.as<double>();
    }
    return 0;
}

static bool logRowWanted(const LogView &v, JsonObjectConst row, const char *ql)
{
    bool inCamp = false;
    if (v.campTag.length() && row["campaign"].is<const char *>())
        inCamp = String("[C:") + row["campaign"].as<const char *>() + "]" == v.campTag;
    if ((v.rangeFrom || v.rangeTo) && !inCamp) {
        const uint32_t t = logRowEpoch(row);
        if (!t || t < v.rangeFrom || t > v.rangeTo) return false;
    }
    if (!ql[0]) return true;
    for (const String &k : v.keys) {
        if (dbHas(logFieldText(row[k], k, row).c_str(), ql)) return true;
    }
    return false;
}

struct LogLine {
    uint32_t off;
    uint16_t len;
};

// Sorted line positions for one log and one view, kept in the cache region between pages.
struct LogIndex {
    const char *path = nullptr;
    String key;
    size_t builtSize = 0;
    LogLine *lines = nullptr;
    uint32_t count = 0;
    uint32_t first = 0;
    uint32_t last = 0;
    String top;
    bool built = false;
    void reset()
    {
        cacheHeapRelease(lines);
        lines = nullptr;
        count = first = last = 0;
        key = "";
        top = "";
        builtSize = 0;
        built = false;
    }
};

static String logViewKey(const LogView &v)
{
    String k = v.sortKey + '|' + String(v.asc ? 1 : 0) + '|' + v.q + '|' + String(v.rangeFrom) + '|' + String(v.rangeTo) + '|' +
               v.campTag + '|' + v.topKey + '|';
    for (const String &s : v.keys) k += s + ',';
    return k;
}

static const size_t kLogLine = 2048;

static bool logBuildIndex(LogIndex &ix, const LogView &v)
{
    ix.reset();
    char ql[65];
    dbLower(v.q.c_str(), ql, sizeof(ql));
    const bool keyed = v.sortKey.length() > 0;
    const size_t size = SafeSD::exists(v.path) ? SafeSD::size(v.path) : 0;
    size_t cap = size / 120 + 64;
    LogKey *ent = static_cast<LogKey *>(cacheHeapAlloc(cap * sizeof(LogKey)));
    LogStrKey *strs = keyed ? static_cast<LogStrKey *>(cacheHeapAlloc(cap * sizeof(LogStrKey))) : nullptr;
    const size_t kBlk = 24576;
    uint8_t *blk = static_cast<uint8_t *>(heap_caps_malloc(kBlk, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    char *line = static_cast<char *>(heap_caps_malloc(kLogLine, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    std::unique_ptr<DbTopK> top(new (std::nothrow) DbTopK());
    bool ok = ent && (!keyed || strs) && blk && line && top;
    size_t n = 0;
    uint32_t firstLo = UINT32_MAX, lastHi = 0;
    DynamicJsonDocument doc(3072);
    size_t lineLen = 0, lineStart = 0;
    bool lineTooLong = false;
    auto grow = [&]() {
        const size_t ncap = cap + cap / 2 + 64;
        LogKey *ne = static_cast<LogKey *>(cacheHeapAlloc(ncap * sizeof(LogKey)));
        LogStrKey *ns = keyed ? static_cast<LogStrKey *>(cacheHeapAlloc(ncap * sizeof(LogStrKey))) : nullptr;
        if (!ne || (keyed && !ns)) {
            cacheHeapRelease(ne);
            cacheHeapRelease(ns);
            return false;
        }
        memcpy(ne, ent, n * sizeof(LogKey));
        if (keyed) memcpy(ns, strs, n * sizeof(LogStrKey));
        cacheHeapRelease(ent);
        cacheHeapRelease(strs);
        ent = ne;
        strs = ns;
        cap = ncap;
        return true;
    };
    auto handle = [&](size_t start, size_t len) {
        if (!ok || !len) return;
        line[len] = '\0';
        doc.clear();
        if (deserializeJson(doc, line, len)) return;
        JsonObjectConst row = doc.as<JsonObjectConst>();
        if (row.isNull() || !logRowWanted(v, row, ql)) return;
        if (n >= cap && !grow()) {
            ok = false;
            return;
        }
        const uint32_t t = logRowEpoch(row);
        if (t && t < firstLo) firstLo = t;
        if (t > lastHi) lastHi = t;
        if (v.topKey.length()) top->add(logFieldText(row[v.topKey], v.topKey, row).c_str());
        LogKey &k = ent[n];
        k.off = (uint32_t)start;
        k.i = (uint32_t)n;
        k.len = (uint16_t)len;
        k.isNum = false;
        k.num = 0;
        if (keyed) {
            strs[n][0] = '\0';
            JsonVariantConst f = row[v.sortKey];
            if (f.is<double>() && !f.is<bool>()) {
                k.isNum = true;
                k.num = f.as<double>();
            } else {
                dbLower(logFieldText(f, v.sortKey, row).c_str(), strs[n], sizeof(LogStrKey));
            }
        }
        n++;
    };
    for (size_t pos = 0; ok && pos < size;) {
        const size_t want = size - pos < kBlk ? size - pos : kBlk;
        const size_t got = SafeSD::readAt(v.path, pos, blk, want);
        if (!got) break;
        for (size_t i = 0; i < got; i++) {
            const char c = (char)blk[i];
            if (c == '\n') {
                if (!lineTooLong) handle(lineStart, lineLen);
                lineLen = 0;
                lineTooLong = false;
                lineStart = pos + i + 1;
            } else if (lineLen + 1 < kLogLine) {
                line[lineLen++] = c;
            } else {
                lineTooLong = true;
            }
        }
        pos += got;
        vTaskDelay(1);
    }
    if (ok && !lineTooLong) handle(lineStart, lineLen);
    heap_caps_free(blk);
    heap_caps_free(line);
    if (!ok) {
        cacheHeapRelease(ent);
        cacheHeapRelease(strs);
        return false;
    }

    const bool asc = v.asc;
    std::sort(ent, ent + n, [asc, keyed, strs](const LogKey &a, const LogKey &b) {
        if (keyed) {
            if (a.isNum && b.isNum) {
                if (a.num != b.num) return asc ? a.num < b.num : a.num > b.num;
            } else {
                const int c = strcmp(strs[a.i], strs[b.i]);
                if (c) return asc ? c < 0 : c > 0;
            }
        }
        return a.off > b.off;
    });
    cacheHeapRelease(strs);
    ix.lines = n ? static_cast<LogLine *>(cacheHeapAlloc(n * sizeof(LogLine))) : nullptr;
    if (n && !ix.lines) {
        cacheHeapRelease(ent);
        return false;
    }
    for (size_t i = 0; i < n; i++) ix.lines[i] = {ent[i].off, ent[i].len};
    cacheHeapRelease(ent);
    ix.path = v.path;
    ix.count = (uint32_t)n;
    ix.first = firstLo == UINT32_MAX ? 0 : firstLo;
    ix.last = lastHi;
    ix.top = top->json();
    ix.key = logViewKey(v);
    ix.builtSize = size;
    ix.built = true;
    return true;
}

static LogIndex s_logIndex[5];

static LogIndex &logIndexFor(const char *path)
{
    for (LogIndex &ix : s_logIndex) {
        if (ix.path == path) return ix;
    }
    for (LogIndex &ix : s_logIndex) {
        if (!ix.path) {
            ix.path = path;
            return ix;
        }
    }
    s_logIndex[0].reset();
    s_logIndex[0].path = path;
    return s_logIndex[0];
}

static void logRunView(LogView &v, LogIndex &ix)
{
    const size_t size = SafeSD::exists(v.path) ? SafeSD::size(v.path) : 0;
    if (v.fresh || !ix.built || ix.key != logViewKey(v) || size < ix.builtSize) {
        if (!logBuildIndex(ix, v)) {
            ix.reset();
            ix.path = v.path;
            v.out = "{\"error\":\"Not enough memory or SD read failed\"}";
            return;
        }
    }
    v.out = "{\"total\":" + String(ix.count) + ",\"first\":" + String(ix.first) + ",\"last\":" + String(ix.last) +
            ",\"top\":" + ix.top + ",\"rows\":[";
    char *line = static_cast<char *>(heap_caps_malloc(kLogLine, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    const uint32_t from = v.off < ix.count ? v.off : ix.count;
    const uint32_t to = from + v.lim < ix.count ? from + v.lim : ix.count;
    bool first = true;
    for (uint32_t i = from; line && i < to; i++) {
        const size_t n = ix.lines[i].len < kLogLine ? ix.lines[i].len : kLogLine - 1;
        if (SafeSD::readAt(v.path, ix.lines[i].off, reinterpret_cast<uint8_t *>(line), n) != n) continue;
        if (!first) v.out += ',';
        v.out.concat(line, n);
        first = false;
    }
    heap_caps_free(line);
    v.out += "]}";
}

bool logViewStart(std::shared_ptr<LogView> v)
{
    return sdWorkerRun([v]() {
        logRunView(*v, logIndexFor(v->path));
        v->done = true;
    });
}
