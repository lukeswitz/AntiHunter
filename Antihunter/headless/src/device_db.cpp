#include <ArduinoJson.h>
#include <SD.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <mutex>
#include <string>
#include "scanner.h"
#include "hardware.h"
#include "main.h"
#include "scanner_internal.h"
#include "psram_table.h"
#include "cuckoo_filter.h"
#include "detect.h"

extern bool parseMac6(const String &in, uint8_t out[6]);

// SD /devicedb.bin is the full append-only record; RAM is a bounded live cache plus a fixed-size cuckoo filter for "seen this MAC", so memory never rises with the number of distinct devices.

static PsramTable<DeviceDBEntry> deviceDB;
static CuckooFilter s_devSeen;
static PsramSet<uint64_t> s_devDirty;
static std::mutex deviceDBMutex;

static const char *DEVICE_DB_BIN = "/devicedb.bin";
static const char *DEVICE_DB_BIN_TMP = "/devicedb.bin.tmp";
static const char *DEVICE_DB_JSONL = "/devicedb.jsonl";
static const char *DEVICE_DB_JSONL_BAK = "/devicedb.jsonl.bak";
static const char *DEVICE_DB_ARCHIVE = "/devicedb_archive.jsonl";

static const uint32_t DEVICE_DB_IDLE_SECS = 7200;
static const uint32_t DEVICE_DB_SEEN_BUCKETS = 65536;
static const size_t REC = sizeof(DeviceDBEntry);
static const size_t DEV_BUF_BYTES = 32 * 1024;

static uint8_t *s_devBuf = nullptr;
static size_t s_devBufLen = 0;
static uint32_t s_devRecords = 0;
static uint32_t s_lastSweepSecs = 0;

static uint64_t deviceDBKey(const uint8_t mac[6])
{
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | mac[i];
    return k;
}

static uint64_t deviceDBKeyStr(const char *macStr)
{
    uint8_t mac[6];
    if (!parseMac6(String(macStr), mac)) return 0;
    return deviceDBKey(mac);
}

static void devBufReserve()
{
    if (!s_devBuf) s_devBuf = static_cast<uint8_t *>(heap_caps_malloc(DEV_BUF_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
}

static void devBufFlush()
{
    if (s_devBufLen == 0) return;
    File f = SafeSD::open(DEVICE_DB_BIN, FILE_APPEND);
    const size_t wrote = f ? SafeSD::write(f, s_devBuf, s_devBufLen) : 0;
    if (f) f.close();
    if (wrote != s_devBufLen) Serial.printf("[DEVDB] SD write failed: %u bytes not saved\n", (unsigned)s_devBufLen);
    s_devBufLen = 0;
}

static void devAppend(const DeviceDBEntry &e)
{
    devBufReserve();
    if (!s_devBuf) return;
    if (s_devBufLen + REC > DEV_BUF_BYTES) devBufFlush();
    memcpy(s_devBuf + s_devBufLen, &e, REC);
    s_devBufLen += REC;
    s_devRecords++;
}

static void deviceDBNewEntry(DeviceDBEntry &e, const Hit &h, uint32_t now, bool nameIsReal)
{
    memset(&e, 0, sizeof(e));
    snprintf(e.mac, sizeof(e.mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4], h.mac[5]);
    e.totalSeen = 1;
    e.firstEpoch = now;
    e.lastEpoch = now;
    e.sessionCount = 1;
    e.bestRssi = h.rssi;
    e.isRandomized = (h.mac[0] & 0x02) && !(h.mac[0] & 0x01);
    e.isBLE = h.isBLE;
    e.channel = h.ch;
    if (nameIsReal) strncpy(e.name, h.name, sizeof(e.name) - 1);
    const char *v = lookupOuiVendor(h.mac);
    if (v) strncpy(e.vendor, v, sizeof(e.vendor) - 1);
}

static void deviceDBMergeHit(DeviceDBEntry &e, const Hit &h, uint32_t now, bool nameIsReal)
{
    e.totalSeen++;
    e.sessionCount++;
    e.lastEpoch = now;
    if (h.rssi > e.bestRssi) e.bestRssi = h.rssi;
    if (h.ch) e.channel = h.ch;
    if (nameIsReal && !e.name[0]) {
        strncpy(e.name, h.name, sizeof(e.name) - 1);
        e.name[sizeof(e.name) - 1] = '\0';
    }
    const char *v = lookupOuiVendor(h.mac);
    if (v) {
        strncpy(e.vendor, v, sizeof(e.vendor) - 1);
        e.vendor[sizeof(e.vendor) - 1] = '\0';
    }
}

static void deviceDBEvictHook(const PsramTable<DeviceDBEntry>::Entry &e, void *)
{
    devAppend(e.val);
    s_devDirty.erase(e.key);
}

static void deviceDBImportLegacy()
{
    for (const char *path : {DEVICE_DB_JSONL, DEVICE_DB_JSONL_BAK, DEVICE_DB_ARCHIVE}) {
        if (!SafeSD::exists(path)) continue;
        File f = SafeSD::open(path, FILE_READ);
        if (!f) continue;
        uint32_t n = 0;
        while (f.available()) {
            String line = f.readStringUntil('\n');
            line.trim();
            if (line.length() < 10) continue;
            DynamicJsonDocument doc(384);
            if (deserializeJson(doc, line) != DeserializationError::Ok) continue;
            const char *mac = doc["m"] | "";
            uint8_t mb[6];
            if (strlen(mac) < 17 || !parseMac6(String(mac), mb)) continue;
            DeviceDBEntry e = {};
            strncpy(e.mac, mac, 17);
            e.mac[17] = '\0';
            e.totalSeen = doc["t"].as<uint32_t>();
            e.firstEpoch = doc["f"].as<uint32_t>();
            e.lastEpoch = doc["l"].as<uint32_t>();
            e.sessionCount = doc["s"].as<uint16_t>();
            e.bestRssi = doc["r"] | -128;
            e.isRandomized = doc["rd"].as<bool>();
            e.isBLE = doc["ble"].as<bool>();
            e.channel = doc["c"].as<uint8_t>();
            strncpy(e.name, doc["n"] | "", sizeof(e.name) - 1);
            const char *ov = lookupOuiVendor(mb);
            strncpy(e.vendor, ov ? ov : (doc["v"] | ""), sizeof(e.vendor) - 1);
            s_devSeen.insertIfNew(deviceDBKey(mb));
            devAppend(e);
            if ((++n & 0x3FF) == 0) vTaskDelay(1);
        }
        f.close();
    }
    devBufFlush();
}

void loadDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDB.setEvictHook(deviceDBEvictHook, nullptr);
    devBufReserve();
    s_devSeen.reserve(DEVICE_DB_SEEN_BUCKETS);
    s_devSeen.clear();
    s_devDirty.clear();
    s_devBufLen = s_devRecords = 0;
    Serial.printf("[DEVDB] seen filter %u KB fixed\n", (unsigned)(s_devSeen.bytes() / 1024));

    if (!SafeSD::exists(DEVICE_DB_BIN)) {
        if (SafeSD::exists(DEVICE_DB_JSONL) || SafeSD::exists(DEVICE_DB_JSONL_BAK) || SafeSD::exists(DEVICE_DB_ARCHIVE)) {
            deviceDBImportLegacy();
            Serial.printf("[DEVDB] Imported %u devices from the old format\n", (unsigned)s_devSeen.count());
            return;
        }
        Serial.println("[DEVDB] No database on SD");
        return;
    }

    File f = SafeSD::open(DEVICE_DB_BIN, FILE_READ);
    if (!f) {
        Serial.println("[DEVDB] Failed to open database");
        return;
    }
    DeviceDBEntry e;
    uint32_t total = 0;
    while (f.available() >= (int)REC) {
        if (SafeSD::read(f, reinterpret_cast<uint8_t *>(&e), REC) != REC) break;
        e.mac[17] = '\0';
        s_devSeen.insertIfNew(deviceDBKeyStr(e.mac));
        total++;
        if ((total & 0x3FF) == 0) vTaskDelay(1);
    }
    f.close();
    s_devRecords = total;
    Serial.printf("[DEVDB] Loaded %u devices from SD\n", (unsigned)s_devSeen.count());
}

// Rewrites the record keeping only the newest entry per MAC, bounding file size and de-duplicating.
static void deviceDBCompact()
{
    devBufFlush();
    File in = SafeSD::open(DEVICE_DB_BIN, FILE_READ);
    if (!in) return;
    const uint32_t total = (uint32_t)(in.size() / REC);
    if (total == 0) { in.close(); return; }
    CuckooFilter emitted;
    if (!emitted.reserve(DEVICE_DB_SEEN_BUCKETS)) { in.close(); return; }
    File out = SafeSD::open(DEVICE_DB_BIN_TMP, FILE_WRITE);
    if (!out) { in.close(); return; }
    DeviceDBEntry e;
    uint32_t kept = 0;
    for (uint32_t k = 0; k < total; k++) {
        const uint32_t idx = total - 1 - k;
        in.seek((size_t)idx * REC);
        if (SafeSD::read(in, reinterpret_cast<uint8_t *>(&e), REC) != REC) continue;
        e.mac[17] = '\0';
        if (!emitted.insertIfNew(deviceDBKeyStr(e.mac))) continue;
        SafeSD::write(out, reinterpret_cast<uint8_t *>(&e), REC);
        kept++;
        if ((kept & 0x3FF) == 0) vTaskDelay(1);
    }
    in.close();
    out.close();
    SafeSD::remove(DEVICE_DB_BIN);
    if (!SafeSD::rename(DEVICE_DB_BIN_TMP, DEVICE_DB_BIN)) {
        Serial.println("[DEVDB] Compaction rename failed");
        return;
    }
    s_devRecords = kept;
}

void mergeHitToDeviceDB(const Hit &h)
{
    bool nameIsReal = h.name[0] &&
                      strcmp(h.name, "Unknown") != 0 &&
                      strcmp(h.name, "WiFi") != 0 &&
                      strcmp(h.name, "[Hidden]") != 0;

    std::lock_guard<std::mutex> lock(deviceDBMutex);
    const uint32_t now = getEventTimestamp();
    const uint64_t key = deviceDBKey(h.mac);

    bool isNew = false;
    auto *te = deviceDB.upsert(key, now, &isNew);
    if (!te) {
        DeviceDBEntry e;
        deviceDBNewEntry(e, h, now, nameIsReal);
        s_devSeen.insertIfNew(key);
        devAppend(e);
        return;
    }

    if (!isNew) {
        deviceDBMergeHit(te->val, h, now, nameIsReal);
        s_devDirty.insert(key);
        return;
    }

    deviceDBNewEntry(te->val, h, now, nameIsReal);
    s_devSeen.insertIfNew(key);
    s_devDirty.insert(key);
}

// Flush idle devices to SD and drop them from RAM; called from the scan loop.
void deviceDBIdleSweep()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    const uint32_t now = getEventTimestamp();
    if (now - s_lastSweepSecs < 60) return;
    s_lastSweepSecs = now;
    deviceDB.eraseOlderThan(now, DEVICE_DB_IDLE_SECS);
}

#if AH_SELFTEST
size_t deviceDBForceSweep(uint32_t maxAgeSecs)
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    const size_t n = deviceDB.eraseOlderThan(getEventTimestamp(), maxAgeSecs);
    devBufFlush();
    return n;
}
#endif

void saveDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    for (const uint64_t key : s_devDirty) {
        const auto *e = deviceDB.find(key);
        if (e) devAppend(e->val);
    }
    s_devDirty.clear();
    devBufFlush();
    const uint32_t uniq = (uint32_t)s_devSeen.count();
    if (uniq > 0 && s_devRecords > uniq * 2) deviceDBCompact();
    Serial.printf("[DEVDB] Saved: %u devices on SD (%u live in memory)\n",
                  (unsigned)s_devSeen.count(), (unsigned)deviceDB.size());
}

uint32_t getDeviceDBSize()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    return (uint32_t)s_devSeen.count();
}

void clearDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDB.clear();
    s_devSeen.clear();
    s_devDirty.clear();
    s_devBufLen = s_devRecords = 0;
    for (const char *p : {DEVICE_DB_BIN, DEVICE_DB_BIN_TMP, DEVICE_DB_JSONL,
                          DEVICE_DB_JSONL_BAK, DEVICE_DB_ARCHIVE})
        SafeSD::remove(p);
    Serial.println("[DEVDB] Database cleared");
}
