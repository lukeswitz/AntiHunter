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

extern bool parseMac6(const String &in, uint8_t out[6]);

static PsramTable<DeviceDBEntry> deviceDB;
static std::mutex deviceDBMutex;
static const char *DEVICE_DB_PATH = "/devicedb.jsonl";
static const char *DEVICE_DB_TMP = "/devicedb.jsonl.tmp";
static const char *DEVICE_DB_BAK = "/devicedb.jsonl.bak";

static uint64_t deviceDBKey(const uint8_t mac[6])
{
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | mac[i];
    return k;
}

static void deviceDBNoteDrops(uint32_t before, bool flush = false)
{
    static uint32_t pending = 0, lastPrintMs = 0;
    pending += deviceDB.evicted() - before;
    if (pending && (flush || millis() - lastPrintMs >= 10000)) {
        lastPrintMs = millis();
        Serial.printf("[DEVDB] PSRAM low: dropped %u least recently seen devices (%u held)\n",
                      (unsigned)pending, (unsigned)deviceDB.size());
        pending = 0;
    }
}

void loadDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);

    const char *path = SafeSD::exists(DEVICE_DB_PATH) ? DEVICE_DB_PATH
                     : SafeSD::exists(DEVICE_DB_BAK)  ? DEVICE_DB_BAK : nullptr;
    if (!path) {
        Serial.println("[DEVDB] No database on SD");
        return;
    }

    File f = SafeSD::open(path, FILE_READ);
    if (!f) {
        Serial.println("[DEVDB] Failed to open database");
        return;
    }

    const uint32_t evictedBefore = deviceDB.evicted();
    uint32_t count = 0, unstored = 0;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 10) continue;

        DynamicJsonDocument doc(384);
        if (deserializeJson(doc, line) != DeserializationError::Ok) continue;

        const char *mac = doc["m"] | "";
        if (strlen(mac) < 17) continue;
        uint8_t macBytes[6];
        if (!parseMac6(String(mac), macBytes)) continue;

        DeviceDBEntry entry = {};
        strncpy(entry.mac, mac, 17);
        entry.mac[17] = '\0';
        entry.totalSeen = doc["t"].as<uint32_t>();
        entry.firstEpoch = doc["f"].as<uint32_t>();
        entry.lastEpoch = doc["l"].as<uint32_t>();
        entry.sessionCount = doc["s"].as<uint16_t>();
        entry.bestRssi = doc["r"] | -128;
        entry.isRandomized = doc["rd"].as<bool>();
        entry.isBLE = doc["ble"].as<bool>();
        entry.channel = doc["c"].as<uint8_t>();

        const char *devName = doc["n"] | "";
        strncpy(entry.name, devName, sizeof(entry.name) - 1);

        const char *ouiVendor = lookupOuiVendor(macBytes);
        if (ouiVendor) {
            strncpy(entry.vendor, ouiVendor, sizeof(entry.vendor) - 1);
        } else {
            const char *vendor = doc["v"] | "";
            strncpy(entry.vendor, vendor, sizeof(entry.vendor) - 1);
        }

        bool isNew = false;
        auto *e = deviceDB.upsert(deviceDBKey(macBytes), entry.lastEpoch, &isNew);
        if (!e) {
            unstored++;
            continue;
        }
        e->val = entry;
        count++;
    }
    f.close();
    Serial.printf("[DEVDB] Loaded %u devices from SD\n", count);
    if (unstored) Serial.printf("[DEVDB] PSRAM full: %u devices on SD not loaded\n", (unsigned)unstored);
    deviceDBNoteDrops(evictedBefore, true);
}

void saveDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDBNoteDrops(deviceDB.evicted(), true);

    File f = SafeSD::open(DEVICE_DB_TMP, FILE_WRITE);
    SdWriter f_w(f);
    if (!f) {
        Serial.println("[DEVDB] Failed to write database");
        return;
    }

    uint32_t written = 0;
    for (size_t i = 0; i < deviceDB.size(); i++) {
        const DeviceDBEntry &e = deviceDB.at(i).val;
        DynamicJsonDocument doc(384);
        doc["m"] = e.mac;
        doc["t"] = e.totalSeen;
        doc["f"] = e.firstEpoch;
        doc["l"] = e.lastEpoch;
        doc["s"] = e.sessionCount;
        doc["r"] = e.bestRssi;
        if (e.vendor[0]) doc["v"] = e.vendor;
        if (e.name[0]) doc["n"] = e.name;
        doc["rd"] = e.isRandomized ? 1 : 0;
        doc["ble"] = e.isBLE ? 1 : 0;
        doc["c"] = e.channel;

        serializeJson(doc, f_w);
        f_w.println();
        written++;
        if ((written & 0x3FF) == 0) vTaskDelay(1);
    }
    f.close();
    if (written == 0) {
        for (const char *p : {DEVICE_DB_TMP, DEVICE_DB_PATH, DEVICE_DB_BAK}) SafeSD::remove(p);
        return;
    }
    if (!sdCommitStaged(DEVICE_DB_TMP, DEVICE_DB_PATH, DEVICE_DB_BAK)) return;
    Serial.printf("[DEVDB] Saved %u devices to SD\n", written);
}

void mergeHitToDeviceDB(const Hit &h)
{
    bool nameIsReal = h.name[0] &&
                      strcmp(h.name, "Unknown") != 0 &&
                      strcmp(h.name, "WiFi") != 0 &&
                      strcmp(h.name, "[Hidden]") != 0;

    std::lock_guard<std::mutex> lock(deviceDBMutex);
    const uint32_t now = getEventTimestamp();
    const uint32_t evictedBefore = deviceDB.evicted();

    bool isNew = false;
    auto *slot = deviceDB.upsert(deviceDBKey(h.mac), now, &isNew);
    deviceDBNoteDrops(evictedBefore);
    if (!slot) {
        static uint32_t lastWarnMs = 0;
        if (millis() - lastWarnMs > 10000) {
            lastWarnMs = millis();
            Serial.println("[DEVDB] PSRAM exhausted: device not stored");
        }
        return;
    }
    DeviceDBEntry &e = slot->val;

    if (!isNew) {
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
        return;
    }

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
    { const char *v = lookupOuiVendor(h.mac); if (v) strncpy(e.vendor, v, sizeof(e.vendor) - 1); }
}

uint32_t getDeviceDBSize()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    return deviceDB.size();
}

static size_t deviceDBFormatRow(const DeviceDBEntry &e, bool first, char *out, size_t cap)
{
    String v = sanitizeAscii(e.vendor, sizeof(e.vendor));
    String n = sanitizeAscii(e.name, sizeof(e.name));
    int len = snprintf(out, cap,
                       "%s{\"mac\":\"%s\",\"seen\":%u,\"sessions\":%u,\"first\":%u,\"last\":%u,"
                       "\"rssi\":%d,\"vendor\":\"%s\",\"name\":\"%s\",\"rand\":%s,\"ble\":%s,\"ch\":%u}",
                       first ? "" : ",", e.mac, (unsigned)e.totalSeen, (unsigned)e.sessionCount,
                       (unsigned)e.firstEpoch, (unsigned)e.lastEpoch, (int)e.bestRssi, v.c_str(), n.c_str(),
                       e.isRandomized ? "true" : "false", e.isBLE ? "true" : "false", (unsigned)e.channel);
    if (len < 0) return 0;
    return (size_t)len < cap ? (size_t)len : cap - 1;
}

size_t deviceDBStreamFill(DeviceDBStream &st, uint8_t *buf, size_t maxLen)
{
    size_t written = 0;
    while (written < maxLen) {
        if (st.pendOff < st.pendLen) {
            size_t n = st.pendLen - st.pendOff;
            if (n > maxLen - written) n = maxLen - written;
            memcpy(buf + written, st.pend + st.pendOff, n);
            st.pendOff += n;
            written += n;
            continue;
        }
        st.pendOff = st.pendLen = 0;
        if (st.phase == 0) {
            st.pend[0] = '[';
            st.pendLen = 1;
            st.phase = 1;
            continue;
        }
        if (st.phase == 1) {
            std::lock_guard<std::mutex> lock(deviceDBMutex);
            if (st.cursor < deviceDB.size()) {
                st.pendLen = (uint16_t)deviceDBFormatRow(deviceDB.at(st.cursor).val, st.cursor == 0,
                                                         st.pend, sizeof(st.pend));
                st.cursor++;
                continue;
            }
            st.phase = 2;
        }
        if (st.phase == 2) {
            st.pend[0] = ']';
            st.pendLen = 1;
            st.phase = 3;
            continue;
        }
        break;
    }
    return written;
}

void clearDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDB.clear();
    for (const char *p : {DEVICE_DB_PATH, DEVICE_DB_TMP, DEVICE_DB_BAK}) SafeSD::remove(p);
    Serial.println("[DEVDB] Database cleared");
}
