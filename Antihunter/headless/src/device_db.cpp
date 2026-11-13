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

    if (!SD.exists(DEVICE_DB_PATH)) {
        Serial.println("[DEVDB] No database on SD");
        return;
    }

    File f = SafeSD::open(DEVICE_DB_PATH, FILE_READ);
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

    File f = SafeSD::open(DEVICE_DB_PATH, FILE_WRITE);
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

void clearDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDB.clear();
    SafeSD::remove(DEVICE_DB_PATH);
    Serial.println("[DEVDB] Database cleared");
}
