#include <ArduinoJson.h>
#include <SD.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <algorithm>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include "scanner.h"
#include "hardware.h"
#include "main.h"
#include "scanner_internal.h"

extern bool parseMac6(const String &in, uint8_t out[6]);

static std::map<String, DeviceDBEntry> deviceDB;
static std::mutex deviceDBMutex;
static const char *DEVICE_DB_PATH = "/devicedb.jsonl";
static const size_t DEVICE_DB_MAX_ENTRIES = 2000;

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

    uint32_t count = 0;
    while (f.available() && count < DEVICE_DB_MAX_ENTRIES) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 10) continue;

        DynamicJsonDocument doc(384);
        if (deserializeJson(doc, line) != DeserializationError::Ok) continue;

        const char *mac = doc["m"] | "";
        if (strlen(mac) < 17) continue;

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

        uint8_t macBytes[6];
        const char *ouiVendor = parseMac6(String(mac), macBytes) ? lookupOuiVendor(macBytes) : nullptr;
        if (ouiVendor) {
            strncpy(entry.vendor, ouiVendor, sizeof(entry.vendor) - 1);
        } else {
            const char *vendor = doc["v"] | "";
            strncpy(entry.vendor, vendor, sizeof(entry.vendor) - 1);
        }

        deviceDB[String(mac)] = entry;
        count++;
    }
    f.close();
    Serial.printf("[DEVDB] Loaded %u devices from SD\n", count);
}

void saveDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);

    File f = SafeSD::open(DEVICE_DB_PATH, FILE_WRITE);
    if (!f) {
        Serial.println("[DEVDB] Failed to write database");
        return;
    }

    uint32_t written = 0;
    for (const auto &p : deviceDB) {
        DynamicJsonDocument doc(384);
        doc["m"] = p.second.mac;
        doc["t"] = p.second.totalSeen;
        doc["f"] = p.second.firstEpoch;
        doc["l"] = p.second.lastEpoch;
        doc["s"] = p.second.sessionCount;
        doc["r"] = p.second.bestRssi;
        if (p.second.vendor[0]) doc["v"] = p.second.vendor;
        if (p.second.name[0]) doc["n"] = p.second.name;
        doc["rd"] = p.second.isRandomized ? 1 : 0;
        doc["ble"] = p.second.isBLE ? 1 : 0;
        doc["c"] = p.second.channel;

        serializeJson(doc, f);
        f.println();
        written++;
    }
    f.close();
    Serial.printf("[DEVDB] Saved %u devices to SD\n", written);
}

void mergeHitToDeviceDB(const Hit &h)
{
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4], h.mac[5]);

    bool nameIsReal = h.name[0] &&
                      strcmp(h.name, "Unknown") != 0 &&
                      strcmp(h.name, "WiFi") != 0 &&
                      strcmp(h.name, "[Hidden]") != 0;

    std::lock_guard<std::mutex> lock(deviceDBMutex);
    uint32_t now = getEventTimestamp();

    auto it = deviceDB.find(String(macStr));
    if (it != deviceDB.end()) {
        DeviceDBEntry &e = it->second;
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

    if (deviceDB.size() >= DEVICE_DB_MAX_ENTRIES) {
        uint32_t oldestEpoch = UINT32_MAX;
        String oldestKey;
        for (const auto &p : deviceDB) {
            if (p.second.lastEpoch < oldestEpoch) {
                oldestEpoch = p.second.lastEpoch;
                oldestKey = p.first;
            }
        }
        if (oldestKey.length() == 0) return;
        deviceDB.erase(oldestKey);
    }

    DeviceDBEntry e = {};
    strncpy(e.mac, macStr, 17);
    e.mac[17] = '\0';
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
    deviceDB[String(macStr)] = e;
}

uint32_t getDeviceDBSize()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    return deviceDB.size();
}

PsramJsonString getDeviceDBJson()
{
    std::vector<DeviceDBEntry> snap;
    {
        std::lock_guard<std::mutex> lock(deviceDBMutex);
        snap.reserve(deviceDB.size());
        std::transform(deviceDB.begin(), deviceDB.end(), std::back_inserter(snap),
                       [](const auto &p) { return p.second; });
    }

    PsramJsonString out;
    out.reserve(2 + snap.size() * 160);
    out.push_back('[');
    char num[16];
    bool first = true;
    for (const auto &e : snap) {
        if (!first) out.push_back(',');
        first = false;
        out += "{\"mac\":\"";
        out += e.mac;
        out += "\",\"seen\":";
        snprintf(num, sizeof(num), "%u", (unsigned)e.totalSeen); out += num;
        out += ",\"sessions\":";
        snprintf(num, sizeof(num), "%u", (unsigned)e.sessionCount); out += num;
        out += ",\"first\":";
        snprintf(num, sizeof(num), "%u", (unsigned)e.firstEpoch); out += num;
        out += ",\"last\":";
        snprintf(num, sizeof(num), "%u", (unsigned)e.lastEpoch); out += num;
        out += ",\"rssi\":";
        snprintf(num, sizeof(num), "%d", (int)e.bestRssi); out += num;
        out += ",\"vendor\":\"";
        { String v = sanitizeAscii(e.vendor, sizeof(e.vendor)); out.append(v.c_str(), v.length()); }
        out += "\",\"name\":\"";
        { String n = sanitizeAscii(e.name, sizeof(e.name)); out.append(n.c_str(), n.length()); }
        out += "\",\"rand\":";
        out += (e.isRandomized ? "true" : "false");
        out += ",\"ble\":";
        out += (e.isBLE ? "true" : "false");
        out += ",\"ch\":";
        snprintf(num, sizeof(num), "%u", (unsigned)e.channel); out += num;
        out += "}";
    }
    out.push_back(']');
    return out;
}

void clearDeviceDB()
{
    std::lock_guard<std::mutex> lock(deviceDBMutex);
    deviceDB.clear();
    SafeSD::remove(DEVICE_DB_PATH);
    Serial.println("[DEVDB] Database cleared");
}
