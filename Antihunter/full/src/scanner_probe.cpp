#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include <algorithm>
#include <iterator>
#include "randomization.h"
#include <string>
#include <atomic>
#include <mutex>
#include <unistd.h>
#include "scanner.h"
#include "hardware.h"
#include "campaign.h"
#include "network.h"
#include "triangulation.h"
#include "baseline.h"
#include "detect.h"
#include "main.h"
#include "scanner_internal.h"
#include "psram_table.h"
#include "cuckoo_filter.h"
#include "db_view.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
#include "esp_heap_caps.h"
}

extern bool parseMac6(const String &in, uint8_t out[6]);

using StringU32MapPsram = std::map<String, uint32_t, std::less<String>,
    PsramAllocator<std::pair<const String, uint32_t>>>;

static std::atomic<uint32_t> totalProbeCount(0);
static std::atomic<uint32_t> probeHitCount(0);
static StringU32MapPsram probeHitCooldowns;
static const uint32_t PROBE_HIT_COOLDOWN_MS = 60000;

void addProbeSsid(ProbeDevice &dev, const char *ssid, bool fromResponse)
{
    if (!ssid || ssid[0] == '\0') return;
    if (!ssidIsValid(ssid, strlen(ssid))) return;
    if (ssidLooksRandom(ssid, strlen(ssid))) return;
    for (uint8_t i = 0; i < dev.ssidCount; i++) {
        if (strcasecmp(dev.ssids[i], ssid) == 0) return;
    }
    if (dev.ssidCount < 8) {
        strncpy(dev.ssids[dev.ssidCount], ssid, 32);
        dev.ssids[dev.ssidCount][32] = '\0';
        dev.ssidCount++;
        return;
    }
    if (fromResponse) {
        for (uint8_t i = 1; i < 8; i++) {
            memcpy(dev.ssids[i - 1], dev.ssids[i], 33);
        }
        strncpy(dev.ssids[7], ssid, 32);
        dev.ssids[7][32] = '\0';
    }
}

bool extractSsidFromIE(const uint8_t *payload, uint16_t frameLen, uint16_t ieStart, char *ssidBuf, size_t ssidBufSize)
{
    if (frameLen < ieStart + 2) return false;
    const uint8_t *ie = payload + ieStart;
    uint16_t ieLen = frameLen - ieStart;
    uint16_t offset = 0;
    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];
        if (offset + 2 + len > ieLen) break;
        if (tag == 0) {
            if (len == 0) { ssidBuf[0] = '\0'; return false; }
            size_t copyLen = (len < ssidBufSize - 1) ? len : (ssidBufSize - 1);
            memcpy(ssidBuf, &ie[offset + 2], copyLen);
            ssidBuf[copyLen] = '\0';
            return true;
        }
        offset += 2 + len;
    }
    return false;
}

bool extractSsidFromProbe(const uint8_t *payload, uint16_t frameLen, char *ssidBuf, size_t ssidBufSize, bool *isWildcard)
{
    if (isWildcard) *isWildcard = false;
    if (frameLen < 26) return false;
    const uint8_t *ie = payload + 24;
    uint16_t ieLen = frameLen - 24;
    uint16_t offset = 0;
    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];
        if (offset + 2 + len > ieLen) break;
        if (tag == 0) {
            if (len == 0) {
                ssidBuf[0] = '\0';
                if (isWildcard) *isWildcard = true;
                return false;
            }
            size_t copyLen = (len < ssidBufSize - 1) ? len : (ssidBufSize - 1);
            memcpy(ssidBuf, &ie[offset + 2], copyLen);
            ssidBuf[copyLen] = '\0';
            return true;
        }
        offset += 2 + len;
    }
    return false;
}

static const size_t PROBE_HIT_COOLDOWN_MAX = 500;

static bool shouldSendProbeHit(const String &key)
{
    uint32_t now = millis();

    std::lock_guard<std::mutex> lock(probeMutex);

    static uint32_t lastSweep = 0;
    if (probeHitCooldowns.size() >= PROBE_HIT_COOLDOWN_MAX && now - lastSweep >= 10000) {
        lastSweep = now;
        for (auto it = probeHitCooldowns.begin(); it != probeHitCooldowns.end(); ) {
            if ((now - it->second) >= PROBE_HIT_COOLDOWN_MS)
                it = probeHitCooldowns.erase(it);
            else
                ++it;
        }
    }

    auto it = probeHitCooldowns.find(key);
    if (it == probeHitCooldowns.end()) {
        probeHitCooldowns[key] = now;
        return true;
    }
    if ((now - it->second) >= PROBE_HIT_COOLDOWN_MS) {
        it->second = now;
        return true;
    }
    return false;
}

static void sendProbeHitMesh(const uint8_t *mac, int8_t rssi, uint8_t channel,
                              const char *ssid, const char *vendor, bool isDst,
                              bool ghostSsid)
{
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    String key = String(macStr);
    if (ssid && ssid[0]) key += String(ssid);
    if (!shouldSendProbeHit(key)) return;

    String msg = getNodeId() + ": PROBE_HIT " + String(macStr);
    bool randomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
    if (randomized) {
        msg += " Randomized";
    } else if (vendor && vendor[0]) {
        msg += " " + String(vendor);
    }
    msg += " RSSI=" + String(rssi) + " CH=" + String(channel);
    if (ssid && ssid[0]) {
        msg += " SSID=\"" + sanitizeAscii(ssid, 33) + "\"";
        if (ghostSsid) msg += " GHOST";
    }
    if (isDst) {
        msg += " DST";
    }

    if (msg.length() <= static_cast<size_t>(MAX_MESH_SIZE)) {
        meshEnqueue(msg);
    }
}

// Caller holds probeMutex. Moves the oldest non-target device into the probe database before dropping it.
static size_t probeEvictOldestToDB(void *)
{
    uint32_t oldestTime = UINT32_MAX;
    auto oldest = probeDevices.end();
    for (auto it = probeDevices.begin(); it != probeDevices.end(); ++it) {
        if (!it->second.isTargetHit && it->second.lastSeen < oldestTime) {
            oldestTime = it->second.lastSeen;
            oldest = it;
        }
    }
    if (oldest == probeDevices.end()) return 0;
    mergeProbeDeviceToDB(oldest->second);
    probeDevices.erase(oldest);
    return 1;
}

void probeMakeRoom()
{
    cacheHeapMakeRoom(sizeof(ProbeDevicesMap::value_type) + 4 * sizeof(void *), &probeDevices, probeEvictOldestToDB,
                      nullptr);
}

void probeDetectionTask(void *pv)
{
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);

    Serial.printf("[PROBE] Starting probe detection, duration=%d forever=%d\n", duration, forever);
    scanSetCountdown(duration, forever);

    loadProbeDB();
    Serial.printf("[PROBE] Probe DB loaded: %u known devices\n", getProbeDBSize());

    {
        std::lock_guard<std::mutex> lock(probeMutex);
        probeDevices.clear();
        uniqueSsids.clear();
        respondedSsids.clear();
        totalProbeCount = 0;
        probeHitCount = 0;
        probeHitCooldowns.clear();
    }

    scanning = true;

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Probe scan - Mode: WiFi (IN PROGRESS)\nDevices: 0 | Probes: 0 | SSIDs: 0 | Saved: 0\n\n(Starting...)\n";
    }

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (probeRequestQueue == nullptr) {
        for (size_t depth = AH_PROBE_QUEUE_LEN; !probeRequestQueue && depth >= 32; depth /= 2)
            probeRequestQueue = xQueueCreateWithCaps(depth, sizeof(ProbeRequestEvent), AH_ISR_QUEUE_CAPS);
        if (!probeRequestQueue) Serial.println("[PROBE] WARNING: queue alloc failed (PSRAM) - probe capture inert");
    } else {
        xQueueReset(probeRequestQueue);
    }
    g_probeQueueDrops = 0;

    probeDetectionEnabled = true;

    uint32_t startTime = millis();
    uint32_t nextResultsUpdate = startTime;
    size_t lastWrittenProbeCount = SIZE_MAX;
    uint32_t lastBLEScan = 0;
    uint32_t lastDBSave = startTime;
    uint32_t totalDrained = 0;

    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {

        NimBLEScan *bleScan = pBLEScan;

        ProbeRequestEvent event;
        int processedCount = 0;
        const UBaseType_t waiting = probeRequestQueue ? uxQueueMessagesWaiting(probeRequestQueue) : 0;
        while (probeRequestQueue && (UBaseType_t)processedCount < waiting && xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE) {
            totalDrained++;
            processedCount++;

            if (event.isProbeResponse) {
                char devMacStr[18];
                snprintf(devMacStr, sizeof(devMacStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         event.addr1[0], event.addr1[1], event.addr1[2],
                         event.addr1[3], event.addr1[4], event.addr1[5]);

                char apBssid[18];
                snprintf(apBssid, sizeof(apBssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                         event.addr3[0], event.addr3[1], event.addr3[2],
                         event.addr3[3], event.addr3[4], event.addr3[5]);

                char respSsid[33] = {0};
                extractSsidFromIE(event.payload, event.payloadLen, 36, respSsid, sizeof(respSsid));

                std::lock_guard<std::mutex> lock(probeMutex);
                auto it = probeDevices.find(String(devMacStr));
                if (it != probeDevices.end()) {
                    ProbeDevice &dev = it->second;
                    strncpy(dev.respondingAP, apBssid, 17);
                    dev.respondingAP[17] = '\0';
                    if (respSsid[0]) {
                        strncpy(dev.respondingSSID, respSsid, 32);
                        dev.respondingSSID[32] = '\0';
                        addProbeSsid(dev, respSsid, true);
                        uniqueSsids.insert(String(respSsid));
                        respondedSsids.insert(String(respSsid));
                    }
                }
                continue;
            }

            totalProbeCount++;

            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                     event.mac[0], event.mac[1], event.mac[2],
                     event.mac[3], event.mac[4], event.mac[5]);

            if (event.dstMatch) {
                if (!matchesMac(event.mac)) continue;
            }

            char ssidBuf[33] = {0};
            bool hasSSID = false;
            bool isWildcardProbe = false;
            if (!event.dstMatch) {
                hasSSID = extractSsidFromProbe(event.payload, event.payloadLen, ssidBuf, sizeof(ssidBuf), &isWildcardProbe);
            }

            bool macHit = matchesMac(event.mac);
            bool ssidHit = hasSSID && matchesSsid(ssidBuf);
            bool dstHit = event.dstMatch;
            bool isHit = macHit || ssidHit || dstHit;

            bool randomized = (event.mac[0] & 0x02) && !(event.mac[0] & 0x01);
            const char *vendor = nullptr;
            if (!randomized) {
                vendor = lookupOuiVendor(event.mac);
            }

            {
                std::lock_guard<std::mutex> lock(probeMutex);

                if (hasSSID && ssidBuf[0]) {
                    uniqueSsids.insert(String(ssidBuf));
                }

                auto it = probeDevices.find(String(macStr));
                if (it != probeDevices.end()) {
                    ProbeDevice &dev = it->second;
                    dev.rssi = event.rssi;
                    if (event.rssi < dev.rssiMin) dev.rssiMin = event.rssi;
                    if (event.rssi > dev.rssiMax) dev.rssiMax = event.rssi;
                    dev.channel = event.channel;
                    dev.lastSeen = millis();
                    dev.probeCount++;
                    if (hasSSID) addProbeSsid(dev, ssidBuf);
                    if (isWildcardProbe) dev.wildcardCount++;
                    if (isHit && !dev.isTargetHit) {
                        dev.isTargetHit = true;
                        probeHitCount++;
                    }
                    if (dstHit) dev.isDstHit = true;
                } else {
                    probeMakeRoom();

                    ProbeDevice dev = {};
                    memcpy(dev.mac, event.mac, 6);
                    dev.rssi = event.rssi;
                    dev.rssiMin = event.rssi;
                    dev.rssiMax = event.rssi;
                    dev.channel = event.channel;
                    dev.firstSeen = millis();
                    dev.lastSeen = millis();
                    dev.probeCount = 1;
                    dev.ssidCount = 0;
                    dev.isRandomized = randomized;
                    dev.isTargetHit = isHit;
                    dev.isDstHit = dstHit;
                    dev.respondingAP[0] = '\0';
                    dev.respondingSSID[0] = '\0';

                    ProbeDBEntry hist;
                    if (lookupProbeHistory(macStr, hist)) {
                        dev.histKnown = true;
                        dev.histTotalSeen = hist.totalSeen;
                        dev.histFirstEpoch = hist.firstEpoch;
                        dev.histLastEpoch = hist.lastEpoch;
                        dev.histSessionCount = hist.sessionCount;
                    } else {
                        dev.histKnown = false;
                        dev.histTotalSeen = 0;
                        dev.histFirstEpoch = 0;
                        dev.histLastEpoch = 0;
                        dev.histSessionCount = 0;
                    }

                    if (vendor) {
                        strncpy(dev.vendor, vendor, sizeof(dev.vendor) - 1);
                        dev.vendor[sizeof(dev.vendor) - 1] = '\0';
                    } else {
                        dev.vendor[0] = '\0';
                    }

                    if (ssidHit) strncpy(dev.hitReason, "SSID", sizeof(dev.hitReason));
                    else if (dstHit) strncpy(dev.hitReason, "DST", sizeof(dev.hitReason));
                    else if (macHit) strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason));
                    else dev.hitReason[0] = '\0';

                    if (hasSSID) addProbeSsid(dev, ssidBuf);
                    if (isWildcardProbe) dev.wildcardCount++;
                    probeDevices[String(macStr)] = dev;
                    if (isHit) probeHitCount++;
                }
            }

            if (isHit || probeBroadcastAll.load(std::memory_order_relaxed)) {
                bool ghostSsid = hasSSID && ssidBuf[0] &&
                                 respondedSsids.find(String(ssidBuf)) == respondedSsids.end();
                sendProbeHitMesh(event.mac, event.rssi, event.channel, ssidBuf, vendor, dstHit, ghostSsid);
            }
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0 || probeDevices.size() != lastWrittenProbeCount) {
            std::string results = getProbeResults().c_str();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            nextResultsUpdate = millis() + 1000;
            lastWrittenProbeCount = probeDevices.size();
        }

        if (bleScan && (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) &&
            (millis() - lastBLEScan >= rfConfig.bleScanInterval || lastBLEScan == 0)) {
            if (bleScan->isScanning()) bleScan->stop();
            NimBLEScanResults scanResults = bleScan->getResults(rfConfig.bleScanDuration, false);
            int count = scanResults.getCount();
            for (int i = 0; i < count; i++) {
                const NimBLEAdvertisedDevice *device = scanResults.getDevice(i);
                if (!device) continue;
                String macStr = device->getAddress().toString().c_str();
                macStr.toUpperCase();
                uint8_t mac[6];
                if (sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                    bool isHit = matchesMac(mac);
                    int8_t rssi = device->getRSSI();
                    if (!isHit && rssi < rfConfig.globalRssiThreshold) continue;

                    std::lock_guard<std::mutex> lock(probeMutex);
                    auto it = probeDevices.find(macStr);
                    if (it != probeDevices.end()) {
                        ProbeDevice &dev = it->second;
                        dev.lastSeen = millis();
                        dev.rssi = rssi;
                        if (rssi < dev.rssiMin) dev.rssiMin = rssi;
                        if (rssi > dev.rssiMax) dev.rssiMax = rssi;
                        dev.probeCount++;
                        if (isHit && !dev.isTargetHit) {
                            dev.isTargetHit = true;
                            strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason) - 1);
                            probeHitCount++;
                        }
                        if (!dev.name[0] && device->getName().length() > 0) {
                            strncpy(dev.name, device->getName().c_str(), sizeof(dev.name) - 1);
                        }
                        continue;
                    }
                    probeMakeRoom();

                    ProbeDevice dev = {};
                    memcpy(dev.mac, mac, 6);
                    dev.rssi = rssi;
                    dev.rssiMin = rssi;
                    dev.rssiMax = rssi;
                    dev.channel = 0;
                    dev.firstSeen = millis();
                    dev.lastSeen = millis();
                    dev.probeCount = 1;
                    dev.isRandomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
                    dev.isTargetHit = isHit;
                    dev.isBLE = true;
                    if (isHit) strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason) - 1);
                    if (device->getName().length() > 0) {
                        strncpy(dev.name, device->getName().c_str(), sizeof(dev.name) - 1);
                    }
                    { const char *bv = lookupOuiVendor(mac);
                      if (bv) strncpy(dev.vendor, bv, sizeof(dev.vendor) - 1); }
                    probeDevices[macStr] = dev;
                    if (isHit) probeHitCount++;
                }
            }
            lastBLEScan = millis();
        }

        if ((millis() - lastDBSave) >= 60000) {
            {
                std::lock_guard<std::mutex> lock(probeMutex);
                mergeProbeDevicesToDB(probeDevices);
            }
            saveProbeDB();
            lastDBSave = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    probeDetectionEnabled = false;
    probeBroadcastAll.store(false, std::memory_order_relaxed);

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStopSTA();
    }

    {
        std::lock_guard<std::mutex> lock(probeMutex);
        mergeProbeDevicesToDB(probeDevices);
    }
    saveProbeDB(true);
    Serial.printf("[PROBE] Merged %u devices into probe database\n", probeDevices.size());
    Serial.printf("[PROBE] Probe events lost to a full queue: %u\n", (unsigned)g_probeQueueDrops.load());

    {
        std::vector<String> lines;
        {
            uint32_t now = getEventTimestamp();
            std::lock_guard<std::mutex> lock(probeMutex);
            lines.reserve(probeDevices.size());
            for (auto &p : probeDevices) {
                ProbeDevice &dev = p.second;
                DynamicJsonDocument doc(512);
                doc["t"] = now;
                doc["mac"] = p.first;
                doc["rssi"] = dev.rssi;
                doc["ch"] = dev.channel;
                doc["cnt"] = dev.probeCount;
                doc["rand"] = dev.isRandomized;
                doc["ble"] = dev.isBLE;
                if (dev.vendor[0]) doc["v"] = dev.vendor;
                if (dev.name[0]) doc["n"] = dev.name;
                if (dev.isTargetHit) doc["hit"] = true;
                if (dev.isDstHit) doc["dst"] = true;
                JsonArray ss = doc.createNestedArray("ss");
                for (uint8_t i = 0; i < dev.ssidCount; i++) {
                    ss.add(dev.ssids[i]);
                }
                if (dev.respondingAP[0]) doc["ap"] = dev.respondingAP;
                if (dev.respondingSSID[0]) doc["apssid"] = dev.respondingSSID;
                String line;
                serializeJson(doc, line);
                lines.push_back(line);
            }
        }
        logEventsToSD("/probes.jsonl", lines.data(), lines.size());
    }

    scanning = false;

    {
        String probeRes = getProbeResults();
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = probeRes.c_str();
    }
    {
        std::lock_guard<std::mutex> lock(probeMutex);
        probeDevices.clear();
        uniqueSsids.clear();
        respondedSsids.clear();
    }
    workerTaskHandle = nullptr;
    Serial.println("[PROBE] Probe detection stopped");
    vTaskDelete(nullptr);
}

static String formatAge(uint32_t epochNow, uint32_t epochThen)
{
    if (epochThen == 0 || epochNow <= epochThen) return "now";
    uint32_t diff = epochNow - epochThen;
    if (diff < 60) return String(diff) + "s ago";
    if (diff < 3600) return String(diff / 60) + "m ago";
    if (diff < 86400) return String(diff / 3600) + "h ago";
    return String(diff / 86400) + "d ago";
}

String getProbeResults()
{
    static String cachedProbeResults = "";
    static uint32_t lastProbeResultsTime = 0;
    if (scanning && millis() - lastProbeResultsTime < 2000 && cachedProbeResults.length() > 0) {
        return cachedProbeResults;
    }
    lastProbeResultsTime = millis();
    std::lock_guard<std::mutex> lock(probeMutex);
    probeDBResolveHistory(probeDevices);

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    String results = "Probe scan - Mode: " + modeStr;
    if (scanning) results += " (IN PROGRESS)";
    results += "\nDevices: " + String(probeDevices.size()) +
               " | Probes: " + String((uint32_t)totalProbeCount) +
               " | SSIDs: " + String(uniqueSsids.size()) +
               " | Saved: " + String(getProbeDBSize()) + "\n\n";

    std::vector<std::pair<String, ProbeDevice*>> sorted;
    sorted.reserve(probeDevices.size());
    std::transform(probeDevices.begin(), probeDevices.end(), std::back_inserter(sorted),
        [](std::pair<const String, ProbeDevice> &p) -> std::pair<String, ProbeDevice*> {
            return {p.first, &p.second};
        });
    std::sort(sorted.begin(), sorted.end(),
        [](const std::pair<String, ProbeDevice*> &a, const std::pair<String, ProbeDevice*> &b) {
        if (a.second->histKnown != b.second->histKnown) return a.second->histKnown;
        return a.second->rssi > b.second->rssi;
    });

    uint32_t nowEpoch = millis() / 1000;

    size_t devShown = 0;
    for (const auto &p : sorted) {
        if (devShown++ >= PROBE_RESULTS_SHOW) {
            results += "... (" + String((unsigned)(sorted.size() - PROBE_RESULTS_SHOW)) + " more in the probe database)\n";
            break;
        }
        ProbeDevice &dev = *p.second;
        results += (dev.isBLE ? "BLE " : "WiFi ") + p.first + " RSSI=" + String(dev.rssi) + "dBm";
        if (!dev.isBLE) results += " CH=" + String(dev.channel);
        results += " ";

        if (dev.isRandomized) {
            results += "Randomized";
        } else if (dev.vendor[0]) {
            String v = sanitizeAscii(dev.vendor, sizeof(dev.vendor));
            if (v.length() > 0) results += v;
        }
        if (dev.name[0]) {
            String n = sanitizeAscii(dev.name, sizeof(dev.name));
            if (n.length() > 0) results += " NAME=\"" + n + "\"";
        }

        if (dev.ssidCount > 0) {
            bool any = false;
            for (uint8_t i = 0; i < dev.ssidCount; i++) {
                String s = sanitizeAscii(dev.ssids[i], 33);
                if (s.length() == 0) continue;
                if (!any) { results += " probes:"; any = true; }
                else results += ",";
                bool ghost = respondedSsids.find(String(dev.ssids[i])) == respondedSsids.end();
                results += (ghost ? "~\"" : "\"") + s + "\"";
            }
            if (!any && dev.wildcardCount) results += " (wildcard)";
        } else if (dev.wildcardCount) {
            results += " (wildcard)";
        }

        if (dev.respondingSSID[0]) {
            String rs = sanitizeAscii(dev.respondingSSID, sizeof(dev.respondingSSID));
            if (rs.length() > 0) {
                results += " AP=\"" + rs + "\"";
                if (dev.respondingAP[0]) {
                    String rap = sanitizeAscii(dev.respondingAP, sizeof(dev.respondingAP));
                    if (rap.length() > 0) results += " APBSSID=" + rap;
                }
            }
        }

        if (dev.probeCount > 1) {
            results += " x" + String(dev.probeCount);
        }

        if (dev.histKnown && dev.histSessionCount == 0) {
            results += " [KNOWN]";
        } else if (dev.histKnown) {
            results += " [KNOWN:seen=" + String(dev.histTotalSeen) +
                       " sessions=" + String(dev.histSessionCount) +
                       " last=" + formatAge(nowEpoch, dev.histLastEpoch) + "]";
        }

        results += "\n";
    }

    if (uniqueSsids.size() > 0) {
        results += "\nSSIDs seen (" + String(uniqueSsids.size()) + "):\n";

        std::map<String, std::vector<String>> ssidToDevices;
        for (const auto &p : probeDevices) {
            for (uint8_t i = 0; i < p.second.ssidCount; i++) {
                ssidToDevices[String(p.second.ssids[i])].push_back(p.first);
            }
        }

        std::vector<std::pair<String, std::vector<String>>> ssidSorted(ssidToDevices.begin(), ssidToDevices.end());
        std::sort(ssidSorted.begin(), ssidSorted.end(),
            [](const std::pair<String, std::vector<String>> &a,
               const std::pair<String, std::vector<String>> &b) { return a.second.size() > b.second.size(); });

        for (const auto &s : ssidSorted) {
            bool ghost = respondedSsids.find(s.first) == respondedSsids.end();
            results += "  " + String(ghost ? "~" : "") + "\"" + s.first + "\" (" + String(s.second.size()) +
                       (s.second.size() == 1 ? " device" : " devices") + ")";
            if (s.second.size() <= 3) {
                results += " [";
                for (size_t i = 0; i < s.second.size(); i++) {
                    if (i > 0) results += ", ";
                    auto dit = probeDevices.find(s.second[i]);
                    results += (dit != probeDevices.end() && dit->second.isBLE) ? "B:" : "W:";
                    results += s.second[i].substring(9);
                }
                results += "]";
            }
            results += "\n";
        }
    }

    cachedProbeResults = results;
    return results;
}

// --- SD Probe Device Database: /probedb.bin is the append-only record (newest last); RAM caches live devices, a fixed cuckoo filter answers "seen before" ---

static PsramTable<ProbeDBEntry> probeDB;
static CuckooFilter s_probeSeen;
static PsramSet<uint64_t> s_probeDirty;
static std::mutex probeDBMutex;
static bool s_probeLoaded = false;
static bool s_probeRestoreOk = true;
static bool s_probeBakPending = false;
static std::atomic<uint32_t> s_probeFileGen{0};
static uint8_t *s_probeBuf = nullptr;
static size_t s_probeBufLen = 0;
static uint32_t s_probeRecords = 0;
static uint32_t s_probeCleanRecords = 0;
static uint32_t s_probeNewKeys = 0;

static void probeSeenAdd(uint64_t key)
{
    if (s_probeSeen.insertIfNew(key)) s_probeNewKeys++;
}

static bool probeHasDuplicates()
{
    return s_probeRecords > s_probeCleanRecords + s_probeNewKeys;
}

static const char *PROBE_DB_BIN = "/probedb.bin";
static const char *PROBE_DB_BIN_TMP = "/probedb.bin.tmp";
static const char *PROBE_DB_BIN_BAK = "/probedb.bin.bak";
static const char *PROBE_DB_PATH = "/probedb.jsonl";
static const char *PROBE_DB_TMP = "/probedb.jsonl.tmp";
static const char *PROBE_DB_BAK = "/probedb.jsonl.bak";
static const char *PROBE_DB_ARCHIVE = "/probedb_archive.jsonl";
static const uint32_t PROBE_DB_IDLE_SECS = 7200;
static const uint32_t PROBE_DB_SEEN_BUCKETS = 65536;
static const size_t PREC = sizeof(ProbeDBEntry);
static const size_t PROBE_BUF_BYTES = 32 * 1024;

static uint64_t probeDBKey(const uint8_t mac[6])
{
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | mac[i];
    return k;
}

static uint64_t probeDBKeyStr(const char *macStr)
{
    uint8_t mac[6];
    if (!parseMac6(String(macStr), mac)) return 0;
    return probeDBKey(mac);
}

static bool probeWriteWhole(const uint8_t *data, size_t len)
{
    std::lock_guard<std::recursive_mutex> sdLock(SafeSD::fileLock());
    if (s_probeBakPending) {
        if (!SafeSD::rename(PROBE_DB_BIN_BAK, PROBE_DB_BIN)) return false;
        s_probeBakPending = false;
        s_probeFileGen++;
    }
    File f = SafeSD::open(PROBE_DB_BIN, FILE_APPEND);
    const size_t pos = f ? f.size() : 0;
    const size_t wrote = f ? SafeSD::write(f, data, len) : 0;
    if (f) f.close();
    if (wrote == len) return true;
    if (wrote) truncate((String("/sd") + PROBE_DB_BIN).c_str(), pos);
    return false;
}

static bool probeBufFlush()
{
    if (s_probeBufLen == 0) return true;
    if (!probeWriteWhole(s_probeBuf, s_probeBufLen)) {
        Serial.printf("[PROBEDB] SD write failed: %u devices kept in memory for the next save\n", (unsigned)(s_probeBufLen / PREC));
        return false;
    }
    s_probeBufLen = 0;
    return true;
}

static void probeAppend(const ProbeDBEntry &e)
{
    if (!s_probeBuf) s_probeBuf = static_cast<uint8_t *>(heap_caps_malloc(PROBE_BUF_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!s_probeBuf || (s_probeBufLen + PREC > PROBE_BUF_BYTES && !probeBufFlush())) {
        if (probeWriteWhole(reinterpret_cast<const uint8_t *>(&e), PREC)) {
            s_probeRecords++;
        } else {
            Serial.println("[PROBEDB] SD write failed: 1 device not saved");
            g_sdRecordsNotSaved++;
        }
        return;
    }
    memcpy(s_probeBuf + s_probeBufLen, &e, PREC);
    s_probeBufLen += PREC;
    s_probeRecords++;
}

static void probeDBEvictHook(const PsramTable<ProbeDBEntry>::Entry &e, void *)
{
    probeAppend(e.val);
    s_probeDirty.erase(e.key);
    g_sdRecordsMoved++;
}

static size_t probeDBShedForOtherCache(void *)
{
    if (!probeDBMutex.try_lock()) return 0;
    const size_t n = probeDB.shed(getEventTimestamp());
    probeDBMutex.unlock();
    return n;
}

static bool probeDBFlushDirty()
{
    for (const uint64_t key : s_probeDirty) {
        const auto *e = probeDB.find(key);
        if (e) probeAppend(e->val);
    }
    s_probeDirty.clear();
    return probeBufFlush();
}

static void probeDBInitLocked()
{
    probeDB.setEvictHook(probeDBEvictHook, nullptr);
    cacheHeapAddShedder(&probeDB, probeDBShedForOtherCache, nullptr);
    s_probeSeen.reserve(PROBE_DB_SEEN_BUCKETS);
    s_probeSeen.clear();
    s_probeDirty.clear();
    probeDB.clear();
    s_probeBufLen = s_probeRecords = s_probeCleanRecords = s_probeNewKeys = 0;
}

static void probeDBAddSsid(ProbeDBEntry &e, const char *ss)
{
    if (!ss || !ss[0]) return;
    for (uint8_t j = 0; j < e.ssidCount; j++)
        if (strcasecmp(e.ssids[j], ss) == 0) return;
    if (e.ssidCount >= 8) return;
    strncpy(e.ssids[e.ssidCount], ss, 32);
    e.ssids[e.ssidCount][32] = '\0';
    e.ssidCount++;
}

// Adds a separate earlier record of the same device (old-format import only).
static void probeDBCombine(ProbeDBEntry &into, const ProbeDBEntry &from)
{
    into.totalSeen += from.totalSeen;
    into.sessionCount += from.sessionCount;
    if (from.firstEpoch && (!into.firstEpoch || from.firstEpoch < into.firstEpoch)) into.firstEpoch = from.firstEpoch;
    if (from.lastEpoch > into.lastEpoch) into.lastEpoch = from.lastEpoch;
    if (from.bestRssi > into.bestRssi) into.bestRssi = from.bestRssi;
    if (!into.name[0]) memcpy(into.name, from.name, sizeof(into.name));
    if (!into.vendor[0]) memcpy(into.vendor, from.vendor, sizeof(into.vendor));
    for (uint8_t i = 0; i < from.ssidCount && i < 8; i++) probeDBAddSsid(into, from.ssids[i]);
}

static bool probeDBParseLegacy(const String &line, ProbeDBEntry &entry)
{
    DynamicJsonDocument doc(1024);
    if (deserializeJson(doc, line) != DeserializationError::Ok) return false;
    const char *mac = doc["m"] | "";
    if (strlen(mac) < 17) return false;

    entry = {};
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
    } else if (entry.isBLE && !doc.containsKey("n")) {
        const char *legacy = doc["v"] | "";
        if (legacy[0]) strncpy(entry.name, legacy, sizeof(entry.name) - 1);
    } else {
        const char *legacy = doc["v"] | "";
        strncpy(entry.vendor, legacy, sizeof(entry.vendor) - 1);
    }

    JsonArray ssArr = doc["ss"];
    if (ssArr) {
        for (JsonVariant s : ssArr) probeDBAddSsid(entry, s.as<const char *>());
    }
    return true;
}

// One-time import of the old JSON files: the live file (or its backup) plus every archived line, combined per device.
static void probeDBImportLegacy()
{
    const char *live = SafeSD::exists(PROBE_DB_PATH) ? PROBE_DB_PATH : PROBE_DB_BAK;
    uint32_t n = 0;
    for (const char *path : {live, PROBE_DB_ARCHIVE}) {
        if (!SafeSD::exists(path)) continue;
        File f = SafeSD::open(path, FILE_READ);
        if (!f) continue;
        while (f.available()) {
            String line = f.readStringUntil('\n');
            line.trim();
            if (line.length() < 10) continue;
            ProbeDBEntry in;
            if (!probeDBParseLegacy(line, in)) continue;
            const uint64_t key = probeDBKeyStr(in.mac);
            probeSeenAdd(key);
            bool isNew = false;
            auto *te = probeDB.upsert(key, in.lastEpoch, &isNew);
            if (!te) probeAppend(in);
            else if (isNew) te->val = in;
            else probeDBCombine(te->val, in);
            if ((++n & 0xFF) == 0) vTaskDelay(1);
        }
        f.close();
    }
    for (size_t i = 0; i < probeDB.size(); i++) probeAppend(probeDB.at(i).val);
    probeBufFlush();
    probeDB.clear();
}

static uint64_t probeDBRecKey(uint8_t *rec)
{
    ProbeDBEntry *e = reinterpret_cast<ProbeDBEntry *>(rec);
    e->mac[17] = '\0';
    return probeDBKeyStr(e->mac);
}

// Caller holds probeDBMutex. Reads the newest SD record of each wanted key back into RAM in one pass over the file.
static void probeDBRestore(const PsramSet<uint64_t> &want)
{
    if (want.empty()) return;
    probeBufFlush();
    const size_t n = want.size();
    uint64_t *keys = static_cast<uint64_t *>(heap_caps_malloc(n * sizeof(uint64_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    ProbeDBEntry *found = static_cast<ProbeDBEntry *>(heap_caps_malloc(n * PREC, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    uint8_t *hit = static_cast<uint8_t *>(heap_caps_calloc(n, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    int32_t got = -1;
    if (keys && found && hit) {
        size_t i = 0;
        for (const uint64_t k : want) keys[i++] = k;
        got = sdReadNewestRecords(PROBE_DB_BIN, PREC, probeDBRecKey, keys, n, reinterpret_cast<uint8_t *>(found), hit);
    }
    s_probeRestoreOk = got >= 0 || !SafeSD::exists(PROBE_DB_BIN);
    if (got > 0) {
        const uint32_t now = getEventTimestamp();
        for (size_t k = 0; k < n; k++) {
            if (!hit[k]) continue;
            bool isNew = false;
            auto *te = probeDB.upsert(keys[k], now, &isNew);
            if (te && isNew) te->val = found[k];
        }
    } else if (!s_probeRestoreOk) {
        Serial.printf("[PROBEDB] Could not read the history of %u devices from SD; they are merged after the next good read\n", (unsigned)n);
    }
    heap_caps_free(keys);
    heap_caps_free(found);
    heap_caps_free(hit);
}

static std::atomic<int> s_probeStreams{0};

ProbeDBStream::~ProbeDBStream()
{
    if (holds) s_probeStreams--;
    heap_caps_free(blk);
}

static void probeDBCompact()
{
    if (s_probeStreams.load() > 0) return;
    probeBufFlush();
    const int32_t kept = sdCompactNewestPerKey(PROBE_DB_BIN, PROBE_DB_BIN_TMP, PROBE_DB_BIN_BAK, PREC, probeDBRecKey, "PROBEDB");
    s_probeFileGen++;
    if (kept < 0) return;
    s_probeRecords = s_probeCleanRecords = (uint32_t)kept;
    s_probeNewKeys = 0;
}

static std::atomic<uint32_t> s_probePrepReq{0};
static std::atomic<uint32_t> s_probePrepDone{0};
static std::atomic<bool> s_probePrepOk{true};

void probeDBServicePrep()
{
    const uint32_t want = s_probePrepReq.load();
    if (want == s_probePrepDone.load()) return;
    {
        std::lock_guard<std::mutex> lock(probeDBMutex);
        const bool ok = probeDBFlushDirty();
        if (ok && probeHasDuplicates()) probeDBCompact();
        s_probePrepOk = ok;
    }
    s_probePrepDone = want;
}

// Builds the "seen before" filter from SD once; later calls (each scan start) keep the live cache.
void loadProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    if (s_probeLoaded || !SafeSD::isAvailable()) return;
    s_probeLoaded = true;
    probeDBInitLocked();

    s_probeBakPending = !SafeSD::exists(PROBE_DB_BIN) && SafeSD::exists(PROBE_DB_BIN_BAK) &&
                        !SafeSD::rename(PROBE_DB_BIN_BAK, PROBE_DB_BIN);
    const char *src = s_probeBakPending ? PROBE_DB_BIN_BAK : PROBE_DB_BIN;
    if (s_probeBakPending) Serial.printf("[PROBEDB] Could not restore %s; reading it in place\n", PROBE_DB_BIN_BAK);
    if (!SafeSD::exists(src)) {
        if (SafeSD::exists(PROBE_DB_PATH) || SafeSD::exists(PROBE_DB_BAK) || SafeSD::exists(PROBE_DB_ARCHIVE)) {
            probeDBImportLegacy();
            Serial.printf("[PROBEDB] Imported %u devices from the old format\n", (unsigned)s_probeSeen.count());
            return;
        }
        Serial.println("[PROBEDB] No database file on SD");
        return;
    }

    File f = SafeSD::open(src, FILE_READ);
    if (!f) {
        Serial.println("[PROBEDB] Failed to open database");
        return;
    }
    ProbeDBEntry e;
    uint32_t total = 0;
    while (f.available() >= (int)PREC) {
        if (SafeSD::read(f, reinterpret_cast<uint8_t *>(&e), PREC) != PREC) break;
        e.mac[17] = '\0';
        if (s_probeSeen.insertIfNew(probeDBKeyStr(e.mac))) s_probeCleanRecords++;
        if ((++total & 0xFF) == 0) vTaskDelay(1);
    }
    f.close();
    s_probeRecords = total;
    Serial.printf("[PROBEDB] Loaded %u devices from SD\n", (unsigned)s_probeSeen.count());
}

bool probeDBFlushPending()
{
    std::unique_lock<std::mutex> lock(probeDBMutex, std::defer_lock);
    for (int i = 0; i < 200 && !lock.try_lock(); i++) vTaskDelay(pdMS_TO_TICKS(10));
    if (!lock.owns_lock()) return false;
    if (s_probeLoaded) probeDBFlushDirty();
    return true;
}

void saveProbeDB(bool releaseCache)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    if (!s_probeLoaded) return;
    probeDB.eraseOlderThan(getEventTimestamp(), PROBE_DB_IDLE_SECS);
    const bool flushed = probeDBFlushDirty();
    const uint32_t uniq = (uint32_t)s_probeSeen.count();
    if (flushed && uniq > 0 && s_probeRecords > uniq * 2) probeDBCompact();
    if (flushed)
        Serial.printf("[PROBEDB] Saved: %u devices on SD (%u live in memory)\n",
                      (unsigned)s_probeSeen.count(), (unsigned)probeDB.size());
    else
        Serial.printf("[PROBEDB] Save incomplete: %u devices are still waiting for SD\n",
                      (unsigned)(s_probeBufLen / PREC));
    if (releaseCache) probeDB.clear();
}

// Caller holds probeDBMutex. Adds only what this device gained since its last merge, so periodic saves never count twice.
static void probeDBMergeLocked(ProbeDevice &dev, uint32_t now)
{
    const uint64_t key = probeDBKey(dev.mac);
    if (!s_probeRestoreOk && !probeDB.find(key) && s_probeSeen.contains(key)) return;
    const uint32_t newProbes = dev.probeCount - dev.dbMergedProbes;
    bool isNew = false;
    auto *te = probeDB.upsert(key, now, &isNew);
    if (te && !isNew && dev.dbMerged && newProbes == 0) return;
    ProbeDBEntry fresh = {};
    ProbeDBEntry &e = te ? te->val : fresh;

    if (!te || isNew) {
        e = {};
        snprintf(e.mac, sizeof(e.mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);
        e.totalSeen = newProbes;
        e.firstEpoch = now;
        e.sessionCount = 1;
        e.bestRssi = dev.rssi;
        e.isRandomized = dev.isRandomized;
        e.isBLE = dev.isBLE;
        strncpy(e.name, dev.name, sizeof(e.name) - 1);
    } else {
        e.totalSeen += newProbes;
        if (!dev.dbMerged) e.sessionCount++;
        if (dev.rssi > e.bestRssi) e.bestRssi = dev.rssi;
        if (dev.name[0] && !e.name[0]) {
            strncpy(e.name, dev.name, sizeof(e.name) - 1);
            e.name[sizeof(e.name) - 1] = '\0';
        }
    }
    e.lastEpoch = now;
    if (dev.channel) e.channel = dev.channel;
    if (dev.vendor[0]) {
        strncpy(e.vendor, dev.vendor, sizeof(e.vendor) - 1);
        e.vendor[sizeof(e.vendor) - 1] = '\0';
    }
    for (uint8_t i = 0; i < dev.ssidCount && i < 8; i++) probeDBAddSsid(e, dev.ssids[i]);

    dev.dbMergedProbes = dev.probeCount;
    dev.dbMerged = true;
    probeSeenAdd(key);
    if (te) s_probeDirty.insert(key);
    else probeAppend(e);
}

// Caller holds probeDBMutex. Reads back from SD every listed device that was seen before but is not in RAM.
static void probeDBRestoreFor(const ProbeDevicesMap &devs, bool onlyUnresolved)
{
    PsramSet<uint64_t> want;
    for (const auto &p : devs) {
        const ProbeDevice &d = p.second;
        if (onlyUnresolved && !(d.histKnown && d.histSessionCount == 0)) continue;
        const uint64_t key = probeDBKey(d.mac);
        if (!probeDB.find(key) && s_probeSeen.contains(key)) want.insert(key);
    }
    probeDBRestore(want);
}

// Caller holds probeDBMutex. A device the filter called known but SD does not hold was a filter false match.
static void probeDBFillHistory(ProbeDevicesMap &devs)
{
    for (auto &p : devs) {
        ProbeDevice &d = p.second;
        if (!d.histKnown || d.histSessionCount != 0) continue;
        const auto *e = probeDB.find(probeDBKey(d.mac));
        if (!e) {
            d.histKnown = false;
            continue;
        }
        d.histTotalSeen = e->val.totalSeen;
        d.histFirstEpoch = e->val.firstEpoch;
        d.histLastEpoch = e->val.lastEpoch;
        d.histSessionCount = e->val.sessionCount;
    }
}

void probeDBResolveHistory(ProbeDevicesMap &devs)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDBRestoreFor(devs, true);
    probeDBFillHistory(devs);
}

void mergeProbeDevicesToDB(ProbeDevicesMap &devs)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDBRestoreFor(devs, false);
    probeDBFillHistory(devs);
    const uint32_t now = getEventTimestamp();
    for (auto &p : devs) probeDBMergeLocked(p.second, now);
}

void mergeProbeDeviceToDB(ProbeDevice &dev)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    const uint64_t key = probeDBKey(dev.mac);
    if (!probeDB.find(key) && s_probeSeen.contains(key)) {
        PsramSet<uint64_t> want;
        want.insert(key);
        probeDBRestore(want);
    }
    probeDBMergeLocked(dev, getEventTimestamp());
}

// A device known only from the filter returns true with zero counts; probeDBResolveHistory fills them from SD.
bool lookupProbeHistory(const char *macStr, ProbeDBEntry &out)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    const uint64_t key = probeDBKeyStr(macStr);
    if (const auto *e = probeDB.find(key)) {
        out = e->val;
        return true;
    }
    if (!s_probeSeen.contains(key)) return false;
    out = {};
    return true;
}

uint32_t getProbeDBSize()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    return (uint32_t)s_probeSeen.count();
}

static size_t probeDBFormatRow(const ProbeDBEntry &e, bool first, char *out, size_t cap)
{
    const String v = sanitizeAscii(e.vendor, sizeof(e.vendor));
    const String n = sanitizeAscii(e.name, sizeof(e.name));
    int len = snprintf(out, cap,
        "%s{\"mac\":\"%s\",\"seen\":%u,\"sessions\":%u,\"first\":%u,\"last\":%u,\"rssi\":%d,"
        "\"vendor\":\"%s\",\"name\":\"%s\",\"rand\":%s,\"ble\":%s,\"ch\":%u,\"ssids\":[",
        first ? "" : ",", e.mac, (unsigned)e.totalSeen, (unsigned)e.sessionCount, (unsigned)e.firstEpoch,
        (unsigned)e.lastEpoch, (int)e.bestRssi, v.c_str(), n.c_str(), e.isRandomized ? "true" : "false",
        e.isBLE ? "true" : "false", (unsigned)e.channel);
    bool sfirst = true;
    for (uint8_t i = 0; i < e.ssidCount && i < 8 && len > 0 && (size_t)len < cap; i++) {
        const String s = sanitizeAscii(e.ssids[i], 33);
        if (s.length() == 0) continue;
        len += snprintf(out + len, cap - len, "%s\"%s\"", sfirst ? "" : ",", s.c_str());
        sfirst = false;
    }
    if (len > 0 && (size_t)len < cap) len += snprintf(out + len, cap - len, "]}");
    return (len > 0 && (size_t)len < cap) ? (size_t)len : 0;
}

void probeDBStreamPrepare(ProbeDBStream &st)
{
    st.waitGen = s_probePrepReq.fetch_add(1) + 1;
    probeDBServicePrep();
}

size_t probeDBStreamFill(ProbeDBStream &st, uint8_t *buf, size_t maxLen)
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
            if (!st.waitGen) {
                st.waitGen = s_probePrepReq.fetch_add(1) + 1;
                if (!dbWorkerKick()) probeDBServicePrep();
            }
            if ((int32_t)(s_probePrepDone.load() - st.waitGen) < 0) return DB_STREAM_WAIT;
            if (!s_probePrepOk.load()) break;
            std::lock_guard<std::mutex> lock(probeDBMutex);
            st.end = SafeSD::exists(PROBE_DB_BIN) ? SafeSD::size(PROBE_DB_BIN) : 0;
            st.holds = true;
            s_probeStreams++;
            st.pend[0] = '[';
            st.pendLen = 1;
            st.cursor = 0;
            st.phase = 1;
            continue;
        }
        if (st.phase == 1) {
            if (st.cursor + PREC > st.end) {
                st.phase = 2;
            } else {
                if (st.cursor < st.blkStart || st.cursor + PREC > st.blkStart + st.blkLen) {
                    const size_t kBlkRecs = 64;
                    if (!st.blk) st.blk = static_cast<uint8_t *>(heap_caps_malloc(kBlkRecs * PREC, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
                    size_t want = st.end - st.cursor;
                    if (want > kBlkRecs * PREC) want = kBlkRecs * PREC;
                    want -= want % PREC;
                    size_t got = 0;
                    if (st.blk) {
                        std::lock_guard<std::mutex> lock(probeDBMutex);
                        File f = SafeSD::open(PROBE_DB_BIN, FILE_READ);
                        if (f && f.seek(st.cursor)) got = SafeSD::read(f, st.blk, want);
                        if (f) f.close();
                    }
                    if (got < PREC) {
                        Serial.println("[PROBEDB] Read failed while sending the probe list");
                        st.phase = 3;
                        break;
                    }
                    st.blkStart = st.cursor;
                    st.blkLen = got - got % PREC;
                }
                ProbeDBEntry e;
                memcpy(&e, st.blk + (st.cursor - st.blkStart), PREC);
                e.mac[17] = '\0';
                st.pendLen = (uint16_t)probeDBFormatRow(e, st.first, st.pend, sizeof(st.pend));
                st.first = false;
                st.cursor += PREC;
                continue;
            }
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

static void probeSsidJoin(const ProbeDBEntry &e, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    for (uint8_t i = 0; i < e.ssidCount && i < 8; i++) {
        const String s = sanitizeAscii(e.ssids[i], 33);
        if (!s.length()) continue;
        n += snprintf(out + n, n < cap ? cap - n : 0, "%s%s", n ? "," : "", s.c_str());
        if (n >= cap) break;
    }
}

static DbIndex s_probeIndex;

static void probeDBRunView(DbView &v)
{
    if (dbIndexStale(s_probeIndex, v)) {
        std::lock_guard<std::mutex> lock(probeDBMutex);
        const bool ok = probeDBFlushDirty();
        if (ok && probeHasDuplicates()) probeDBCompact();
        if (!ok) {
            v.out = "{\"error\":\"SD write failed\"}";
            return;
        }
    }
    const size_t maxRecs = (SafeSD::exists(PROBE_DB_BIN) ? SafeSD::size(PROBE_DB_BIN) / PREC : 0) + 256;
    dbIndexedView<ProbeDBEntry>(
        s_probeIndex, v, s_probeFileGen.load(), maxRecs, v.sort == 0 || v.sort == 2 || v.sort == 3 || v.sort == 10,
        [](const std::function<void(const ProbeDBEntry &, uint32_t)> &fn) {
            return dbScanFile<ProbeDBEntry>(PROBE_DB_BIN, probeDBMutex, s_probeStreams, fn);
        },
        [](const uint32_t *recs, size_t n, ProbeDBEntry *out) {
            return dbReadRecs<ProbeDBEntry>(PROBE_DB_BIN, probeDBMutex, recs, n, out);
        },
        probeDBFormatRow,
        [](const ProbeDBEntry &e, uint8_t sort, const char *vend, const char *nm, DbSortKey &k) {
            if (dbKeyCommon(e, sort, vend, nm, k)) return;
            if (sort == 10) {
                char all[300];
                probeSsidJoin(e, all, sizeof(all));
                dbLower(all, k.str, sizeof(k.str));
            } else {
                k.num = e.isRandomized;
            }
        },
        [](const ProbeDBEntry &e, const char *ql, const char *vend, const char *nm) {
            if (dbMatchCommon(e, ql, vend, nm)) return true;
            char ss[34];
            for (uint8_t i = 0; i < e.ssidCount && i < 8; i++) {
                dbSanitize(e.ssids[i], 33, ss, sizeof(ss));
                if (dbHas(ss, ql)) return true;
            }
            return false;
        });
}

bool probeDBViewStart(std::shared_ptr<DbView> v)
{
    return sdWorkerRun([v]() {
        probeDBRunView(*v);
        v->done = true;
        if (v->then) v->then();
    });
}

static void probeEventLineRender(const char *text, size_t len, PsramJsonString &out)
{
    String line;
    line.concat(text, len);
    line.trim();
    if (line.length() < 10) return;

    DynamicJsonDocument doc(768);
    if (deserializeJson(doc, line) != DeserializationError::Ok) return;

    const char *mac = doc["mac"] | "";
    uint8_t macBytes[6];
    const char *v = (strlen(mac) >= 17 && parseMac6(String(mac), macBytes))
                    ? lookupOuiVendor(macBytes) : nullptr;

    if (!doc.containsKey("ble")) doc["ble"] = (doc["ch"].as<int>() == 0);

    if (doc["ble"].as<bool>() && doc.containsKey("v") && !doc.containsKey("n")) {
        doc["n"] = doc["v"];
        doc.remove("v");
    }
    if (v) doc["v"] = v;

    String rendered;
    serializeJson(doc, rendered);
    out.append(rendered.c_str(), rendered.length());
    out.push_back('\n');
}

size_t probeEventsStreamFill(ProbeLogStream &st, uint8_t *buf, size_t maxLen)
{
    if (!st.started) {
        st.started = true;
        st.end = SafeSD::size("/probes.jsonl");
    }
    size_t written = 0;
    while (written < maxLen) {
        if (st.pendOff < st.pend.size()) {
            size_t n = st.pend.size() - st.pendOff;
            if (n > maxLen - written) n = maxLen - written;
            memcpy(buf + written, st.pend.data() + st.pendOff, n);
            st.pendOff += n;
            written += n;
            continue;
        }
        st.pend.clear();
        st.pendOff = 0;
        if (st.eof) break;
        uint8_t chunk[1024];
        const size_t want = st.end > st.offset ? std::min(sizeof(chunk), st.end - st.offset) : 0;
        const size_t n = want ? SafeSD::readAt("/probes.jsonl", st.offset, chunk, want) : 0;
        st.offset += n;
        if (n == 0) {
            st.eof = true;
            if (!st.carry.empty()) probeEventLineRender(st.carry.data(), st.carry.size(), st.pend);
            st.carry.clear();
            continue;
        }
        st.carry.append(reinterpret_cast<const char *>(chunk), n);
        size_t pos = 0;
        for (size_t nl; (nl = st.carry.find('\n', pos)) != PsramJsonString::npos; pos = nl + 1)
            probeEventLineRender(st.carry.data() + pos, nl - pos, st.pend);
        st.carry.erase(0, pos);
    }
    return written;
}

bool clearProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDBInitLocked();
    s_probeFileGen++;
    s_probeLoaded = SafeSD::isAvailable();
    bool ok = s_probeLoaded;
    for (const char *p : {PROBE_DB_BIN, PROBE_DB_BIN_TMP, PROBE_DB_BIN_BAK, PROBE_DB_PATH, PROBE_DB_TMP,
                          PROBE_DB_BAK, PROBE_DB_ARCHIVE})
        if (SafeSD::exists(p) && !SafeSD::remove(p)) ok = false;
    Serial.println(ok ? "[PROBEDB] Database cleared" : "[PROBEDB] Database clear failed on SD");
    return ok;
}
