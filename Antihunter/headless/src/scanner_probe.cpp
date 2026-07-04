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
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "triangulation.h"
#include "baseline.h"
#include "detect.h"
#include "main.h"
#include "scanner_internal.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
#include "esp_heap_caps.h"
}

// Probe-hit cooldown map type (probe-only)
using StringU32MapPsram = std::map<String, uint32_t, std::less<String>,
    PsramAllocator<std::pair<const String, uint32_t>>>;

static std::atomic<uint32_t> totalProbeCount(0);
static std::atomic<uint32_t> probeHitCount(0);
static StringU32MapPsram probeHitCooldowns;
static const uint32_t PROBE_HIT_COOLDOWN_MS = 60000;

void addProbeSsid(ProbeDevice &dev, const char *ssid, bool fromResponse)
{
    if (!ssid || ssid[0] == '\0') return;
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

// Extract SSID from IE tags. ieStart=24 for probe requests, 36 for probe responses/beacons.
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

bool extractSsidFromProbe(const uint8_t *payload, uint16_t frameLen, char *ssidBuf, size_t ssidBufSize)
{
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

    if (probeHitCooldowns.size() >= PROBE_HIT_COOLDOWN_MAX) {
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

    String msg = getNodeId() + ": PROBE_HIT " + String(macStr) + " ";
    bool randomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
    if (randomized) {
        msg += "Randomized";
    } else if (vendor && vendor[0]) {
        msg += String(vendor);
    } else {
        msg += "Unknown";
    }
    msg += " RSSI=" + String(rssi) + " CH=" + String(channel);
    if (ssid && ssid[0]) {
        msg += " SSID=\"" + String(ssid) + "\"";
        if (ghostSsid) msg += " GHOST";
    }
    if (isDst) {
        msg += " DST";
    }

    if (msg.length() <= static_cast<size_t>(MAX_MESH_SIZE)) {
        meshEnqueue(msg);
    }
}

void probeDetectionTask(void *pv)
{
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);

    Serial.printf("[PROBE] Starting probe detection, duration=%d forever=%d\n", duration, forever);
    scanSetCountdown(duration, forever);

    // Load known device database from SD
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

    if (probeRequestQueue == nullptr) {
        probeRequestQueue = xQueueCreateWithCaps(256, sizeof(ProbeRequestEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    } else {
        xQueueReset(probeRequestQueue);
    }

    probeDetectionEnabled = true;
    scanning = true;

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Probe scan - Mode: WiFi (IN PROGRESS)\nDevices: 0 | Probes: 0 | SSIDs: 0 | Hits: 0\n\n(Starting...)\n";
    }

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    uint32_t startTime = millis();
    uint32_t nextResultsUpdate = startTime;
    uint32_t lastBLEScan = 0;
    uint32_t lastDBSave = startTime;

    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < static_cast<uint32_t>(duration * 1000) && !stopRequested)) {

        ProbeRequestEvent event;
        int processedCount = 0;
        while (xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE && processedCount < 200) {
            processedCount++;

            // --- Probe Response (stype 5) ---
            // Maps the responding AP's SSID to the device that sent the probe request
            if (event.isProbeResponse) {
                // addr1 = device that probed, extract SSID from probe response IEs (offset 36)
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

            // dst events are unfiltered unicast from ISR — verify target here
            if (event.dstMatch) {
                if (!matchesMac(event.mac)) continue;
            }

            char ssidBuf[33] = {0};
            bool hasSSID = false;
            if (!event.dstMatch) {
                hasSSID = extractSsidFromProbe(event.payload, event.payloadLen, ssidBuf, sizeof(ssidBuf));
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
                    if (isHit && !dev.isTargetHit) {
                        dev.isTargetHit = true;
                        probeHitCount++;
                    }
                    if (dstHit) dev.isDstHit = true;
                } else {
                    if (probeDevices.size() >= 100) {
                        uint32_t oldestTime = UINT32_MAX;
                        String oldestKey;
                        for (const auto &p : probeDevices) {
                            if (!p.second.isTargetHit && p.second.lastSeen < oldestTime) {
                                oldestTime = p.second.lastSeen;
                                oldestKey = p.first;
                            }
                        }
                        if (oldestKey.length() > 0) probeDevices.erase(oldestKey);
                    }

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

                    // Annotate with SD database history
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

        if (static_cast<int32_t>(millis() - nextResultsUpdate) >= 0) {
            std::string results = getProbeResults().c_str();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            nextResultsUpdate = millis() + 2000;
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) &&
            pBLEScan && (millis() - lastBLEScan >= 3000)) {
            pBLEScan->start(2, false);
            NimBLEScanResults scanResults = pBLEScan->getResults(500, false);
            int count = scanResults.getCount();
            for (int i = 0; i < count; i++) {
                const NimBLEAdvertisedDevice *device = scanResults.getDevice(i);
                if (!device) continue;
                String macStr = device->getAddress().toString().c_str();
                macStr.toUpperCase();
                uint8_t mac[6];
                if (sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                    if (matchesMac(mac)) {
                        std::lock_guard<std::mutex> lock(probeMutex);
                        auto it = probeDevices.find(macStr);
                        if (it == probeDevices.end()) {
                            ProbeDevice dev = {};
                            memcpy(dev.mac, mac, 6);
                            dev.rssi = device->getRSSI();
                            dev.rssiMin = dev.rssi;
                            dev.rssiMax = dev.rssi;
                            dev.channel = 0;
                            dev.firstSeen = millis();
                            dev.lastSeen = millis();
                            dev.probeCount = 1;
                            dev.isRandomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
                            dev.isTargetHit = true;
                            strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason));
                            if (device->getName().length() > 0) {
                                strncpy(dev.vendor, device->getName().c_str(), sizeof(dev.vendor) - 1);
                            }
                            probeDevices[macStr] = dev;
                            probeHitCount++;
                        }
                    }
                }
            }
            pBLEScan->clearResults();
            lastBLEScan = millis();
        }

        // Periodic DB save every 60s (for forever mode resilience)
        if ((millis() - lastDBSave) >= 60000) {
            {
                std::lock_guard<std::mutex> lock(probeMutex);
                for (const auto &p : probeDevices) {
                    mergeProbeDeviceToDB(p.second);
                }
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

    // Merge all devices into SD database and save
    {
        std::lock_guard<std::mutex> lock(probeMutex);
        for (const auto &p : probeDevices) {
            mergeProbeDeviceToDB(p.second);
        }
    }
    saveProbeDB();
    Serial.printf("[PROBE] Merged %u devices into probe database\n", probeDevices.size());

    // Log probe events to /probes.jsonl on SD
    {
        File logFile = SD.open("/probes.jsonl", FILE_APPEND);
        if (logFile) {
            uint32_t now = getEventTimestamp();
            std::lock_guard<std::mutex> lock(probeMutex);
            for (auto &p : probeDevices) {
                ProbeDevice &dev = p.second;
                DynamicJsonDocument doc(512);
                doc["t"] = now;
                doc["mac"] = p.first;
                doc["rssi"] = dev.rssi;
                doc["ch"] = dev.channel;
                doc["cnt"] = dev.probeCount;
                doc["rand"] = dev.isRandomized;
                if (dev.vendor[0]) doc["v"] = dev.vendor;
                if (dev.isTargetHit) doc["hit"] = true;
                if (dev.isDstHit) doc["dst"] = true;
                JsonArray ss = doc.createNestedArray("ss");
                for (uint8_t i = 0; i < dev.ssidCount; i++) {
                    ss.add(dev.ssids[i]);
                }
                if (dev.respondingAP[0]) doc["ap"] = dev.respondingAP;
                if (dev.respondingSSID[0]) doc["apssid"] = dev.respondingSSID;
                serializeJson(doc, logFile);
                logFile.println();
            }
            logFile.close();

            // Rotate if over 1MB
            File check = SD.open("/probes.jsonl", FILE_READ);
            if (check && check.size() > 1048576) {
                check.close();
                SD.remove("/probes_old.jsonl");
                SD.rename("/probes.jsonl", "/probes_old.jsonl");
                Serial.println("[PROBE] Rotated probes.jsonl");
            } else if (check) {
                check.close();
            }
        }
    }

    scanning = false;

    {
        String probeRes = getProbeResults();
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = probeRes.c_str();
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
    if (millis() - lastProbeResultsTime < 2000 && cachedProbeResults.length() > 0) {
        return cachedProbeResults;
    }
    lastProbeResultsTime = millis();
    std::lock_guard<std::mutex> lock(probeMutex);

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    String results = "Probe scan - Mode: " + modeStr;
    if (scanning) results += " (IN PROGRESS)";
    results += "\nDevices: " + String(probeDevices.size()) +
               " | Probes: " + String(static_cast<uint32_t>(totalProbeCount)) +
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

    for (const auto &p : sorted) {
        ProbeDevice &dev = *p.second;
        results += "WiFi " + p.first + " RSSI=" + String(dev.rssi) + "dBm CH=" + String(dev.channel) + " ";

        if (dev.isRandomized) {
            results += "Randomized";
        } else if (dev.vendor[0]) {
            String v = sanitizeAscii(dev.vendor, sizeof(dev.vendor));
            if (v.length() > 0) results += v;
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
            if (!any) results += " (wildcard)";
        } else {
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

        // Probe count this session
        if (dev.probeCount > 1) {
            results += " x" + String(dev.probeCount);
        }

        // Historical intelligence from SD database
        if (dev.histKnown) {
            results += " [KNOWN:seen=" + String(dev.histTotalSeen) +
                       " sessions=" + String(dev.histSessionCount) +
                       " last=" + formatAge(nowEpoch, dev.histLastEpoch) + "]";
        }

        results += "\n";
    }

    // SSID summary with device mapping
    if (uniqueSsids.size() > 0) {
        results += "\nSSIDs seen (" + String(uniqueSsids.size()) + "):\n";

        // Build SSID->devices map
        std::map<String, std::vector<String>> ssidToDevices;
        for (auto &p : probeDevices) {
            for (uint8_t i = 0; i < p.second.ssidCount; i++) {
                ssidToDevices[String(p.second.ssids[i])].push_back(p.first);
            }
        }

        // Sort by device count descending
        std::vector<std::pair<String, std::vector<String>>> ssidSorted(ssidToDevices.begin(), ssidToDevices.end());
        std::sort(ssidSorted.begin(), ssidSorted.end(),
            [](const std::pair<String, std::vector<String>> &a,
               const std::pair<String, std::vector<String>> &b) { return a.second.size() > b.second.size(); });

        for (auto &s : ssidSorted) {
            bool ghost = respondedSsids.find(s.first) == respondedSsids.end();
            results += "  " + String(ghost ? "~" : "") + "\"" + s.first + "\" (" + String(s.second.size()) +
                       (s.second.size() == 1 ? " device" : " devices") + ")";
            // Show the first 3 MAC addresses probing for this SSID
            if (s.second.size() <= 3) {
                results += " [";
                for (size_t i = 0; i < s.second.size(); i++) {
                    if (i > 0) results += ", ";
                    results += s.second[i].substring(9); // last 3 octets for brevity
                }
                results += "]";
            }
            results += "\n";
        }
    }

    cachedProbeResults = results;
    return results;
}

// --- SD Probe Device Database ---
// Stores known devices as JSONL on SD: /probedb.jsonl
// Each line: {"m":"AA:BB:CC:DD:EE:FF","t":1234,"f":100,"l":200,"s":3,"r":-42,"v":"Apple","rd":0,"ss":["Net1","Net2"]}

static std::map<String, ProbeDBEntry> probeDB;
static std::mutex probeDBMutex;
static const char *PROBE_DB_PATH = "/probedb.jsonl";
static const size_t PROBE_DB_MAX_ENTRIES = 500;

void loadProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDB.clear();

    if (!SD.exists(PROBE_DB_PATH)) {
        Serial.println("[PROBEDB] No database file on SD");
        return;
    }

    File f = SD.open(PROBE_DB_PATH, FILE_READ);
    if (!f) {
        Serial.println("[PROBEDB] Failed to open database");
        return;
    }

    uint32_t count = 0;
    while (f.available() && count < PROBE_DB_MAX_ENTRIES) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 10) continue;

        DynamicJsonDocument doc(512);
        if (deserializeJson(doc, line) != DeserializationError::Ok) continue;

        const char *mac = doc["m"] | "";
        if (strlen(mac) < 17) continue;

        ProbeDBEntry entry = {};
        strncpy(entry.mac, mac, 17);
        entry.mac[17] = '\0';
        entry.totalSeen = doc["t"].as<uint32_t>();
        entry.firstEpoch = doc["f"].as<uint32_t>();
        entry.lastEpoch = doc["l"].as<uint32_t>();
        entry.sessionCount = doc["s"].as<uint16_t>();
        entry.bestRssi = doc["r"] | -128;
        entry.isRandomized = doc["rd"].as<bool>();

        const char *vendor = doc["v"] | "";
        strncpy(entry.vendor, vendor, sizeof(entry.vendor) - 1);

        JsonArray ssArr = doc["ss"];
        entry.ssidCount = 0;
        if (ssArr) {
            for (JsonVariant s : ssArr) {
                if (entry.ssidCount >= 4) break;
                const char *ss = s.as<const char*>();
                if (ss && ss[0]) {
                    strncpy(entry.ssids[entry.ssidCount], ss, 32);
                    entry.ssids[entry.ssidCount][32] = '\0';
                    entry.ssidCount++;
                }
            }
        }

        probeDB[String(mac)] = entry;
        count++;
    }
    f.close();
    Serial.printf("[PROBEDB] Loaded %u devices from SD\n", count);
}

void saveProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);

    File f = SD.open(PROBE_DB_PATH, FILE_WRITE);
    if (!f) {
        Serial.println("[PROBEDB] Failed to write database");
        return;
    }

    uint32_t written = 0;
    for (auto &p : probeDB) {
        DynamicJsonDocument doc(512);
        doc["m"] = p.second.mac;
        doc["t"] = p.second.totalSeen;
        doc["f"] = p.second.firstEpoch;
        doc["l"] = p.second.lastEpoch;
        doc["s"] = p.second.sessionCount;
        doc["r"] = p.second.bestRssi;
        doc["v"] = p.second.vendor;
        doc["rd"] = p.second.isRandomized ? 1 : 0;

        JsonArray ss = doc.createNestedArray("ss");
        for (uint8_t i = 0; i < p.second.ssidCount; i++) {
            ss.add(p.second.ssids[i]);
        }

        serializeJson(doc, f);
        f.println();
        written++;
    }
    f.close();
    Serial.printf("[PROBEDB] Saved %u devices to SD\n", written);
}

void mergeProbeDeviceToDB(const ProbeDevice &dev)
{
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);

    std::lock_guard<std::mutex> lock(probeDBMutex);
    uint32_t now = getEventTimestamp();

    auto it = probeDB.find(String(macStr));
    if (it != probeDB.end()) {
        ProbeDBEntry &e = it->second;
        e.totalSeen += dev.probeCount;
        e.lastEpoch = now;
        e.sessionCount++;
        if (dev.rssi > e.bestRssi) e.bestRssi = dev.rssi;
        if (dev.vendor[0] && !e.vendor[0]) {
            strncpy(e.vendor, dev.vendor, sizeof(e.vendor) - 1);
        }
        for (uint8_t i = 0; i < dev.ssidCount; i++) {
            bool found = false;
            for (uint8_t j = 0; j < e.ssidCount; j++) {
                if (strcasecmp(e.ssids[j], dev.ssids[i]) == 0) { found = true; break; }
            }
            if (!found && e.ssidCount < 8) {
                strncpy(e.ssids[e.ssidCount], dev.ssids[i], 32);
                e.ssids[e.ssidCount][32] = '\0';
                e.ssidCount++;
            }
        }
    } else {
        if (probeDB.size() >= PROBE_DB_MAX_ENTRIES) {
            uint32_t oldestEpoch = UINT32_MAX;
            String oldestKey;
            for (const auto &p : probeDB) {
                if (p.second.lastEpoch < oldestEpoch) {
                    oldestEpoch = p.second.lastEpoch;
                    oldestKey = p.first;
                }
            }
            if (oldestKey.length() > 0) probeDB.erase(oldestKey);
        }

        ProbeDBEntry e = {};
        strncpy(e.mac, macStr, 17);
        e.mac[17] = '\0';
        e.totalSeen = dev.probeCount;
        e.firstEpoch = now;
        e.lastEpoch = now;
        e.sessionCount = 1;
        e.bestRssi = dev.rssi;
        e.isRandomized = dev.isRandomized;
        strncpy(e.vendor, dev.vendor, sizeof(e.vendor) - 1);
        e.ssidCount = 0;
        for (uint8_t i = 0; i < dev.ssidCount && e.ssidCount < 8; i++) {
            strncpy(e.ssids[e.ssidCount], dev.ssids[i], 32);
            e.ssids[e.ssidCount][32] = '\0';
            e.ssidCount++;
        }
        probeDB[String(macStr)] = e;
    }
}

bool lookupProbeHistory(const char *macStr, ProbeDBEntry &out)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    auto it = probeDB.find(String(macStr));
    if (it != probeDB.end()) {
        out = it->second;
        return true;
    }
    return false;
}

uint32_t getProbeDBSize()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    return probeDB.size();
}

String getProbeDBJson()
{
    std::vector<ProbeDBEntry> snap;
    {
        std::lock_guard<std::mutex> lock(probeDBMutex);
        snap.reserve(probeDB.size());
        for (const auto &p : probeDB) snap.push_back(p.second);
    }

    String out;
    out.reserve(2 + snap.size() * 240);
    out += "[";
    bool first = true;
    for (const auto &e : snap) {
        if (!first) out += ",";
        first = false;
        DynamicJsonDocument doc(512);
        doc["mac"] = e.mac;
        doc["seen"] = e.totalSeen;
        doc["sessions"] = e.sessionCount;
        doc["first"] = e.firstEpoch;
        doc["last"] = e.lastEpoch;
        doc["rssi"] = e.bestRssi;
        doc["vendor"] = e.vendor;
        doc["rand"] = e.isRandomized;
        JsonArray ss = doc.createNestedArray("ssids");
        for (uint8_t i = 0; i < e.ssidCount && i < 8; i++) {
            ss.add(e.ssids[i]);
        }
        serializeJson(doc, out);
    }
    out += "]";
    return out;
}

void clearProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDB.clear();
    SafeSD::remove(PROBE_DB_PATH);
    Serial.println("[PROBEDB] Database cleared");
}
