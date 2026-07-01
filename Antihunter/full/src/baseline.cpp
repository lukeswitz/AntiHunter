#include "baseline.h"
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"
#include "detect.h"
#include <algorithm>
#include <iterator>
#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include <Preferences.h>

// External deps
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern Preferences prefs;
extern std::atomic<bool> stopRequested;
extern ScanMode currentScanMode;
extern std::atomic<bool> scanning;
extern std::atomic<uint32_t> framesSeen;
extern std::atomic<uint32_t> bleFramesSeen;
extern QueueHandle_t macQueue;
extern TaskHandle_t workerTaskHandle;
extern bool sdAvailable;
extern bool meshEnabled;
extern float gpsLat, gpsLon;
extern bool gpsValid;
extern NimBLEScan *pBLEScan;
extern String getNodeId();
extern void logToSD(const String &msg);
extern void radioStartSTA();
extern void radioStopListScan();
extern void radioStartListScan();
extern void radioStopListScan();
extern bool isAllowlisted(const uint8_t *mac);

// Pack a 6-byte MAC into a uint64 key (avoids per-device internal-heap String buffers)
static inline uint64_t blKey(const uint8_t *m) {
    uint64_t v = 0;
    for (int i = 0; i < 6; i++) v = (v << 8) | m[i];
    return v;
}

// RAM SD Cache
PsramMap<uint64_t, bool> sdLookupCache;
std::list<uint64_t, PsramAllocator<uint64_t>> sdLookupLRU;
const uint32_t SD_LOOKUP_CACHE_SIZE = 200;
PsramMap<uint64_t, uint32_t> sdDeviceIndex;

// Scan intervals from scanner
extern uint32_t WIFI_SCAN_INTERVAL;
extern uint32_t BLE_SCAN_INTERVAL;

// Baseline detection state variables
std::mutex baselineMutex;
BaselineStats baselineStats;
bool baselineDetectionEnabled = false;
bool baselineEstablished = false;
static bool baselineResultsDirty = false;
uint32_t baselineStartTime = 0;
uint32_t baselineDuration = 300000;
PsramMap<uint64_t, BaselineDevice> baselineCache;

struct LRUNode {
    uint64_t key;
    uint32_t lastSeen;
};
std::list<LRUNode, PsramAllocator<LRUNode>> lruList;
PsramMap<uint64_t, std::list<LRUNode, PsramAllocator<LRUNode>>::iterator> lruMap;

uint32_t totalDevicesOnSD = 0;
uint32_t lastSDFlush = 0;
bool sdBaselineInitialized = false;
std::vector<AnomalyHit> anomalyLog;
uint32_t anomalyCount = 0;
uint32_t baselineDeviceCount = 0;
QueueHandle_t anomalyQueue = nullptr;
int8_t baselineRssiThreshold = -60;
uint32_t baselineRamCacheSize = 400;
uint32_t baselineSdMaxDevices = 50000;
static unsigned long lastBaselineAnomalyMeshSend = 0;
const unsigned long BASELINE_ANOMALY_MESH_INTERVAL = 5000;
const uint32_t MIN_FLUSH_INTERVAL = 60000;
const uint32_t MIN_DIRTY_COUNT = 50;

const uint32_t MESH_SLOT_CYCLE_MS = 15000;
const uint32_t MESH_NUM_SLOTS = 5;
const uint32_t MESH_SLOT_DURATION_MS = MESH_SLOT_CYCLE_MS / MESH_NUM_SLOTS;
static uint32_t meshCycleStartTime = 0;

static uint8_t getNodeSlot() {
    String nodeId = getNodeId();
    uint32_t hash = 0;
    for (size_t i = 0; i < nodeId.length(); i++) {
        hash = hash * 31 + nodeId.charAt(i);
    }
    return hash % MESH_NUM_SLOTS;
}

static bool isMyMeshSlot() {
    if (meshCycleStartTime == 0) {
        meshCycleStartTime = millis();
    }
    uint32_t elapsed = millis() - meshCycleStartTime;
    uint32_t positionInCycle = elapsed % MESH_SLOT_CYCLE_MS;
    uint8_t currentSlot = positionInCycle / MESH_SLOT_DURATION_MS;
    return currentSlot == getNodeSlot();
}


// ============ Baseline Detection Implementation ============

// Baseline Scanner 
int8_t getBaselineRssiThreshold() {
    return baselineRssiThreshold;
}

void setBaselineRssiThreshold(int8_t threshold) {
    if (threshold >= -100 && threshold <= -30) {
        baselineRssiThreshold = threshold;
        prefs.putInt("baselineRSSI", threshold);
        Serial.printf("[BASELINE] RSSI threshold set to %d dBm\n", threshold);
    }
}

void resetBaselineDetection() {
    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        baselineCache.clear();
        anomalyLog.clear();
        sdDeviceIndex.clear();
        lruList.clear();
        lruMap.clear();
        anomalyCount = 0;
        baselineDeviceCount = 0;
        baselineEstablished = false;
        totalDevicesOnSD = 0;

        baselineStats.wifiDevices = 0;
        baselineStats.bleDevices = 0;
        baselineStats.totalDevices = 0;
        baselineStats.wifiHits = 0;
        baselineStats.bleHits = 0;
    }

    // Clear SD storage
      if (SafeSD::isAvailable()) {
        if (SafeSD::exists("/baseline_data.bin")) {
            SafeSD::remove("/baseline_data.bin");
            Serial.println("[BASELINE] Removed SD data file");
        }
        if (SafeSD::exists("/baseline_stats.json")) {
            SafeSD::remove("/baseline_stats.json");
            Serial.println("[BASELINE] Removed SD stats file");
        }
    }
    
    sdBaselineInitialized = false;
    initializeBaselineSD();
    
    Serial.println("[BASELINE] Reset complete");
}

void updateBaselineDevice(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel) {
    // Discard implausible RSSI (NimBLE glitch values like -8 dBm)
    if (rssi > -10) {
        return;
    }
    uint64_t macKey = blKey(mac);
    uint32_t now = millis();

    // Phase 2.2: feed device into local Bloom filter for mesh baseline gossip.
    // ieHash defaults to 0 here; randomization.cpp feeds the proper IE-hash
    // via its own detect_addLocalBaseline call when it has the IE set.
    detect_addLocalBaseline(mac, 0);

    BaselineDevice evictDevice;
    bool haveEvictDevice = false;

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        if (baselineCache.find(macKey) == baselineCache.end()) {
            uint32_t effectiveLimit = (sdAvailable && sdBaselineInitialized) ?
                                        baselineRamCacheSize : 1500;

            if (baselineCache.size() >= effectiveLimit) {
                if (sdAvailable && sdBaselineInitialized) {
                    if (!lruList.empty()) {
                        const auto& oldest = lruList.front();
                        uint64_t evictKey = oldest.key;

                        const auto& oldestDevice = baselineCache[evictKey];
                        if (oldestDevice.dirtyFlag) {
                            evictDevice = oldestDevice;
                            haveEvictDevice = true;
                        }

                        baselineCache.erase(evictKey);
                        lruMap.erase(evictKey);
                        lruList.pop_front();
                    }
                } else {
                    if (baselineCache.size() % 100 == 0) {
                        Serial.printf("[BASELINE] No SD - RAM limit reached: %d devices (heap: %u)\n",
                                    baselineCache.size(), ESP.getFreeHeap());
                    }
                    return;
                }
            }

            BaselineDevice dev;
            memcpy(dev.mac, mac, 6);
            dev.avgRssi = rssi;
            dev.minRssi = rssi;
            dev.maxRssi = rssi;
            dev.firstSeen = now;
            dev.lastSeen = now;
            strncpy(dev.name, name, sizeof(dev.name) - 1);
            dev.name[sizeof(dev.name) - 1] = '\0';
            dev.isBLE = isBLE;
            dev.channel = channel;
            dev.hitCount = 1;
            dev.checksum = 0;
            dev.dirtyFlag = true;

            baselineCache[macKey] = dev;

            LRUNode node;
            node.key = macKey;
            node.lastSeen = now;
            lruList.push_back(node);
            lruMap[macKey] = --lruList.end();

            baselineDeviceCount++;
            baselineResultsDirty = true;
        } else {
            BaselineDevice &dev = baselineCache[macKey];
            dev.avgRssi = (int32_t(dev.avgRssi) * int32_t(dev.hitCount) + rssi) / int32_t(dev.hitCount + 1);
            if (rssi < dev.minRssi) dev.minRssi = rssi;
            if (rssi > dev.maxRssi) dev.maxRssi = rssi;
            dev.lastSeen = now;
            if (dev.hitCount < UINT32_MAX) dev.hitCount++;
            dev.dirtyFlag = true;
            baselineResultsDirty = true;

            auto lruIt = lruMap.find(macKey);
            if (lruIt != lruMap.end()) {
                lruList.erase(lruIt->second);
                LRUNode node;
                node.key = macKey;
                node.lastSeen = now;
                lruList.push_back(node);
                lruMap[macKey] = --lruList.end();
            }

            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0 && strcmp(name, "WiFi") != 0) {
                strncpy(dev.name, name, sizeof(dev.name) - 1);
                dev.name[sizeof(dev.name) - 1] = '\0';
            }
        }
    }

    if (haveEvictDevice) {
        writeBaselineDeviceToSD(evictDevice);
    }

    if (sdAvailable && sdBaselineInitialized && millis() - lastSDFlush >= BASELINE_SD_FLUSH_INTERVAL) {
        flushBaselineCacheToSD();
        lastSDFlush = millis();
    }
}

static void appendCacheDeviceLines(String& out) {
    out.reserve(out.length() + baselineCache.size() * 90);
    for (const auto &entry : baselineCache) {
        const BaselineDevice &dev = entry.second;
        out += String(dev.isBLE ? "BLE  " : "WiFi ") + macFmt6(dev.mac);
        out += " Avg:" + String(dev.avgRssi) + "dBm";
        out += " Min:" + String(dev.minRssi) + "dBm";
        out += " Max:" + String(dev.maxRssi) + "dBm";
        out += " Hits:" + String(dev.hitCount);
        if (!dev.isBLE && dev.channel > 0) {
            out += " CH:" + String(dev.channel);
        }
        if (strlen(dev.name) > 0 && strcmp(dev.name, "Unknown") != 0 && strcmp(dev.name, "WiFi") != 0) {
            out += " \"" + String(dev.name) + "\"";
        }
        out += "\n";
    }
}

String getBaselineResults() {
    String results;
    std::lock_guard<std::mutex> lock(baselineMutex);

    if (baselineEstablished) {
        results.reserve(256 + baselineCache.size() * 90 + anomalyLog.size() * 80);
        results += "Baseline Detection Results\n";
        results += "Total devices in baseline: " + String(baselineDeviceCount) + "\n";
        results += "WiFi devices: " + String(baselineStats.wifiDevices) + "\n";
        results += "BLE devices: " + String(baselineStats.bleDevices) + "\n";
        results += "RSSI threshold: " + String(baselineRssiThreshold) + " dBm\n\n";

        results += "=== BASELINE DEVICES (Cached in RAM) ===\n";
        appendCacheDeviceLines(results);

        results += "\n=== ANOMALIES DETECTED ===\n";
        results += "Total anomalies: " + String(anomalyCount) + "\n\n";

        for (const auto &anomaly : anomalyLog) {
            results += String(anomaly.isBLE ? "BLE  " : "WiFi ") + macFmt6(anomaly.mac);
            results += " RSSI:" + String(anomaly.rssi) + "dBm";
            if (!anomaly.isBLE && anomaly.channel > 0) {
                results += " CH:" + String(anomaly.channel);
            }
            if (strlen(anomaly.name) > 0 && strcmp(anomaly.name, "Unknown") != 0) {
                results += " \"" + String(anomaly.name) + "\"";
            }
            results += " - " + anomaly.reason;
            results += "\n";
        }
    } else {
        results.reserve(128 + baselineCache.size() * 90);
        results += "Baseline not yet established\n";
        results += "Devices detected so far: " + String(baselineDeviceCount) + "\n";
        if (baselineStartTime > 0) {
            uint32_t elapsed = (millis() - baselineStartTime) / 1000;
            uint32_t total = baselineDuration / 1000;
            results += "Elapsed: " + String(elapsed) + "s / " + String(total) + "s\n";
        }

        results += "\n=== BASELINE DEVICES (Cached in RAM) ===\n";
        appendCacheDeviceLines(results);
    }

    return results;
}

void updateBaselineStats() {
    std::lock_guard<std::mutex> lock(baselineMutex);
    baselineStats.wifiDevices = 0;
    baselineStats.bleDevices = 0;

    for (const auto& device : baselineCache) {
        if (device.second.isBLE) {
            baselineStats.bleDevices++;
        } else {
            baselineStats.wifiDevices++;
        }
    }

    baselineStats.totalDevices = baselineDeviceCount;
    baselineStats.wifiHits = framesSeen;
    baselineStats.bleHits = bleFramesSeen;
}

uint32_t calculateOptimalCacheSize() {
    uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < 30000) return 100;
    if (freeHeap < 50000) return 200;
    if (freeHeap < 100000) return 300;
    return 400;
}

// Non-blocking WiFi AP scan: start when due, harvest when ready. A synchronous
// scanNetworks() blocked the baseline loop for the whole sweep, delaying STOP and
// anomaly/results handling by seconds; async keeps the loop responsive.
static void baselineHarvestWifiAsync(uint32_t &lastWiFiScan) {
    int wifiScan = WiFi.scanComplete();
    if (wifiScan == WIFI_SCAN_FAILED) {
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL) {
            lastWiFiScan = millis();
            WiFi.scanNetworks(true, false, false, rfConfig.wifiChannelTime, nextActiveScanChannel());
        }
        return;
    }
    if (wifiScan < 0) return;  // WIFI_SCAN_RUNNING
    for (int i = 0; i < wifiScan && !stopRequested; i++) {
        const uint8_t *bssidBytes = WiFi.BSSID(i);
        String ssid = WiFi.SSID(i);
        int32_t rssi = WiFi.RSSI(i);
        uint8_t channel = WiFi.channel(i);

        if (ssid.length() == 0) ssid = "[Hidden]";

        Hit wh;
        memcpy(wh.mac, bssidBytes, 6);
        wh.rssi = rssi;
        wh.ch = channel;
        strncpy(wh.name, ssid.c_str(), sizeof(wh.name) - 1);
        wh.name[sizeof(wh.name) - 1] = '\0';
        wh.isBLE = false;

        if (macQueue) {
            xQueueSend(macQueue, &wh, 0);
        }
        framesSeen = framesSeen + 1;
    }
    WiFi.scanDelete();
}

void baselineDetectionTask(void *pv) {
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);
    scanSetCountdown(duration, forever);

    if (!sdBaselineInitialized) {
        if (initializeBaselineSD()) {
            loadBaselineFromSD();
            if (baselineDeviceCount > 0) {
                Serial.printf("[BASELINE] Resuming with %d devices from SD\n", baselineDeviceCount);
                baselineEstablished = true;
            }
        }
    }
    
    Serial.printf("[BASELINE] Starting detection - Threshold: %d dBm\n", baselineRssiThreshold);
    Serial.printf("[BASELINE] RAM cache: %u devices, SD limit: %u devices\n", baselineRamCacheSize, baselineSdMaxDevices);
    Serial.printf("[BASELINE] Phase 1: Establishing baseline for %d seconds\n", baselineDuration / 1000);
    
    stopRequested = false;
    baselineDetectionEnabled = true;
    // Always re-enter Phase 1 on a new run — keep the cache but clear transient state
    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        baselineEstablished = false;
        anomalyLog.clear();
        anomalyCount = 0;
    }
    deviceHistory.clear();
    baselineStartTime = millis();
    currentScanMode = SCAN_BOTH;

    if (anomalyQueue) vQueueDeleteWithCaps(anomalyQueue);
    anomalyQueue = xQueueCreateWithCaps(256, sizeof(AnomalyHit), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!anomalyQueue) {
        Serial.println("[BASELINE] FATAL: anomalyQueue creation failed");
        scanning = false;
        vTaskDelete(NULL);
        return;
    }

    if (macQueue) vQueueDeleteWithCaps(macQueue);
    macQueue = xQueueCreateWithCaps(512, sizeof(Hit), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!macQueue) {
        Serial.println("[BASELINE] FATAL: macQueue creation failed");
        vQueueDeleteWithCaps(anomalyQueue);
        anomalyQueue = nullptr;
        scanning = false;
        vTaskDelete(NULL);
        return;
    }

    std::set<String> transmittedDevices;
    std::set<String> transmittedAnomalies;
    
    framesSeen = 0;
    bleFramesSeen = 0;
    scanning = true;
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Baseline not yet established\nStarting...\n";
    }

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        baselineStats = BaselineStats();
        baselineStats.isScanning = true;
        baselineStats.phase1Complete = false;
        baselineStats.totalDuration = baselineDuration;
    }

    radioStartListScan();
    vTaskDelay(pdMS_TO_TICKS(200));

    if (!pBLEScan) {
        BLEDevice::init("");
        pBLEScan = BLEDevice::getScan();
    }
    
    if (pBLEScan && !pBLEScan->isScanning()) {
        pBLEScan->setActiveScan(true);
        // 30% BLE duty (was ~99%) leaves the shared radio airtime for the AP
        pBLEScan->setInterval(160);
        pBLEScan->setWindow(48);
        pBLEScan->setDuplicateFilter(false);
        pBLEScan->start(0, false);
    }

    uint32_t phaseStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t nextStatsUpdate = millis() + 1000;
    uint32_t nextResultsUpdate = millis() + 2000;
    uint32_t nextCacheSizeCheck = millis() + 30000;
    uint32_t lastCleanup = millis();
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    uint32_t lastMeshUpdate = 0;
    const uint32_t MESH_DEVICE_UPDATE_INTERVAL = 5000;
    
    Hit h;
    
    Serial.printf("[BASELINE] Phase 1 starting at %u ms, will run until %u ms\n",
                  phaseStart, phaseStart + baselineDuration);

    // Write initial results immediately so web UI shows scan is active
    {
        String initialResults = getBaselineResults();
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = initialResults.c_str();
    }

    while (millis() - phaseStart < baselineDuration && !stopRequested) {
        {
            std::lock_guard<std::mutex> lock(baselineMutex);
            baselineStats.elapsedTime = millis() - phaseStart;
        }

        if ((int32_t)(millis() - nextStatsUpdate) >= 0) {
            updateBaselineStats();
            nextStatsUpdate += 1000;
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            nextResultsUpdate += 2000;
            // Always update during Phase 1 — UI needs to show establishment progress
            String phase1Results = getBaselineResults();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = phase1Results.c_str();
            }
            baselineResultsDirty = false;
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BASELINE] Establishing... Devices:%d WiFi:%u BLE:%u Heap:%u\n",
                        baselineDeviceCount, framesSeen.load(), bleFramesSeen.load(), ESP.getFreeHeap());
            nextStatus += 5000;
        }

        if ((int32_t)(millis() - nextCacheSizeCheck) >= 0) {
            uint32_t newLimit = calculateOptimalCacheSize();
            std::vector<BaselineDevice> evictedDirty;
            {
                std::lock_guard<std::mutex> lock(baselineMutex);
                if (newLimit < baselineRamCacheSize && baselineCache.size() > newLimit) {
                    while (baselineCache.size() > newLimit && !lruList.empty()) {
                        const auto& oldest = lruList.front();
                        uint64_t oldestKey = oldest.key;
                        const auto& oldestDevice = baselineCache[oldestKey];
                        if (oldestDevice.dirtyFlag) {
                            evictedDirty.push_back(oldestDevice);
                        }
                        baselineCache.erase(oldestKey);
                        lruMap.erase(oldestKey);
                        lruList.pop_front();
                    }
                }
                baselineRamCacheSize = newLimit;
            }
            for (size_t ei = 0; ei < evictedDirty.size(); ei++) {
                writeBaselineDeviceToSD(evictedDirty[ei]);
                if ((ei & 15) == 15) {
                    vTaskDelay(pdMS_TO_TICKS(0));
                }
            }
            nextCacheSizeCheck += 30000;
        }

        if (stopRequested) {
            break;
        }
        
        baselineHarvestWifiAsync(lastWiFiScan);

        if (stopRequested) {
            break;
        }

        if (pBLEScan && (millis() - lastBLEScan >= rfConfig.bleScanInterval)) {
            lastBLEScan = millis();
            
            if (!pBLEScan->isScanning()) {
                pBLEScan->start(0, false);
                vTaskDelay(pdMS_TO_TICKS(100));
            }

            if (stopRequested) {
                break;
            }
            
            NimBLEScanResults scanResults = pBLEScan->getResults(0, true);
            
            for (int i = 0; i < scanResults.getCount() && !stopRequested; i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStr = device->getAddress().toString().c_str();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();
                if (rssi > -10) continue;

                uint8_t mac[6];
                if (parseMac6(macStr, mac)) {
                    Hit bh;
                    memcpy(bh.mac, mac, 6);
                    bh.rssi = rssi;
                    bh.ch = 0;
                    strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                    bh.name[sizeof(bh.name) - 1] = '\0';
                    bh.isBLE = true;
                    
                    if (macQueue) {
                        xQueueSend(macQueue, &bh, 0);
                    }
                    bleFramesSeen = bleFramesSeen + 1;
                }  else {
                    Serial.printf("[BASELINE] Failed to parse BLE MAC: %s\n", macStr.c_str());
                }
            }
            pBLEScan->clearResults();
        }
        
        while (xQueueReceive(macQueue, &h, 0) == pdTRUE && !stopRequested) {
            if (isAllowlisted(h.mac)) {
                continue;
            }
            updateBaselineDevice(h.mac, h.rssi, h.name, h.isBLE, h.ch);
        }

        if (millis() - lastCleanup >= BASELINE_CLEANUP_INTERVAL) {
            cleanupBaselineMemory();
            lastCleanup = millis();

            uint32_t dirtyCount;
            {
                std::lock_guard<std::mutex> lock(baselineMutex);
                dirtyCount = std::count_if(baselineCache.begin(), baselineCache.end(),
                    [](const std::pair<const uint64_t, BaselineDevice>& entry) { return entry.second.dirtyFlag; });
            }

            if ((millis() - lastSDFlush > MIN_FLUSH_INTERVAL && dirtyCount > 0) || dirtyCount >= MIN_DIRTY_COUNT) {
                flushBaselineCacheToSD();
                lastSDFlush = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (stopRequested) {
        {
            std::lock_guard<std::mutex> lock(baselineMutex);
            baselineStats.isScanning = false;
        }
        scanning = false;
        updateBaselineStats();

        radioStopListScan();
        vTaskDelay(pdMS_TO_TICKS(200));

        if (macQueue) {
            vQueueDeleteWithCaps(macQueue);
            macQueue = nullptr;
        }
        if (anomalyQueue) {
            vQueueDeleteWithCaps(anomalyQueue);
            anomalyQueue = nullptr;
        }

        sdLookupCache.clear();
        sdLookupLRU.clear();

        baselineDetectionEnabled = false;
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        baselineEstablished = true;
        baselineStats.phase1Complete = true;
    }
    updateBaselineStats();
    
    Serial.printf("[BASELINE] Baseline established with %d devices\n", baselineDeviceCount);
    Serial.printf("[BASELINE] Phase 2: Monitoring for anomalies (threshold: %d dBm)\n", baselineRssiThreshold);

    phaseStart = millis();
    nextStatus = millis() + 5000;
    nextStatsUpdate = millis() + 1000;
    nextResultsUpdate = millis() + 2000;
    lastCleanup = millis();
    lastWiFiScan = 0;
    lastBLEScan = 0;
    lastMeshUpdate = 0;

    Serial.printf("[BASELINE] Phase 2 starting at %u ms, target duration: %u ms\n",
                phaseStart, (forever ? UINT32_MAX : (uint32_t)duration * 1000));

    while ((forever && !stopRequested) ||
        (!forever && (int)(millis() - phaseStart) < duration * 1000 && !stopRequested)) {

        {
            std::lock_guard<std::mutex> lock(baselineMutex);
            baselineStats.elapsedTime = (millis() - phaseStart);
        }

        if ((int32_t)(millis() - nextStatsUpdate) >= 0) {
            updateBaselineStats();
            nextStatsUpdate += 1000;
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BASELINE] Monitoring... Baseline:%d Anomalies:%d Heap:%u\n",
                        baselineDeviceCount, anomalyCount, ESP.getFreeHeap());
            nextStatus += 5000;
        }

        if (stopRequested) {
            break;
        }

        baselineHarvestWifiAsync(lastWiFiScan);

        if (stopRequested) {
            break;
        }

        if (pBLEScan && (millis() - lastBLEScan >= rfConfig.bleScanInterval)) {
            lastBLEScan = millis();

            if (!pBLEScan->isScanning()) {
                pBLEScan->start(0, false);
                vTaskDelay(pdMS_TO_TICKS(100));
            }

            if (stopRequested) {
                break;
            }

            NimBLEScanResults scanResults = pBLEScan->getResults(0, true);

            for (int i = 0; i < scanResults.getCount() && !stopRequested; i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStr = device->getAddress().toString().c_str();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();
                if (rssi > -10) continue;

                uint8_t mac[6];
                if (parseMac6(macStr, mac)) {
                    Hit bh;
                    memcpy(bh.mac, mac, 6);
                    bh.rssi = rssi;
                    bh.ch = 0;
                    strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                    bh.name[sizeof(bh.name) - 1] = '\0';
                    bh.isBLE = true;

                    if (macQueue) {
                        xQueueSend(macQueue, &bh, 0);
                    }
                    bleFramesSeen = bleFramesSeen + 1;
                } else {
                    Serial.printf("[BASELINE] Failed to parse BLE MAC: %s\n", macStr.c_str());
                }
            }
            pBLEScan->clearResults();
        }

        while (xQueueReceive(macQueue, &h, 0) == pdTRUE && !stopRequested) {
            if (isAllowlisted(h.mac)) {
                continue;
            }

            if (baselineEstablished) {
                checkForAnomalies(h.mac, h.rssi, h.name, h.isBLE, h.ch);
            }

            updateBaselineDevice(h.mac, h.rssi, h.name, h.isBLE, h.ch);
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0 || baselineResultsDirty) {
            nextResultsUpdate = millis() + 2000;
            String resultStr = getBaselineResults();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = resultStr.c_str();
            }
            Serial.printf("[BASELINE] Results updated: %d bytes, anomalies=%d, dirty=%s\n",
                        resultStr.length(), anomalyCount, baselineResultsDirty ? "true" : "false");
            baselineResultsDirty = false;
        }

        if (meshEnabled && millis() - lastMeshUpdate >= MESH_DEVICE_UPDATE_INTERVAL) {
            lastMeshUpdate = millis();

            // Mesh TX during monitoring carries anomalies only (not the full baseline)
            std::vector<AnomalyHit> anomalySnapshot;
            {
                std::lock_guard<std::mutex> lock(baselineMutex);
                anomalySnapshot = anomalyLog;
            }

            for (const auto& anomaly : anomalySnapshot) {
                String macStr = macFmt6(anomaly.mac);

                if (transmittedAnomalies.find(macStr) == transmittedAnomalies.end()) {
                    String anomalyMsg = getNodeId() + ": ANOMALY: " + String(anomaly.isBLE ? "BLE " : "WiFi ") + macStr;
                    anomalyMsg += " RSSI:" + String(anomaly.rssi);
                    anomalyMsg += " " + anomaly.reason;

                    if (strlen(anomaly.name) > 0 && strcmp(anomaly.name, "Unknown") != 0) {
                        anomalyMsg += " N:" + String(anomaly.name).substring(0, 20);
                    }

                    if (anomalyMsg.length() <= MAX_MESH_SIZE) {
                        if (meshEnqueue(anomalyMsg)) {
                            transmittedAnomalies.insert(macStr);
                        }
                    }
                }
            }
        }

        if (millis() - lastCleanup >= BASELINE_CLEANUP_INTERVAL) {
            cleanupBaselineMemory();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    Serial.printf("[BASELINE] Phase 2 loop exited: forever=%s, stopRequested=%s, elapsed=%ums, duration=%d\n",
                forever ? "true" : "false", stopRequested.load() ? "true" : "false",
                (millis() - phaseStart), duration);

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        baselineStats.isScanning = false;
    }
    updateBaselineStats();

    {
        String finalResults = getBaselineResults();
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = finalResults.c_str();
    }
    
    uint32_t finalHeap = ESP.getFreeHeap();
    Serial.printf("[BASELINE] Memory status: Baseline=%d devices, Anomalies=%d, Free heap=%u bytes\n",
                 baselineDeviceCount, anomalyCount, finalHeap);
    
    radioStopListScan();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    if (sdBaselineInitialized) {
        flushBaselineCacheToSD();
        Serial.printf("[BASELINE] Final flush: %d total devices\n", baselineDeviceCount);
    }

    if (meshEnabled && !stopRequested) {
        uint32_t snapDeviceCount;
        uint32_t snapAnomalyCount;
        uint32_t snapWifiDevices;
        uint32_t snapBleDevices;
        {
            std::lock_guard<std::mutex> lock(baselineMutex);
            snapDeviceCount = baselineDeviceCount;
            snapAnomalyCount = anomalyCount;
            snapWifiDevices = baselineStats.wifiDevices;
            snapBleDevices = baselineStats.bleDevices;
        }

        uint32_t finalTransmitted = transmittedDevices.size();
        uint32_t finalRemaining = snapDeviceCount - finalTransmitted;

        String summary = getNodeId() + ": BASELINE_DONE: Devices=" + String(snapDeviceCount) +
                        " Anomalies=" + String(snapAnomalyCount) +
                        " WiFi=" + String(snapWifiDevices) +
                        " BLE=" + String(snapBleDevices) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        meshEnqueue(summary);
        Serial.println("[BASELINE] Detection complete summary enqueued");
    }

    if (macQueue) {
        vQueueDeleteWithCaps(macQueue);
        macQueue = nullptr;
    }
    if (anomalyQueue) {
        vQueueDeleteWithCaps(anomalyQueue);
        anomalyQueue = nullptr;
    }

    sdLookupCache.clear();
    sdLookupLRU.clear();

    scanning = false;
    baselineDetectionEnabled = false;
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void cleanupBaselineMemory() {
    uint32_t now = millis();
    
    // Mark disappeared devices
    for (auto& entry : deviceHistory) {
        DeviceHistory &hist = entry.second;
        
        if (hist.wasPresent && (now - hist.lastSeen > deviceAbsenceThreshold)) {
            if (hist.disappearedAt == 0) {
                hist.disappearedAt = now;
                Serial.printf("[BASELINE] Device disappeared: %s (absent %us)\n", 
                            entry.first.c_str(), (now - hist.lastSeen) / 1000);
            }
        }
    }
    
    // Clean old disappeared devices (beyond reappearance window)
    if (deviceHistory.size() > 500) {
        std::vector<String> toRemove;
        for (const auto& entry : deviceHistory) {
            if (entry.second.disappearedAt > 0 && 
                (now - entry.second.disappearedAt > reappearanceAlertWindow)) {
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            deviceHistory.erase(key);
        }
        if (deviceHistory.size() > 1000) {
            std::vector<std::pair<uint32_t, String>> ages;
            ages.reserve(deviceHistory.size());
            std::transform(deviceHistory.begin(), deviceHistory.end(), std::back_inserter(ages),
                [](const auto& entry) { return std::make_pair(entry.second.lastSeen, entry.first); });
            std::sort(ages.begin(), ages.end());
            size_t toCut = deviceHistory.size() - 1000;
            for (size_t i = 0; i < toCut; ++i) deviceHistory.erase(ages[i].second);
        }
    }

    size_t cacheSizeSnapshot;
    size_t anomalySizeSnapshot;
    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        if (baselineEstablished) {
            std::vector<uint64_t> toRemove;
            for (const auto& entry : baselineCache) {
                if (now - entry.second.lastSeen > BASELINE_DEVICE_TIMEOUT) {
                    toRemove.push_back(entry.first);
                }
            }

            for (const auto& key : toRemove) {
                auto lruIt = lruMap.find(key);
                if (lruIt != lruMap.end()) {
                    lruList.erase(lruIt->second);
                    lruMap.erase(lruIt);
                }
                baselineCache.erase(key);
            }

            if (!toRemove.empty()) {
                Serial.printf("[BASELINE] Removed %d stale devices from cache\n", toRemove.size());
            }
        }

        if (anomalyLog.size() > BASELINE_MAX_ANOMALIES) {
            size_t toErase = anomalyLog.size() - BASELINE_MAX_ANOMALIES;
            anomalyLog.erase(anomalyLog.begin(), anomalyLog.begin() + toErase);
        }

        cacheSizeSnapshot = baselineCache.size();
        anomalySizeSnapshot = anomalyLog.size();
    }

    Serial.printf("[BASELINE] Cache: %d devices, History: %d tracked, Anomalies: %d, Heap: %u\n",
                 cacheSizeSnapshot, deviceHistory.size(), anomalySizeSnapshot, ESP.getFreeHeap());
}

// Baseline SD 
uint8_t calculateDeviceChecksum(BaselineDevice& device) {
    device.checksum = 0;
    uint8_t sum = 0;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&device);
    for (size_t i = 0; i < sizeof(BaselineDevice) - 1; i++) {
        sum ^= ptr[i];
    }
    device.checksum = sum;
    return sum;
}

bool initializeBaselineSD() {
     if (!SafeSD::isAvailable()) {
        Serial.println("[BASELINE_SD] SD card not available");
        return false;
    }
    
    if (!SafeSD::exists("/baseline_data.bin")) {
        Serial.println("[BASELINE_SD] Creating baseline data file");
        File dataFile = SafeSD::open("/baseline_data.bin", FILE_WRITE);
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to create data file");
            return false;
        }
        
        uint32_t magic = 0xBA5EBA11;
        uint16_t version = 1;
        uint32_t deviceCount = 0;
        
        dataFile.write(reinterpret_cast<uint8_t*>(&magic), sizeof(magic));
        dataFile.write(reinterpret_cast<uint8_t*>(&version), sizeof(version));
        dataFile.write(reinterpret_cast<uint8_t*>(&deviceCount), sizeof(deviceCount));
        dataFile.close();
        
        Serial.println("[BASELINE_SD] Data file created");
    } else {
        buildSDIndex();
    }
    
    if (!SafeSD::exists("/baseline_stats.json")) {
        Serial.println("[BASELINE_SD] Creating stats file");
         File statsFile = SafeSD::open("/baseline_stats.json", FILE_WRITE);
        if (!statsFile) {
            Serial.println("[BASELINE_SD] Failed to create stats file");
            return false;
        }
        
        statsFile.print("{\"totalDevices\":0,\"wifiDevices\":0,\"bleDevices\":0,\"established\":false,\"rssiThreshold\":");
        statsFile.print(baselineRssiThreshold);
        statsFile.print(",\"createdAt\":");
        statsFile.print(millis());
        statsFile.println("}");
        statsFile.close();
    }
    
    sdBaselineInitialized = true;
    Serial.println("[BASELINE_SD] Initialized");
    return true;
}

bool writeBaselineDeviceToSD(const BaselineDevice& device) {
    if (!SafeSD::isAvailable() || !sdBaselineInitialized) {
        return false;
    }
    
    BaselineDevice writeDevice = device;
    calculateDeviceChecksum(writeDevice);

    const uint64_t macKey = blKey(device.mac);

    if (sdDeviceIndex.find(macKey) != sdDeviceIndex.end()) {
        const uint32_t position = sdDeviceIndex[macKey];

        File dataFile = SafeSD::open("/baseline_data.bin", "r+");
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to open for update");
            return false;
        }
        
        dataFile.seek(position);
        size_t written = dataFile.write(reinterpret_cast<uint8_t*>(&writeDevice), sizeof(BaselineDevice));
        dataFile.close();

        return (written == sizeof(BaselineDevice));
    } else {
        File dataFile = SafeSD::open("/baseline_data.bin", FILE_APPEND);
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to open for append");
            return false;
        }

        uint32_t position = dataFile.position();
        size_t written = dataFile.write(reinterpret_cast<uint8_t*>(&writeDevice), sizeof(BaselineDevice));
        dataFile.close();
        
        if (written == sizeof(BaselineDevice)) {
            sdDeviceIndex[macKey] = position;
            totalDevicesOnSD++;
            
            File headerFile = SafeSD::open("/baseline_data.bin", "r+");
            if (headerFile) {
                headerFile.seek(6);
                headerFile.write(reinterpret_cast<uint8_t*>(&totalDevicesOnSD), sizeof(totalDevicesOnSD));
                headerFile.close();
            }
            
            return true;
        }
    }
    
    return false;
}

bool readBaselineDeviceFromSD(const uint8_t* mac, BaselineDevice& device) {
    if (!SafeSD::isAvailable() || !sdBaselineInitialized) {
        return false;
    }
    
    const uint64_t macKey = blKey(mac);

    if (sdDeviceIndex.find(macKey) == sdDeviceIndex.end()) {
        return false;
    }

    const uint32_t position = sdDeviceIndex[macKey];

    File dataFile = SafeSD::open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        return false;
    }

    dataFile.seek(position);
    const size_t bytesRead = SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&device), sizeof(BaselineDevice));
    dataFile.close();
    
    if (bytesRead != sizeof(BaselineDevice)) {
        return false;
    }
    
    const uint8_t storedChecksum = device.checksum;
    const uint8_t calcChecksum = calculateDeviceChecksum(device);
    
    if (calcChecksum != storedChecksum) {
        Serial.println("[BASELINE_SD] Checksum fail");
        return false;
    }
    
    return true;
}

bool flushBaselineCacheToSD() {
    if (!SafeSD::isAvailable() || !sdBaselineInitialized) {
        return false;
    }

    // Separate dirty entries into updates (existing on SD) and appends (new)
    std::vector<std::pair<uint64_t, BaselineDevice>> updates;
    std::vector<std::pair<uint64_t, BaselineDevice>> appends;

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        if (baselineCache.empty()) {
            return false;
        }
        for (auto& entry : baselineCache) {
            if (entry.second.dirtyFlag) {
                if (sdDeviceIndex.find(entry.first) != sdDeviceIndex.end()) {
                    updates.push_back({entry.first, entry.second});
                } else {
                    appends.push_back({entry.first, entry.second});
                }
            }
        }
    }

    const uint32_t total = updates.size() + appends.size();
    if (total == 0) {
        return true;
    }

    Serial.printf("[BASELINE_SD] Flushing %d modified devices (%d updates, %d new)\n",
                  total, updates.size(), appends.size());

    uint32_t flushed = 0;
    std::vector<uint64_t> cleanedKeys;
    cleanedKeys.reserve(total);

    // Batch updates: single file open in r+ mode, seek to each position
    if (!updates.empty()) {
        File dataFile = SafeSD::open("/baseline_data.bin", "r+");
        if (dataFile) {
            for (size_t i = 0; i < updates.size(); i++) {
                BaselineDevice wd = updates[i].second;
                calculateDeviceChecksum(wd);
                dataFile.seek(sdDeviceIndex[updates[i].first]);
                if (dataFile.write(reinterpret_cast<uint8_t*>(&wd), sizeof(BaselineDevice)) == sizeof(BaselineDevice)) {
                    cleanedKeys.push_back(updates[i].first);
                    flushed++;
                }
                if ((i & 15) == 15) {
                    vTaskDelay(pdMS_TO_TICKS(0));
                }
            }
            dataFile.close();
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    // Batch appends: single file open in append mode
    if (!appends.empty()) {
        File dataFile = SafeSD::open("/baseline_data.bin", FILE_APPEND);
        if (dataFile) {
            for (size_t i = 0; i < appends.size(); i++) {
                BaselineDevice wd = appends[i].second;
                calculateDeviceChecksum(wd);
                uint32_t position = dataFile.position();
                if (dataFile.write(reinterpret_cast<uint8_t*>(&wd), sizeof(BaselineDevice)) == sizeof(BaselineDevice)) {
                    sdDeviceIndex[appends[i].first] = position;
                    totalDevicesOnSD++;
                    cleanedKeys.push_back(appends[i].first);
                    flushed++;
                }
                if ((i & 15) == 15) {
                    vTaskDelay(pdMS_TO_TICKS(0));
                }
            }
            dataFile.close();

            // Update header device count once
            File headerFile = SafeSD::open("/baseline_data.bin", "r+");
            if (headerFile) {
                headerFile.seek(6);
                headerFile.write(reinterpret_cast<uint8_t*>(&totalDevicesOnSD), sizeof(totalDevicesOnSD));
                headerFile.close();
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    if (!cleanedKeys.empty()) {
        std::lock_guard<std::mutex> lock(baselineMutex);
        for (const auto& key : cleanedKeys) {
            auto it = baselineCache.find(key);
            if (it != baselineCache.end()) {
                it->second.dirtyFlag = false;
            }
        }
    }

    Serial.printf("[BASELINE_SD] Flushed %d devices. Total unique on SD: %d\n", flushed, totalDevicesOnSD);
    saveBaselineStatsToSD();

    return true;
}

void loadBaselineFromSD() {
    if (!SafeSD::isAvailable() || !sdBaselineInitialized) {
        return;
    }
    
    File dataFile = SafeSD::open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        Serial.println("[BASELINE_SD] No baseline file");
        return;
    }
    
    uint32_t magic;
    uint16_t version;
    uint32_t deviceCount;

    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&magic), sizeof(magic));
    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&version), sizeof(version));
    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&deviceCount), sizeof(deviceCount));
    (void)version; // read to advance file position; value unused

    if (magic != 0xBA5EBA11) {
        Serial.println("[BASELINE_SD] Invalid header");
        dataFile.close();
        return;
    }

    Serial.printf("[BASELINE_SD] Loading %d devices\n", deviceCount);

    totalDevicesOnSD = deviceCount;
    baselineDeviceCount = deviceCount;
    
    if (deviceCount > 0) {
        uint32_t toLoad = min(deviceCount, baselineRamCacheSize);
        uint32_t skipRecords = (deviceCount > toLoad) ? (deviceCount - toLoad) : 0;
        
        dataFile.seek(10 + (skipRecords * sizeof(BaselineDevice)));
        
        BaselineDevice rec;
        uint32_t loaded = 0;
        
        while (dataFile.available() >= sizeof(BaselineDevice) && loaded < toLoad) {
            size_t bytesRead = SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&rec), sizeof(BaselineDevice));

            if (bytesRead != sizeof(BaselineDevice)) {
                break;
            }

            const uint8_t storedChecksum = rec.checksum;
            const uint8_t calcChecksum = calculateDeviceChecksum(rec);

            if (calcChecksum != storedChecksum) {
                continue;
            }

            rec.dirtyFlag = false;
            uint64_t recKey = blKey(rec.mac);
            baselineCache[recKey] = rec;
            LRUNode node;
            node.key = recKey;
            node.lastSeen = rec.lastSeen;
            lruList.push_back(node);
            lruMap[recKey] = --lruList.end();
            loaded++;
        }
        
        Serial.printf("[BASELINE_SD] Loaded %d devices into cache\n", loaded);
    }
    
    dataFile.close();
    buildSDIndex();
    loadBaselineStatsFromSD();
}

void saveBaselineStatsToSD() {
     if (!SafeSD::isAvailable()) {
        return;
    }

    uint32_t snapDeviceCount;
    uint32_t snapWifiDevices;
    uint32_t snapBleDevices;
    bool snapEstablished;
    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        snapDeviceCount = baselineDeviceCount;
        snapWifiDevices = baselineStats.wifiDevices;
        snapBleDevices = baselineStats.bleDevices;
        snapEstablished = baselineEstablished;
    }

    File statsFile = SafeSD::open("/baseline_stats.json", FILE_WRITE);
    if (!statsFile) {
        return;
    }

    statsFile.print("{\"totalDevices\":");
    statsFile.print(snapDeviceCount);
    statsFile.print(",\"wifiDevices\":");
    statsFile.print(snapWifiDevices);
    statsFile.print(",\"bleDevices\":");
    statsFile.print(snapBleDevices);
    statsFile.print(",\"established\":");
    statsFile.print(snapEstablished ? "true" : "false");
    statsFile.print(",\"rssiThreshold\":");
    statsFile.print(baselineRssiThreshold);
    statsFile.print(",\"lastUpdate\":");
    statsFile.print(millis());
    statsFile.println("}");

    statsFile.close();
}

void loadBaselineStatsFromSD() {
    if (!SafeSD::isAvailable()) {
        return;
    }
    
    File statsFile = SafeSD::open("/baseline_stats.json", FILE_READ);
    if (!statsFile) {
        return;
    }
    
    const String json = statsFile.readString();
    statsFile.close();
    
    DynamicJsonDocument doc(512);
    const DeserializationError error = deserializeJson(doc, json);
    
    if (!error) {
        baselineDeviceCount = doc["totalDevices"].as<int>();
        baselineStats.wifiDevices = doc["wifiDevices"].as<int>();
        baselineStats.bleDevices = doc["bleDevices"].as<int>();
        baselineEstablished = doc["established"].as<bool>();
        baselineRssiThreshold = doc["rssiThreshold"] | -60;
        
        Serial.printf("[BASELINE_SD] Stats loaded: total=%d\n", baselineDeviceCount);
    }
}

uint32_t getBaselineRamCacheSize() {
    return baselineRamCacheSize;
}

void setBaselineRamCacheSize(uint32_t size) {
    if (size >= 200 && size <= 500) {
        baselineRamCacheSize = size;
        prefs.putUInt("baselineRamSize", size);
        Serial.printf("[BASELINE] RAM cache size set to %u\n", size);
    }
}

uint32_t getBaselineSdMaxDevices() {
    return baselineSdMaxDevices;
}

void setBaselineSdMaxDevices(uint32_t size) {
    if (size >= 1000 && size <= 100000) {
        baselineSdMaxDevices = size;
        prefs.putUInt("baselineSdMax", size);
        Serial.printf("[BASELINE] SD max devices set to %u\n", size);
    }
}

uint32_t getDeviceAbsenceThreshold() {
    return deviceAbsenceThreshold;
}

void setDeviceAbsenceThreshold(uint32_t ms) {
    if (ms >= 30000 && ms <= 600000) {  // 30s - 10min
        deviceAbsenceThreshold = ms;
        prefs.putUInt("absenceThresh", ms);
        Serial.printf("[BASELINE] Absence threshold set to %u ms\n", ms);
    }
}

uint32_t getReappearanceAlertWindow() {
    return reappearanceAlertWindow;
}

void setReappearanceAlertWindow(uint32_t ms) {
    if (ms >= 60000 && ms <= 1800000) {  // 1min - 30min
        reappearanceAlertWindow = ms;
        prefs.putUInt("reappearWin", ms);
        Serial.printf("[BASELINE] Reappearance window set to %u ms\n", ms);
    }
}

int8_t getSignificantRssiChange() {
    return significantRssiChange;
}

void setSignificantRssiChange(int8_t dBm) {
    if (dBm >= 5 && dBm <= 50) {
        significantRssiChange = dBm;
        prefs.putInt("rssiChange", dBm);
        Serial.printf("[BASELINE] RSSI change threshold set to %d dBm\n", dBm);
    }
}

// RAM SD Caching 

void addToSDCache(uint64_t mac, bool found) {
    if (sdLookupCache.size() >= SD_LOOKUP_CACHE_SIZE) {
        if (!sdLookupLRU.empty()) {
            uint64_t oldest = sdLookupLRU.front();
            sdLookupLRU.pop_front();
            sdLookupCache.erase(oldest);
        }
    }

    sdLookupCache[mac] = found;
    sdLookupLRU.push_back(mac);
}

bool checkSDCache(uint64_t mac, bool& found) {
    auto it = sdLookupCache.find(mac);
    if (it != sdLookupCache.end()) {
        found = it->second;
        
        sdLookupLRU.remove(mac);
        sdLookupLRU.push_back(mac);
        
        return true;
    }
    return false;
}

bool isDeviceInBaseline(const uint8_t *mac) {
    uint64_t macKey = blKey(mac);

    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        if (baselineCache.find(macKey) != baselineCache.end()) {
            return true;
        }
    }

    bool found;
    if (checkSDCache(macKey, found)) {
        return found;
    }

    BaselineDevice dev;
    bool inSD = readBaselineDeviceFromSD(mac, dev);
    addToSDCache(macKey, inSD);

    return inSD;
}

void checkForAnomalies(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel) {
    if (rssi < baselineRssiThreshold) {
        return;
    }
    // Discard implausible RSSI values (BLE/WiFi glitches)
    // -10 dBm is stronger than physically possible at any realistic distance
    if (rssi > -10) {
        return;
    }
    
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    
    if (deviceHistory.find(macStr) == deviceHistory.end()) {
        bool inBaseline = isDeviceInBaseline(mac);
        deviceHistory[macStr] = {rssi, now, 0, inBaseline, 0, now, 0};
    }
    
    DeviceHistory &history = deviceHistory[macStr];
    
    if (!history.wasPresent) {
        if (now - history.firstSeenAt > 60000) {
            history.firstSeenAt = now;
            history.sightings = 1;
        } else {
            history.sightings++;
        }
        history.lastRssi = rssi;
        history.lastSeen = now;
        if (history.sightings < 2) {
            return;
        }
        history.wasPresent = true;

        AnomalyHit hit;
        memcpy(hit.mac, mac, 6);
        hit.rssi = rssi;
        hit.channel = channel;
        strncpy(hit.name, name, sizeof(hit.name) - 1);
        hit.name[sizeof(hit.name) - 1] = '\0';
        hit.isBLE = isBLE;
        hit.timestamp = now;
        hit.reason = "New device (not in baseline)";

        if (anomalyQueue) xQueueSend(anomalyQueue, &hit, 0);
        {
            std::lock_guard<std::mutex> lock(baselineMutex);
            if (anomalyLog.size() >= BASELINE_MAX_ANOMALIES) anomalyLog.erase(anomalyLog.begin());
            anomalyLog.push_back(hit);
            anomalyCount++;
        }
        baselineResultsDirty = true;

        String alert = "[ANOMALY] NEW: " + macStr;
        alert += " RSSI:" + String(rssi) + "dBm";
        alert += " Type:" + String(isBLE ? "BLE" : "WiFi");
        if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
            alert += " Name:" + String(name);
        }
        if (gpsValid) {
            if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                alert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                xSemaphoreGive(gpsMutex);
            }
        }

        Serial.println(alert);
        logToSD(alert);

        if (meshEnabled && isMyMeshSlot() && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
            lastBaselineAnomalyMeshSend = millis();
            String meshAlert = getNodeId() + ": ANOMALY-NEW: " + String(isBLE ? "BLE " : "WiFi ") + macStr;
            meshAlert += " RSSI:" + String(rssi);
            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                meshAlert += " Name:" + String(name);
            }
            meshEnqueue(meshAlert);
        }

        return;
    }

    if (history.disappearedAt > 0) {
        uint32_t absentTime = now - history.disappearedAt;
        if (absentTime <= reappearanceAlertWindow) {
            AnomalyHit hit;
            memcpy(hit.mac, mac, 6);
            hit.rssi = rssi;
            hit.channel = channel;
            strncpy(hit.name, name, sizeof(hit.name) - 1);
            hit.name[sizeof(hit.name) - 1] = '\0';
            hit.isBLE = isBLE;
            hit.timestamp = now;
            hit.reason = "Device returned after " + String(absentTime / 1000) + "s absence";

            if (anomalyQueue) xQueueSend(anomalyQueue, &hit, 0);
            {
                std::lock_guard<std::mutex> lock(baselineMutex);
                anomalyLog.push_back(hit);
                anomalyCount++;
            }
            baselineResultsDirty = true;

            String alert = "[ANOMALY] RETURNED: " + macStr;
            alert += " was absent " + String(absentTime / 1000) + "s";
            alert += " RSSI:" + String(rssi) + "dBm";
            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                alert += " Name:" + String(name);
            }

            Serial.println(alert);
            logToSD(alert);

            if (meshEnabled && isMyMeshSlot() && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
                lastBaselineAnomalyMeshSend = millis();
                String meshAlert = getNodeId() + ": ANOMALY-RETURN: " + String(isBLE ? "BLE " : "WiFi ") + macStr;
                meshAlert += " RSSI:" + String(rssi) + "dBm";
                if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                    meshAlert += " Name:" + String(name);
                }
                sendToSerial1(meshAlert, false);
            }
        }

        history.disappearedAt = 0;
    }

    if (abs(rssi - history.lastRssi) >= significantRssiChange) {
        history.significantChanges++;

        if (history.significantChanges >= 3) {
            AnomalyHit hit;
            memcpy(hit.mac, mac, 6);
            hit.rssi = rssi;
            hit.channel = channel;
            strncpy(hit.name, name, sizeof(hit.name) - 1);
            hit.name[sizeof(hit.name) - 1] = '\0';
            hit.isBLE = isBLE;
            hit.timestamp = now;
            hit.reason = "Significant RSSI change: " + String(history.lastRssi) + " -> " + String(rssi) + " dBm";

            if (anomalyQueue) xQueueSend(anomalyQueue, &hit, 0);
            {
                std::lock_guard<std::mutex> lock(baselineMutex);
                anomalyLog.push_back(hit);
                anomalyCount++;
            }
            baselineResultsDirty = true;

            String alert = "[ANOMALY] RSSI-CHANGE: " + macStr;
            alert += " " + String(history.lastRssi) + "dBm -> " + String(rssi) + "dBm";

            Serial.println(alert);
            logToSD(alert);

            if (meshEnabled && isMyMeshSlot() && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
                lastBaselineAnomalyMeshSend = millis();
                int delta = abs(rssi - history.lastRssi);
                String meshAlert = getNodeId() + ": ANOMALY-RSSI: " + String(isBLE ? "BLE " : "WiFi ") + macStr;
                meshAlert += " Old:" + String(history.lastRssi) + "dBm";
                meshAlert += " New:" + String(rssi) + "dBm";
                meshAlert += " Delta:" + String(delta) + "dBm";
                sendToSerial1(meshAlert, false);
            }
            
            history.significantChanges = 0;
        }
    }
    
    history.lastRssi = rssi;
    history.lastSeen = now;
    history.wasPresent = true;
}

void buildSDIndex() {
    sdDeviceIndex.clear();
    
    File dataFile = SafeSD::open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        return;
    }
    
    uint32_t magic, deviceCount;
    uint16_t version;

    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&magic), sizeof(magic));
    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&version), sizeof(version));
    SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&deviceCount), sizeof(deviceCount));
    (void)version; // read to advance file position; value unused
    (void)deviceCount; // used only to validate header was read completely

    if (magic != 0xBA5EBA11) {
        dataFile.close();
        return;
    }

    BaselineDevice rec;
    uint32_t position = 10;

    while (dataFile.available() >= sizeof(BaselineDevice)) {
        size_t bytesRead = SafeSD::read(dataFile, reinterpret_cast<uint8_t*>(&rec), sizeof(BaselineDevice));
        
        if (bytesRead != sizeof(BaselineDevice)) {
            break;
        }
        
        const uint8_t storedChecksum = rec.checksum;
        const uint8_t calcChecksum = calculateDeviceChecksum(rec);

        if (calcChecksum == storedChecksum) {
            sdDeviceIndex[blKey(rec.mac)] = position;
        }
        
        position += sizeof(BaselineDevice);
    }
    
    dataFile.close();
    totalDevicesOnSD = sdDeviceIndex.size();
    Serial.printf("[BASELINE_SD] Index built: %d unique devices\n", totalDevicesOnSD);
}