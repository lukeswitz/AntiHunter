#include "baseline.h"
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"
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
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern volatile bool scanning;
extern volatile uint32_t framesSeen;
extern volatile uint32_t bleFramesSeen;
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
extern void radioStopSTA();
extern bool isAllowlisted(const uint8_t *mac);

// Scan intervals from scanner
extern uint32_t WIFI_SCAN_INTERVAL;
extern uint32_t BLE_SCAN_INTERVAL;

// Baseline detection state variables
BaselineStats baselineStats;
bool baselineDetectionEnabled = false;
bool baselineEstablished = false;
uint32_t baselineStartTime = 0;
uint32_t baselineDuration = 300000;
std::map<String, BaselineDevice> baselineCache;
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
    baselineCache.clear();
    anomalyLog.clear();
    anomalyCount = 0;
    baselineDeviceCount = 0;
    baselineEstablished = false;
    totalDevicesOnSD = 0;
    
    baselineStats.wifiDevices = 0;
    baselineStats.bleDevices = 0;
    baselineStats.totalDevices = 0;
    baselineStats.wifiHits = 0;
    baselineStats.bleHits = 0;
    
    // Clear SD storage
    if (sdAvailable) {
        if (SD.exists("/baseline_data.bin")) {
            SD.remove("/baseline_data.bin");
            Serial.println("[BASELINE] Removed SD data file");
        }
        if (SD.exists("/baseline_stats.json")) {
            SD.remove("/baseline_stats.json");
            Serial.println("[BASELINE] Removed SD stats file");
        }
    }
    
    sdBaselineInitialized = false;
    initializeBaselineSD();
    
    Serial.println("[BASELINE] Reset complete");
}

bool isDeviceInBaseline(const uint8_t *mac) {
    String macStr = macFmt6(mac);
    
    // Check RAM cache quicjk
    if (baselineCache.find(macStr) != baselineCache.end()) {
        return true;
    }
    
    // Check SD (slower)
    BaselineDevice dev;
    return readBaselineDeviceFromSD(mac, dev);
}

void updateBaselineDevice(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel) {
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    
    // Check RAM cache first
    if (baselineCache.find(macStr) == baselineCache.end()) {
        // Not in cache - make room if needed
        if (baselineCache.size() >= baselineRamCacheSize) {
            // Evict oldest from cache to SD
            String oldestKey;
            uint32_t oldestTime = UINT32_MAX;
            
            for (const auto& entry : baselineCache) {
                if (entry.second.lastSeen < oldestTime) {
                    oldestTime = entry.second.lastSeen;
                    oldestKey = entry.first;
                }
            }
            
            if (oldestKey.length() > 0) {
                writeBaselineDeviceToSD(baselineCache[oldestKey]);
                baselineCache.erase(oldestKey);
            }
        }
        
        // Create new device in cache
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
        
        baselineCache[macStr] = dev;
        baselineDeviceCount++;
    } else {
        // Update existing device in cache
        BaselineDevice &dev = baselineCache[macStr];
        dev.avgRssi = (dev.avgRssi * dev.hitCount + rssi) / (dev.hitCount + 1);
        if (rssi < dev.minRssi) dev.minRssi = rssi;
        if (rssi > dev.maxRssi) dev.maxRssi = rssi;
        dev.lastSeen = now;
        dev.hitCount++;
        
        if (strlen(name) > 0 && strcmp(name, "Unknown") != 0 && strcmp(name, "WiFi") != 0) {
            strncpy(dev.name, name, sizeof(dev.name) - 1);
            dev.name[sizeof(dev.name) - 1] = '\0';
        }
    }
    
    // Periodic flush to SD
    if (millis() - lastSDFlush >= BASELINE_SD_FLUSH_INTERVAL) {
        flushBaselineCacheToSD();
        lastSDFlush = millis();
    }
}

void checkForAnomalies(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel) {
    if (rssi < baselineRssiThreshold) {
        return;
    }
    
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    bool isInBaseline = (baselineCache.find(macStr) != baselineCache.end());
    
    // Initialize devices history
    if (deviceHistory.find(macStr) == deviceHistory.end()) {
        // Check RAM/SD for it
        bool inFullBaseline = isDeviceInBaseline(mac);
        deviceHistory[macStr] = {rssi, now, 0, inFullBaseline, 0};
    }
    
    DeviceHistory &history = deviceHistory[macStr];
    
    // Check for new device (not in baseline)
    if (!isInBaseline) {
        // Only alert once per device
        if (!history.wasPresent) {
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
            anomalyLog.push_back(hit);
            anomalyCount++;
            
            String alert = "[ANOMALY] NEW: " + macStr;
            alert += " RSSI:" + String(rssi) + "dBm";
            alert += " Type:" + String(isBLE ? "BLE" : "WiFi");
            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                alert += " Name:" + String(name);
            }
            if (gpsValid) {
                alert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }
            
            Serial.println(alert);
            logToSD(alert);

            if (meshEnabled && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
                lastBaselineAnomalyMeshSend = millis();
                String meshAlert = getNodeId() + ": ANOMALY-NEW: " + String(isBLE ? "BLE" : "WiFi") + 
                                " " + macStr + " RSSI:" + String(rssi) + "dBm";
                sendToSerial1(String(meshAlert), false);
            }
            
            history.wasPresent = true;
        }
    } else {
        // Device is in baseline - check for suspicious patterns
        
        // Check for reappearance after absence
        if (history.disappearedAt > 0 && (now - history.disappearedAt < reappearanceAlertWindow)) {
            uint32_t absenceDuration = history.disappearedAt - history.lastSeen;
            
            AnomalyHit hit;
            memcpy(hit.mac, mac, 6);
            hit.rssi = rssi;
            hit.channel = channel;
            strncpy(hit.name, name, sizeof(hit.name) - 1);
            hit.name[sizeof(hit.name) - 1] = '\0';
            hit.isBLE = isBLE;
            hit.timestamp = now;
            hit.reason = "Reappeared after " + String(absenceDuration / 1000) + "s absence";
            
            if (anomalyQueue) xQueueSend(anomalyQueue, &hit, 0);
            anomalyLog.push_back(hit);
            anomalyCount++;
            
            String alert = "[ANOMALY] REAPPEAR: " + macStr;
            alert += " RSSI:" + String(rssi) + "dBm";
            alert += " Absent:" + String(absenceDuration / 1000) + "s";
            
            Serial.println(alert);
            logToSD(alert);
            
            if (meshEnabled && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
                lastBaselineAnomalyMeshSend = millis();
                String meshAlert = getNodeId() + ": ANOMALY-REAPPEAR: " + macStr + 
                                " Absent:" + String(absenceDuration / 1000) + "s";
                sendToSerial1(String(meshAlert), false);
            }

            history.disappearedAt = 0;  // Reset
        }
        
        // Check for significant RSSI change
        int8_t rssiDelta = abs(rssi - history.lastRssi);
        if (rssiDelta >= significantRssiChange) {
            history.significantChanges++;
            
            // Only alert on first few changes to avoid spam
            if (history.significantChanges <= 3) {
                AnomalyHit hit;
                memcpy(hit.mac, mac, 6);
                hit.rssi = rssi;
                hit.channel = channel;
                strncpy(hit.name, name, sizeof(hit.name) - 1);
                hit.name[sizeof(hit.name) - 1] = '\0';
                hit.isBLE = isBLE;
                hit.timestamp = now;
                
                if (rssi > history.lastRssi) {
                    hit.reason = "Signal stronger +" + String(rssiDelta) + "dBm";
                } else {
                    hit.reason = "Signal weaker -" + String(rssiDelta) + "dBm";
                }
                
                if (anomalyQueue) xQueueSend(anomalyQueue, &hit, 0);
                anomalyLog.push_back(hit);
                anomalyCount++;
                
                String alert = "[ANOMALY] RSSI: " + macStr;
                alert += " " + String(history.lastRssi) + "→" + String(rssi) + "dBm";
                alert += " (" + String(rssi > history.lastRssi ? "+" : "") + String(rssiDelta) + ")";
                
                Serial.println(alert);
                logToSD(alert);
            }
        }
    }
    
    // Update history
    history.lastRssi = rssi;
    history.lastSeen = now;
}

String getBaselineResults() {
    String results;
    
    if (baselineEstablished) {
        results += "=== BASELINE ESTABLISHED ===\n";
        results += "Total devices in baseline: " + String(baselineDeviceCount) + "\n";
        results += "WiFi devices: " + String(baselineStats.wifiDevices) + "\n";
        results += "BLE devices: " + String(baselineStats.bleDevices) + "\n";
        results += "RSSI threshold: " + String(baselineRssiThreshold) + " dBm\n\n";
        
        results += "=== BASELINE DEVICES (Cached in RAM) ===\n";
        for (const auto &entry : baselineCache) {
            const BaselineDevice &dev = entry.second;
            results += String(dev.isBLE ? "BLE  " : "WiFi ") + macFmt6(dev.mac);
            results += " Avg:" + String(dev.avgRssi) + "dBm";
            results += " Min:" + String(dev.minRssi) + "dBm";
            results += " Max:" + String(dev.maxRssi) + "dBm";
            results += " Hits:" + String(dev.hitCount);
            if (!dev.isBLE && dev.channel > 0) {
                results += " CH:" + String(dev.channel);
            }
            if (strlen(dev.name) > 0 && strcmp(dev.name, "Unknown") != 0 && strcmp(dev.name, "WiFi") != 0) {
                results += " \"" + String(dev.name) + "\"";
            }
            results += "\n";
        }
        
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
        results += "Baseline not yet established\n";
        results += "Devices detected so far: " + String(baselineDeviceCount) + "\n";
    }
    
    return results;
}

void updateBaselineStats() {
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


void baselineDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

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
    baselineEstablished = false;
    baselineStartTime = millis();
    currentScanMode = SCAN_BOTH;
    
    if (anomalyQueue) vQueueDelete(anomalyQueue);
    anomalyQueue = xQueueCreate(256, sizeof(AnomalyHit));
    
    if (macQueue) vQueueDelete(macQueue);
    macQueue = xQueueCreate(512, sizeof(Hit));
    
    framesSeen = 0;
    bleFramesSeen = 0;
    scanning = true;
    
    baselineStats = BaselineStats();
    baselineStats.isScanning = true;
    baselineStats.phase1Complete = false;
    baselineStats.totalDuration = baselineDuration;
    
    radioStartSTA();
    vTaskDelay(pdMS_TO_TICKS(200)); 

    if (!pBLEScan) {
        BLEDevice::init("");
        pBLEScan = BLEDevice::getScan();
    }
    
    if (pBLEScan && !pBLEScan->isScanning()) {
        pBLEScan->setActiveScan(true);
        pBLEScan->setInterval(rfConfig.bleScanInterval / 10);
        pBLEScan->setWindow((rfConfig.bleScanInterval / 10) - 10);
        pBLEScan->setDuplicateFilter(false);
        pBLEScan->start(0, false);
    }

    uint32_t phaseStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t nextStatsUpdate = millis() + 1000;
    uint32_t lastCleanup = millis();
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    
    Hit h;
    
    Serial.printf("[BASELINE] Phase 1 starting at %u ms, will run until %u ms\n", 
                  phaseStart, phaseStart + baselineDuration);
    
    while (millis() - phaseStart < baselineDuration && !stopRequested) {
        baselineStats.elapsedTime = millis() - phaseStart;
        
        if ((int32_t)(millis() - nextStatsUpdate) >= 0) {
            updateBaselineStats();
            nextStatsUpdate += 1000;
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BASELINE] Establishing... Devices:%d WiFi:%u BLE:%u Heap:%u\n",
                         baselineDeviceCount, framesSeen, bleFramesSeen, ESP.getFreeHeap());
            nextStatus += 5000;
        }
        
        // WiFi scanning
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, true, false, rfConfig.wifiChannelTime);
            
            if (networksFound > 0) {
                for (int i = 0; i < networksFound; i++) {
                    uint8_t *bssidBytes = WiFi.BSSID(i);
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
            }
            WiFi.scanDelete();
        }
        
        // BLE scanning - only if pBLEScan is valid and running
        if (pBLEScan && pBLEScan->isScanning() && (millis() - lastBLEScan >= BLE_SCAN_INTERVAL)) {
            lastBLEScan = millis();
            
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            
            for (int i = 0; i < scanResults.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStr = device->getAddress().toString().c_str();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();
                
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
                }
            }
            pBLEScan->clearResults();
        }
        
        // Process queue
        while (xQueueReceive(macQueue, &h, 0) == pdTRUE) {
            if (isAllowlisted(h.mac)) {
                continue;
            }
            updateBaselineDevice(h.mac, h.rssi, h.name, h.isBLE, h.ch);
        }
        
        if (millis() - lastCleanup >= BASELINE_CLEANUP_INTERVAL) {
            cleanupBaselineMemory();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    baselineEstablished = true;
    baselineStats.phase1Complete = true;
    updateBaselineStats();
    
    Serial.printf("[BASELINE] Baseline established with %d devices\n", baselineDeviceCount);
    Serial.printf("[BASELINE] Phase 2: Monitoring for anomalies (threshold: %d dBm)\n", baselineRssiThreshold);

    // Phase 2: Same pattern, checking pBLEScan validity
    uint32_t monitorStart = millis();
    phaseStart = millis();
    nextStatus = millis() + 5000;
    nextStatsUpdate = millis() + 1000;
    lastCleanup = millis();
    lastWiFiScan = 0;
    lastBLEScan = 0;

    Serial.printf("[BASELINE] Phase 2 starting at %u ms, target duration: %u ms\n", 
                monitorStart, (forever ? UINT32_MAX : (uint32_t)duration * 1000));
        
    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - monitorStart) < duration * 1000 && !stopRequested)) {
        
        baselineStats.elapsedTime = (millis() - phaseStart);

        if ((int32_t)(millis() - nextStatsUpdate) >= 0) {
            updateBaselineStats();
            nextStatsUpdate += 1000;
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BASELINE] Monitoring... Baseline:%d Anomalies:%d Heap:%u\n",
                         baselineDeviceCount, anomalyCount, ESP.getFreeHeap());
            nextStatus += 5000;
        }

        // WiFi scanning
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, true, false, rfConfig.wifiChannelTime);

            if (networksFound > 0) {
                for (int i = 0; i < networksFound; i++) {
                    uint8_t *bssidBytes = WiFi.BSSID(i);
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
                }
            }
            WiFi.scanDelete();
        }

        // BLE scanning - check validity
        if (pBLEScan && pBLEScan->isScanning() && (millis() - lastBLEScan >= BLE_SCAN_INTERVAL)) {
            lastBLEScan = millis();
            
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            
            for (int i = 0; i < scanResults.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStr = device->getAddress().toString().c_str();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();
                
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
                }
            }
            pBLEScan->clearResults();
        }
        
        // Process queue for anomaly detection
        while (xQueueReceive(macQueue, &h, 0) == pdTRUE) {
            if (isAllowlisted(h.mac)) {
                continue;
            }
            checkForAnomalies(h.mac, h.rssi, h.name, h.isBLE, h.ch);
        }

        if (millis() - lastCleanup >= BASELINE_CLEANUP_INTERVAL) {
            cleanupBaselineMemory();
            lastCleanup = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    baselineStats.isScanning = false;
    updateBaselineStats();
    
    uint32_t finalHeap = ESP.getFreeHeap();
    Serial.printf("[BASELINE] Memory status: Baseline=%d devices, Anomalies=%d, Free heap=%u bytes\n",
                 baselineDeviceCount, anomalyCount, finalHeap);
    
    radioStopSTA();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    Serial.printf("[BASELINE] Memory status: Baseline=%d devices, Anomalies=%d, Free heap=%u bytes\n",
                 baselineDeviceCount, anomalyCount, ESP.getFreeHeap());
    
    if (sdBaselineInitialized) {
        flushBaselineCacheToSD();
        Serial.printf("[BASELINE] Final flush: %d total devices\n", baselineDeviceCount);
    }

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
    }
    
    if (baselineEstablished) {
        std::vector<String> toRemove;
        for (const auto& entry : baselineCache) {
            if (now - entry.second.lastSeen > BASELINE_DEVICE_TIMEOUT) {
                toRemove.push_back(entry.first);
            }
        }
        
        for (const auto& key : toRemove) {
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
    
    Serial.printf("[BASELINE] Cache: %d devices, History: %d tracked, Anomalies: %d, Heap: %u\n",
                 baselineCache.size(), deviceHistory.size(), anomalyLog.size(), ESP.getFreeHeap());
}

// Baseline SD 
uint8_t calculateDeviceChecksum(BaselineDevice& device) {
    uint8_t sum = 0;
    uint8_t* ptr = (uint8_t*)&device;
    for (size_t i = 0; i < sizeof(BaselineDevice) - 1; i++) {
        sum ^= ptr[i];
    }
    device.checksum = sum;
    return sum;
}

bool initializeBaselineSD() {
    if (!sdAvailable) {
        Serial.println("[BASELINE_SD] SD card not available");
        return false;
    }
    
    if (!SD.exists("/baseline_data.bin")) {
        Serial.println("[BASELINE_SD] Creating baseline data file");
        File dataFile = SD.open("/baseline_data.bin", FILE_WRITE);
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to create data file");
            return false;
        }
        
        // Throw a header on there
        uint32_t magic = 0xBA5EBA11;
        uint16_t version = 1;
        uint32_t deviceCount = 0;
        
        dataFile.write((uint8_t*)&magic, sizeof(magic));
        dataFile.write((uint8_t*)&version, sizeof(version));
        dataFile.write((uint8_t*)&deviceCount, sizeof(deviceCount));
        dataFile.close();
        
        Serial.println("[BASELINE_SD] Data file created");
    }
    
    if (!SD.exists("/baseline_stats.json")) {
        Serial.println("[BASELINE_SD] Creating stats file");
        File statsFile = SD.open("/baseline_stats.json", FILE_WRITE);
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
    if (!sdAvailable || !sdBaselineInitialized) {
        return false;
    }
    
    BaselineDevice writeDevice = device;
    calculateDeviceChecksum(writeDevice);
    
    File dataFile = SD.open("/baseline_data.bin", FILE_APPEND);
    if (!dataFile) {
        Serial.println("[BASELINE_SD] Failed to open for append");
        return false;
    }
    
    size_t written = dataFile.write((uint8_t*)&writeDevice, sizeof(BaselineDevice));
    dataFile.close();
    
    if (written == sizeof(BaselineDevice)) {
        totalDevicesOnSD++;
        return true;
    }
    
    return false;
}

bool readBaselineDeviceFromSD(const uint8_t* mac, BaselineDevice& device) {
    if (!sdAvailable || !sdBaselineInitialized) {
        return false;
    }
    
    File dataFile = SD.open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        return false;
    }
    
    dataFile.seek(10);  // Skip header
    
    BaselineDevice rec;
    String targetMac = macFmt6(mac);
    
    while (dataFile.available() >= sizeof(BaselineDevice)) {
        size_t bytesRead = dataFile.read((uint8_t*)&rec, sizeof(BaselineDevice));
        
        if (bytesRead != sizeof(BaselineDevice)) {
            break;
        }
        
        uint8_t storedChecksum = rec.checksum;
        uint8_t calcChecksum = calculateDeviceChecksum(rec);
        
        if (calcChecksum != storedChecksum) {
            Serial.println("[BASELINE_SD] Checksum fail");
            continue;
        }
        
        if (macFmt6(rec.mac) == targetMac) {
            device = rec;
            dataFile.close();
            return true;
        }
    }
    
    dataFile.close();
    return false;
}

bool flushBaselineCacheToSD() {
    if (!sdAvailable || !sdBaselineInitialized || baselineCache.empty()) {
        return false;
    }
    
    Serial.printf("[BASELINE_SD] Flushing %d devices\n", baselineCache.size());
    
    uint32_t flushed = 0;
    for (const auto& entry : baselineCache) {
        if (writeBaselineDeviceToSD(entry.second)) {
            flushed++;
        }
    }
    
    // Update header with device count
    File dataFile = SD.open("/baseline_data.bin", "r+");
    if (dataFile) {
        dataFile.seek(6);
        dataFile.write((uint8_t*)&totalDevicesOnSD, sizeof(totalDevicesOnSD));
        dataFile.close();
    }
    
    Serial.printf("[BASELINE_SD] Flushed %d devices. Total on SD: %d\n", flushed, totalDevicesOnSD);
    saveBaselineStatsToSD();
    
    return true;
}

void loadBaselineFromSD() {
    if (!sdAvailable || !sdBaselineInitialized) {
        return;
    }
    
    File dataFile = SD.open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        Serial.println("[BASELINE_SD] No baseline file");
        return;
    }
    
    uint32_t magic;
    uint16_t version;
    uint32_t deviceCount;
    
    dataFile.read((uint8_t*)&magic, sizeof(magic));
    dataFile.read((uint8_t*)&version, sizeof(version));
    dataFile.read((uint8_t*)&deviceCount, sizeof(deviceCount));
    
    if (magic != 0xBA5EBA11) {
        Serial.println("[BASELINE_SD] Invalid header");
        dataFile.close();
        return;
    }
    
    Serial.printf("[BASELINE_SD] Loading %d devices\n", deviceCount);
    
    totalDevicesOnSD = deviceCount;
    baselineDeviceCount = deviceCount;
    
    // Load last N devices into RAM cache
    if (deviceCount > 0) {
          uint32_t toLoad = min(deviceCount, baselineRamCacheSize);
        uint32_t skipRecords = (deviceCount > toLoad) ? (deviceCount - toLoad) : 0;
        
        dataFile.seek(10 + (skipRecords * sizeof(BaselineDevice)));
        
        BaselineDevice rec;
        uint32_t loaded = 0;
        
        while (dataFile.available() >= sizeof(BaselineDevice) && loaded < toLoad) {
            size_t bytesRead = dataFile.read((uint8_t*)&rec, sizeof(BaselineDevice));
            
            if (bytesRead != sizeof(BaselineDevice)) {
                break;
            }
            
            uint8_t storedChecksum = rec.checksum;
            uint8_t calcChecksum = calculateDeviceChecksum(rec);
            
            if (calcChecksum != storedChecksum) {
                continue;
            }
            
            baselineCache[macFmt6(rec.mac)] = rec;
            loaded++;
        }
        
        Serial.printf("[BASELINE_SD] Loaded %d devices into cache\n", loaded);
    }
    
    dataFile.close();
    loadBaselineStatsFromSD();
}

void saveBaselineStatsToSD() {
    if (!sdAvailable) {
        return;
    }
    
    File statsFile = SD.open("/baseline_stats.json", FILE_WRITE);
    if (!statsFile) {
        return;
    }
    
    statsFile.print("{\"totalDevices\":");
    statsFile.print(baselineDeviceCount);
    statsFile.print(",\"wifiDevices\":");
    statsFile.print(baselineStats.wifiDevices);
    statsFile.print(",\"bleDevices\":");
    statsFile.print(baselineStats.bleDevices);
    statsFile.print(",\"established\":");
    statsFile.print(baselineEstablished ? "true" : "false");
    statsFile.print(",\"rssiThreshold\":");
    statsFile.print(baselineRssiThreshold);
    statsFile.print(",\"lastUpdate\":");
    statsFile.print(millis());
    statsFile.println("}");
    
    statsFile.close();
}

void loadBaselineStatsFromSD() {
    if (!sdAvailable) {
        return;
    }
    
    File statsFile = SD.open("/baseline_stats.json", FILE_READ);
    if (!statsFile) {
        return;
    }
    
    String json = statsFile.readString();
    statsFile.close();
    
    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, json);
    
    if (!error) {
        baselineDeviceCount = doc["totalDevices"] | 0;
        baselineStats.wifiDevices = doc["wifiDevices"] | 0;
        baselineStats.bleDevices = doc["bleDevices"] | 0;
        baselineEstablished = doc["established"] | false;
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