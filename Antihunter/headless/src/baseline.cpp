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

// RAM SD Cache
std::map<String, bool> sdLookupCache;
std::list<String> sdLookupLRU;
const uint32_t SD_LOOKUP_CACHE_SIZE = 200;
const uint32_t SD_LOOKUP_CACHE_TTL = 300000;
std::map<String, uint32_t> sdDeviceIndex;

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
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    
    if (baselineCache.find(macStr) == baselineCache.end()) {
        uint32_t effectiveLimit = (sdAvailable && sdBaselineInitialized) ? 
                                    baselineRamCacheSize : 1500;
        
        if (baselineCache.size() >= effectiveLimit) {
            if (sdAvailable && sdBaselineInitialized) {
                String oldestKey;
                uint32_t oldestTime = UINT32_MAX;
                
                for (const auto& entry : baselineCache) {
                    if (entry.second.lastSeen < oldestTime) {
                        oldestTime = entry.second.lastSeen;
                        oldestKey = entry.first;
                    }
                }
                
                if (oldestKey.length() > 0) {
                    auto& oldestDevice = baselineCache[oldestKey];
                    if (oldestDevice.dirtyFlag) {
                        writeBaselineDeviceToSD(oldestDevice);
                    }
                    baselineCache.erase(oldestKey);
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
        
        baselineCache[macStr] = dev;
        baselineDeviceCount++;
    } else {
        BaselineDevice &dev = baselineCache[macStr];
        dev.avgRssi = (dev.avgRssi * dev.hitCount + rssi) / (dev.hitCount + 1);
        if (rssi < dev.minRssi) dev.minRssi = rssi;
        if (rssi > dev.maxRssi) dev.maxRssi = rssi;
        dev.lastSeen = now;
        dev.hitCount++;
        dev.dirtyFlag = true;
        
        if (strlen(name) > 0 && strcmp(name, "Unknown") != 0 && strcmp(name, "WiFi") != 0) {
            strncpy(dev.name, name, sizeof(dev.name) - 1);
            dev.name[sizeof(dev.name) - 1] = '\0';
        }
    }
    
    if (sdAvailable && sdBaselineInitialized && millis() - lastSDFlush >= BASELINE_SD_FLUSH_INTERVAL) {
        flushBaselineCacheToSD();
        lastSDFlush = millis();
    }
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
    
    std::set<String> transmittedDevices;
    std::set<String> transmittedAnomalies;
    
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
        pBLEScan->setInterval(100);
        pBLEScan->setWindow(99);
        pBLEScan->setDuplicateFilter(false);
        pBLEScan->start(0, false);
    }

    uint32_t phaseStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t nextStatsUpdate = millis() + 1000;
    uint32_t lastCleanup = millis();
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    uint32_t lastMeshUpdate = 0;
    const uint32_t MESH_DEVICE_UPDATE_INTERVAL = 5000;
    
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

        if (stopRequested) {
            break;
        }
        
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, false, false, rfConfig.wifiChannelTime);
            
            if (stopRequested) {
                WiFi.scanDelete();
                break;
            }

            if (networksFound > 0) {
                for (int i = 0; i < networksFound && !stopRequested; i++) {
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
        
        if (meshEnabled && millis() - lastMeshUpdate >= MESH_DEVICE_UPDATE_INTERVAL) {
        lastMeshUpdate = millis();
        uint32_t sentThisCycle = 0;
        
        for (const auto& entry : baselineCache) {
            String macStr = macFmt6(entry.second.mac);
            
            if (transmittedDevices.find(macStr) == transmittedDevices.end()) {
                String deviceMsg = getNodeId() + ": DEVICE:" + macStr;
                deviceMsg += entry.second.isBLE ? " B " : " W ";
                deviceMsg += String(entry.second.avgRssi);
                
                if (!entry.second.isBLE && entry.second.channel > 0) {
                    deviceMsg += " C" + String(entry.second.channel);
                }
                
                if (strlen(entry.second.name) > 0 && 
                    strcmp(entry.second.name, "Unknown") != 0 && 
                    strcmp(entry.second.name, "[Hidden]") != 0) {
                    deviceMsg += " N:" + String(entry.second.name).substring(0, 30);
                }
                
                if (deviceMsg.length() < 230) {
                    if (sendToSerial1(deviceMsg, true)) {
                        transmittedDevices.insert(macStr);
                        sentThisCycle++;
                        
                        if (sentThisCycle % 2 == 0) {
                            delay(1000);
                            rateLimiter.refillTokens();
                        }
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

    if (stopRequested) {
        baselineStats.isScanning = false;
        scanning = false;
        updateBaselineStats();
        
        radioStopSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
        
        if (macQueue) {
            vQueueDelete(macQueue);
            macQueue = nullptr;
        }
        if (anomalyQueue) {
            vQueueDelete(anomalyQueue);
            anomalyQueue = nullptr;
        }
        
        sdLookupCache.clear();
        sdLookupLRU.clear();
        
        baselineDetectionEnabled = false;
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    baselineEstablished = true;
    baselineStats.phase1Complete = true;
    updateBaselineStats();
    
    Serial.printf("[BASELINE] Baseline established with %d devices\n", baselineDeviceCount);
    Serial.printf("[BASELINE] Phase 2: Monitoring for anomalies (threshold: %d dBm)\n", baselineRssiThreshold);

    uint32_t monitorStart = millis();
    phaseStart = millis();
    nextStatus = millis() + 5000;
    nextStatsUpdate = millis() + 1000;
    lastCleanup = millis();
    lastWiFiScan = 0;
    lastBLEScan = 0;
    lastMeshUpdate = 0;

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

        if (stopRequested) {
            break;
        }

        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, false, false, rfConfig.wifiChannelTime);

            if (stopRequested) {
                WiFi.scanDelete();
                break;
            }

            if (networksFound > 0) {
                for (int i = 0; i < networksFound && !stopRequested; i++) {
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
        
        if (meshEnabled && millis() - lastMeshUpdate >= MESH_DEVICE_UPDATE_INTERVAL) {
            lastMeshUpdate = millis();
            uint32_t sentThisCycle = 0;
            
            for (const auto& entry : baselineCache) {
                String macStr = macFmt6(entry.second.mac);
                
                if (transmittedDevices.find(macStr) == transmittedDevices.end()) {
                    String deviceMsg = getNodeId() + ": DEVICE:" + macStr;
                    deviceMsg += entry.second.isBLE ? " B " : " W ";
                    deviceMsg += String(entry.second.avgRssi);
                    
                    if (!entry.second.isBLE && entry.second.channel > 0) {
                        deviceMsg += " C" + String(entry.second.channel);
                    }
                    
                    if (strlen(entry.second.name) > 0 && 
                        strcmp(entry.second.name, "Unknown") != 0 && 
                        strcmp(entry.second.name, "[Hidden]") != 0) {
                        deviceMsg += " N:" + String(entry.second.name).substring(0, 30);
                    }
                    
                    if (deviceMsg.length() < 230) {
                        if (sendToSerial1(deviceMsg, true)) {
                            transmittedDevices.insert(macStr);
                            sentThisCycle++;
                            
                            if (sentThisCycle % 2 == 0) {
                                delay(1000);
                                rateLimiter.refillTokens();
                            }
                        }
                    }
                }
            }
            
            for (const auto& anomaly : anomalyLog) {
                String macStr = macFmt6(anomaly.mac);
                
                if (transmittedAnomalies.find(macStr) == transmittedAnomalies.end()) {
                    String anomalyMsg = getNodeId() + ": ANOMALY: " + String(anomaly.isBLE ? "BLE " : "WiFi ") + macStr;
                    anomalyMsg += " RSSI:" + String(anomaly.rssi);
                    anomalyMsg += " " + anomaly.reason;
                    
                    if (strlen(anomaly.name) > 0 && strcmp(anomaly.name, "Unknown") != 0) {
                        anomalyMsg += " N:" + String(anomaly.name).substring(0, 20);
                    }
                    
                    if (anomalyMsg.length() < 230) {
                        if (sendToSerial1(anomalyMsg, true)) {
                            transmittedAnomalies.insert(macStr);
                            sentThisCycle++;
                            
                            if (sentThisCycle % 2 == 0) {
                                delay(1000);
                                rateLimiter.refillTokens();
                            }
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
    
    baselineStats.isScanning = false;
    updateBaselineStats();
    
    uint32_t finalHeap = ESP.getFreeHeap();
    Serial.printf("[BASELINE] Memory status: Baseline=%d devices, Anomalies=%d, Free heap=%u bytes\n",
                 baselineDeviceCount, anomalyCount, finalHeap);
    
    radioStopSTA();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    if (sdBaselineInitialized) {
        flushBaselineCacheToSD();
        Serial.printf("[BASELINE] Final flush: %d total devices\n", baselineDeviceCount);
    }

    if (meshEnabled && !stopRequested) {
        uint32_t finalTransmitted = transmittedDevices.size();
        uint32_t finalRemaining = baselineDeviceCount - finalTransmitted;
        
        String summary = getNodeId() + ": BASELINE_DONE: Devices=" + String(baselineDeviceCount) +
                        " Anomalies=" + String(anomalyCount) +
                        " WiFi=" + String(baselineStats.wifiDevices) +
                        " BLE=" + String(baselineStats.bleDevices) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        sendToSerial1(summary, true);
        Serial.println("[BASELINE] Detection complete summary transmitted");
    }

    if (macQueue) {
        vQueueDelete(macQueue);
        macQueue = nullptr;
    }
    if (anomalyQueue) {
        vQueueDelete(anomalyQueue);
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
        
        dataFile.write((uint8_t*)&magic, sizeof(magic));
        dataFile.write((uint8_t*)&version, sizeof(version));
        dataFile.write((uint8_t*)&deviceCount, sizeof(deviceCount));
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
    
    String macStr = macFmt6(device.mac);
    
    if (sdDeviceIndex.find(macStr) != sdDeviceIndex.end()) {
        uint32_t position = sdDeviceIndex[macStr];
        
        File dataFile = SafeSD::open("/baseline_data.bin", "r+");
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to open for update");
            return false;
        }
        
        dataFile.seek(position);
        size_t written = dataFile.write((uint8_t*)&writeDevice, sizeof(BaselineDevice));
        dataFile.close();
        
        return (written == sizeof(BaselineDevice));
    } else {
        File dataFile = SafeSD::open("/baseline_data.bin", FILE_APPEND);
        if (!dataFile) {
            Serial.println("[BASELINE_SD] Failed to open for append");
            return false;
        }
        
        uint32_t position = dataFile.position();
        size_t written = dataFile.write((uint8_t*)&writeDevice, sizeof(BaselineDevice));
        dataFile.close();
        
        if (written == sizeof(BaselineDevice)) {
            sdDeviceIndex[macStr] = position;
            totalDevicesOnSD++;
            
            File headerFile = SafeSD::open("/baseline_data.bin", "r+");
            if (headerFile) {
                headerFile.seek(6);
                headerFile.write((uint8_t*)&totalDevicesOnSD, sizeof(totalDevicesOnSD));
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
    
    String macStr = macFmt6(mac);
    
    if (sdDeviceIndex.find(macStr) == sdDeviceIndex.end()) {
        return false;
    }
    
    uint32_t position = sdDeviceIndex[macStr];
    
    File dataFile = SafeSD::open("/baseline_data.bin", FILE_READ);
    if (!dataFile) {
        return false;
    }
    
    dataFile.seek(position);
    size_t bytesRead = SafeSD::read(dataFile, (uint8_t*)&device, sizeof(BaselineDevice));
    dataFile.close();
    
    if (bytesRead != sizeof(BaselineDevice)) {
        return false;
    }
    
    uint8_t storedChecksum = device.checksum;
    uint8_t calcChecksum = calculateDeviceChecksum(device);
    
    if (calcChecksum != storedChecksum) {
        Serial.println("[BASELINE_SD] Checksum fail");
        return false;
    }
    
    return true;
}

bool flushBaselineCacheToSD() {
    if (!SafeSD::isAvailable() || !sdBaselineInitialized || baselineCache.empty()) {
        return false;
    }
    
    uint32_t dirtyCount = 0;
    for (const auto& entry : baselineCache) {
        if (entry.second.dirtyFlag) {
            dirtyCount++;
        }
    }
    
    if (dirtyCount == 0) {
        return true;
    }
    
    Serial.printf("[BASELINE_SD] Flushing %d modified devices\n", dirtyCount);
    
    uint32_t flushed = 0;
    for (auto& entry : baselineCache) {
        if (entry.second.dirtyFlag) {
            if (writeBaselineDeviceToSD(entry.second)) {
                entry.second.dirtyFlag = false;
                flushed++;
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
    
    SafeSD::read(dataFile, (uint8_t*)&magic, sizeof(magic));
    SafeSD::read(dataFile, (uint8_t*)&version, sizeof(version));
    SafeSD::read(dataFile, (uint8_t*)&deviceCount, sizeof(deviceCount));
    
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
            size_t bytesRead = SafeSD::read(dataFile, (uint8_t*)&rec, sizeof(BaselineDevice));
            
            if (bytesRead != sizeof(BaselineDevice)) {
                break;
            }
            
            uint8_t storedChecksum = rec.checksum;
            uint8_t calcChecksum = calculateDeviceChecksum(rec);
            
            if (calcChecksum != storedChecksum) {
                continue;
            }
            
            rec.dirtyFlag = false;
            baselineCache[macFmt6(rec.mac)] = rec;
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
    
    File statsFile = SafeSD::open("/baseline_stats.json", FILE_WRITE);
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
    if (!SafeSD::isAvailable()) {
        return;
    }
    
    File statsFile = SafeSD::open("/baseline_stats.json", FILE_READ);
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

// RAM SD Caching 

void addToSDCache(const String& mac, bool found) {
    if (sdLookupCache.size() >= SD_LOOKUP_CACHE_SIZE) {
        if (!sdLookupLRU.empty()) {
            String oldest = sdLookupLRU.front();
            sdLookupLRU.pop_front();
            sdLookupCache.erase(oldest);
        }
    }
    
    sdLookupCache[mac] = found;
    sdLookupLRU.push_back(mac);
}

bool checkSDCache(const String& mac, bool& found) {
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
    String macStr = macFmt6(mac);
    
    if (baselineCache.find(macStr) != baselineCache.end()) {
        return true;
    }
    
    bool found;
    if (checkSDCache(macStr, found)) {
        return found;
    }
    
    BaselineDevice dev;
    bool inSD = readBaselineDeviceFromSD(mac, dev);
    addToSDCache(macStr, inSD);
    
    return inSD;
}

void checkForAnomalies(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel) {
    if (rssi < baselineRssiThreshold) {
        return;
    }
    
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    
    if (deviceHistory.find(macStr) == deviceHistory.end()) {
        bool inBaseline = isDeviceInBaseline(mac);
        deviceHistory[macStr] = {rssi, now, 0, inBaseline, 0};
    }
    
    DeviceHistory &history = deviceHistory[macStr];
    
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
            String meshAlert = getNodeId() + ": ANOMALY-NEW: " + String(isBLE ? "BLE " : "WiFi ") + macStr;
            meshAlert += " RSSI:" + String(rssi);
            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                meshAlert += " Name:" + String(name);
            }
            sendToSerial1(meshAlert, false);
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
            anomalyLog.push_back(hit);
            anomalyCount++;
            
            String alert = "[ANOMALY] RETURNED: " + macStr;
            alert += " was absent " + String(absentTime / 1000) + "s";
            alert += " RSSI:" + String(rssi) + "dBm";
            if (strlen(name) > 0 && strcmp(name, "Unknown") != 0) {
                alert += " Name:" + String(name);
            }
            
            Serial.println(alert);
            logToSD(alert);

            if (meshEnabled && millis() - lastBaselineAnomalyMeshSend > BASELINE_ANOMALY_MESH_INTERVAL) {
                lastBaselineAnomalyMeshSend = millis();
                String meshAlert = getNodeId() + ": ANOMALY-RETURN: " + String(isBLE ? "BLE " : "WiFi ") + macStr;
                meshAlert += " absent:" + String(absentTime / 1000) + "s";
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
            anomalyLog.push_back(hit);
            anomalyCount++;
            
            String alert = "[ANOMALY] RSSI-CHANGE: " + macStr;
            alert += " " + String(history.lastRssi) + "dBm -> " + String(rssi) + "dBm";
            
            Serial.println(alert);
            logToSD(alert);
            
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
    
    SafeSD::read(dataFile, (uint8_t*)&magic, sizeof(magic));
    SafeSD::read(dataFile, (uint8_t*)&version, sizeof(version));
    SafeSD::read(dataFile, (uint8_t*)&deviceCount, sizeof(deviceCount));
    
    if (magic != 0xBA5EBA11) {
        dataFile.close();
        return;
    }
    
    BaselineDevice rec;
    uint32_t position = 10;
    
    while (dataFile.available() >= sizeof(BaselineDevice)) {
        size_t bytesRead = SafeSD::read(dataFile, (uint8_t*)&rec, sizeof(BaselineDevice));
        
        if (bytesRead != sizeof(BaselineDevice)) {
            break;
        }
        
        uint8_t storedChecksum = rec.checksum;
        uint8_t calcChecksum = calculateDeviceChecksum(rec);
        
        if (calcChecksum == storedChecksum) {
            String macStr = macFmt6(rec.mac);
            sdDeviceIndex[macStr] = position;
        }
        
        position += sizeof(BaselineDevice);
    }
    
    dataFile.close();
    totalDevicesOnSD = sdDeviceIndex.size();
    Serial.printf("[BASELINE_SD] Index built: %d unique devices\n", totalDevicesOnSD);
}