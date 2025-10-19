#include "randomization.h"
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"
#include <algorithm>
#include <cmath>
#include <mutex>

#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_wifi_types.h"
}

extern NimBLEScan *pBLEScan;

// Global state
bool randomizationDetectionEnabled = false;
std::map<String, ProbeSession> activeSessions;
std::map<String, DeviceIdentity> deviceIdentities;
uint32_t identityIdCounter = 0;
QueueHandle_t probeRequestQueue = nullptr;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern TaskHandle_t workerTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void radioStartSTA();
extern void radioStopSTA();
extern volatile bool scanning;
extern NimBLEScan *pBLEScan;

// Mutex for thread-safe access (NOT used in ISR)
std::mutex randMutex;

// MAC type validation
bool isRandomizedMAC(const uint8_t *mac) {
    return (mac[0] & 0x02) && !(mac[0] & 0x01);
}

bool isGlobalMAC(const uint8_t *mac) {
    return !(mac[0] & 0x02) && !(mac[0] & 0x01);
}

// CRC16 for fingerprinting
uint16_t computeCRC16(const uint8_t *data, uint16_t length) {
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < length; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

String generateTrackId() {
    identityIdCounter++;
    char id[10];
    snprintf(id, sizeof(id), "T-%04X", (identityIdCounter & 0xFFFF));
    return String(id);
}

void extractIEFingerprint(const uint8_t *ieData, uint16_t ieLength, uint16_t fingerprint[6]) {
    memset(fingerprint, 0, 6 * sizeof(uint16_t));
    
    uint16_t pos = 0;
    uint8_t htCapBuf[32] = {0};
    uint8_t vhtCapBuf[16] = {0};
    uint8_t ratesBuf[16] = {0};
    uint8_t extCapBuf[16] = {0};
    uint8_t vendorBuf[64] = {0};
    uint16_t htLen = 0, vhtLen = 0, ratesLen = 0, extCapLen = 0, vendorLen = 0;
    
    while (pos + 2 <= ieLength) {
        uint8_t id = ieData[pos];
        uint8_t len = ieData[pos + 1];
        
        if (pos + 2 + len > ieLength) break;
        
        const uint8_t *ieBody = &ieData[pos + 2];
        
        switch (id) {
            case 1:
                if (len <= 16) {
                    memcpy(ratesBuf, ieBody, len);
                    ratesLen = len;
                }
                break;
            case 45:
                if (len <= 32) {
                    memcpy(htCapBuf, ieBody, len);
                    htLen = len;
                }
                break;
            case 127:
                if (len <= 16) {
                    memcpy(extCapBuf, ieBody, len);
                    extCapLen = len;
                }
                break;
            case 191:
                if (len <= 16) {
                    memcpy(vhtCapBuf, ieBody, len);
                    vhtLen = len;
                }
                break;
            case 221:
                if (vendorLen + len < 64) {
                    memcpy(vendorBuf + vendorLen, ieBody, min((int)len, 8));
                    vendorLen += min((int)len, 8);
                }
                break;
        }
        
        pos += 2 + len;
    }
    
    fingerprint[0] = htLen > 0 ? computeCRC16(htCapBuf, htLen) : 0;
    fingerprint[1] = vhtLen > 0 ? computeCRC16(vhtCapBuf, vhtLen) : 0;
    fingerprint[2] = ratesLen > 0 ? computeCRC16(ratesBuf, ratesLen) : 0;
    fingerprint[3] = extCapLen > 0 ? computeCRC16(extCapBuf, extCapLen) : 0;
    fingerprint[4] = vendorLen > 0 ? computeCRC16(vendorBuf, vendorLen) : 0;
    fingerprint[5] = (fingerprint[0] ^ fingerprint[1]) + (fingerprint[2] ^ fingerprint[3]);
}

// Behavioral metrics
float calculateIntervalConsistency(const uint32_t intervals[], uint8_t count) {
    if (count < 3) return 0.0f;
    
    uint32_t sum = 0;
    for (uint8_t i = 0; i < count; i++) sum += intervals[i];
    uint32_t mean = sum / count;
    
    if (mean == 0) return 0.0f;
    
    uint32_t variance = 0;
    for (uint8_t i = 0; i < count; i++) {
        int32_t diff = (int32_t)intervals[i] - (int32_t)mean;
        variance += (uint32_t)(diff * diff);
    }
    variance /= count;
    
    float stdDev = sqrtf((float)variance);
    float cv = stdDev / (float)mean;
    
    return max(0.0f, 1.0f - (cv / 0.5f));
}

float calculateRssiConsistency(const int8_t readings[], uint8_t count) {
    if (count < 2) return 0.0f;
    
    int16_t sum = 0;
    for (uint8_t i = 0; i < count; i++) sum += readings[i];
    int8_t mean = sum / count;
    
    uint32_t variance = 0;
    for (uint8_t i = 0; i < count; i++) {
        int16_t diff = readings[i] - mean;
        variance += (uint32_t)(diff * diff);
    }
    variance /= count;
    
    float stdDev = sqrtf((float)variance);
    
    if (stdDev > 15.0f) return 0.1f;
    if (stdDev > 10.0f) return 0.5f;
    return 0.9f;
}

uint32_t countChannels(uint32_t bitmap) {
    uint32_t count = 0;
    while (bitmap) {
        count += bitmap & 1;
        bitmap >>= 1;
    }
    return count;
}

bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches) {
    matches = 0;
    
    for (int i = 0; i < 4; i++) {
        if (fp1[i] != 0 && fp2[i] != 0 && fp1[i] == fp2[i]) {
            matches++;
        }
    }
    
    return matches >= FINGERPRINT_MATCH_THRESHOLD;
}

// FAST ISR-SAFE: Queue probe request instead of processing in ISR
void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel,
                        const uint8_t *payload, uint16_t length) {
    if (!randomizationDetectionEnabled || !probeRequestQueue) return;
    
    if (!isRandomizedMAC(mac)) {
        return;
    }
    
    // Only queue, don't process in ISR
    ProbeRequestEvent event;
    memcpy(event.mac, mac, 6);
    event.rssi = rssi;
    event.channel = channel;
    event.payloadLen = min((uint16_t)128, length);
    if (length > 0 && payload) {
        memcpy(event.payload, payload, event.payloadLen);
    }
    
    BaseType_t higher_prio_woken = pdFALSE;
    xQueueSendFromISR(probeRequestQueue, &event, &higher_prio_woken);
    if (higher_prio_woken) portYIELD_FROM_ISR();
}

// Process queued probes in task context (NOT in ISR)
static void processQueuedProbes() {
    ProbeRequestEvent event;
    
    while (xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE) {
        String macStr = macFmt6(event.mac);
        uint32_t now = millis();
        
        std::lock_guard<std::mutex> lock(randMutex);
        
        bool isSession = activeSessions.find(macStr) != activeSessions.end();
        
        if (!isSession && activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
            continue;  // Skip if at capacity
        }
        
        if (!isSession) {
            ProbeSession session;
            memcpy(session.mac, event.mac, 6);
            session.startTime = now;
            session.lastSeen = now;
            session.rssiSum = event.rssi;
            session.rssiMin = event.rssi;
            session.rssiMax = event.rssi;
            session.probeCount = 1;
            session.primaryChannel = event.channel;
            session.channelMask = (1 << event.channel);
            session.rssiReadings.push_back(event.rssi);
            session.probeTimestamps[0] = now;
            
            if (event.payloadLen > 24) {
                const uint8_t *ieStart = event.payload + 24;
                uint16_t ieLength = event.payloadLen - 24;
                extractIEFingerprint(ieStart, ieLength, session.fingerprint);
            } else {
                memset(session.fingerprint, 0, sizeof(session.fingerprint));
            }
            
            activeSessions[macStr] = session;
            
        } else {
            ProbeSession& session = activeSessions[macStr];
            
            if (session.probeCount < 50) {
                session.probeTimestamps[session.probeCount] = now;
            }
            
            session.lastSeen = now;
            session.rssiSum += event.rssi;
            session.rssiMin = min(session.rssiMin, event.rssi);
            session.rssiMax = max(session.rssiMax, event.rssi);
            session.probeCount++;
            session.channelMask |= (1 << event.channel);
            
            if (session.rssiReadings.size() < 20) {
                session.rssiReadings.push_back(event.rssi);
            }
        }
    }
}

void linkSessionToTrackBehavioral(const ProbeSession& session) {
    String macStr = macFmt6(session.mac);
    uint32_t now = millis();
    
    bool allZero = true;
    for (int i = 0; i < 6; i++) {
        if (session.fingerprint[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) return;
    
    BehavioralSignature sessionSig;
    memset(&sessionSig, 0, sizeof(sessionSig));
    
    if (session.probeCount > 2) {
        for (uint8_t i = 1; i < session.probeCount && i < 20; i++) {
            sessionSig.probeIntervals[i-1] = 
                session.probeTimestamps[i] - session.probeTimestamps[i-1];
        }
        sessionSig.intervalCount = min((uint8_t)19, (uint8_t)(session.probeCount - 1));
        sessionSig.intervalConsistency = 
            calculateIntervalConsistency(sessionSig.probeIntervals, sessionSig.intervalCount);
    }
    
    uint8_t rssiCount = min((uint8_t)20, (uint8_t)session.rssiReadings.size());
    for (uint8_t i = 0; i < rssiCount; i++) {
        sessionSig.rssiHistory[i] = session.rssiReadings[i];
    }
    sessionSig.rssiHistoryCount = rssiCount;
    sessionSig.rssiConsistency = calculateRssiConsistency(
        sessionSig.rssiHistory, sessionSig.rssiHistoryCount);
    
    sessionSig.channelBitmap = session.channelMask;
    memcpy(sessionSig.ieFingerprint, session.fingerprint, sizeof(session.fingerprint));
    sessionSig.observationCount = 1;
    sessionSig.lastObserved = now;
    
    String bestIdentityKey;
    float bestScore = 0.0f;
    
    for (auto& identityEntry : deviceIdentities) {
        DeviceIdentity& identity = identityEntry.second;
        
        if (now - identity.lastSeen > TRACK_STALE_TIME) continue;
        
        float behaviorScore = 0.0f;
        
        if (sessionSig.intervalCount > 0 && identity.signature.intervalCount > 0) {
            float intervalDiff = fabs(sessionSig.intervalConsistency - 
                                     identity.signature.intervalConsistency);
            float intervalMatch = max(0.0f, 1.0f - (intervalDiff / 0.3f));
            behaviorScore += intervalMatch * 0.3f;
        }
        
        if (sessionSig.rssiHistoryCount > 0 && identity.signature.rssiHistoryCount > 0) {
            float rssiDiff = fabs(sessionSig.rssiConsistency - 
                                 identity.signature.rssiConsistency);
            float rssiMatch = max(0.0f, 1.0f - (rssiDiff / 0.4f));
            behaviorScore += rssiMatch * 0.4f;
        }
        
        uint32_t sessionChannels = countChannels(sessionSig.channelBitmap);
        uint32_t identityChannels = countChannels(identity.signature.channelBitmap);
        
        if (sessionChannels > 0 && identityChannels > 0) {
            float channelDiff = fabs((float)sessionChannels - (float)identityChannels);
            float channelMatch = max(0.0f, 1.0f - (channelDiff / 5.0f));
            behaviorScore += channelMatch * 0.3f;
        }
        
        float fingerprintMatch = 0.0f;
        uint8_t matches = 0;
        if (matchFingerprints(sessionSig.ieFingerprint, 
                            identity.signature.ieFingerprint, matches)) {
            fingerprintMatch = (float)matches / 4.0f;
        }
        
        float totalScore = (behaviorScore * 0.7f) + (fingerprintMatch * 0.3f);
        
        if (totalScore > 0.65f && 
            behaviorScore > 0.5f && 
            identity.observedSessions >= 1) {
            
            if (totalScore > bestScore) {
                bestScore = totalScore;
                bestIdentityKey = identityEntry.first;
            }
        }
    }
    
    if (bestScore > 0.65f && !bestIdentityKey.isEmpty()) {
        DeviceIdentity& identity = deviceIdentities[bestIdentityKey];
        
        bool alreadyLinked = false;
        for (const auto& existingMac : identity.macs) {
            if (memcmp(existingMac.bytes.data(), session.mac, 6) == 0) {
                alreadyLinked = true;
                break;
            }
        }
        
        if (!alreadyLinked && identity.macs.size() < 50) {
            identity.macs.push_back(MacAddress(session.mac));
            identity.confidence = bestScore;
            identity.observedSessions++;
        }
        
        identity.lastSeen = now;
        
        Serial.printf("[RAND] Linked %s to identity %s (behavior:%.2f fp:%.2f)\n",
                     macStr.c_str(), identity.identityId, bestScore * 0.7f, 
                     bestScore * 0.3f);
        
    } else if (sessionSig.intervalConsistency > 0.5f || 
               sessionSig.rssiConsistency > 0.6f) {
        
        if (deviceIdentities.size() >= MAX_DEVICE_TRACKS) {
            cleanupStaleTracks();
            if (deviceIdentities.size() >= MAX_DEVICE_TRACKS) return;
        }
        
        DeviceIdentity newIdentity;
        String identityId = generateTrackId();
        strncpy(newIdentity.identityId, identityId.c_str(), sizeof(newIdentity.identityId) - 1);
        newIdentity.identityId[sizeof(newIdentity.identityId) - 1] = '\0';
        
        newIdentity.macs.push_back(MacAddress(session.mac));
        newIdentity.signature = sessionSig;
        newIdentity.firstSeen = session.startTime;
        newIdentity.lastSeen = now;
        newIdentity.confidence = max(sessionSig.intervalConsistency, 
                                 sessionSig.rssiConsistency);
        newIdentity.sessionCount = 1;
        newIdentity.observedSessions = 1;
        
        deviceIdentities[identityId] = newIdentity;
        
        Serial.printf("[RAND] New identity %s (behavior:%.2f intervals:%.2f rssi:%.2f)\n",
                     identityId.c_str(), newIdentity.confidence,
                     sessionSig.intervalConsistency,
                     sessionSig.rssiConsistency);
    } else {
        Serial.printf("[RAND] Skipping %s - random behavior (intervals:%.2f rssi:%.2f)\n",
                     macStr.c_str(), sessionSig.intervalConsistency, 
                     sessionSig.rssiConsistency);
    }
}

void cleanupStaleSessions() {
    uint32_t now = millis();
    std::vector<String> toRemove;
    
    for (auto& entry : activeSessions) {
        uint32_t age = now - entry.second.lastSeen;
        
        if (age > SESSION_END_TIMEOUT) {
            linkSessionToTrackBehavioral(entry.second);
            
            if (age > SESSION_CLEANUP_AGE) {
                toRemove.push_back(entry.first);
            }
        }
    }
    
    for (const String& key : toRemove) {
        activeSessions.erase(key);
    }
    
    if (!toRemove.empty()) {
        Serial.printf("[RAND] Cleaned up %d stale sessions\n", toRemove.size());
    }
}

void cleanupStaleTracks() {
    uint32_t now = millis();
    std::vector<String> toRemove;
    
    for (auto& entry : deviceIdentities) {
        if (now - entry.second.lastSeen > TRACK_STALE_TIME) {
            toRemove.push_back(entry.first);
        }
    }
    
    for (const String& key : toRemove) {
        deviceIdentities.erase(key);
    }
    
    if (!toRemove.empty()) {
        Serial.printf("[RAND] Cleaned up %d stale identities\n", toRemove.size());
    }
}

String getRandomizationResults() {
    std::lock_guard<std::mutex> lock(randMutex);
    
    String results = "MAC Randomization Detection Results\n\n";
    
    results += "Active Sessions: " + String(activeSessions.size()) + "\n";
    results += "Device Identities: " + String(deviceIdentities.size()) + "\n\n";
    
    if (deviceIdentities.empty()) {
        results += "No device identities detected.\n";
        return results;
    }
    
    std::vector<std::pair<String, DeviceIdentity>> sortedIdentities;
    for (const auto& entry : deviceIdentities) {
        sortedIdentities.push_back(entry);
    }
    
    std::sort(sortedIdentities.begin(), sortedIdentities.end(),
              [](const auto& a, const auto& b) {
                  return a.second.observedSessions > b.second.observedSessions;
              });
    
    for (const auto& entry : sortedIdentities) {
        const DeviceIdentity& identity = entry.second;
        
        results += "Identity ID: " + String(identity.identityId) + "\n";
        results += "  Sessions: " + String(identity.observedSessions) + "\n";
        results += "  Confidence: " + String(identity.confidence, 2) + "\n";
        results += "  MACs: " + String(identity.macs.size()) + "\n";
        
        int macCount = min((int)identity.macs.size(), 5);
        for (int i = 0; i < macCount; i++) {
            const uint8_t* mac = identity.macs[i].bytes.data();
            results += "    ";
            for (int j = 0; j < 6; j++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02X", mac[j]);
                results += String(hex);
                if (j < 5) results += ":";
            }
            results += "\n";
        }
        
        if ((int)identity.macs.size() > 5) {
            results += "    ... (" + String(identity.macs.size() - 5) + " more)\n";
        }
        
        uint32_t age = (millis() - identity.lastSeen) / 1000;
        results += "  Last seen: " + String(age) + "s ago\n\n";
    }
    
    return results;
}

void resetRandomizationDetection() {
    std::lock_guard<std::mutex> lock(randMutex);
    
    activeSessions.clear();
    deviceIdentities.clear();
    identityIdCounter = 0;
    Serial.println("[RAND] Detection reset");
}

void randomizationDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    Serial.printf("[RAND] Starting randomization detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());
    
    if (probeRequestQueue) vQueueDelete(probeRequestQueue);
    probeRequestQueue = xQueueCreate(256, sizeof(ProbeRequestEvent));
    
    randomizationDetectionEnabled = true;
    scanning = true;
    
    currentScanMode = SCAN_BOTH;
    
    {
        std::lock_guard<std::mutex> lock(randMutex);
        uint32_t now = millis();
        
        std::vector<String> staleSessions;
        for (auto& entry : activeSessions) {
            if (now - entry.second.lastSeen > 300000) {
                staleSessions.push_back(entry.first);
            }
        }
        for (const auto& key : staleSessions) {
            activeSessions.erase(key);
        }
        
        std::vector<String> staleIdentities;
        for (auto& entry : deviceIdentities) {
            if (now - entry.second.lastSeen > 600000) {
                staleIdentities.push_back(entry.first);
            }
        }
        for (const auto& key : staleIdentities) {
            deviceIdentities.erase(key);
        }
        
        Serial.printf("[RAND] Cleaned %d stale sessions, %d stale identities. Retained: %d sessions, %d identities\n",
                     staleSessions.size(), staleIdentities.size(), 
                     activeSessions.size(), deviceIdentities.size());
    }
    
    radioStartSTA();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    uint32_t startTime = millis();
    uint32_t nextStatus = startTime + 5000;
    uint32_t nextLink = startTime + 8000;
    uint32_t nextCacheUpdate = startTime + 1000;
    uint32_t lastBLEScan = 0;
    const uint32_t BLE_SCAN_INTERVAL = 3000;
    
    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {
        
        // Process WiFi probe requests from ISR
        {
            std::lock_guard<std::mutex> lock(randMutex);
            
            ProbeRequestEvent event;
            int processedCount = 0;
            
            while (processedCount < 100 && xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE) {
                processedCount++;
                
                String macStr = macFmt6(event.mac);
                uint32_t now = millis();
                
                bool isSession = activeSessions.find(macStr) != activeSessions.end();
                
                if (!isSession && activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
                    continue;
                }
                
                if (!isSession) {
                    ProbeSession session;
                    memcpy(session.mac, event.mac, 6);
                    session.startTime = now;
                    session.lastSeen = now;
                    session.rssiSum = event.rssi;
                    session.rssiMin = event.rssi;
                    session.rssiMax = event.rssi;
                    session.probeCount = 1;
                    session.primaryChannel = event.channel;
                    session.channelMask = (1 << event.channel);
                    session.rssiReadings.push_back(event.rssi);
                    session.probeTimestamps[0] = now;
                    
                    if (event.payloadLen > 24) {
                        extractIEFingerprint(event.payload + 24, event.payloadLen - 24, session.fingerprint);
                    } else {
                        memset(session.fingerprint, 0, sizeof(session.fingerprint));
                    }
                    
                    activeSessions[macStr] = session;
                    
                } else {
                    ProbeSession& session = activeSessions[macStr];
                    if (session.probeCount < 50) {
                        session.probeTimestamps[session.probeCount] = now;
                    }
                    session.lastSeen = now;
                    session.rssiSum += event.rssi;
                    session.rssiMin = min(session.rssiMin, event.rssi);
                    session.rssiMax = max(session.rssiMax, event.rssi);
                    session.probeCount++;
                    session.channelMask |= (1 << event.channel);
                    
                    if (session.rssiReadings.size() < 20) {
                        session.rssiReadings.push_back(event.rssi);
                    }
                }
            }
        }
        
        if (pBLEScan && (millis() - lastBLEScan >= BLE_SCAN_INTERVAL)) {
            lastBLEScan = millis();
            
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            
            if (scanResults.getCount() > 0) {
                std::lock_guard<std::mutex> lock(randMutex);
                
                for (int i = 0; i < scanResults.getCount(); i++) {
                    const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                    
                    const uint8_t* macBytes = device->getAddress().getVal();
                    uint8_t mac[6];
                    memcpy(mac, macBytes, 6);
                    
                    // Check if randomized
                    if (!isRandomizedMAC(mac)) {
                        continue;
                    }
                    
                    String macStr = macFmt6(mac);
                    uint32_t now = millis();
                    int8_t rssi = device->getRSSI();
                    
                    bool isSession = activeSessions.find(macStr) != activeSessions.end();
                    
                    if (!isSession && activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
                        continue;
                    }
                    
                    if (!isSession) {
                        ProbeSession session;
                        memcpy(session.mac, mac, 6);
                        session.startTime = now;
                        session.lastSeen = now;
                        session.rssiSum = rssi;
                        session.rssiMin = rssi;
                        session.rssiMax = rssi;
                        session.probeCount = 1;
                        session.primaryChannel = 0;
                        session.channelMask = 0;
                        session.rssiReadings.push_back(rssi);
                        session.probeTimestamps[0] = now;
                        memset(session.fingerprint, 0, sizeof(session.fingerprint));
                        
                        activeSessions[macStr] = session;
                        Serial.printf("[RAND] New BLE randomized device: %s RSSI=%d\n", 
                                    macStr.c_str(), rssi);
                        
                    } else {
                        ProbeSession& session = activeSessions[macStr];
                        if (session.probeCount < 50) {
                            session.probeTimestamps[session.probeCount] = now;
                        }
                        session.lastSeen = now;
                        session.rssiSum += rssi;
                        session.rssiMin = min(session.rssiMin, rssi);
                        session.rssiMax = max(session.rssiMax, rssi);
                        session.probeCount++;
                        
                        if (session.rssiReadings.size() < 20) {
                            session.rssiReadings.push_back(rssi);
                        }
                    }
                }
            }
            
            pBLEScan->clearResults();
        }
        
        vTaskDelay(pdMS_TO_TICKS(10));

        // Send results to cache display
        if ((int32_t)(millis() - nextCacheUpdate) >= 0) {
            antihunter::lastResults = getRandomizationResults().c_str();
            nextCacheUpdate += 1000;
        }
        
        if ((int32_t)(millis() - nextLink) >= 0) {
            {
                std::lock_guard<std::mutex> lock(randMutex);
                
                uint32_t now = millis();
                std::vector<String> toLink;
                std::vector<String> toRemove;
                
                for (auto& entry : activeSessions) {
                    uint32_t age = now - entry.second.lastSeen;
                    if (age > SESSION_END_TIMEOUT) {
                        toLink.push_back(entry.first);
                        if (age > SESSION_CLEANUP_AGE) {
                            toRemove.push_back(entry.first);
                        }
                    }
                }
                
                for (const String& key : toLink) {
                    linkSessionToTrackBehavioral(activeSessions[key]);
                }
                
                for (const String& key : toRemove) {
                    activeSessions.erase(key);
                }
            }
            
            nextLink += 8000;
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            {
                std::lock_guard<std::mutex> lock(randMutex);
                Serial.printf("[RAND] Sessions:%u Identities:%u Heap:%u\n",
                             activeSessions.size(), deviceIdentities.size(), ESP.getFreeHeap());
            }
            nextStatus += 5000;
        }
        
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    
    randomizationDetectionEnabled = false;
    scanning = false;

    String finalResults = getRandomizationResults();

    {
        std::lock_guard<std::mutex> resultsLock(antihunter::lastResultsMutex);
        antihunter::lastResults = finalResults.c_str();
    }

    Serial.printf("[RAND] Results cached: %d bytes\n", finalResults.length());
    Serial.printf("[RAND] Complete. Identities:%d\n", deviceIdentities.size());

    radioStopSTA();
    delay(100);

    if (probeRequestQueue) {
        vQueueDelete(probeRequestQueue);
        probeRequestQueue = nullptr;
    }

    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}