#include "randomization.h"
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"
#include <algorithm>

extern "C" {
#include "esp_wifi.h"
#include "esp_wifi_types.h"
}

// Global state
bool randomizationDetectionEnabled = false;
std::map<String, ProbeSession> activeSessions;
std::map<String, DeviceTrack> deviceTracks;
uint32_t trackIdCounter = 0;

extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern TaskHandle_t workerTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void radioStartSTA();
extern void radioStopSTA();
extern volatile bool scanning;

// MAC type validation
bool isRandomizedMAC(const uint8_t *mac) {
    // Bit 1 of first octet = 1 (locally administered)
    // Bit 0 of first octet = 0 (unicast)
    return (mac[0] & 0x02) && !(mac[0] & 0x01);
}

bool isGlobalMAC(const uint8_t *mac) {
    // Bit 1 of first octet = 0 (globally administered)
    // Bit 0 of first octet = 0 (unicast)
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

// Generate unique track ID
String generateTrackId() {
    trackIdCounter++;
    char id[10];
    snprintf(id, sizeof(id), "T-%04X", (trackIdCounter & 0xFFFF));
    return String(id);
}

// Extract IE fingerprint from probe request
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
            case 1: // Supported Rates
                if (len <= 16) {
                    memcpy(ratesBuf, ieBody, len);
                    ratesLen = len;
                }
                break;
            case 45: // HT Capabilities
                if (len <= 32) {
                    memcpy(htCapBuf, ieBody, len);
                    htLen = len;
                }
                break;
            case 127: // Extended Capabilities
                if (len <= 16) {
                    memcpy(extCapBuf, ieBody, len);
                    extCapLen = len;
                }
                break;
            case 191: // VHT Capabilities
                if (len <= 16) {
                    memcpy(vhtCapBuf, ieBody, len);
                    vhtLen = len;
                }
                break;
            case 221: // Vendor Specific
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

// Match fingerprints
bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches) {
    matches = 0;
    
    for (int i = 0; i < 4; i++) {
        if (fp1[i] != 0 && fp2[i] != 0 && fp1[i] == fp2[i]) {
            matches++;
        }
    }
    
    return matches >= FINGERPRINT_MATCH_THRESHOLD;
}

// Process probe request frame
void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel,
                        const uint8_t *payload, uint16_t length) {
    if (!randomizationDetectionEnabled) return;
    
    // CRITICAL: Only track locally administered (randomized) MACs
    if (!isRandomizedMAC(mac)) {
        return;
    }
    
    String macStr = macFmt6(mac);
    uint32_t now = millis();
    
    bool isSession = activeSessions.find(macStr) != activeSessions.end();
    
    if (!isSession && activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
        cleanupStaleSessions();
        if (activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
            return;
        }
    }
    
    if (!isSession) {
        ProbeSession session;
        memcpy(session.mac, mac, 6);
        session.startTime = now;
        session.lastSeen = now;
        session.rssiSum = rssi;
        session.rssiMin = rssi;
        session.rssiMax = rssi;
        session.hitCount = 1;
        session.primaryChannel = channel;
        session.channelMask = (1 << channel);
        
        if (length > 24) {
            const uint8_t *ieStart = payload + 24;
            uint16_t ieLength = length - 24;
            extractIEFingerprint(ieStart, ieLength, session.fingerprint);
        } else {
            memset(session.fingerprint, 0, sizeof(session.fingerprint));
        }
        
        activeSessions[macStr] = session;
        
    } else {
        ProbeSession& session = activeSessions[macStr];
        session.lastSeen = now;
        session.rssiSum += rssi;
        session.rssiMin = min(session.rssiMin, rssi);
        session.rssiMax = max(session.rssiMax, rssi);
        session.hitCount++;
        session.channelMask |= (1 << channel);
    }
}

// Link session to track
void linkSessionToTrack(const ProbeSession& session) {
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
    
    String bestTrackKey;
    float bestScore = 0.0;
    uint8_t bestMatches = 0;
    
    for (auto& trackEntry : deviceTracks) {
        DeviceTrack& track = trackEntry.second;
        
        if (now - track.lastSeen > TRACK_STALE_TIME) continue;
        
        uint8_t matches = 0;
        if (!matchFingerprints(session.fingerprint, track.fingerprint, matches)) {
            continue;
        }
        
        uint32_t timeDelta = (session.startTime > track.lastSeen) ? 
                             (session.startTime - track.lastSeen) : 0;
        
        if (timeDelta > 15000) continue;
        
        float timeScore = max(0.0f, 1.0f - (timeDelta / 15000.0f));
        float fingerprintScore = matches / 4.0f;
        float score = (fingerprintScore * 0.7f) + (timeScore * 0.3f);
        
        if (score > bestScore && score >= CONFIDENCE_THRESHOLD) {
            bestScore = score;
            bestTrackKey = trackEntry.first;
            bestMatches = matches;
        }
    }
    
    if (bestScore >= CONFIDENCE_THRESHOLD && !bestTrackKey.isEmpty()) {
        DeviceTrack& track = deviceTracks[bestTrackKey];
        
        bool alreadyLinked = false;
        for (const auto& existingMac : track.macs) {
            if (memcmp(existingMac.bytes.data(), session.mac, 6) == 0) {
                alreadyLinked = true;
                break;
            }
        }
        
        if (!alreadyLinked) {
            track.macs.push_back(MacAddress(session.mac));
            track.lastSeen = now;
            track.confidence = bestScore;
            track.sessionCount++;
            
            Serial.printf("[RAND] Linked %s to track %s (conf:%.2f matches:%d)\n",
                         macStr.c_str(), track.trackId, bestScore, bestMatches);
        }
        track.lastSeen = now;
        
    } else {
        if (deviceTracks.size() >= MAX_DEVICE_TRACKS) {
            cleanupStaleTracks();
            if (deviceTracks.size() >= MAX_DEVICE_TRACKS) {
                return;
            }
        }
        
        DeviceTrack newTrack;
        String trackId = generateTrackId();
        strncpy(newTrack.trackId, trackId.c_str(), sizeof(newTrack.trackId) - 1);
        newTrack.trackId[sizeof(newTrack.trackId) - 1] = '\0';
        
        newTrack.macs.push_back(MacAddress(session.mac));
        
        newTrack.firstSeen = session.startTime;
        newTrack.lastSeen = now;
        memcpy(newTrack.fingerprint, session.fingerprint, sizeof(newTrack.fingerprint));
        newTrack.confidence = 1.0;
        newTrack.sessionCount = 1;
        
        deviceTracks[trackId] = newTrack;
        
        Serial.printf("[RAND] New track %s for MAC %s\n", trackId.c_str(), macStr.c_str());
    }
}

// Cleanup stale sessions
void cleanupStaleSessions() {
    uint32_t now = millis();
    std::vector<String> toRemove;
    
    for (auto& entry : activeSessions) {
        uint32_t age = now - entry.second.lastSeen;
        
        if (age > SESSION_END_TIMEOUT) {
            linkSessionToTrack(entry.second);
            
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

// Cleanup stale tracks
void cleanupStaleTracks() {
    uint32_t now = millis();
    std::vector<String> toRemove;
    
    for (auto& entry : deviceTracks) {
        if (now - entry.second.lastSeen > TRACK_STALE_TIME) {
            toRemove.push_back(entry.first);
        }
    }
    
    for (const String& key : toRemove) {
        deviceTracks.erase(key);
    }
    
    if (!toRemove.empty()) {
        Serial.printf("[RAND] Cleaned up %d stale tracks\n", toRemove.size());
    }
}

// Get results
String getRandomizationResults() {
    String results = "MAC Randomization Detection Results\n\n";
    
    results += "Active Sessions: " + String(activeSessions.size()) + "\n";
    results += "Device Tracks: " + String(deviceTracks.size()) + "\n\n";
    
    if (deviceTracks.empty()) {
        results += "No device tracks detected.\n";
        return results;
    }
    
    std::vector<std::pair<String, DeviceTrack>> sortedTracks;
    for (const auto& entry : deviceTracks) {
        sortedTracks.push_back(entry);
    }
    
    std::sort(sortedTracks.begin(), sortedTracks.end(),
              [](const auto& a, const auto& b) {
                  return a.second.sessionCount > b.second.sessionCount;
              });
    
    for (const auto& entry : sortedTracks) {
        const DeviceTrack& track = entry.second;
        
        results += "Track ID: " + String(track.trackId) + "\n";
        results += "  Sessions: " + String(track.sessionCount) + "\n";
        results += "  Confidence: " + String(track.confidence, 2) + "\n";
        results += "  MACs:\n";
        
        int macCount = min((int)track.macs.size(), 10);
        for (int i = 0; i < macCount; i++) {
            const uint8_t* mac = track.macs[i].bytes.data();
            results += "    ";
            for (int j = 0; j < 6; j++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02X", mac[j]);
                results += String(hex);
                if (j < 5) results += ":";
            }
            results += "\n";
        }
        
        if ((int)track.macs.size() > 10) {
            results += "    ... (" + String(track.macs.size() - 10) + " more)\n";
        }
        
        uint32_t age = (millis() - track.lastSeen) / 1000;
        results += "  Last seen: " + String(age) + "s ago\n\n";
    }
    
    return results;
}

// Reset detection
void resetRandomizationDetection() {
    activeSessions.clear();
    deviceTracks.clear();
    trackIdCounter = 0;
    Serial.println("[RAND] Detection reset");
}

// Main detection task
void randomizationDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    
    Serial.printf("[RAND] Starting randomization detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());
    
    randomizationDetectionEnabled = true;
    scanning = true;
    activeSessions.clear();
    deviceTracks.clear();
    
    radioStartSTA();
    vTaskDelay(pdMS_TO_TICKS(500));
    
    uint32_t startTime = millis();
    uint32_t nextCleanup = startTime + 10000;
    uint32_t nextStatus = startTime + 5000;
    
    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {
        
        if ((int32_t)(millis() - nextCleanup) >= 0) {
            cleanupStaleSessions();
            cleanupStaleTracks();
            nextCleanup += 10000;
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[RAND] Sessions:%d Tracks:%d Heap:%u\n",
                         activeSessions.size(), deviceTracks.size(), ESP.getFreeHeap());
            nextStatus += 5000;
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Final session linking
    cleanupStaleSessions();
    
    randomizationDetectionEnabled = false;
    scanning = false;
    radioStopSTA();
    
    Serial.printf("[RAND] Detection complete. Tracks:%d\n", deviceTracks.size());
    
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}