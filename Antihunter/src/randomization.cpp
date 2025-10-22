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
extern void radioStartBLE();
extern void radioStopBLE();

std::mutex randMutex;

bool isRandomizedMAC(const uint8_t *mac) {
    return (mac[0] & 0x02) && !(mac[0] & 0x01);
}

bool isGlobalMAC(const uint8_t *mac) {
    return !(mac[0] & 0x02) && !(mac[0] & 0x01);
}

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

bool detectWiFiBLECorrelation(const uint8_t* wifiMac, const uint8_t* bleMac) {
    if (memcmp(wifiMac, bleMac, 3) != 0) {
        return false;
    }
    
    if ((wifiMac[0] & 0x02) != (bleMac[0] & 0x02)) {
        return false;
    }
    
    bool midBytesClose = (abs((int)wifiMac[3] - (int)bleMac[3]) <= 1) && 
                         (abs((int)wifiMac[4] - (int)bleMac[4]) <= 1);
    
    int wifiLast = wifiMac[5];
    int bleLast = bleMac[5];
    int lastDiff = abs(wifiLast - bleLast);
    
    return (lastDiff <= 1) && midBytesClose;
}

bool detectGlobalMACLeak(const ProbeSession& session, uint8_t* globalMac) {
    if ((session.mac[0] & 0x02) == 0) {
        memcpy(globalMac, session.mac, 6);
        return true;
    }
    return false;
}

float calculateRSSIDistributionSimilarity(const int8_t* rssi1, uint8_t count1,
                                         const int8_t* rssi2, uint8_t count2) {
    if (count1 < 3 || count2 < 3) return 0.0f;
    
    float mean1 = 0, mean2 = 0;
    for (uint8_t i = 0; i < count1; i++) mean1 += rssi1[i];
    for (uint8_t i = 0; i < count2; i++) mean2 += rssi2[i];
    mean1 /= count1;
    mean2 /= count2;
    
    float var1 = 0, var2 = 0;
    for (uint8_t i = 0; i < count1; i++) {
        float diff = rssi1[i] - mean1;
        var1 += diff * diff;
    }
    for (uint8_t i = 0; i < count2; i++) {
        float diff = rssi2[i] - mean2;
        var2 += diff * diff;
    }
    var1 /= count1;
    var2 /= count2;
    
    float meanDiff = abs(mean1 - mean2);
    float varSum = (var1 + var2) / 2.0f;
    
    if (varSum < 0.1f) return 0.0f;
    
    float similarity = exp(-0.25f * (meanDiff * meanDiff) / varSum);
    return similarity;
}

float calculateInterFrameTimingSimilarity(const uint32_t* times1, uint8_t count1,
                                         const uint32_t* times2, uint8_t count2) {
    if (count1 < 2 || count2 < 2) return 0.0f;
    
    std::vector<uint32_t> intervals1, intervals2;
    
    for (uint8_t i = 1; i < count1 && i < 50; i++) {
        if (times1[i] > times1[i-1]) {
            uint32_t interval = times1[i] - times1[i-1];
            if (interval > 0 && interval < 60000) {
                intervals1.push_back(interval);
            }
        }
    }
    
    for (uint8_t i = 1; i < count2 && i < 50; i++) {
        if (times2[i] > times2[i-1]) {
            uint32_t interval = times2[i] - times2[i-1];
            if (interval > 0 && interval < 60000) {
                intervals2.push_back(interval);
            }
        }
    }
    
    if (intervals1.size() < 2 || intervals2.size() < 2) return 0.0f;
    
    uint32_t sum1 = 0, sum2 = 0;
    for (auto& val : intervals1) sum1 += val;
    for (auto& val : intervals2) sum2 += val;
    
    float mean1 = (float)sum1 / intervals1.size();
    float mean2 = (float)sum2 / intervals2.size();
    
    float var1 = 0, var2 = 0;
    for (auto& val : intervals1) {
        float diff = val - mean1;
        var1 += diff * diff;
    }
    for (auto& val : intervals2) {
        float diff = val - mean2;
        var2 += diff * diff;
    }
    
    var1 /= intervals1.size();
    var2 /= intervals2.size();
    
    float std1 = sqrtf(var1);
    float std2 = sqrtf(var2);
    
    float cv1 = (mean1 > 0) ? (std1 / mean1) : 1.0f;
    float cv2 = (mean2 > 0) ? (std2 / mean2) : 1.0f;
    
    float cvDiff = abs(cv1 - cv2);
    float meanDiff = abs(mean1 - mean2);
    float meanAvg = (mean1 + mean2) / 2.0f;
    
    float cvScore = max(0.0f, 1.0f - (cvDiff / 0.5f));
    float meanScore = (meanAvg > 0) ? max(0.0f, 1.0f - (meanDiff / meanAvg)) : 0.0f;
    
    return (cvScore * 0.6f) + (meanScore * 0.4f);
}

void extractIEOrderSignature(const uint8_t *ieData, uint16_t ieLength, IEOrderSignature& sig) {
    memset(&sig, 0, sizeof(sig));
    
    uint16_t pos = 0;
    uint8_t idx = 0;
    
    while (pos + 2 <= ieLength && idx < 16) {
        uint8_t id = ieData[pos];
        uint8_t len = ieData[pos + 1];
        
        if (pos + 2 + len > ieLength) break;
        
        sig.ieTypes[idx++] = id;
        pos += 2 + len;
    }
    
    sig.ieCount = idx;
    sig.orderHash = computeCRC16(sig.ieTypes, sig.ieCount);
}

bool matchIEOrder(const IEOrderSignature& sig1, const IEOrderSignature& sig2) {
    if (sig1.ieCount == 0 || sig2.ieCount == 0) return false;
    if (sig1.orderHash == sig2.orderHash) return true;
    
    uint8_t matches = 0;
    uint8_t minCount = min(sig1.ieCount, sig2.ieCount);
    
    for (uint8_t i = 0; i < minCount; i++) {
        if (sig1.ieTypes[i] == sig2.ieTypes[i]) {
            matches++;
        }
    }
    
    return (matches >= minCount * 0.8f);
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

void extractBLEFingerprint(const NimBLEAdvertisedDevice* device, uint16_t fingerprint[6]) {
    memset(fingerprint, 0, 6 * sizeof(uint16_t));
    if (!device) return;
    
    uint8_t tempBuf[64] = {0};
    uint16_t bufPos = 0;
    
    if (device->haveManufacturerData() && bufPos < 48) {
        std::string mfgData = device->getManufacturerData();
        uint16_t copyLen = min((size_t)16, mfgData.length());
        memcpy(tempBuf + bufPos, mfgData.data(), copyLen);
        bufPos += copyLen;
    }
    
    if (device->haveServiceUUID() && bufPos < 48) {
        NimBLEUUID uuid = device->getServiceUUID();
        const uint8_t* uuidData = uuid.getValue();
        uint8_t uuidLen = uuid.bitSize() / 8;
        uint16_t copyLen = min((uint8_t)16, uuidLen);
        memcpy(tempBuf + bufPos, uuidData, copyLen);
        bufPos += copyLen;
    }
    
    if (device->haveServiceData() && bufPos < 48) {
        NimBLEUUID uuid = device->getServiceDataUUID();
        const uint8_t* uuidData = uuid.getValue();
        uint8_t uuidLen = uuid.bitSize() / 8;
        uint16_t copyLen = min((uint8_t)8, uuidLen);
        memcpy(tempBuf + bufPos, uuidData, copyLen);
        bufPos += copyLen;
    }
    
    if (bufPos > 0) {
        uint16_t seg1Len = min((uint16_t)16, bufPos);
        uint16_t seg2Len = bufPos > 16 ? min((uint16_t)16, (uint16_t)(bufPos - 16)) : 0;
        uint16_t seg3Len = bufPos > 32 ? min((uint16_t)16, (uint16_t)(bufPos - 32)) : 0;
        
        fingerprint[0] = seg1Len > 0 ? computeCRC16(tempBuf, seg1Len) : 0;
        fingerprint[1] = seg2Len > 0 ? computeCRC16(tempBuf + 16, seg2Len) : 0;
        fingerprint[2] = seg3Len > 0 ? computeCRC16(tempBuf + 32, seg3Len) : 0;
        fingerprint[3] = bufPos;
        fingerprint[4] = (fingerprint[0] ^ fingerprint[1]);
        fingerprint[5] = (fingerprint[0] + fingerprint[1] + fingerprint[2]) & 0xFFFF;
    }
}

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

void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel,
                        const uint8_t *payload, uint16_t length) {
    if (!randomizationDetectionEnabled || !probeRequestQueue) return;
    
    bool isRand = isRandomizedMAC(mac);
    bool isGlobal = isGlobalMAC(mac);
    
    if (!isRand && !isGlobal) {
        return;
    }
    
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


uint16_t extractSequenceNumber(const uint8_t *payload, uint16_t length) {
    if (length < 24) return 0;
    uint16_t seqCtrl = (payload[23] << 8) | payload[22];
    return (seqCtrl >> 4) & 0x0FFF;
}

bool detectMACRotationGap(const DeviceIdentity& identity, uint32_t currentTime) {
    uint32_t gap = currentTime - identity.lastSeen;
    return (gap >= MAC_ROTATION_GAP_MIN && gap <= MAC_ROTATION_GAP_MAX);
}

bool detectSequenceNumberAnomaly(const ProbeSession& session, const DeviceIdentity& identity) {
    if (!session.seqNumValid || !identity.sequenceValid) return false;
    
    uint16_t expectedDelta = (session.lastSeqNum >= identity.lastSequenceNum) ?
                             (session.lastSeqNum - identity.lastSequenceNum) :
                             (4096 + session.lastSeqNum - identity.lastSequenceNum);
    
    return (expectedDelta > 300 || expectedDelta == 0);
}

uint8_t calculateMACPrefixSimilarity(const uint8_t* mac1, const uint8_t* mac2) {
    uint8_t matches = 0;
    for (uint8_t i = 0; i < 4; i++) {
        if (mac1[i] == mac2[i]) {
            matches++;
        }
    }
    return matches;
}

void linkSessionToTrackBehavioral(ProbeSession& session) {
    String macStr = macFmt6(session.mac);
    uint32_t now = millis();
    
    if (session.linkedToIdentity) {
        return;
    }
    
    if (session.probeCount < 5) return;
    
    int16_t sessionRssiSum = 0;
    for (size_t i = 0; i < session.rssiReadings.size(); i++) {
        sessionRssiSum += session.rssiReadings[i];
    }
    int8_t sessionAvgRssi = session.rssiReadings.size() > 0 ?
                            sessionRssiSum / (int)session.rssiReadings.size() : 
                            session.rssiSum / max(1, (int)session.probeCount);
    
    float sessionIntervalConsistency = 0.0f;
    if (session.probeCount >= 3) {
        uint32_t intervals[49];
        uint8_t intervalCount = 0;
        for (uint8_t i = 1; i < min((uint8_t)50, session.probeCount); i++) {
            if (session.probeTimestamps[i] > session.probeTimestamps[i-1]) {
                intervals[intervalCount++] = session.probeTimestamps[i] - session.probeTimestamps[i-1];
            }
        }
        if (intervalCount >= 2) {
            sessionIntervalConsistency = calculateIntervalConsistency(intervals, intervalCount);
        }
    }
    
    float sessionRssiConsistency = calculateRssiConsistency(
        session.rssiReadings.data(), 
        min((uint8_t)20, (uint8_t)session.rssiReadings.size())
    );
    
    bool isBLE = (session.primaryChannel == 0);
    
    uint8_t globalMac[6];
    bool hasGlobalMac = false;
    if (!isBLE) {
        hasGlobalMac = detectGlobalMACLeak(session, globalMac);
    }
    
    Serial.printf("[RAND] Link eval %s: n:%d rssi:%d ic:%.2f rc:%.2f type:%s\n",
                 macStr.c_str(), session.probeCount, sessionAvgRssi,
                 sessionIntervalConsistency, sessionRssiConsistency, isBLE ? "BLE" : "WiFi");
    
    String bestIdentityKey;
    float bestScore = 0.0f;
    int8_t bestRssiDelta = 127;
    
    for (auto& identityEntry : deviceIdentities) {
        DeviceIdentity& identity = identityEntry.second;
        
        if (now - identity.lastSeen > TRACK_STALE_TIME) continue;
        
        bool alreadyLinked = false;
        for (const auto& existingMac : identity.macs) {
            if (memcmp(existingMac.bytes.data(), session.mac, 6) == 0) {
                alreadyLinked = true;
                break;
            }
        }
        if (alreadyLinked) continue;
        
        bool inRotationGap = detectMACRotationGap(identity, now);
        
        int16_t identityRssiSum = 0;
        for (uint8_t i = 0; i < identity.signature.rssiHistoryCount; i++) {
            identityRssiSum += identity.signature.rssiHistory[i];
        }
        int8_t identityAvgRssi = identity.signature.rssiHistoryCount > 0 ? 
                                 identityRssiSum / (int)identity.signature.rssiHistoryCount : 
                                 sessionAvgRssi;
        
        int8_t rssiDelta = abs(sessionAvgRssi - identityAvgRssi);
        uint32_t timeDelta = (now > identity.lastSeen) ? 
                             (now - identity.lastSeen) : (identity.lastSeen - now);
        
        float score = 0.0f;
        
        float rssiScore = 0.0f;
        if (rssiDelta <= 25) {
            rssiScore = 1.0f - (rssiDelta / 50.0f);
        }
        rssiScore *= 0.12f;
        
        float macPrefixScore = 0.0f;
        uint8_t prefixMatches = calculateMACPrefixSimilarity(session.mac, identity.macs[0].bytes.data());
        if (prefixMatches >= 3) {
            macPrefixScore = (float)prefixMatches / 4.0f;
        }
        macPrefixScore *= 0.35f;
        
        float fingerprintScore = 0.0f;
        uint8_t fpMatches = 0;
        if (matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fpMatches)) {
            fingerprintScore = (float)fpMatches / 4.0f;
        }
        fingerprintScore *= 0.15f;
        
        float ieOrderScore = 0.0f;
        if (matchIEOrder(session.ieOrder, identity.signature.ieOrder)) {
            ieOrderScore = 1.0f;
        }
        ieOrderScore *= 0.12f;
        
        float timingScore = 0.0f;
        if (sessionIntervalConsistency > 0.1f && identity.signature.intervalConsistency > 0.1f) {
            float timingDelta = abs(sessionIntervalConsistency - identity.signature.intervalConsistency);
            timingScore = max(0.0f, 1.0f - (timingDelta * 2.0f));
        }
        
        if (session.probeCount >= 2 && identity.observedSessions >= 1) {
            float interFrameScore = calculateInterFrameTimingSimilarity(
                session.probeTimestamps, min((uint8_t)50, session.probeCount),
                identity.signature.probeIntervals, identity.signature.intervalCount
            );
            timingScore = max(timingScore, interFrameScore);
        }
        timingScore *= 0.08f;
        
        float rssiDistScore = calculateRSSIDistributionSimilarity(
            session.rssiReadings.data(), session.rssiReadings.size(),
            identity.signature.rssiHistory, identity.signature.rssiHistoryCount
        );
        rssiDistScore *= 0.08f;
        
        float seqNumScore = 0.0f;
        if (!isBLE && session.seqNumValid && identity.sequenceValid) {
            uint16_t seqDelta = (session.lastSeqNum > identity.lastSequenceNum) ?
                               (session.lastSeqNum - identity.lastSequenceNum) :
                               (4096 + session.lastSeqNum - identity.lastSequenceNum);
            
            if (seqDelta < 100) {
                seqNumScore = 1.0f - (seqDelta / 100.0f);
            }
        }
        seqNumScore *= 0.05f;
        
        float rotationGapScore = 0.0f;
        if (inRotationGap) {
            rotationGapScore = 1.0f;
        } else if (timeDelta < MAC_ROTATION_GAP_MIN) {
            rotationGapScore = 0.5f;
        }
        rotationGapScore *= 0.03f;
        
        float globalMacScore = 0.0f;
        if (hasGlobalMac && identity.hasKnownGlobalMac) {
            if (memcmp(globalMac, identity.knownGlobalMac, 6) == 0) {
                globalMacScore = 1.0f;
            }
        }
        globalMacScore *= 0.02f;
        
        score = rssiScore + macPrefixScore + fingerprintScore + ieOrderScore + timingScore + 
                rssiDistScore + seqNumScore + rotationGapScore + globalMacScore;
        
        if (score > 0.1f) {
            Serial.printf("[RAND]   vs %s: %.3f (r:%.2f mp:%.2f fp:%.2f ie:%.2f t:%.2f rd:%.2f s:%.2f g:%.2f rg:%.2f) dR:%d dt:%u\n",
                         identity.identityId, score, rssiScore, macPrefixScore, fingerprintScore, ieOrderScore,
                         timingScore, rssiDistScore, seqNumScore, globalMacScore, rotationGapScore,
                         rssiDelta, timeDelta);
        }
        
        if (score > bestScore) {
            bestScore = score;
            bestIdentityKey = identityEntry.first;
            bestRssiDelta = rssiDelta;
        }
    }
    
    float confidenceThreshold = (deviceIdentities.empty() || session.probeCount < 8) ? 
                                CONFIDENCE_THRESHOLD_NEW_SESSION : CONFIDENCE_THRESHOLD_ESTABLISHED;
    
    if (bestScore >= confidenceThreshold && !bestIdentityKey.isEmpty()) {
        DeviceIdentity& identity = deviceIdentities[bestIdentityKey];
        
        if (identity.macs.size() >= 50) return;
        
        identity.macs.push_back(MacAddress(session.mac));
        identity.confidence = min(1.0f, identity.confidence * 0.7f + bestScore * 0.3f);
        identity.observedSessions++;
        
        if (session.rssiReadings.size() > 0 && identity.signature.rssiHistoryCount < 20) {
            for (size_t i = 0; i < session.rssiReadings.size() && 
                 identity.signature.rssiHistoryCount < 20; i++) {
                identity.signature.rssiHistory[identity.signature.rssiHistoryCount++] = 
                    session.rssiReadings[i];
            }
        }
        
        if (session.probeCount >= 2 && identity.signature.intervalCount < 20) {
            for (uint8_t i = 1; i < min((uint8_t)50, session.probeCount) && 
                 identity.signature.intervalCount < 20; i++) {
                if (session.probeTimestamps[i] > session.probeTimestamps[i-1]) {
                    identity.signature.probeIntervals[identity.signature.intervalCount++] = 
                        session.probeTimestamps[i] - session.probeTimestamps[i-1];
                }
            }
        }
        
        if (sessionIntervalConsistency > 0.0f) {
            identity.signature.intervalConsistency = 
                (identity.signature.intervalConsistency * 0.7f) + (sessionIntervalConsistency * 0.3f);
        }
        
        if (sessionRssiConsistency > 0.0f) {
            identity.signature.rssiConsistency = 
                (identity.signature.rssiConsistency * 0.7f) + (sessionRssiConsistency * 0.3f);
        }
        
        if (!isBLE && session.seqNumValid) {
            identity.lastSequenceNum = session.lastSeqNum;
            identity.sequenceValid = true;
        }
        
        if (hasGlobalMac && !identity.hasKnownGlobalMac) {
            memcpy(identity.knownGlobalMac, globalMac, 6);
            identity.hasKnownGlobalMac = true;
        }
        
        identity.signature.channelBitmap |= session.channelMask;
        identity.lastSeen = now;
        
        session.linkedToIdentity = true;
        strncpy(session.linkedIdentityId, identity.identityId, sizeof(session.linkedIdentityId) - 1);
        
        Serial.printf("[RAND] Linked %s -> %s (score:%.3f dR:%d macs:%d conf:%.2f)\n",
                     macStr.c_str(), identity.identityId, bestScore,
                     bestRssiDelta, identity.macs.size(), identity.confidence);
        
    } else {
        if (deviceIdentities.size() >= MAX_DEVICE_TRACKS) {
            return;
        }
        
        DeviceIdentity newIdentity;
        String identityId = generateTrackId();
        strncpy(newIdentity.identityId, identityId.c_str(), sizeof(newIdentity.identityId) - 1);
        newIdentity.identityId[sizeof(newIdentity.identityId) - 1] = '\0';

        newIdentity.macs.push_back(MacAddress(session.mac));

        memcpy(newIdentity.knownGlobalMac, session.mac, 6);
        newIdentity.hasKnownGlobalMac = true;
        
        newIdentity.signature.rssiHistoryCount = 0;
        for (size_t i = 0; i < session.rssiReadings.size() && newIdentity.signature.rssiHistoryCount < 20; i++) {
            newIdentity.signature.rssiHistory[newIdentity.signature.rssiHistoryCount++] = 
                session.rssiReadings[i];
        }
        
        newIdentity.signature.intervalCount = 0;
        for (uint8_t i = 1; i < min((uint8_t)50, session.probeCount) && 
             newIdentity.signature.intervalCount < 20; i++) {
            if (session.probeTimestamps[i] > session.probeTimestamps[i-1]) {
                newIdentity.signature.probeIntervals[newIdentity.signature.intervalCount++] = 
                    session.probeTimestamps[i] - session.probeTimestamps[i-1];
            }
        }
        
        memcpy(newIdentity.signature.ieFingerprint, session.fingerprint, sizeof(session.fingerprint));
        newIdentity.signature.ieOrder = session.ieOrder;
        
        newIdentity.signature.intervalConsistency = sessionIntervalConsistency;
        newIdentity.signature.rssiConsistency = sessionRssiConsistency;
        newIdentity.signature.channelBitmap = session.channelMask;
        
        if (!isBLE && session.seqNumValid) {
            newIdentity.lastSequenceNum = session.lastSeqNum;
            newIdentity.sequenceValid = true;
        }
        
        if (hasGlobalMac) {
            memcpy(newIdentity.knownGlobalMac, globalMac, 6);
            newIdentity.hasKnownGlobalMac = true;
        }
        
        newIdentity.firstSeen = now;
        newIdentity.lastSeen = now;
        newIdentity.confidence = 0.5f;
        newIdentity.sessionCount = 1;
        newIdentity.observedSessions = 1;
        
        deviceIdentities[macStr] = newIdentity;
        
        session.linkedToIdentity = true;
        strncpy(session.linkedIdentityId, newIdentity.identityId, sizeof(session.linkedIdentityId) - 1);
        
        Serial.printf("[RAND] New %s from %s (n:%d rssi:%d ic:%.2f type:%s)\n",
                     newIdentity.identityId, macStr.c_str(), session.probeCount, 
                     sessionAvgRssi, sessionIntervalConsistency, isBLE ? "BLE" : "WiFi");
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
    
    for (const auto& key : toRemove) {
        activeSessions.erase(key);
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
    
    for (const auto& key : toRemove) {
        deviceIdentities.erase(key);
    }
}

void resetRandomizationDetection() {
    std::lock_guard<std::mutex> lock(randMutex);
    activeSessions.clear();
    deviceIdentities.clear();
    identityIdCounter = 0;
}

String getRandomizationResults() {
    std::lock_guard<std::mutex> lock(randMutex);
    
    String results = "MAC Randomization Detection Results\n";
    results += "Active Sessions: " + String(activeSessions.size()) + "\n";
    results += "Device Identities: " + String(deviceIdentities.size()) + "\n\n";
    
    for (const auto& entry : deviceIdentities) {
        const DeviceIdentity& identity = entry.second;
        
        results += "Track ID: " + String(identity.identityId) + "\n";
        results += "  MACs linked: " + String(identity.macs.size()) + "\n";
        results += "  Confidence: " + String(identity.confidence, 2) + "\n";
        results += "  Sessions: " + String(identity.observedSessions) + "\n";
        results += "  Interval consistency: " + String(identity.signature.intervalConsistency, 2) + "\n";
        results += "  RSSI consistency: " + String(identity.signature.rssiConsistency, 2) + "\n";
        results += "  Channels: " + String(countChannels(identity.signature.channelBitmap)) + "\n";
        
        if (identity.hasKnownGlobalMac) {
            results += "  Global MAC: " + macFmt6(identity.knownGlobalMac) + "\n";
        }
        
        uint32_t age = (millis() - identity.lastSeen) / 1000;
        results += "  Last seen: " + String(age) + "s ago\n";
        
        results += "  MACs: ";
        for (size_t i = 0; i < min((size_t)5, identity.macs.size()); i++) {
            results += macFmt6(identity.macs[i].bytes.data());
            if (i < min((size_t)5, identity.macs.size()) - 1) results += ", ";
        }
        if (identity.macs.size() > 5) {
            results += " (+" + String(identity.macs.size() - 5) + " more)";
        }
        results += "\n\n";
    }
    
    return results;
}

void randomizationDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    
    Serial.printf("[RAND] Starting detection for %s\n", forever ? "forever" : (String(duration) + "s").c_str());
    
    if (probeRequestQueue) {
        vQueueDelete(probeRequestQueue);
        probeRequestQueue = nullptr;
    }
    
    probeRequestQueue = xQueueCreate(512, sizeof(ProbeRequestEvent));
    if (!probeRequestQueue) {
        Serial.println("[RAND] FATAL: Failed to create queue");
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(randMutex);
        
        uint32_t now = millis();
        std::vector<String> staleSessions;
        std::vector<String> staleIdentities;
        
        for (auto& entry : activeSessions) {
            if (now - entry.second.lastSeen > SESSION_CLEANUP_AGE) {
                staleSessions.push_back(entry.first);
            }
        }
        
        for (auto& entry : deviceIdentities) {
            if (now - entry.second.lastSeen > TRACK_STALE_TIME) {
                staleIdentities.push_back(entry.first);
            }
        }
        
        for (const auto& key : staleSessions) {
            activeSessions.erase(key);
        }
        
        for (const auto& key : staleIdentities) {
            deviceIdentities.erase(key);
        }
        
        Serial.printf("[RAND] Cleanup: Removed %d stale sessions, %d stale identities. Retained: %d sessions, %d identities\n",
                     staleSessions.size(), staleIdentities.size(), 
                     activeSessions.size(), deviceIdentities.size());
    }
    
    randomizationDetectionEnabled = true;
    scanning = true;
    
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (currentScanMode == SCAN_BLE) {
        WiFi.mode(WIFI_AP);
        delay(100);
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (currentScanMode == SCAN_BOTH) {
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    uint32_t startTime = millis();
    uint32_t nextStatus = startTime + 5000;
    uint32_t nextCleanup = startTime + 30000;
    uint32_t nextResultsUpdate = startTime + 2000;
    uint32_t lastBLEScan = 0;
    const uint32_t BLE_SCAN_INTERVAL = 3000;
    
    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {
        
        if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
            ProbeRequestEvent event;
            int processedCount = 0;
            
            while (processedCount < 100 && xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE) {
                processedCount++;
                
                String macStr = macFmt6(event.mac);
                uint32_t now = millis();
                
                std::lock_guard<std::mutex> lock(randMutex);
                
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
                    session.primaryChannel = 0;
                    session.channelMask = 0;
                    session.rssiReadings.push_back(event.rssi);
                    session.probeTimestamps[0] = now;
                    session.linkedToIdentity = false;
                    memset(session.linkedIdentityId, 0, sizeof(session.linkedIdentityId));
                    session.seqNumGaps = 0;
                    session.seqNumWraps = 0;
                    session.hasGlobalMacLeak = false;
                    
                    if (event.payloadLen >= 24) {
                        session.lastSeqNum = extractSequenceNumber(event.payload, event.payloadLen);
                        session.seqNumValid = true;
                        
                        const uint8_t *ieStart = event.payload + 24;
                        uint16_t ieLength = event.payloadLen - 24;
                        extractIEFingerprint(ieStart, ieLength, session.fingerprint);
                        extractIEOrderSignature(ieStart, ieLength, session.ieOrder);
                    } else {
                        session.lastSeqNum = 0;
                        session.seqNumValid = false;
                        memset(session.fingerprint, 0, sizeof(session.fingerprint));
                        memset(&session.ieOrder, 0, sizeof(session.ieOrder));
                    }
                    
                    activeSessions[macStr] = session;
                    Serial.printf("[RAND] WiFi session %s rssi:%d\n", macStr.c_str(), event.rssi);
                    
                } else {
                    ProbeSession& session = activeSessions[macStr];
                    
                    if (session.probeCount < 50) {
                        session.probeTimestamps[session.probeCount] = now;
                    }
                    
                    if (event.payloadLen >= 24) {
                        uint16_t newSeqNum = extractSequenceNumber(event.payload, event.payloadLen);
                        
                        if (session.seqNumValid) {
                            uint16_t expectedNext = (session.lastSeqNum + 1) & 0x0FFF;
                            if (newSeqNum != expectedNext) {
                                if (newSeqNum < session.lastSeqNum) {
                                    session.seqNumWraps++;
                                } else {
                                    uint16_t gap = newSeqNum - session.lastSeqNum;
                                    if (gap > 10) {
                                        session.seqNumGaps++;
                                    }
                                }
                            }
                        }
                        
                        session.lastSeqNum = newSeqNum;
                        session.seqNumValid = true;
                    }
                    
                    session.lastSeen = now;
                    session.rssiSum += event.rssi;
                    session.rssiMin = min(session.rssiMin, event.rssi);
                    session.rssiMax = max(session.rssiMax, event.rssi);
                    session.probeCount++;

                    if (session.rssiReadings.size() < 20) {
                        session.rssiReadings.push_back(event.rssi);
                    }

                    if (session.probeCount >= 8 && (now - session.startTime) >= 5000 && !session.linkedToIdentity) {
                        linkSessionToTrackBehavioral(session);
                    }
                }
            }
        }
        
        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && 
            pBLEScan && (millis() - lastBLEScan >= BLE_SCAN_INTERVAL)) {
            lastBLEScan = millis();
            
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            
            if (scanResults.getCount() > 0) {
                std::lock_guard<std::mutex> lock(randMutex);
                
                for (int i = 0; i < scanResults.getCount(); i++) {
                    const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                    
                    const uint8_t* macBytes = device->getAddress().getVal();
                    uint8_t mac[6];
                    memcpy(mac, macBytes, 6);
                    
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
                        session.linkedToIdentity = false;
                        memset(session.linkedIdentityId, 0, sizeof(session.linkedIdentityId));
                        session.seqNumValid = false;
                        session.lastSeqNum = 0;
                        session.seqNumGaps = 0;
                        session.seqNumWraps = 0;
                        session.hasGlobalMacLeak = false;
                        
                        extractBLEFingerprint(device, session.fingerprint);
                        memset(&session.ieOrder, 0, sizeof(session.ieOrder));
                        
                        activeSessions[macStr] = session;
                        Serial.printf("[RAND] BLE session %s rssi:%d\n", macStr.c_str(), rssi);

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

                        if (session.probeCount >= 10 && (now - session.startTime) >= 8000 && !session.linkedToIdentity) {
                            linkSessionToTrackBehavioral(session);
                        }
                    }
                }
                
                pBLEScan->clearResults();
            }
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            std::lock_guard<std::mutex> lock(randMutex);
            Serial.printf("[RAND] Sessions:%d Identities:%d Heap:%lu\n",
                         activeSessions.size(), deviceIdentities.size(), ESP.getFreeHeap());
            nextStatus += 5000;
        }
        
        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            antihunter::lastResults = getRandomizationResults().c_str();
            nextResultsUpdate += 2000;
        }
        
        if ((int32_t)(millis() - nextCleanup) >= 0) {
            cleanupStaleSessions();
            nextCleanup += 30000;
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    randomizationDetectionEnabled = false;
    scanning = false;
    
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStopBLE();
    }
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStopSTA();
    }
    delay(100);
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = getRandomizationResults().c_str();
    }
    
    if (probeRequestQueue) {
        vQueueDelete(probeRequestQueue);
        probeRequestQueue = nullptr;
    }
    
    Serial.println("[RAND] Detection complete, results stored");
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}