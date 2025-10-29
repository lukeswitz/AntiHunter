#include "randomization.h"
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"
#include <algorithm>
#include <cmath>
#include <mutex>

#include <SD.h>
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
    if (!isRandomizedMAC(session.mac)) {
        return false;
    }
    
    for (const auto& entry : activeSessions) {
        const ProbeSession& candidate = entry.second;
        if (isRandomizedMAC(candidate.mac)) continue;
        if (!isGlobalMAC(candidate.mac)) continue;
        
        uint32_t timeDelta = (session.lastSeen > candidate.lastSeen) ?
                            (session.lastSeen - candidate.lastSeen) :
                            (candidate.lastSeen - session.lastSeen);
        if (timeDelta > 30000) continue;
        
        bool seqMatch = false;
        if (session.seqNumValid && candidate.seqNumValid) {
            uint16_t seqDelta = (session.lastSeqNum >= candidate.lastSeqNum) ?
                               (session.lastSeqNum - candidate.lastSeqNum) :
                               ((4096 + session.lastSeqNum - candidate.lastSeqNum) & 0x0FFF);
            seqMatch = (seqDelta > 0 && seqDelta < 200);
        }
        
        uint8_t fpMatches = 0;
        bool fpMatch = matchFingerprints(session.fingerprint, candidate.fingerprint, fpMatches);
        
        if (seqMatch || (fpMatch && fpMatches >= 2)) {
            memcpy(globalMac, candidate.mac, 6);
            return true;
        }
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

float calculateSignatureSetSimilarity(const ProbeSession& session, const DeviceIdentity& identity) {
    uint8_t fpMatches = 0;
    float fpScore = 0.0f;
    
    if (matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fpMatches)) {
        fpScore = (float)fpMatches / 6.0f;
    }
    
    float ieOrderScore = matchIEOrder(session.ieOrder, identity.signature.ieOrder) ? 1.0f : 0.0f;
    
    return (fpScore * 0.6f) + (ieOrderScore * 0.4f);
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

void updateDeviceSignatureSet(DeviceIdentity& identity, const ProbeSession& session) {
    bool signatureExists = false;
    
    uint8_t fpMatches = 0;
    if (matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fpMatches)) {
        if (fpMatches >= 4) {
            signatureExists = true;
        }
    }
    
    if (!signatureExists) {
        if (session.rssiReadings.size() > 0) {
            uint8_t addCount = min((size_t)(20 - identity.signature.rssiHistoryCount), 
                                   session.rssiReadings.size());
            for (size_t i = 0; i < addCount; i++) {
                identity.signature.rssiHistory[identity.signature.rssiHistoryCount++] = 
                    session.rssiReadings[i];
            }
        }
        
        for (uint8_t i = 1; i < min((uint8_t)50, session.probeCount) && 
             identity.signature.intervalCount < 20; i++) {
            if (session.probeTimestamps[i] > session.probeTimestamps[i-1]) {
                identity.signature.probeIntervals[identity.signature.intervalCount++] = 
                    session.probeTimestamps[i] - session.probeTimestamps[i-1];
            }
        }
    }
    
    identity.signature.channelBitmap |= session.channelMask;
    identity.signature.observationCount++;
    identity.signature.lastObserved = millis();
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
            case 1:   // Supported Rates
            case 50:  // Extended Supported Rates - merge em
                if (ratesLen + len <= 16) {
                    memcpy(ratesBuf + ratesLen, ieBody, len);
                    ratesLen += len;
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
                    size_t copyLen = min((int)len, 8);
                    memcpy(vendorBuf + vendorLen, ieBody, copyLen);
                    vendorLen += copyLen;
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

bool isMinimalSignature(const uint16_t fingerprint[6]) {
    uint8_t nonZero = 0;
    for(int i = 0; i < 4; i++) {
        if(fingerprint[i] != 0) nonZero++;
    }
    return nonZero <= 1;
}

bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches) {
    matches = 0;
    
    bool fp1Minimal = isMinimalSignature(fp1);
    bool fp2Minimal = isMinimalSignature(fp2);
    
    for (int i = 0; i < 5; i++) {
        if (fp1[i] != 0 && fp2[i] != 0 && fp1[i] == fp2[i]) {
            matches++;
        }
    }
    
    if(fp1Minimal || fp2Minimal) {
        return matches >= 1;
    }
    
    return matches >= FINGERPRINT_MATCH_THRESHOLD;
}

void extractChannelSequence(const ProbeSession& session, uint8_t* channelSeq, uint8_t& seqLen) {
    seqLen = 0;
    for(uint8_t i = 0; i < session.probeCount && seqLen < 32; i++) {
        uint8_t ch = (session.channelMask >> i) & 0x1 ? i : 0;
        if(ch > 0) {
            channelSeq[seqLen++] = ch;
        }
    }
}

float calculateChannelSequenceSimilarity(const uint8_t* seq1, uint8_t len1, 
                                        const uint8_t* seq2, uint8_t len2) {
    if(len1 == 0 || len2 == 0) return 0.0f;
    
    uint8_t maxLen = max(len1, len2);
    uint8_t minLen = min(len1, len2);
    
    if(maxLen == 0) return 0.0f;
    
    float dotProduct = 0.0f;
    float mag1 = 0.0f;
    float mag2 = 0.0f;
    
    for(uint8_t i = 0; i < maxLen; i++) {
        float v1 = (i < len1) ? (float)seq1[i] : 0.0f;
        float v2 = (i < len2) ? (float)seq2[i] : 0.0f;
        dotProduct += v1 * v2;
        mag1 += v1 * v1;
        mag2 += v2 * v2;
    }
    
    float magnitude = sqrt(mag1) * sqrt(mag2);
    return (magnitude > 0.0f) ? (dotProduct / magnitude) : 0.0f;
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
    if (identity.isBLE) {
        return (gap >= MAC_ROTATION_GAP_MIN_BLE && gap <= MAC_ROTATION_GAP_MAX_BLE);
    }
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

void correlateAuthFrameToRandomizedSession(const uint8_t* globalMac, int8_t rssi, 
                                           uint8_t channel, const uint8_t* frame, uint16_t frameLen) {
    std::lock_guard<std::mutex> lock(randMutex);
    
    uint32_t now = millis();
    uint16_t seqNum = extractSequenceNumber(frame, frameLen);
    
    String bestSessionKey;
    float bestScore = 0.0f;
    
    for (auto& sessionEntry : activeSessions) {
        ProbeSession& session = sessionEntry.second;
        
        if (!isRandomizedMAC(session.mac)) continue;
        if (session.linkedToIdentity) continue;
        if ((now - session.lastSeen) > 30000) continue;
        if (session.probeCount < 1) continue; // TODO fix this, right now all shall pass
        
        float score = 0.0f;
        
        if (session.seqNumValid && seqNum > 0) {
            uint16_t seqDelta = (seqNum >= session.lastSeqNum) ?
                               (seqNum - session.lastSeqNum) :
                               ((4096 + seqNum - session.lastSeqNum) & 0x0FFF);
            
            if (seqDelta < 100) {
                score += 0.60f * (1.0f - (seqDelta / 100.0f));
            }
        }
        
        int8_t sessionAvgRssi = session.rssiReadings.size() > 0 ?
                               session.rssiSum / (int)session.rssiReadings.size() : 
                               session.rssiSum / max(1, (int)session.probeCount);
        int8_t rssiDelta = abs(rssi - sessionAvgRssi);
        if (rssiDelta < 20) {
            score += 0.25f * (1.0f - (rssiDelta / 40.0f));
        }
        
        uint32_t timeDelta = now - session.lastSeen;
        if (timeDelta < 15000) {
            score += 0.15f * (1.0f - (timeDelta / 15000.0f));
        }
        
        if (score > bestScore) {
            bestScore = score;
            bestSessionKey = sessionEntry.first;
        }
    }
    
    if (bestScore > 0.40f && !bestSessionKey.isEmpty()) {
        ProbeSession& session = activeSessions[bestSessionKey];
        
        session.hasGlobalMacLeak = true;
        memcpy(session.globalMacLeaked, globalMac, 6);
        
        Serial.printf("[RAND] AUTH LEAK: %s->%s sc:%.2f sq:%d->%d\n",
                     macFmt6(session.mac).c_str(), macFmt6(globalMac).c_str(),
                     bestScore, session.lastSeqNum, seqNum);

        if (session.probeCount < 8) session.probeCount = 8;
        linkSessionToTrackBehavioral(session);
    }
}

void linkSessionToTrackBehavioral(ProbeSession& session) {
    if (session.linkedToIdentity) return; // bail if already linked
    
    // if (!isRandomizedMAC(session.mac)) return;
    
    // if (session.probeCount < 1) return; // let all though, for speed
    
    // std::lock_guard<std::mutex> lock(randMutex);
    
    String macStr = macFmt6(session.mac);
    uint32_t now = millis();
    
    bool sessionIsMinimal = isMinimalSignature(session.fingerprint);
    
    uint8_t sessionChannelSeq[20];
    uint8_t sessionChannelSeqLen = 0;
    extractChannelSequence(session, sessionChannelSeq, sessionChannelSeqLen);
    
    int16_t sessionRssiSum = 0;
    for (const auto& rssi : session.rssiReadings) {
        sessionRssiSum += rssi;
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
    
    if (!hasGlobalMac && session.hasGlobalMacLeak) {
        hasGlobalMac = true;
        memcpy(globalMac, session.globalMacLeaked, 6);
    }
    
    Serial.printf("[RAND] Link eval %s: n:%d rssi:%d ic:%.2f rc:%.2f type:%s sig:%s\n",
                 macStr.c_str(), session.probeCount, sessionAvgRssi,
                 sessionIntervalConsistency, sessionRssiConsistency, isBLE ? "BLE" : "WiFi",
                 sessionIsMinimal ? "MIN" : "FULL");
    
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
        rssiScore *= 0.10f;
        
        float macPrefixScore = 0.0f;
        uint8_t prefixMatches = calculateMACPrefixSimilarity(session.mac, identity.macs[0].bytes.data());
        if (prefixMatches >= 3) {
            macPrefixScore = (float)prefixMatches / 4.0f;
        }
        macPrefixScore *= 0.30f;
        
        float fingerprintScore = 0.0f;
        uint8_t fpMatches = 0;
        bool fpMatch = false;
        
        if(sessionIsMinimal && identity.signature.hasMinimalSignature) {
            fpMatch = matchFingerprints(session.fingerprint, identity.signature.ieFingerprintMinimal, fpMatches);
        } else if(!sessionIsMinimal && identity.signature.hasFullSignature) {
            fpMatch = matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fpMatches);
        } else if(identity.signature.hasFullSignature && identity.signature.hasMinimalSignature) {
            uint8_t fullMatches = 0, minMatches = 0;
            bool fullMatch = matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fullMatches);
            bool minMatch = matchFingerprints(session.fingerprint, identity.signature.ieFingerprintMinimal, minMatches);
            fpMatch = fullMatch || minMatch;
            fpMatches = max(fullMatches, minMatches);
        } else {
            fpMatch = matchFingerprints(session.fingerprint, identity.signature.ieFingerprint, fpMatches);
        }
        
        if (fpMatch) {
            fingerprintScore = (float)fpMatches / 5.0f;
        }
        fingerprintScore *= 0.12f;
        
        float ieOrderScore = 0.0f;
        if(sessionIsMinimal && identity.signature.hasMinimalSignature) {
            if(matchIEOrder(session.ieOrder, identity.signature.ieOrderMinimal)) {
                ieOrderScore = 1.0f;
            }
        } else if(!sessionIsMinimal && identity.signature.hasFullSignature) {
            if(matchIEOrder(session.ieOrder, identity.signature.ieOrder)) {
                ieOrderScore = 1.0f;
            }
        } else {
            if(matchIEOrder(session.ieOrder, identity.signature.ieOrder) ||
               matchIEOrder(session.ieOrder, identity.signature.ieOrderMinimal)) {
                ieOrderScore = 1.0f;
            }
        }
        ieOrderScore *= 0.10f;
        
        float channelSeqScore = 0.0f;
        if(sessionChannelSeqLen > 0 && identity.signature.channelSeqLength > 0) {
            channelSeqScore = calculateChannelSequenceSimilarity(
                sessionChannelSeq, sessionChannelSeqLen,
                identity.signature.channelSequence, identity.signature.channelSeqLength
            );
        }
        channelSeqScore *= 0.10f;
        
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
        globalMacScore *= 0.04f;
        
        score = rssiScore + macPrefixScore + fingerprintScore + ieOrderScore + channelSeqScore +
                timingScore + rssiDistScore + seqNumScore + rotationGapScore + globalMacScore;
        
        if (score > 0.1f) {
            Serial.printf("[RAND]   vs %s: %.3f (r:%.2f mp:%.2f fp:%.2f[%d] ie:%.2f ch:%.2f t:%.2f rd:%.2f s:%.2f g:%.2f rg:%.2f) sig:%s/%s\n",
                         identity.identityId, score, rssiScore, macPrefixScore, fingerprintScore, fpMatches, ieOrderScore,
                         channelSeqScore, timingScore, rssiDistScore, seqNumScore, globalMacScore, rotationGapScore,
                         identity.signature.hasFullSignature ? "F" : "-",
                         identity.signature.hasMinimalSignature ? "M" : "-");
        }
        
        if (score > bestScore) {
            bestScore = score;
            bestIdentityKey = identityEntry.first;
            bestRssiDelta = rssiDelta;
        }
    }
    
    float confidenceThreshold = CONFIDENCE_THRESHOLD_ESTABLISHED;
    
    if (deviceIdentities.empty() || session.probeCount < 8) {
        confidenceThreshold = CONFIDENCE_THRESHOLD_NEW_SESSION;
    }
    
    if (bestScore >= confidenceThreshold && !bestIdentityKey.isEmpty()) {
        DeviceIdentity& identity = deviceIdentities[bestIdentityKey];
        
        if (identity.macs.size() >= 50) return;
        
        if(sessionIsMinimal && !identity.signature.hasMinimalSignature) {
            memcpy(identity.signature.ieFingerprintMinimal, session.fingerprint, sizeof(session.fingerprint));
            identity.signature.ieOrderMinimal = session.ieOrder;
            identity.signature.hasMinimalSignature = true;
        } else if(!sessionIsMinimal && !identity.signature.hasFullSignature) {
            memcpy(identity.signature.ieFingerprint, session.fingerprint, sizeof(session.fingerprint));
            identity.signature.ieOrder = session.ieOrder;
            identity.signature.hasFullSignature = true;
        }
        
        if(sessionChannelSeqLen > 0 && identity.signature.channelSeqLength == 0) {
            memcpy(identity.signature.channelSequence, sessionChannelSeq, sessionChannelSeqLen);
            identity.signature.channelSeqLength = sessionChannelSeqLen;
        }
        
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
        
        Serial.printf("[RAND] Linked %s -> %s (score:%.3f dR:%d macs:%d conf:%.2f sig:%s)\n",
                     macStr.c_str(), identity.identityId, bestScore,
                     bestRssiDelta, identity.macs.size(), identity.confidence,
                     sessionIsMinimal ? "MIN" : "FULL");
        
     } else {
        if (deviceIdentities.size() >= MAX_DEVICE_TRACKS) {
            return;
        }
        
        for (const auto& existingEntry : deviceIdentities) {
            const DeviceIdentity& existingIdentity = existingEntry.second;
            for (const auto& existingMac : existingIdentity.macs) {
                if (memcmp(existingMac.bytes.data(), session.mac, 6) == 0) {
                    Serial.printf("[RAND] MAC %s already in %s, skipping new identity\n",
                                macStr.c_str(), existingIdentity.identityId);
                    return;
                }
            }
        }
        
        DeviceIdentity newIdentity;
        String identityId = generateTrackId();
        strncpy(newIdentity.identityId, identityId.c_str(), sizeof(newIdentity.identityId) - 1);
        newIdentity.identityId[sizeof(newIdentity.identityId) - 1] = '\0';

        newIdentity.macs.push_back(MacAddress(session.mac));
        newIdentity.isBLE = isBLE;

        if(sessionIsMinimal) {
            memcpy(newIdentity.signature.ieFingerprintMinimal, session.fingerprint, sizeof(session.fingerprint));
            newIdentity.signature.ieOrderMinimal = session.ieOrder;
            newIdentity.signature.hasMinimalSignature = true;
            newIdentity.signature.hasFullSignature = false;
        } else {
            memcpy(newIdentity.signature.ieFingerprint, session.fingerprint, sizeof(session.fingerprint));
            newIdentity.signature.ieOrder = session.ieOrder;
            newIdentity.signature.hasFullSignature = true;
            newIdentity.signature.hasMinimalSignature = false;
        }
        
        if(sessionChannelSeqLen > 0) {
            memcpy(newIdentity.signature.channelSequence, sessionChannelSeq, sessionChannelSeqLen);
            newIdentity.signature.channelSeqLength = sessionChannelSeqLen;
        }
        
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
        newIdentity.confidence = 1.0f;
        newIdentity.sessionCount = 1;
        newIdentity.observedSessions = 1;
        
        deviceIdentities[macStr] = newIdentity;
        
        session.linkedToIdentity = true;
        strncpy(session.linkedIdentityId, newIdentity.identityId, sizeof(session.linkedIdentityId) - 1);
        
        Serial.printf("[RAND] New %s from %s (n:%d rssi:%d ic:%.2f type:%s sig:%s)\n",
                     newIdentity.identityId, macStr.c_str(), session.probeCount, 
                     sessionAvgRssi, sessionIntervalConsistency, isBLE ? "BLE" : "WiFi",
                     sessionIsMinimal ? "MIN" : "FULL");
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
        results += "  Type: " + String(identity.isBLE ? "BLE Device" : "WiFi Device") + "\n";
        results += "  MACs linked: " + String(identity.macs.size()) + "\n";
        results += "  Confidence: " + String(identity.confidence, 2) + "\n";
        results += "  Sessions: " + String(identity.observedSessions) + "\n";
        results += "  Signatures: ";
        if (identity.signature.hasFullSignature) results += "Full ";
        if (identity.signature.hasMinimalSignature) results += "Minimal ";
        if (!identity.signature.hasFullSignature && !identity.signature.hasMinimalSignature) results += "None ";
        results += "\n";
        results += "  Interval consistency: " + String(identity.signature.intervalConsistency, 2) + "\n";
        results += "  RSSI consistency: " + String(identity.signature.rssiConsistency, 2) + "\n";
        results += "  Channels: " + String(countChannels(identity.signature.channelBitmap)) + "\n";
        
        if (identity.signature.channelSeqLength > 0) {
            results += "  Channel sequence: ";
            for (uint8_t i = 0; i < min((uint8_t)8, identity.signature.channelSeqLength); i++) {
                results += String(identity.signature.channelSequence[i]);
                if (i < min((uint8_t)8, identity.signature.channelSeqLength) - 1) results += ",";
            }
            if (identity.signature.channelSeqLength > 8) {
                results += "...";
            }
            results += "\n";
        }
        
        if (identity.sequenceValid) {
            results += "  Sequence tracking: Active (last:" + String(identity.lastSequenceNum) + ")\n";
        }
        
        if (identity.macs.size() > 0) {
            results += "  Anchor MAC: " + macFmt6(identity.macs[0].bytes.data()) + "\n";
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
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    probeRequestQueue = xQueueCreate(256, sizeof(ProbeRequestEvent));
    if (!probeRequestQueue) {
        Serial.printf("[RAND] FATAL: Failed to create queue (heap: %u)\n", ESP.getFreeHeap());
        vTaskDelay(pdMS_TO_TICKS(200));
        
        probeRequestQueue = xQueueCreate(128, sizeof(ProbeRequestEvent));
        if (!probeRequestQueue) {
            Serial.printf("[RAND] FATAL: Queue creation failed twice (heap: %u), aborting\n", ESP.getFreeHeap());
            workerTaskHandle = nullptr;
            vTaskDelete(nullptr);
            return;
        }
        Serial.printf("[RAND] Reduced queue created (128 entries, heap: %u)\n", ESP.getFreeHeap());
    } else {
        Serial.printf("[RAND] Queue created (256 entries, heap: %u)\n", ESP.getFreeHeap());
    }

    loadDeviceIdentities();

    std::set<String> transmittedIdentities;
    
    {
        std::lock_guard<std::mutex> lock(randMutex);
        activeSessions.clear();
        deviceIdentities.clear();
    }
    
    Serial.println("[RAND] Starting radios...");
    vTaskDelay(pdMS_TO_TICKS(100));
    
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    } else if (currentScanMode == SCAN_BLE) {
        vTaskDelay(pdMS_TO_TICKS(100));
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    
    Serial.println("[RAND] Enabling detection...");
    randomizationDetectionEnabled = true;
    scanning = true;

    uint32_t startTime = millis();
    uint32_t nextStatus = startTime + 5000;
    uint32_t nextCleanup = startTime + 10000;
    uint32_t nextResultsUpdate = startTime + 2000;
    uint32_t lastBLEScan = 0;
    uint32_t lastMeshUpdate = 0;
    const uint32_t MESH_IDENTITY_UPDATE_INTERVAL = 5000;
    const uint32_t BLE_SCAN_INTERVAL = rfConfig.bleScanInterval;

    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {
        
        if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
            ProbeRequestEvent event;
            int processedCount = 0;
            
            while (processedCount < 200 && xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE) {
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
                    session.primaryChannel = event.channel;
                    session.channelMask = (1 << event.channel);
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
                    
                    if (session.primaryChannel == 0 && event.channel > 0) {
                        session.primaryChannel = event.channel;
                    }
                    session.channelMask |= (1 << event.channel);
                    
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
                }
            }
        }
        
        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && 
            pBLEScan && (millis() - lastBLEScan >= BLE_SCAN_INTERVAL)) {
            lastBLEScan = millis();

            // Stop any existing scan before starting a new one
            if (pBLEScan->isScanning()) {
                pBLEScan->stop();
                vTaskDelay(pdMS_TO_TICKS(100)); // Brief delay
            }
            
            bool scanStarted = pBLEScan->start(rfConfig.bleScanDuration, false);
            
            if (scanStarted) {
                
                // Wait for scan to complete
                vTaskDelay(pdMS_TO_TICKS(rfConfig.bleScanDuration));
                
                NimBLEScanResults scanResults = pBLEScan->getResults();
                Serial.printf("[RAND BLE] Scan results: %d devices\n", scanResults.getCount());
                
                if (scanResults.getCount() > 0) {
                    std::lock_guard<std::mutex> lock(randMutex);
                    
                    for (int i = 0; i < scanResults.getCount(); i++) {
                        const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                        
                        Serial.printf("[RAND BLE] Processing device %d/%d\n", i+1, scanResults.getCount());
                        broadcastToTerminal("[RAND BLE] Processing device %d/%d\n");
                        
                        const uint8_t* macBytes = device->getAddress().getVal();
                        uint8_t mac[6];
                        memcpy(mac, macBytes, 6);
                        
                        Serial.printf("[RAND BLE] Device %s - MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                    device->getName().c_str(),
                                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        
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
                            
                            Serial.printf("[RAND BLE] Updated session %s rssi:%d count:%d\n",
                                        macStr.c_str(), rssi, session.probeCount);
                            
                            try {
                                if (session.rssiReadings.size() < 20) {
                                    session.rssiReadings.push_back(rssi);
                                }
                                if (session.probeCount >= 2 && (now - session.startTime) >= 2000 && !session.linkedToIdentity) {
                                    Serial.printf("[RAND BLE] About to link session %s\n", macStr.c_str());
                                    uint32_t linkStartTime = millis();
                                    linkSessionToTrackBehavioral(session);
                                    uint32_t linkDuration = millis() - linkStartTime;
                                    
                                    Serial.printf("[RAND BLE] Linked session %s in %ums\n", macStr.c_str(), linkDuration);
                                }
                            } catch (const std::exception& e) {
                                Serial.printf("[RAND BLE] Exception: %s\n", e.what());
                            }
                        }
                    }
                }
                pBLEScan->clearResults();
            } else {
                Serial.printf("[RAND BLE] Scan start FAILED!\n");
            }
        } 
        
        // Process all unlinked randomized sessions
        if ((int32_t)(millis() - nextStatus) >= 0) {
            uint32_t now = millis();
            std::vector<ProbeSession*> toProcess;
            
            {
                std::lock_guard<std::mutex> lock(randMutex);
                for (auto& entry : activeSessions) {
                    if (!entry.second.linkedToIdentity && isRandomizedMAC(entry.second.mac)) {
                        if (now - entry.second.startTime >= 2000) {
                            toProcess.push_back(&entry.second);
                        }
                    }
                }
            }
            
            for (auto* session : toProcess) {
                linkSessionToTrackBehavioral(*session);
            }
            
            {
                std::lock_guard<std::mutex> lock(randMutex);
                Serial.printf("[RAND] Sessions:%d Identities:%d Heap:%lu\n",
                            activeSessions.size(), deviceIdentities.size(), ESP.getFreeHeap());
            }
            
            nextStatus += 5000;
        }
        
        if (meshEnabled && millis() - lastMeshUpdate >= MESH_IDENTITY_UPDATE_INTERVAL) {
            lastMeshUpdate = millis();
            uint32_t sentThisCycle = 0;
            
            std::lock_guard<std::mutex> lock(randMutex);
            
            for (const auto& entry : deviceIdentities) {
                const DeviceIdentity& identity = entry.second;
                String identityKey = String(identity.identityId);
                
                if (transmittedIdentities.find(identityKey) == transmittedIdentities.end()) {
                    String identityMsg = getNodeId() + ": IDENTITY:" + String(identity.identityId);
                    identityMsg += identity.isBLE ? " B " : " W ";
                    identityMsg += "MACs:" + String(identity.macs.size());
                    identityMsg += " Conf:" + String(identity.confidence, 2);
                    identityMsg += " Sess:" + String(identity.observedSessions);
                    
                    if (identity.macs.size() > 0) {
                        identityMsg += " Anchor:" + macFmt6(identity.macs[0].bytes.data());
                    }
                    
                    if (identityMsg.length() < 230) {
                        if (sendToSerial1(identityMsg, true)) {
                            transmittedIdentities.insert(identityKey);
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

        

        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            std::string results = getRandomizationResults().c_str();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            nextResultsUpdate += 2000;
        }
        

        if ((int32_t)(millis() - nextCleanup) >= 0) {
            cleanupStaleSessions();
            nextCleanup += 30000;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (meshEnabled && !stopRequested) {
        Serial.printf("[RAND] Scan complete - transmitting final batch\n");
        
        std::lock_guard<std::mutex> lock(randMutex);
        
        rateLimiter.flush();
        delay(100);
        
        for (const auto& entry : deviceIdentities) {
            String identityKey = String(entry.second.identityId);
            
            if (transmittedIdentities.find(identityKey) == transmittedIdentities.end()) {
                const DeviceIdentity& identity = entry.second;
                
                String identityMsg = getNodeId() + ": IDENTITY:" + identityKey;
                identityMsg += identity.isBLE ? " B " : " W ";
                identityMsg += "MACs:" + String(identity.macs.size());
                identityMsg += " Conf:" + String(identity.confidence, 2);
                identityMsg += " Sess:" + String(identity.observedSessions);
                
                if (identity.macs.size() > 0) {
                    identityMsg += " Anchor:" + macFmt6(identity.macs[0].bytes.data());
                }
                
                if (identityMsg.length() < 230) {
                    if (sendToSerial1(identityMsg, true)) {
                        transmittedIdentities.insert(identityKey);
                    }
                }
            }
        }
        
        Serial1.flush();
        delay(100);
        
        uint32_t totalIdentities = deviceIdentities.size();
        uint32_t finalTransmitted = transmittedIdentities.size();
        uint32_t finalRemaining = totalIdentities - finalTransmitted;
        
        String summary = getNodeId() + ": RANDOMIZATION_DONE: Identities=" + String(totalIdentities) +
                        " Sessions=" + String(activeSessions.size()) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        sendToSerial1(summary, true);
        Serial.printf("[RAND] Detection complete: %d/%d identities transmitted, %d pending\n",
                     finalTransmitted, totalIdentities, finalRemaining);
        
        if (finalRemaining > 0) {
            Serial.printf("[RAND] WARNING: %d identities not transmitted\n", finalRemaining);
        }
    }
    
    randomizationDetectionEnabled = false;
    scanning = false;

    radioStopSTA();
    delay(100);
    
    Serial.println("[RAND] Processing all remaining sessions...");
    {
        std::lock_guard<std::mutex> lock(randMutex);
        for (auto& entry : activeSessions) {
            if (!entry.second.linkedToIdentity && isRandomizedMAC(entry.second.mac)) {
                linkSessionToTrackBehavioral(entry.second);
            }
        }
    }

    saveDeviceIdentities();
    
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

// Storage
void saveDeviceIdentities() {
    if (!SafeSD::isAvailable()) return;
    
    std::lock_guard<std::mutex> lock(randMutex);
    
    File file = SafeSD::open("/rand_identities.dat", FILE_WRITE);
    if (!file) {
        Serial.println("[RAND] Failed to open identities file for writing");
        return;
    }
    
    uint32_t count = deviceIdentities.size();
    file.write((uint8_t*)&count, sizeof(count));
    
    for (const auto& entry : deviceIdentities) {
        const DeviceIdentity& id = entry.second;
        
        file.write((uint8_t*)&id.identityId, sizeof(id.identityId));
        
        uint32_t macCount = id.macs.size();
        file.write((uint8_t*)&macCount, sizeof(macCount));
        for (const auto& mac : id.macs) {
            file.write(mac.bytes.data(), 6);
        }
        
        file.write((uint8_t*)&id.signature, sizeof(BehavioralSignature));
        file.write((uint8_t*)&id.firstSeen, sizeof(id.firstSeen));
        file.write((uint8_t*)&id.lastSeen, sizeof(id.lastSeen));
        file.write((uint8_t*)&id.confidence, sizeof(id.confidence));
        file.write((uint8_t*)&id.sessionCount, sizeof(id.sessionCount));
        file.write((uint8_t*)&id.observedSessions, sizeof(id.observedSessions));
        file.write((uint8_t*)&id.lastSequenceNum, sizeof(id.lastSequenceNum));
        file.write((uint8_t*)&id.sequenceValid, sizeof(id.sequenceValid));
        file.write((uint8_t*)&id.hasKnownGlobalMac, sizeof(id.hasKnownGlobalMac));
        file.write((uint8_t*)&id.knownGlobalMac, sizeof(id.knownGlobalMac));
        file.write((uint8_t*)&id.isBLE, sizeof(id.isBLE));
    }
    
    file.close();
    Serial.printf("[RAND] Saved %d identities to SD\n", count);
}

void loadDeviceIdentities() {
    if (!SafeSD::isAvailable()) return;
    if (!SafeSD::exists("/rand_identities.dat")) return;
    
    std::lock_guard<std::mutex> lock(randMutex);
    
    File file = SafeSD::open("/rand_identities.dat", FILE_READ);
    if (!file) {
        Serial.println("[RAND] Failed to open identities file");
        return;
    }
    
    uint32_t count = 0;
    if (file.read((uint8_t*)&count, sizeof(count)) != sizeof(count)) {
        Serial.println("[RAND] Failed to read identity count");
        file.close();
        return;
    }
    
    if (count > MAX_DEVICE_TRACKS) {
        Serial.printf("[RAND] Invalid count: %u\n", count);
        file.close();
        return;
    }
    
    for (uint32_t i = 0; i < count; i++) {
        DeviceIdentity id;
        memset(&id, 0, sizeof(id));
        
        if (file.read((uint8_t*)&id.identityId, sizeof(id.identityId)) != sizeof(id.identityId)) break;
        
        uint32_t macCount = 0;
        if (file.read((uint8_t*)&macCount, sizeof(macCount)) != sizeof(macCount)) break;
        
        if (macCount > 50) break;
        
        for (uint32_t j = 0; j < macCount; j++) {
            uint8_t macBytes[6];
            if (file.read(macBytes, 6) != 6) {
                file.close();
                return;
            }
            id.macs.push_back(MacAddress(macBytes));
        }
        
        if (file.read((uint8_t*)&id.signature, sizeof(BehavioralSignature)) != sizeof(BehavioralSignature)) break;
        if (file.read((uint8_t*)&id.firstSeen, sizeof(id.firstSeen)) != sizeof(id.firstSeen)) break;
        if (file.read((uint8_t*)&id.lastSeen, sizeof(id.lastSeen)) != sizeof(id.lastSeen)) break;
        if (file.read((uint8_t*)&id.confidence, sizeof(id.confidence)) != sizeof(id.confidence)) break;
        if (file.read((uint8_t*)&id.sessionCount, sizeof(id.sessionCount)) != sizeof(id.sessionCount)) break;
        if (file.read((uint8_t*)&id.observedSessions, sizeof(id.observedSessions)) != sizeof(id.observedSessions)) break;
        if (file.read((uint8_t*)&id.lastSequenceNum, sizeof(id.lastSequenceNum)) != sizeof(id.lastSequenceNum)) break;
        if (file.read((uint8_t*)&id.sequenceValid, sizeof(id.sequenceValid)) != sizeof(id.sequenceValid)) break;
        if (file.read((uint8_t*)&id.hasKnownGlobalMac, sizeof(id.hasKnownGlobalMac)) != sizeof(id.hasKnownGlobalMac)) break;
        if (file.read((uint8_t*)&id.knownGlobalMac, sizeof(id.knownGlobalMac)) != sizeof(id.knownGlobalMac)) break;
        if (file.read((uint8_t*)&id.isBLE, sizeof(id.isBLE)) != sizeof(id.isBLE)) break;
        
        if (!id.macs.empty()) {
            String key = macFmt6(id.macs[0].bytes.data());
            deviceIdentities[key] = id;
            identityIdCounter = max(identityIdCounter, (uint32_t)strtol(id.identityId + 2, NULL, 16));
        }
    }
    
    file.close();
    Serial.printf("[RAND] Loaded %d identities\n", deviceIdentities.size());
}