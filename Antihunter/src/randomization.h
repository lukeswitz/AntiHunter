#pragma once
#include <Arduino.h>
#include <map>
#include <vector>
#include <array>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <mutex>

class NimBLEAdvertisedDevice;

struct MacAddress {
    std::array<uint8_t, 6> bytes;
    
    MacAddress() { bytes.fill(0); }
    MacAddress(const uint8_t* mac) {
        memcpy(bytes.data(), mac, 6);
    }
};

struct ProbeRequestEvent {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    uint16_t payloadLen;
    uint8_t payload[128];
};

extern QueueHandle_t probeRequestQueue;

struct IEOrderSignature {
    uint8_t ieTypes[16];
    uint8_t ieCount;
    uint16_t orderHash;
};

struct BehavioralSignature {
    uint32_t probeIntervals[20];
    uint8_t intervalCount;
    
    int8_t rssiHistory[20];
    uint8_t rssiHistoryCount;
    
    uint32_t channelBitmap;
    uint16_t ieFingerprint[6];
    uint16_t ieFingerprintMinimal[6];
    IEOrderSignature ieOrder;
    IEOrderSignature ieOrderMinimal;
    
    bool hasFullSignature;
    bool hasMinimalSignature;
    
    uint8_t channelSequence[32];
    uint8_t channelSeqLength;
    
    float intervalConsistency;
    float rssiConsistency;
    
    uint32_t observationCount;
    uint32_t lastObserved;
    float trackConfidence;
    
    uint8_t burstCount;
    uint32_t burstDuration;
    float burstIntervalMean;
};

struct ProbeSession {
    uint8_t mac[6];
    uint32_t startTime;
    uint32_t lastSeen;
    
    uint32_t probeTimestamps[50];
    uint8_t probeCount;
    
    int8_t rssiSum;
    int8_t rssiMin;
    int8_t rssiMax;
    std::vector<int8_t> rssiReadings;
    
    uint8_t primaryChannel;
    uint32_t channelMask;
    uint16_t fingerprint[6];
    IEOrderSignature ieOrder;
    
    uint16_t lastSeqNum;
    bool seqNumValid;
    uint16_t seqNumGaps;
    uint16_t seqNumWraps;
    
    float avgProbeInterval;
    float intervalStdDev;
    float rssiVariance;
    
    bool linkedToIdentity;
    char linkedIdentityId[10];
    
    bool hasGlobalMacLeak;
    uint8_t globalMacLeaked[6];
};

struct DeviceIdentity {
    char identityId[10];
    std::vector<MacAddress> macs;
    BehavioralSignature signature;
    uint32_t firstSeen;
    uint32_t lastSeen;
    float confidence;
    uint8_t sessionCount;
    uint8_t observedSessions;
    
    uint16_t lastSequenceNum;
    bool sequenceValid;
    
    bool hasKnownGlobalMac;
    uint8_t knownGlobalMac[6];
};

const uint32_t SESSION_START_THRESHOLD = 3000;
const uint32_t SESSION_END_TIMEOUT = 20000;
const uint32_t SESSION_CLEANUP_AGE = 90000;
const uint32_t TRACK_STALE_TIME = 120000;
const uint32_t MAX_ACTIVE_SESSIONS = 50;
const uint32_t MAX_DEVICE_TRACKS = 30;
const uint32_t FINGERPRINT_MATCH_THRESHOLD = 2;
const uint32_t MAC_ROTATION_GAP_MIN = 100;
const uint32_t MAC_ROTATION_GAP_MAX = 120000;
const float CONFIDENCE_THRESHOLD_NEW_SESSION = 0.18f;
const float CONFIDENCE_THRESHOLD_ESTABLISHED = 0.35f;
const uint8_t MAC_PREFIX_SIMILARITY_BYTES = 4;

extern bool randomizationDetectionEnabled;
extern std::map<String, ProbeSession> activeSessions;
extern std::map<String, DeviceIdentity> deviceIdentities;
extern uint32_t identityIdCounter;
extern std::mutex randMutex;

void randomizationDetectionTask(void *pv);
void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel, 
                        const uint8_t *payload, uint16_t length);
void resetRandomizationDetection();
void correlateAuthFrameToRandomizedSession(const uint8_t* globalMac, int8_t rssi, 
                                           uint8_t channel, const uint8_t* frame, uint16_t frameLen);
void extractIEFingerprint(const uint8_t *ieData, uint16_t ieLength, uint16_t fingerprint[6]);
void extractIEOrderSignature(const uint8_t *ieData, uint16_t ieLength, IEOrderSignature& sig);
void extractBLEFingerprint(const NimBLEAdvertisedDevice* device, uint16_t fingerprint[6]);
bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches);
bool matchIEOrder(const IEOrderSignature& sig1, const IEOrderSignature& sig2);
uint16_t computeCRC16(const uint8_t *data, uint16_t length);
uint16_t extractSequenceNumber(const uint8_t *payload, uint16_t length);
bool isMinimalSignature(const uint16_t fingerprint[6]);
void extractChannelSequence(const ProbeSession& session, uint8_t* channelSeq, uint8_t& seqLen);
float calculateChannelSequenceSimilarity(const uint8_t* seq1, uint8_t len1, const uint8_t* seq2, uint8_t len2);
float calculateSignatureSetSimilarity(const ProbeSession& session, const DeviceIdentity& identity);
void updateDeviceSignatureSet(DeviceIdentity& identity, const ProbeSession& session);

float calculateIntervalConsistency(const uint32_t intervals[], uint8_t count);
float calculateRssiConsistency(const int8_t readings[], uint8_t count);
uint32_t countChannels(uint32_t bitmap);
void linkSessionToTrackBehavioral(ProbeSession& session);

bool detectWiFiBLECorrelation(const uint8_t* wifiMac, const uint8_t* bleMac);
bool detectGlobalMACLeak(const ProbeSession& session, uint8_t* globalMac);
float calculateRSSIDistributionSimilarity(const int8_t* rssi1, uint8_t count1,
                                         const int8_t* rssi2, uint8_t count2);
float calculateInterFrameTimingSimilarity(const uint32_t* times1, uint8_t count1,
                                         const uint32_t* times2, uint8_t count2);
bool detectMACRotationGap(const DeviceIdentity& identity, uint32_t currentTime);
bool detectSequenceNumberAnomaly(const ProbeSession& session, const DeviceIdentity& identity);

void cleanupStaleSessions();
void cleanupStaleTracks();

void saveDeviceIdentities();
void loadDeviceIdentities();

String generateTrackId();
String getRandomizationResults();
bool isRandomizedMAC(const uint8_t *mac);
bool isGlobalMAC(const uint8_t *mac);

extern std::mutex randMutex;