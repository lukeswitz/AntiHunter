#pragma once
#include <Arduino.h>
#include <map>
#include <vector>
#include <array>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

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

// Behavioral signature for device tracking
struct BehavioralSignature {
    uint32_t probeIntervals[20];
    uint8_t intervalCount;
    
    int8_t rssiHistory[20];
    uint8_t rssiHistoryCount;
    
    uint32_t channelBitmap;
    uint16_t ieFingerprint[6];
    
    float intervalConsistency;
    float rssiConsistency;
    
    uint32_t observationCount;
    uint32_t lastObserved;
    float trackConfidence;
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
    
    float avgProbeInterval;
    float intervalStdDev;
    float rssiVariance;
};

// Device track structure
struct DeviceIdentity {
    char identityId[10];
    std::vector<MacAddress> macs;
    BehavioralSignature signature;
    uint32_t firstSeen;
    uint32_t lastSeen;
    float confidence;
    uint8_t sessionCount;
    uint8_t observedSessions;
};

// Constants
const uint32_t SESSION_START_THRESHOLD = 2000;
const uint32_t SESSION_END_TIMEOUT = 5000;
const uint32_t SESSION_CLEANUP_AGE = 30000;
const uint32_t TRACK_STALE_TIME = 60000;
const uint32_t MAX_ACTIVE_SESSIONS = 100;
const uint32_t MAX_DEVICE_TRACKS = 50;
const uint32_t FINGERPRINT_MATCH_THRESHOLD = 3;
const float CONFIDENCE_THRESHOLD = 0.75f;

// Global state
extern bool randomizationDetectionEnabled;
extern std::map<String, ProbeSession> activeSessions;
extern std::map<String, DeviceIdentity> deviceIdentities;
extern uint32_t identityIdCounter;

// Core detection functions
void randomizationDetectionTask(void *pv);
void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel, 
                        const uint8_t *payload, uint16_t length);
void resetRandomizationDetection();

// IE and fingerprint functions
void extractIEFingerprint(const uint8_t *ieData, uint16_t ieLength, uint16_t fingerprint[6]);
bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches);
uint16_t computeCRC16(const uint8_t *data, uint16_t length);

// Behavioral analysis functions
float calculateIntervalConsistency(const uint32_t intervals[], uint8_t count);
float calculateRssiConsistency(const int8_t readings[], uint8_t count);
uint32_t countChannels(uint32_t bitmap);
void linkSessionToTrackBehavioral(const ProbeSession& session);

// Cleanup functions
void cleanupStaleSessions();
void cleanupStaleTracks();

// Utility functions
String generateTrackId();
String getRandomizationResults();
bool isRandomizedMAC(const uint8_t *mac);
bool isGlobalMAC(const uint8_t *mac);