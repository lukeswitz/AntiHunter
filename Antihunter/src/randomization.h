#pragma once
#include <Arduino.h>
#include <map>
#include <vector>
#include <array>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// MAC address wrapper for vector storage
struct MacAddress {
    std::array<uint8_t, 6> bytes;
    
    MacAddress() { bytes.fill(0); }
    MacAddress(const uint8_t* mac) {
        memcpy(bytes.data(), mac, 6);
    }
};

// Session tracking structures
struct ProbeSession {
    uint8_t mac[6];
    uint32_t startTime;
    uint32_t lastSeen;
    int8_t rssiSum;
    int8_t rssiMin;
    int8_t rssiMax;
    uint8_t hitCount;
    uint8_t primaryChannel;
    uint32_t channelMask;
    uint16_t fingerprint[6];
};

struct DeviceTrack {
    char trackId[10];
    std::vector<MacAddress> macs;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint16_t fingerprint[6];
    float confidence;
    uint8_t sessionCount;
};

// Constants
const uint32_t SESSION_START_THRESHOLD = 2000;
const uint32_t SESSION_END_TIMEOUT = 5000;
const uint32_t SESSION_CLEANUP_AGE = 30000;
const uint32_t TRACK_STALE_TIME = 60000;
const uint32_t MAX_ACTIVE_SESSIONS = 100;
const uint32_t MAX_DEVICE_TRACKS = 50;
const uint32_t FINGERPRINT_MATCH_THRESHOLD = 3;
const float CONFIDENCE_THRESHOLD = 0.75;

// Global state
extern bool randomizationDetectionEnabled;
extern std::map<String, ProbeSession> activeSessions;
extern std::map<String, DeviceTrack> deviceTracks;
extern uint32_t trackIdCounter;

// Core functions
void randomizationDetectionTask(void *pv);
void processProbeRequest(const uint8_t *mac, int8_t rssi, uint8_t channel, 
                        const uint8_t *payload, uint16_t length);
void extractIEFingerprint(const uint8_t *ieData, uint16_t ieLength, uint16_t fingerprint[6]);
bool matchFingerprints(const uint16_t fp1[6], const uint16_t fp2[6], uint8_t& matches);
void linkSessionToTrack(const ProbeSession& session);
String generateTrackId();
void cleanupStaleSessions();
void cleanupStaleTracks();
String getRandomizationResults();
void resetRandomizationDetection();
uint16_t computeCRC16(const uint8_t *data, uint16_t length);
bool isRandomizedMAC(const uint8_t *mac);
bool isGlobalMAC(const uint8_t *mac);