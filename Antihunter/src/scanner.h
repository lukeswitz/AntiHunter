#pragma once
#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"


struct Hit {
   uint8_t mac[6];
   int8_t rssi;
   uint8_t ch;
   char name[32];
   bool isBLE;
};

struct DeauthHit {
   uint8_t srcMac[6];
   uint8_t destMac[6];
   uint8_t bssid[6];
   int8_t rssi;
   uint8_t channel;
   uint16_t reasonCode;
   uint32_t timestamp;
   bool isDisassoc;
   bool isBroadcast;
   uint16_t companyId;
};

struct APProfile {
   String ssid;
   uint8_t bssid[6];
   uint8_t channel;
   int8_t rssi;
   uint32_t lastSeen;
   uint16_t beaconInterval;
   uint8_t capabilities[2];
   bool isLegitimate;
};

struct EvilTwinHit {
   String ssid;
   uint8_t rogueMAC[6];
   uint8_t legitimateMAC[6];
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
   String suspicionReason;
};

struct KarmaHit {
   uint8_t apMAC[6];
   String clientSSID;
   uint8_t clientMAC[6];
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
   String reason;
};

struct EAPOLHit {
   uint8_t clientMAC[6];
   uint8_t apMAC[6];
   String ssid;
   uint8_t messageType;
   bool hasPMKID;
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
};

struct ProbeFloodHit {
   uint8_t clientMAC[6];
   String ssid;
   uint32_t probeCount;
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
   String reason;
};

struct BeaconHit {
   uint8_t srcMac[6];
   uint8_t bssid[6];
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
   String ssid;
   uint16_t beaconInterval;
   uint16_t companyId;
   String reason;
};

struct BLESpamHit {
    uint8_t mac[6];
    uint8_t advType;
    char deviceName[32];
    int8_t rssi;
    uint32_t timestamp;
    uint32_t advCount;
    char spamType[32];
    uint16_t companyId;
};

struct BLEAnomalyHit {
    uint8_t mac[6];
    char anomalyType[32];
    char details[64];
    int8_t rssi;
    uint32_t timestamp;
};

// Pwnagotchi detection
struct PwnagotchiHit {
    uint8_t mac[6];
    String name;
    String version;
    uint32_t pwnd_tot;
    int8_t rssi;
    uint8_t channel;
    uint32_t timestamp;
};

// Pineapple detection
struct PineappleHit {
    uint8_t mac[6];
    String ssid;
    bool suspicious_capability;
    bool minimal_tags;
    int8_t rssi;
    uint8_t channel;
    uint32_t timestamp;
};

// Multi-SSID AP detection
struct MultiSSIDTracker {
    uint8_t mac[6];
    std::set<uint16_t> ssid_hashes;
    uint32_t first_seen;
    uint32_t last_seen;
    int ssid_count;
};

struct ConfirmedMultiSSID {
    uint8_t mac[6];
    int ssid_count;
    uint32_t timestamp;
};


// Attack detection thresholds

// Deauth/Disassoc Detection - Multi-pattern detection
const uint32_t DEAUTH_TARGETED_THRESHOLD = 2;      // 2+ deauths to same target = targeted attack
const uint32_t DEAUTH_FLOOD_THRESHOLD = 5;         // 5+ deauths in window = flood
const uint32_t DEAUTH_TIMING_WINDOW = 2000;        // 2 second window
const uint32_t DEAUTH_BROADCAST_SCORE = 10;        // Broadcast deauth weight
const uint32_t DEAUTH_TARGETED_WINDOW = 10000;     // 10s window for targeted attacks

// Beacon Flood Detection - Pattern-based detection  
const uint32_t BEACON_UNIQUE_MAC_THRESHOLD = 10;   // 10+ unique MACs in window
const uint32_t BEACON_TIMING_WINDOW = 3000;        // 3 second sliding window
const uint32_t BEACON_BURST_THRESHOLD = 15;        // 15+ beacons in 1 second
const uint32_t BEACON_RANDOM_MAC_THRESHOLD = 8;    // 8+ random MACs = suspicious
const uint32_t BEACON_SSID_VARIANCE_THRESHOLD = 5; // Same MAC with 5+ SSIDs

// Karma Attack Detection - Correlation-based
const uint32_t KARMA_SSID_THRESHOLD = 3;           // AP responding to 3+ unique SSIDs
const uint32_t KARMA_RESPONSE_TIME = 100;          // Response within 100ms = suspicious
const uint32_t KARMA_PROBE_RESPONSE_WINDOW = 500;  // Correlation window
const uint32_t KARMA_CLIENT_PROBE_THRESHOLD = 5;   // Client probing 5+ SSIDs

// Probe Flood Detection - Burst and pattern detection
const uint32_t PROBE_RATE_THRESHOLD = 15;          // 15+ probes/second
const uint32_t PROBE_BURST_THRESHOLD = 8;          // 8+ in 500ms burst
const uint32_t PROBE_UNIQUE_SSID_THRESHOLD = 10;   // 10+ unique SSIDs from one client
const uint32_t PROBE_TIMING_WINDOW = 1000;         // 1 second window
const uint32_t PROBE_RANDOM_SSID_LENGTH = 8;       // Random SSID pattern detection

// BLE Spam Detection - Pattern matching
const uint32_t BLE_ADV_THRESHOLD = 50;             // 50+ advertisements/second  
const uint32_t BLE_TIMING_WINDOW = 3000;           // 3 second window
const uint32_t BLE_UNIQUE_ADDR_THRESHOLD = 20;     // 20+ unique addresses
const uint32_t BLE_RANDOM_ADDR_PATTERN = 15;       // Random address pattern threshold

// Evil Twin Detection - BSSID and capabilities matching
const uint32_t EVIL_TWIN_RSSI_VARIANCE = 20;       // RSSI difference threshold
const uint32_t EVIL_TWIN_CHANNEL_HOP_TIME = 5000;  // Channel hop detection window

// EAPOL Harvesting Detection
const uint32_t EAPOL_CAPTURE_THRESHOLD = 3;        // 3+ EAPOL frames = harvesting
const uint32_t EAPOL_TIMING_WINDOW = 30000;        // 30 second window

// Eviction and cleanup
const uint32_t EVICTION_AGE_MS = 30000;            // Clean entries older than 30s
const uint32_t MAX_LOG_SIZE = 1000;                // Max log entries
const uint32_t MAX_MAP_SIZE = 500;                 // Max map entries
const uint32_t MAX_TIMING_SIZE = 100;              // Max timing entries per device

extern std::map<String, uint32_t> deauthSourceCounts;
extern std::map<String, uint32_t> deauthTargetCounts;
extern std::map<String, std::vector<uint32_t>> deauthTimings;
extern std::vector<DeauthHit> deauthLog;
extern volatile uint32_t deauthCount;
extern volatile uint32_t disassocCount;
extern bool deauthDetectionEnabled;
extern QueueHandle_t deauthQueue;

extern std::map<String, APProfile> knownAPs;
extern std::vector<String> suspiciousAPs;
extern bool evilTwinDetectionEnabled;
extern QueueHandle_t evilTwinQueue;

extern std::vector<PwnagotchiHit> pwnagotchiLog;
extern std::vector<PineappleHit> pineappleLog;
extern std::vector<MultiSSIDTracker> multissidTrackers;
extern std::vector<ConfirmedMultiSSID> confirmedMultiSSID;
extern volatile uint32_t pwnagotchiCount;
extern volatile uint32_t pineappleCount;
extern volatile uint32_t multissidCount;

extern volatile uint32_t karmaCount;
extern volatile uint32_t probeFloodCount;
extern bool karmaDetectionEnabled;
extern QueueHandle_t karmaQueue;
extern std::map<String, std::vector<String>> clientProbeRequests;
extern std::map<String, uint32_t> karmaAPResponses;

extern bool eapolDetectionEnabled;
extern QueueHandle_t eapolQueue;
extern std::map<String, uint32_t> eapolCaptureAttempts;

extern bool probeFloodDetectionEnabled;
extern QueueHandle_t probeFloodQueue;
extern std::map<String, uint32_t> probeRequestCounts;
extern std::map<String, std::vector<uint32_t>> probeTimings;

extern std::vector<BeaconHit> beaconLog;
extern std::map<String, uint32_t> beaconCounts;
extern std::map<String, uint32_t> beaconLastSeen;
extern std::map<String, std::vector<uint32_t>> beaconTimings;
extern volatile uint32_t totalBeaconsSeen;
extern volatile uint32_t suspiciousBeacons;
extern bool beaconFloodDetectionEnabled;
extern QueueHandle_t beaconQueue;

extern std::vector<BLESpamHit> bleSpamLog;
extern std::map<String, uint32_t> bleAdvCounts;
extern std::map<String, std::vector<uint32_t>> bleAdvTimings;
extern volatile uint32_t bleSpamCount;
extern volatile uint32_t bleAnomalyCount;
extern bool bleSpamDetectionEnabled;
extern QueueHandle_t bleSpamQueue;
extern QueueHandle_t bleAnomalyQueue;

extern TaskHandle_t workerTaskHandle;

extern uint8_t trackerMac[6];
extern volatile int8_t trackerRssi;
extern volatile uint32_t trackerLastSeen;
extern volatile uint32_t trackerPackets;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern bool triangulationActive;

extern bool pineappleDetectionEnabled;
extern bool espressifDetectionEnabled; 
extern bool multissidDetectionEnabled;

extern QueueHandle_t macQueue;

static int blueTeamDuration = 300;
static bool blueTeamForever = false;

void snifferScanTask(void *pv);
void initializeScanner();
void listScanTask(void *pv);
void trackerTask(void *pv);
void karmaDetectionTask(void *pv);
void probeFloodDetectionTask(void *pv);
void pwnagotchiDetectionTask(void *pv);
void multissidDetectionTask(void *pv);
void blueTeamTask(void *pv);
void beaconFloodTask(void *pv);
void bleScannerTask(void *pv);
void saveTargetsList(const String &txt);
void setTrackerMac(const uint8_t mac[6]);
void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets);
String getTargetsList();
String getDiagnostics();
size_t getTargetCount();
String getSnifferCache();
void cleanupMaps();

