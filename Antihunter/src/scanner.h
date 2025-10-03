#pragma once
#include "drone_detector.h"
#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// Target Match
struct Hit {
   uint8_t mac[6];
   int8_t rssi;
   uint8_t ch;
   char name[32];
   bool isBLE;
};

struct BaselineDevice {
    uint8_t mac[6];
    int8_t avgRssi;
    int8_t minRssi;
    int8_t maxRssi;
    uint32_t firstSeen;
    uint32_t lastSeen;
    char name[32];
    bool isBLE;
    uint8_t channel;
    uint16_t hitCount;
    uint8_t checksum;
} __attribute__((packed));

struct AnomalyHit {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    char name[32];
    bool isBLE;
    uint32_t timestamp;
    String reason;
};

// Baseline detection configuration
const uint32_t BASELINE_SCAN_DURATION = 300000;  // 5 minutes default
const uint32_t BASELINE_DEVICE_TIMEOUT = 600000;  // 10 minutes before device removed
const uint32_t BASELINE_SD_FLUSH_INTERVAL = 5000;  // Flush every 5s
const uint32_t BASELINE_MAX_ANOMALIES = 200;     // Maximum anomaly log entries
const uint32_t BASELINE_CLEANUP_INTERVAL = 60000; // Cleanup every 60 seconds

// Baseline detection state
extern bool baselineDetectionEnabled;
extern bool baselineEstablished;
extern uint32_t baselineStartTime;
extern uint32_t baselineDuration;
extern std::map<String, BaselineDevice> baselineCache;
extern std::vector<AnomalyHit> anomalyLog;
extern uint32_t anomalyCount;
extern uint32_t baselineDeviceCount;
extern QueueHandle_t anomalyQueue;
extern int8_t baselineRssiThreshold;
extern uint32_t deviceAbsenceThreshold;
extern uint32_t reappearanceAlertWindow;
extern int8_t significantRssiChange;

// SD-backed baseline storage
extern uint32_t totalDevicesOnSD;
extern uint32_t lastSDFlush;
extern bool sdBaselineInitialized;

struct Target {
    uint8_t bytes[6];
    uint8_t len;
};

struct BaselineStats {
    uint32_t wifiDevices;
    uint32_t bleDevices;
    uint32_t totalDevices;
    uint32_t wifiHits;
    uint32_t bleHits;
    bool isScanning;
    bool phase1Complete;
    uint32_t elapsedTime;
    uint32_t totalDuration;
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

extern uint32_t baselineRamCacheSize;
extern uint32_t baselineSdMaxDevices;

extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern bool triangulationActive;

extern bool pineappleDetectionEnabled;
extern bool espressifDetectionEnabled; 
extern bool multissidDetectionEnabled;

extern bool droneDetectionEnabled;
extern void processDronePacket(const uint8_t *payload, int length, int8_t rssi);

extern QueueHandle_t macQueue;

static int blueTeamDuration = 300;
static bool blueTeamForever = false;
extern BaselineStats baselineStats;  

void initializeScanner();
void saveTargetsList(const String &txt);
void snifferScanTask(void *pv);
void bleScannerTask(void *pv);
void listScanTask(void *pv);
void karmaDetectionTask(void *pv);
void probeFloodDetectionTask(void *pv);
void pwnagotchiDetectionTask(void *pv);
void multissidDetectionTask(void *pv);
void baselineDetectionTask(void *pv);
void blueTeamTask(void *pv);
void beaconFloodTask(void *pv);

String getTargetsList();
String getDiagnostics();
size_t getTargetCount();
String getSnifferCache();
String getBaselineResults();

void cleanupMaps();

void resetBaselineDetection();
bool isDeviceInBaseline(const uint8_t *mac);
void updateBaselineDevice(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel);
void checkForAnomalies(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel);
void cleanupBaselineMemory();
int8_t getBaselineRssiThreshold();
void setBaselineRssiThreshold(int8_t threshold);
bool initializeBaselineSD();
bool writeBaselineDeviceToSD(const BaselineDevice& device);
bool readBaselineDeviceFromSD(const uint8_t* mac, BaselineDevice& device);
bool flushBaselineCacheToSD();
void loadBaselineFromSD();
void saveBaselineStatsToSD();
void loadBaselineStatsFromSD();
uint8_t calculateDeviceChecksum(BaselineDevice& device);
uint32_t getBaselineRamCacheSize();
void setBaselineRamCacheSize(uint32_t size);
uint32_t getBaselineSdMaxDevices();
void setBaselineSdMaxDevices(uint32_t size);
uint32_t getDeviceAbsenceThreshold();
void setDeviceAbsenceThreshold(uint32_t ms);
uint32_t getReappearanceAlertWindow();
void setReappearanceAlertWindow(uint32_t ms);
int8_t getSignificantRssiChange();
void setSignificantRssiChange(int8_t dBm);