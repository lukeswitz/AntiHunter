#pragma once
#include "drone_detector.h"
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

struct Allowlist {
    uint8_t bytes[6];
    uint8_t len;
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

// Allowlist
extern std::vector<Allowlist> allowlist;
size_t getAllowlistCount();
String getAllowlistText();
void saveAllowlist(const String &txt);
bool isAllowlisted(const uint8_t *mac);

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
extern TaskHandle_t workerTaskHandle;
extern uint32_t baselineRamCacheSize;
extern uint32_t baselineSdMaxDevices;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern bool triangulationActive;

extern bool droneDetectionEnabled;
extern void processDronePacket(const uint8_t *payload, int length, int8_t rssi);

extern QueueHandle_t macQueue;

static int blueTeamDuration = 300;
static bool blueTeamForever = false;
extern BaselineStats baselineStats;

void initializeScanner();
void saveTargetsList(const String &txt);
void snifferScanTask(void *pv);
void listScanTask(void *pv);
void baselineDetectionTask(void *pv);
void blueTeamTask(void *pv);

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