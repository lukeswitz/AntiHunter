#pragma once

#include <Arduino.h>
#include <vector>
#include <map>
#include <list>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// Baseline structures
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
    bool dirtyFlag;
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

struct DeviceHistory {
    int8_t lastRssi;
    uint32_t lastSeen;
    uint32_t disappearedAt;
    bool wasPresent;
    uint8_t significantChanges;
};

struct CachedSDLookup {
    String mac;
    bool inBaseline;
    uint32_t timestamp;
};

extern std::map<String, bool> sdLookupCache;
extern std::list<String> sdLookupLRU;
extern const uint32_t SD_LOOKUP_CACHE_SIZE;
extern const uint32_t SD_LOOKUP_CACHE_TTL;

void addToSDCache(const String& mac, bool found);
bool checkSDCache(const String& mac, bool& found);

// Baseline detection configuration constants
const uint32_t BASELINE_SCAN_DURATION = 300000;
const uint32_t BASELINE_DEVICE_TIMEOUT = 600000;
const uint32_t BASELINE_SD_FLUSH_INTERVAL = 5000;
const uint32_t BASELINE_MAX_ANOMALIES = 200;
const uint32_t BASELINE_CLEANUP_INTERVAL = 60000;

// Baseline detection state variables
extern BaselineStats baselineStats;
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
extern uint32_t baselineRamCacheSize;
extern uint32_t baselineSdMaxDevices;
extern std::map<String, DeviceHistory> deviceHistory;
extern uint32_t deviceAbsenceThreshold;
extern uint32_t reappearanceAlertWindow;
extern int8_t significantRssiChange;

// SD-backed baseline storage
extern uint32_t totalDevicesOnSD;
extern uint32_t lastSDFlush;
extern bool sdBaselineInitialized;

// Core baseline functions
void baselineDetectionTask(void *pv);
void resetBaselineDetection();
bool isDeviceInBaseline(const uint8_t *mac);
void updateBaselineDevice(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel);
void checkForAnomalies(const uint8_t *mac, int8_t rssi, const char *name, bool isBLE, uint8_t channel);
void cleanupBaselineMemory();
String getBaselineResults();
void updateBaselineStats();

// Baseline configuration getters/setters
int8_t getBaselineRssiThreshold();
void setBaselineRssiThreshold(int8_t threshold);
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

// SD storage functions
bool initializeBaselineSD();
bool writeBaselineDeviceToSD(const BaselineDevice& device);
bool readBaselineDeviceFromSD(const uint8_t* mac, BaselineDevice& device);
bool flushBaselineCacheToSD();
void loadBaselineFromSD();
void saveBaselineStatsToSD();
void loadBaselineStatsFromSD();
uint8_t calculateDeviceChecksum(BaselineDevice& device);