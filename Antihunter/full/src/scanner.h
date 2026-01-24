#pragma once
#include "drone_detector.h"
#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "randomization.h"

struct Hit {
   uint8_t mac[6];
   int8_t rssi;
   uint8_t ch;
   char name[32];
   bool isBLE;
};

struct DeauthStats {
    String srcMac;
    uint32_t count;
    uint32_t broadcastCount;
    uint32_t targetedCount;
    int8_t lastRssi;
    uint8_t channel;
};

struct Target {
    uint8_t bytes[6];
    uint8_t len;
    char identityId[10];
};

struct Allowlist {
    uint8_t bytes[6];
    uint8_t len;
};

struct TriangulationAccumulator {
    uint8_t targetMac[6];

    int wifiHitCount;
    int8_t wifiMaxRssi;
    int8_t wifiMinRssi;
    float wifiRssiSum;
    int64_t wifiFirstDetectionTimestamp;

    int bleHitCount;
    int8_t bleMaxRssi;
    int8_t bleMinRssi;
    float bleRssiSum;
    int64_t bleFirstDetectionTimestamp;

    float lat;
    float lon;
    float hdop;
    bool hasGPS;

    uint32_t lastSendTime;
    uint32_t windowStartTime;
    bool finalReportSent;
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

struct RFScanConfig {
    uint32_t wifiChannelTime;
    uint32_t wifiScanInterval;
    uint32_t bleScanInterval;
    uint32_t bleScanDuration;
    uint8_t preset;
    String wifiChannels;
    int8_t globalRssiThreshold;
};

// Granular settings
extern RFScanConfig rfConfig;
void setRFPreset(uint8_t preset);
void setCustomRFConfig(uint32_t wifiChanTime, uint32_t wifiInterval, uint32_t bleInterval, uint32_t bleDuration, const String &channels, int8_t rssiThreshold);
RFScanConfig getRFConfig();
void loadRFConfigFromPrefs();
int8_t getGlobalRssiThreshold();
void setGlobalRssiThreshold(int8_t threshold);

extern TaskHandle_t workerTaskHandle;

// Allowlist
extern std::vector<Allowlist> allowlist;

// Eviction and cleanup
const uint32_t EVICTION_AGE_MS = 30000;            // Clean entries older than 30s
const uint32_t MAX_LOG_SIZE = 1000;                // Max RAM log entries
const uint32_t MAX_MAP_SIZE = 500;                 // Max map entries in RAM
const uint32_t MAX_TIMING_SIZE = 100;              // Max RAM timing entries per device

// Blue team scans
static int blueTeamDuration = 300;
static bool blueTeamForever = false;

const uint32_t DEAUTH_TARGETED_WINDOW = 10000;     
const uint32_t DEAUTH_TARGETED_THRESHOLD = 3;      
const uint32_t DEAUTH_CLEANUP_INTERVAL = 60000;    
const uint32_t DEAUTH_HISTORY_MAX_SIZE = 200;    

extern std::map<String, uint32_t> deauthSourceCounts;
extern std::map<String, uint32_t> deauthTargetCounts;
extern std::map<String, std::vector<uint32_t>> deauthTimings;
extern std::vector<DeauthHit> deauthLog;
extern volatile uint32_t deauthCount;
extern volatile uint32_t disassocCount;
extern bool deauthDetectionEnabled;
extern QueueHandle_t deauthQueue;

// Baseline scan
extern uint32_t baselineRamCacheSize;
extern uint32_t baselineSdMaxDevices;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern bool triangulationActive;

// Triangulation
extern TriangulationAccumulator triAccum;
extern bool droneDetectionEnabled;
extern void processDronePacket(const uint8_t *payload, int length, int8_t rssi);
extern QueueHandle_t macQueue;

// Functions
void initializeScanner();
bool matchesIdentityMac(const char* identityId, const uint8_t* mac);
void saveTargetsList(const String &txt);
void snifferScanTask(void *pv);
void listScanTask(void *pv);
void baselineDetectionTask(void *pv);
void blueTeamTask(void *pv);
String getDeauthReasonText(uint16_t reasonCode);

// Radio control functions
void radioStartSTA();       // Promiscuous mode for sniffer
void radioStopSTA();
void radioStartListScan();  // Non-promiscuous mode for WiFi.scanNetworks()
void radioStopListScan();
void radioStartBLE();
void radioStopBLE();

// Safe queue functions (mutex protected)
void initMacQueueMutex();
bool safeMacQueueSend(const Hit* hit, TickType_t timeout);
bool safeMacQueueReceive(Hit* hit, TickType_t timeout);
void safeMacQueueDelete();
bool safeMacQueueCreate(size_t queueSize);

String getTargetsList();
String getDiagnostics();
size_t getTargetCount();
String getSnifferCache();

size_t getAllowlistCount();
String getAllowlistText();
void saveAllowlist(const String &txt);
bool isAllowlisted(const uint8_t *mac);

void cleanupMaps();