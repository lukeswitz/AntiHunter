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

struct Target {
    uint8_t bytes[6];
    uint8_t len;
};

struct Allowlist {
    uint8_t bytes[6];
    uint8_t len;
};

struct TriangulationAccumulator {
    uint8_t targetMac[6];
    int hitCount;
    int8_t maxRssi;
    int8_t minRssi;
    float rssiSum;
    float lat;
    float lon;
    float hdop;
    bool hasGPS;
    uint32_t lastSendTime;
    uint32_t windowStartTime;
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

// Allowlist
extern std::vector<Allowlist> allowlist;
size_t getAllowlistCount();
String getAllowlistText();
void saveAllowlist(const String &txt);
bool isAllowlisted(const uint8_t *mac);

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
extern TriangulationAccumulator triAccum;
extern bool droneDetectionEnabled;
extern void processDronePacket(const uint8_t *payload, int length, int8_t rssi);
extern QueueHandle_t macQueue;

static int blueTeamDuration = 300;
static bool blueTeamForever = false;

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

void cleanupMaps();