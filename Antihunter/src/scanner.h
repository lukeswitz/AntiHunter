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
};

struct BeaconHit {
   uint8_t srcMac[6];
   uint8_t bssid[6];
   int8_t rssi;
   uint8_t channel;
   uint32_t timestamp;
   String ssid;
   uint16_t beaconInterval;
};

struct BLESpamHit {
    uint8_t mac[6];
    uint8_t advType;
    char deviceName[32];
    int8_t rssi;
    uint32_t timestamp;
    uint32_t advCount;
    char spamType[32];
};

struct BLEAnomalyHit {
    uint8_t mac[6];
    char anomalyType[32];
    char details[64];
    int8_t rssi;
    uint32_t timestamp;
};

// Attack detection thresholds
static const uint32_t DEAUTH_FLOOD_THRESHOLD = 3;      // 3+ deauths in window = attack
static const uint32_t DEAUTH_TIMING_WINDOW = 500;      // 500ms burst window
static const uint32_t BEACON_FLOOD_THRESHOLD = 20;     // 20+ NEW MACs in window = flood
static const uint32_t BEACON_TIMING_WINDOW = 5000;     // 5 second window
static const uint32_t BEACON_BURST_THRESHOLD = 10;     // 10+ NEW MACs per second
static const uint32_t BLE_SPAM_THRESHOLD = 5;          // 5+ per second for Apple
static const uint32_t BLE_TIMING_WINDOW = 1000;        // 1 second
static const uint32_t PROBE_FLOOD_THRESHOLD = 50;      // 50 probes/sec
static const uint32_t PROBE_TIMING_WINDOW = 1000;      // 1 second
static const uint32_t BEACON_RANDOM_MAC_THRESHOLD = 15; // 15+ random MACs = attack
static const uint32_t MAX_SSIDS_PER_MAC = 3;           // Normal APs don't change SSIDs

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

extern QueueHandle_t macQueue;

static int blueTeamDuration = 300;
static bool blueTeamForever = false;

void snifferScanTask(void *pv);
void initializeScanner();
void listScanTask(void *pv);
void trackerTask(void *pv);
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

