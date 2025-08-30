#pragma once
#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// Forward declarations
struct Hit {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t ch;
    String name;
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

// Function declarations
void initializeScanner();
void listScanTask(void *pv);
void trackerTask(void *pv);
void deauthDetectionTask(void *pv);
void beaconFloodTask(void *pv);
String getTargetsList();
void saveTargetsList(const String &txt);
void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets);
void setTrackerMac(const uint8_t mac[6]);
String getDiagnostics();
size_t getTargetCount();

// Global state exports
extern volatile bool scanning;
extern volatile int totalHits;
extern volatile uint32_t framesSeen;
extern volatile uint32_t bleFramesSeen;
extern volatile bool trackerMode;
extern volatile uint32_t deauthCount;
extern volatile uint32_t disassocCount;
extern volatile uint32_t totalBeaconsSeen;
extern volatile uint32_t suspiciousBeacons;

// Collections exports
extern std::set<String> uniqueMacs;
extern std::vector<Hit> hitsLog;
extern std::vector<DeauthHit> deauthLog;
extern std::vector<BeaconHit> beaconLog;

// Tracker state exports
extern uint8_t trackerMac[6];
extern volatile int8_t trackerRssi;
extern volatile uint32_t trackerLastSeen;
extern volatile uint32_t trackerPackets;
extern uint32_t lastScanSecs;
extern bool lastScanForever;

// Queue handles 
extern QueueHandle_t macQueue;
extern QueueHandle_t deauthQueue;
extern QueueHandle_t beaconQueue;