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

void initializeScanner();
void listScanTask(void *pv);
void trackerTask(void *pv);
void saveTargetsList(const String &txt);
void setTrackerMac(const uint8_t mac[6]);
void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets);
String getTargetsList();
String getDiagnostics();
size_t getTargetCount();

// Globals
extern volatile bool scanning;
extern volatile int totalHits;
extern volatile uint32_t framesSeen;
extern volatile uint32_t bleFramesSeen;
extern volatile bool trackerMode;

// Collections
extern std::set<String> uniqueMacs;
extern std::vector<Hit> hitsLog;

// Tracker state
extern uint8_t trackerMac[6];
extern volatile int8_t trackerRssi;
extern volatile uint32_t trackerLastSeen;
extern volatile uint32_t trackerPackets;
extern uint32_t lastScanSecs;
extern bool lastScanForever;

// Queue 
extern QueueHandle_t macQueue;