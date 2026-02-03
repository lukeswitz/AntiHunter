#pragma once
#include <Arduino.h>
#include <vector>
#include <map>
#include "opendroneid.h"
#include <atomic>

struct DroneDetection {
    uint8_t mac[6];
    int8_t rssi;
    uint32_t timestamp;
    uint32_t lastSeen;
    
    char uavId[ODID_ID_SIZE + 1];
    uint8_t uaType;
    
    double latitude;
    double longitude;
    float altitudeMsl;
    float heightAgl;
    float speed;
    float heading;
    float speedVertical;
    int status;
    
    double operatorLat;
    double operatorLon;
    char operatorId[ODID_ID_SIZE + 1];
    
    char description[ODID_STR_SIZE + 1];
    
    uint8_t authType;
    uint32_t authTimestamp;
    uint8_t authData[ODID_AUTH_PAGE_NONZERO_DATA_SIZE + 1];
};

extern std::map<String, DroneDetection> detectedDrones;
extern std::vector<String> droneEventLog;
extern std::atomic<uint32_t> droneDetectionCount;
extern bool droneDetectionEnabled;
extern QueueHandle_t droneQueue;

void droneDetectorTask(void *pv);
void initializeDroneDetector();
void processDronePacket(const uint8_t *payload, int length, int8_t rssi);
String getDroneDetectionResults();
String getDroneEventLog();
void cleanupDroneData();