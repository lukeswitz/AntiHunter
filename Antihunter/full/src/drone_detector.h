#pragma once
#include <Arduino.h>
#include <vector>
#include <map>
#include "opendroneid.h"
#include <atomic>
#include <mutex>

struct DroneDetection {
    uint8_t mac[6];
    int8_t rssi;
    uint32_t timestamp;
    uint32_t lastSeen;
    
    char uavId[ODID_ID_SIZE + 1];
    uint8_t uaType;
    uint8_t idType;

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

struct DroneFrameEvent {
    uint8_t payload[400];
    uint16_t len;
    int8_t rssi;
};

extern std::map<String, DroneDetection> detectedDrones;
extern std::mutex detectedDronesMutex;
extern std::vector<String> droneEventLog;
extern std::atomic<uint32_t> droneDetectionCount;
extern std::atomic<bool> droneDetectionEnabled;
extern QueueHandle_t droneQueue;
extern QueueHandle_t droneFrameQueue;

void droneDetectorTask(void *pv);
void initializeDroneDetector();
void processDronePacket(const uint8_t *payload, int length, int8_t rssi);
// Phase 3.2: BLE-side ODID Remote ID (ASTM F3411 over BLE 5.x). The 6-byte
// addr is the BLE peer address; odid points at the ODID-encoded message
// bytes (immediately after the 0x16 FA FF AD type+UUID header).
void processDroneOdidBle(const uint8_t *addr, int8_t rssi,
                         const uint8_t *odid, int odidLen);
String getDroneDetectionResults();
String getDroneEventLog();
void cleanupDroneData();