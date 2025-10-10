#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include "scanner.h"

enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

extern AsyncWebServer *server;
extern bool meshEnabled;

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS  
#define AP_PASS "ouispy123"
#endif
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif

struct KalmanFilterState {
    float estimate;
    float errorCovariance;
    float processNoise;
    float measurementNoise;
    bool initialized;
};

struct TriangulationNode {
    String nodeId;
    float lat;
    float lon;
    int8_t rssi;
    uint32_t hitCount;
    bool hasGPS;
    uint32_t lastUpdate;
    std::vector<int8_t> rssiHistory;
    KalmanFilterState kalmanFilter;
    float filteredRssi;
    float distanceEstimate;
    float signalQuality;
};

struct NodeSyncStatus {
    String nodeId;
    time_t rtcTimestamp;
    uint32_t millisOffset;
    bool synced;
    uint32_t lastSyncCheck;
};

struct PreciseTimestamp {
    time_t rtc_seconds;
    uint16_t rtc_subseconds;
    uint32_t micros_offset;
};



// Triangulation functions
void initNodeKalmanFilter(TriangulationNode &node);
float kalmanFilterRSSI(TriangulationNode &node, int8_t measurement);
float haversineDistance(float lat1, float lon1, float lat2, float lon2);
void geodeticToENU(float lat, float lon, float refLat, float refLon, float &east, float &north);
float calculateGDOP(const std::vector<TriangulationNode> &nodes);
float calculateSignalQuality(const TriangulationNode &node);
void updateNodeRSSI(TriangulationNode &node, int8_t newRssi);
float rssiToDistance(const TriangulationNode &node, bool isWiFi = true);
bool performWeightedTrilateration(const std::vector<TriangulationNode> &nodes, float &estLat, float &estLon, float &confidence);
void broadcastTimeSyncRequest();
void handleTimeSyncResponse(const String &nodeId, time_t timestamp, uint32_t milliseconds);
bool verifyNodeSynchronization(uint32_t maxOffsetMs = 10);
String getNodeSyncStatus();
extern std::vector<NodeSyncStatus> nodeSyncStatus;
String calculateTriangulationResults();
void stopTriangulation();
void startTriangulation(const String &targetMac, int duration);
bool isTriangulationActive();

// Network and Web Server functions
void initializeNetwork();
void initializeMesh();
void startWebServer();
void startAPAndServer();
void stopAPAndServer();

// Mesh communication functions
void sendMeshNotification(const Hit &hit);
void sendTrackerMeshUpdate();
void sendMeshCommand(const String &command);
void processMeshMessage(const String &message);
void processUSBToMesh();
void setNodeId(const String &id);
String getNodeId();