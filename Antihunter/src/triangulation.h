#pragma once
#include "scanner.h"
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include <map>
#include <vector>

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
    std::vector<int8_t> rssiRawWindow;
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

struct ClockDiscipline {
    float driftRate;
    uint32_t lastDiscipline;
    uint32_t disciplineCount;
    bool converged;
};

struct PathLossCalibration {
    float rssi0_wifi;
    float rssi0_ble;
    float n_wifi;
    float n_ble;
    bool calibrated;
};

extern std::vector<TriangulationNode> triangulationNodes;
const float KALMAN_MEASUREMENT_NOISE = 4.0;
const uint32_t RSSI_HISTORY_SIZE = 10;
const uint32_t SYNC_CHECK_INTERVAL = 30000;

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
String calculateTriangulation();
void stopTriangulation();
void startTriangulation(const String &targetMac, int duration);
bool isTriangulationActive();
void disciplineRTCFromGPS();
int64_t getCorrectedMicroseconds();
void calibratePathLoss(const String &targetMac, float knownDistance);
void processMeshTimeSyncWithDelay(const String &senderId, const String &message, uint32_t rxMicros);

extern ClockDiscipline clockDiscipline;
extern PathLossCalibration pathLoss;
extern std::map<String, uint32_t> nodePropagationDelays;
extern std::vector<NodeSyncStatus> nodeSyncStatus;
extern uint8_t triangulationTarget[6];
extern uint32_t triangulationStart;
extern uint32_t triangulationDuration;