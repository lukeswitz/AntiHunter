#pragma once
#include "scanner.h"
#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <map>
#include <vector>
#include <mutex>

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
    int64_t detectionTimestamp;  // Microsecond timestamp from GPS-synced RTC
    std::vector<int8_t> rssiHistory;
    std::vector<int8_t> rssiRawWindow;
    KalmanFilterState kalmanFilter;
    float filteredRssi;
    float distanceEstimate;
    float signalQuality;
    float hdop;
    bool isBLE;
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
    int64_t bootToEpochOffsetMicros;  // Offset from boot micros() to Unix epoch microseconds
    bool offsetCalibrated;
};

enum RFEnvironment : uint8_t {
    RF_ENV_OPEN_SKY = 0,
    RF_ENV_SUBURBAN = 1,
    RF_ENV_INDOOR = 2,
    RF_ENV_INDOOR_DENSE = 3,
    RF_ENV_INDUSTRIAL = 4
};

struct RFEnvironmentPreset {
    float n_wifi;
    float n_ble;
    float rssi0_wifi;
    float rssi0_ble;
};

// RF Environment Presets calibrated for 8 dBi RX antenna
// { n_wifi, n_ble, rssi0_wifi (dBm @ 1m), rssi0_ble (dBm @ 1m) }
// WiFi: ESP32 ~20dBm TX, 8dBi RX gain, ~40dB FSPL @ 1m
// BLE: Most phones/wearables TX at 0 to -8dBm (not +4dBm), giving -63 to -71dBm @ 1m
// BLE n typically 2.0-4.0 indoors (Google/Apple Exposure Notifications research)
static const RFEnvironmentPreset RF_PRESETS[] = {
    { 2.0f, 2.0f, -22.0f, -59.0f },   // RF_ENV_OPEN_SKY: clear LOS, minimal obstruction
    { 2.7f, 2.5f, -25.0f, -63.0f },   // RF_ENV_SUBURBAN: light foliage, some buildings
    { 3.2f, 3.0f, -27.0f, -67.0f },   // RF_ENV_INDOOR: typical indoor, some walls
    { 4.0f, 3.5f, -29.0f, -71.0f },   // RF_ENV_INDOOR_DENSE: office, many partitions
    { 4.8f, 4.0f, -32.0f, -75.0f }    // RF_ENV_INDUSTRIAL: heavy obstruction, machinery
};

struct PathLossCalibration {
    float rssi0_wifi;
    float rssi0_ble;
    float n_wifi;
    float n_ble;
    bool calibrated;
};

extern RFEnvironment currentRFEnvironment;
void setRFEnvironment(RFEnvironment env);
RFEnvironment getRFEnvironment();

struct PathLossSample {
    float rssi;
    float distance;  // from GPS
    bool isWiFi;
    uint32_t timestamp;
};

struct AdaptivePathLoss {
    // Current estimates
    float rssi0_wifi;
    float rssi0_ble;
    float n_wifi;
    float n_ble;
    
    // Sample buffers for adaptation
    std::vector<PathLossSample> wifiSamples;
    std::vector<PathLossSample> bleSamples;
    
    // Estimation confidence
    bool wifi_calibrated;
    bool ble_calibrated;
    uint32_t lastUpdate;
    
    static constexpr size_t MIN_SAMPLES = 5;
    static constexpr size_t MAX_SAMPLES = 50;
};

struct APFinalResult {
    bool hasResult;
    float latitude;
    float longitude;
    float confidence;
    float uncertainty;
    uint32_t timestamp;
    String coordinatorNodeId;
};

extern AdaptivePathLoss adaptivePathLoss;
extern std::vector<TriangulationNode> triangulationNodes;
extern std::mutex triangulationMutex;  // Protects triangulationNodes and triangulateAcks
extern APFinalResult apFinalResult;

const float KALMAN_MEASUREMENT_NOISE = 4.0;
const uint32_t RSSI_HISTORY_SIZE = 10;
const uint32_t SYNC_CHECK_INTERVAL = 30000;

// Triangulation functions
void initNodeKalmanFilter(TriangulationNode &node);
float kalmanFilterRSSI(TriangulationNode &node, int8_t measurement);
float haversineDistance(float lat1, float lon1, float lat2, float lon2);
void geodeticToENU(float lat, float lon, float refLat, float refLon, float &east, float &north);
float calculateGDOP(const std::vector<TriangulationNode> &nodes); // TODO decide if we need 3D and 2D 
float getAverageHDOP(const std::vector<TriangulationNode> &nodes);
float calculateSignalQuality(const TriangulationNode &node);
void updateNodeRSSI(TriangulationNode &node, int8_t newRssi);
float rssiToDistance(const TriangulationNode &node, bool isWiFi = true);
bool performWeightedTrilateration(const std::vector<TriangulationNode> &nodes, float &estLat, float &estLon, float &confidence);
bool performTDOATriangulation(const std::vector<TriangulationNode> &nodes, float &estLat, float &estLon, float &confidence);
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
void estimatePathLossParameters(bool isWiFi);
void addPathLossSample(float rssi, float distance, bool isWiFi);
void processMeshTimeSyncWithDelay(const String &senderId, const String &message, uint32_t rxMicros);
void markTriangulationStopFromMesh();

struct NodeReportingInfo {
    String nodeId;
    uint8_t slotIndex;
    uint32_t firstReportTime;
    uint32_t lastReportTime;
    bool hasReported;
};

struct DynamicReportingSchedule {
    std::map<String, NodeReportingInfo> nodes;
    uint32_t slotDurationMs = 0;
    uint32_t cycleStartMs = 0;
    uint32_t guardIntervalMs = 200;
    std::mutex nodeMutex;
    
    void addNode(const String& nodeId) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.find(nodeId) == nodes.end()) {
            NodeReportingInfo info;
            info.nodeId = nodeId;
            info.slotIndex = nodes.size();
            info.firstReportTime = millis();
            info.lastReportTime = millis();
            info.hasReported = false;
            nodes[nodeId] = info;
            
            recalculateSlotDuration();
            
            Serial.printf("[SLOTS] Registered: %s -> slot %d/%d (duration=%ums)\n",
                         nodeId.c_str(), info.slotIndex, nodes.size(), slotDurationMs);
        }
    }
    
    void recalculateSlotDuration() {
        if (nodes.empty()) {
            slotDurationMs = 0;
            return;
        }

        uint8_t numNodes = nodes.size();

        // Each T_D message ~100-150 chars, need 2-3s spacing between nodes
        if (numNodes <= 2) {
            slotDurationMs = 3000;   // 2 nodes = 6s cycle (safe for mesh)
        } else if (numNodes <= 3) {
            slotDurationMs = 3000;   // 3 nodes = 9s cycle
        } else if (numNodes <= 6) {
            slotDurationMs = 2500;   // 6 nodes = 15s cycle
        } else if (numNodes <= 10) {
            slotDurationMs = 2000;   // 10 nodes = 20s cycle
        } else {
            slotDurationMs = 2000;   // scales for more nodes
        }

        Serial.printf("[SLOTS] Recalculated: %d nodes, %ums/slot, %ums guard\n",
                     numNodes, slotDurationMs, guardIntervalMs);
    }
    
    bool isMySlotActive(const String& nodeId, uint32_t& nextSlotMs, uint32_t now = 0) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.find(nodeId) == nodes.end()) return false;
        if (cycleStartMs == 0) return false;

        uint8_t numNodes = nodes.size();
        if (numNodes == 0) return false;

        // Use provided GPS-synchronized time if available, otherwise fall back to millis()
        if (now == 0) {
            now = millis();
        }
        uint32_t elapsed = (now >= cycleStartMs) ? (now - cycleStartMs) :
                          (UINT32_MAX - cycleStartMs + now + 1);
        
        uint32_t cycleMs = slotDurationMs * numNodes;
        uint8_t mySlot = nodes[nodeId].slotIndex;
        
        uint32_t positionInCycle = elapsed % cycleMs;
        uint32_t slotStartMs = mySlot * slotDurationMs;
        uint32_t slotEndMs = slotStartMs + slotDurationMs - guardIntervalMs;
        
        bool isActive = (positionInCycle >= slotStartMs && positionInCycle < slotEndMs);
        
        if (isActive) {
            uint32_t currentCycleStart = cycleStartMs + (elapsed / cycleMs) * cycleMs;
            nextSlotMs = currentCycleStart + ((mySlot + 1) % numNodes) * slotDurationMs;
        } else {
            uint32_t cyclesCompleted = elapsed / cycleMs;
            uint32_t currentCycleStart = cycleStartMs + cyclesCompleted * cycleMs;
            
            if (positionInCycle < slotStartMs) {
                nextSlotMs = currentCycleStart + slotStartMs;
            } else {
                nextSlotMs = currentCycleStart + cycleMs + slotStartMs;
            }
        }
        
        return isActive;
    }
    
    void markReportReceived(const String& nodeId) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.find(nodeId) != nodes.end()) {
            nodes[nodeId].lastReportTime = millis();
            nodes[nodeId].hasReported = true;
        }
    }
    
    void initializeCycle(uint32_t startTimeMs) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        cycleStartMs = startTimeMs;
        recalculateSlotDuration();
        Serial.printf("[SLOTS] Cycle initialized at %ums\n", cycleStartMs);
    }
    
    void reset() {
        std::lock_guard<std::mutex> lock(nodeMutex);
        nodes.clear();
        cycleStartMs = 0;
        slotDurationMs = 0;
    }
};

extern DynamicReportingSchedule reportingSchedule;

struct TriangulateAckInfo {
    String nodeId;
    uint32_t ackTimestamp;
    bool reportReceived;  // Track if node has sent TRIANGULATE_REPORT
    uint32_t reportTimestamp;
    uint32_t lastHeartbeatTimestamp;  // Track last heartbeat from child node
};

extern ClockDiscipline clockDiscipline;
extern PathLossCalibration pathLoss;
extern std::map<String, uint32_t> nodePropagationDelays;
extern std::vector<NodeSyncStatus> nodeSyncStatus;
extern uint8_t triangulationTarget[6];
extern uint32_t triangulationStart;
extern uint32_t triangulationDuration;
extern bool triangulationInitiator;
extern char triangulationTargetIdentity[10];
extern std::vector<TriangulateAckInfo> triangulateAcks;
extern std::vector<String> triangulateReportedNodes;
extern String triangulationCoordinator;
extern uint32_t ackCollectionStart;
extern uint32_t stopSentTimestamp;
extern bool waitingForFinalReports;