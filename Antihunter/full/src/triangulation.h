#pragma once
#include "scanner.h"
#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <map>
#include <set>
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
    float lat{};
    float lon{};
    int8_t rssi{};
    uint32_t hitCount{};
    bool hasGPS{};
    uint32_t lastUpdate{};
    std::vector<int8_t> rssiHistory;
    std::vector<int8_t> rssiRawWindow;
    KalmanFilterState kalmanFilter{};
    float filteredRssi{};
    float distanceEstimate{};
    float distanceSigma{};
    bool hasBLE{};
    int8_t bleRssi{};
    float signalQuality{};
    float hdop{};
    uint16_t gpsSamples{};
    bool isBLE{};
};

struct NodeSyncStatus {
    String nodeId;
    time_t rtcTimestamp{};
    uint32_t millisOffset{};
    bool synced{};
    uint32_t lastSyncCheck{};
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
    float sigma_db;
};

// RF Environment Presets calibrated for 6 dBi RX antenna (empirically verified 2026-02)
// { n_wifi, n_ble, rssi0_wifi (dBm @ 1m), rssi0_ble (dBm @ 1m) }
// WiFi: ESP32 ~20dBm TX, 6dBi RX gain, ~40dB FSPL @ 1m
// BLE: Most phones/wearables TX at 0 to -8dBm (not +4dBm), giving -62 to -69dBm @ 1m
// BLE n typically 2.0-4.0 indoors, measurements suggest 2.5-3.0 more common
// Calibration based on XIAO ESP32S3 measurements with antenna gain extrapolation
static const RFEnvironmentPreset RF_PRESETS[] = {
    { 2.0f, 2.0f, -23.0f, -60.0f, 4.0f },   // RF_ENV_OPEN_SKY: clear LOS, minimal obstruction
    { 2.7f, 2.5f, -24.0f, -62.0f, 5.5f },   // RF_ENV_SUBURBAN: light foliage, some buildings
    { 3.2f, 2.9f, -25.0f, -65.0f, 7.0f },   // RF_ENV_INDOOR: typical indoor, some walls
    { 4.0f, 3.5f, -27.0f, -69.0f, 8.2f },   // RF_ENV_INDOOR_DENSE: office, many partitions
    { 4.8f, 4.0f, -30.0f, -73.0f, 9.0f }    // RF_ENV_INDUSTRIAL: heavy obstruction, machinery
};

struct PathLossCalibration {
    float rssi0_wifi;
    float rssi0_ble;
    float n_wifi;
    float n_ble;
    bool calibrated;
};

struct DistanceTuning {
    float wifi_multiplier;
    float ble_multiplier;
    bool enabled;
};

extern RFEnvironment currentRFEnvironment;
extern DistanceTuning distanceTuning;
void setRFEnvironment(RFEnvironment env);

struct PathLossSample {
    float rssi;
    float distance;  // from GPS
    bool isWiFi;
    uint32_t timestamp;
};

struct AdaptivePathLoss {
    // Current estimates
    float rssi0_wifi{};
    float rssi0_ble{};
    float n_wifi{};
    float n_ble{};
    
    // Sample buffers for adaptation
    std::vector<PathLossSample> wifiSamples;
    std::vector<PathLossSample> bleSamples;
    
    // Estimation confidence
    bool wifi_calibrated{};
    bool ble_calibrated{};
    uint32_t lastUpdate{};
    
    static constexpr size_t MIN_SAMPLES = 5;
    static constexpr size_t MAX_SAMPLES = 50;
};

struct APFinalResult {
    bool hasResult{};
    float latitude{};
    float longitude{};
    float confidence{};
    float uncertainty{};
    uint32_t timestamp{};
    String coordinatorNodeId;
};

extern AdaptivePathLoss adaptivePathLoss;
extern std::vector<TriangulationNode> triangulationNodes;
extern std::mutex triangulationMutex;  // Protects triangulationNodes and triangulateAcks
extern APFinalResult apFinalResult;
extern const size_t MAX_TRIANGULATION_NODES;
extern const size_t MAX_ACK_INFO;

const float KALMAN_MEASUREMENT_NOISE = 4.0;
const uint32_t RSSI_HISTORY_SIZE = 10;
const int8_t RSSI_SENSITIVITY_FLOOR = -95;
const int TRILATERATION_MAX_ITER = 24;
const double TRILATERATION_STEP_TOL_M = 0.1;
const float BLE_TXPOWER_SIGMA_DB = 6.0f;
const float PATHLOSS_UNCALIBRATED_SIGMA_DB = 3.0f;
const uint32_t SYNC_CHECK_INTERVAL = 30000;
const uint32_t REPORT_PROGRESS_GRACE_MS = 8000;
const uint32_t REPORT_HARD_CEILING_MS = 60000;
const uint32_t REPORT_FIRST_MIN_MS = 20000;
const uint16_t GPS_MIN_SAMPLES_TO_JUDGE = 5;
const float GPS_HDOP_REJECT_RATIO = 3.0f;
const float GPS_JUMP_REJECT_M = 40.0f;
const float ANCHOR_OUTLIER_FLOOR_M = 50.0f;
const uint8_t GPS_REJECT_RESET_COUNT = 12;
const float TRI_UNC_MAX_M = 100.0f;

// Triangulation functions
void initNodeKalmanFilter(TriangulationNode &node);
float kalmanFilterRSSI(TriangulationNode &node, int8_t measurement);
float haversineDistance(float lat1, float lon1, float lat2, float lon2);
void geodeticToENU(double lat, double lon, double refLat, double refLon, double &east, double &north);
void enuToGeodetic(double east, double north, double refLat, double refLon, double &lat, double &lon);
float calculateGDOP(const std::vector<TriangulationNode> &nodes, double estLat, double estLon);
float getAverageHDOP(const std::vector<TriangulationNode> &nodes);
float calculateSignalQuality(const TriangulationNode &node);
void updateNodeRSSI(TriangulationNode &node, int8_t newRssi);
float rssiToDistance(const TriangulationNode &node, bool isWiFi = true);
float rssiDistanceSigma(const TriangulationNode &node, float distance, bool isWiFi);
void nodeUpdateDistance(TriangulationNode &node);
bool rssiUsable(int8_t rssi);
float estimateRangeM(int8_t rssi, bool isWiFi);
float estimateRangeSigmaM(int8_t rssi, bool isWiFi);
bool performWeightedTrilateration(const std::vector<TriangulationNode> &nodes, float &estLat, float &estLon, float &confidence, float &uncertaintyM);
void broadcastTimeSyncRequest();
void handleTimeSyncResponse(const String &nodeId, time_t timestamp, uint32_t milliseconds);
bool verifyNodeSynchronization(uint32_t maxOffsetMs = 10);
String calculateTriangulation();
void stopTriangulation();
void requestTriangulationStop();
bool startTriangulation(const String &targetMac, int duration, String *err = nullptr);
void disciplineRTCFromGPS();
int64_t getCorrectedMicroseconds();
void calibratePathLoss(const String &targetMac, float knownDistance);
void processMeshTimeSyncWithDelay(const String &senderId, const String &message, uint32_t rxMicros);
void markTriangulationStopFromMesh();

// peer spacing pulls it down on a fast one.
static const uint32_t TRI_SKIP_UNCALIBRATED_MS = 4000;
static const uint32_t TRI_SKIP_MIN_MS = 1500;
static const uint32_t TRI_SKIP_MAX_MS = 8000;
static const uint32_t TRI_RESEED_MIN_MS = 15000;

struct DynamicReportingSchedule {
    std::set<String> nodes;
    uint32_t slotDurationMs = 0;
    uint32_t cycleStartMs = 0;
    String lastSpeaker;
    uint32_t lastActivityMs = 0;
    uint32_t lastPeerReportMs = 0;
    uint32_t peerIntervalMs = 0;
    uint32_t reportSeq = 0;
    std::mutex nodeMutex;

    size_t nodeCount() {
        std::lock_guard<std::mutex> lock(nodeMutex);
        return nodes.size();
    }

    uint32_t peerSeq() {
        std::lock_guard<std::mutex> lock(nodeMutex);
        return reportSeq;
    }

    bool hasNode(const String& nid) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        return nodes.find(nid) != nodes.end();
    }

    // flight and lap back to ourselves - so it is measured, never a fixed constant.
    uint32_t skipTimeoutMs() const {
        uint32_t t = peerIntervalMs ? peerIntervalMs + (peerIntervalMs >> 1)
                                    : TRI_SKIP_UNCALIBRATED_MS;
        if (t < TRI_SKIP_MIN_MS) t = TRI_SKIP_MIN_MS;
        if (t > TRI_SKIP_MAX_MS) t = TRI_SKIP_MAX_MS;
        return t;
    }

    // get a turn. Without this a delayed frame re-opens the send gate and one node
    // bursts three or four times while the rest of the ring waits.
    uint32_t selfGapMs() {
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.size() <= 1) return slotDurationMs ? slotDurationMs : 3000u;
        uint32_t hop = peerIntervalMs ? peerIntervalMs : TRI_SKIP_UNCALIBRATED_MS;
        return (uint32_t)(nodes.size() - 1) * hop;
    }

    bool lapElapsed(uint32_t now) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        uint32_t ref = lastPeerReportMs ? lastPeerReportMs : lastActivityMs;
        if (ref == 0) return false;
        uint32_t laps = 3u * (nodes.empty() ? 1u : (uint32_t)nodes.size()) * skipTimeoutMs();
        if (laps < TRI_RESEED_MIN_MS) laps = TRI_RESEED_MIN_MS;
        return (uint32_t)(now - ref) >= laps;
    }

    String successorOf(const String& who) const {
        if (nodes.empty()) return String("");
        auto it = nodes.find(who);
        if (it == nodes.end()) return *nodes.begin();
        if (++it == nodes.end()) return *nodes.begin();
        return *it;
    }

    static uint32_t startupStaggerMs(const String& nid) {
        uint32_t h = 2166136261u;
        for (size_t i = 0; i < nid.length(); i++) { h ^= (uint8_t)nid.c_str()[i]; h *= 16777619u; }
        h ^= h >> 16; h *= 0x7feb352du; h ^= h >> 15; h *= 0x846ca68bu; h ^= h >> 16;
        return h % 2000;
    }

    // phase, so two nodes could both believe they held the turn and transmit together.
    bool isMyTurn(const String& nid, uint32_t now, String& waitingOn) {
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.empty() || nodes.find(nid) == nodes.end()) return false;
        if (lastActivityMs == 0) lastActivityMs = now;

        if (lastSpeaker == nid && nodes.size() > 1) {
            uint32_t ref = lastPeerReportMs ? lastPeerReportMs : lastActivityMs;
            uint32_t dead = 3u * (uint32_t)nodes.size() * skipTimeoutMs();
            if (dead < TRI_RESEED_MIN_MS) dead = TRI_RESEED_MIN_MS;
            if (ref == 0 || (uint32_t)(now - ref) < dead) {
                waitingOn = successorOf(nid);
                return false;
            }
        }

        uint32_t skip = skipTimeoutMs() + (startupStaggerMs(nid) % 400);
        uint32_t elapsed = (uint32_t)(now - lastActivityMs);
        size_t hops = elapsed / skip;

        if (lastSpeaker.length() == 0) {
            if (elapsed < startupStaggerMs(nid)) { waitingOn = String("start"); return false; }
            auto it = nodes.begin();
            for (size_t i = 0, k = hops % nodes.size(); i < k; i++) ++it;
            if (*it == nid) return true;
            waitingOn = *it;
            return false;
        }

        hops %= nodes.size();
        String expected = lastSpeaker;
        for (size_t i = 0; i <= hops; i++) expected = successorOf(expected);
        if (expected.length() == 0) return false;
        if (expected == nid) return true;
        waitingOn = expected;
        return false;
    }

    void addNode(const String& nid) {
        if (nid.length() == 0) return;
        std::lock_guard<std::mutex> lock(nodeMutex);
        if (nodes.insert(nid).second) {
            recalculateSlotDuration();
            Serial.printf("[SLOTS] Registered: %s (%u nodes, gap=%ums)\n",
                         nid.c_str(), (unsigned)nodes.size(), slotDurationMs);
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
    }

    void markReportReceived(const String& nid, bool fromPeer = true) {
        if (nid.length() == 0) return;
        std::lock_guard<std::mutex> lock(nodeMutex);
        uint32_t now = millis();
        nodes.insert(nid);
        if (fromPeer) {
            if (lastPeerReportMs != 0) {
                uint32_t d = (uint32_t)(now - lastPeerReportMs);
                if (d >= 200 && d <= 10000) {
                    if (peerIntervalMs == 0) peerIntervalMs = d;
                    else if (d <= peerIntervalMs * 3) peerIntervalMs = (peerIntervalMs * 3 + d) / 4;
                }
            }
            lastPeerReportMs = now;
        }
        lastSpeaker = nid;
        lastActivityMs = now;
        reportSeq++;
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
        lastSpeaker = "";
        lastActivityMs = 0;
        lastPeerReportMs = 0;
        peerIntervalMs = 0;
        reportSeq = 0;
        cycleStartMs = 0;
        slotDurationMs = 0;
    }
};

extern DynamicReportingSchedule reportingSchedule;

struct TriangulateAckInfo {
    String nodeId;
    uint32_t ackTimestamp{};
    bool reportReceived{};  // Track if node has sent TRIANGULATE_REPORT
    uint32_t reportTimestamp{};
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