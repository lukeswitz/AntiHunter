#include "triangulation.h"
#include "scanner.h"
#include "hardware.h"
#include <math.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <TinyGPSPlus.h>

extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern TinyGPSPlus gps;
extern float gpsLat, gpsLon;
extern bool gpsValid;
extern TriangulationAccumulator triAccum;
extern bool triangulationOrchestratorAssigned;

// Triang
static TaskHandle_t calibrationTaskHandle = nullptr;
static TaskHandle_t coordinatorSetupTaskHandle = nullptr;
ClockDiscipline clockDiscipline = {0.0, 0, 0, false, 0, false};
std::map<String, uint32_t> nodePropagationDelays;
std::vector<NodeSyncStatus> nodeSyncStatus;
std::vector<TriangulationNode> triangulationNodes;
APFinalResult apFinalResult = {false, 0.0, 0.0, 0.0, 0.0, 0, ""};
String calculateTriangulation();
uint8_t triangulationTarget[6];
uint32_t triangulationStart = 0;
uint32_t triangulationDuration = 0;
bool triangulationActive = false;
bool triangulationInitiator = false;
char triangulationTargetIdentity[10] = {0};
DynamicReportingSchedule reportingSchedule;
std::vector<TriangulateAckInfo> triangulateAcks;
std::vector<String> triangulateReportedNodes;  // Nodes that sent final T_D
String triangulationCoordinator = "";
uint32_t ackCollectionStart = 0;
uint32_t stopSentTimestamp = 0;  // When TRIANGULATE_STOP was sent
bool waitingForFinalReports = false;
const uint32_t FINAL_REPORT_TIMEOUT_MS = 15000;  // 15 seconds for nodes to report
static volatile bool triStopCameFromMesh = false;
static uint32_t lastTriangulationStopTime = 0;
const uint32_t TRIANGULATION_DEBOUNCE_MS = 20000; // 20 seconds

RFEnvironment currentRFEnvironment = RF_ENV_INDOOR;

// Path loss defaults calibrated for 8 dBi RX antenna, indoor environment
PathLossCalibration pathLoss = {
    -27.0,   // rssi0_wifi (dBm @ 1m, 8dBi antenna)
    -62.0,   // rssi0_ble (dBm @ 1m, 8dBi antenna, low-power BLE)
    3.2,     // n_wifi (path loss exponent)
    3.6,     // n_ble (path loss exponent)
    false    // calibrated flag
};

void setRFEnvironment(RFEnvironment env) {
    if (env > RF_ENV_INDUSTRIAL) env = RF_ENV_INDOOR;
    currentRFEnvironment = env;
    const RFEnvironmentPreset& preset = RF_PRESETS[env];
    pathLoss.n_wifi = preset.n_wifi;
    pathLoss.n_ble = preset.n_ble;
    pathLoss.rssi0_wifi = preset.rssi0_wifi;
    pathLoss.rssi0_ble = preset.rssi0_ble;
    adaptivePathLoss.n_wifi = preset.n_wifi;
    adaptivePathLoss.n_ble = preset.n_ble;
    adaptivePathLoss.rssi0_wifi = preset.rssi0_wifi;
    adaptivePathLoss.rssi0_ble = preset.rssi0_ble;
    Serial.printf("[TRIANGULATE] RF environment set to %d (n_wifi=%.1f, n_ble=%.1f)\n",
                  env, preset.n_wifi, preset.n_ble);
}

RFEnvironment getRFEnvironment() {
    return currentRFEnvironment;
}

// Helpers
bool isTriangulationActive() {
    return triangulationActive;
}

float rssiToDistance(const TriangulationNode &node, bool isWiFi) {
    float rssi0 = isWiFi ? adaptivePathLoss.rssi0_wifi : adaptivePathLoss.rssi0_ble;
    float n = isWiFi ? adaptivePathLoss.n_wifi : adaptivePathLoss.n_ble;
    
    // Log-distance path loss model: d = 10^((RSSI0 - RSSI)/(10*n))
    float distance = pow(10.0, (rssi0 - node.filteredRssi) / (10.0 * n));
    
    // Apply signal quality degradation
    float qualityFactor = 1.0 + (1.0 - node.signalQuality) * 0.5;
    distance *= qualityFactor;
    
    // Bounds checking
    if (distance < 0.1) distance = 0.1;       // Minimum 10cm
    if (distance > 200.0) distance = 200.0;   // BLE max ~50m, WiFi max ~200m indoors
    
    return distance;
}

float getAverageHDOP(const std::vector<TriangulationNode> &nodes) {
    if (nodes.size() == 0) return 99.9;
    
    float totalHDOP = 0.0;
    int validCount = 0;
    
    for (const auto& node : nodes) {
        if (node.hasGPS && node.hdop > 0.0 && node.hdop < 50.0) {
            totalHDOP += node.hdop;
            validCount++;
        }
    }
    
    if (validCount == 0) return 99.9;
    return totalHDOP / validCount;
}

float calculateGDOP(const std::vector<TriangulationNode> &nodes) {
    if (nodes.size() < 3) return 999.9;
    
    float minAngle = 180.0;
    for (size_t i = 0; i < nodes.size(); i++) {
        for (size_t j = i + 1; j < nodes.size(); j++) {
            float dx1 = nodes[i].lat;
            float dy1 = nodes[i].lon;
            float dx2 = nodes[j].lat;
            float dy2 = nodes[j].lon;
            
            float dot = dx1 * dx2 + dy1 * dy2;
            float mag1 = sqrt(dx1*dx1 + dy1*dy1);
            float mag2 = sqrt(dx2*dx2 + dy2*dy2);
            
            if (mag1 > 0 && mag2 > 0) {
                float angle = acos(dot / (mag1 * mag2)) * 180.0 / M_PI;
                if (angle < minAngle) minAngle = angle;
            }
        }
    }
    
    if (minAngle < 20.0) return 9.0;
    if (minAngle < 30.0) return 5.0;
    if (minAngle < 45.0) return 3.0;
    return 1.5;
}

void initNodeKalmanFilter(TriangulationNode &node) {
    node.kalmanFilter.estimate = (float)node.rssi;
    node.kalmanFilter.errorCovariance = 10.0;
    node.kalmanFilter.processNoise = 0.5;
    node.kalmanFilter.measurementNoise = 4.0;
    node.kalmanFilter.initialized = true;
    node.filteredRssi = (float)node.rssi;
}

float kalmanFilterRSSI(TriangulationNode &node, int8_t measurement) {
    if (!node.kalmanFilter.initialized) {
        initNodeKalmanFilter(node);
        return (float)measurement;
    }
    
    if (node.rssiHistory.size() > 5) {
        float variance = 0.0;
        float mean = 0.0;
        for (int8_t rssi : node.rssiHistory) {
            mean += rssi;
        }
        mean /= node.rssiHistory.size();
        
        for (int8_t rssi : node.rssiHistory) {
            float diff = rssi - mean;
            variance += diff * diff;
        }
        variance /= node.rssiHistory.size();
        
        node.kalmanFilter.measurementNoise = max(2.0f, variance);
    }
    
    float prediction = node.kalmanFilter.estimate;
    float predictionCovariance = node.kalmanFilter.errorCovariance + node.kalmanFilter.processNoise;
    float kalmanGain = predictionCovariance / (predictionCovariance + node.kalmanFilter.measurementNoise);
    float estimate = prediction + kalmanGain * ((float)measurement - prediction);
    float errorCovariance = (1.0 - kalmanGain) * predictionCovariance;
    
    node.kalmanFilter.estimate = estimate;
    node.kalmanFilter.errorCovariance = errorCovariance;
    
    return estimate;
}

float calculateSignalQuality(const TriangulationNode &node) {
    if (node.rssiHistory.size() < 3) {
        // Even with few samples, factor in hit count for initial quality estimate
        float hitFactor = min(1.0f, (float)node.hitCount / 15.0f);
        return 0.3f + (hitFactor * 0.2f);  // Range 0.3-0.5 based on hits
    }

    float variance = 0.0;
    float mean = 0.0;
    for (int8_t rssi : node.rssiHistory) {
        mean += rssi;
    }
    mean /= node.rssiHistory.size();

    for (int8_t rssi : node.rssiHistory) {
        float diff = rssi - mean;
        variance += diff * diff;
    }
    variance /= node.rssiHistory.size();

    float stability = 1.0 / (1.0 + sqrt(variance));
    float strength = (node.filteredRssi + 100.0) / 100.0;
    strength = constrain(strength, 0.0, 1.0);

    // Hit count factor: more detections = higher confidence in this node's data
    // Saturates at ~15 hits (typical good detection count during scan)
    float hitFactor = min(1.0f, (float)node.hitCount / 15.0f);

    // Weight: 40% stability, 30% signal strength, 30% hit count
    // Node with strongest signal AND most hits gets highest weight
    return (stability * 0.4f + strength * 0.3f + hitFactor * 0.3f);
}

bool performWeightedTrilateration(const std::vector<TriangulationNode> &nodes, 
                                   float &estLat, float &estLon, float &confidence) {
    if (nodes.size() < 3) return false;
    
    std::vector<TriangulationNode> sortedNodes = nodes;
    std::sort(sortedNodes.begin(), sortedNodes.end(), 
              [](const TriangulationNode &a, const TriangulationNode &b) {
                  return a.signalQuality > b.signalQuality;
              });
    
    // This would bail on it if too low quality... 
    // float gdop = calculateGDOP(sortedNodes);
    // if (gdop > 6.0) return false;
    
    float avgHDOP = getAverageHDOP(sortedNodes);
    if (avgHDOP > 15.0) return false;
    
    float refLat = 0.0;
    float refLon = 0.0;
    for (const auto &node : sortedNodes) {
        refLat += node.lat;
        refLon += node.lon;
    }
    refLat /= sortedNodes.size();
    refLon /= sortedNodes.size();
    
    float sumWeightedEast = 0.0;
    float sumWeightedNorth = 0.0;
    float sumWeights = 0.0;
    
    size_t numNodes = std::min((size_t)5, sortedNodes.size());
    if (numNodes < 3) return false;
    
    for (size_t i = 0; i < numNodes; i++) {
        for (size_t j = i + 1; j < numNodes; j++) {
            for (size_t k = j + 1; k < numNodes; k++) {
                float e1, n1, e2, n2, e3, n3;
                geodeticToENU(sortedNodes[i].lat, sortedNodes[i].lon, refLat, refLon, e1, n1);
                geodeticToENU(sortedNodes[j].lat, sortedNodes[j].lon, refLat, refLon, e2, n2);
                geodeticToENU(sortedNodes[k].lat, sortedNodes[k].lon, refLat, refLon, e3, n3);
                
                float r1 = sortedNodes[i].distanceEstimate;
                float r2 = sortedNodes[j].distanceEstimate;
                float r3 = sortedNodes[k].distanceEstimate;
                
                float A = 2.0 * (e2 - e1);
                float B = 2.0 * (n2 - n1);
                float C = pow(r1, 2) - pow(r2, 2) - pow(e1, 2) + pow(e2, 2) - pow(n1, 2) + pow(n2, 2);
                
                float D = 2.0 * (e3 - e2);
                float E = 2.0 * (n3 - n2);
                float F = pow(r2, 2) - pow(r3, 2) - pow(e2, 2) + pow(e3, 2) - pow(n2, 2) + pow(n3, 2);
                
                float denominator = A * E - B * D;
                
                if (abs(denominator) > 0.001) {
                    float tripletEast = (C * E - F * B) / denominator;
                    float tripletNorth = (A * F - D * C) / denominator;
                    
                    float tripletWeight = sortedNodes[i].signalQuality * 
                                         sortedNodes[j].signalQuality * 
                                         sortedNodes[k].signalQuality;
                    
                    sumWeightedEast += tripletEast * tripletWeight;
                    sumWeightedNorth += tripletNorth * tripletWeight;
                    sumWeights += tripletWeight;
                }
            }
        }
    }
    
    if (sumWeights < 0.001) return false;
    
    float estEast = sumWeightedEast / sumWeights;
    float estNorth = sumWeightedNorth / sumWeights;
    
    float dLat = estNorth / 6371000.0 * 180.0 / M_PI;
    float dLon = estEast / (6371000.0 * cos(refLat * M_PI / 180.0)) * 180.0 / M_PI;
    
    estLat = refLat + dLat;
    estLon = refLon + dLon;
    
    float avgQuality = 0.0;
    for (size_t i = 0; i < numNodes; i++) {
        avgQuality += sortedNodes[i].signalQuality;
    }
    avgQuality /= numNodes;
    
    confidence = avgQuality * (1.0 - 0.1 * (avgHDOP - 1.0)) * (1.0 - 0.05 * (numNodes - 3));
    confidence = constrain(confidence, 0.0, 1.0);
    
    return true;
}

void broadcastTimeSyncRequest() {
    if (!rtcAvailable) return;
    if (rtcMutex == NULL) return;
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return;
    
    DateTime now = rtc.now();
    time_t currentTime = now.unixtime();
    
    xSemaphoreGive(rtcMutex);
    
    int64_t correctedMicros = getCorrectedMicroseconds();
    uint16_t subsecond = (correctedMicros % 1000000) / 10000;
    
    String syncMsg = getNodeId() + ": TIME_SYNC_REQ:" + 
                     String((unsigned long)currentTime) + ":" + 
                     String(subsecond) + ":" +
                     String((unsigned long)(correctedMicros & 0xFFFFFFFF));
    
    sendToSerial1(syncMsg, false);
    Serial.printf("[SYNC] Broadcast: %lu.%03u (drift-corrected)\n", currentTime, subsecond);
}

void updateNodeRSSI(TriangulationNode &node, int8_t newRssi) {
    node.rssi = newRssi;
    
    node.rssiRawWindow.push_back(newRssi);
    if (node.rssiRawWindow.size() > 5) {
        node.rssiRawWindow.erase(node.rssiRawWindow.begin());
    }
    
    if (node.rssiRawWindow.size() >= 5) {
        std::vector<int8_t> sorted = node.rssiRawWindow;
        std::sort(sorted.begin(), sorted.end());
        int8_t median = sorted[sorted.size() / 2];
        node.filteredRssi = kalmanFilterRSSI(node, median);
    } else {
        node.filteredRssi = kalmanFilterRSSI(node, newRssi);
    }
    
    node.rssiHistory.push_back(newRssi);
    if (node.rssiHistory.size() > RSSI_HISTORY_SIZE) {
        node.rssiHistory.erase(node.rssiHistory.begin());
    }
    
    node.signalQuality = calculateSignalQuality(node);
    node.lastUpdate = millis();
}

void handleTimeSyncResponse(const String &nodeId, time_t timestamp, uint32_t milliseconds) {
    if (!rtcAvailable) return;
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return;
    DateTime now = rtc.now();
    time_t localTime = now.unixtime();
    xSemaphoreGive(rtcMutex);
    
    int64_t localMicros = getCorrectedMicroseconds();
    
    int32_t timeOffset = (int32_t)(localTime - timestamp);
    
    uint32_t reportedPropDelay = 0;
    if (nodePropagationDelays.count(nodeId) > 0) {
        reportedPropDelay = nodePropagationDelays[nodeId];
    }
    
    int64_t effectiveMicrosOffset = (int64_t)localMicros - (int64_t)milliseconds - (int64_t)reportedPropDelay;
    
    bool found = false;
    for (auto &sync : nodeSyncStatus) {
        if (sync.nodeId == nodeId) {
            sync.rtcTimestamp = timestamp;
            sync.millisOffset = (uint32_t)((effectiveMicrosOffset < 0 ? -effectiveMicrosOffset : effectiveMicrosOffset) / 1000);
            sync.synced = (abs(timeOffset) == 0 && sync.millisOffset < 1);
            sync.lastSyncCheck = millis();
            found = true;
            break;
        }
    }
    
    if (!found) {
        NodeSyncStatus newSync;
        newSync.nodeId = nodeId;
        newSync.rtcTimestamp = timestamp;
        newSync.millisOffset = (uint32_t)((effectiveMicrosOffset < 0 ? -effectiveMicrosOffset : effectiveMicrosOffset) / 1000);
        newSync.synced = (abs(timeOffset) == 0 && newSync.millisOffset < 1);
        newSync.lastSyncCheck = millis();
        nodeSyncStatus.push_back(newSync);
    }
    
    Serial.printf("[SYNC] Node %s: offset=%ldus synced=%d\n", 
                  nodeId.c_str(), (long)effectiveMicrosOffset, 
                  (abs(timeOffset) == 0 && abs(effectiveMicrosOffset) < 1000));
}

bool verifyNodeSynchronization(uint32_t maxOffsetMs) {
    if (!triangulationActive) return true;
    
    uint32_t now = millis();
    int syncedCount = 0;
    int totalCount = 0;
    
    for (const auto &sync : nodeSyncStatus) {
        if (now - sync.lastSyncCheck < SYNC_CHECK_INTERVAL) {
            totalCount++;
            if (sync.synced && sync.millisOffset <= maxOffsetMs) {
                syncedCount++;
            }
        }
    }
    
    return (totalCount == 0) || (syncedCount >= (totalCount * 2 / 3));
}

String getNodeSyncStatus() {
    String status = "=== Node Synchronization Status ===\n";
    status += "Nodes tracked: " + String(nodeSyncStatus.size()) + "\n\n";
    
    for (const auto &sync : nodeSyncStatus) {
        status += sync.nodeId + ": ";
        status += sync.synced ? "SYNCED" : "OUT_OF_SYNC";
        status += " offset=" + String(sync.millisOffset) + "ms";
        status += " age=" + String((millis() - sync.lastSyncCheck) / 1000) + "s\n";
    }
    
    return status;
}

// Traingulation actions

// Task that handles ACK collection and cycle start (runs async to avoid blocking web handler)
void coordinatorSetupTask(void *parameter) {
    int duration = (int)(intptr_t)parameter;

    // Wait for child nodes to ACK - give mesh time to relay responses
    // Children use 0-2s staggered delay + mesh propagation time
    Serial.println("[TRIANGULATE] Waiting for child node ACKs...");
    vTaskDelay(pdMS_TO_TICKS(15000));  // Wait 15s for staggered ACKs (0-2s stagger + mesh latency + buffer)

    // Count total nodes: coordinator + ACK'd children
    int totalNodes = 1 + triangulateAcks.size();  // 1 = coordinator
    Serial.printf("[TRIANGULATE] ACK collection complete: %d child nodes responded (%d total)\n",
                  triangulateAcks.size(), totalNodes);

    // Require minimum 3 nodes for meaningful trilateration
    if (totalNodes < 3) {
        Serial.printf("[TRIANGULATE] ABORTED: Only %d nodes available, need at least 3 for triangulation\n", totalNodes);

        // Store error in lastResults so UI can show it
        {
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            antihunter::lastResults = ("TRIANGULATION FAILED: Only " + String(totalNodes) +
                                      " node(s) responded. Need at least 3 nodes for triangulation.\n"
                                      "Ensure other nodes are powered on and in mesh range.").c_str();
        }

        // Broadcast stop to any nodes that did ACK
        if (triangulateAcks.size() > 0) {
            String stopCmd = "@ALL TRIANGULATE_STOP";
            sendMeshCommand(stopCmd);
        }

        // Clean up state
        triangulationActive = false;
        triangulationInitiator = false;
        triangulateAcks.clear();
        coordinatorSetupTaskHandle = nullptr;
        vTaskDelete(NULL);
        return;  // Won't reach here but makes intent clear
    }

    // Additional buffer before next broadcast
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Broadcast synchronized cycle start time + node list for slot coordination
    int64_t cycleStartUs = getCorrectedMicroseconds();
    uint32_t cycleStartMs = (uint32_t)(cycleStartUs / 1000LL);

    // Build comma-separated list of node IDs (sorted for consistent slot assignment)
    // Include coordinator itself
    std::vector<String> nodeList;
    String coordinatorId = getNodeId();
    if (coordinatorId.length() > 0) {
        nodeList.push_back(coordinatorId);
    }
    for (const auto& ack : triangulateAcks) {
        nodeList.push_back(ack.nodeId);
    }
    std::sort(nodeList.begin(), nodeList.end());

    // Rebuild coordinator's own reporting schedule with all nodes
    reportingSchedule.reset();
    for (const auto& node : nodeList) {
        reportingSchedule.addNode(node);
    }
    reportingSchedule.cycleStartMs = cycleStartMs;

    String nodeListStr = "";
    for (size_t i = 0; i < nodeList.size(); i++) {
        if (i > 0) nodeListStr += ",";
        nodeListStr += nodeList[i];
    }

    String cycleCmd = "@ALL TRI_CYCLE_START:" + String(cycleStartMs) + ":" + nodeListStr;
    sendMeshCommand(cycleCmd);
    Serial.printf("[TRIANGULATE] Cycle start broadcast: %u ms, %d nodes: %s\n",
                  cycleStartMs, nodeList.size(), nodeListStr.c_str());

    vTaskDelay(pdMS_TO_TICKS(500));

    if (!workerTaskHandle) {
        xTaskCreatePinnedToCore(
            listScanTask,
            "triangulate",
            8192,
            (void *)(intptr_t)duration,
            1,
            &workerTaskHandle,
            1
        );
    }

    // Set active flag AFTER task is created to prevent UI race condition
    triangulationActive = true;

    Serial.println("[TRIANGULATE] Mesh sync initiated, scanning active");

    // Clean up - task deletes itself
    coordinatorSetupTaskHandle = nullptr;
    vTaskDelete(NULL);
}

void startTriangulation(const String &targetMac, int duration) {
    // Debounce check: prevent rapid restarts
    uint32_t timeSinceLastStop = millis() - lastTriangulationStopTime;
    if (lastTriangulationStopTime > 0 && timeSinceLastStop < TRIANGULATION_DEBOUNCE_MS) {
        uint32_t remainingWait = (TRIANGULATION_DEBOUNCE_MS - timeSinceLastStop) / 1000;
        Serial.printf("[TRIANGULATE] DEBOUNCE: Must wait %us before starting again (last stopped %us ago)\n",
                     remainingWait, timeSinceLastStop / 1000);
        return;
    }

    uint8_t macBytes[6];
    bool isIdentityId = false;

    if (targetMac.startsWith("T-") && targetMac.length() >= 6 && targetMac.length() <= 9) {
        bool validId = true;
        for (size_t i = 2; i < targetMac.length(); i++) {
            if (!isdigit(targetMac[i])) {
                validId = false;
                break;
            }
        }

        if (validId) {
            isIdentityId = true;
            strncpy(triangulationTargetIdentity, targetMac.c_str(), sizeof(triangulationTargetIdentity) - 1);
            triangulationTargetIdentity[sizeof(triangulationTargetIdentity) - 1] = '\0';
            memset(triangulationTarget, 0, 6);
            Serial.printf("[TRIANGULATE] Target is identity ID: %s\n", triangulationTargetIdentity);
        }
    }

    if (!isIdentityId) {
        if (!parseMac6(targetMac, macBytes)) {
            Serial.printf("[TRIANGULATE] Invalid MAC format: %s\n", targetMac.c_str());
            return;
        }
        memcpy(triangulationTarget, macBytes, 6);
        memset(triangulationTargetIdentity, 0, sizeof(triangulationTargetIdentity));
    }

    // // Force stop any existing triangulation first
    // if (triangulationActive) {
    //     Serial.println("[TRIANGULATE] Already active, forcing full stop first...");
    //     stopTriangulation();
    //     vTaskDelay(pdMS_TO_TICKS(2000)); // Wait for complete cleanup

    //     // After stop, re-check debounce since stop updates the timestamp
    //     uint32_t timeSinceStop = millis() - lastTriangulationStopTime;
    //     if (timeSinceStop < TRIANGULATION_DEBOUNCE_MS) {
    //         uint32_t remainingWait = (TRIANGULATION_DEBOUNCE_MS - timeSinceStop) / 1000;
    //         Serial.printf("[TRIANGULATE] DEBOUNCE: Must wait %us after forced stop before starting again\n", remainingWait);
    //         return;
    //     }
    // }

    if (workerTaskHandle) {
        Serial.println("[TRIANGULATE] WARNING: Worker task still exists, stopping...");
        stopRequested = true;

        uint32_t taskStopWait = millis();
        while (workerTaskHandle != nullptr && (millis() - taskStopWait) < 3000) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (workerTaskHandle != nullptr) {
            Serial.println("[TRIANGULATE] ERROR: Worker task still running after 3s, aborting start");
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }

    triangulationNodes.clear();
    nodeSyncStatus.clear();
    triangulationNodes.reserve(10);
    nodeSyncStatus.reserve(10);
    triangulationStart = millis();
    triangulationDuration = duration;
    currentScanMode = SCAN_BOTH;
    stopRequested = false;
    triangulationInitiator = true;
    reportingSchedule.reset();

    // Clear ACK and report tracking for new session
    triangulateAcks.clear();
    triangulateReportedNodes.clear();
    waitingForFinalReports = false;
    stopSentTimestamp = 0;
    ackCollectionStart = millis();

    Serial.printf("[TRIANGULATE] Initiator started for %s (%ds)\n", targetMac.c_str(), duration);

    broadcastTimeSyncRequest();
    vTaskDelay(pdMS_TO_TICKS(2000));

    String myNodeId = getNodeId();
    String cmd = "@ALL TRIANGULATE_START:" + targetMac + ":" + String(duration) + ":" + myNodeId + ":" + String(currentRFEnvironment);
    sendMeshCommand(cmd);

    Serial.printf("[TRIANGULATE] Broadcast sent to mesh nodes (initiator: %s)\n", myNodeId.c_str());

    // Create async task to collect ACKs and start scanning (avoids blocking web handler)
    if (!coordinatorSetupTaskHandle) {
        xTaskCreatePinnedToCore(
            coordinatorSetupTask,
            "triCoordSetup",
            4096,
            (void *)(intptr_t)duration,
            2,  // Higher priority than scanner
            &coordinatorSetupTaskHandle,
            1
        );
        Serial.println("[TRIANGULATE] Coordinator setup task created (async ACK collection)");
    }
}

uint32_t calculateAdaptiveTimeout(uint32_t baseTimeoutMs, float perNodeFactor) {
    // Calculate adaptive timeout based on node count and measured mesh latency
    uint32_t timeout = baseTimeoutMs;

    // Factor in number of nodes (more nodes = more potential for delays)
    uint32_t nodeCount = triangulateAcks.size();
    if (nodeCount > 0) {
        timeout += (uint32_t)(nodeCount * perNodeFactor);
    }

    // Factor in measured mesh propagation delays
    uint32_t maxPropDelay = 0;
    uint32_t avgPropDelay = 0;
    uint32_t delayCount = 0;

    for (const auto& pair : nodePropagationDelays) {
        uint32_t delay = pair.second;  // Delay in microseconds
        if (delay < 1000000) {  // Sanity check: ignore delays > 1 second (likely wraparound)
            if (delay > maxPropDelay) {
                maxPropDelay = delay;
            }
            avgPropDelay += delay;
            delayCount++;
        }
    }

    if (delayCount > 0) {
        avgPropDelay /= delayCount;
        // Add 3x worst-case propagation delay (convert from us to ms, multiply by 3 for safety)
        uint32_t latencyMargin = (maxPropDelay / 1000) * 3;
        timeout += latencyMargin;

        Serial.printf("[ADAPTIVE_TIMEOUT] Base=%ums, Nodes=%u (+%.0fms), MaxProp=%uus (+%ums), Total=%ums\n",
                     baseTimeoutMs, nodeCount, nodeCount * perNodeFactor,
                     maxPropDelay, latencyMargin, timeout);
    } else {
        Serial.printf("[ADAPTIVE_TIMEOUT] Base=%ums, Nodes=%u (+%.0fms), No latency data, Total=%ums\n",
                     baseTimeoutMs, nodeCount, nodeCount * perNodeFactor, timeout);
    }

    return timeout;
}

void markTriangulationStopFromMesh() {
    triStopCameFromMesh = true;
}

void stopTriangulation() {
    if (!triangulationActive) {
        Serial.println("[TRIANGULATE] Not active, nothing to stop");
        return;
    }

    Serial.println("[TRIANGULATE] Stop requested, beginning cleanup...");

    if (triangulationInitiator && !triStopCameFromMesh) {
        String stopCmd = "@ALL TRIANGULATE_STOP";
        sendMeshCommand(stopCmd);
        stopSentTimestamp = millis();
        waitingForFinalReports = true;
        
        for (auto &ack : triangulateAcks) {
            ack.reportReceived = false;
            ack.reportTimestamp = 0;
        }

        Serial.printf("[TRIANGULATE] Stop broadcast sent to all child nodes (%d ACK'd), reset report flags\n",
                     triangulateAcks.size());
        Serial.println("[TRIANGULATE] Waiting for late ACKs and initial T_D reports...");
        vTaskDelay(pdMS_TO_TICKS(10000));
        Serial.printf("[TRIANGULATE] After initial wait: %d nodes in tracking\n", triangulateAcks.size());
        if (triangulateAcks.size() > 0) {
            Serial.printf("[TRIANGULATE] Waiting for reports from %d nodes...\n", triangulateAcks.size());
            uint32_t waitStart = millis();
            const uint32_t REPORT_TIMEOUT = calculateAdaptiveTimeout(8000, 2000.0f);  // Increased from 3000/1000 for mesh reliability
            const uint32_t CHECK_INTERVAL = 100;

            int lastNodeCount = triangulateAcks.size();
            uint32_t lastNewNodeTime = millis();

            while (millis() - waitStart < REPORT_TIMEOUT) {
                // Count how many nodes have reported
                int reportedCount = 0;
                int totalAcked = triangulateAcks.size();

                for (const auto &ack : triangulateAcks) {
                    if (ack.reportReceived) {
                        reportedCount++;
                    }
                }

                // Check if new nodes were discovered (late T_D from nodes whose ACK was lost)
                if (totalAcked > lastNodeCount) {
                    Serial.printf("[TRIANGULATE] New node discovered! Now have %d nodes (was %d)\n",
                                 totalAcked, lastNodeCount);
                    lastNodeCount = totalAcked;
                    lastNewNodeTime = millis();
                }

                Serial.printf("[TRIANGULATE] Reports: %d/%d (%.0f%%)\n",
                             reportedCount, totalAcked, (reportedCount * 100.0f) / totalAcked);

                // All nodes reported - but wait a bit longer if we recently discovered new nodes
                // This gives time for more late T_Ds to arrive
                if (reportedCount >= totalAcked) {
                    uint32_t timeSinceNewNode = millis() - lastNewNodeTime;
                    if (timeSinceNewNode < 3000) {
                        Serial.printf("[TRIANGULATE] All %d nodes reported, but waiting %ums more for potential late nodes\n",
                                     reportedCount, 3000 - timeSinceNewNode);
                        vTaskDelay(pdMS_TO_TICKS(CHECK_INTERVAL));
                        continue;
                    }
                    Serial.printf("[TRIANGULATE] All %d nodes reported! Proceeding...\n", reportedCount);
                    break;
                }

                // Check if we're making progress
                uint32_t elapsed = millis() - waitStart;
                if (elapsed > 2000 && reportedCount == 0) {
                    Serial.println("[TRIANGULATE] WARNING: No reports yet after 2s");
                }

                // Yield more aggressively to prevent watchdog issues
                vTaskDelay(pdMS_TO_TICKS(CHECK_INTERVAL));
            }

            // Final status
            int finalReported = 0;
            for (const auto &ack : triangulateAcks) {
                if (ack.reportReceived) {
                    finalReported++;
                } else {
                    Serial.printf("[TRIANGULATE] WARNING: Node %s did not report\n", ack.nodeId.c_str());
                }
            }

            Serial.printf("[TRIANGULATE] Wait complete: %d/%d nodes reported\n",
                         finalReported, triangulateAcks.size());

            // Grace period to process any final in-flight T_D messages (e.g., BLE after WiFi)
            Serial.println("[TRIANGULATE] Grace period for final T_D messages...");
            vTaskDelay(pdMS_TO_TICKS(2000));
        } else {
            Serial.println("[TRIANGULATE] No ACKs received - no child nodes participated");
            vTaskDelay(pdMS_TO_TICKS(700));
        }
    }

    uint32_t elapsedMs = millis() - triangulationStart;
    uint32_t elapsedSec = elapsedMs / 1000;

    Serial.printf("[TRIANGULATE] Stopping after %us (%u nodes reported)\n", elapsedSec, triangulationNodes.size());

    if (triangulationInitiator && (triAccum.wifiHitCount > 0 || triAccum.bleHitCount > 0)) {
        String myNodeId = getNodeId();
        if (myNodeId.length() == 0) {
            myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
        }
        
        bool selfNodeExists = false;
        for (const auto &node : triangulationNodes) {
            if (node.nodeId == myNodeId) {
                selfNodeExists = true;
                Serial.printf("[TRIANGULATE] Self node already exists with %d hits\n", node.hitCount);
                break;
            }
        }
        
        if (!selfNodeExists) {
            int8_t avgRssi;
            int totalHits;
            bool isBLE;
            
            if (triAccum.wifiHitCount > 0) {
                avgRssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
                totalHits = triAccum.wifiHitCount;
                isBLE = false;
            } else {
                avgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
                totalHits = triAccum.bleHitCount;
                isBLE = true;
            }
            
            TriangulationNode selfNode;
            selfNode.nodeId = myNodeId;
            selfNode.lat = triAccum.lat;
            selfNode.lon = triAccum.lon;
            selfNode.hdop = triAccum.hdop;
            selfNode.rssi = avgRssi;
            selfNode.hitCount = totalHits;
            selfNode.hasGPS = triAccum.hasGPS;
            selfNode.isBLE = isBLE;
            selfNode.lastUpdate = millis();

            initNodeKalmanFilter(selfNode);
            updateNodeRSSI(selfNode, avgRssi);
            selfNode.distanceEstimate = rssiToDistance(selfNode, !isBLE);
            
            triangulationNodes.push_back(selfNode);
            Serial.printf("[TRIANGULATE] Added coordinator self-detection: %d hits, RSSI=%d, type=%s\n",
                         totalHits, avgRssi, isBLE ? "BLE" : "WiFi");
        }
    }

    Serial.println("[TRIANGULATE] Stopping scan task...");
    stopRequested = true;
    vTaskDelay(pdMS_TO_TICKS(500));

    if (workerTaskHandle != nullptr) {
        uint32_t taskStopWait = millis();

        // Wait for task to set workerTaskHandle = nullptr before deleting itself
        // Do NOT call eTaskGetState() - the handle becomes invalid after vTaskDelete
        // and calling it on a deleted task is undefined behavior (crash risk)
        while (workerTaskHandle != nullptr && (millis() - taskStopWait) < 3000) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (workerTaskHandle == nullptr) {
            Serial.println("[TRIANGULATE] Worker task exited cleanly");
        } else {
            Serial.println("[TRIANGULATE] WARNING: Worker task didn't exit within 3s, will exit on its own");
        }
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    Serial.println("[TRIANGULATE] Calculating final results...");
    String results = calculateTriangulation();
    Serial.printf("[TRIANGULATE] Final results calculated: %d chars\n", results.length());
    Serial.printf("[TRIANGULATE] Results preview: %.100s...\n", results.c_str());

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = results.c_str();
        Serial.printf("[TRIANGULATE] Final results stored in lastResults (%d chars)\n", antihunter::lastResults.length());
    }
    
    if (sdAvailable) {
        String logEntry = getFormattedTimestamp() + " TRIANGULATION_COMPLETE\n";
        logEntry += results;
        logEntry += "\n---\n";
        logToSD(logEntry);
    }

    uint32_t totalElapsed = (millis() - triangulationStart) / 1000;
    String targetMacStr = macFmt6(triangulationTarget);

    float estLat = 0.0, estLon = 0.0, confidence = 0.0;
    std::vector<TriangulationNode> gpsNodes;
    for (const auto& node : triangulationNodes) {
        Serial.printf("[TRIANGULATE] Node %s: hits=%d RSSI=%d GPS=%s\n",
                      node.nodeId.c_str(), node.hitCount, node.rssi,
                      node.hasGPS ? "YES" : "NO");
        if (node.hasGPS) {
            gpsNodes.push_back(node);
        }
    }

    String resultMsg = getNodeId() + ": T_C: MAC=" + targetMacStr +
                " Nodes=" + String(gpsNodes.size());

    Serial.printf("[TRIANGULATE] Total nodes: %u, GPS nodes: %u, Coordinator: %s\n",
                  triangulationNodes.size(), gpsNodes.size(), 
                  triangulationInitiator ? "YES" : "NO");

    if (gpsNodes.size() >= 3) {
        Serial.println("[TRIANGULATE] Sufficient GPS nodes, attempting trilateration...");
        bool trilaterationSuccess = performWeightedTrilateration(gpsNodes, estLat, estLon, confidence);
        Serial.printf("[TRIANGULATE] Trilateration %s (confidence=%.1f%%)\n",
                      trilaterationSuccess ? "SUCCESS" : "FAILED", confidence * 100.0);

        if (trilaterationSuccess && confidence > 0.0) {
            resultMsg += " GPS=" + String(estLat, 6) + "," + String(estLon, 6);
            resultMsg += " CONF=" + String(confidence * 100.0, 1);

            String mapsUrl = "https://www.google.com/maps?q=" + 
                           String(estLat, 6) + "," + String(estLon, 6);
            resultMsg += " URL=" + mapsUrl;

            if (triangulationInitiator) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) myNodeId = "COORDINATOR";

                float avgDistance = 0.0;
                int validDistances = 0;
                for (const auto& node : gpsNodes) {
                    if (node.distanceEstimate > 0) {
                        avgDistance += node.distanceEstimate;
                        validDistances++;
                    }
                }
                if (validDistances > 0) avgDistance /= validDistances;

                float avgHDOP = getAverageHDOP(gpsNodes);
                float gdop = calculateGDOP(gpsNodes);

                float gpsPositionError = avgHDOP * 2.5;
                float rssiDistanceError = avgDistance * 0.20;
                float geometricError = gdop * 5.0;
                float syncError = verifyNodeSynchronization(10) ? 0.0 : (avgDistance * 0.10);
                float calibError = pathLoss.calibrated ? 0.0 : (avgDistance * 0.15);

                float uncertainty = sqrt(
                    gpsPositionError * gpsPositionError +
                    rssiDistanceError * rssiDistanceError +
                    geometricError * geometricError +
                    syncError * syncError +
                    calibError * calibError
                );
                float cep = uncertainty * 0.59;

                apFinalResult.hasResult = true;
                apFinalResult.latitude = estLat;
                apFinalResult.longitude = estLon;
                apFinalResult.confidence = confidence;
                apFinalResult.uncertainty = cep;
                apFinalResult.timestamp = millis();
                apFinalResult.coordinatorNodeId = myNodeId;

                String finalMsg = myNodeId + ": T_F: MAC=" + targetMacStr +
                                " GPS=" + String(estLat, 6) + "," + String(estLon, 6) +
                                " CONF=" + String(confidence * 100.0, 1) +
                                " UNC=" + String(cep, 1);
                sendToSerial1(finalMsg, true);
                Serial.printf("[TRIANGULATE] Initiator sent final result: %s\n", finalMsg.c_str());

                vTaskDelay(pdMS_TO_TICKS(2000));
            }
        } else {
            if (triangulationInitiator) {
                Serial.println("[TRIANGULATE] Trilateration failed - T_F not sent");
            }
        }
    } else {
        if (triangulationInitiator) {
            Serial.printf("[TRIANGULATE] Insufficient GPS nodes (%u < 3) - T_F not sent\n", gpsNodes.size());
        }
    }

    // Flush rate limiter BEFORE sending final results to prevent drops
    rateLimiter.flush();
    Serial.println("[TRIANGULATE] Rate limiter flushed for final results");

    // Coordinator sends its own T_D for data aggregation
    // This is used by external systems to see all detection data
    // Single source of truth is TRIANGULATION_FINAL (calculated position), not the raw data
    String myNodeId = getNodeId();
    int selfHits = 0;
    int8_t selfBestRSSI = -128;
    bool selfDetected = false;

    for (const auto& node : triangulationNodes) {
        if (node.nodeId == myNodeId) {
            selfHits = node.hitCount;
            selfBestRSSI = node.rssi;
            selfDetected = true;
            break;
        }
    }

    if (selfDetected && selfHits > 0) {
        String dataMsg = myNodeId + ": T_D: " + macFmt6(triangulationTarget) +
                        " Hits=" + String(selfHits) +
                        " RSSI:" + String(selfBestRSSI);

        if (gpsValid) {
            float hdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.9;
            dataMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            dataMsg += " HDOP=" + String(hdop, 1);
        }

        sendToSerial1(dataMsg, true);
        Serial.printf("[TRIANGULATE] Sent self-detection data: %s\n", dataMsg.c_str());
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if (triangulationInitiator) {
        bool sent = sendToSerial1(resultMsg, true);
        Serial.printf("[TRIANGULATE] Initiator sent T_C: %s\n", sent ? "SUCCESS" : "FAILED");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    // Clear flags first to prevent any race conditions
    triangulationActive = false;
    triangulationInitiator = false;
    waitingForFinalReports = false;
    triangulationDuration = 0;
    memset(triangulationTarget, 0, 6);

    triAccum.wifiHitCount = 0;
    triAccum.wifiRssiSum = 0.0f;
    triAccum.bleHitCount = 0;
    triAccum.bleRssiSum = 0.0f;
    triAccum.lastSendTime = 0;

    apFinalResult.hasResult = false;
    apFinalResult.latitude = 0.0;
    apFinalResult.longitude = 0.0;
    apFinalResult.confidence = 0.0;
    apFinalResult.uncertainty = 0.0;
    apFinalResult.timestamp = 0;
    apFinalResult.coordinatorNodeId = "";

    triangulationOrchestratorAssigned = false;
    triStopCameFromMesh = false;

    // Clear ACKs and reports
    triangulateAcks.clear();
    triangulateReportedNodes.clear();
    stopSentTimestamp = 0;

    // Clear node data to prevent memory accumulation across sessions
    triangulationNodes.clear();
    nodeSyncStatus.clear();

    // Record stop time for debounce mechanism (MUST be last)
    lastTriangulationStopTime = millis();

    Serial.println("[TRIANGULATE] Stopped, results generated, buffers cleared");
}

float haversineDistance(float lat1, float lon1, float lat2, float lon2) { //TODO make it more accurate 
    const float R = 6371000.0;
    float dLat = (lat2 - lat1) * M_PI / 180.0;
    float dLon = (lon2 - lon1) * M_PI / 180.0;
    float a = sin(dLat/2) * sin(dLat/2) +
              cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) *
              sin(dLon/2) * sin(dLon/2);
    return R * 2.0 * atan2(sqrt(a), sqrt(1-a));
}

void geodeticToENU(float lat, float lon, float refLat, float refLon, float &east, float &north) {
    float dLat = (lat - refLat) * M_PI / 180.0;
    float dLon = (lon - refLon) * M_PI / 180.0;
    float R = 6371000.0;
    east = R * dLon * cos(refLat * M_PI / 180.0);
    north = R * dLat;
}

String calculateTriangulation() {
    if (!triangulationActive) {
        return "Triangulation not active\n";
    }
    
    uint32_t elapsed = (millis() - triangulationStart) / 1000;
    
    String results = "\n=== Triangulation Results ===\n";
    results += "Target MAC: " + macFmt6(triangulationTarget) + "\n";
    results += "Duration: " + String(triangulationDuration) + "s\n";
    results += "Elapsed: " + String(elapsed) + "s\n";
    results += "Reporting Nodes: " + String(triangulationNodes.size()) + "\n";

    // Check clock sync status
    bool syncVerified = verifyNodeSynchronization(10);
    results += "Clock Sync: " + String(syncVerified ? "VERIFIED <10ms" : "WARNING >10ms") + "\n";

    // Add quick maps link at top if we have a final position
    if (apFinalResult.hasResult) {
        String quickMapsUrl = "https://www.google.com/maps?q=" +
                            String(apFinalResult.latitude, 6) + "," +
                            String(apFinalResult.longitude, 6);
        results += "Maps Link: " + quickMapsUrl + "\n";
    }
    results += "\n";

    // Display AP/Coordinator Final Result prominently if available
    if (apFinalResult.hasResult) {
        uint32_t age = (millis() - apFinalResult.timestamp) / 1000;
        results += "╔════════════════════════════════════════════════╗\n";
        results += "║       COORDINATOR FINAL RESULT                 ║\n";
        results += "╚════════════════════════════════════════════════╝\n";
        results += "Coordinator Node: " + apFinalResult.coordinatorNodeId + "\n";
        results += "Final Position:\n";
        results += "  Latitude:  " + String(apFinalResult.latitude, 6) + "\n";
        results += "  Longitude: " + String(apFinalResult.longitude, 6) + "\n";
        results += "  Confidence: " + String(apFinalResult.confidence * 100.0, 1) + "%\n";
        results += "  Uncertainty (CEP68): ±" + String(apFinalResult.uncertainty, 1) + "m\n";

        String mapsUrl = "https://www.google.com/maps?q=" +
                        String(apFinalResult.latitude, 6) + "," +
                        String(apFinalResult.longitude, 6);
        results += "  Maps: " + mapsUrl + "\n";
        results += "  Age: " + String(age) + "s\n";
        results += "════════════════════════════════════════════════\n\n";
    }
    
    // NO NODES RESPONDING :(
    if (triangulationNodes.size() == 0) {
        results += "--- No Mesh Nodes Responding ---\n\n";
        results += "\n=== End Triangulation ===\n";
        return results;
    }

    // Always show Node Reports section - regardless of GPS status
    results += "--- Node Reports ---\n";
    std::vector<TriangulationNode> gpsNodes;
    int gpsNodeCount = 0;
    for (const auto& node : triangulationNodes) {
        results += node.nodeId + ": ";
        results += "Filtered=" + String(node.filteredRssi, 1) + "dBm ";
        results += "Hits=" + String(node.hitCount) + " ";
        results += "Signal=" + String(node.signalQuality * 100.0, 1) + "% ";
        results += "Type=" + String(node.isBLE ? "BLE" : "WiFi") + " "; 

        if (node.hasGPS) {
            results += "GPS=" + String(node.lat, 6) + "," + String(node.lon, 6) + " ";
            results += "Dist=" + String(node.distanceEstimate, 1) + "m";

            if (node.hdop > 0.0 && node.hdop < 20.0) {
                results += " HDOP=" + String(node.hdop, 1);
            } else {
                results += "GPS rejected: " + node.nodeId + "  (HDOP=" + String(node.hdop, 1) + " too high)\n";
            }

            gpsNodes.push_back(node);
        } else {
            results += "GPS=NO";
        }
        results += "\n";

        if (node.hasGPS) {
            gpsNodeCount++;
        }
    }
    results += "\n";

    // Check GPS node status and show warnings if needed
    if (gpsNodeCount == 0) {
        results += "--- TRIANGULATION IMPOSSIBLE ---\n\n";
        results += String(triangulationNodes.size()) + " node(s) reporting, but none have GPS\n\n";
        results += "Cannot triangulate without position data.\n";
        results += "Triangulation requires GPS coordinates from nodes.\n\n";
        results += "\n=== End Triangulation ===\n";
        return results;
    }

    // Show status message when we don't have enough GPS nodes, but continue processing
    if (gpsNodeCount < 3) {
        results += "--- Insufficient GPS Nodes ---\n\n";
        results += "GPS nodes: " + String(gpsNodeCount) + "/3 required\n";
        results += "Total nodes: " + String(triangulationNodes.size()) + "\n\n";

        if (gpsNodeCount == 2) {
            results += "Have 2 GPS nodes - can show GPS-RSSI validation but need 1 more for triangulation.\n\n";
        } else if (gpsNodeCount == 1) {
            results += "Have 1 GPS node - need 2 more for triangulation.\n\n";
        }

        if (gpsNodeCount >= 1) {
            results += "Current GPS nodes:\n";
            for (const auto& node : gpsNodes) {
                results += "  • " + node.nodeId + " @ ";
                results += String(node.lat, 6) + "," + String(node.lon, 6) + "\n";
            }
            results += "\n";
        }

        results += "Non-GPS nodes:\n";
        for (const auto& node : triangulationNodes) {
            if (!node.hasGPS) {
                results += "  • " + node.nodeId + " (enable GPS)\n";
            }
        }
        results += "\n";

        // If we have < 2 GPS nodes, can't even do GPS-RSSI validation, so return here
        if (gpsNodeCount < 2) {
            results += "\n=== End Triangulation ===\n";
            return results;
        }
    }

    // GPS RSSI validation - show even with 2 GPS nodes
    if (gpsNodes.size() >= 2) {
        results += "--- GPS-RSSI Distance Validation ---\n";
        
        float totalError = 0.0;
        int validationCount = 0;
        
        for (size_t i = 0; i < gpsNodes.size(); i++) {
            for (size_t j = i + 1; j < gpsNodes.size(); j++) {
                float gpsDistance = haversineDistance(
                    gpsNodes[i].lat, gpsNodes[i].lon,
                    gpsNodes[j].lat, gpsNodes[j].lon
                );
                
                float rssiDist1 = gpsNodes[i].distanceEstimate;
                float rssiDist2 = gpsNodes[j].distanceEstimate;
                
                results += gpsNodes[i].nodeId + " <-> " + gpsNodes[j].nodeId + ": ";
                results += "GPS=" + String(gpsDistance, 1) + "m ";
                results += "RSSI=" + String(rssiDist1, 1) + "m/" + String(rssiDist2, 1) + "m";
                
                float minExpected = gpsDistance * 0.5;
                float maxExpected = gpsDistance * 2.0;
                float sumRssi = rssiDist1 + rssiDist2;
                
                if (sumRssi >= minExpected && sumRssi <= maxExpected) {
                    results += " ✓\n";
                    validationCount++;
                } else {
                    float error = abs(sumRssi - gpsDistance) / gpsDistance * 100.0;
                    totalError += error;
                    results += " ✗ (error: " + String(error, 0) + "%)\n";
                    validationCount++;
                }
            }
        }
        
        if (validationCount > 0) {
            float avgError = totalError / validationCount;
            results += "Avg error: " + String(avgError, 1) + "% ";
            
            if (avgError < 25.0) {
                results += "(GOOD)\n";
            } else if (avgError < 50.0) {
                results += "(FAIR - consider calibration)\n";
            } else {
                results += "(POOR - calibration needed)\n";
                results += "Run: POST /triangulate/calibrate?mac=<target>&distance=<meters>\n";
            }
        }
        results += "\n";
    }

    // If we only have 2 GPS nodes, we can show GPS-RSSI validation but can't triangulate
    if (gpsNodeCount < 3) {
        results += "Need 1 more GPS node for full triangulation.\n\n";
        results += "\n=== End Triangulation ===\n";
        return results;
    }

    // WE HAVE 3+ GPS NODES - DO TRIANGULATION!
    results += "--- Weighted GPS Trilateration ---\n";
    results += "Using " + String(gpsNodes.size()) + " GPS-equipped nodes\n";
    
    float avgHDOP = getAverageHDOP(gpsNodes);
    results += "Average HDOP: " + String(avgHDOP, 1);
    if (avgHDOP < 2.0) {
        results += " (EXCELLENT)\n\n";
    } else if (avgHDOP < 5.0) {
        results += " (GOOD)\n\n";
    } else if (avgHDOP < 10.0) {
        results += " (MODERATE)\n\n";
    } else {
        results += " (POOR)\n\n";
    }

    float estLat, estLon, confidence;
    bool hasRSSI = performWeightedTrilateration(gpsNodes, estLat, estLon, confidence);

    if (hasRSSI) {
        results += "ESTIMATED POSITION (RSSI):\n";
        results += "  Latitude:  " + String(estLat, 6) + "\n";
        results += "  Longitude: " + String(estLon, 6) + "\n";
        results += "  Confidence: " + String(confidence * 100.0, 1) + "%\n";
        results += "  Method: Weighted trilateration + Kalman filtering\n";


         // Calibrate path loss using estimated target position
        for (const auto& node : gpsNodes) {
            float distToTarget = haversineDistance(node.lat, node.lon, estLat, estLon);
            if (distToTarget > 0.5 && distToTarget < 50.0) {
                addPathLossSample(node.filteredRssi, distToTarget, !node.isBLE);
            }
        }

        if (gpsNodes.size() >= 1) {
            results += "\n  Position validation:\n";
            for (const auto& node : gpsNodes) {
                float gpsDistToNode = haversineDistance(estLat, estLon, node.lat, node.lon);
                float rssiDist = node.distanceEstimate;
                float error = abs(gpsDistToNode - rssiDist);
                float errorPercent = (error / rssiDist) * 100.0;
                results += "    " + node.nodeId + ": GPS=" + String(gpsDistToNode, 1) +
                        "m RSSI=" + String(rssiDist, 1) + "m ";
                if (errorPercent < 25.0) {
                    results += "✓\n";
                } else {
                    results += "✗ (" + String(errorPercent, 0) + "% error)\n";
                }
            }
        }
        
        const float UERE = 4.0;
        float gpsPositionError = avgHDOP * UERE;
        
        float totalRssiError = 0.0;
        float avgDistance = 0.0;
        float worstSignalQuality = 1.0;
        
        for (const auto &node : gpsNodes) {
            avgDistance += node.distanceEstimate;
            if (node.signalQuality < worstSignalQuality) {
                worstSignalQuality = node.signalQuality;
            }
            float nodeRssiError = node.distanceEstimate * (0.25 + (1.0 - node.signalQuality) * 0.30);
            if (node.isBLE) nodeRssiError *= 1.2;
            totalRssiError += nodeRssiError * nodeRssiError;
        }
        avgDistance /= gpsNodes.size();
        float rssiDistanceError = sqrt(totalRssiError / gpsNodes.size());
        
        float geometricError = 0.0;
        if (gpsNodes.size() == 3) {
            float x1 = gpsNodes[0].lat, y1 = gpsNodes[0].lon;
            float x2 = gpsNodes[1].lat, y2 = gpsNodes[1].lon;
            float x3 = gpsNodes[2].lat, y3 = gpsNodes[2].lon;
            float area = abs((x1*(y2-y3) + x2*(y3-y1) + x3*(y1-y2)) / 2.0);
            float areaMeters = area * 111000.0 * 111000.0;
            
            if (areaMeters < 100.0) geometricError = avgDistance * 0.5;
            else if (areaMeters < 500.0) geometricError = avgDistance * 0.25;
            else if (areaMeters < 1000.0) geometricError = avgDistance * 0.15;
            else geometricError = avgDistance * 0.05;
        } else {
            geometricError = avgDistance * 0.10 / sqrt(gpsNodes.size() - 2);
        }
        
        float syncError = syncVerified ? 0.0 : (avgDistance * 0.10);
        float calibError = pathLoss.calibrated ? 0.0 : (avgDistance * 0.15);
        
        float uncertainty = sqrt(
            gpsPositionError * gpsPositionError +
            rssiDistanceError * rssiDistanceError +
            geometricError * geometricError +
            syncError * syncError +
            calibError * calibError
        );
        
        float cep = uncertainty * 0.59;
        
        results += "  Uncertainty (CEP68): ±" + String(cep, 1) + "m\n";
        results += "  Uncertainty (95%): ±" + String(uncertainty, 1) + "m\n";
        results += "  Error budget: GPS=" + String(gpsPositionError, 1) + "m RSSI=" + 
                String(rssiDistanceError, 1) + "m Geom=" + String(geometricError, 1) + "m\n";
        results += "  Sync Status: " + String(syncVerified ? "Verified" : "Degraded") + "\n";
        results += "  GPS Quality: " + String(avgHDOP < 2.0 ? "Excellent" :
                                            (avgHDOP < 5.0 ? "Good" : 
                                            (avgHDOP < 10.0 ? "Moderate" : "Poor"))) + "\n\n";
        
        String mapsUrl = "https://www.google.com/maps?q=" + String(estLat, 6) + "," + String(estLon, 6);
        results += "  Maps: " + mapsUrl + "\n";
    } else {
        results += "TRILATERATION FAILED\n";
        results += "Reason: Poor geometry or signal quality\n";
        results += "Average HDOP: " + String(avgHDOP, 1) + " (>10.0 = poor)\n\n";
        results += "Suggestions:\n";
        results += "  • Reposition nodes (120 degree separation ideal)\n";
        results += "  • Improve with more runtime\n";
    }

    results += "\n=== End Triangulation ===\n";
    return results;

}


void disciplineRTCFromGPS() {
    if (!rtcAvailable || !gpsValid) return;
    if (!gps.date.isValid() || !gps.time.isValid()) return;
    if (triangulationActive) return;
    
    if (rtcMutex == nullptr) return;
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    
    DateTime rtcTime = rtc.now();
    time_t rtcEpoch = rtcTime.unixtime();
    
    xSemaphoreGive(rtcMutex);
    
    int year = gps.date.year();
    int month = gps.date.month();
    int day = gps.date.day();
    int hour = gps.time.hour();
    int minute = gps.time.minute();
    int second = gps.time.second();
    int centisecond = gps.time.centisecond();  // 0-99, 10ms precision

    if (year < 2020 || year > 2050) return;
    if (month < 1 || month > 12) return;
    if (day < 1 || day > 31) return;
    if (hour > 23 || minute > 59 || second > 59) return;

    DateTime gpsTime(year, month, day, hour, minute, second);
    time_t gpsEpoch = gpsTime.unixtime();

    // GPS time with centisecond precision (10ms)
    int64_t gpsEpochMicros = ((int64_t)gpsEpoch * 1000000LL) + (centisecond * 10000);

    int32_t offset = (int32_t)(gpsEpoch - rtcEpoch);

    if (abs(offset) > 2) {
        if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            rtc.adjust(gpsTime);
            xSemaphoreGive(rtcMutex);

            // Recalibrate boot-to-epoch offset with centisecond precision
            uint32_t bootMicros = micros();
            clockDiscipline.bootToEpochOffsetMicros = gpsEpochMicros - (int64_t)bootMicros;
            clockDiscipline.offsetCalibrated = true;
            clockDiscipline.disciplineCount = 0;
            clockDiscipline.converged = false;

            Serial.printf("[DISCIPLINE] Large correction: %ds, offset calibrated (cs=%d)\n", offset, centisecond);
        }
    } else if (!clockDiscipline.offsetCalibrated) {
        // Calibrate offset on first GPS sync with centisecond precision
        uint32_t bootMicros = micros();
        clockDiscipline.bootToEpochOffsetMicros = gpsEpochMicros - (int64_t)bootMicros;
        clockDiscipline.offsetCalibrated = true;
        Serial.printf("[DISCIPLINE] Boot-to-epoch offset calibrated (cs=%d)\n", centisecond);
    } else if (abs(offset) <= 1) {
        // Small drift - update offset without adjusting RTC
        uint32_t bootMicros = micros();
        clockDiscipline.bootToEpochOffsetMicros = gpsEpochMicros - (int64_t)bootMicros;

        if (clockDiscipline.lastDiscipline > 0) {
            uint32_t elapsed = millis() - clockDiscipline.lastDiscipline;

            if (abs(offset) == 1) {
                clockDiscipline.driftRate = (float)offset / (elapsed / 1000.0);
                clockDiscipline.disciplineCount++;

                if (clockDiscipline.disciplineCount >= 3) {
                    clockDiscipline.converged = true;
                }
            } else {
                clockDiscipline.disciplineCount++;
            }
        }
        clockDiscipline.lastDiscipline = millis();
    }
}

int64_t getCorrectedMicroseconds() {
    // Get Unix timestamp with microsecond precision for timing synchronization
    if (!rtcAvailable || rtcMutex == nullptr || !clockDiscipline.offsetCalibrated) {
        // Fallback to boot-relative microseconds if no RTC or not calibrated
        uint32_t currentMicros = micros();
        if (clockDiscipline.converged && clockDiscipline.lastDiscipline > 0) {
            uint32_t elapsedMs = millis() - clockDiscipline.lastDiscipline;
            int64_t correction = (int64_t)(clockDiscipline.driftRate * elapsedMs * 1000.0);
            return (int64_t)currentMicros - correction;
        }
        return (int64_t)currentMicros;
    }

    // Use calibrated boot-to-epoch offset to convert micros() to Unix timestamp
    uint32_t bootMicros = micros();
    int64_t unixTimestampMicros = (int64_t)bootMicros + clockDiscipline.bootToEpochOffsetMicros;

    // Apply drift correction if converged
    if (clockDiscipline.converged && clockDiscipline.lastDiscipline > 0) {
        uint32_t elapsedMs = millis() - clockDiscipline.lastDiscipline;
        int64_t correction = (int64_t)(clockDiscipline.driftRate * elapsedMs * 1000.0);
        unixTimestampMicros -= correction;
    }

    return unixTimestampMicros;
}

void calibrationTask(void *parameter) {
    struct CalibParams {
        uint8_t macBytes[6];
        float distance;
    };
    
    CalibParams* params = (CalibParams*)parameter;
    uint8_t macBytes[6];
    memcpy(macBytes, params->macBytes, 6);
    float knownDistance = params->distance;
    delete params;
    
    Serial.printf("[CALIB] Starting calibration task for target at %.1fm\n", knownDistance);
    Serial.println("[CALIB] Collecting WiFi and BLE samples for 30 seconds...");
    
    std::vector<int8_t> wifiSamples;
    std::vector<int8_t> bleSamples;
    
    // Initialize BLE if not already done
    NimBLEScan* pScan = NimBLEDevice::getScan();
    if (!pScan) {
        NimBLEDevice::init("");
        pScan = NimBLEDevice::getScan();
        pScan->setActiveScan(true);
        pScan->setInterval(100);
        pScan->setWindow(99);
    }
    
    uint32_t startTime = millis();
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    
    while (millis() - startTime < 30000) {
        uint32_t elapsed = (millis() - startTime) / 1000;
        
        // WiFi scan every 3 seconds to avoid blocking
        if (millis() - lastWiFiScan >= 3000) {
            int n = WiFi.scanNetworks(false, false, false, rfConfig.wifiChannelTime);
            for (int i = 0; i < n; i++) {
                uint8_t *bssid = WiFi.BSSID(i);
                if (memcmp(bssid, macBytes, 6) == 0) {
                    int8_t rssi = WiFi.RSSI(i);
                    wifiSamples.push_back(rssi);
                    Serial.printf("[CALIB] [%02ds] WiFi #%d: %d dBm\n", 
                                 elapsed, wifiSamples.size(), rssi);
                }
            }
            WiFi.scanDelete();
            lastWiFiScan = millis();
            vTaskDelay(pdMS_TO_TICKS(100)); // Yield to other tasks
        }
        
        // BLE scan every 3 seconds
        if (millis() - lastBLEScan >= 3000) {
            pScan->start(1, false);
            NimBLEScanResults results = pScan->getResults();
            
            for (int i = 0; i < results.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = results.getDevice(i);
                String deviceMacStr = device->getAddress().toString().c_str();
                
                uint8_t deviceMac[6];
                if (parseMac6(deviceMacStr, deviceMac) && 
                    memcmp(deviceMac, macBytes, 6) == 0) {
                    int8_t rssi = device->getRSSI();
                    bleSamples.push_back(rssi);
                    Serial.printf("[CALIB] [%02ds] BLE #%d: %d dBm\n", 
                                 elapsed, bleSamples.size(), rssi);
                }
            }
            
            pScan->clearResults();
            lastBLEScan = millis();
            vTaskDelay(pdMS_TO_TICKS(100)); // get out of the way of other tasks
        }
        
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    Serial.println("\n[CALIB] ========== CALIBRATION RESULTS ==========");
    
    // WiFi calibration
    if (wifiSamples.size() >= 10) {
        float meanRssi = 0;
        for (int8_t rssi : wifiSamples) {
            meanRssi += rssi;
        }
        meanRssi /= wifiSamples.size();
        
        float variance = 0;
        for (int8_t rssi : wifiSamples) {
            float diff = rssi - meanRssi;
            variance += diff * diff;
        }
        variance /= wifiSamples.size();
        float stdDev = sqrt(variance);
        
        // CORRECTED FORMULA
        pathLoss.rssi0_wifi = meanRssi + 10.0 * pathLoss.n_wifi * log10(knownDistance);
        
        Serial.println("[CALIB] WiFi Calibration: SUCCESS");
        Serial.printf("  Distance: %.1f m\n", knownDistance);
        Serial.printf("  Samples: %d\n", wifiSamples.size());
        Serial.printf("  Mean RSSI: %.1f dBm\n", meanRssi);
        Serial.printf("  Std Dev: %.1f dB\n", stdDev);
        Serial.printf("  Path loss exponent (n): %.2f\n", pathLoss.n_wifi);
        Serial.printf("  Calculated RSSI0 @ 1m: %.1f dBm\n", pathLoss.rssi0_wifi);
    }
    
    // BLE calibration
    if (bleSamples.size() >= 10) {
        float meanRssi = 0;
        for (int8_t rssi : bleSamples) {
            meanRssi += rssi;
        }
        meanRssi /= bleSamples.size();
        
        float variance = 0;
        for (int8_t rssi : bleSamples) {
            float diff = rssi - meanRssi;
            variance += diff * diff;
        }
        variance /= bleSamples.size();
        float stdDev = sqrt(variance);

        pathLoss.rssi0_ble = meanRssi + 10.0 * pathLoss.n_ble * log10(knownDistance);

        Serial.println("[CALIB] BLE Calibration: SUCCESS");
        Serial.printf("  Distance: %.1f m\n", knownDistance);
        Serial.printf("  Samples: %d\n", bleSamples.size());
        Serial.printf("  Mean RSSI: %.1f dBm\n", meanRssi);
        Serial.printf("  Std Dev: %.1f dB\n", stdDev);
        Serial.printf("  Path loss exponent (n): %.2f\n", pathLoss.n_ble);
        Serial.printf("  Calculated RSSI0 @ 1m: %.1f dBm\n", pathLoss.rssi0_ble);
    } else {
        Serial.printf("[CALIB] BLE Calibration: FAILED\n");
        Serial.printf("  Insufficient samples: %d (need ≥10)\n", bleSamples.size());
    }
    
    if (wifiSamples.size() >= 10 || bleSamples.size() >= 10) {
        pathLoss.calibrated = true;
        Serial.println("\n[CALIB] Status: CALIBRATED");
    } else {
        Serial.println("\n[CALIB] Status: FAILED");
    }
    
    Serial.println("[CALIB] ==========================================\n");
    
    // Clean up
    calibrationTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void calibratePathLoss(const String &targetMac, float knownDistance) {
    uint8_t macBytes[6];
    if (!parseMac6(targetMac, macBytes)) {
        Serial.printf("[CALIB] Invalid MAC format: %s\n", targetMac.c_str());
        return;
    }
    
    if (calibrationTaskHandle) {
        Serial.println("[CALIB] Calibration already in progress");
        return;
    }
    
    if (triangulationActive) {
        Serial.println("[CALIB] ERROR: Cannot calibrate during triangulation");
        return;
    }
    
    if (workerTaskHandle) {
        Serial.println("[CALIB] WARNING: Scan task active, may interfere");
    }
    
    // Allocate parameters on heap
    struct CalibParams {
        uint8_t macBytes[6];
        float distance;
    };
    
    CalibParams* params = new CalibParams();
    memcpy(params->macBytes, macBytes, 6);
    params->distance = knownDistance;

    // Create calibration task on core 1
    BaseType_t result = xTaskCreatePinnedToCore(
        calibrationTask,
        "calibrate",
        8192,
        (void*)params,
        1,
        &calibrationTaskHandle,
        1
    );

    if (result != pdPASS) {
        Serial.println("[CALIB] ERROR: Failed to create calibration task");
        delete params;
        return;
    }

    Serial.println("[CALIB] Calibration task started");
}

void processMeshTimeSyncWithDelay(const String &senderId, const String &message, uint32_t rxMicros) {
    int firstColon = message.indexOf(':', 14);
    if (firstColon < 0) return;
    
    int secondColon = message.indexOf(':', firstColon + 1);
    if (secondColon < 0) return;
    
    int thirdColon = message.indexOf(':', secondColon + 1);
    if (thirdColon < 0) return;
    
    time_t senderTime = strtoul(message.substring(14, firstColon).c_str(), nullptr, 10);
    uint16_t senderSubsec = message.substring(firstColon + 1, secondColon).toInt();
    uint32_t senderTxMicros = strtoul(message.substring(secondColon + 1, thirdColon).c_str(), nullptr, 10);
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return;
    DateTime now = rtc.now();
    time_t myTime = now.unixtime();
    xSemaphoreGive(rtcMutex);
    
    int64_t myMicros = getCorrectedMicroseconds();
    uint16_t mySubsec = (myMicros % 1000000) / 10000;
    
    uint32_t propagationDelay = rxMicros - senderTxMicros;
    if (propagationDelay > 100000) {
        propagationDelay = rxMicros + (0xFFFFFFFF - senderTxMicros);
    }
    
    nodePropagationDelays[senderId] = propagationDelay;
    
    Serial.printf("[SYNC] %s: prop_delay=%luus offset=%dms\n", 
                  senderId.c_str(), propagationDelay, (int)(myTime - senderTime));
    
    String response = getNodeId() + ": TIME_SYNC_RESP:" +
                    String((unsigned long)myTime) + ":" +
                    String(mySubsec) + ":" +
                    String((unsigned long)(myMicros & 0xFFFFFFFF)) + ":" +
                    String(propagationDelay);

    sendToSerial1(response, false);
}


// Adaptive path loss calibrated for 8 dBi RX antenna, indoor environment default
AdaptivePathLoss adaptivePathLoss = {
    -27.0,                             // rssi0_wifi (dBm @ 1m, 8dBi antenna)
    -62.0,                             // rssi0_ble (dBm @ 1m, 8dBi antenna, low-power BLE)
    3.2,                               // n_wifi (indoor path loss exponent)
    3.6,                               // n_ble (indoor path loss exponent)
    std::vector<PathLossSample>(),     // wifiSamples
    std::vector<PathLossSample>(),     // bleSamples
    false,                             // wifi_calibrated
    false,                             // ble_calibrated
    0                                  // lastUpdate
};

// Least squares estimation of path loss parameters
void estimatePathLossParameters(bool isWiFi) {
    auto& samples = isWiFi ? adaptivePathLoss.wifiSamples : adaptivePathLoss.bleSamples;
    
    if (samples.size() < adaptivePathLoss.MIN_SAMPLES) {
        Serial.printf("[PATH_LOSS] Insufficient samples for %s: %d/%d\n",
                     isWiFi ? "WiFi" : "BLE", samples.size(), adaptivePathLoss.MIN_SAMPLES);
        return;
    }
    
    // Linear regression on (log10(distance), RSSI)
    // Model: RSSI = A - 10*n*log10(d)
    // Where A = RSSI0, slope = -10*n
    
    float sum_x = 0, sum_y = 0, sum_xx = 0, sum_xy = 0;
    size_t n_samples = samples.size();
    
    for (const auto& sample : samples) {
        if (sample.distance > 0.1) {  // Minimum 10cm to avoid log(0)
            float x = log10(sample.distance);
            float y = sample.rssi;
            sum_x += x;
            sum_y += y;
            sum_xx += x * x;
            sum_xy += x * y;
        }
    }
    
    // Least squares solution
    float denominator = n_samples * sum_xx - sum_x * sum_x;
    if (abs(denominator) < 0.0001) {
        Serial.printf("[PATH_LOSS] Singular matrix for %s, using defaults\n",
                     isWiFi ? "WiFi" : "BLE");
        return;
    }
    
    float slope = (n_samples * sum_xy - sum_x * sum_y) / denominator;
    float intercept = (sum_y - slope * sum_x) / n_samples;
    
    // Extract parameters
    float n_estimate = -slope / 10.0;
    float rssi0_estimate = intercept;
    
    // Sanity check: n should be 1.5-6.0, RSSI0 should be -60 to -20 dBm
    if (n_estimate < 1.5 || n_estimate > 6.0) {
        Serial.printf("[PATH_LOSS] Invalid n=%f for %s, clamping\n", 
                     n_estimate, isWiFi ? "WiFi" : "BLE");
        n_estimate = constrain(n_estimate, 1.5, 6.0);
    }
    
    if (rssi0_estimate < -60.0 || rssi0_estimate > -20.0) {
        Serial.printf("[PATH_LOSS] Invalid RSSI0=%f for %s, clamping\n",
                     rssi0_estimate, isWiFi ? "WiFi" : "BLE");
        rssi0_estimate = constrain(rssi0_estimate, -60.0, -20.0);
    }
    
    // Update estimates with exponential moving average for stability
    const float alpha = 0.3;  // Learning rate
    if (isWiFi) {
        if (adaptivePathLoss.wifi_calibrated) {
            adaptivePathLoss.n_wifi = alpha * n_estimate + (1 - alpha) * adaptivePathLoss.n_wifi;
            adaptivePathLoss.rssi0_wifi = alpha * rssi0_estimate + (1 - alpha) * adaptivePathLoss.rssi0_wifi;
        } else {
            adaptivePathLoss.n_wifi = n_estimate;
            adaptivePathLoss.rssi0_wifi = rssi0_estimate;
            adaptivePathLoss.wifi_calibrated = true;
        }
        Serial.printf("[PATH_LOSS] WiFi updated: RSSI0=%.1f n=%.2f (samples=%d)\n",
                     adaptivePathLoss.rssi0_wifi, adaptivePathLoss.n_wifi, n_samples);
    } else {
        if (adaptivePathLoss.ble_calibrated) {
            adaptivePathLoss.n_ble = alpha * n_estimate + (1 - alpha) * adaptivePathLoss.n_ble;
            adaptivePathLoss.rssi0_ble = alpha * rssi0_estimate + (1 - alpha) * adaptivePathLoss.rssi0_ble;
        } else {
            adaptivePathLoss.n_ble = n_estimate;
            adaptivePathLoss.rssi0_ble = rssi0_estimate;
            adaptivePathLoss.ble_calibrated = true;
        }
        Serial.printf("[PATH_LOSS] BLE updated: RSSI0=%.1f n=%.2f (samples=%d)\n",
                     adaptivePathLoss.rssi0_ble, adaptivePathLoss.n_ble, n_samples);
    }
    
    adaptivePathLoss.lastUpdate = millis();
}

// Add sample when we have both RSSI and GPS-derived distance
void addPathLossSample(float rssi, float distance, bool isWiFi) {
    if (distance < 0.1 || distance > 200.0) return;  // Sanity check
    
    PathLossSample sample = {rssi, distance, isWiFi, millis()};
    auto& samples = isWiFi ? adaptivePathLoss.wifiSamples : adaptivePathLoss.bleSamples;
    
    samples.push_back(sample);
    
    // Keep only recent samples
    if (samples.size() > adaptivePathLoss.MAX_SAMPLES) {
        samples.erase(samples.begin());
    }
    
    // Trigger re-estimation every 10 samples or every 30 seconds
    if (samples.size() % 10 == 0 || millis() - adaptivePathLoss.lastUpdate > 30000) {
        estimatePathLossParameters(isWiFi);
    }
}