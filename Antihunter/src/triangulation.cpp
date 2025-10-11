#include "triangulation.h"
#include "scanner.h"
#include "hardware.h"
#include <math.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>

extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
static TaskHandle_t calibrationTaskHandle = nullptr;

ClockDiscipline clockDiscipline = {0.0, 0, 0, false};
PathLossCalibration pathLoss = {-40.0, -50.0, 2.5, 2.5, false};
std::map<String, uint32_t> nodePropagationDelays;
std::vector<NodeSyncStatus> nodeSyncStatus;
std::vector<TriangulationNode> triangulationNodes;
String calculateTriangulation();
uint8_t triangulationTarget[6];
uint32_t triangulationStart = 0;
uint32_t triangulationDuration = 0;
bool triangulationActive = false;


// Helpers
bool isTriangulationActive() {
    return triangulationActive;
}

float rssiToDistance(const TriangulationNode &node, bool isWiFi) {
    float rssi0 = isWiFi ? pathLoss.rssi0_wifi : pathLoss.rssi0_ble;
    float n = isWiFi ? pathLoss.n_wifi : pathLoss.n_ble;
    
    float distance = pow(10.0, (rssi0 - node.filteredRssi) / (10.0 * n));
    float qualityFactor = 1.0 + (1.0 - node.signalQuality) * 0.5;
    distance *= qualityFactor;
    
    return distance;
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
        return 0.5;
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
    
    return (stability * 0.6 + strength * 0.4);
}

bool performWeightedTrilateration(const std::vector<TriangulationNode> &nodes, 
                                   float &estLat, float &estLon, float &confidence) {
    if (nodes.size() < 3) return false;
    
    std::vector<TriangulationNode> sortedNodes = nodes;
    std::sort(sortedNodes.begin(), sortedNodes.end(), 
              [](const TriangulationNode &a, const TriangulationNode &b) {
                  return a.signalQuality > b.signalQuality;
              });
    
    float gdop = calculateGDOP(sortedNodes);
    if (gdop > 6.0) return false;
    
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
    
    confidence = avgQuality * (1.0 - 0.1 * (gdop - 1.0)) * (1.0 - 0.05 * (numNodes - 3));
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
    
    if (Serial1.availableForWrite() >= syncMsg.length()) {
        Serial1.println(syncMsg);
        Serial.printf("[SYNC] Broadcast: %lu.%03u (drift-corrected)\n", currentTime, subsecond);
    }
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

void startTriangulation(const String &targetMac, int duration) {
    uint8_t macBytes[6];
    if (!parseMac6(targetMac, macBytes)) {
        Serial.printf("[TRIANGULATE] Invalid MAC format: %s\n", targetMac.c_str());
        return;
    }
    
    if (workerTaskHandle) {
        Serial.println("[TRIANGULATE] Stopping existing scan task...");
        stopRequested = true;
        vTaskDelay(pdMS_TO_TICKS(500));
        workerTaskHandle = nullptr;
    }
    
    if (triangulationActive) {
        Serial.println("[TRIANGULATE] Already active, stopping first...");
        stopTriangulation();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    memcpy(triangulationTarget, macBytes, 6);
    triangulationNodes.clear();
    nodeSyncStatus.clear();
    
    triangulationNodes.reserve(10);
    nodeSyncStatus.reserve(10);
    
    triangulationStart = millis();
    triangulationDuration = duration;
    
    currentScanMode = SCAN_BOTH;
    stopRequested = false;
    
    triangulationActive = true;
    
    Serial.printf("[TRIANGULATE] Started for %s (%ds)\n", targetMac.c_str(), duration);
    
    broadcastTimeSyncRequest();
    
    String cmd = "@ALL TRIANGULATE_START:" + targetMac + ":" + String(duration);
    sendMeshCommand(cmd);
    
    vTaskDelay(pdMS_TO_TICKS(100));
    
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
    
    Serial.println("[TRIANGULATE] Mesh sync check initiated, scanning active");
}

void stopTriangulation() {
    if (!triangulationActive) {
        Serial.println("[TRIANGULATE] Not active, nothing to stop");
        return;
    }
    
    uint32_t elapsedMs = millis() - triangulationStart;
    uint32_t elapsedSec = elapsedMs / 1000;
    
    Serial.printf("[TRIANGULATE] Stopping after %us (%u nodes reported)\n", 
                  elapsedSec, triangulationNodes.size());
    
    String results = calculateTriangulation();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = results.c_str();
    }
    
    if (sdAvailable) {
        String logEntry = getFormattedTimestamp() + " TRIANGULATION_COMPLETE\n";
        logEntry += results;
        logEntry += "\n---\n";
        logToSD(logEntry);
    }

    String resultMsg = getNodeId() + ": TRIANGULATE_COMPLETE: Nodes=" + 
                       String(triangulationNodes.size());
    if (Serial1.availableForWrite() >= resultMsg.length()) {
        Serial1.println(resultMsg);
    }

    triangulationActive = false;
    triangulationDuration = 0;
    memset(triangulationTarget, 0, 6);

    Serial.println("[TRIANGULATE] Stopped and results generated");
}

float haversineDistance(float lat1, float lon1, float lat2, float lon2) {
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
    results += "Clock Sync: " + String(syncVerified ? "VERIFIED (<10ms)" : "WARNING (>10ms)") + "\n\n";
    
    // Count GPS-equipped nodes
    int gpsNodeCount = 0;
    for (const auto& node : triangulationNodes) {
        if (node.hasGPS) gpsNodeCount++;
    }
    
    // NO NODES RESPONDING :(
    if (triangulationNodes.size() == 0) {
        results += "--- No Mesh Nodes Responding ---\n\n";  
        results += "\n=== End Triangulation ===\n";
        return results;
    }
    
    // NODES RESPONDING BUT NO GPS
    if (gpsNodeCount == 0) {
        results += "--- TRIANGULATION IMPOSSIBLE ---\n\n";
        results += String(triangulationNodes.size()) + " node(s) reporting, but NONE have GPS\n\n";
        results += "Cannot triangulate without position data.\n";
        results += "Triangulation requires GPS coordinates from nodes.\n\n";
        results += "Enable GPS on mesh nodes:\n";
        results += "  • Check GPS module connection\n";
        results += "  • Wait for satellite lock (LED indicator)\n";
        results += "  • Check '/gps' endpoint on each node\n";
        
        results += "\n=== End Triangulation ===\n";
        return results;
    }
    
    // INSUFFICIENT GPS NODES
    if (gpsNodeCount < 3) {
        results += "--- Insufficient GPS Nodes ---\n\n";
        results += "GPS nodes: " + String(gpsNodeCount) + "/3 required\n";
        results += "Total nodes: " + String(triangulationNodes.size()) + "\n\n";
        
        results += "Cannot triangulate with < 3 GPS positions.\n";
        results += "Need " + String(3 - gpsNodeCount) + " more GPS-equipped node(s).\n\n";
        
        results += "Current GPS nodes:\n";
        for (const auto& node : triangulationNodes) {
            if (node.hasGPS) {
                results += "  • " + node.nodeId + " @ ";
                results += String(node.lat, 6) + "," + String(node.lon, 6) + "\n";
            }
        }
        
        results += "\nNon-GPS nodes:\n";
        for (const auto& node : triangulationNodes) {
            if (!node.hasGPS) {
                results += "  • " + node.nodeId + " (enable GPS)\n";
            }
        }
        
        results += "\n=== End Triangulation ===\n";
        return results;
    }
    
    // WE HAVE 3+ GPS NODES - DO THINGS!
    std::vector<TriangulationNode> gpsNodes;
    
    results += "--- Node Reports ---\n";
    for (const auto& node : triangulationNodes) {
        results += node.nodeId + ": ";
        results += "Filtered=" + String(node.filteredRssi, 1) + "dBm ";
        results += "Hits=" + String(node.hitCount) + " ";
        results += "Q=" + String(node.signalQuality * 100.0, 0) + "% ";
        
        if (node.hasGPS) {
            results += "GPS=" + String(node.lat, 6) + "," + String(node.lon, 6) + " ";
            results += "Dist=" + String(node.distanceEstimate, 1) + "m";
            gpsNodes.push_back(node);
        } else {
            results += "GPS=NO";
        }
        results += "\n";
    }
    results += "\n";
    
    results += "--- Weighted GPS Trilateration ---\n";
    results += "Using " + String(gpsNodes.size()) + " GPS-equipped nodes\n\n";
    
    float estLat, estLon, confidence;
    if (performWeightedTrilateration(gpsNodes, estLat, estLon, confidence)) {
        results += "ESTIMATED POSITION:\n";
        results += "  Latitude:  " + String(estLat, 6) + "\n";
        results += "  Longitude: " + String(estLon, 6) + "\n";
        results += "  Confidence: " + String(confidence * 100.0, 1) + "%\n";
        
        float avgDist = 0.0;
        for (const auto &node : gpsNodes) {
            avgDist += node.distanceEstimate;
        }
        avgDist /= gpsNodes.size();
        
        float uncertainty = avgDist * (0.15 + (1.0 - confidence) * 0.35);
        results += "  Uncertainty: ±" + String(uncertainty, 1) + "m\n";
        results += "  Sync: " + String(syncVerified ? "Verified" : "Degraded") + "\n";
        results += "  GDOP: " + String(calculateGDOP(gpsNodes), 1) + "\n\n";
        
        String mapsUrl = "https://www.google.com/maps?q=" + String(estLat, 6) + "," + String(estLon, 6);
        results += "  Maps: " + mapsUrl + "\n";
    } else {
        results += "TRILATERATION FAILED\n";
        results += "Reason: Poor geometry or signal quality\n";
        results += "GDOP: " + String(calculateGDOP(gpsNodes), 1) + " (>3.0 = poor)\n\n";
        results += "Suggestions:\n";
        results += "  • Reposition nodes (120° separation ideal)\n";
        results += "  • Improve signal quality\n";
        results += "  • Add more GPS nodes\n";
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
    
    if (year < 2020 || year > 2050) return;
    if (month < 1 || month > 12) return;
    if (day < 1 || day > 31) return;
    if (hour > 23 || minute > 59 || second > 59) return;
    
    DateTime gpsTime(year, month, day, hour, minute, second);
    time_t gpsEpoch = gpsTime.unixtime();
    
    int32_t offset = (int32_t)(gpsEpoch - rtcEpoch);
    
    if (abs(offset) > 2) {
        if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            rtc.adjust(gpsTime);
            xSemaphoreGive(rtcMutex);
            
            clockDiscipline.disciplineCount = 0;
            clockDiscipline.converged = false;
            
            Serial.printf("[DISCIPLINE] Large correction: %ds\n", offset);
        }
    } else if (abs(offset) == 1) {
        if (clockDiscipline.lastDiscipline > 0) {
            uint32_t elapsed = millis() - clockDiscipline.lastDiscipline;
            
            clockDiscipline.driftRate = (float)offset / (elapsed / 1000.0);
            clockDiscipline.disciplineCount++;
            
            Serial.printf("[DISCIPLINE] Drift rate: %.6f s/s (%.2f ppm)\n", 
                         clockDiscipline.driftRate, 
                         clockDiscipline.driftRate * 1e6);
            
            if (clockDiscipline.disciplineCount >= 3) {
                clockDiscipline.converged = true;
            }
        }
        clockDiscipline.lastDiscipline = millis();
    } else {
        clockDiscipline.lastDiscipline = millis();
        if (clockDiscipline.disciplineCount > 0) {
            clockDiscipline.disciplineCount++;
        }
    }
}

int64_t getCorrectedMicroseconds() {
    uint32_t currentMicros = micros();
    
    if (clockDiscipline.converged && clockDiscipline.lastDiscipline > 0) {
        uint32_t elapsedMs = millis() - clockDiscipline.lastDiscipline;
        int64_t correction = (int64_t)(clockDiscipline.driftRate * elapsedMs * 1000.0);
        return (int64_t)currentMicros - correction;
    }
    
    return (int64_t)currentMicros;
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
            int n = WiFi.scanNetworks(false, false, false, 120);
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
        
        pathLoss.rssi0_wifi = meanRssi + 10.0 * pathLoss.n_wifi * log10(knownDistance);
        
        Serial.println("[CALIB] WiFi Calibration: SUCCESS");
        Serial.printf("  Distance: %.1f m\n", knownDistance);
        Serial.printf("  Samples: %d\n", wifiSamples.size());
        Serial.printf("  Mean RSSI: %.1f dBm\n", meanRssi);
        Serial.printf("  Std Dev: %.1f dB\n", stdDev);
        Serial.printf("  Path loss exponent (n): %.2f\n", pathLoss.n_wifi);
        Serial.printf("  Calculated RSSI0 @ 1m: %.1f dBm\n", pathLoss.rssi0_wifi);
    } else {
        Serial.printf("[CALIB] WiFi Calibration: FAILED\n");
        Serial.printf("  Insufficient samples: %d (need ≥10)\n", wifiSamples.size());
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
    xTaskCreatePinnedToCore(
        calibrationTask,
        "calibrate",
        8192,
        (void*)params,
        1,
        &calibrationTaskHandle,
        1
    );
    
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
    
    if (Serial1.availableForWrite() >= response.length()) {
        Serial1.println(response);
    }
}
