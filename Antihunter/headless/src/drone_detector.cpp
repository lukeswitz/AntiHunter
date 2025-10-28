#include <cstdint>
#include "drone_detector.h"
#include "hardware.h"
#include "network.h"
#include "scanner.h"
#include "opendroneid.h"
#include "odid_wifi.h"
#include <ArduinoJson.h>
#include <cstdint>

const size_t MAX_DRONE_LOG_ENTRIES = 100;
const size_t MAX_DETECTED_DRONES = 50;
const uint32_t DRONE_STALE_TIME = 300000;

std::map<String, DroneDetection> detectedDrones;
std::set<String> transmittedDrones;
std::vector<String> droneEventLog;
volatile uint32_t droneDetectionCount = 0;
bool droneDetectionEnabled = false;
QueueHandle_t droneQueue = nullptr;

extern volatile bool stopRequested;
extern void radioStartSTA();
extern void radioStopSTA();
extern volatile bool scanning; 

static unsigned long lastDroneLog = 0;
const unsigned long DRONE_LOG_INTERVAL = 1000;
static unsigned long lastDroneMeshSend = 0;
static const unsigned long DRONE_MESH_INTERVAL = 3000;

extern String macFmt6(const uint8_t *m);
extern void sendMeshNotification(const Hit &hit);

void initializeDroneDetector() {
    if (droneQueue) {
        vQueueDelete(droneQueue);
    }
    droneQueue = xQueueCreate(64, sizeof(DroneDetection));
    detectedDrones.clear();
    droneEventLog.clear();
    droneDetectionCount = 0;
}

static void parseDroneData(DroneDetection *drone, ODID_UAS_Data *uasData) {
    if (uasData->BasicIDValid[0]) {
        strncpy(drone->uavId, (char *)uasData->BasicID[0].UASID, ODID_ID_SIZE);
        drone->uaType = uasData->BasicID[0].UAType;
    }
    
    if (uasData->LocationValid) {
        drone->latitude = uasData->Location.Latitude;
        drone->longitude = uasData->Location.Longitude;
        drone->altitudeMsl = uasData->Location.AltitudeGeo;
        drone->heightAgl = uasData->Location.Height;
        drone->speed = uasData->Location.SpeedHorizontal;
        drone->heading = uasData->Location.Direction;
        drone->speedVertical = uasData->Location.SpeedVertical;
        drone->status = uasData->Location.Status;
    }
    
    if (uasData->SystemValid) {
        drone->operatorLat = uasData->System.OperatorLatitude;
        drone->operatorLon = uasData->System.OperatorLongitude;
    }
    
    if (uasData->OperatorIDValid) {
        strncpy(drone->operatorId, (char *)uasData->OperatorID.OperatorId, ODID_ID_SIZE);
    }
    
    if (uasData->SelfIDValid) {
        strncpy(drone->description, uasData->SelfID.Desc, ODID_STR_SIZE);
    }
    
    if (uasData->AuthValid[0]) {
        drone->authType = uasData->Auth[0].AuthType;
        drone->authTimestamp = uasData->Auth[0].Timestamp;
        memcpy(drone->authData, uasData->Auth[0].AuthData, sizeof(drone->authData) - 1);
    }
}

static void parseFrenchDrone(DroneDetection *drone, uint8_t *payload) {
    union {
        uint32_t u32;
        int32_t i32;
    } uav_lat, uav_long, base_lat, base_long;
    
    union {
        uint16_t u16;
        int16_t i16;
    } alt, height;

    int j = 9;
    int frame_length = payload[1];

    while (j < frame_length) {
        uint8_t t = payload[j];
        uint8_t l = payload[j + 1];
        uint8_t *v = &payload[j + 2];

        switch (t) {
        case 2:
            for (int i = 0; (i < (l - 6)) && (i < ODID_ID_SIZE); ++i) {
                drone->operatorId[i] = (char)v[i + 6];
            }
            break;
        case 3:
            for (int i = 0; (i < l) && (i < ODID_ID_SIZE); ++i) {
                drone->uavId[i] = (char)v[i];
            }
            break;
        case 4:
            for (int i = 0; i < 4; ++i) {
                uav_lat.u32 <<= 8;
                uav_lat.u32 |= v[i];
            }
            drone->latitude = 1.0e-5 * (double)uav_lat.i32;
            break;
        case 5:
            for (int i = 0; i < 4; ++i) {
                uav_long.u32 <<= 8;
                uav_long.u32 |= v[i];
            }
            drone->longitude = 1.0e-5 * (double)uav_long.i32;
            break;
        case 6:
            alt.u16 = (((uint16_t)v[0]) << 8) | (uint16_t)v[1];
            drone->altitudeMsl = alt.i16;
            break;
        case 7:
            height.u16 = (((uint16_t)v[0]) << 8) | (uint16_t)v[1];
            drone->heightAgl = height.i16;
            break;
        case 8:
            for (int i = 0; i < 4; ++i) {
                base_lat.u32 <<= 8;
                base_lat.u32 |= v[i];
            }
            drone->operatorLat = 1.0e-5 * (double)base_lat.i32;
            break;
        case 9:
            for (int i = 0; i < 4; ++i) {
                base_long.u32 <<= 8;
                base_long.u32 |= v[i];
            }
            drone->operatorLon = 1.0e-5 * (double)base_long.i32;
            break;
        case 10:
            drone->speed = v[0];
            break;
        case 11:
            drone->heading = (((uint16_t)v[0]) << 8) | (uint16_t)v[1];
            break;
        default:
            break;
        }
        j += l + 2;
    }
}

void processDronePacket(const uint8_t *payload, int length, int8_t rssi) {
    if (!droneDetectionEnabled || length < 24) return;
    
    DroneDetection drone;
    memset(&drone, 0, sizeof(drone));
    
    memcpy(drone.mac, payload + 10, 6);
    drone.rssi = rssi;
    drone.timestamp = millis();
    drone.lastSeen = millis();
    
    ODID_UAS_Data uasData;
    odid_initUasData(&uasData);
    
    bool validDrone = false;
    
    static const uint8_t nan_dest[6] = {0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00};
    if (memcmp(nan_dest, payload + 4, 6) == 0) {
        char op_id[ODID_ID_SIZE + 1];
        if (odid_wifi_receive_message_pack_nan_action_frame(&uasData, op_id, (uint8_t*)payload, (size_t)length) == 0) {
            parseDroneData(&drone, &uasData);
            validDrone = true;
        }
    }
    else if (payload[0] == 0x80 && length > 38) {
        int offset = 36;
        bool printed = false;
        
        while (offset < length && !printed) {
            if (offset + 2 >= length) break;
            
            int typ = payload[offset];
            int len = payload[offset + 1];
            
            if (offset + 2 + len > length) break;
            
            uint8_t *val = (uint8_t*)&payload[offset + 2];
            
            if ((typ == 0xdd) && (val[0] == 0x6a) && (val[1] == 0x5c) && (val[2] == 0x35)) {
                parseFrenchDrone(&drone, (uint8_t*)&payload[offset]);
                validDrone = true;
                printed = true;
            }
            else if ((typ == 0xdd) &&
                     (((val[0] == 0x90 && val[1] == 0x3a && val[2] == 0xe6)) ||
                      ((val[0] == 0xfa && val[1] == 0x0b && val[2] == 0xbc)))) {
                int j = offset + 7;
                if (j < length) {
                    memset(&uasData, 0, sizeof(uasData));
                    odid_message_process_pack(&uasData, (uint8_t*)&payload[j], length - j);
                    parseDroneData(&drone, &uasData);
                    validDrone = true;
                    printed = true;
                }
            }
            
            offset += len + 2;
        }
    }
    
    if (validDrone) {
        String macStr = macFmt6(drone.mac);
        String uavIdStr = String(drone.uavId);
        
        // Deduplicate by UAV ID, not MAC
        bool foundExisting = false;
        for (auto& entry : detectedDrones) {
            if (String(entry.second.uavId) == uavIdStr && uavIdStr.length() > 0) {
                entry.second.rssi = drone.rssi;
                entry.second.lastSeen = millis();
                memcpy(entry.second.mac, drone.mac, 6);
                
                if (drone.latitude != 0) entry.second.latitude = drone.latitude;
                if (drone.longitude != 0) entry.second.longitude = drone.longitude;
                if (drone.altitudeMsl != 0) entry.second.altitudeMsl = drone.altitudeMsl;
                if (drone.operatorLat != 0) entry.second.operatorLat = drone.operatorLat;
                if (drone.operatorLon != 0) entry.second.operatorLon = drone.operatorLon;
                
                foundExisting = true;
                break;
            }
        }
        
        if (!foundExisting) {
            detectedDrones[macStr] = drone;
            droneDetectionCount = droneDetectionCount + 1;
        }
        
        if (millis() - lastDroneLog >= DRONE_LOG_INTERVAL) {
            lastDroneLog = millis();
            
            DynamicJsonDocument doc(512);
            doc["timestamp"] = drone.timestamp;
            doc["mac"] = macStr;
            doc["rssi"] = drone.rssi;
            doc["uav_id"] = uavIdStr;
            doc["type"] = drone.uaType;
            
            if (drone.latitude != 0 || drone.longitude != 0) {
                doc["lat"] = drone.latitude;
                doc["lon"] = drone.longitude;
                doc["alt"] = drone.altitudeMsl;
                doc["speed"] = drone.speed;
            }
            
            if (drone.operatorLat != 0 || drone.operatorLon != 0) {
                doc["op_lat"] = drone.operatorLat;
                doc["op_lon"] = drone.operatorLon;
            }
            
            String jsonStr;
            serializeJson(doc, jsonStr);
            
            if (droneEventLog.size() >= MAX_DRONE_LOG_ENTRIES) {
                droneEventLog.erase(droneEventLog.begin());
            }
            droneEventLog.push_back(jsonStr);
            
            logToSD("DRONE: " + jsonStr);
            
            String meshMsg = getNodeId() + ": DRONE: " + macStr + " ID:" + uavIdStr;
            if (drone.latitude != 0) {
                meshMsg += " GPS:" + String(drone.latitude, 6) + "," + String(drone.longitude, 6);
            }
            sendToSerial1(String(meshMsg), false);

            if (sendToSerial1(meshMsg, false)) {
                transmittedDrones.insert(drone.uavId);
            }
            
            Serial.println("[DRONE] " + jsonStr);
        }
        
        if (droneQueue) {
            xQueueSend(droneQueue, &drone, 0);
        }
    }
}

String getDroneDetectionResults() {
    String results = "Drone Detection Results\n";
    results += "Total detections: " + String(droneDetectionCount) + "\n";
    results += "Unique drones: " + String(detectedDrones.size()) + "\n\n";
    
    for (const auto& entry : detectedDrones) {
        const DroneDetection& d = entry.second;
        results += "MAC: " + entry.first + "\n";
        results += "  UAV ID: " + String(d.uavId) + "\n";
        results += "  RSSI: " + String(d.rssi) + " dBm\n";
        
        if (d.latitude != 0 || d.longitude != 0) {
            results += "  Location: " + String(d.latitude, 6) + ", " + 
                      String(d.longitude, 6) + "\n";
            results += "  Altitude: " + String(d.altitudeMsl) + "m\n";
            results += "  Speed: " + String(d.speed) + " m/s\n";
        }
        
        if (d.operatorLat != 0 || d.operatorLon != 0) {
            results += "  Operator: " + String(d.operatorLat, 6) + ", " + 
                      String(d.operatorLon, 6) + "\n";
        }
        
        if (strlen(d.description) > 0) {
            results += "  Description: " + String(d.description) + "\n";
        }
        
        uint32_t age = (millis() - d.lastSeen) / 1000;
        results += "  Last seen: " + String(age) + "s ago\n\n";
    }
    
    return results;
}

String getDroneEventLog() {
    String log = "[\n";
    for (size_t i = 0; i < droneEventLog.size(); i++) {
        log += droneEventLog[i];
        if (i < droneEventLog.size() - 1) log += ",";
        log += "\n";
    }
    log += "]";
    return log;
}

void cleanupDroneData() {
    uint32_t now = millis();
    
    for (auto it = detectedDrones.begin(); it != detectedDrones.end();) {
        if (now - it->second.lastSeen > DRONE_STALE_TIME) {
            it = detectedDrones.erase(it);
        } else {
            ++it;
        }
    }
    
    while (detectedDrones.size() > MAX_DETECTED_DRONES) {
        uint32_t oldestTime = UINT32_MAX;
        String oldestKey;
        for (const auto& entry : detectedDrones) {
            if (entry.second.lastSeen < oldestTime) {
                oldestTime = entry.second.lastSeen;
                oldestKey = entry.first;
            }
        }
        if (oldestKey.length() > 0) {
            detectedDrones.erase(oldestKey);
        }
    }
    
    while (droneEventLog.size() > MAX_DRONE_LOG_ENTRIES) {
        droneEventLog.erase(droneEventLog.begin());
    }
    
    if (ESP.getFreeHeap() < 20000) {
        Serial.println("[DRONE] Low memory - clearing old data");
        while (detectedDrones.size() > 10) {
            detectedDrones.erase(detectedDrones.begin());
        }
        while (droneEventLog.size() > 20) {
            droneEventLog.erase(droneEventLog.begin());
        }
    }
}

void droneDetectorTask(void *pv)
{
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[DRONE] Starting drone detection %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    initializeDroneDetector();
    droneDetectionEnabled = true;
    scanning = true;
    stopRequested = false;
    
    uint32_t localFramesSeen = 0;
    transmittedDrones.clear();
    
    radioStartSTA();
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    uint32_t lastMeshUpdate = millis();
    const unsigned long MESH_DRONE_UPDATE_INTERVAL = 5000;
    DroneDetection drone;
    
    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        while (xQueueReceive(droneQueue, &drone, 0) == pdTRUE) {
            localFramesSeen++;
            
            String logEntry = "DRONE: ID=" + String(drone.uavId) +
                            " Lat=" + String(drone.latitude, 6) +
                            " Lon=" + String(drone.longitude, 6) +
                            " Alt=" + String(drone.altitudeMsl, 1) + "m" +
                            " Speed=" + String(drone.speed, 1) + "m/s" +
                            " RSSI=" + String(drone.rssi) + "dBm";
            
            Serial.println("[DRONE] " + logEntry);
            logToSD(logEntry);
            
            String droneId = String(drone.uavId);
            if (meshEnabled && transmittedDrones.find(droneId) == transmittedDrones.end()) {
                String meshMsg = getNodeId() + ": DRONE: ID=" + droneId +
                                " RSSI=" + String(drone.rssi);
                if (drone.latitude != 0) {
                    meshMsg += " GPS:" + String(drone.latitude, 6) + "," + String(drone.longitude, 6);
                }
                if (sendToSerial1(meshMsg, false)) {
                    transmittedDrones.insert(droneId);
                }
            }
        }
        
        if (meshEnabled && (millis() - lastMeshUpdate >= MESH_DRONE_UPDATE_INTERVAL)) {
            lastMeshUpdate = millis();
            
            int sentThisCycle = 0;
            for (const auto& entry : detectedDrones) {
                String droneId = String(entry.second.uavId);
                
                if (transmittedDrones.find(droneId) == transmittedDrones.end()) {
                    String droneMsg = getNodeId() + ": DRONE: ID=" + droneId;
                    droneMsg += " R" + String(entry.second.rssi);
                    
                    if (entry.second.latitude != 0) {
                        droneMsg += " GPS:" + String(entry.second.latitude, 6) + 
                                   "," + String(entry.second.longitude, 6);
                    }
                    
                    if (droneMsg.length() < 230 && sendToSerial1(droneMsg, true)) {
                        transmittedDrones.insert(droneId);
                        sentThisCycle++;
                        
                        if (sentThisCycle % 2 == 0) {
                            delay(1000);
                            rateLimiter.refillTokens();
                        }
                    }
                }
            }
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[DRONE] Detected:%u Unique:%u Frames:%u\n", 
                         droneDetectionCount, (unsigned)detectedDrones.size(), localFramesSeen);
            nextStatus += 5000;
        }
        
        if (millis() - lastCleanup > 60000) {
            cleanupDroneData();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    droneDetectionEnabled = false;
    scanning = false;

    if (meshEnabled && !stopRequested) {
        Serial.printf("[DRONE] Scan complete - transmitting final batch\n");
        rateLimiter.flush();
        delay(100);
        
        for (const auto& entry : detectedDrones) {
            String droneId = String(entry.second.uavId);
            
            if (transmittedDrones.find(droneId) == transmittedDrones.end()) {
                String droneMsg = getNodeId() + ": DRONE: ID=" + droneId;
                droneMsg += " R" + String(entry.second.rssi);
                
                if (entry.second.latitude != 0) {
                    droneMsg += " GPS:" + String(entry.second.latitude, 6) + 
                               "," + String(entry.second.longitude, 6);
                }
                
                if (droneMsg.length() < 230) {
                    if (sendToSerial1(droneMsg, true)) {
                        transmittedDrones.insert(droneId);
                    }
                }
            }
        }
        
        Serial1.flush();
        delay(100);
        
        uint32_t totalDrones = detectedDrones.size();
        uint32_t finalTransmitted = transmittedDrones.size();
        uint32_t finalRemaining = totalDrones - finalTransmitted;
        
        String summary = getNodeId() + ": DRONE_DONE: Detected=" + String(droneDetectionCount) +
                        " Unique=" + String(totalDrones) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        
        sendToSerial1(summary, true);
        Serial.printf("[DRONE] Detection complete: %d/%d drones transmitted, %d pending\n",
                     finalTransmitted, totalDrones, finalRemaining);
        
        if (finalRemaining > 0) {
            Serial.printf("[DRONE] WARNING: %d drones not transmitted\n", finalRemaining);
        }
    }

    radioStopSTA();
    delay(100);

    Serial.printf("[DRONE] Complete: %u drones detected, %u unique\n",
                  droneDetectionCount, (unsigned)detectedDrones.size());

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}