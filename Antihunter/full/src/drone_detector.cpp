#include <algorithm>
#include <cstdint>
#include <atomic>
#include "drone_detector.h"
#include "hardware.h"
#include "network.h"
#include "scanner.h"
#include "main.h"
#include "opendroneid.h"
#include "odid_wifi.h"
#include "detect.h"
#include <ArduinoJson.h>

const size_t MAX_DRONE_LOG_ENTRIES = 100;
const size_t MAX_DETECTED_DRONES = 50;
const uint32_t DRONE_STALE_TIME = 300000;

std::map<String, DroneDetection> detectedDrones;
// Audit fix C1: detectedDrones is mutated by droneDetectorTask and read/cleared by web handlers.
// A portMUX spinlock (old droneMux) was applied at only one site and is wrong for the long
// map-iterate/string-build sites; a std::mutex guards every access consistently.
std::mutex detectedDronesMutex;
std::set<String> transmittedDrones;
std::vector<String> droneEventLog;
std::atomic<uint32_t> droneDetectionCount(0);
std::atomic<bool> droneDetectionEnabled{false};
QueueHandle_t droneQueue = nullptr;
QueueHandle_t droneFrameQueue = nullptr;

extern std::atomic<bool> stopRequested;
extern void radioStartSTA();
extern void radioStopSTA();
extern std::atomic<bool> scanning; 

static unsigned long lastDroneLog = 0;
const unsigned long DRONE_LOG_INTERVAL = 1000;
static unsigned long lastDroneMeshSend = 0;
static const unsigned long DRONE_MESH_INTERVAL = 3000;

static std::map<String, uint32_t> droneMeshLastTx;
static const uint32_t DRONE_MESH_COOLDOWN_MS = 60000;
static bool droneMeshCooldownReady(const String &key) {
    if (key.length() == 0) return true;
    const uint32_t now = millis();
    auto it = droneMeshLastTx.find(key);
    if (it != droneMeshLastTx.end() && (now - it->second) < DRONE_MESH_COOLDOWN_MS) return false;
    droneMeshLastTx[key] = now;
    return true;
}

extern String macFmt6(const uint8_t *m);
extern void sendMeshNotification(const Hit &hit);

void initializeDroneDetector() {
    if (droneFrameQueue) {
        vQueueDeleteWithCaps(droneFrameQueue);
    }
    droneFrameQueue = xQueueCreateWithCaps(8, sizeof(DroneFrameEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (droneQueue) {
        vQueueDeleteWithCaps(droneQueue);
    }
    droneQueue = xQueueCreateWithCaps(64, sizeof(DroneDetection), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    {
        std::lock_guard<std::mutex> lock(detectedDronesMutex);
        detectedDrones.clear();
        droneEventLog.clear();
    }
    droneMeshLastTx.clear();
    droneDetectionCount = 0;
}

static void mergeDroneTelemetry(DroneDetection &dst, const DroneDetection &src) {
    dst.rssi = src.rssi;
    dst.lastSeen = src.lastSeen;
    memcpy(dst.mac, src.mac, 6);
    if (src.latitude != 0)                                     dst.latitude      = src.latitude;
    if (src.longitude != 0)                                    dst.longitude     = src.longitude;
    if (src.altitudeMsl != 0 && src.altitudeMsl > MIN_ALT)     dst.altitudeMsl   = src.altitudeMsl;
    if (src.heightAgl != 0 && src.heightAgl > MIN_ALT)         dst.heightAgl     = src.heightAgl;
    if (src.speed != 0 && src.speed < INV_SPEED_H)             dst.speed         = src.speed;
    if (src.speedVertical != 0 && src.speedVertical < INV_SPEED_V) dst.speedVertical = src.speedVertical;
    if (src.heading != 0 && src.heading < INV_DIR)             dst.heading       = src.heading;
    if (src.uaType != 0)                                       dst.uaType        = src.uaType;
    if (src.latitude != 0 || src.longitude != 0)               dst.status        = src.status;
    if (src.operatorLat != 0)                                  dst.operatorLat   = src.operatorLat;
    if (src.operatorLon != 0)                                  dst.operatorLon   = src.operatorLon;
    if (src.operatorId[0])                                     strncpy(dst.operatorId, src.operatorId, ODID_ID_SIZE);
    if (src.description[0])                                    strncpy(dst.description, src.description, ODID_STR_SIZE);
    if (src.authType != 0) {
        dst.authType = src.authType;
        dst.authTimestamp = src.authTimestamp;
        memcpy(dst.authData, src.authData, sizeof(dst.authData) - 1);
    }
}

static void parseDroneData(DroneDetection *drone, const ODID_UAS_Data *uasData) {
    if (uasData->BasicIDValid[0]) {
        strncpy(drone->uavId, reinterpret_cast<const char *>(uasData->BasicID[0].UASID), ODID_ID_SIZE);
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

        // Phase 2.1: Feed Remote ID claim into mesh-cooperative spoof validator.
        // Uses our own GPS + RSSI vs claimed coords for geometric consistency.
        if (drone->uavId[0] != 0) {
            detect_recordRidClaim(drone->uavId, drone->latitude, drone->longitude,
                                  drone->altitudeMsl, drone->rssi);
        }
    }

    if (uasData->SystemValid) {
        drone->operatorLat = uasData->System.OperatorLatitude;
        drone->operatorLon = uasData->System.OperatorLongitude;
    }

    if (uasData->OperatorIDValid) {
        strncpy(drone->operatorId, reinterpret_cast<const char *>(uasData->OperatorID.OperatorId), ODID_ID_SIZE);
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

static void parseFrenchDrone(DroneDetection *drone, const uint8_t *payload, int buf_len) {
    union {
        uint32_t u32;
        int32_t i32;
    } uav_lat, uav_long, base_lat, base_long;
    
    union {
        uint16_t u16;
        int16_t i16;
    } alt, height;

    int j = 9;
    const int frame_length = payload[1];

    while (j < frame_length && j + 1 < buf_len) {
        const uint8_t t = payload[j];
        const uint8_t l = payload[j + 1];
        if (j + 2 + l > buf_len) break;
        const uint8_t *v = &payload[j + 2];

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
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                uav_lat.u32 <<= 8;
                uav_lat.u32 |= v[i];
            }
            drone->latitude = 1.0e-5 * (double)uav_lat.i32;
            break;
        case 5:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                uav_long.u32 <<= 8;
                uav_long.u32 |= v[i];
            }
            drone->longitude = 1.0e-5 * (double)uav_long.i32;
            break;
        case 6:
            if (l < 2) break;
            alt.u16 = (((uint16_t)v[0]) << 8) | (uint16_t)v[1];
            drone->altitudeMsl = alt.i16;
            break;
        case 7:
            if (l < 2) break;
            height.u16 = (((uint16_t)v[0]) << 8) | (uint16_t)v[1];
            drone->heightAgl = height.i16;
            break;
        case 8:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                base_lat.u32 <<= 8;
                base_lat.u32 |= v[i];
            }
            drone->operatorLat = 1.0e-5 * (double)base_lat.i32;
            break;
        case 9:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                base_long.u32 <<= 8;
                base_long.u32 |= v[i];
            }
            drone->operatorLon = 1.0e-5 * (double)base_long.i32;
            break;
        case 10:
            if (l < 1) break;
            drone->speed = v[0];
            break;
        case 11:
            if (l < 2) break;
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
    
    DroneDetection drone{};
    memcpy(drone.mac, payload + 10, 6);
    drone.rssi = rssi;
    drone.timestamp = millis();
    drone.lastSeen = millis();
    
    if (rssi < rfConfig.globalRssiThreshold) {
        return;
    }
    
    ODID_UAS_Data uasData;
    odid_initUasData(&uasData);
    
    bool validDrone = false;
    
    static const uint8_t nan_dest[6] = {0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00};
    if (memcmp(nan_dest, payload + 4, 6) == 0) {
        char op_id[ODID_ID_SIZE + 1];
        if (odid_wifi_receive_message_pack_nan_action_frame(&uasData, op_id, const_cast<uint8_t*>(payload), static_cast<size_t>(length)) == 0) {
            parseDroneData(&drone, &uasData);
            validDrone = true;
        }
    }
    else if (payload[0] == 0x80 && length > 38) {
        int offset = 36;

        while (offset < length) {
            if (offset + 2 >= length) break;

            const int typ = payload[offset];
            const int len = payload[offset + 1];

            if (offset + 2 + len > length) break;

            const uint8_t *val = &payload[offset + 2];

            if ((typ == 0xdd) && len >= 3 && (val[0] == 0x6a) && (val[1] == 0x5c) && (val[2] == 0x35)) {
                parseFrenchDrone(&drone, &payload[offset], length - offset);
                validDrone = true;
                break;
            }
            else if ((typ == 0xdd) && len >= 3 &&
                     (((val[0] == 0x90 && val[1] == 0x3a && val[2] == 0xe6)) ||
                      ((val[0] == 0xfa && val[1] == 0x0b && val[2] == 0xbc)))) {
                const int j = offset + 7;
                if (j < length) {
                    uasData = ODID_UAS_Data{};
                    odid_message_process_pack(&uasData, const_cast<uint8_t*>(&payload[j]), length - j);
                    parseDroneData(&drone, &uasData);
                    validDrone = true;
                }
                break;
            }

            offset += len + 2;
        }
    }
    
    if (validDrone) {
        const String macStr = macFmt6(drone.mac);
        const String uavIdStr = String(drone.uavId);
        
        // Deduplicate by UAV ID, not MAC
        {
        std::lock_guard<std::mutex> lock(detectedDronesMutex);
        auto existingIt = std::find_if(detectedDrones.begin(), detectedDrones.end(),
            [&uavIdStr](const std::pair<const String, DroneDetection>& entry) {
                return String(entry.second.uavId) == uavIdStr && uavIdStr.length() > 0;
            });

        if (existingIt != detectedDrones.end()) {
            mergeDroneTelemetry(existingIt->second, drone);
        }

        if (existingIt == detectedDrones.end()) {
            detectedDrones[macStr] = drone;
            droneDetectionCount = droneDetectionCount + 1;
        }
        }
        
        if (millis() - lastDroneLog >= DRONE_LOG_INTERVAL) {
            lastDroneLog = millis();
            
            DynamicJsonDocument doc(512);
            doc["timestamp"] = getEventTimestamp();
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
            
            {
                std::lock_guard<std::mutex> lock(detectedDronesMutex);
                if (droneEventLog.size() >= MAX_DRONE_LOG_ENTRIES) {
                    droneEventLog.erase(droneEventLog.begin());
                }
                droneEventLog.push_back(jsonStr);
            }

            logToSD("DRONE: " + jsonStr);
            logEventToSD("/drones.jsonl", jsonStr);

            const String meshKey = uavIdStr.length() ? uavIdStr : macStr;
            if (droneMeshCooldownReady(meshKey)) {
                String meshMsg = getNodeId() + ": DRONE: " + macStr + " ID:" + uavIdStr;
                meshMsg += " R" + String(drone.rssi);
                if (drone.latitude != 0) {
                    meshMsg += " GPS:" + String(drone.latitude, 6) + "," + String(drone.longitude, 6);
                }
                if (drone.altitudeMsl != 0) {
                    meshMsg += " ALT:" + String(drone.altitudeMsl, 1);
                }
                if (drone.speed != 0) {
                    meshMsg += " SPD:" + String(drone.speed, 1);
                }
                if (drone.operatorLat != 0 || drone.operatorLon != 0) {
                    meshMsg += " OP:" + String(drone.operatorLat, 6) + "," + String(drone.operatorLon, 6);
                }
                if (meshEnqueue(meshMsg)) {
                    transmittedDrones.insert(drone.uavId);
                }
            }

            Serial.println("[DRONE] " + jsonStr);
        }
        
        if (droneQueue) {
            xQueueSend(droneQueue, &drone, 0);
        }
    }
}

// Phase 3.2: BLE-side ODID Remote ID. Decodes ASTM F3411 message bytes directly
// (already extracted from BLE adv 0x16 FA FF AD header by scanner). Same
// DroneDetection upsert/dedup logic as the WiFi path.
void processDroneOdidBle(const uint8_t *addr, int8_t rssi,
                         const uint8_t *odid, int odidLen) {
    if (!droneDetectionEnabled || !addr || !odid || odidLen < 1) return;
    if (rssi < rfConfig.globalRssiThreshold) return;

    DroneDetection drone{};
    memcpy(drone.mac, addr, 6);
    drone.rssi = rssi;
    drone.timestamp = millis();
    drone.lastSeen = millis();

    ODID_UAS_Data uasData;
    odid_initUasData(&uasData);

    // ODID over BLE uses the same packed-message encoding as WiFi NAN payload.
    // The first byte of the ODID adv is a sequence counter for ASTM F3411;
    // skip it before passing to the standard pack parser.
    int skip = 1;
    if (odidLen - skip < 1) return;
    if (odid_message_process_pack(&uasData,
                                  const_cast<uint8_t*>(odid + skip),
                                  (size_t)(odidLen - skip)) != 0) {
        return;
    }
    bool useful = uasData.BasicIDValid[0] || uasData.LocationValid ||
                  uasData.SystemValid || uasData.OperatorIDValid;
    if (!useful) return;

    parseDroneData(&drone, &uasData);

    const String macStr = macFmt6(drone.mac);
    const String uavIdStr = String(drone.uavId);

    std::lock_guard<std::mutex> lock(detectedDronesMutex);
    auto existingIt = std::find_if(detectedDrones.begin(), detectedDrones.end(),
        [&uavIdStr](const std::pair<const String, DroneDetection>& entry) {
            return String(entry.second.uavId) == uavIdStr && uavIdStr.length() > 0;
        });
    if (existingIt != detectedDrones.end()) {
        mergeDroneTelemetry(existingIt->second, drone);
    } else {
        detectedDrones[macStr] = drone;
        droneDetectionCount = droneDetectionCount + 1;
    }
}

static const char *uaTypeStr(uint8_t t) {
    switch (t) {
        case 0: return "None";
        case 1: return "Aeroplane";
        case 2: return "Multirotor";
        case 3: return "Gyroplane";
        case 4: return "Hybrid Lift";
        case 5: return "Ornithopter";
        case 6: return "Glider";
        case 7: return "Kite";
        case 8: return "Free Balloon";
        case 9: return "Captive Balloon";
        case 10: return "Airship";
        case 11: return "Parachute";
        case 12: return "Rocket";
        case 13: return "Tethered";
        case 14: return "Ground Obstacle";
        default: return "Other";
    }
}

static String droneFmtAlt(float v)     { return (v <= MIN_ALT) ? String("n/a") : (String(v, 1) + " m"); }
static String droneFmtSpeed(float v)   { return (v >= INV_SPEED_H) ? String("n/a") : (String(v, 1) + " m/s"); }
static String droneFmtVSpeed(float v)  { return (v >= INV_SPEED_V) ? String("n/a") : (String(v, 1) + " m/s"); }
static String droneFmtHeading(float v) { return (v >= INV_DIR) ? String("n/a") : (String(v, 0) + " deg"); }

String getDroneDetectionResults() {
    static String cachedResults = "";
    static unsigned long lastCacheTime = 0;

    // Cache for 3 seconds to reduce performance impact
    if (millis() - lastCacheTime < 3000 && cachedResults.length() > 0) {
        return cachedResults;
    }
    lastCacheTime = millis();

    String results = "Drone Detection Results\n";
    results += "Total detections: " + String(droneDetectionCount) + "\n";
    std::lock_guard<std::mutex> lock(detectedDronesMutex);
    results += "Unique drones: " + String(detectedDrones.size()) + "\n\n";

    for (const auto& entry : detectedDrones) {
        const DroneDetection& d = entry.second;
        results += "MAC: " + entry.first + "\n";
        results += "  UAV ID: " + String(d.uavId) + "\n";
        results += "  UA Type: " + String(uaTypeStr(d.uaType)) + " (" + String(d.uaType) + ")\n";
        results += "  RSSI: " + String(d.rssi) + " dBm\n";

        const bool hasTelem = (d.latitude != 0 || d.longitude != 0 ||
                               d.altitudeMsl != 0 || d.heightAgl != 0 ||
                               d.speed != 0 || d.heading != 0);
        if (hasTelem) {
            results += "  Location: " + ((d.latitude != 0 || d.longitude != 0)
                        ? (String(d.latitude, 6) + ", " + String(d.longitude, 6))
                        : String("n/a")) + "\n";
            results += "  Altitude MSL: " + droneFmtAlt(d.altitudeMsl) + "\n";
            results += "  Height AGL: " + droneFmtAlt(d.heightAgl) + "\n";
            results += "  Speed: " + droneFmtSpeed(d.speed) + "  Vert: " +
                      droneFmtVSpeed(d.speedVertical) + "\n";
            results += "  Heading: " + droneFmtHeading(d.heading) + "\n";
            results += "  Status: " + String(d.status) + "\n";
        }

        if (d.operatorLat != 0 || d.operatorLon != 0) {
            results += "  Operator: " + String(d.operatorLat, 6) + ", " +
                      String(d.operatorLon, 6) + "\n";
        }
        if (strlen(d.operatorId) > 0) {
            results += "  Operator ID: " + String(d.operatorId) + "\n";
        }
        if (strlen(d.description) > 0) {
            results += "  Description: " + String(d.description) + "\n";
        }
        if (d.authType != 0) {
            results += "  Auth: type " + String(d.authType) + " ts " + String(d.authTimestamp) + "\n";
        }

        const uint32_t age = (millis() - d.lastSeen) / 1000;
        results += "  Last seen: " + String(age) + "s ago\n\n";
    }

    cachedResults = results;
    return results;
}

String getDroneEventLog() {
    String log = "[\n";
    {
        std::lock_guard<std::mutex> lock(detectedDronesMutex);
        for (size_t i = 0; i < droneEventLog.size(); i++) {
            log += droneEventLog[i];
            if (i < droneEventLog.size() - 1) log += ",";
            log += "\n";
        }
    }
    log += "]";
    return log;
}

void cleanupDroneData() {
    const uint32_t now = millis();
    std::lock_guard<std::mutex> lock(detectedDronesMutex);

    for (auto it = detectedDrones.begin(); it != detectedDrones.end();) {
        if (now - it->second.lastSeen > DRONE_STALE_TIME) {
            it = detectedDrones.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = droneMeshLastTx.begin(); it != droneMeshLastTx.end();) {
        if (now - it->second > DRONE_STALE_TIME) {
            it = droneMeshLastTx.erase(it);
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
    sentinel_kill();
    const int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    const bool forever = (duration <= 0);
    scanSetCountdown(duration, forever);

    Serial.printf("[DRONE] Starting drone detection %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    initializeDroneDetector();
    droneDetectionEnabled = true;
    scanning = true;
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Drone Detection Results\nStarting...\n";
    }
    stopRequested = false;
    
    uint32_t localFramesSeen = 0;
    transmittedDrones.clear();
    
    radioStartSTA();
    
    const uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t nextResultsUpdate = millis() + 2000;
    uint32_t lastCleanup = millis();
    uint32_t lastMeshUpdate = millis();
    const unsigned long MESH_DRONE_UPDATE_INTERVAL = 5000;
    
    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {

        DroneFrameEvent rawFrame;
        while (xQueueReceive(droneFrameQueue, &rawFrame, 0) == pdTRUE) {
            processDronePacket(rawFrame.payload, rawFrame.len, rawFrame.rssi);
        }

        DroneDetection drone;
        while (xQueueReceive(droneQueue, &drone, 0) == pdTRUE) {
            localFramesSeen++;

            const String macStr = macFmt6(drone.mac);
            String logEntry = "DRONE: " + macStr + " ID:" + String(drone.uavId) +
                            " Lat=" + String(drone.latitude, 6) +
                            " Lon=" + String(drone.longitude, 6) +
                            " Alt=" + String(drone.altitudeMsl, 1) + "m" +
                            " Speed=" + String(drone.speed, 1) + "m/s" +
                            " RSSI=" + String(drone.rssi) + "dBm";

            if (drone.operatorLat != 0 || drone.operatorLon != 0) {
                logEntry += " OpLat=" + String(drone.operatorLat, 6) +
                        " OpLon=" + String(drone.operatorLon, 6);
            }

            Serial.println("[DRONE] " + logEntry);
            logToSD(logEntry);

            const String queueDroneId = String(drone.uavId);
            if (meshEnabled && droneMeshCooldownReady(queueDroneId)) {
                String meshMsg = getNodeId() + ": DRONE: " + macStr + " ID:" + queueDroneId;
                meshMsg += " R" + String(drone.rssi);
                if (drone.latitude != 0) {
                    meshMsg += " GPS:" + String(drone.latitude, 6) + "," + String(drone.longitude, 6);
                }
                if (drone.altitudeMsl != 0) {
                    meshMsg += " ALT:" + String(drone.altitudeMsl, 1);
                }
                if (drone.speed != 0) {
                    meshMsg += " SPD:" + String(drone.speed, 1);
                }
                if (drone.operatorLat != 0 || drone.operatorLon != 0) {
                    meshMsg += " OP:" + String(drone.operatorLat, 6) + "," + String(drone.operatorLon, 6);
                }
                if (meshEnqueue(meshMsg)) {
                    transmittedDrones.insert(queueDroneId);
                }
            }
        }

        if (meshEnabled && (millis() - lastMeshUpdate >= MESH_DRONE_UPDATE_INTERVAL)) {
            lastMeshUpdate = millis();

            std::lock_guard<std::mutex> lock(detectedDronesMutex);
            for (const auto& entry : detectedDrones) {
                const String meshDroneId = String(entry.second.uavId);

                if (droneMeshCooldownReady(meshDroneId)) {
                    String droneMsg = getNodeId() + ": DRONE: " + entry.first + " ID:" + meshDroneId;
                    droneMsg += " R" + String(entry.second.rssi);
                    if (entry.second.latitude != 0) {
                        droneMsg += " GPS:" + String(entry.second.latitude, 6) +
                                "," + String(entry.second.longitude, 6);
                    }
                    if (entry.second.altitudeMsl != 0) {
                        droneMsg += " ALT:" + String(entry.second.altitudeMsl, 1);
                    }
                    if (entry.second.speed != 0) {
                        droneMsg += " SPD:" + String(entry.second.speed, 1);
                    }
                    if (entry.second.operatorLat != 0 || entry.second.operatorLon != 0) {
                        droneMsg += " OP:" + String(entry.second.operatorLat, 6) +
                                "," + String(entry.second.operatorLon, 6);
                    }

                    if (droneMsg.length() <= MAX_MESH_SIZE && meshEnqueue(droneMsg)) {
                        transmittedDrones.insert(meshDroneId);
                    }
                }
            }
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            size_t uniqueN;
            { std::lock_guard<std::mutex> lock(detectedDronesMutex); uniqueN = detectedDrones.size(); }
            Serial.printf("[DRONE] Detected:%u Unique:%u Frames:%u\n",
                         droneDetectionCount.load(), (unsigned)uniqueN, localFramesSeen);
            nextStatus += 5000;
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            nextResultsUpdate += 2000;
            String liveResults = getDroneDetectionResults();
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            antihunter::lastResults = liveResults.c_str();
        }

        if (millis() - lastCleanup > 60000) {
            cleanupDroneData();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    droneDetectionEnabled = false;
    scanning = false;

    if (droneFrameQueue) {
        vQueueDeleteWithCaps(droneFrameQueue);
        droneFrameQueue = nullptr;
    }

    if (meshEnabled && !stopRequested) {
        uint32_t enqueuedDrones = 0;
        std::lock_guard<std::mutex> lock(detectedDronesMutex);
        for (const auto& entry : detectedDrones) {
            const String finalDroneId = String(entry.second.uavId);

            if (transmittedDrones.find(finalDroneId) == transmittedDrones.end()) {
                String droneMsg = getNodeId() + ": DRONE: " + entry.first + " ID:" + finalDroneId;
                droneMsg += " R" + String(entry.second.rssi);
                if (entry.second.latitude != 0) {
                    droneMsg += " GPS:" + String(entry.second.latitude, 6) +
                            "," + String(entry.second.longitude, 6);
                }
                if (entry.second.altitudeMsl != 0) {
                    droneMsg += " ALT:" + String(entry.second.altitudeMsl, 1);
                }
                if (entry.second.speed != 0) {
                    droneMsg += " SPD:" + String(entry.second.speed, 1);
                }
                if (entry.second.operatorLat != 0 || entry.second.operatorLon != 0) {
                    droneMsg += " OP:" + String(entry.second.operatorLat, 6) +
                            "," + String(entry.second.operatorLon, 6);
                }

                if (droneMsg.length() <= MAX_MESH_SIZE && meshEnqueue(droneMsg)) {
                    transmittedDrones.insert(finalDroneId);
                    enqueuedDrones++;
                }
            }
        }

        const uint32_t totalDrones = detectedDrones.size();
        String summary = getNodeId() + ": DRONE_DONE: Detected=" + String(droneDetectionCount) +
                        " Unique=" + String(totalDrones) +
                        " TX=" + String(transmittedDrones.size());
        meshEnqueue(summary);
        Serial.printf("[DRONE] Detection complete: enqueued %u (total unique %u)\n",
                     enqueuedDrones, totalDrones);
    }

    radioStopSTA();
    delay(100);
       
    {
        String droneRes = getDroneDetectionResults();
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = droneRes.c_str();
    }

    size_t finalUniqueN;
    { std::lock_guard<std::mutex> lock(detectedDronesMutex); finalUniqueN = detectedDrones.size(); }
    Serial.printf("[DRONE] Complete: %u drones detected, %u unique\n",
                  droneDetectionCount.load(), (unsigned)finalUniqueN);

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}