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
const uint32_t DRONE_STALE_TIME = 120000;

std::map<String, DroneDetection> detectedDrones;
std::mutex detectedDronesMutex;
std::vector<String> droneEventLog;
std::atomic<uint32_t> droneDetectionCount(0);
std::atomic<bool> droneDetectionEnabled{false};
QueueHandle_t droneQueue = nullptr;
QueueHandle_t droneFrameQueue = nullptr;

extern std::atomic<bool> stopRequested;
extern void radioStartSTA();
extern void radioStartBLE();
extern void radioStopSTA();
extern ScanMode currentScanMode;
extern std::atomic<bool> scanning; 

static unsigned long lastDroneLog = 0;
const unsigned long DRONE_LOG_INTERVAL = 1000;
static unsigned long lastDroneMeshSend = 0;
static const unsigned long DRONE_MESH_INTERVAL = 3000;

struct DroneAnnounce { uint32_t announcedMs; uint32_t lastMeshMs; bool stale; };
static std::map<String, DroneAnnounce> droneMeshAnnounced;
static std::mutex droneMeshMutex;
static const uint32_t DRONE_ANNOUNCE_RETAIN_MS = 900000;
static const size_t MAX_DRONE_ANNOUNCED = 64;
static const uint32_t DRONE_ANNOUNCE_GRACE_MS = 3000;

static bool droneMeshShouldAnnounce(const String &key) {
    if (key.length() == 0) return false;
    auto it = droneMeshAnnounced.find(key);
    if (it == droneMeshAnnounced.end()) return true;
    if (!it->second.stale) return false;
    return (millis() - it->second.lastMeshMs) >= DRONE_STALE_TIME;
}
static void droneMeshMarkSent(const String &key) {
    if (key.length() == 0) return;
    DroneAnnounce &a = droneMeshAnnounced[key];
    if (a.announcedMs == 0) a.announcedMs = millis();
    a.lastMeshMs = millis();
    a.stale = false;
}
static uint32_t droneMeshLastSeen(const String &key, const DroneAnnounce &a, String &macOut, String &idOut) {
    macOut = key;
    idOut = "";
    auto it = detectedDrones.find(key);
    if (it == detectedDrones.end()) return a.lastMeshMs;
    idOut = String(it->second.uavId);
    return it->second.lastSeen;
}

extern String macFmt6(const uint8_t *m);
extern void sendMeshNotification(const Hit &hit);

static String droneMeshLine(const String &mac, const DroneDetection &d) {
    String msg = getNodeId() + ": DRONE: " + mac + " ID:" + String(d.uavId);
    msg += " R" + String(d.rssi);
    if (d.latitude != 0) {
        msg += " GPS:" + String(d.latitude, 6) + "," + String(d.longitude, 6);
    }
    if (d.altitudeMsl != 0) {
        msg += " ALT:" + String(d.altitudeMsl, 1);
    }
    if (d.speed != 0) {
        msg += " SPD:" + String(d.speed, 1);
    }
    if (d.operatorLat != 0 || d.operatorLon != 0) {
        msg += " OP:" + String(d.operatorLat, 6) + "," + String(d.operatorLon, 6);
    }
    return msg;
}

static bool droneMeshAnnounce(const String &key, const DroneDetection &d) {
    if (!meshEnabled || key.length() == 0) return false;
    std::lock_guard<std::mutex> lock(droneMeshMutex);
    if (!droneMeshShouldAnnounce(key)) return false;

    String msg = droneMeshLine(key, d);
    if (msg.length() > MAX_MESH_SIZE) {
        msg = getNodeId() + ": DRONE: " + key + " ID:" + String(d.uavId) + " R" + String(d.rssi);
    }
    if (msg.length() > MAX_MESH_SIZE || !meshEnqueue(msg)) return false;

    droneMeshMarkSent(key);
    return true;
}

void initializeDroneDetector() {
    if (droneFrameQueue) {
        vQueueDeleteWithCaps(droneFrameQueue);
    }
    droneFrameQueue = xQueueCreateWithCaps(8, sizeof(DroneFrameEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (droneQueue) {
        vQueueDeleteWithCaps(droneQueue);
    }
    droneQueue = xQueueCreateWithCaps(64, sizeof(DroneDetection), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!droneFrameQueue || !droneQueue) Serial.println("[DRONE] WARNING: queue alloc failed (PSRAM) - detection inert");
    {
        std::lock_guard<std::mutex> lock(detectedDronesMutex);
        detectedDrones.clear();
        droneEventLog.clear();
    }
    {
        std::lock_guard<std::mutex> lock(droneMeshMutex);
        droneMeshAnnounced.clear();
    }
    droneDetectionCount = 0;
}

static void mergeDroneTelemetry(DroneDetection &dst, const DroneDetection &src) {
    dst.rssi = src.rssi;
    dst.lastSeen = src.lastSeen;
    memcpy(dst.mac, src.mac, 6);
    if (src.viaWifi) dst.viaWifi = true;
    if (src.viaBle) dst.viaBle = true;
    if (src.uaType != 0) dst.uaType = src.uaType;

    if (src.hasLocation) {
        dst.hasLocation = true;
        if (src.latitude != 0 || src.longitude != 0) {
            dst.latitude  = src.latitude;
            dst.longitude = src.longitude;
        }
        if (src.altitudeMsl   > MIN_ALT)      dst.altitudeMsl   = src.altitudeMsl;
        if (src.altitudeBaro  > MIN_ALT)      dst.altitudeBaro  = src.altitudeBaro;
        if (src.heightAgl     > MIN_ALT)      dst.heightAgl     = src.heightAgl;
        if (src.speed         < INV_SPEED_H)  dst.speed         = src.speed;
        if (src.speedVertical < INV_SPEED_V)  dst.speedVertical = src.speedVertical;
        if (src.heading       < INV_DIR)      dst.heading       = src.heading;
        dst.status       = src.status;
        dst.heightType   = src.heightType;
        dst.horizAcc     = src.horizAcc;
        dst.vertAcc      = src.vertAcc;
        dst.baroAcc      = src.baroAcc;
        dst.speedAcc     = src.speedAcc;
        dst.tsAcc        = src.tsAcc;
        dst.locTimestamp = src.locTimestamp;
    }

    if (src.hasSystem) {
        dst.hasSystem = true;
        if (src.operatorLat != 0 || src.operatorLon != 0) {
            dst.operatorLat = src.operatorLat;
            dst.operatorLon = src.operatorLon;
        }
        if (src.operatorAltitude > MIN_ALT) dst.operatorAltitude = src.operatorAltitude;
        if (src.areaCeiling      > MIN_ALT) dst.areaCeiling      = src.areaCeiling;
        if (src.areaFloor        > MIN_ALT) dst.areaFloor        = src.areaFloor;
        dst.operatorLocType    = src.operatorLocType;
        dst.classificationType = src.classificationType;
        dst.areaCount          = src.areaCount;
        dst.areaRadius         = src.areaRadius;
        dst.categoryEU         = src.categoryEU;
        dst.classEU            = src.classEU;
        if (src.systemTimestamp != 0) dst.systemTimestamp = src.systemTimestamp;
    }

    if (src.operatorId[0]) {
        strncpy(dst.operatorId, src.operatorId, ODID_ID_SIZE);
        dst.operatorIdType = src.operatorIdType;
    }
    if (src.description[0]) {
        strncpy(dst.description, src.description, ODID_STR_SIZE);
        dst.selfIdDescType = src.selfIdDescType;
    }
    if (src.authType != 0) {
        dst.authType = src.authType;
        dst.authTimestamp = src.authTimestamp;
        memcpy(dst.authData, src.authData, sizeof(dst.authData) - 1);
    }
}

static const char *droneIdTypeStr(uint8_t t) {
    switch (t) {
        case ODID_IDTYPE_SERIAL_NUMBER:       return "Serial";
        case ODID_IDTYPE_CAA_REGISTRATION_ID: return "CAA";
        case ODID_IDTYPE_UTM_ASSIGNED_UUID:   return "UTM";
        case ODID_IDTYPE_SPECIFIC_SESSION_ID: return "Session";
        default:                              return "None";
    }
}

static const char *operatorLocTypeStr(uint8_t t) {
    switch (t) {
        case ODID_OPERATOR_LOCATION_TYPE_TAKEOFF:   return "Takeoff";
        case ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS: return "Live GNSS";
        case ODID_OPERATOR_LOCATION_TYPE_FIXED:     return "Fixed";
        default:                                    return "Unknown";
    }
}

static const char *horizAccStr(uint8_t a) {
    switch (a) {
        case 1:  return "<18.52 km"; case 2:  return "<7.408 km"; case 3:  return "<3.704 km";
        case 4:  return "<1.852 km"; case 5:  return "<926 m";    case 6:  return "<555.6 m";
        case 7:  return "<185.2 m";  case 8:  return "<92.6 m";   case 9:  return "<30 m";
        case 10: return "<10 m";     case 11: return "<3 m";      case 12: return "<1 m";
        default: return "unknown";
    }
}

static const char *vertAccStr(uint8_t a) {
    switch (a) {
        case 1: return "<150 m"; case 2: return "<45 m"; case 3: return "<25 m";
        case 4: return "<10 m";  case 5: return "<3 m";  case 6: return "<1 m";
        default: return "unknown";
    }
}

static const char *speedAccStr(uint8_t a) {
    switch (a) {
        case 1: return "<10 m/s"; case 2: return "<3 m/s";
        case 3: return "<1 m/s";  case 4: return "<0.3 m/s";
        default: return "unknown";
    }
}

static String tsAccStr(uint8_t a) {
    return (a == 0) ? String("unknown") : (String(a * 0.1f, 1) + " s");
}

static const char *heightTypeStr(uint8_t t) { return (t == 1) ? "above ground" : "above takeoff"; }

static const char *classificationTypeStr(uint8_t t) { return (t == 1) ? "EU" : "Undeclared"; }

static const char *categoryEUStr(uint8_t c) {
    switch (c) {
        case 1: return "Open"; case 2: return "Specific"; case 3: return "Certified";
        default: return "Undeclared";
    }
}

static const char *classEUStr(uint8_t c) {
    switch (c) {
        case 1: return "Class 0"; case 2: return "Class 1"; case 3: return "Class 2"; case 4: return "Class 3";
        case 5: return "Class 4"; case 6: return "Class 5"; case 7: return "Class 6";
        default: return "Undeclared";
    }
}

static const char *descTypeStr(uint8_t t) {
    switch (t) {
        case 1: return "Emergency"; case 2: return "Extended status";
        default: return "Text";
    }
}

static void parseDroneData(DroneDetection *drone, const ODID_UAS_Data *uasData) {
    // Drones broadcast up to 2 Basic IDs (Serial + CAA). Prefer the Serial Number.
    int idSlot = -1;
    for (int i = 0; i < ODID_BASIC_ID_MAX_MESSAGES; i++) {
        if (!uasData->BasicIDValid[i]) continue;
        if (uasData->BasicID[i].IDType == ODID_IDTYPE_SERIAL_NUMBER) { idSlot = i; break; }
        if (idSlot < 0) idSlot = i;
    }
    if (idSlot >= 0) {
        strncpy(drone->uavId, reinterpret_cast<const char *>(uasData->BasicID[idSlot].UASID), ODID_ID_SIZE);
        drone->uaType = uasData->BasicID[idSlot].UAType;
        drone->idType = uasData->BasicID[idSlot].IDType;
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
        drone->altitudeBaro = uasData->Location.AltitudeBaro;
        drone->heightType = uasData->Location.HeightType;
        drone->horizAcc = uasData->Location.HorizAccuracy;
        drone->vertAcc = uasData->Location.VertAccuracy;
        drone->baroAcc = uasData->Location.BaroAccuracy;
        drone->speedAcc = uasData->Location.SpeedAccuracy;
        drone->tsAcc = uasData->Location.TSAccuracy;
        drone->locTimestamp = uasData->Location.TimeStamp;
        drone->hasLocation = true;
        if (drone->uavId[0] != 0) {
            detect_recordRidClaim(drone->uavId, drone->latitude, drone->longitude,
                                  drone->altitudeMsl, drone->rssi);
        }
    }
    
    if (uasData->SystemValid) {
        drone->operatorLat = uasData->System.OperatorLatitude;
        drone->operatorLon = uasData->System.OperatorLongitude;
        drone->operatorAltitude = uasData->System.OperatorAltitudeGeo;
        drone->operatorLocType = uasData->System.OperatorLocationType;
        drone->classificationType = uasData->System.ClassificationType;
        drone->areaCount = uasData->System.AreaCount;
        drone->areaRadius = uasData->System.AreaRadius;
        drone->areaCeiling = uasData->System.AreaCeiling;
        drone->areaFloor = uasData->System.AreaFloor;
        drone->categoryEU = uasData->System.CategoryEU;
        drone->classEU = uasData->System.ClassEU;
        drone->systemTimestamp = uasData->System.Timestamp;
        drone->hasSystem = true;
    }
    
    if (uasData->OperatorIDValid) {
        strncpy(drone->operatorId, reinterpret_cast<const char *>(uasData->OperatorID.OperatorId), ODID_ID_SIZE);
        drone->operatorIdType = uasData->OperatorID.OperatorIdType;
    }
    
    if (uasData->SelfIDValid) {
        strncpy(drone->description, uasData->SelfID.Desc, ODID_STR_SIZE);
        drone->selfIdDescType = uasData->SelfID.DescType;
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
    int frame_length = payload[1];

    while (j < frame_length && j + 1 < buf_len) {
        uint8_t t = payload[j];
        uint8_t l = payload[j + 1];
        if (j + 2 + l > buf_len) break;
        const uint8_t *v = &payload[j + 2];

        switch (t) {
        case 2:
            for (int i = 0; (i < (l - 6)) && (i < ODID_ID_SIZE); ++i) {
                drone->operatorId[i] = static_cast<char>(v[i + 6]);
            }
            break;
        case 3:
            for (int i = 0; (i < l) && (i < ODID_ID_SIZE); ++i) {
                drone->uavId[i] = static_cast<char>(v[i]);
            }
            break;
        case 4:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                uav_lat.u32 <<= 8;
                uav_lat.u32 |= v[i];
            }
            drone->latitude = 1.0e-5 * static_cast<double>(uav_lat.i32);
            break;
        case 5:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                uav_long.u32 <<= 8;
                uav_long.u32 |= v[i];
            }
            drone->longitude = 1.0e-5 * static_cast<double>(uav_long.i32);
            break;
        case 6:
            if (l < 2) break;
            alt.u16 = (static_cast<uint16_t>(v[0]) << 8) | static_cast<uint16_t>(v[1]);
            drone->altitudeMsl = alt.i16;
            break;
        case 7:
            if (l < 2) break;
            height.u16 = (static_cast<uint16_t>(v[0]) << 8) | static_cast<uint16_t>(v[1]);
            drone->heightAgl = height.i16;
            break;
        case 8:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                base_lat.u32 <<= 8;
                base_lat.u32 |= v[i];
            }
            drone->operatorLat = 1.0e-5 * static_cast<double>(base_lat.i32);
            break;
        case 9:
            if (l < 4) break;
            for (int i = 0; i < 4; ++i) {
                base_long.u32 <<= 8;
                base_long.u32 |= v[i];
            }
            drone->operatorLon = 1.0e-5 * static_cast<double>(base_long.i32);
            break;
        case 10:
            if (l < 1) break;
            drone->speed = v[0];
            break;
        case 11:
            if (l < 2) break;
            drone->heading = (static_cast<uint16_t>(v[0]) << 8) | static_cast<uint16_t>(v[1]);
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
        bool foundDrone = false;

        while (offset < length && !foundDrone) {
            if (offset + 2 >= length) break;
            
            int typ = payload[offset];
            int len = payload[offset + 1];
            
            if (offset + 2 + len > length) break;
            
            const uint8_t *val = &payload[offset + 2];
            
            if ((typ == 0xdd) && len >= 3 && (val[0] == 0x6a) && (val[1] == 0x5c) && (val[2] == 0x35)) {
                parseFrenchDrone(&drone, &payload[offset], length - offset);
                validDrone = true;
                foundDrone = true;
            }
            else if ((typ == 0xdd) && len >= 3 &&
                     (((val[0] == 0x90 && val[1] == 0x3a && val[2] == 0xe6)) ||
                      ((val[0] == 0xfa && val[1] == 0x0b && val[2] == 0xbc)))) {
                int j = offset + 7;
                if (j < length &&
                    odid_message_process_pack(&uasData, const_cast<uint8_t*>(&payload[j]), length - j) >= 0 &&
                    (uasData.BasicIDValid[0] || uasData.LocationValid ||
                     uasData.SystemValid || uasData.OperatorIDValid)) {
                    parseDroneData(&drone, &uasData);
                    validDrone = true;
                    foundDrone = true;
                }
            }
            
            offset += len + 2;
        }
    }
    
    if (validDrone) {
        drone.viaWifi = true;
        {
            int n = length < 96 ? length : 96;
            String hx; hx.reserve(n * 2);
            for (int i = 0; i < n; i++) { char b[3]; snprintf(b, sizeof(b), "%02X", payload[i]); hx += b; }
            Serial.printf("[DRONE][WIFI-RAW] %s rssi=%d len=%d raw=%s%s\n",
                          macFmt6(drone.mac).c_str(), rssi, length, hx.c_str(), length > n ? "..." : "");
        }
        String macStr = macFmt6(drone.mac);
        String uavIdStr = String(drone.uavId);
        
        String announceKey;
        DroneDetection announceCopy{};
        {
            std::lock_guard<std::mutex> lock(detectedDronesMutex);
            auto existingIt = detectedDrones.end();
            if (uavIdStr.length() > 0) {
                for (auto it = detectedDrones.begin(); it != detectedDrones.end(); ++it) {
                    if (String(it->second.uavId) == uavIdStr) { existingIt = it; break; }
                }
            }
            if (existingIt == detectedDrones.end()) existingIt = detectedDrones.find(macStr);

            if (existingIt != detectedDrones.end()) {
                mergeDroneTelemetry(existingIt->second, drone);
            } else {
                existingIt = detectedDrones.emplace(macStr, drone).first;
                droneDetectionCount = droneDetectionCount + 1;
            }
            announceKey = existingIt->first;
            announceCopy = existingIt->second;
        }

        if (announceCopy.uavId[0] != 0) droneMeshAnnounce(announceKey, announceCopy);

        if (millis() - lastDroneLog >= DRONE_LOG_INTERVAL) {
            lastDroneLog = millis();
            
            DynamicJsonDocument doc(512);
            doc["timestamp"] = getEventTimestamp();
            doc["mac"] = macStr;
            doc["rssi"] = drone.rssi;
            doc["uav_id"] = uavIdStr;
            doc["id_type"] = droneIdTypeStr(drone.idType);
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

            Serial.println("[DRONE] " + jsonStr);
        }
        
        if (droneQueue) {
            xQueueSend(droneQueue, &drone, 0);
        }
    }
}

// Phase 3.2: BLE ODID Remote ID (ASTM F3411 over BLE 5.x).
void processDroneOdidBle(const uint8_t *addr, int8_t rssi,
                         const uint8_t *odid, int odidLen) {
    if (!droneDetectionEnabled || !addr || !odid || odidLen < 1) return;

    // Uncomment this to sanity check incoming RID
    // {
    //     int n = odidLen < 96 ? odidLen : 96;
    //     String hx; hx.reserve(n * 2);
    //     for (int i = 0; i < n; i++) { char b[3]; snprintf(b, sizeof(b), "%02X", odid[i]); hx += b; }
    //     uint8_t mt = odidLen > 2 ? (uint8_t)(odid[2] >> 4) : 0xFF;
    //     Serial.printf("[DRONE][BLE-RAW] %s rssi=%d len=%d msgtype=%u raw=%s%s\n",
    //                   macFmt6(addr).c_str(), rssi, odidLen, mt, hx.c_str(), odidLen > n ? "..." : "");
    // }

    if (rssi < rfConfig.globalRssiThreshold) return;
    DroneDetection drone{};
    memcpy(drone.mac, addr, 6);
    drone.viaBle = true;
    drone.rssi = rssi;
    drone.timestamp = millis();
    drone.lastSeen = millis();
    ODID_UAS_Data uasData;
    odid_initUasData(&uasData);
    // BLE svc-data after 0xFFFA UUID: [appcode 0x0D][msg counter][ODID msg|pack]. Skip 2 to reach msg.
    const int skip = 2;
    if (odidLen - skip < 1) return;
    uint8_t *msg = const_cast<uint8_t*>(odid + skip);
    const int msgLen = odidLen - skip;
    if ((msg[0] >> 4) == ODID_MESSAGETYPE_PACKED) {
        if (odid_message_process_pack(&uasData, msg, (size_t)msgLen) < 0) return;
    } else {
        if (msgLen < ODID_MESSAGE_SIZE) return;
        decodeOpenDroneID(&uasData, msg);
    }
    bool useful = uasData.BasicIDValid[0] || uasData.LocationValid ||
                  uasData.SystemValid || uasData.OperatorIDValid ||
                  uasData.SelfIDValid || uasData.AuthValid[0];
    if (!useful) return;
    parseDroneData(&drone, &uasData);
    bool idIsSerial = false;
    for (int i = 0; i < ODID_BASIC_ID_MAX_MESSAGES; i++)
        if (uasData.BasicIDValid[i] && uasData.BasicID[i].IDType == ODID_IDTYPE_SERIAL_NUMBER) { idIsSerial = true; break; }
    const String macStr = macFmt6(drone.mac);
    const String uavIdStr = String(drone.uavId);
    String announceKey;
    DroneDetection announceCopy{};
    {
    std::lock_guard<std::mutex> lock(detectedDronesMutex);
    auto existingIt = std::find_if(detectedDrones.begin(), detectedDrones.end(),
        [&](const std::pair<const String, DroneDetection>& entry) {
            if (uavIdStr.length() > 0 && String(entry.second.uavId) == uavIdStr) return true;
            return memcmp(entry.second.mac, drone.mac, 6) == 0;
        });
    if (existingIt != detectedDrones.end()) {
        mergeDroneTelemetry(existingIt->second, drone);
        if (uavIdStr.length() > 0 && (idIsSerial || existingIt->second.uavId[0] == '\0')) {
            strncpy(existingIt->second.uavId, drone.uavId, ODID_ID_SIZE);
            existingIt->second.idType = drone.idType;
        }
    } else {
        existingIt = detectedDrones.emplace(macStr, drone).first;
        droneDetectionCount = droneDetectionCount + 1;
    }
    announceKey = existingIt->first;
    announceCopy = existingIt->second;
    }

    if (announceCopy.uavId[0] != 0) droneMeshAnnounce(announceKey, announceCopy);
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
    std::lock_guard<std::mutex> lock(detectedDronesMutex);

    // Cache for 3 seconds to reduce performance impact
    if (millis() - lastCacheTime < 3000 && cachedResults.length() > 0) {
        return cachedResults;
    }
    lastCacheTime = millis();

    String results = "Drone Detection Results\n";
    results += "Total detections: " + String(droneDetectionCount) + "\n";
    results += "Unique drones: " + String(detectedDrones.size()) + "\n\n";

    for (const auto& entry : detectedDrones) {
        const DroneDetection& d = entry.second;
        results += "MAC: " + entry.first + "\n";
        results += "  UAV ID: " + String(d.uavId) + " [" + String(droneIdTypeStr(d.idType)) + "]\n";
        results += "  UA Type: " + String(uaTypeStr(d.uaType)) + " (" + String(d.uaType) + ")\n";
        results += "  RSSI: " + String(d.rssi) + " dBm\n";
        results += "  Via: " + String(d.viaWifi && d.viaBle ? "WiFi+BLE" : d.viaBle ? "BLE" : "WiFi") + "\n";

        // Always emit the full field skeleton (zero-coordinate RIDs included) for a consistent card.
        results += "  Location: " + ((d.latitude != 0 || d.longitude != 0)
                    ? (String(d.latitude, 6) + ", " + String(d.longitude, 6))
                    : String("n/a")) + "\n";
        results += "  Altitude MSL: " + droneFmtAlt(d.altitudeMsl) + "\n";
        results += "  Altitude Baro: " + droneFmtAlt(d.altitudeBaro) + "\n";
        results += "  Height AGL: " + droneFmtAlt(d.heightAgl) +
                  " (" + String(heightTypeStr(d.heightType)) + ")\n";
        results += "  Speed: " + droneFmtSpeed(d.speed) + "  Vert: " +
                  droneFmtVSpeed(d.speedVertical) + "\n";
        results += "  Heading: " + droneFmtHeading(d.heading) + "\n";
        results += "  Status: " + String(d.status) + "\n";
        results += "  Horiz accuracy: " + String(horizAccStr(d.horizAcc)) + "\n";
        results += "  Vert accuracy: " + String(vertAccStr(d.vertAcc)) + "\n";
        results += "  Baro accuracy: " + String(vertAccStr(d.baroAcc)) + "\n";
        results += "  Speed accuracy: " + String(speedAccStr(d.speedAcc)) + "\n";
        results += "  Time accuracy: " + tsAccStr(d.tsAcc) + "\n";
        results += "  Location timestamp: " + String(d.locTimestamp, 1) + " s\n";

        if (d.operatorLat != 0 || d.operatorLon != 0) {
            results += "  Operator: " + String(d.operatorLat, 6) + ", " + String(d.operatorLon, 6);
            if (d.operatorAltitude > MIN_ALT)
                results += "  Alt: " + String(d.operatorAltitude, 1) + " m";
            results += "\n";
        }
        results += "  Operator location type: " + String(operatorLocTypeStr(d.operatorLocType)) + "\n";
        results += "  Classification: " + String(classificationTypeStr(d.classificationType));
        if (d.classificationType == 1)
            results += " (" + String(categoryEUStr(d.categoryEU)) + ", " + String(classEUStr(d.classEU)) + ")";
        results += "\n";
        if (d.areaCount > 1) {
            results += "  Operational area: " + String(d.areaCount) + " aircraft, radius " +
                      String(d.areaRadius) + " m, ceiling " + droneFmtAlt(d.areaCeiling) +
                      ", floor " + droneFmtAlt(d.areaFloor) + "\n";
        }
        if (d.systemTimestamp != 0)
            results += "  System timestamp: " + String(d.systemTimestamp) + "\n";
        if (strlen(d.operatorId) > 0) {
            results += "  Operator ID: " + String(d.operatorId) + " [type " + String(d.operatorIdType) + "]\n";
        }
        if (strlen(d.description) > 0) {
            results += "  Description: " + String(d.description);
            if (d.selfIdDescType != 0)
                results += " [" + String(descTypeStr(d.selfIdDescType)) + "]";
            results += "\n";
        }
        if (d.authType != 0) {
            results += "  Auth: type " + String(d.authType) + " ts " + String(d.authTimestamp) + "\n";
        }

        uint32_t ageMs = millis() - d.lastSeen;
        results += "  Last seen: " + String(ageMs / 1000) + "s ago" +
                   (ageMs >= DRONE_STALE_TIME ? " (STALE)" : "") + "\n\n";
    }

    cachedResults = results;
    return cachedResults;
}

void cleanupDroneData() {
    uint32_t now = millis();
    std::lock_guard<std::mutex> lock(detectedDronesMutex);

    {
        std::lock_guard<std::mutex> meshLock(droneMeshMutex);
        while (droneMeshAnnounced.size() > MAX_DRONE_ANNOUNCED) {
            auto oldest = droneMeshAnnounced.begin();
            for (auto it = droneMeshAnnounced.begin(); it != droneMeshAnnounced.end(); ++it) {
                if (static_cast<uint32_t>(now - it->second.lastMeshMs) > static_cast<uint32_t>(now - oldest->second.lastMeshMs)) oldest = it;
            }
            droneMeshAnnounced.erase(oldest);
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
            if (droneDetectionCount > 0) droneDetectionCount = droneDetectionCount - 1;
        } else {
            break;
        }
    }

    while (droneEventLog.size() > MAX_DRONE_LOG_ENTRIES) {
        droneEventLog.erase(droneEventLog.begin());
    }

    if (ESP.getFreeHeap() < 20000) {
        Serial.println("[DRONE] Low memory - clearing old data");
        while (detectedDrones.size() > 10) {
            detectedDrones.erase(detectedDrones.begin());
            if (droneDetectionCount > 0) droneDetectionCount = droneDetectionCount - 1;
        }
        while (droneEventLog.size() > 20) {
            droneEventLog.erase(droneEventLog.begin());
        }
    }
}

void droneDetectorTask(void *pv)
{
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);
    scanSetCountdown(duration, forever);

    Serial.printf("[DRONE] Starting drone detection %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    initializeDroneDetector();
    droneDetectionEnabled = true;
    scanning = true;
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }
    stopRequested = false;
    
    uint32_t localFramesSeen = 0;

    // BLE-only skips promiscuous + channel hopping; radioStartSTA covers WiFi and WiFi+BLE
    if (currentScanMode == SCAN_BLE) radioStartBLE();
    else radioStartSTA();
    g_dronePinChannel.store(true);
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t nextResultsUpdate = millis() + 2000;
    uint32_t lastWrittenDroneCount = UINT32_MAX;
    uint32_t lastCleanup = millis();
    uint32_t lastLossSweep = millis();
    const unsigned long MESH_DRONE_LOSS_SWEEP_MS = 5000;
    DroneDetection drone;
    
    while ((forever && !stopRequested) ||
           (!forever && static_cast<int>(millis() - scanStart) < duration * 1000 && !stopRequested)) {

        DroneFrameEvent rawFrame;
        while (droneFrameQueue && xQueueReceive(droneFrameQueue, &rawFrame, 0) == pdTRUE) {
            processDronePacket(rawFrame.payload, rawFrame.len, rawFrame.rssi);
        }

        while (droneQueue && xQueueReceive(droneQueue, &drone, 0) == pdTRUE) {
            localFramesSeen++;
            
            String macStr = macFmt6(drone.mac);
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
            
        }

        if (meshEnabled && (millis() - lastLossSweep >= MESH_DRONE_LOSS_SWEEP_MS)) {
            lastLossSweep = millis();

            std::vector<std::pair<String, DroneDetection>> pending;
            {
                std::lock_guard<std::mutex> lock(detectedDronesMutex);
                std::lock_guard<std::mutex> meshLock(droneMeshMutex);
                for (const auto &e : detectedDrones) {
                    if (droneMeshAnnounced.find(e.first) != droneMeshAnnounced.end()) continue;
                    if ((millis() - e.second.timestamp) < DRONE_ANNOUNCE_GRACE_MS) continue;
                    if ((millis() - e.second.lastSeen) >= DRONE_STALE_TIME) continue;
                    pending.push_back({e.first, e.second});
                }

                for (auto it = droneMeshAnnounced.begin(); it != droneMeshAnnounced.end();) {
                    String mac, uavId;
                    const uint32_t lastSeen = droneMeshLastSeen(it->first, it->second, mac, uavId);
                    const uint32_t age = millis() - lastSeen;

                    if (age < DRONE_STALE_TIME) {
                        ++it;
                        continue;
                    }

                    if (!it->second.stale) {
                        String lostMsg = getNodeId() + ": DRONE_LOST: " + mac;
                        if (uavId.length()) lostMsg += " ID:" + uavId;
                        lostMsg += " AGE:" + String(age / 1000);
                        if (lostMsg.length() <= MAX_MESH_SIZE) meshEnqueue(lostMsg);
                        it->second.stale = true;
                        it->second.lastMeshMs = millis();
                        Serial.println("[DRONE] STALE " + mac + " ID:" + uavId);
                    }

                    if ((millis() - it->second.lastMeshMs) > DRONE_ANNOUNCE_RETAIN_MS) it = droneMeshAnnounced.erase(it);
                    else ++it;
                }
            }
            for (const auto &p : pending) droneMeshAnnounce(p.first, p.second);
        }

        if (static_cast<int32_t>(millis() - nextStatus) >= 0) {
            size_t uniqueN;
            { std::lock_guard<std::mutex> lock(detectedDronesMutex); uniqueN = detectedDrones.size(); }
            Serial.printf("[DRONE] Detected:%u Unique:%u Frames:%u\n",
                         droneDetectionCount.load(), static_cast<unsigned>(uniqueN), localFramesSeen);
            nextStatus += 5000;
        }

        uint32_t curDroneCount = droneDetectionCount.load();
        if (static_cast<int32_t>(millis() - nextResultsUpdate) >= 0 || curDroneCount != lastWrittenDroneCount) {
            nextResultsUpdate += 2000;
            lastWrittenDroneCount = curDroneCount;
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
        uint32_t totalDrones = 0, txDrones = 0;
        {
            std::vector<std::pair<String, DroneDetection>> snapshot;
            {
                std::lock_guard<std::mutex> lock(detectedDronesMutex);
                for (const auto& entry : detectedDrones) snapshot.push_back({entry.first, entry.second});
                totalDrones = detectedDrones.size();
            }
            for (const auto &p : snapshot) if (droneMeshAnnounce(p.first, p.second)) enqueuedDrones++;
            std::lock_guard<std::mutex> meshLock(droneMeshMutex);
            txDrones = droneMeshAnnounced.size();
        }

        String summary = getNodeId() + ": DRONE_DONE: Detected=" + String(droneDetectionCount) +
                        " Unique=" + String(totalDrones) +
                        " TX=" + String(txDrones);
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
                  droneDetectionCount.load(), static_cast<unsigned>(finalUniqueN));

    vTaskDelay(pdMS_TO_TICKS(100));
    g_dronePinChannel.store(false);
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}