#include "hardware.h"
#include "network.h"
#include "baseline.h"
#include <Arduino.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include "esp_wifi.h"
#include "esp_task_wdt.h"

extern Preferences prefs;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;

// GPS
TinyGPSPlus gps;
HardwareSerial GPS(2);
bool sdAvailable = false;
String lastGPSData = "No GPS data";
float gpsLat = 0.0, gpsLon = 0.0;
bool gpsValid = false;

// RTC
RTC_DS3231 rtc;
bool rtcAvailable = false;
bool rtcSynced = false;
time_t lastRTCSync = 0;
SemaphoreHandle_t rtcMutex = nullptr;
String rtcTimeString = "RTC not initialized";

// Vibration Sensor
volatile bool vibrationDetected = false;
unsigned long lastVibrationTime = 0;
unsigned long lastVibrationAlert = 0;
const unsigned long VIBRATION_ALERT_INTERVAL = 3000; 

// Diagnostics
extern volatile bool scanning;
extern volatile int totalHits;
extern volatile uint32_t framesSeen;
extern volatile uint32_t bleFramesSeen;
extern std::set<String> uniqueMacs;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern String macFmt6(const uint8_t *m);
extern size_t getTargetCount();
extern TaskHandle_t blueTeamTaskHandle;

// Tamper Detection Erase
uint32_t setupDelay = 120000;  // 2 minutes default
uint32_t setupStartTime = 0;
bool inSetupMode = false;
bool tamperEraseActive = false;
uint32_t tamperSequenceStart = 0;
String tamperAuthToken = "";
bool autoEraseEnabled = false;
uint32_t autoEraseDelay = 30000;
uint32_t autoEraseCooldown = 300000;  // 5 minutes default
static uint32_t lastAutoEraseAttempt = 0;
uint32_t vibrationsRequired = 3;
uint32_t detectionWindow = 20000;
String eraseStatus = "INACTIVE";
bool eraseInProgress = false;


void initializeHardware()
{
    Serial.println("Loading preferences...");
    prefs.begin("antihunter", false);
    loadRFConfigFromPrefs();

    baselineRamCacheSize = prefs.getUInt("baselineRamSize", 400);
    baselineSdMaxDevices = prefs.getUInt("baselineSdMax", 50000);
    deviceAbsenceThreshold = prefs.getUInt("absenceThresh", 120000);
    reappearanceAlertWindow = prefs.getUInt("reappearWin", 300000);
    significantRssiChange = prefs.getInt("rssiChange", 20);
    
    String nodeId = prefs.getString("nodeId", "");
    if (nodeId.length() == 0)
    {
        uint64_t chipid = ESP.getEfuseMac();
        nodeId = "NODE_" + String((uint32_t)(chipid >> 32), HEX) + String((uint32_t)chipid, HEX);
        prefs.putString("nodeId", nodeId);
    }
    setNodeId(nodeId);
    Serial.println("[NODE_ID] " + nodeId);
    Serial.printf("Hardware initialized: nodeID=%s\n", nodeId);
}

void saveConfiguration() {
    if (!sdAvailable) {
        Serial.println("SD card not available, cannot save configuration");
        return;
    }
    
    File configFile = SD.open("/config.json", FILE_WRITE);
    if (!configFile) {
        Serial.println("Failed to open config file for writing!");
        return;
    }

    String channelsCSV = "";
    for (size_t i = 0; i < CHANNELS.size(); i++) {
        channelsCSV += String(CHANNELS[i]);
        if (i < CHANNELS.size() - 1) {
            channelsCSV += ",";
        }
    }

    String config = "{\n";
    config += " \"nodeId\":\"" + prefs.getString("nodeId", "") + "\",\n";
    config += " \"scanMode\":" + String(currentScanMode) + ",\n";
    config += " \"channels\":\"" + channelsCSV + "\",\n";
    config += " \"autoEraseEnabled\":" + String(autoEraseEnabled ? "true" : "false") + ",\n";
    config += " \"autoEraseDelay\":" + String(autoEraseDelay) + ",\n";
    config += " \"autoEraseCooldown\":" + String(autoEraseCooldown) + ",\n";
    config += " \"vibrationsRequired\":" + String(vibrationsRequired) + ",\n";
    config += " \"detectionWindow\":" + String(detectionWindow) + ",\n";
    config += " \"setupDelay\":" + String(setupDelay) + ",\n";
    config += " \"baselineRamSize\":" + String(getBaselineRamCacheSize()) + ",\n";
    config += " \"baselineSdMax\":" + String(getBaselineSdMaxDevices()) + ",\n";
    config += " \"rfPreset\":" + String(rfConfig.preset) + ",\n";
    config += " \"wifiChannelTime\":" + String(rfConfig.wifiChannelTime) + ",\n";
    config += " \"wifiScanInterval\":" + String(rfConfig.wifiScanInterval) + ",\n";
    config += " \"bleScanInterval\":" + String(rfConfig.bleScanInterval) + ",\n";
    config += " \"bleScanDuration\":" + String(rfConfig.bleScanDuration) + ",\n";
    config += " \"targets\":\"" + prefs.getString("maclist", "") + "\"\n";
    config += "}";

    configFile.print(config);
    configFile.close();
    Serial.println("Configuration saved to SD card");
    // Serial.println("Saved JSON: " + config); // Debug
}
void loadConfiguration() {
    if (!sdAvailable) {
        Serial.println("SD card not available, cannot load configuration from SD");
        return;
    }
    
    if (!SD.exists("/config.json")) {
        Serial.println("No config file found on SD card");
        return;
    }

    File configFile = SD.open("/config.json", FILE_READ);
    if (!configFile) {
        Serial.println("Failed to open config file!");
        return;
    }

    String config = configFile.readString();
    configFile.close();
    
    // Serial.println("Raw config: " + config);
    
    DynamicJsonDocument doc(2048);
    DeserializationError error = deserializeJson(doc, config);
    
    if (error) {
        Serial.println("Failed to parse config file: " + String(error.c_str()));
        Serial.println("Config content was: " + config);
        return;
    }

    if (doc.containsKey("nodeId") && doc["nodeId"].is<String>()) {
        String nodeId = doc["nodeId"].as<String>();
        if (nodeId.length() > 0) {
            prefs.putString("nodeId", nodeId);
            setNodeId(nodeId);
            // Serial.println("Loaded nodeId from SD: " + nodeId);
        }
    }

    if (doc.containsKey("scanMode") && doc["scanMode"].is<int>()) {
        int scanMode = doc["scanMode"].as<int>();
        if (scanMode >= 0 && scanMode <= 2) {
            currentScanMode = (ScanMode)scanMode;
            prefs.putInt("scanMode", scanMode);
            // Serial.println("Loaded scanMode from SD: " + String(scanMode));
        }
    }

    if (doc.containsKey("rfPreset")) {
        uint8_t preset = doc["rfPreset"].as<uint8_t>();
        if (preset < 3) {
            setRFPreset(preset);
        } else if (doc.containsKey("wifiChannelTime") && doc.containsKey("wifiScanInterval") && 
                doc.containsKey("bleScanInterval") && doc.containsKey("bleScanDuration")) {
            uint32_t wct = doc["wifiChannelTime"].as<uint32_t>();
            uint32_t wsi = doc["wifiScanInterval"].as<uint32_t>();
            uint32_t bsi = doc["bleScanInterval"].as<uint32_t>();
            uint32_t bsd = doc["bleScanDuration"].as<uint32_t>();
            setCustomRFConfig(wct, wsi, bsi, bsd);
        }
    }

    if (doc.containsKey("channels") && doc["channels"].is<String>()) {
        String channels = doc["channels"].as<String>();
        if (channels.length() > 0) {
            parseChannelsCSV(channels);
            prefs.putString("channels", channels);
            // Serial.println("Loaded channels from SD: " + channels);
        }
    }

    if (doc.containsKey("targets") && doc["targets"].is<String>()) {
        String targets = doc["targets"].as<String>();
        if (targets.length() > 0) {
            saveTargetsList(targets);
            prefs.putString("maclist", targets);
            // Serial.println("Loaded targets from SD: " + targets);
            Serial.println("Target count: " + String(getTargetCount()));
        }
    }
    if (doc.containsKey("autoEraseEnabled")) {
        autoEraseEnabled = doc["autoEraseEnabled"].as<bool>();
    }
    if (doc.containsKey("autoEraseDelay")) {
        autoEraseDelay = doc["autoEraseDelay"].as<uint32_t>();
    }
    if (doc.containsKey("autoEraseCooldown")) {
        autoEraseCooldown = doc["autoEraseCooldown"].as<uint32_t>();
    }
    if (doc.containsKey("autoEraseEnabled")) {
        autoEraseEnabled = doc["autoEraseEnabled"].as<bool>();
    }
    if (doc.containsKey("autoEraseDelay")) {
        autoEraseDelay = doc["autoEraseDelay"].as<uint32_t>();
    }
    if (doc.containsKey("autoEraseCooldown")) {
        autoEraseCooldown = doc["autoEraseCooldown"].as<uint32_t>();
    }
    if (doc.containsKey("vibrationsRequired")) {
        vibrationsRequired = doc["vibrationsRequired"].as<uint32_t>();
    }
    if (doc.containsKey("detectionWindow")) {
        detectionWindow = doc["detectionWindow"].as<uint32_t>();
    }
    if (doc.containsKey("baselineRamSize")) {
        uint32_t ramSize = doc["baselineRamSize"].as<uint32_t>();
        setBaselineRamCacheSize(ramSize);
    }
    if (doc.containsKey("baselineSdMax")) {
        uint32_t sdMax = doc["baselineSdMax"].as<uint32_t>();
        setBaselineSdMaxDevices(sdMax);
    }

    Serial.println("Configuration loaded from SD card");
}

String getDiagnostics() {
    static unsigned long lastDiagTime = 0;
    static unsigned long lastSDTime = 0;
    static String cachedDiag = "";
    static String cachedSDInfo = "";
    
    if (millis() - lastDiagTime < 5000 && cachedDiag.length() > 0) {
        return cachedDiag;
    }
    lastDiagTime = millis();
    
    String s;
    s += "Scanning: " + String(scanning ? "yes" : "no") + "\n";
    
    // Task type tracking for the start/stop button
    if (workerTaskHandle) {
        const char* taskName = pcTaskGetName(workerTaskHandle);
        s += "Task Type: " + String(taskName) + "\n";
    } else if (blueTeamTaskHandle) {
        const char* taskName = pcTaskGetName(blueTeamTaskHandle);
        s += "Task Type: " + String(taskName) + "\n";
    } else {
        s += "Task Type: none\n";
    }
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    uint32_t uptime_total_seconds = millis() / 1000;
    uint32_t uptime_hours = uptime_total_seconds / 3600;
    uint32_t uptime_minutes = (uptime_total_seconds % 3600) / 60;
    uint32_t uptime_seconds = uptime_total_seconds % 60;

    char uptimeBuffer[10];
    snprintf(uptimeBuffer, sizeof(uptimeBuffer), "%02lu:%02lu:%02lu", uptime_hours, uptime_minutes, uptime_seconds);
    s += "Up:" + String(uptimeBuffer) + "\n";
    s += "Scan Mode: " + modeStr + "\n";
    s += String("Scanning: ") + (scanning ? "yes" : "no") + "\n";
    s += "WiFi Frames: " + String((unsigned)framesSeen) + "\n";
    s += "BLE Frames: " + String((unsigned)bleFramesSeen) + "\n";
    s += "Devices Found: " + String(totalHits) + "\n";
    s += "Current channel: " + String(WiFi.channel()) + "\n";
    s += "AP IP: " + WiFi.softAPIP().toString() + "\n";
    s += "Unique devices: " + String((int)uniqueMacs.size()) + "\n";
    s += "Targets Loaded: " + String(getTargetCount()) + "\n";
    s += "Mesh Node ID: " + getNodeId() + "\n";
    s += "Vibration sensor: " + String(lastVibrationTime > 0 ? "Active" : "Standby") + "\n";
    if (lastVibrationTime > 0) {
        unsigned long vibrationTime = lastVibrationTime;
        unsigned long seconds = vibrationTime / 1000;
        unsigned long minutes = seconds / 60;
        unsigned long hours = minutes / 60;
        
        seconds = seconds % 60;
        minutes = minutes % 60;
        hours = hours % 24;
        
        char timeStr[12];
        snprintf(timeStr, sizeof(timeStr), "%02lu:%02lu:%02lu", hours, minutes, seconds);
        
        unsigned long agoSeconds = (millis() - lastVibrationTime) / 1000;
        
        s += "Last Movement: " + String(timeStr) + " (" + String(agoSeconds) + "s ago)\n";
    }
    s += "SD Card: " + String(sdAvailable ? "Available" : "Not available") + "\n";
    if (sdAvailable) {
        if (millis() - lastSDTime > 30000 || cachedSDInfo.length() == 0) {
            lastSDTime = millis();
            cachedSDInfo = "";
            
            uint64_t cardSize = SD.cardSize() / (1024 * 1024);
            uint64_t totalBytes = SD.totalBytes();
            uint64_t usedBytes = SD.usedBytes();
            uint64_t freeBytes = totalBytes - usedBytes;

            uint8_t cardType = SD.cardType();
            String cardTypeStr = (cardType == CARD_MMC) ? "MMC" :
                                (cardType == CARD_SD) ? "SDSC" :
                                (cardType == CARD_SDHC) ? "SDHC" : "UNKNOWN";
            cachedSDInfo += "SD Free Space: " + String(freeBytes / (1024 * 1024)) + "MB\n";
        }
        s += cachedSDInfo;
    }
    s += "GPS: ";
    if (gpsValid) {
        s += "Locked\n";
    } else {
        s += "Waiting for data\n";
    }
    s += "RTC: ";
    if (rtcAvailable) {
        s += rtcSynced ? "Synced" : "Not synced";
        s += " Time: " + getRTCTimeString() + "\n";
        if (lastRTCSync > 0) {
            s += "Last sync: " + String((millis() - lastRTCSync) / 1000) + "s ago\n";
        }
    } else {
        s += "Not available\n";
    }
    s += "Drone Detection: " + String(droneDetectionEnabled ? "Active" : "Inactive") + "\n";
    if (droneDetectionEnabled) {
        s += "Drones detected: " + String(droneDetectionCount) + "\n";
        s += "Unique drones: " + String(detectedDrones.size()) + "\n";
    }

    s += "Last scan secs: " + String((unsigned)lastScanSecs) + (lastScanForever ? " (forever)" : "") + "\n";

    float temp_c = temperatureRead();
    float temp_f = (temp_c * 9.0 / 5.0) + 32.0;
    s += "ESP32 Temp: " + String(temp_c, 1) + "°C / " + String(temp_f, 1) + "°F\n";
    
    s += "WiFi Channels: ";
    for (auto c : CHANNELS) {
        s += String((int)c) + " ";
    }
    s += "\n";

    cachedDiag = s;
    return s;
}

void initializeSD()
{
    Serial.println("Initializing SD card...");
    Serial.printf("[SD] GPIO Pins SCK=%d MISO=%d MOSI=%d CS=%d\n", SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);

    SPI.end();
    SPI.begin(SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN);
    delay(100);

    if (SD.begin(SD_CS_PIN, SPI, 400000)) {
        Serial.println("SD card initialized");
        sdAvailable = true;
        delay(10);        
        
        initializeBaselineSD();

        return;
    }

    Serial.println("[SD] FAILED");
    sdAvailable = false;
}

void initializeGPS() {
    Serial.println("Initializing GPS…");

    // Grow buffer and start UART
    GPS.setRxBufferSize(2048);
    GPS.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    // Give it a moment to start spitting characters
    delay(120);
    unsigned long start = millis();
    bool sawSentence = false;
    while (millis() - start < 2000) {
        if (GPS.available()) {
            char c = GPS.read();
            if (gps.encode(c)) {
                sawSentence = true;
                break;
            }
        }
    }

    if (sawSentence) {
        Serial.println("[GPS] GPS module responding (NMEA detected)");
    } else {
        Serial.println("[GPS] No NMEA data – check wiring or allow cold-start time");
        Serial.println("[GPS] First fix can take 5–15 minutes outdoors");
    }

    // Send startup GPS status to server
    sendStartupStatus();

    Serial.printf("[GPS] UART on RX:%d TX:%d\n", GPS_RX_PIN, GPS_TX_PIN);
}

void sendStartupStatus() {
    float temp_c = temperatureRead();
    float temp_f = (temp_c * 9.0 / 5.0) + 32.0;

    String startupMsg = getNodeId() + ": STARTUP: System initialized";
    startupMsg += " GPS:";
    startupMsg += (gpsValid ? "LOCKED " : "SEARCHING ");
    startupMsg += "TEMP: " + String(temp_c, 1) + "°C / " + String(temp_f, 1) + "°F\n";
    startupMsg += " SD:";
    startupMsg += (sdAvailable ? "OK" : "FAIL");
    startupMsg += " Status:ONLINE";
    
    Serial.printf("[STARTUP] %s\n", startupMsg.c_str());
    sendToSerial1(startupMsg, false);
    logToSD(startupMsg);
}

void sendGPSLockStatus(bool locked) {
    String gpsMsg = getNodeId() + ": GPS: ";
    gpsMsg += (locked ? "LOCKED" : "LOST");
    if (locked) {
        gpsMsg += " Location:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
        gpsMsg += " Satellites:" + String(gps.satellites.value());
        gpsMsg += " HDOP:" + String(gps.hdop.hdop(), 2);
    }
    
    Serial.printf("[GPS] %s\n", gpsMsg.c_str());
    
    sendToSerial1(gpsMsg, true);
    logToSD("GPS Status: " + gpsMsg);
}

void updateGPSLocation() {
    static unsigned long lastDataTime = 0;
    static bool wasLocked = false;

    while (GPS.available() > 0) {
        char c = GPS.read();
        if (gps.encode(c)) {
            lastDataTime = millis();

            bool nowLocked = gps.location.isValid();
            
            if (nowLocked) {
                gpsLat = gps.location.lat();
                gpsLon = gps.location.lng();
                gpsValid = true;
                lastGPSData = "Lat: " + String(gpsLat, 6)
                            + ", Lon: " + String(gpsLon, 6)
                            + " (" + String((millis() - lastDataTime) / 1000) 
                            + "s ago)";
                
                if (!wasLocked && nowLocked) {
                    sendGPSLockStatus(true);
                }
            } else {
                gpsValid = false;
                lastGPSData = "No valid GPS fix (" 
                            + String((millis() - lastDataTime) / 1000)
                            + "s ago)";
                
                if (wasLocked && !nowLocked) {
                    sendGPSLockStatus(false);
                }
            }
            
            wasLocked = nowLocked;
        }
    }

    if (lastDataTime > 0 && millis() - lastDataTime > 30000) {
        if (gpsValid) {
            gpsValid = false;
            sendGPSLockStatus(false);
        }
        lastGPSData = "No data for " 
                    + String((millis() - lastDataTime) / 1000)
                    + "s";
    }
}


void logToSD(const String &data) {
    if (!sdAvailable) return;
    
    static uint32_t totalWrites = 0;
    static uint32_t failCount = 0;
    static File logFile;

    if (!SD.exists("/")) {
        failCount++;
        if (failCount > 5) {
            Serial.println("[SD] Multiple failures, marking unavailable");
            sdAvailable = false;
        }
        return;
    }
    
    if (!SD.exists("/")) {
        SD.mkdir("/");
    }

    if (!logFile || totalWrites % 50 == 0) {
        if (logFile) {
            logFile.close();
        }
        logFile = SD.open("/antihunter.log", FILE_APPEND);
        if (!logFile) {
            logFile = SD.open("/antihunter.log", FILE_WRITE);
            if (!logFile) {
                Serial.println("[SD] Failed to open log file");
                return;
            }
        }
    }
    
    // Use RTC time if available, otherwise fall back to millis
    String timestamp = getFormattedTimestamp();
    
    logFile.printf("[%s] %s\n", timestamp.c_str(), data.c_str());
    
    // Batch flush every 10 writes 
    if (++totalWrites % 10 == 0) {
        logFile.flush();
    }
    
    static unsigned long lastSizeCheck = 0;
    if (millis() - lastSizeCheck > 10000) {
        File checkFile = SD.open("/antihunter.log", FILE_READ);
        if (checkFile) {
            Serial.printf("[SD] Log file size: %lu bytes\n", checkFile.size());
            checkFile.close();
        }
        lastSizeCheck = millis();
    }
}
void logVibrationEvent(int sensorValue) {
    String event = String(sensorValue ? "Motion" : "Impact") + " detected";
    if (gpsValid) {
        event += " @" + String(gpsLat, 4) + "," + String(gpsLon, 4);
    }
    logToSD(event);
    Serial.printf("[MOTION] %s\n", event.c_str());
}

String getGPSData()
{
    return lastGPSData;
}

// Vibration Sensor
void IRAM_ATTR vibrationISR() {
    vibrationDetected = true;
    lastVibrationTime = millis();
}

void initializeVibrationSensor() {
    try {
        pinMode(VIBRATION_PIN, INPUT_PULLDOWN);
        attachInterrupt(digitalPinToInterrupt(VIBRATION_PIN), vibrationISR, RISING);
        Serial.println("[VIBRATION] Sensor initialized");
    } catch (...) {
        Serial.println("[VIBRATION] Failed to initialize vibration sensor");
    }
}

void checkAndSendVibrationAlert() {
    if (vibrationDetected) {
        vibrationDetected = false;
        
        // Check if we're in setup mode
        if (inSetupMode) {
            uint32_t elapsed = millis() - setupStartTime;
            if (elapsed >= setupDelay) {
                inSetupMode = false;
                Serial.println("[SETUP] Setup period complete - auto-erase now ACTIVE");
                
                String setupMsg = getNodeId() + ": SETUP_COMPLETE: Auto-erase activated";
                sendToSerial1(setupMsg, false);
            } else {
                uint32_t remaining = (setupDelay - elapsed) / 1000;
                Serial.printf("[SETUP] Setup mode - auto-erase activates in %us\n", remaining);
                
                // Send setup status in vibration alert
                String vibrationMsg = getNodeId() + ": VIBRATION: Movement in setup mode (active in " + String(remaining) + "s)";
                if (gpsValid) {
                    vibrationMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                }
                sendToSerial1(vibrationMsg, true);
                return;
            }
        }

        if (autoEraseEnabled && !tamperEraseActive && 
            millis() - lastVibrationTime < 1000 &&
            millis() - lastAutoEraseAttempt > autoEraseCooldown) {
            
            Serial.println("[TAMPER] Device movement detected - auto-erase enabled");
            tamperAuthToken = generateEraseToken();
            initiateTamperErase();
            lastAutoEraseAttempt = millis();
        }
        
        // Only send alert if enough time has passed since last alert
        if (millis() - lastVibrationAlert > VIBRATION_ALERT_INTERVAL) {
            lastVibrationAlert = millis();
            
            // Format timestamp as HH:MM:SS
            unsigned long currentTime = lastVibrationTime;
            unsigned long seconds = currentTime / 1000;
            unsigned long minutes = seconds / 60;
            unsigned long hours = minutes / 60;
            
            seconds = seconds % 60;
            minutes = minutes % 60;
            hours = hours % 24;
            
            char timeStr[12];
            snprintf(timeStr, sizeof(timeStr), "%02lu:%02lu:%02lu", hours, minutes, seconds);
            int sensorValue = digitalRead(VIBRATION_PIN);
            
            String vibrationMsg = getNodeId() + ": VIBRATION: Movement detected at " + String(timeStr);
            
            // Add GPS if we have it
            if (gpsValid) {
                vibrationMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }
            
            // Add tamper status
            if (tamperEraseActive) {
                uint32_t timeLeft = (TAMPER_DETECTION_WINDOW - (millis() - tamperSequenceStart)) / 1000;
                vibrationMsg += " TAMPER_ERASE_IN:" + String(timeLeft) + "s";
            }
            
            Serial.printf("[VIBRATION] Sending mesh alert: %s\n", vibrationMsg.c_str());
            sendToSerial1(vibrationMsg, true);
            logVibrationEvent(sensorValue);
            
        } else {
            Serial.printf("[VIBRATION] Alert rate limited - %lums since last alert\n", millis() - lastVibrationAlert);
        }
    }
}

// RTC functions
void initializeRTC() {
    Serial.println("Initializing RTC...");
    Serial.printf("[RTC] Using GPIO SDA:%d SCL:%d\n", RTC_SDA_PIN, RTC_SCL_PIN);

    if (rtcMutex == nullptr) {
        rtcMutex = xSemaphoreCreateMutex();
        if (rtcMutex == nullptr) {
            Serial.println("[RTC] Failed to create mutex!");
            rtcAvailable = false;
            return;
        }
    }

    Wire.begin(RTC_SDA_PIN, RTC_SCL_PIN, 400000);
    delay(100);
    
    if (!rtc.begin()) {
        Serial.println("[RTC] Failed at 400kHz, retrying at 100kHz...");
        Wire.end();
        delay(100);
        Wire.begin(RTC_SDA_PIN, RTC_SCL_PIN, 100000);
        delay(100);
        
        if (!rtc.begin()) {
            Serial.println("[RTC] DS3231 not found at 0x68!");
            Serial.println("[RTC] Check wiring: SDA->GPIO3, SCL->GPIO6, VCC->3.3V, GND->GND");
            rtcAvailable = false;
            return;
        }
        Serial.println("[RTC] Initialized at 100kHz");
    } else {
        Serial.println("[RTC] Initialized at 400kHz");
    }
    
    rtcAvailable = true;
    rtcSynced = false;
    lastRTCSync = 0;
    delay(100);

    DateTime now = rtc.now();
    bool powerLost = rtc.lostPower();
    bool yearInvalid = (now.year() < 2025 || now.year() > 2035);
    
    if (powerLost || yearInvalid) {
        Serial.println("[RTC] Time invalid, setting to compile time");
        rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
        DateTime updated = rtc.now();
        Serial.printf("[RTC] Set to: %04d-%02d-%02d %02d:%02d:%02d\n", 
                      updated.year(), updated.month(), updated.day(),
                      updated.hour(), updated.minute(), updated.second());
    } else {
        Serial.printf("[RTC] Current: %04d-%02d-%02d %02d:%02d:%02d\n", 
                      now.year(), now.month(), now.day(),
                      now.hour(), now.minute(), now.second());
    }
    
    rtc.disable32K();
}

bool setRTCTimeFromEpoch(time_t epoch) {
    if (!rtcAvailable || rtcMutex == nullptr) return false;
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    
    DateTime newTime(epoch);
    rtc.adjust(newTime);
    rtcSynced = false;
    lastRTCSync = 0;
    
    xSemaphoreGive(rtcMutex);
    
    Serial.printf("[TIME] Set: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                  newTime.year(), newTime.month(), newTime.day(),
                  newTime.hour(), newTime.minute(), newTime.second());
    return true;
}

void syncRTCFromGPS() {
    if (!rtcAvailable) return;
    if (!gpsValid) return;
    if (!gps.date.isValid() || !gps.time.isValid()) return;
    
    if (rtcSynced && lastRTCSync > 0 && (millis() - lastRTCSync) < 3600000) return;
    
    if (triangulationActive) return;
    if (rtcMutex == nullptr) return;
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    
    int year = gps.date.year();
    int month = gps.date.month();
    int day = gps.date.day();
    int hour = gps.time.hour();
    int minute = gps.time.minute();
    int second = gps.time.second();
    
    if (year < 2020 || year > 2050) {
        xSemaphoreGive(rtcMutex);
        return;
    }
    if (month < 1 || month > 12) {
        xSemaphoreGive(rtcMutex);
        return;
    }
    if (day < 1 || day > 31) {
        xSemaphoreGive(rtcMutex);
        return;
    }
    if (hour > 23 || minute > 59 || second > 59) {
        xSemaphoreGive(rtcMutex);
        return;
    }
    
    DateTime gpsTime(year, month, day, hour, minute, second);
    DateTime rtcTime = rtc.now();
    
    int timeDiff = abs((int)(gpsTime.unixtime() - rtcTime.unixtime()));
    
    if (timeDiff > 2 || !rtcSynced) {
        rtc.adjust(gpsTime);
        rtcSynced = true;
        lastRTCSync = millis();
        
        Serial.printf("[RTC] GPS sync: %04d-%02d-%02d %02d:%02d:%02d UTC (offset: %ds)\n",
                      year, month, day, hour, minute, second, timeDiff);
        
        String syncMsg = "RTC synced from GPS";
        logToSD(syncMsg);
        
        String meshMsg = getNodeId() + ": RTC_SYNC: GPS";
        sendToSerial1(meshMsg, false);
    }
    
    xSemaphoreGive(rtcMutex);
}

void updateRTCTime() {
    if (!rtcAvailable) {
        rtcTimeString = "RTC not available";
        return;
    }

    if (!rtc.begin()) {
        Serial.println("[RTC] Communication lost");
        rtcAvailable = false;
        return;
    }
    
    if (rtcMutex == nullptr) return;
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return;
    
    DateTime now = rtc.now();
    
    char buffer[30];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
             now.year(), now.month(), now.day(),
             now.hour(), now.minute(), now.second());
    
    rtcTimeString = String(buffer);
    
    xSemaphoreGive(rtcMutex);
    
    if (gpsValid && !rtcSynced) {
        syncRTCFromGPS();
    }
    
    if (gpsValid && rtcSynced && lastRTCSync > 0 && (millis() - lastRTCSync) > 3600000) {
        syncRTCFromGPS();
    }
}


String getRTCTimeString() {
    updateRTCTime();
    return rtcTimeString;
}

String getFormattedTimestamp() {
    if (!rtcAvailable) {
        uint32_t ts = millis();
        uint8_t hours = (ts / 3600000) % 24;
        uint8_t mins = (ts / 60000) % 60;
        uint8_t secs = (ts / 1000) % 60;
        
        char buffer[12];
        snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d", hours, mins, secs);
        return String(buffer);
    }
    
    if (rtcMutex == nullptr) return "MUTEX_NULL";
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return "MUTEX_TIMEOUT";
    
    DateTime now = rtc.now();
    char buffer[30];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
             now.year(), now.month(), now.day(),
             now.hour(), now.minute(), now.second());
    
    xSemaphoreGive(rtcMutex);
    
    return String(buffer);
}


time_t getRTCEpoch() {
    if (!rtcAvailable) return 0;
    if (rtcMutex == nullptr) return 0;
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return 0;
    
    DateTime now = rtc.now();
    time_t epoch = now.unixtime();
    
    xSemaphoreGive(rtcMutex);
    
    return epoch;
}

bool setRTCTime(int year, int month, int day, int hour, int minute, int second) {
    if (!rtcAvailable) return false;
    if (rtcMutex == nullptr) return false;
    
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    
    DateTime newTime(year, month, day, hour, minute, second);
    rtc.adjust(newTime);
    rtcSynced = true;
    
    xSemaphoreGive(rtcMutex);
    
    Serial.printf("[RTC] Manually set to: %04d-%02d-%02d %02d:%02d:%02d\n",
                  year, month, day, hour, minute, second);
    
    return true;
}

// SD Erase

String generateEraseToken() {
    uint32_t token1 = esp_random();
    uint32_t token2 = esp_random();
    uint32_t timestamp = millis() / 1000;
    
    char tokenBuffer[32];
    snprintf(tokenBuffer, sizeof(tokenBuffer), "AH_%08X_%08X_%08X", 
             token1, token2, timestamp);
    
    return String(tokenBuffer);
}

bool validateEraseToken(const String &token) {
    if (token != tamperAuthToken) return false;
    
    int lastUnderscorePos = token.lastIndexOf('_');
    if (lastUnderscorePos < 0) return false;
    
    String timestampStr = token.substring(lastUnderscorePos + 1);
    uint32_t tokenTime = strtoul(timestampStr.c_str(), nullptr, 16);
    uint32_t currentTime = millis() / 1000;
    
    return (currentTime - tokenTime) < 300;
}

bool initiateTamperErase() {
    if (tamperEraseActive) return false;
    
    tamperEraseActive = true;
    tamperSequenceStart = millis();
    tamperAuthToken = generateEraseToken();
    
    Serial.println("[TAMPER] Device movement detected - auto-erase in 30 seconds");
    
    String alertMsg = getNodeId() + ": TAMPER_DETECTED: Auto-erase in 30s";
    if (gpsValid) {
        alertMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    sendToSerial1(alertMsg, false);
    
    logEraseAttempt("Tamper detection triggered", true);
    return true;
}

void cancelTamperErase() {
    if (tamperEraseActive) {
        Serial.println("[TAMPER] Auto-erase cancelled");
        String cancelMsg = getNodeId() + ": TAMPER_CANCELLED";
        sendToSerial1(cancelMsg, false);
    }
    
    tamperEraseActive = false;
    tamperSequenceStart = 0;
    tamperAuthToken = "";
}

bool checkTamperTimeout() {
    if (!tamperEraseActive) return false;
    
    uint32_t elapsed = millis() - tamperSequenceStart;
    
    if (elapsed >= TAMPER_DETECTION_WINDOW) {
        Serial.println("[TAMPER] Timeout - executing erase");
        return executeSecureErase("Tamper timeout");
    }
    
    return false;
}

bool executeSecureErase(const String &reason) {
    eraseStatus = "EXECUTING";
    eraseInProgress = true;
    
    Serial.println("EXECUTING SECURE ERASE: " + reason);
    
    if (!sdAvailable) {
        eraseStatus = "FAILED - SD card not available";
        eraseInProgress = false;
        return false;
    }
    
    String finalAlert = getNodeId() + ": ERASE_EXECUTING: " + reason;
    if (gpsValid) {
        finalAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    sendToSerial1(finalAlert, true);
    
    bool success = performSecureWipe();
    
    if (success) {
        eraseStatus = "COMPLETED";
        String confirmMsg = getNodeId() + ": ERASE_COMPLETE";
        sendToSerial1(confirmMsg, true);
    } else {
        eraseStatus = "FAILED";
    }
    
    eraseInProgress = false;
    
    if (tamperEraseActive) {
        cancelTamperErase();
    }
    
    return success;
}

bool performSecureWipe() {
    Serial.println("[WIPE] Starting secure wipe");
    
    deleteAllFiles("/");
    
    File marker = SD.open("/weather-air-feed.txt", FILE_WRITE);
    if (marker) {
        marker.println("Weather and AQ data could not be sent to your network. Check your API key and settings or contact support.");
        marker.close();
    
        if (SD.exists("/weather-air-feed.txt")) {
            Serial.println("[WIPE] Marker file created successfully - wipe completed");
            return true;
        } else {
            Serial.println("[WIPE] Marker file creation failed");
            return false;
        }
    } else {
        Serial.println("[WIPE] Failed to create marker file - SD card may be inaccessible");
        return false;
    }
}

void deleteAllFiles(const String &dirname) {
    File root = SD.open(dirname);
    if (!root) {
        Serial.println("[WIPE] Failed to open directory: " + dirname);
        return;
    }
    
    if (!root.isDirectory()) {
        Serial.println("[WIPE] Not a directory: " + dirname);
        root.close();
        return;
    }
    
    File file = root.openNextFile();
    
    while (file) {
        String fileName = file.name();
        String fullPath = dirname + "/" + fileName;
        
        if (file.isDirectory()) {
            // Recursively delete subdirectory
            deleteAllFiles(fullPath);
            
            // Remove the directory itself
            if (SD.rmdir(fullPath)) {
                Serial.println("[WIPE] Removed directory: " + fullPath);
            } else {
                Serial.println("[WIPE] Failed to remove directory: " + fullPath);
            }
        } else {
            // Remove the file
            if (SD.remove(fullPath)) {
                Serial.println("[WIPE] Removed file: " + fullPath);
            } else {
                Serial.println("[WIPE] Failed to remove file: " + fullPath);
            }
        }
        
        file = root.openNextFile();
    }
    
    root.close();
}

void logEraseAttempt(const String &reason, bool success) {
    String logEntry = "ERASE: " + reason + " Success:" + (success ? "YES" : "NO");
    Serial.println(logEntry);
    if (sdAvailable && !success) {
        logToSD(logEntry);
    }
}