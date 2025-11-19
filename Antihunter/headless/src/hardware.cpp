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
#include "nvs_flash.h"

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

// Diagnostics & Config
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
uint32_t SafeSD::lastCheckTime = 0;
bool SafeSD::lastCheckResult = false;
static unsigned long lastSaveTime = 0;
const unsigned long SAVE_DEBOUNCE_MS = 2000;

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

// SD & HW Init

bool SafeSD::checkAvailability() {
    uint32_t now = millis();
    if (now - lastCheckTime < CHECK_INTERVAL_MS) {
        return lastCheckResult;
    }
    
    lastCheckTime = now;
    lastCheckResult = SD.begin(SD_CS_PIN);
    sdAvailable = lastCheckResult;
    
    if (!lastCheckResult) {
        Serial.println("[SAFE_SD] SD card not available");
    }
    
    return lastCheckResult;
}

bool SafeSD::isAvailable() {
    return checkAvailability();
}

fs::File SafeSD::open(const char* path, const char* mode) {
    if (!checkAvailability()) {
        return File();
    }
    
    fs::File f = SD.open(path, mode);
    if (!f) {
        Serial.printf("[SAFE_SD] Failed to open: %s\n", path);
    }
    return f;
}

bool SafeSD::exists(const char* path) {
    if (!checkAvailability()) {
        return false;
    }
    return SD.exists(path);
}

bool SafeSD::remove(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot remove %s - SD unavailable\n", path);
        return false;
    }
    
    bool result = SD.remove(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to remove: %s\n", path);
    }
    return result;
}

bool SafeSD::mkdir(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot mkdir %s - SD unavailable\n", path);
        return false;
    }
    
    bool result = SD.mkdir(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to mkdir: %s\n", path);
    }
    return result;
}

bool SafeSD::rmdir(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot rmdir %s - SD unavailable\n", path);
        return false;
    }
    
    bool result = SD.rmdir(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to rmdir: %s\n", path);
    }
    return result;
}

size_t SafeSD::write(fs::File& file, const uint8_t* data, size_t len) {
    if (!file || !checkAvailability()) {
        Serial.println("[SAFE_SD] Write failed - file invalid or SD unavailable");
        return 0;
    }
    
    size_t written = file.write(data, len);
    if (written != len) {
        Serial.printf("[SAFE_SD] Partial write: %d/%d bytes\n", written, len);
    }
    return written;
}

size_t SafeSD::read(fs::File& file, uint8_t* data, size_t len) {
    if (!file || !checkAvailability()) {
        Serial.println("[SAFE_SD] Read failed - file invalid or SD unavailable");
        return 0;
    }
    
    size_t bytesRead = file.read(data, len);
    if (bytesRead != len) {
        Serial.printf("[SAFE_SD] Partial read: %d/%d bytes\n", bytesRead, len);
    }
    return bytesRead;
}

bool SafeSD::flush(fs::File& file) {
    if (!file || !checkAvailability()) {
        return false;
    }
    file.flush();
    return true;
}

void SafeSD::forceRecheck() {
    lastCheckTime = 0;
}

String sanitizeNodeId(String nodeId) {
    nodeId.toUpperCase();
    
    if (!nodeId.startsWith("AH")) {
        Serial.printf("[SANITIZE] Adding AH prefix to '%s'\n", nodeId.c_str());
        nodeId = "AH" + nodeId;
    }
    
    String result = nodeId.substring(0, 2);
    for (size_t i = 2; i < nodeId.length() && result.length() < 5; i++) {
        if (isdigit(nodeId[i])) {
            result += nodeId[i];
        } else {
            Serial.printf("[SANITIZE] Skipping non-digit char '%c' at position %d\n", nodeId[i], i);
        }
    }
    
    if (result.length() < 3) {
        Serial.printf("[SANITIZE] Too short after sanitization, padding with digits\n");
        while (result.length() < 3) {
            result += String(random(0, 10));
        }
    }
    
    if (result.length() > 5) {
        Serial.printf("[SANITIZE] Truncating from %d to 5 chars\n", result.length());
        result = result.substring(0, 5);
    }
    
    return result;
}

void initializeHardware()
{
    Serial.println("Loading preferences...");
    prefs.begin("antihunter", false);
    
    randomSeed(esp_random());
    
    loadRFConfigFromPrefs();
    
    meshSendInterval = prefs.getULong("meshInterval", 5000);
    if (meshSendInterval < 1500 || meshSendInterval > 60000) {
        meshSendInterval = 5000;
    }
    Serial.printf("[CONFIG] Mesh send interval: %lums\n", meshSendInterval);
    
    baselineRamCacheSize = prefs.getUInt("baselineRamSize", 400);
    baselineSdMaxDevices = prefs.getUInt("baselineSdMax", 50000);
    deviceAbsenceThreshold = prefs.getUInt("absenceThresh", 120000);
    reappearanceAlertWindow = prefs.getUInt("reappearWin", 300000);
    significantRssiChange = prefs.getInt("rssiChange", 20);
    
    String nodeId = prefs.getString("nodeId", "");
    if (nodeId.length() == 0)
    {
        int randomNum = random(10, 100);
        char buffer[10];
        sprintf(buffer, "AH%02d", randomNum);
        nodeId = buffer;
        prefs.putString("nodeId", nodeId);
    }
    setNodeId(nodeId);
    Serial.println("[NODE_ID] " + nodeId);
    Serial.printf("Hardware initialized: nodeID=%s\n", nodeId.c_str());
}

void syncSettingsToNVS() {
    prefs.putInt("scanMode", currentScanMode);
    prefs.putULong("meshInterval", meshSendInterval);
    prefs.putUInt("blRamSize", getBaselineRamCacheSize());
    prefs.putUInt("blSdMax", getBaselineSdMaxDevices());
    prefs.putUInt("absenceThresh", getDeviceAbsenceThreshold());
    prefs.putUInt("reappearWin", getReappearanceAlertWindow());
    prefs.putInt("rssiChange", getSignificantRssiChange());
    prefs.putBool("autoErase", autoEraseEnabled);
    prefs.putUInt("eraseDelay", autoEraseDelay);
    prefs.putUInt("eraseCooldown", autoEraseCooldown);
    prefs.putUInt("vibRequired", vibrationsRequired);
    prefs.putUInt("detectWindow", detectionWindow);
    prefs.putUInt("setupDelay", setupDelay);
    prefs.putUInt("blDuration", baselineDuration);
    prefs.putInt("blRssi", getBaselineRssiThreshold());
}

void saveConfiguration() {
    uint32_t now = millis();
    if (now - lastSaveTime < SAVE_DEBOUNCE_MS) {
        return;  // Ignore if called too soon
    }
    lastSaveTime = now;
    
    if (!SafeSD::isAvailable()) {
        Serial.println("SD card not available, settings saved to NVS only");
        return;
    }
    
    File configFile = SafeSD::open("/config.json", FILE_WRITE);
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
    config += " \"meshInterval\":" + String(meshSendInterval) + ",\n";
    config += " \"autoEraseEnabled\":" + String(autoEraseEnabled ? "true" : "false") + ",\n";
    config += " \"autoEraseDelay\":" + String(autoEraseDelay) + ",\n";
    config += " \"autoEraseCooldown\":" + String(autoEraseCooldown) + ",\n";
    config += " \"vibrationsRequired\":" + String(vibrationsRequired) + ",\n";
    config += " \"detectionWindow\":" + String(detectionWindow) + ",\n";
    config += " \"setupDelay\":" + String(setupDelay) + ",\n";
    config += " \"baselineRamSize\":" + String(getBaselineRamCacheSize()) + ",\n";
    config += " \"baselineSdMax\":" + String(getBaselineSdMaxDevices()) + ",\n";
    config += " \"baselineRssiThreshold\":" + String(getBaselineRssiThreshold()) + ",\n";
    config += " \"baselineDuration\":" + String(baselineDuration / 1000) + ",\n";
    config += " \"absenceThreshold\":" + String(getDeviceAbsenceThreshold() / 1000) + ",\n";
    config += " \"reappearanceWindow\":" + String(getReappearanceAlertWindow() / 1000) + ",\n";
    config += " \"rssiChangeDelta\":" + String(getSignificantRssiChange()) + ",\n";
    config += " \"rfPreset\":" + String(rfConfig.preset) + ",\n";
    config += " \"wifiChannelTime\":" + String(rfConfig.wifiChannelTime) + ",\n";
    config += " \"wifiScanInterval\":" + String(rfConfig.wifiScanInterval) + ",\n";
    config += " \"bleScanInterval\":" + String(rfConfig.bleScanInterval) + ",\n";
    config += " \"bleScanDuration\":" + String(rfConfig.bleScanDuration) + ",\n";
    config += " \"globalRssiThreshold\":" + String(rfConfig.globalRssiThreshold) + ",\n";
    config += " \"targets\":\"" + prefs.getString("maclist", "") + "\"\n";
    config += "}";
    
    configFile.print(config);
    configFile.close();
    
    Serial.println("Configuration saved to NVS and SD card");
}

void loadConfiguration() {
    if (!SafeSD::isAvailable()) {
        Serial.println("SD card not available, loading from NVS only");
        currentScanMode = (ScanMode)prefs.getInt("scanMode", SCAN_BOTH);
        meshSendInterval = prefs.getULong("meshInterval", 5000);
        autoEraseEnabled = prefs.getBool("autoErase", false);
        autoEraseDelay = prefs.getUInt("eraseDelay", 30000);
        autoEraseCooldown = prefs.getUInt("eraseCooldown", 300000);
        vibrationsRequired = prefs.getUInt("vibRequired", 3);
        detectionWindow = prefs.getUInt("detectWindow", 20000);
        setupDelay = prefs.getUInt("setupDelay", 120000);
        setBaselineRamCacheSize(prefs.getUInt("blRamSize", 400));
        setBaselineSdMaxDevices(prefs.getUInt("blSdMax", 50000));
        setDeviceAbsenceThreshold(prefs.getUInt("absenceThresh", 120000));
        setReappearanceAlertWindow(prefs.getUInt("reappearWin", 300000));
        setSignificantRssiChange(prefs.getInt("rssiChange", 20));
        setBaselineRssiThreshold(prefs.getInt("blRssi", -70));
        baselineDuration = prefs.getUInt("blDuration", 300000);
        return;
    }
    
    if (!SafeSD::exists("/config.json")) {
        Serial.println("No config file found on SD card, using NVS defaults");
        return;
    }

    File configFile = SafeSD::open("/config.json", FILE_READ);
    if (!configFile) {
        Serial.println("Failed to open config file!");
        return;
    }

    String config = configFile.readString();
    configFile.close();

    config.replace(",\n}", "\n}");
    config.replace(",}", "}");

    DynamicJsonDocument doc(2048);
    DeserializationError error = deserializeJson(doc, config);

    if (error) {
        Serial.println("Failed to parse config file: " + String(error.c_str()));
        Serial.println("Deleting corrupted config and creating new one");
        SafeSD::remove("/config.json");
        saveConfiguration();
        return;
    }

    if (doc.containsKey("nodeId") && doc["nodeId"].is<String>()) {
        String nodeId = doc["nodeId"].as<String>();
        if (nodeId.length() > 0) {
            String original = nodeId;
            nodeId = sanitizeNodeId(nodeId);
            
            if (nodeId != original) {
                Serial.printf("[CONFIG] Sanitized nodeId from SD: '%s' -> '%s'\n", original.c_str(), nodeId.c_str());
            } else {
                Serial.printf("[CONFIG] Loaded valid nodeId from SD: %s\n", nodeId.c_str());
            }
            
            prefs.putString("nodeId", nodeId);
            setNodeId(nodeId);
        }
    }

    if (doc.containsKey("scanMode") && doc["scanMode"].is<int>()) {
        int scanMode = doc["scanMode"].as<int>();
        if (scanMode >= 0 && scanMode <= 2) {
            currentScanMode = (ScanMode)scanMode;
            prefs.putInt("scanMode", scanMode);
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
            String channels = doc.containsKey("channels") && doc["channels"].is<String>() ?
                            doc["channels"].as<String>() : "1..14";
            int8_t rssiThreshold = doc["globalRssiThreshold"] | -90;
            setCustomRFConfig(wct, wsi, bsi, bsd, channels, rssiThreshold);
        }
    }

    if (doc.containsKey("globalRssiThreshold")) {
        int8_t rssiThreshold = doc["globalRssiThreshold"].as<int>();
        rfConfig.globalRssiThreshold = constrain(rssiThreshold, -100, -10);
        prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
        Serial.printf("Loaded globalRssiThreshold from SD: %d dBm\n", rssiThreshold);
    }

    if (doc.containsKey("channels") && doc["channels"].is<String>()) {
        String channels = doc["channels"].as<String>();
        if (channels.length() > 0) {
            parseChannelsCSV(channels);
            prefs.putString("channels", channels);
            Serial.println("Loaded channels from SD: " + channels);
        }
    }

    if (doc.containsKey("meshInterval") && doc["meshInterval"].is<unsigned long>()) {
        unsigned long interval = doc["meshInterval"].as<unsigned long>();
        if (interval >= 500 && interval <= 30000) {
            meshSendInterval = interval;
            prefs.putULong("meshInterval", interval);
            Serial.printf("Loaded meshInterval from SD: %lums\n", interval);
        }
    }

    if (doc.containsKey("targets") && doc["targets"].is<String>()) {
        String targets = doc["targets"].as<String>();
        if (targets.length() > 0) {
            saveTargetsList(targets);
            prefs.putString("maclist", targets);
            Serial.println("Target count: " + String(getTargetCount()));
        }
    }
    
    if (doc.containsKey("apSsid") && doc["apSsid"].is<String>()) {
        String apSsid = doc["apSsid"].as<String>();
        if (apSsid.length() > 0) {
            prefs.putString("apSsid", apSsid);
        }
    }
    
    if (doc.containsKey("apPass") && doc["apPass"].is<String>()) {
        String apPass = doc["apPass"].as<String>();
        if (apPass.length() >= 8) {
            prefs.putString("apPass", apPass);
        }
    }
    
    if (doc.containsKey("autoEraseEnabled")) {
        autoEraseEnabled = doc["autoEraseEnabled"].as<bool>();
        prefs.putBool("autoErase", autoEraseEnabled);
    }
    
    if (doc.containsKey("autoEraseDelay")) {
        autoEraseDelay = doc["autoEraseDelay"].as<uint32_t>();
        prefs.putUInt("eraseDelay", autoEraseDelay);
    }
    
    if (doc.containsKey("autoEraseCooldown")) {
        autoEraseCooldown = doc["autoEraseCooldown"].as<uint32_t>();
        prefs.putUInt("eraseCooldown", autoEraseCooldown);
    }
    
    if (doc.containsKey("vibrationsRequired")) {
        vibrationsRequired = doc["vibrationsRequired"].as<uint32_t>();
        prefs.putUInt("vibRequired", vibrationsRequired);
    }
    
    if (doc.containsKey("detectionWindow")) {
        detectionWindow = doc["detectionWindow"].as<uint32_t>();
        prefs.putUInt("detectWindow", detectionWindow);
    }
    
    if (doc.containsKey("setupDelay")) {
        setupDelay = doc["setupDelay"].as<uint32_t>();
        prefs.putUInt("setupDelay", setupDelay);
    }
    
    if (doc.containsKey("baselineRamSize")) {
        uint32_t ramSize = doc["baselineRamSize"].as<uint32_t>();
        setBaselineRamCacheSize(ramSize);
        prefs.putUInt("blRamSize", ramSize);
    }
    
    if (doc.containsKey("baselineSdMax")) {
        uint32_t sdMax = doc["baselineSdMax"].as<uint32_t>();
        setBaselineSdMaxDevices(sdMax);
        prefs.putUInt("blSdMax", sdMax);
    }
    
    if (doc.containsKey("baselineRssiThreshold")) {
        int8_t rssiThresh = doc["baselineRssiThreshold"].as<int>();
        setBaselineRssiThreshold(rssiThresh);
        prefs.putInt("blRssi", rssiThresh);
    }
    
    if (doc.containsKey("baselineDuration")) {
        baselineDuration = doc["baselineDuration"].as<uint32_t>() * 1000;
        prefs.putUInt("blDuration", baselineDuration);
    }
    
    if (doc.containsKey("absenceThreshold")) {
        uint32_t absence = doc["absenceThreshold"].as<uint32_t>() * 1000;
        setDeviceAbsenceThreshold(absence);
        prefs.putUInt("absenceThresh", absence);
    }
    
    if (doc.containsKey("reappearanceWindow")) {
        uint32_t reappear = doc["reappearanceWindow"].as<uint32_t>() * 1000;
        setReappearanceAlertWindow(reappear);
        prefs.putUInt("reappearWin", reappear);
    }
    
    if (doc.containsKey("rssiChangeDelta")) {
        int8_t delta = doc["rssiChangeDelta"].as<int>();
        setSignificantRssiChange(delta);
        prefs.putInt("rssiChange", delta);
    }

    Serial.println("Configuration loaded from SD card and synced to NVS");
}

bool waitForInitialConfig() {
    if (!sdAvailable) {
        Serial.println("[CONFIG] SD card not available, skipping initial config");
        return false;
    }
    
    // Check if config exists
    bool configExists = SD.exists("/config.json");
    
    if (configExists) {
        Serial.println("[CONFIG] Existing config found");
        Serial.println("[CONFIG] Waiting for RECONFIG command...");
        Serial.flush();
        
        unsigned long startWait = millis();
        while (millis() - startWait < 10000) {
            if (Serial.available()) {
                String line = Serial.readStringUntil('\n');
                line.trim();
                if (line == "RECONFIG") {
                    Serial.println("[CONFIG] Entering reconfiguration mode");
                    SD.remove("/config.json");
                    break;
                } else {
                    Serial.println("[CONFIG] Skipped - using existing config");
                    return false;
                }
            }
            delay(100);
        }
        
        if (SD.exists("/config.json")) {
            Serial.println("[CONFIG] Timeout - using existing config");
            return false;
        }
    }
    
    Serial.println("\n==================================================");
    Serial.println("=== INITIAL CONFIGURATION MODE ===");
    Serial.println("==================================================");
    Serial.println("Send JSON config or timeout in 30s...");
    Serial.println("Format: CONFIG:{json}");
    Serial.flush();
    
    unsigned long startWait = millis();
    String configBuffer = "";
    bool receivingConfig = false;
    
    while (millis() - startWait < 30000) {
        if (Serial.available()) {
            String line = Serial.readStringUntil('\n');
            line.trim();
            
            if (line.startsWith("CONFIG:")) {
                configBuffer = line.substring(7);
                receivingConfig = true;
                break;
            } else if (line == "SKIP") {
                Serial.println("[CONFIG] Skipped - using defaults");
                return false;
            }
        }
        delay(100);
    }
    
    if (!receivingConfig || configBuffer.length() < 10) {
        Serial.println("[CONFIG] Timeout - using defaults");
        return false;
    }
    
    Serial.println("[CONFIG] Received config, validating...");
    
    DynamicJsonDocument doc(2048);
    DeserializationError error = deserializeJson(doc, configBuffer);
    
    if (error) {
        Serial.println("[CONFIG] Invalid JSON: " + String(error.c_str()));
        return false;
    }
    
    File configFile = SD.open("/config.json", FILE_WRITE);
    if (!configFile) {
        Serial.println("[CONFIG] Failed to create config file");
        return false;
    }
    
    configFile.print(configBuffer);
    configFile.close();
    
    Serial.println("[CONFIG] Configuration saved to SD card!");
    Serial.println("[CONFIG] Rebooting in 2 seconds...");
    Serial.flush();
    delay(2000);
    
    ESP.restart();
    return true;
}

String getDiagnostics() {
    static unsigned long lastDiagTime = 0;
    static unsigned long lastSDTime = 0;
    static String cachedDiag = "";
    static String cachedSDInfo = "";
    
    if (millis() - lastDiagTime < 3000 && cachedDiag.length() > 0) {
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
        if (rtcSynced) {
            s += "Synced";
        } else {
            if (gpsValid) {
                s += "Not synced (waiting)";
            } else {
                s += "Not synced (no GPS)";
            }
        }
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
    s += "ESP32 Temp: " + String(temp_c, 1) + "C / " + String(temp_f, 1) + "F\n";
    
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
        uint64_t cardSize = SD.cardSize() / (1024 * 1024);
        Serial.printf("SD Card initialized: %lluMB\n", cardSize);
        sdAvailable = true;
        SafeSD::forceRecheck();
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
    delay(500);
    unsigned long start = millis();
    bool sawSentence = false;
    while (millis() - start < 4000) {
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
    startupMsg += "TEMP: " + String(temp_c, 1) + "C / " + String(temp_f, 1) + "F\n";
    // startupMsg += " SD:";
    // startupMsg += (sdAvailable ? "OK" : "FAIL");
    // startupMsg += " Status:ONLINE";
    
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
    if (!SafeSD::isAvailable()) return;
    
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
    
    if (!SafeSD::exists("/")) {
        SafeSD::mkdir("/");
    }

    if (!logFile || totalWrites % 50 == 0) {
        if (logFile) {
            logFile.close();
        }
        logFile = SafeSD::open("/antihunter.log", FILE_APPEND);
        if (!logFile) {
            logFile = SafeSD::open("/antihunter.log", FILE_WRITE);
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
        File checkFile = SafeSD::open("/antihunter.log", FILE_READ);
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
        
        if (millis() - lastVibrationAlert > VIBRATION_ALERT_INTERVAL) {
            lastVibrationAlert = millis();
            
            String timestamp = getFormattedTimestamp();
            int sensorValue = digitalRead(VIBRATION_PIN);
            
            String vibrationMsg = getNodeId() + ": VIBRATION: Movement detected at " + timestamp;
            
            if (gpsValid) {
                vibrationMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }
            
            if (tamperEraseActive) {
                uint32_t timeLeft = (autoEraseDelay - (millis() - tamperSequenceStart)) / 1000;
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
    
    Serial.printf("[TAMPER] Device movement detected - auto-erase in %us\n", autoEraseDelay/1000);
    
    String alertMsg = getNodeId() + ": TAMPER_DETECTED: Auto-erase in " + String(autoEraseDelay/1000) + "s";
    if (gpsValid) {
        alertMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    sendToSerial1(alertMsg, false);
    
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
    
    if (elapsed >= autoEraseDelay) {
        Serial.println("[TAMPER] Timeout - executing erase");
        return executeSecureErase("Tamper timeout");
    }
    
    return false;
}

bool executeSecureErase(const String &reason) {
    eraseStatus = "EXECUTING";
    eraseInProgress = true;
    
    Serial.println("EXECUTING SECURE ERASE: " + reason);
    
    if (!SafeSD::isAvailable()) {
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
    
    // Close and erase NVS
    prefs.end();
    delay(100);
    
    esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        Serial.printf("[WIPE] NVS erase failed: %d\n", err);
        return false;
    }
    
    err = nvs_flash_init();
    if (err != ESP_OK) {
        Serial.printf("[WIPE] NVS init failed: %d\n", err);
        return false;
    }
    
    Serial.println("[WIPE] NVS cleared");
    
    // Clear SD card
    deleteAllFiles("/");
    
    File marker = SafeSD::open("/weather-air-feed.txt", FILE_WRITE);
    if (marker) {
        marker.println("AntiHunter Weather Monitor and AQ data could not be sent to your network. Check your API key and settings or contact support.");
        marker.close();
    
        if (SafeSD::exists("/weather-air-feed.txt")) {
            Serial.println("[WIPE] Marker file created - wipe completed");
            return true;
        } else {
            Serial.println("[WIPE] Marker file creation failed");
            return false;
        }
    } else {
        Serial.println("[WIPE] Failed to create marker file");
        return false;
    }
}

void deleteAllFiles(const String &dirname) {
    File root = SafeSD::open(dirname.c_str());
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
            if (SafeSD::rmdir(fullPath.c_str())) {
                Serial.println("[WIPE] Removed directory: " + fullPath);
            } else {
                Serial.println("[WIPE] Failed to remove directory: " + fullPath);
            }
        } else {
            // Remove the file
            if (SafeSD::remove(fullPath.c_str())) {
                Serial.println("[WIPE] Removed file: " + fullPath);
            } else {
                Serial.println("[WIPE] Failed to remove file: " + fullPath);
            }
        }
        
        file = root.openNextFile();
    }
    
    root.close();
}
