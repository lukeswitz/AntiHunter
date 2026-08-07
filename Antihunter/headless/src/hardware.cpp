#include "hardware.h"
#include "network.h"
#include "baseline.h"
#include "detect.h"
#include <Arduino.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>
#include "esp_system.h"
#include "esp_heap_caps.h"
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include "esp_wifi.h"
#include "mbedtls/md.h"
#include "nvs_flash.h"
#include "esp_pm.h"
#include "esp_sleep.h"
#include "esp_bt.h"
#include "esp_system.h"
#include "driver/gpio.h"

extern Preferences prefs;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern void disciplineRTCFromGPS();

// Preferences::getString() log_e()s on a missing key; gate it so optional keys stay quiet
String prefsGetString(const char *key, const String &defaultValue) {
    if (!prefs.isKey(key)) return defaultValue;
    return prefs.getString(key, defaultValue);
}

// GPS
TinyGPSPlus gps;
#ifdef ARDUINO_XIAO_ESP32C5
HardwareSerial GPS(0);
#else
HardwareSerial GPS(2);
#endif
bool sdAvailable = false;
String lastGPSData = "No GPS data";
float gpsLat = 0.0, gpsLon = 0.0;
static const uint32_t GPS_FIX_MAX_AGE_MS = 20000;
std::atomic<bool> gpsValid{false};
SemaphoreHandle_t gpsMutex = nullptr;
extern bool hbEnabled;
extern uint32_t hbInterval;

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

bool vibAutoScanEnabled = false;
uint8_t vibAutoScanMode = 0;
uint16_t vibAutoScanDuration = 60;
uint32_t vibAutoScanCooldownMs = 60000;
volatile bool vibAutoScanPending = false;
unsigned long lastVibAutoScanFire = 0;

// Diagnostics & Config
extern std::atomic<bool> scanning;
extern std::atomic<int> totalHits;
extern std::atomic<uint32_t> framesSeen;
extern std::atomic<uint32_t> bleFramesSeen;
extern UniqueMacsSet uniqueMacs;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern String macFmt6(const uint8_t *m);
extern size_t getTargetCount();
extern TaskHandle_t blueTeamTaskHandle;
extern TaskHandle_t workerTaskHandle;
extern std::atomic<bool> triangulationActive;
uint32_t SafeSD::lastCheckTime = 0;
bool SafeSD::lastCheckResult = false;
unsigned long lastSaveTime = 0;
const unsigned long SAVE_DEBOUNCE_MS = 2000;

// Tamper Detection Erase
uint32_t setupDelay = 120000;  // 2 minutes default
uint32_t setupStartTime = 0;
bool inSetupMode = false;
bool tamperEraseActive = false;
uint32_t tamperSequenceStart = 0;
String tamperAuthToken = "";
String erasePSK = "";
bool autoEraseEnabled = false;
uint32_t autoEraseDelay = 30000;
uint32_t autoEraseCooldown = 300000;  // 5 minutes default
static uint32_t lastAutoEraseAttempt = 0;
uint32_t vibrationsRequired = 3;
uint32_t detectionWindow = 20000;
String eraseStatus = "INACTIVE";
bool eraseInProgress = false;

// Battery Saver Mode
bool batterySaverEnabled = false;
uint32_t batterySaverHeartbeatInterval = 300000;  // 5 minutes default
uint32_t lastBatterySaverHeartbeat = 0;

// SD & HW Init

bool SafeSD::checkAvailability() {
    static std::mutex sdCheckMutex;
    std::lock_guard<std::mutex> lock(sdCheckMutex);
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

bool SafeSD::rename(const char* from, const char* to) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot rename %s - SD unavailable\n", from);
        return false;
    }

    SD.remove(to);
    bool result = SD.rename(from, to);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to rename %s -> %s\n", from, to);
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

String jsonEscape(const String &in) {
    String out;
    out.reserve(in.length() + 16);
    for (size_t i = 0; i < in.length(); i++) {
        char c = in[i];
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if ((uint8_t)c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", (uint8_t)c);
                    out += esc;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Node ID = 2-5 alphanumeric (A-Z, 0-9), same rule as /node-id and CONFIG_NODEID.
String sanitizeNodeId(String nodeId) {
    nodeId.toUpperCase();

    String result;
    for (size_t i = 0; i < nodeId.length() && result.length() < 5; i++) {
        if (isalnum(nodeId[i])) {
            result += nodeId[i];
        } else {
            Serial.printf("[SANITIZE] Dropping non-alphanumeric char '%c' at position %d\n", nodeId[i], i);
        }
    }

    if (result.length() < 2) {
        char buffer[10];
        sprintf(buffer, "AH%02d", (int)random(10, 100));
        Serial.printf("[SANITIZE] '%s' left too little to use, generating %s\n", nodeId.c_str(), buffer);
        result = buffer;
    }

    return result;
}

void initializeHardware()
{
    Serial.println("Loading preferences...");
    
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        Serial.println("[NVS] Erasing corrupted NVS");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    
    if (err != ESP_OK) {
        Serial.printf("[NVS] Init failed: 0x%x (%s) - attempting recovery\n", err, esp_err_to_name(err));
        
        esp_err_t erase_err = nvs_flash_erase();
        if (erase_err == ESP_OK) {
            err = nvs_flash_init();
            if (err == ESP_OK) {
                Serial.println("[NVS] Recovery successful");
            }
        }
        
        if (err != ESP_OK) {
            // halt with diagnostics
            Serial.printf("[NVS] FATAL: Cannot initialize NVS: 0x%x (%s)\n", err, esp_err_to_name(err));
            Serial.println("[NVS] Device requires factory reset via esptool");
            while(1) { delay(5000); Serial.printf("[NVS] HALTED: Error 0x%x\n", err); }
        }
    }
    
    if (!prefs.begin("antihunter", false)) {
        // Single recovery try, then halt
        Serial.println("[NVS] Cannot open namespace - attempting recovery");
        prefs.end();
        delay(100);
        
        esp_err_t erase_err = nvs_flash_erase();
        if (erase_err == ESP_OK) {
            nvs_flash_init();
        }
        
        if (!prefs.begin("antihunter", false)) {
            // HALT - avoid restart loop
            Serial.println("[NVS] FATAL: Cannot open namespace after recovery");
            while(1) { delay(5000); Serial.println("[NVS] HALTED: Namespace failure"); }
        }
        Serial.println("[NVS] Namespace recovered successfully");
    }

    
    if (!prefs.isKey("_init")) {
        Serial.println("[NVS] First boot - initializing all NVS keys");
        prefs.putBool("_init", true);
        prefs.putString("maclist", "");
        prefs.putString("allowlist", "");
        prefs.putString("nodeId", "");
        prefs.putString("channels", "1,2,3,4,5,6,7,8,9,10,11");
        prefs.putUInt("bandMode", DEFAULT_BAND_MODE);
        prefs.putInt("scanMode", SCAN_BOTH);
        prefs.putULong("meshInterval", 5000);
        prefs.putUInt("blRamSize", 400);
        prefs.putUInt("blSdMax", 50000);
        prefs.putUInt("absenceThresh", 120000);
        prefs.putUInt("reappearWin", 300000);
        prefs.putInt("rssiChange", 20);
        prefs.putBool("autoErase", false);
        prefs.putUInt("eraseDelay", 30000);
        prefs.putUInt("eraseCooldown", 300000);
        prefs.putUInt("vibRequired", 3);
        prefs.putUInt("detectWindow", 20000);
        prefs.putUInt("setupDelay", 120000);
        prefs.putUInt("blDuration", 300000);
        prefs.putInt("blRssi", -70);
        prefs.putUInt("rfPreset", 1);
        prefs.putInt("globalRSSI", -95);
        prefs.putUInt("wifiChanTime", 160);
        prefs.putUInt("wifiInterval", 3000);
        prefs.putUInt("bleInterval", 4000);
        prefs.putUInt("bleDuration", 2000);
        prefs.putBool("vibScanEn", false);
        prefs.putUChar("vibScanMode", 0);
        prefs.putUShort("vibScanDur", 60);
        prefs.putUInt("vibScanCd", 60000);
    }
    
    randomSeed(esp_random());
    loadRFConfigFromPrefs();
    
    meshSendInterval = prefs.getULong("meshInterval", 3000);
    if (meshSendInterval < 1500 || meshSendInterval > 60000) {
        meshSendInterval = 3000;
    }
    Serial.printf("[CONFIG] Mesh send interval: %lums\n", meshSendInterval);

    {
        uint32_t ttl = prefs.getUInt("meshDedupTtl", MESH_DEDUP_TTL_DEFAULT_S);
        if (ttl > MESH_DEDUP_TTL_MAX_S) ttl = MESH_DEDUP_TTL_DEFAULT_S;
        setMeshDedupTtlSec(ttl);
        Serial.printf("[CONFIG] Mesh dedup TTL: %us (0=disabled)\n", (unsigned)ttl);
    }
    setMeshSessionDedup(prefs.getBool("meshSessDedup", false));
    
    baselineRamCacheSize = prefs.getUInt("baselineRamSize", 400);
    baselineSdMaxDevices = prefs.getUInt("baselineSdMax", 50000);
    deviceAbsenceThreshold = prefs.getUInt("absenceThresh", 120000);
    reappearanceAlertWindow = prefs.getUInt("reappearWin", 300000);
    significantRssiChange = prefs.getInt("rssiChange", 20);
    
    String nodeId = prefsGetString("nodeId", "");
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
    // Use a static buffer to avoid heap fragmentation
    static char channelsBuf[128];
    channelsBuf[0] = '\0';

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
    prefs.putUInt("rfPreset", rfConfig.preset);
    prefs.putUInt("bandMode", rfConfig.bandMode);
    prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
    prefs.putUInt("wifiChanTime", rfConfig.wifiChannelTime);
    prefs.putUInt("wifiInterval", rfConfig.wifiScanInterval);
    prefs.putUInt("bleInterval", rfConfig.bleScanInterval);
    prefs.putUInt("bleDuration", rfConfig.bleScanDuration);
    prefs.putBool("hbEnabled", hbEnabled);
    prefs.putUInt("hbInterval", hbInterval);
    prefs.putBool("vibEnabled", vibrationEnabled);
    prefs.putBool("vibScanEn", vibAutoScanEnabled);
    prefs.putUChar("vibScanMode", vibAutoScanMode);
    prefs.putUShort("vibScanDur", vibAutoScanDuration);
    prefs.putUInt("vibScanCd", vibAutoScanCooldownMs);

    int offset = 0;
    for (size_t i = 0; i < CHANNELS.size() && offset < 120; i++) {
        offset += snprintf(channelsBuf + offset, sizeof(channelsBuf) - offset,
                          "%d%s", CHANNELS[i], (i < CHANNELS.size() - 1) ? "," : "");
    }
    prefs.putString("channels", channelsBuf);

    vTaskDelay(pdMS_TO_TICKS(50));
    Serial.println("[NVS] Settings synced to flash");
}

// FNV-1a hash over every value saveConfiguration persists. Lets saveConfiguration
// skip the NVS+SD write (and its serial log) when nothing actually changed —
// callers can invoke it freely without churning flash or spamming the console.
static uint32_t configSignature() {
    uint32_t h = 2166136261u;
    auto mix = [&](const void *p, size_t n) {
        const uint8_t *b = static_cast<const uint8_t *>(p);
        for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 16777619u; }
    };
    auto mixStr = [&](const String &s) { mix(s.c_str(), s.length()); h ^= 0x5a; h *= 16777619u; };

    mixStr(prefsGetString("nodeId", ""));
    int sm = currentScanMode; mix(&sm, sizeof(sm));
    for (size_t i = 0; i < CHANNELS.size(); i++) { int c = CHANNELS[i]; mix(&c, sizeof(c)); }
    mix(&meshSendInterval, sizeof(meshSendInterval));
    uint32_t u;
    u = getMeshDedupTtlSec();          mix(&u, 4);
    { bool b = getMeshSessionDedup(); mix(&b, 1); }
    mix(&autoEraseEnabled, 1);
    mix(&autoEraseDelay, 4); mix(&autoEraseCooldown, 4);
    mix(&vibrationsRequired, sizeof(vibrationsRequired));
    mix(&detectionWindow, sizeof(detectionWindow));
    mix(&setupDelay, sizeof(setupDelay));
    u = getBaselineRamCacheSize();     mix(&u, 4);
    u = getBaselineSdMaxDevices();     mix(&u, 4);
    int8_t i8;
    i8 = getBaselineRssiThreshold();   mix(&i8, 1);
    mix(&baselineDuration, sizeof(baselineDuration));
    u = getDeviceAbsenceThreshold();   mix(&u, 4);
    u = getReappearanceAlertWindow();  mix(&u, 4);
    i8 = getSignificantRssiChange();   mix(&i8, 1);
    mix(&rfConfig.preset, sizeof(rfConfig.preset));
    mix(&rfConfig.bandMode, sizeof(rfConfig.bandMode));
    mix(&rfConfig.wifiChannelTime, sizeof(rfConfig.wifiChannelTime));
    mix(&rfConfig.wifiScanInterval, sizeof(rfConfig.wifiScanInterval));
    mix(&rfConfig.bleScanInterval, sizeof(rfConfig.bleScanInterval));
    mix(&rfConfig.bleScanDuration, sizeof(rfConfig.bleScanDuration));
    mix(&rfConfig.globalRssiThreshold, sizeof(rfConfig.globalRssiThreshold));
    mixStr(prefsGetString("maclist", ""));
    mix(&hbEnabled, 1);
    mix(&hbInterval, sizeof(hbInterval));
    mix(&vibrationEnabled, 1);
    mix(&vibAutoScanEnabled, 1);
    mix(&vibAutoScanMode, sizeof(vibAutoScanMode));
    mix(&vibAutoScanDuration, sizeof(vibAutoScanDuration));
    mix(&vibAutoScanCooldownMs, sizeof(vibAutoScanCooldownMs));
    return h;
}

static bool commitConfigFile() {
    File verify = SafeSD::open(CONFIG_TMP_FILE, FILE_READ);
    size_t written = verify ? verify.size() : 0;
    if (verify) verify.close();

    if (written == 0) {
        Serial.println("[CONFIG] ERROR: staged config is empty - previous config kept");
        SafeSD::remove(CONFIG_TMP_FILE);
        return false;
    }

    bool hadConfig = SafeSD::exists(CONFIG_FILE);
    if (hadConfig) {
        SafeSD::rename(CONFIG_FILE, CONFIG_BAK_FILE);
    }

    if (!SafeSD::rename(CONFIG_TMP_FILE, CONFIG_FILE)) {
        Serial.println("[CONFIG] ERROR: failed to commit config - restoring previous");
        if (hadConfig) {
            SafeSD::rename(CONFIG_BAK_FILE, CONFIG_FILE);
        }
        SafeSD::remove(CONFIG_TMP_FILE);
        return false;
    }
    return true;
}

void saveConfiguration() {
    uint32_t now = millis();
    if (now - lastSaveTime < SAVE_DEBOUNCE_MS) {
        return;
    }

    // Only persist when the config actually changed — avoids constant NVS/SD
    // rewrites (flash wear + log spam) from periodic/no-op callers.
    static uint32_t lastCfgSig = 0;
    static bool haveCfgSig = false;
    uint32_t sig = configSignature();
    if (haveCfgSig && sig == lastCfgSig) {
        return;
    }
    haveCfgSig = true;
    lastCfgSig = sig;
    lastSaveTime = now;

    syncSettingsToNVS();
    vTaskDelay(pdMS_TO_TICKS(200));

    if (!SafeSD::isAvailable()) {
        Serial.println("[CONFIG] Settings saved to NVS only (SD unavailable)");
        return;
    }

    File configFile = SafeSD::open(CONFIG_TMP_FILE, FILE_WRITE);
    if (!configFile) {
        Serial.println("[CONFIG] ERROR: Failed to open config file for writing!");
        return;
    }

    static char channelsBuf[128];
    int offset = 0;
    for (size_t i = 0; i < CHANNELS.size() && offset < 120; i++) {
        offset += snprintf(channelsBuf + offset, sizeof(channelsBuf) - offset,
                          "%d%s", CHANNELS[i], (i < CHANNELS.size() - 1) ? "," : "");
    }

    configFile.println("{");
    configFile.printf(" \"nodeId\":\"%s\",\n", jsonEscape(prefsGetString("nodeId", "")).c_str());
    configFile.printf(" \"scanMode\":%d,\n", currentScanMode);
    configFile.printf(" \"channels\":\"%s\",\n", jsonEscape(channelsBuf).c_str());
    configFile.printf(" \"bandMode\":%u,\n", rfConfig.bandMode);
    configFile.printf(" \"meshInterval\":%lu,\n", meshSendInterval);
    configFile.printf(" \"meshDedupTtl\":%u,\n", (unsigned)getMeshDedupTtlSec());
    configFile.printf(" \"meshSessDedup\":%s,\n", getMeshSessionDedup() ? "true" : "false");
    configFile.printf(" \"autoEraseEnabled\":%s,\n", autoEraseEnabled ? "true" : "false");
    configFile.printf(" \"autoEraseDelay\":%u,\n", autoEraseDelay);
    configFile.printf(" \"autoEraseCooldown\":%u,\n", autoEraseCooldown);
    configFile.printf(" \"vibrationsRequired\":%u,\n", vibrationsRequired);
    configFile.printf(" \"detectionWindow\":%u,\n", detectionWindow);
    configFile.printf(" \"setupDelay\":%u,\n", setupDelay);
    configFile.printf(" \"baselineRamSize\":%u,\n", getBaselineRamCacheSize());
    configFile.printf(" \"baselineSdMax\":%u,\n", getBaselineSdMaxDevices());
    configFile.printf(" \"baselineRssiThreshold\":%d,\n", getBaselineRssiThreshold());
    configFile.printf(" \"baselineDuration\":%u,\n", baselineDuration / 1000);
    configFile.printf(" \"absenceThreshold\":%u,\n", getDeviceAbsenceThreshold() / 1000);
    configFile.printf(" \"reappearanceWindow\":%u,\n", getReappearanceAlertWindow() / 1000);
    configFile.printf(" \"rssiChangeDelta\":%d,\n", getSignificantRssiChange());
    configFile.printf(" \"rfPreset\":%u,\n", rfConfig.preset);
    configFile.printf(" \"wifiChannelTime\":%u,\n", rfConfig.wifiChannelTime);
    configFile.printf(" \"wifiScanInterval\":%u,\n", rfConfig.wifiScanInterval);
    configFile.printf(" \"bleScanInterval\":%u,\n", rfConfig.bleScanInterval);
    configFile.printf(" \"bleScanDuration\":%u,\n", rfConfig.bleScanDuration);
    configFile.printf(" \"globalRssiThreshold\":%d,\n", rfConfig.globalRssiThreshold);
    configFile.printf(" \"targets\":\"%s\",\n", jsonEscape(prefsGetString("maclist", "")).c_str());
    configFile.printf(" \"hbEnabled\":%s,\n", hbEnabled ? "true" : "false");
    configFile.printf(" \"hbInterval\":%u,\n", hbInterval / 60000);
    configFile.printf(" \"vibEnabled\":%s,\n", vibrationEnabled ? "true" : "false");
    configFile.printf(" \"vibScanEnabled\":%s,\n", vibAutoScanEnabled ? "true" : "false");
    configFile.printf(" \"vibScanMode\":%u,\n", vibAutoScanMode);
    configFile.printf(" \"vibScanDuration\":%u,\n", vibAutoScanDuration);
    configFile.printf(" \"vibScanCooldown\":%u\n", vibAutoScanCooldownMs);
    configFile.println("}");

    configFile.flush();
    configFile.close();

    if (!commitConfigFile()) {
        return;
    }

    Serial.println("[CONFIG] Configuration saved to NVS and SD card");
}

void loadConfiguration() {
    if (!SafeSD::isAvailable()) {
        Serial.println("SD card not available, loading from NVS only");
        currentScanMode = (ScanMode)prefs.getInt("scanMode", SCAN_BOTH);
        meshSendInterval = prefs.getULong("meshInterval", 5000);
        autoEraseEnabled = prefs.getBool("autoErase", false);
        erasePSK = prefsGetString("erasePSK", "");
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
        hbEnabled = prefs.getBool("hbEnabled", false);
        hbInterval = prefs.getUInt("hbInterval", 600000);
        vibrationEnabled = prefs.getBool("vibEnabled", true);
        vibAutoScanEnabled = prefs.getBool("vibScanEn", false);
        vibAutoScanMode = prefs.getUChar("vibScanMode", 0);
        vibAutoScanDuration = prefs.getUShort("vibScanDur", 60);
        vibAutoScanCooldownMs = prefs.getUInt("vibScanCd", 60000);
        return;
    }

    const char *configPath = CONFIG_FILE;
    if (!SafeSD::exists(CONFIG_FILE)) {
        if (SafeSD::exists(CONFIG_BAK_FILE)) {
            configPath = CONFIG_BAK_FILE;
        } else if (SafeSD::exists(CONFIG_TMP_FILE)) {
            configPath = CONFIG_TMP_FILE;
        } else {
            Serial.println("No config file found on SD card, using NVS defaults");
            return;
        }
        Serial.printf("[CONFIG] %s missing - recovering from %s\n", CONFIG_FILE, configPath);
    }

    File configFile = SafeSD::open(configPath, FILE_READ);
    if (!configFile) {
        Serial.println("Failed to open config file!");
        return;
    }

    String config = configFile.readString();
    configFile.close();

    config.replace(",\n}", "\n}");
    config.replace(",}", "}");

    // Try to fix common corruption issues
    config.trim();
    if (config.endsWith(",")) {
        config = config.substring(0, config.length() - 1);
    }
    if (!config.endsWith("}")) {
        config += "}";
    }

    size_t capacity = config.length() * 2 + 1024;
    if (capacity < MAX_CONFIG_SIZE) capacity = MAX_CONFIG_SIZE;
    if (capacity > 32768) capacity = 32768;

    DynamicJsonDocument doc(capacity);
    DeserializationError error = deserializeJson(doc, config);

    if (error) {
        Serial.println("Failed to parse config file: " + String(error.c_str()));
        SafeSD::remove(CONFIG_BAD_FILE);
        File badFile = SafeSD::open(CONFIG_BAD_FILE, FILE_WRITE);
        if (badFile) {
            badFile.print(config);
            badFile.close();
        }
        Serial.printf("[CONFIG] Unparseable copy saved as %s - original kept, using NVS values\n", CONFIG_BAD_FILE);
        return;
    }

    if (strcmp(configPath, CONFIG_FILE) != 0 && SafeSD::rename(configPath, CONFIG_FILE)) {
        Serial.printf("[CONFIG] Restored %s from %s\n", CONFIG_FILE, configPath);
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
                            doc["channels"].as<String>() : "1..11";
            int8_t rssiThreshold = doc["globalRssiThreshold"] | -95;
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

    if (doc.containsKey("bandMode")) {
        setBandMode((uint8_t)doc["bandMode"].as<int>());
        Serial.printf("Loaded bandMode from SD: %u\n", rfConfig.bandMode);
    }

    if (doc.containsKey("meshInterval") && doc["meshInterval"].is<unsigned long>()) {
        unsigned long interval = doc["meshInterval"].as<unsigned long>();
        if (interval >= 500 && interval <= 30000) {
            meshSendInterval = interval;
            prefs.putULong("meshInterval", interval);
            Serial.printf("Loaded meshInterval from SD: %lums\n", interval);
        }
    }

    if (doc.containsKey("meshDedupTtl") && doc["meshDedupTtl"].is<unsigned int>()) {
        unsigned int ttl = doc["meshDedupTtl"].as<unsigned int>();
        if (ttl <= MESH_DEDUP_TTL_MAX_S) {
            setMeshDedupTtlSec(ttl);
            prefs.putUInt("meshDedupTtl", ttl);
            Serial.printf("Loaded meshDedupTtl from SD: %us\n", ttl);
        }
    }

    if (doc.containsKey("meshSessDedup") && doc["meshSessDedup"].is<bool>()) {
        bool sd = doc["meshSessDedup"].as<bool>();
        setMeshSessionDedup(sd);
        prefs.putBool("meshSessDedup", sd);
        Serial.printf("Loaded meshSessDedup from SD: %s\n", sd ? "ON" : "OFF");
    }

    if (doc.containsKey("targets") && doc["targets"].is<String>()) {
        String targets = doc["targets"].as<String>();
        if (targets.length() > 0) {
            saveTargetsList(targets);
            prefs.putString("maclist", targets);
            Serial.println("Target count: " + String(getTargetCount()));
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
        uint32_t duration = doc["baselineDuration"].as<uint32_t>() * 1000;
        // Minimum 60 seconds to prevent rapid cycling and message flooding
        if (duration < 60000) {
            Serial.println("[CONFIG] Warning: baselineDuration too short, using 60s minimum");
            duration = 60000;
        }
        baselineDuration = duration;
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

    if (doc.containsKey("hbEnabled")) {
        hbEnabled = doc["hbEnabled"].as<bool>();
        prefs.putBool("hbEnabled", hbEnabled);
    }

    if (doc.containsKey("hbInterval")) {
        uint32_t minutes = doc["hbInterval"].as<uint32_t>();
        if (minutes < 1) minutes = 1;
        if (minutes > 60) minutes = 60;
        hbInterval = minutes * 60000;
        prefs.putUInt("hbInterval", hbInterval);
    }

    if (doc.containsKey("vibEnabled")) {
        vibrationEnabled = doc["vibEnabled"].as<bool>();
        prefs.putBool("vibEnabled", vibrationEnabled);
    }

    if (doc.containsKey("vibScanEnabled")) {
        vibAutoScanEnabled = doc["vibScanEnabled"].as<bool>();
        prefs.putBool("vibScanEn", vibAutoScanEnabled);
    }

    if (doc.containsKey("vibScanMode")) {
        vibAutoScanMode = doc["vibScanMode"].as<uint8_t>();
        prefs.putUChar("vibScanMode", vibAutoScanMode);
    }

    if (doc.containsKey("vibScanDuration")) {
        vibAutoScanDuration = doc["vibScanDuration"].as<uint16_t>();
        prefs.putUShort("vibScanDur", vibAutoScanDuration);
    }

    if (doc.containsKey("vibScanCooldown")) {
        vibAutoScanCooldownMs = doc["vibScanCooldown"].as<uint32_t>();
        prefs.putUInt("vibScanCd", vibAutoScanCooldownMs);
    }

    if (doc.containsKey("sentinelBoot")) {
        bool sb = doc["sentinelBoot"].as<bool>();
        prefs.putBool("sentBoot", sb);
        Serial.printf("[CONFIG] sentinelBoot=%s\n", sb ? "on" : "off");
    }

    if (doc.containsKey("detectors") && doc["detectors"].is<JsonObject>()) {
        String dj;
        serializeJson(doc["detectors"], dj);
        detect_setConfigFromJson(dj);
        detect_persistTunables();
        Serial.println("[CONFIG] Detector/sentinel config applied + persisted");
    }

    Serial.println("Configuration loaded from SD card and synced to NVS");
}

bool waitForInitialConfig() {
    if (!sdAvailable) {
        Serial.println("[CONFIG] SD card not available, skipping initial config");
        return false;
    }
    
    // Check if config exists
    bool configExists = SD.exists(CONFIG_FILE);

    if (configExists) {
        bool reconfigRequested = false;
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
                    reconfigRequested = true;
                    break;
                } else {
                    Serial.println("[CONFIG] Skipped - using existing config");
                    return false;
                }
            }
            delay(100);
        }

        if (!reconfigRequested) {
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
        // cppcheck-suppress knownConditionTrueFalse
        Serial.println(configExists ? "[CONFIG] Timeout - keeping existing config"
                                    : "[CONFIG] Timeout - using defaults");
        return false;
    }
    
    Serial.println("[CONFIG] Received config, validating...");
    
    DynamicJsonDocument doc(4096);
    DeserializationError error = deserializeJson(doc, configBuffer);
    
    if (error) {
        Serial.println("[CONFIG] Invalid JSON: " + String(error.c_str()));
        return false;
    }
    
    DynamicJsonDocument merged(16384);
    bool haveBase = false;
    if (SafeSD::exists(CONFIG_FILE)) {
        File base = SafeSD::open(CONFIG_FILE, FILE_READ);
        if (base) {
            String baseText = base.readString();
            base.close();
            if (deserializeJson(merged, baseText) == DeserializationError::Ok && merged.is<JsonObject>()) {
                haveBase = true;
            } else {
                merged.clear();
                Serial.println("[CONFIG] Existing config unreadable - writing pushed fields only");
            }
        }
    }

    uint16_t pushed = 0;
    for (JsonPair kv : doc.as<JsonObject>()) {
        merged[kv.key()] = kv.value();
        pushed++;
    }

    String out;
    serializeJson(merged, out);

    File configFile = SafeSD::open(CONFIG_TMP_FILE, FILE_WRITE);
    if (!configFile) {
        Serial.println("[CONFIG] Failed to create config file");
        return false;
    }

    configFile.print(out);
    configFile.flush();
    configFile.close();

    if (!commitConfigFile()) {
        return false;
    }

    Serial.printf("[CONFIG] %u field(s) %s\n", pushed, haveBase ? "merged into existing config" : "written");
    Serial.println("[CONFIG] Configuration saved to SD card!");
    Serial.println("[CONFIG] Rebooting in 2 seconds...");
    Serial.flush();
    delay(2000);
    
    ESP.restart();
    return true;
}

#if CONFIG_IDF_TARGET_ESP32C5
#include "esp_private/periph_ctrl.h"
#include "hal/spi_ll.h"
#include "hal/spi_types.h"
#include "soc/periph_defs.h"

// arduino-esp32 spiStartBus() has no C5 branch, so SPI2 stays clock-gated and every transfer reads 0x00
static void spi2EnsureBusClock() {
    static bool done = false;
    if (done) return;
    done = true;
    PERIPH_RCC_ACQUIRE_ATOMIC(PERIPH_GPSPI2_MODULE, ref_count) {
        if (ref_count == 0) {
            spi_ll_enable_bus_clock(SPI2_HOST, true);
            spi_ll_reset_register(SPI2_HOST);
            spi_ll_enable_clock(SPI2_HOST, true);
        }
    }
    Serial.println("[SD] C5: SPI2 bus clock ungated");
}
#else
static void spi2EnsureBusClock() {}
#endif

#ifndef AH_SD_DIAG
#define AH_SD_DIAG 0
#endif

#if AH_SD_DIAG

static const int SDDIAG_ROLE_PINS[4] = {SD_CLK_PIN, SD_MOSI_PIN, SD_MISO_PIN, SD_CS_PIN};
static const char *SDDIAG_ROLE_NAMES[4] = {"SCK", "MOSI", "MISO", "CS"};

#ifdef ARDUINO_XIAO_ESP32C5
static const int SDDIAG_PADS[11] = {1, 0, 25, 7, 23, 24, 11, 12, 8, 9, 10};
#else
static const int SDDIAG_PADS[11] = {1, 2, 3, 4, 5, 6, 43, 44, 7, 8, 9};
#endif
static const char *SDDIAG_PAD_NAMES[11] = {"D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"};
static const int SDDIAG_PAD_COUNT = 11;

static int sdd_sck = -1, sdd_mosi = -1, sdd_miso = -1, sdd_cs = -1;
static int sdd_halfUs = 3;

static void sddPin(int pin, gpio_mode_t mode, bool pullup, bool pulldown) {
    gpio_config_t cfg = {};
    cfg.pin_bit_mask = 1ULL << (uint32_t)pin;
    cfg.mode = mode;
    cfg.pull_up_en = pullup ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = pulldown ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&cfg);
}

static const char *sddPadName(int gpio) {
    for (int i = 0; i < SDDIAG_PAD_COUNT; i++)
        if (SDDIAG_PADS[i] == gpio) return SDDIAG_PAD_NAMES[i];
    return "--";
}

static uint8_t sddXfer(uint8_t out) {
    uint8_t in = 0;
    for (int b = 7; b >= 0; b--) {
        gpio_set_level((gpio_num_t)sdd_mosi, (out >> b) & 1);
        delayMicroseconds(sdd_halfUs);
        gpio_set_level((gpio_num_t)sdd_sck, 1);
        delayMicroseconds(sdd_halfUs);
        in = (uint8_t)((in << 1) | (uint8_t)gpio_get_level((gpio_num_t)sdd_miso));
        gpio_set_level((gpio_num_t)sdd_sck, 0);
    }
    return in;
}

static void sddBusAttach(int sck, int mosi, int miso, int cs, bool openDrain, int halfUs) {
    sdd_sck = sck; sdd_mosi = mosi; sdd_miso = miso; sdd_cs = cs; sdd_halfUs = halfUs;
    gpio_mode_t om = openDrain ? GPIO_MODE_OUTPUT_OD : GPIO_MODE_OUTPUT;
    sddPin(sck, om, openDrain, false);
    sddPin(mosi, om, openDrain, false);
    sddPin(cs, om, openDrain, false);
    sddPin(miso, GPIO_MODE_INPUT, true, false);
    gpio_set_level((gpio_num_t)cs, 1);
    gpio_set_level((gpio_num_t)mosi, 1);
    gpio_set_level((gpio_num_t)sck, 0);
}

static uint8_t sddCmd(uint8_t cmd, uint32_t arg, uint8_t crc, uint8_t *tail, int tailLen) {
    sddXfer(0xFF);
    sddXfer((uint8_t)(0x40 | cmd));
    sddXfer((uint8_t)(arg >> 24));
    sddXfer((uint8_t)(arg >> 16));
    sddXfer((uint8_t)(arg >> 8));
    sddXfer((uint8_t)arg);
    sddXfer(crc);
    uint8_t r1 = 0xFF;
    for (int i = 0; i < 10 && (r1 & 0x80); i++) r1 = sddXfer(0xFF);
    for (int i = 0; i < tailLen; i++) tail[i] = sddXfer(0xFF);
    return r1;
}

static uint8_t sddCmd0On(int sck, int mosi, int miso, int cs, bool openDrain, int halfUs) {
    sddBusAttach(sck, mosi, miso, cs, openDrain, halfUs);
    gpio_set_level((gpio_num_t)cs, 1);
    for (int i = 0; i < 12; i++) sddXfer(0xFF);
    gpio_set_level((gpio_num_t)cs, 0);
    uint8_t r1 = sddCmd(0, 0, 0x95, nullptr, 0);
    gpio_set_level((gpio_num_t)cs, 1);
    sddXfer(0xFF);
    return r1;
}

static void sddLineTest() {
    Serial.println("[SDDIAG] --- static line test (internal pull-up vs pull-down readback) ---");
    for (int i = 0; i < 4; i++) {
        int pin = SDDIAG_ROLE_PINS[i];
        sddPin(pin, GPIO_MODE_INPUT, true, false);
        delayMicroseconds(500);
        int up = gpio_get_level((gpio_num_t)pin);
        sddPin(pin, GPIO_MODE_INPUT, false, true);
        delayMicroseconds(500);
        int dn = gpio_get_level((gpio_num_t)pin);
        sddPin(pin, GPIO_MODE_INPUT, true, false);
        const char *verdict = (up && !dn)  ? "floats with pulls (normal for an idle SD line)"
                            : (up && dn)   ? "held HIGH externally (board pull-up or a driver)"
                            : (!up && !dn) ? "held LOW externally (short to GND, or a driver holding it)"
                                           : "inverted/unstable";
        Serial.printf("[SDDIAG] %-4s GPIO%-2d (%-3s) pu=%d pd=%d  %s\n",
                      SDDIAG_ROLE_NAMES[i], pin, sddPadName(pin), up, dn, verdict);
    }
}

static void sddShortTest() {
    Serial.println("[SDDIAG] --- inter-line short test (drive one low, read the other three) ---");
    for (int d = 0; d < 4; d++) {
        for (int i = 0; i < 4; i++)
            sddPin(SDDIAG_ROLE_PINS[i], i == d ? GPIO_MODE_INPUT_OUTPUT : GPIO_MODE_INPUT, i != d, false);
        gpio_set_level((gpio_num_t)SDDIAG_ROLE_PINS[d], 0);
        delayMicroseconds(500);
        int readback = gpio_get_level((gpio_num_t)SDDIAG_ROLE_PINS[d]);
        char followers[32];
        followers[0] = 0;
        for (int i = 0; i < 4; i++) {
            if (i == d) continue;
            if (gpio_get_level((gpio_num_t)SDDIAG_ROLE_PINS[i]) == 0) {
                strncat(followers, SDDIAG_ROLE_NAMES[i], sizeof(followers) - strlen(followers) - 2);
                strncat(followers, " ", sizeof(followers) - strlen(followers) - 1);
            }
        }
        gpio_set_level((gpio_num_t)SDDIAG_ROLE_PINS[d], 1);
        Serial.printf("[SDDIAG] drive %-4s LOW: readback=%d dragged_low=[%s]%s%s\n",
                      SDDIAG_ROLE_NAMES[d], readback, followers,
                      readback ? "  <== PIN CANNOT DRIVE LOW" : "",
                      followers[0] ? "  <== SHORTED LINES" : "");
    }
    for (int i = 0; i < 4; i++) sddPin(SDDIAG_ROLE_PINS[i], GPIO_MODE_INPUT, true, false);
}

static void sddProbeFull() {
    Serial.println("[SDDIAG] --- bit-banged SD init on nominal pins (~160 kHz, push-pull) ---");
    sddBusAttach(SD_CLK_PIN, SD_MOSI_PIN, SD_MISO_PIN, SD_CS_PIN, false, 3);

    gpio_set_level((gpio_num_t)sdd_cs, 1);
    for (int i = 0; i < 12; i++) sddXfer(0xFF);

    gpio_set_level((gpio_num_t)sdd_cs, 0);
    uint8_t r1 = sddCmd(0, 0, 0x95, nullptr, 0);
    gpio_set_level((gpio_num_t)sdd_cs, 1);
    sddXfer(0xFF);
    Serial.printf("[SDDIAG] CMD0  GO_IDLE_STATE  R1=0x%02X  %s\n", r1,
                  r1 == 0x01 ? "OK - card entered SPI idle"
                  : r1 == 0xFF ? "SILENT - MISO idles high, card never answered"
                  : r1 == 0x00 ? "MISO STUCK LOW"
                               : "unexpected R1");
    if (r1 != 0x01) {
        Serial.println("[SDDIAG] card did not reach SPI idle -> the fault is BELOW the SD library");
        Serial.println("[SDDIAG]   R1=0xFF -> CS not reaching the card, card not seated, or no 3V3 at the socket");
        Serial.println("[SDDIAG]   R1=0x00 -> MISO shorted to GND or the pad is not the MISO trace");
        return;
    }

    uint8_t tail[4] = {0, 0, 0, 0};
    gpio_set_level((gpio_num_t)sdd_cs, 0);
    r1 = sddCmd(8, 0x1AA, 0x87, tail, 4);
    gpio_set_level((gpio_num_t)sdd_cs, 1);
    sddXfer(0xFF);
    Serial.printf("[SDDIAG] CMD8  SEND_IF_COND   R1=0x%02X  echo=%02X %02X %02X %02X %s\n",
                  r1, tail[0], tail[1], tail[2], tail[3],
                  (r1 == 0x01 && tail[3] == 0xAA) ? "OK - v2 card, voltage accepted" : "");

    uint32_t t0 = millis();
    uint8_t acmd = 0xFF;
    do {
        gpio_set_level((gpio_num_t)sdd_cs, 0);
        sddCmd(55, 0, 0x65, nullptr, 0);
        acmd = sddCmd(41, 0x40000000, 0x77, nullptr, 0);
        gpio_set_level((gpio_num_t)sdd_cs, 1);
        sddXfer(0xFF);
    } while (acmd == 0x01 && (millis() - t0) < 1000);
    Serial.printf("[SDDIAG] ACMD41 INIT          R1=0x%02X  after %lums  %s\n",
                  acmd, (unsigned long)(millis() - t0),
                  acmd == 0x00 ? "card READY" : "card never left idle");

    gpio_set_level((gpio_num_t)sdd_cs, 0);
    r1 = sddCmd(58, 0, 0xFD, tail, 4);
    gpio_set_level((gpio_num_t)sdd_cs, 1);
    sddXfer(0xFF);
    Serial.printf("[SDDIAG] CMD58 READ_OCR       R1=0x%02X  OCR=%02X%02X%02X%02X %s\n",
                  r1, tail[0], tail[1], tail[2], tail[3],
                  (tail[0] & 0x40) ? "(SDHC/SDXC, block addressed)" : "(byte addressed)");

    if (acmd == 0x00) {
        Serial.println("[SDDIAG] VERDICT: card + wiring answer a hand-clocked init.");
        Serial.println("[SDDIAG]          The fault is in the SPI peripheral routing or the SD library path, not the board.");
    }
}

static void sddFuzzPermutations() {
    Serial.println("[SDDIAG] --- pin fuzz A: all 24 role assignments across the 4 SD pads ---");
    const int p[4] = {SD_CLK_PIN, SD_MOSI_PIN, SD_MISO_PIN, SD_CS_PIN};
    int hits = 0;
    for (int a = 0; a < 4; a++) {
        for (int b = 0; b < 4; b++) {
            if (b == a) continue;
            for (int c = 0; c < 4; c++) {
                if (c == a || c == b) continue;
                for (int d = 0; d < 4; d++) {
                    if (d == a || d == b || d == c) continue;
                    uint8_t r = sddCmd0On(p[a], p[b], p[c], p[d], false, 3);
                    if (r != 0xFF)
                        Serial.printf("[SDDIAG] SCK=%-2d MOSI=%-2d MISO=%-2d CS=%-2d -> R1=0x%02X%s\n",
                                      p[a], p[b], p[c], p[d], r, r == 0x01 ? "  <== RESPONDS" : "");
                    if (r == 0x01) hits++;
                }
            }
        }
    }
    Serial.printf("[SDDIAG] fuzz A: %d of 24 orderings answered CMD0 (silent 0xFF results not printed)\n", hits);
}

static void sddFuzzRoleSweep() {
    Serial.println("[SDDIAG] --- pin fuzz B: sweep one role over every XIAO pad, other three nominal ---");
    Serial.println("[SDDIAG] open-drain @ ~10 kHz so a pad already driven by GPS/mesh/RTC is never fought");
    const int nominal[4] = {SD_CLK_PIN, SD_MOSI_PIN, SD_MISO_PIN, SD_CS_PIN};
    int hits = 0;
    for (int role = 0; role < 4; role++) {
        for (int i = 0; i < SDDIAG_PAD_COUNT; i++) {
            int cand[4] = {nominal[0], nominal[1], nominal[2], nominal[3]};
            cand[role] = SDDIAG_PADS[i];
            bool dup = false;
            for (int x = 0; x < 4; x++)
                for (int y = x + 1; y < 4; y++)
                    if (cand[x] == cand[y]) dup = true;
            if (dup) continue;
            uint8_t r = sddCmd0On(cand[0], cand[1], cand[2], cand[3], true, 50);
            if (r != 0xFF)
                Serial.printf("[SDDIAG] %-4s -> %-3s/GPIO%-2d  R1=0x%02X%s\n",
                              SDDIAG_ROLE_NAMES[role], sddPadName(SDDIAG_PADS[i]), SDDIAG_PADS[i], r,
                              r == 0x01 ? "  <== RESPONDS" : "");
            if (r == 0x01) hits++;
        }
    }
    Serial.printf("[SDDIAG] fuzz B: %d hits. NOTE: one role varies at a time, so two simultaneously\n", hits);
    Serial.println("[SDDIAG]         mis-mapped lines will NOT show up here.");
}

static void sddLibRetry() {
    Serial.println("[SDDIAG] --- SD library retry across bus frequencies ---");
    const uint32_t freqs[5] = {200000, 400000, 1000000, 4000000, 10000000};
    for (int i = 0; i < 5; i++) {
        SD.end();
        SPI.end();
        spi2EnsureBusClock();
        SPI.begin(SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN);
        gpio_set_pull_mode((gpio_num_t)SD_MISO_PIN, GPIO_PULLUP_ONLY);
        delay(20);
        bool ok = SD.begin(SD_CS_PIN, SPI, freqs[i]);
        Serial.printf("[SDDIAG] SD.begin(cs=%d, %luHz) -> %s\n",
                      SD_CS_PIN, (unsigned long)freqs[i], ok ? "MOUNTED" : "fail");
        if (ok) return;
    }
    SD.end();
}

void sdRunDiagnostics() {
    Serial.println("[SDDIAG] ================ SD diagnostics ================");
    Serial.printf("[SDDIAG] SCK=GPIO%d(%s) MOSI=GPIO%d(%s) MISO=GPIO%d(%s) CS=GPIO%d(%s)\n",
                  SD_CLK_PIN, sddPadName(SD_CLK_PIN), SD_MOSI_PIN, sddPadName(SD_MOSI_PIN),
                  SD_MISO_PIN, sddPadName(SD_MISO_PIN), SD_CS_PIN, sddPadName(SD_CS_PIN));
    sddLineTest();
    sddShortTest();
    sddProbeFull();
    sddFuzzPermutations();
    sddFuzzRoleSweep();
    sddLibRetry();
    Serial.println("[SDDIAG] ================ end ================");
}

#else
void sdRunDiagnostics() {}
#endif

void initializeSD()
{
    Serial.println("Initializing SD card...");
    Serial.printf("[SD] GPIO Pins SCK=%d MISO=%d MOSI=%d CS=%d\n", SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
    sdRunDiagnostics();
    SPI.end();
    spi2EnsureBusClock();
    SPI.begin(SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN);
#ifdef ARDUINO_XIAO_ESP32C5
    gpio_set_pull_mode((gpio_num_t)SD_MISO_PIN, GPIO_PULLUP_ONLY);
#endif
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

    GPS.setRxBufferSize(2048);
    GPS.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    gpsMutex = xSemaphoreCreateMutex();

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
        gpsMsg += " Satellites:" + String(gps.satellites.isValid() ? gps.satellites.value() : 0);
        gpsMsg += " HDOP:" + String(gps.hdop.isValid() ? gps.hdop.hdop() : 99.9, 2);
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

            bool nowLocked = gps.location.isValid() && gps.location.age() < GPS_FIX_MAX_AGE_MS;
            bool fixReady = nowLocked && gps.satellites.isValid() && gps.satellites.value() > 0
                            && gps.hdop.isValid() && gps.hdop.age() < GPS_FIX_MAX_AGE_MS
                            && gps.hdop.hdop() > 0;

            if (nowLocked) {
                if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                    gpsLat = gps.location.lat();
                    gpsLon = gps.location.lng();
                    gpsValid = true;
                    xSemaphoreGive(gpsMutex);
                }
                lastGPSData = "Lat: " + String(gpsLat, 6)
                            + ", Lon: " + String(gpsLon, 6)
                            + " (" + String((millis() - lastDataTime) / 1000)
                            + "s ago)";

                if (!wasLocked && fixReady) {
                    sendGPSLockStatus(true);
                }
            } else {
                gpsValid = false;
                lastGPSData = "No valid GPS fix ("
                            + String((millis() - lastDataTime) / 1000)
                            + "s ago)";

                if (wasLocked) {
                    sendGPSLockStatus(false);
                }
            }

            wasLocked = fixReady;
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


static std::mutex g_sdLogMutex;

void logToSD(const String &data) {
    if (!SafeSD::isAvailable()) return;

    std::lock_guard<std::mutex> sdLock(g_sdLogMutex);

    static uint32_t totalWrites = 0;
    static File logFile;

    if (!SD.exists("/")) {
        static uint32_t failCount = 0;
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
        if (logFile) {
            logFile.flush();
            Serial.printf("[SD] Log file size: %lu bytes\n", (unsigned long)logFile.size());
        }
        lastSizeCheck = millis();
    }
}
// Survives panic/WDT/SW resets (lost on power cycle, which is itself the diagnosis).
RTC_DATA_ATTR static uint32_t rtcBootMagic = 0;
RTC_DATA_ATTR static uint32_t rtcLastUptimeSec = 0;
static const uint32_t BOOT_MAGIC = 0xA471B007;

static esp_reset_reason_t g_resetReason = ESP_RST_UNKNOWN;
static uint32_t g_prevUptimeSec = 0;
static bool g_prevUptimeKnown = false;
static bool g_resultsRestored = false;

const char *getResetReasonText() {
    switch (g_resetReason) {
        case ESP_RST_POWERON:  return "POWERON";
        case ESP_RST_EXT:      return "EXT";
        case ESP_RST_SW:       return "SW";
        case ESP_RST_PANIC:    return "PANIC";
        case ESP_RST_INT_WDT:  return "INT_WDT";
        case ESP_RST_TASK_WDT: return "TASK_WDT";
        case ESP_RST_WDT:      return "WDT";
        case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
        case ESP_RST_BROWNOUT: return "BROWNOUT";
        case ESP_RST_SDIO:     return "SDIO";
        default:               return "UNKNOWN";
    }
}

bool wasCleanBoot() { return g_resetReason == ESP_RST_POWERON || g_resetReason == ESP_RST_EXT; }

void recordBootReason() {
    g_resetReason = esp_reset_reason();
    if (rtcBootMagic == BOOT_MAGIC) {
        g_prevUptimeSec = rtcLastUptimeSec;
        g_prevUptimeKnown = true;
    } else {
        g_prevUptimeSec = 0;
        g_prevUptimeKnown = false;
    }
    rtcBootMagic = BOOT_MAGIC;
    rtcLastUptimeSec = 0;
    Serial.printf("[BOOT] reset=%s prevUptime=%s\n", getResetReasonText(),
                  g_prevUptimeKnown ? String(g_prevUptimeSec).c_str() : "unknown");
}

void markUptimeAlive() {
    uint32_t sec = millis() / 1000;
    if (sec != rtcLastUptimeSec) rtcLastUptimeSec = sec;
}

void logBootRecord() {
    String line = "BOOT reset=" + String(getResetReasonText()) +
                  " prevUptime=" + (g_prevUptimeKnown ? String(g_prevUptimeSec) + "s" : String("unknown")) +
                  " heap=" + String((unsigned)ESP.getFreeHeap());
    logToSD(line);
}

static uint32_t resultsHash(const std::string &s) {
    uint32_t h = 2166136261u;
    for (char c : s) { h ^= (uint8_t)c; h *= 16777619u; }
    return h;
}

void saveResultsSnapshot(bool force) {
    static uint32_t nextSaveMs = 0;
    static uint32_t lastHash = 0;
    if (!SafeSD::isAvailable()) return;
    uint32_t now = millis();
    if (!force && nextSaveMs != 0 && (int32_t)(now - nextSaveMs) < 0) return;
    nextSaveMs = now + RESULTS_SNAPSHOT_INTERVAL_MS;

    std::string copy;
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        copy = antihunter::lastResults;
    }
    if (copy.empty() || copy.size() > RESULTS_SNAPSHOT_MAX_BYTES) return;
    uint32_t h = resultsHash(copy);
    if (h == lastHash) return;

    File f = SafeSD::open(RESULTS_SNAPSHOT_FILE, FILE_WRITE);
    if (!f) return;
    f.write(reinterpret_cast<const uint8_t *>(copy.data()), copy.size());
    f.close();
    lastHash = h;
}

void loadResultsSnapshot() {
    if (!SafeSD::isAvailable() || !SafeSD::exists(RESULTS_SNAPSHOT_FILE)) return;
    File f = SafeSD::open(RESULTS_SNAPSHOT_FILE, FILE_READ);
    if (!f) return;
    size_t len = f.size();
    if (len == 0 || len > RESULTS_SNAPSHOT_MAX_BYTES) { f.close(); return; }

    std::string buf;
    buf.resize(len);
    size_t got = f.read(reinterpret_cast<uint8_t *>(&buf[0]), len);
    f.close();
    if (got == 0) return;
    buf.resize(got);

    std::string header = "[Recovered after reset: " + std::string(getResetReasonText());
    if (g_prevUptimeKnown) header += ", prior uptime " + std::to_string(g_prevUptimeSec) + "s";
    header += "]\n\n";

    std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
    antihunter::lastResults = header + buf;
    g_resultsRestored = true;
    Serial.printf("[BOOT] Restored %u bytes of results from snapshot\n", (unsigned)got);
}

void logVibrationEvent(int sensorValue) {
    String event = String(sensorValue ? "Motion" : "Impact") + " detected";
    if (gpsValid) {
        event += " @" + String(gpsLat, 4) + "," + String(gpsLon, 4);
    }
    logToSD(event);
    Serial.printf("[MOTION] %s\n", event.c_str());
}

void logEventToSD(const char* path, const String& jsonLine) {
    if (!SafeSD::isAvailable()) return;

    // Heap-floor guard: under an attack flood, per-event SD writes (File buffers +
    // rotation reads) can drain heap to an abort. Below the floor, drop the write
    // rather than crash — the detector still counted/alerted in RAM. Protects
    // EVERY detector log path in one place.
    if (ESP.getFreeHeap() < 20000) {
        static uint32_t s_lastHeapWarnMs = 0;
        uint32_t nowMs = millis();
        if (nowMs - s_lastHeapWarnMs > 5000) {
            s_lastHeapWarnMs = nowMs;
            Serial.printf("[HEAP-GUARD] dropping SD log (%s) — free heap %u\n",
                          path, (unsigned)ESP.getFreeHeap());
        }
        return;
    }

    std::lock_guard<std::mutex> sdLock(g_sdLogMutex);
    File f = SafeSD::open(path, FILE_APPEND);
    if (!f) {
        f = SafeSD::open(path, FILE_WRITE);
        if (!f) {
            Serial.printf("[SD] Failed to open %s for event log\n", path);
            return;
        }
    }
    f.println(jsonLine);
    size_t curSize = f.size();
    f.close();

    if (curSize > 1048576) {
        String rotated = String(path);
        int dotIdx = rotated.lastIndexOf('.');
        if (dotIdx > 0) {
            rotated = rotated.substring(0, dotIdx) + "_old" + rotated.substring(dotIdx);
        } else {
            rotated += "_old";
        }
        SafeSD::remove(rotated.c_str());
        SD.rename(path, rotated.c_str());
        Serial.printf("[SD] Rotated %s -> %s\n", path, rotated.c_str());
    }
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

void updateSetupModeStatus() {
    // Check if setup mode should be automatically completed
    if (inSetupMode && autoEraseEnabled) {
        uint32_t elapsed = millis() - setupStartTime;
        if (elapsed >= setupDelay) {
            inSetupMode = false;
            Serial.println("[SETUP] Setup period complete - auto-erase now ACTIVE");

            // Use stack buffer to avoid heap fragmentation
            char setupMsg[128];
            snprintf(setupMsg, sizeof(setupMsg), "%s: SETUP_COMPLETE: Auto-erase activated",
                     getNodeId().c_str());
            sendToSerial1(String(setupMsg), false);
        }
    }
}

void checkAndSendVibrationAlert() {
    if (vibrationDetected) {
        vibrationDetected = false;

        if (inSetupMode) {
            uint32_t elapsed = millis() - setupStartTime;
            if (elapsed >= setupDelay) {
                inSetupMode = false;
                Serial.println("[SETUP] Setup period complete - auto-erase now ACTIVE");

                // Use stack buffer to avoid heap fragmentation
                char setupMsg[128];
                snprintf(setupMsg, sizeof(setupMsg), "%s: SETUP_COMPLETE: Auto-erase activated",
                         getNodeId().c_str());
                sendToSerial1(String(setupMsg), false);
            } else {
                uint32_t remaining = (setupDelay - elapsed) / 1000;
                Serial.printf("[SETUP] Setup mode - auto-erase activates in %us\n", remaining);

                // Use stack buffer to avoid heap fragmentation
                char vibrationMsg[256];
                int offset = snprintf(vibrationMsg, sizeof(vibrationMsg),
                                     "%s: VIBRATION: Movement in setup mode (active in %us)",
                                     getNodeId().c_str(), remaining);

                if (gpsValid && offset > 0 && offset < (int)sizeof(vibrationMsg)) {
                    snprintf(vibrationMsg + offset, sizeof(vibrationMsg) - offset,
                            " GPS:%.6f,%.6f", gpsLat, gpsLon);
                }
                Serial.printf("[VIBRATION] Setup-mode alert: %s\n", vibrationMsg);
                if (vibrationEnabled) {
                    sendToSerial1(String(vibrationMsg), true);
                }
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

            // Use stack buffers to avoid heap fragmentation
            char timestamp[32];
            strncpy(timestamp, getFormattedTimestamp().c_str(), sizeof(timestamp) - 1);
            timestamp[sizeof(timestamp) - 1] = '\0';

            int sensorValue = digitalRead(VIBRATION_PIN);

            char vibrationMsg[256];
            int offset = snprintf(vibrationMsg, sizeof(vibrationMsg),
                                 "%s: VIBRATION: Movement detected at %s",
                                 getNodeId().c_str(), timestamp);

            if (gpsValid && offset > 0 && offset < (int)sizeof(vibrationMsg)) {
                offset += snprintf(vibrationMsg + offset, sizeof(vibrationMsg) - offset,
                                  " GPS:%.6f,%.6f", gpsLat, gpsLon);
            }

            if (tamperEraseActive && offset > 0 && offset < (int)sizeof(vibrationMsg)) {
                uint32_t timeLeft = (autoEraseDelay - (millis() - tamperSequenceStart)) / 1000;
                snprintf(vibrationMsg + offset, sizeof(vibrationMsg) - offset,
                        " TAMPER_ERASE_IN:%us", timeLeft);
            }

            Serial.printf("[VIBRATION] Sending mesh alert: %s\n", vibrationMsg);
            if (vibrationEnabled) {
                sendToSerial1(String(vibrationMsg), true);
            }
            if (vibAutoScanEnabled && vibAutoScanMode != 0 && !batterySaverEnabled) {
                vibAutoScanPending = true;
            }
            logVibrationEvent(sensorValue);

            // Structured vibration event log
            {
                DynamicJsonDocument doc(128);
                doc["t"] = getEventTimestamp();
                doc["uptime_ms"] = millis();
                if (gpsValid) {
                    doc["lat"] = gpsLat;
                    doc["lon"] = gpsLon;
                }
                String line;
                serializeJson(doc, line);
                logEventToSD("/vibrations.jsonl", line);
            }

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

    if (timeDiff > 1 || !rtcSynced) {
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

    if (rtcMutex == nullptr) return;
    if (xSemaphoreTake(rtcMutex, pdMS_TO_TICKS(50)) != pdTRUE) return;

    DateTime now = rtc.now();

    // Sanity check: if year is 0 or wildly out of range, I2C read failed
    if (now.year() < 2020 || now.year() > 2099) {
        xSemaphoreGive(rtcMutex);
        static uint8_t rtcFailCount = 0;
        rtcFailCount++;
        if (rtcFailCount >= 5) {
            Serial.println("[RTC] Repeated bad reads, marking unavailable");
            rtcAvailable = false;
            rtcFailCount = 0;
        }
        return;
    }

    static uint8_t rtcFailCount = 0;
    rtcFailCount = 0;  // good read, reset counter

    char buffer[30];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
             now.year(), now.month(), now.day(),
             now.hour(), now.minute(), now.second());

    rtcTimeString = String(buffer);

    xSemaphoreGive(rtcMutex);

    if (gpsValid && gps.time.isValid()) {
        disciplineRTCFromGPS();
    }
    if (gpsValid && !rtcSynced) {
        syncRTCFromGPS();
    }
    
    if (gpsValid && rtcSynced && lastRTCSync > 0 && (millis() - lastRTCSync) > 3600000) {
        syncRTCFromGPS();
    }
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

uint32_t getEventTimestamp() {
    time_t epoch = getRTCEpoch();
    if (epoch > 946684800) return (uint32_t)epoch;  // valid if after year 2000
    return millis() / 1000;
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

void setErasePSK(const String &key) {
    erasePSK = key;
    prefs.putString("erasePSK", key);
}

String computeEraseHmac(const String &nonce) {
    if (erasePSK.length() == 0 || nonce.length() == 0) return "";
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return "";
    uint8_t out[32];
    if (mbedtls_md_hmac(info, reinterpret_cast<const uint8_t *>(erasePSK.c_str()), erasePSK.length(),
                        reinterpret_cast<const uint8_t *>(nonce.c_str()), nonce.length(), out) != 0) {
        return "";
    }
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", out[i]);
    hex[64] = '\0';
    return String(hex);
}

bool validateEraseResponse(const String &response) {
    if (erasePSK.length() == 0) return false;
    if (tamperAuthToken.length() == 0) return false;

    int lastUnderscorePos = tamperAuthToken.lastIndexOf('_');
    if (lastUnderscorePos < 0) return false;
    uint32_t nonceTime = strtoul(tamperAuthToken.substring(lastUnderscorePos + 1).c_str(), nullptr, 16);
    if ((millis() / 1000 - nonceTime) >= 300) return false;

    String expected = computeEraseHmac(tamperAuthToken);
    if (expected.length() == 0 || expected.length() != response.length()) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < expected.length(); i++) {
        diff |= (uint8_t)(expected[i] ^ response[i]);
    }
    return diff == 0;
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

bool performConfigReset() {
    Serial.println("[RESET] Config reset - NVS only");
    prefs.end();
    delay(100);

    esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        Serial.printf("[RESET] NVS erase failed: %d\n", err);
        return false;
    }

    err = nvs_flash_init();
    if (err != ESP_OK) {
        Serial.printf("[RESET] NVS init failed: %d\n", err);
        return false;
    }

    Serial.println("[RESET] NVS cleared - SD data preserved");
    return true;
}

bool performDataReset() {
    Serial.println("[RESET] Data reset - SD only");
    if (!SafeSD::isAvailable()) {
        Serial.println("[RESET] SD card not available");
        return false;
    }

    deleteAllFiles("/");

    File marker = SafeSD::open("/weather-air-feed.txt", FILE_WRITE);
    if (marker) {
        marker.println("AntiHunter Weather Monitor and AQ data could not be sent to your network. Check your API key and settings or contact support.");
        marker.close();
    }

    if (SafeSD::exists("/weather-air-feed.txt")) {
        Serial.println("[RESET] SD data cleared - config preserved");
        return true;
    }
    Serial.println("[RESET] SD clear verification failed");
    return false;
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

        file.close();
        file = root.openNextFile();
    }

    root.close();
}

// Battery Saver Mode Implementation

void enterBatterySaver(uint32_t heartbeatIntervalMs) {
    if (batterySaverEnabled) {
        Serial.println("[BATTERY_SAVER] Already enabled");
        return;
    }

    Serial.println("[BATTERY_SAVER] Entering battery saver mode...");

    // Validate and set heartbeat interval (minimum 60 seconds, maximum 30 minutes)
    if (heartbeatIntervalMs < 60000) heartbeatIntervalMs = 60000;
    if (heartbeatIntervalMs > 1800000) heartbeatIntervalMs = 1800000;
    batterySaverHeartbeatInterval = heartbeatIntervalMs;

    // Stop any active scanning tasks
    stopAllScans(false);

    // Wait for tasks to stop
    uint32_t waitStart = millis();
    while ((workerTaskHandle || blueTeamTaskHandle) && (millis() - waitStart < 5000)) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Disable WiFi promiscuous mode
    esp_wifi_set_promiscuous(false);

    // Disable BLE controller
    esp_bt_controller_disable();
    Serial.println("[BATTERY_SAVER] BLE disabled");

    // Reduce CPU frequency to 80MHz for power saving
    esp_pm_config_t pm_config = {
        .max_freq_mhz = 80,
        .min_freq_mhz = 80,
        .light_sleep_enable = true
    };
    esp_err_t err = esp_pm_configure(&pm_config);
    if (err == ESP_OK) {
        Serial.println("[BATTERY_SAVER] CPU frequency reduced to 80MHz");
    } else {
        Serial.printf("[BATTERY_SAVER] Failed to configure PM: %s\n", esp_err_to_name(err));
    }

    batterySaverEnabled = true;
    lastBatterySaverHeartbeat = 0;  // Send heartbeat immediately

    // Send notification to mesh
    String msg = getNodeId() + ": BATTERY_SAVER: ENABLED Interval:" + String(heartbeatIntervalMs / 60000) + "min";
    sendToSerial1(msg, true);

    Serial.printf("[BATTERY_SAVER] Mode enabled, heartbeat every %lu minutes\n", heartbeatIntervalMs / 60000);
    logToSD("Battery saver mode enabled");
}

void exitBatterySaver() {
    if (!batterySaverEnabled) {
        Serial.println("[BATTERY_SAVER] Already disabled");
        return;
    }

    Serial.println("[BATTERY_SAVER] Exiting battery saver mode...");

    // Restore CPU frequency to 240MHz
    esp_pm_config_t pm_config = {
        .max_freq_mhz = 240,
        .min_freq_mhz = 80,
        .light_sleep_enable = false
    };
    esp_err_t err = esp_pm_configure(&pm_config);
    if (err == ESP_OK) {
        Serial.println("[BATTERY_SAVER] CPU frequency restored to 240MHz");
    } else {
        Serial.printf("[BATTERY_SAVER] Failed to configure PM: %s\n", esp_err_to_name(err));
    }

    // Re-enable BLE controller
    esp_bt_controller_enable(ESP_BT_MODE_BLE);
    Serial.println("[BATTERY_SAVER] BLE re-enabled");

    batterySaverEnabled = false;

    // Send notification to mesh
    String msg = getNodeId() + ": BATTERY_SAVER: DISABLED";
    sendToSerial1(msg, true);

    Serial.println("[BATTERY_SAVER] Mode disabled, normal operation resumed");
    logToSD("Battery saver mode disabled");
}

void sendBatterySaverHeartbeat() {
    if (!batterySaverEnabled) return;

    if (triangulationActive.load()) {
        return;
    }

    uint32_t now = millis();
    if (now - lastBatterySaverHeartbeat < batterySaverHeartbeatInterval) return;

    lastBatterySaverHeartbeat = now;

    float temp_c = temperatureRead();

    // Build heartbeat message
    String heartbeat = getNodeId() + ": HEARTBEAT: Temp:" + String((int)temp_c) + "C";

    // Add GPS if available
    if (gpsValid) {
        heartbeat += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    } else {
        heartbeat += " GPS:N/A";
    }

    heartbeat += " Battery:SAVER";

    sendToSerial1(heartbeat, true);
    Serial.printf("[BATTERY_SAVER] Heartbeat sent: %s\n", heartbeat.c_str());
}

String getBatterySaverStatus() {
    String status = getNodeId() + ": BATTERY_SAVER_STATUS: ";
    status += "Enabled:" + String(batterySaverEnabled ? "YES" : "NO");

    if (batterySaverEnabled) {
        status += " Interval:" + String(batterySaverHeartbeatInterval / 60000) + "min";

        uint32_t nextHeartbeat = 0;
        if (lastBatterySaverHeartbeat > 0) {
            uint32_t elapsed = millis() - lastBatterySaverHeartbeat;
            if (elapsed < batterySaverHeartbeatInterval) {
                nextHeartbeat = (batterySaverHeartbeatInterval - elapsed) / 1000;
            }
        }
        status += " NextHB:" + String(nextHeartbeat) + "s";
    }

    float temp_c = temperatureRead();
    status += " Temp:" + String((int)temp_c) + "C";

    if (gpsValid) {
        status += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }

    return status;
}
