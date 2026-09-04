#pragma once
#include "scanner.h"
#include "network.h"
#include "main.h"
#include <RTClib.h>
#include <TinyGPSPlus.h>
#include <FS.h>
#include <SD.h>

#ifndef COUNTRY
#define COUNTRY "US"
#endif
#ifndef MESH_RX_PIN
#define MESH_RX_PIN 4    // TO MESH PIN 9/19 T114/V3
#endif
#ifndef MESH_TX_PIN
#define MESH_TX_PIN 5    // TO MESH PIN 10/20 T114/V3
#endif
#ifndef VIBRATION_PIN
#define VIBRATION_PIN 2  // TO SW-420 D0
#endif

// SD Card (SPI)
#define SD_CS_PIN   1    // CS on D0
#define SD_CLK_PIN  7    // CLK on D8
#define SD_MISO_PIN 8    // MISO on D9
#define SD_MOSI_PIN 9    // MOSI on D10

// GPS (UART)
#define GPS_RX_PIN 44   // GPS RX
#define GPS_TX_PIN 43   // GPS TX

// RTC (I2C)
#define RTC_SDA_PIN 3    // RTC SDA
#define RTC_SCL_PIN 6    // RTC SCL

// Configuration constants
#define CONFIG_FILE "/config.json"
#define CONFIG_TMP_FILE "/config.json.tmp"
#define CONFIG_BAK_FILE "/config.json.bak"
#define CONFIG_BAD_FILE "/config.json.bad"
#define MAX_CONFIG_SIZE 4096

class SafeSD {
private:
    static uint32_t lastCheckTime;
    static bool lastCheckResult;
    static const uint32_t CHECK_INTERVAL_MS = 1000;
    static const uint32_t SD_OPEN_HEAP_FLOOR = 12288;
    static const uint32_t SD_OPEN_BLOCK_FLOOR = 4096;
    static const uint32_t MOUNT_LOG_INTERVAL_MS = 60000;
    static uint32_t sdMountFailures;
    static uint32_t lastMountLogMs;
    static bool checkAvailability();

public:
    static bool isAvailable();
    static bool hasHeapForOpen();
    static fs::File open(const char* path, const char* mode = FILE_READ);
    static bool exists(const char* path);
    static bool remove(const char* path);
    static bool rename(const char* from, const char* to);
    static bool mkdir(const char* path);
    static bool rmdir(const char* path);
    static size_t write(fs::File& file, const uint8_t* data, size_t len);
    static size_t read(fs::File& file, uint8_t* data, size_t len);
    static bool flush(fs::File& file);
    static void forceRecheck();
    static uint32_t mountFailureCount();
};

String jsonEscape(const String &in);

// RTC Status
extern RTC_DS3231 rtc;
extern bool rtcAvailable;
extern bool rtcSynced;
extern time_t lastRTCSync;
extern String rtcTimeString;
extern SemaphoreHandle_t rtcMutex;


void initializeRTC();
void syncRTCFromGPS();
void updateRTCTime();
String getRTCTimeString();
String getFormattedTimestamp();
time_t getRTCEpoch();
uint32_t getEventTimestamp();
bool setRTCTimeFromEpoch(time_t epoch);

// Sensors and GPS
extern bool sdAvailable;
extern bool sdAutoRepair;
bool sdMountOrRepair();
void setSdAutoRepair(bool on);
void loadSdAutoRepair();
extern std::atomic<bool> gpsValid;
extern float gpsLat, gpsLon;
extern SemaphoreHandle_t gpsMutex;
extern String lastGPSData;
extern HardwareSerial GPS;
extern TinyGPSPlus gps;
extern volatile bool vibrationDetected;
extern unsigned long lastVibrationTime;
extern unsigned long lastVibrationAlert;
extern bool vibAutoScanEnabled;
extern uint8_t vibAutoScanMode;
extern uint16_t vibAutoScanDuration;
extern uint32_t vibAutoScanCooldownMs;
extern volatile bool vibAutoScanPending;
extern unsigned long lastVibAutoScanFire;

void initializeHardware();
void initializeVibrationSensor();
void initializeSD();
void initializeGPS();

bool waitForInitialConfig();
void updateSetupModeStatus();
void checkAndSendVibrationAlert();
String getDiagnostics();
String getGPSData();
void updateGPSLocation();
void sendStartupStatus();
void sendGPSLockStatus(bool locked);
void parseChannelsCSV(const String &csv);
void saveTargetsList(const String &txt);
String prefsGetString(const char *key, const String &defaultValue);
extern unsigned long lastSaveTime;
void saveConfiguration();
void loadConfiguration();
void syncSettingsToNVS();
void logToSD(const String &data);
void logEventToSD(const char* path, const String& jsonLine);

#define RESULTS_SNAPSHOT_FILE "/last_results.txt"
#define RESULTS_SNAPSHOT_INTERVAL_MS 60000
#define RESULTS_SNAPSHOT_MAX_BYTES 16384

void recordBootReason();
void logBootRecord();
void markUptimeAlive();
const char *getResetReasonText();
uint32_t getPrevBootUptimeSec();
bool prevBootUptimeKnown();
bool wasCleanBoot();
bool resultsWereRestored();
void saveResultsSnapshot(bool force = false);
void loadResultsSnapshot();

// Tamper Detection System
extern bool tamperEraseActive;
extern uint32_t tamperSequenceStart;
extern String tamperAuthToken;
extern bool autoEraseEnabled;
extern uint32_t autoEraseDelay;
extern uint32_t autoEraseCooldown;
extern uint32_t vibrationsRequired;
extern uint32_t detectionWindow;
extern uint32_t setupDelay;
extern uint32_t setupStartTime;
extern bool inSetupMode;
extern String eraseStatus;
extern bool eraseInProgress;

// Battery Saver Mode
extern bool batterySaverEnabled;
extern uint32_t batterySaverHeartbeatInterval;
extern uint32_t lastBatterySaverHeartbeat;

bool initiateTamperErase();
void cancelTamperErase();
bool checkTamperTimeout();
bool performSecureWipe();
bool performConfigReset();
bool performDataReset();
void deleteAllFiles(const String &dirname);
bool executeSecureErase(const String &reason);
String generateEraseToken();
bool validateEraseToken(const String &token);
String computeEraseHmac(const String &nonce);
bool validateEraseResponse(const String &response);
void setErasePSK(const String &key);
extern String erasePSK;

// Battery Saver Functions
void enterBatterySaver(uint32_t heartbeatIntervalMs = 300000);
void exitBatterySaver();
void sendBatterySaverHeartbeat();
String getBatterySaverStatus();