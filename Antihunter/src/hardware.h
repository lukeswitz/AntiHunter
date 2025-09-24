#pragma once
#include "scanner.h"
#include "network.h"
#include "main.h"

#ifndef COUNTRY
#define COUNTRY "NO"
#endif
#ifndef MESH_RX_PIN
#define MESH_RX_PIN 4   // MESH PIN 9
#endif
#ifndef MESH_TX_PIN
#define MESH_TX_PIN 5    // MESH PIN 10
#endif
#ifndef VIBRATION_PIN
#define VIBRATION_PIN 2  // SW-420
#endif

// SD Card (SPI)
#define SD_CS_PIN   1    // CS on D0
#define SD_CLK_PIN  7    // CLK on D8
#define SD_MISO_PIN 8    // MISO on D9
#define SD_MOSI_PIN 9   // MOSI on D10

// GPS (UART)
#define GPS_RX_PIN 44   // GPS RX
#define GPS_TX_PIN 43   // GPS TX

// RTC (I2C)
#define RTC_SDA_PIN 3    // RTC SDA
#define RTC_SCL_PIN 6    // RTC SCL

// Configuration constants
#define CONFIG_FILE "/config.json"
#define MAX_CONFIG_SIZE 4096

// RTC Status
extern bool rtcAvailable;
extern bool rtcSynced;
extern time_t lastRTCSync;
extern String rtcTimeString;

extern bool sdAvailable;
extern bool gpsValid;
extern float gpsLat, gpsLon;
extern String lastGPSData;
extern HardwareSerial GPS;
extern volatile bool vibrationDetected;
extern unsigned long lastVibrationTime;
extern unsigned long lastVibrationAlert;

void initializeHardware();
void initializeVibrationSensor();
void initializeSD();
void initializeGPS();
void checkAndSendVibrationAlert();
void saveConfiguration();
String getDiagnostics();
void logToSD(const String &data);
String getGPSData();
void updateGPSLocation();
void sendStartupStatus();
void sendGPSLockStatus(bool locked);
void parseChannelsCSV(const String &csv);
void saveTargetsList(const String &txt);
void saveConfiguration();
void loadConfiguration();

// RTC Functions
void initializeRTC();
void syncRTCFromGPS();
void updateRTCTime();
String getRTCTimeString();
String getFormattedTimestamp();
time_t getRTCEpoch();
bool setRTCTime(int year, int month, int day, int hour, int minute, int second);

// Tamper Detection System
#define TAMPER_DETECTION_WINDOW 30000  // 30 seconds to cancel
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

bool initiateTamperErase();
void cancelTamperErase();
bool checkTamperTimeout();
bool performSecureWipe();
void deleteAllFiles(const String &dirname);
bool executeSecureErase(const String &reason);
String generateEraseToken();
bool validateEraseToken(const String &token);
void logEraseAttempt(const String &reason, bool success);
