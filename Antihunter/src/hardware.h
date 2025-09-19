#pragma once
#include "scanner.h"
#include "network.h"
#include "main.h"

#ifndef COUNTRY
#define COUNTRY "NO"
#endif
#ifndef MESH_RX_PIN
#define MESH_RX_PIN 4   // MESH PIN 20      (GPIO4)
#endif
#ifndef MESH_TX_PIN
#define MESH_TX_PIN 5    // MESH PIN 19     (GPIO5)
#endif
#ifndef VIBRATION_PIN
#define VIBRATION_PIN 1  // SW-420   (GPIO1)
#endif

// SD Card (SPI)
#define SD_CS_PIN   2    // CS on D1        (GPIO2)
#define SD_CLK_PIN  7    // CLK (SCK)       (GPIO7)
#define SD_MISO_PIN 8    // MISO on D9      (GPIO8)
#define SD_MOSI_PIN 9    // MOSI on D10     (GPIO9)

// GPS (UART)
#define GPS_RX_PIN 44   // GPS RX          (GPIO 44)
#define GPS_TX_PIN 43   // GPS TX          (GPIO 43)

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