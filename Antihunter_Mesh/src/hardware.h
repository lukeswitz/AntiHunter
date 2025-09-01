#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>

#ifndef COUNTRY
#define COUNTRY "NO"
#endif
#ifndef BUZZER_PIN
#define BUZZER_PIN 3
#endif
#ifndef BUZZER_IS_PASSIVE
#define BUZZER_IS_PASSIVE 1
#endif
#ifndef MESH_RX_PIN
#define MESH_RX_PIN 6   // to MESH TX PIN 20
#endif
#ifndef MESH_TX_PIN
#define MESH_TX_PIN 5   // to MESH RX PIN 19
#endif

// SD Card (SPI)
#define SD_CS_PIN   2    // CS on D1 (GPIO2)
#define SD_CLK_PIN  7    // CLK (SCK) on D8 (GPIO7)
#define SD_MISO_PIN 8    // MISO on D9 (GPIO8)
#define SD_MOSI_PIN 9    // MOSI on D10 (GPIO9)

// GPS (UART)
#define GPS_RX_PIN 44   // D7 = GPIO44 (ESP RX)
#define GPS_TX_PIN 43   // D6 = GPIO43 (ESP TX)

extern bool sdAvailable;
extern bool gpsValid;
extern float gpsLat, gpsLon;
extern String lastGPSData;
extern HardwareSerial GPS;


void initializeHardware();
void initializeSD();
void initializeGPS();
void testGPSPins();
void beepOnce(uint32_t freq = 3200, uint32_t ms = 80);
void beepPattern(int count, int gap_ms);
void saveConfiguration();
String getDiagnostics();
int getBeepsPerHit();
int getGapMs();
void logToSD(const String &data);
String getGPSData();
void updateGPSLocation();