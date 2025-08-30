#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS  
#define AP_PASS "ouispy123"
#endif
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif
#ifndef COUNTRY
#define COUNTRY "NO"
#endif
#ifndef BUZZER_PIN
#define BUZZER_PIN 3
#endif
#ifndef BUZZER_IS_PASSIVE
#define BUZZER_IS_PASSIVE 1
#endif
#define MESH_RX_PIN 4
#define MESH_TX_PIN 5


void initializeHardware();
void beepOnce(uint32_t freq = 3200, uint32_t ms = 80);
void beepPattern(int count, int gap_ms);
void saveConfiguration();
String getDiagnostics();
int getBeepsPerHit();
int getGapMs();