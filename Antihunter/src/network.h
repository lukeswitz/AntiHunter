#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include "scanner.h"

enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

extern AsyncWebServer *server;

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS  
#define AP_PASS "ouispy123"
#endif
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif

void initializeNetwork();
void startWebServer();
void stopAPAndServer();
void startAPAndServer();