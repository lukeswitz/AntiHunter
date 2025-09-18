#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include "scanner.h"

enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

extern AsyncWebServer *server;
extern bool meshEnabled;

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS  
#define AP_PASS "ouispy123"
#endif
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif

struct TriangulationNode {
    String nodeId;
    float lat, lon;
    int8_t rssi;
    uint32_t hitCount;
    bool hasGPS;
};

// Triangulation functions
String calculateTriangulationResults();
void stopTriangulation();
void startTriangulation(const String &targetMac, int duration);
bool isTriangulationActive();

// Network and Web Server functions
void initializeNetwork();
void initializeMesh();
void startWebServer();
void startAPAndServer();
void stopAPAndServer();

// Mesh communication functions
void sendMeshNotification(const Hit &hit);
void sendTrackerMeshUpdate();
void sendMeshCommand(const String &command);
void processMeshMessage(const String &message);
void processUSBToMesh();
void setNodeId(const String &id);
String getNodeId();