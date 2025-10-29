#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include "scanner.h"

// T114 v2 rate limiter for Serial Module
class SerialRateLimiter {
private:
    static const uint32_t MAX_TOKENS = 200;
    static const uint32_t REFILL_INTERVAL = 1000;
    static const uint32_t TOKENS_PER_REFILL = 200;
    
    uint32_t tokens;
    unsigned long lastRefill;
    
public:
    SerialRateLimiter();
    bool canSend(size_t messageLength);
    void consume(size_t messageLength);
    void refillTokens();
    uint32_t waitTime(size_t messageLength);
    void flush();
};

bool sendToSerial1(const String &message, bool canDelay = true);
enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

extern SerialRateLimiter rateLimiter;
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

// Network and Web Server functions
void initializeNetwork();
void initializeMesh();
void startWebServer();

// Mesh communication
void sendMeshNotification(const Hit &hit);
void sendMeshCommand(const String &command);
void processMeshMessage(const String &message);
void processUSBToMesh();
void setNodeId(const String &id);
String getNodeId();
extern unsigned long meshSendInterval;
void setMeshSendInterval(unsigned long interval);
unsigned long getMeshSendInterval();