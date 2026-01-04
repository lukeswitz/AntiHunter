#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include "scanner.h"

// T114 v2 rate limiter for Serial Module
class SerialRateLimiter {
private:
    static const uint32_t MAX_TOKENS = 200;
    static const uint32_t REFILL_INTERVAL = 3000;
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

extern const int MAX_MESH_SIZE;
extern SerialRateLimiter rateLimiter;
extern bool meshEnabled;

// Mesh communication
void initializeNetwork();
void initializeMesh();
void sendMeshNotification(const Hit &hit);
void sendMeshCommand(const String &command);
void processMeshMessage(const String &message);
void processUSBToMesh();
void setNodeId(const String &id);
String getNodeId();
extern unsigned long meshSendInterval;
void setMeshSendInterval(unsigned long interval);
unsigned long getMeshSendInterval();