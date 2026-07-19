#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include "scanner.h"

// T114 v2 rate limiter for Serial Module
// Rebalanced (Phase 4): ~167 B/s sustained, 1 KB burst. Consumer task owns inter-frame pacing via vTaskDelayUntil.
class SerialRateLimiter {
private:
    static const uint32_t MAX_TOKENS = 1000;
    static const uint32_t REFILL_INTERVAL = 3000;
    static const uint32_t TOKENS_PER_REFILL = 500;

    uint32_t tokens;
    unsigned long lastRefill;

public:
    SerialRateLimiter();
    bool canSend(size_t messageLength);
    void consume(size_t messageLength);
    void refillTokens();
    void flush();
    uint32_t available() const { return tokens; }
    static constexpr uint32_t capacity() { return MAX_TOKENS; }
};

// Mesh TX priority classes (Phase 2). CTRL preempts EVENT preempts BULK; CTRL/EVENT may evict back-of-BULK on enqueue-full.
enum MeshPriority : uint8_t {
    PRIO_CONTROL = 0,
    PRIO_EVENT   = 1,
    PRIO_BULK    = 2,
    PRIO_DEFAULT = PRIO_BULK,
};

bool sendToSerial1(const String &message, bool canDelay = true);
bool meshEnqueue(const String &msg, bool priority = false);
bool meshEnqueuePrio(const String &msg, MeshPriority prio);
void meshTxFlushQueue();
uint32_t meshTxQueueDepth();
uint32_t meshMsgUnits(const String &msg);
uint32_t meshTxDroppedCount();
enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

// Headless has no SoftAP; AP_CHANNEL is the sentinel's default pin channel.
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif

extern const int MAX_MESH_SIZE;
extern SerialRateLimiter rateLimiter;
extern SemaphoreHandle_t serial1Mutex;
extern bool meshEnabled;
extern bool hbEnabled;
extern uint32_t hbInterval;
extern bool vibrationEnabled;

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
