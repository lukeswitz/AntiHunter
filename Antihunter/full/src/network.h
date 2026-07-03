#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
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
};

// Mesh TX priority classes (Phase 2).
// CONTROL preempts EVENT preempts BULK at drain time, and CONTROL/EVENT may evict back-of-BULK on enqueue-full.
enum MeshPriority : uint8_t {
    PRIO_CONTROL = 0,  // triangulation T_F/T_C/T_D, *_ACK, TRI_*, TRIANGULATE_*
    PRIO_EVENT   = 1,  // ATTACK, DEAUTH, DETECT, EAPOL, HSHK, KARMA, BLETRACK, VIBRATION, GPS, RTC_SYNC, STARTUP, Target
    PRIO_BULK    = 2,  // DEVICE, SCAN_DONE, heartbeat, default
    PRIO_DEFAULT = PRIO_BULK,
};

bool sendToSerial1(const String &message, bool canDelay = true);
bool meshEnqueue(const String &msg, bool priority = false);
bool meshEnqueuePrio(const String &msg, MeshPriority prio);
void meshTxFlushQueue();
uint32_t meshTxQueueDepth();
uint32_t meshTxDroppedCount();
enum ScanMode { SCAN_WIFI, SCAN_BLE, SCAN_BOTH };

constexpr int MAX_MESH_SIZE = 200;  // T114 tests allow 200char/3s in sequence
extern SerialRateLimiter rateLimiter;
extern SemaphoreHandle_t serial1Mutex;
extern std::atomic<bool> g_eraseWipeBusy;
extern AsyncWebServer *server;
extern bool meshEnabled;
extern bool hbEnabled;
extern uint32_t hbInterval;
extern bool vibrationEnabled;
extern volatile uint32_t apScanSuppressUntilMs;

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS  
#define AP_PASS "antihunt3r123"
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