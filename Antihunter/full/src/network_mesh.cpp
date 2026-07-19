// network_mesh.cpp - mesh subsystem extracted from network.cpp
#include "network.h"
#include "baseline.h"
#include "triangulation.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include "detect.h"
#include <AsyncTCP.h>
#include <RTClib.h>
#include <esp_timer.h>
#include <algorithm>
#include <deque>

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_coexist.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
}


// --- shared globals defined elsewhere (mirrors network.cpp externs) ---
extern std::atomic<bool> scanning;
extern std::atomic<int> totalHits;
extern UniqueMacsSet uniqueMacs;
extern Preferences prefs;
extern std::atomic<bool> stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t workerTaskHandle;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void parseChannelsCSV(const String &csv);
extern void randomizeMacAddress();

// --- mesh-only state (moved from network.cpp) ---
static unsigned long lastMeshSend = 0;
static String nodeId = "";
// Per-MAC deduplication tracking for mesh notifications
struct MeshTargetState {
    unsigned long lastSent;
    int8_t lastRssi;
    float lastLat;
    float lastLon;
    bool hadGPS;
};
static std::map<uint64_t, MeshTargetState> meshTargetStates;
const int RSSI_CHANGE_THRESHOLD = 5;  // dBm
const float GPS_CHANGE_THRESHOLD = 0.0001;  // ~10 meters
const unsigned long PER_TARGET_MIN_INTERVAL = 30000;  // 30 seconds per target

// Mesh UART Message Sender
void sendMeshNotification(const Hit &hit) {
    if (triangulationActive) return;
    if (!meshEnabled) return;

    // Convert MAC to uint64_t for map lookup
    uint64_t macKey = 0;
    for (int i = 0; i < 6; i++) {
        macKey = (macKey << 8) | hit.mac[i];
    }

    unsigned long now = millis();
    bool shouldSend = false;

    // Check if we've seen this MAC before
    auto it = meshTargetStates.find(macKey);
    if (it == meshTargetStates.end()) {
        shouldSend = true;
    } else {
        const MeshTargetState &state = it->second;
        if (now - state.lastSent < PER_TARGET_MIN_INTERVAL) {
            int rssiDelta = abs(hit.rssi - state.lastRssi);

            if (rssiDelta >= RSSI_CHANGE_THRESHOLD) {
                shouldSend = true;
            } else if (gpsValid && state.hadGPS) {
                float latDelta = abs(gpsLat - state.lastLat);
                float lonDelta = abs(gpsLon - state.lastLon);
                if (latDelta >= GPS_CHANGE_THRESHOLD || lonDelta >= GPS_CHANGE_THRESHOLD) {
                    shouldSend = true;
                }
            } else if (gpsValid && !state.hadGPS) {
                shouldSend = true;  // GPS just became available
            }
        } else {
            shouldSend = true;
        }
    }

    // Wait our turn
    if (!shouldSend) {
      return;
    }

    // Respect global mesh send rate limit
    if (now - lastMeshSend < meshSendInterval) {
        return;
    }
    lastMeshSend = now;

    // Update the state for this MAC
    MeshTargetState newState;
    newState.lastSent = now;
    newState.lastRssi = hit.rssi;
    newState.lastLat = gpsValid ? gpsLat : 0.0;
    newState.lastLon = gpsValid ? gpsLon : 0.0;
    newState.hadGPS = gpsValid;
    if (meshTargetStates.size() >= 1000 && meshTargetStates.find(macKey) == meshTargetStates.end()) {
        for (auto sit = meshTargetStates.begin(); sit != meshTargetStates.end(); ) {
            if (now - sit->second.lastSent > (PER_TARGET_MIN_INTERVAL * 10)) sit = meshTargetStates.erase(sit);
            else ++sit;
        }
    }
    meshTargetStates[macKey] = newState;

    // Build and send the message
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             hit.mac[0], hit.mac[1], hit.mac[2], hit.mac[3], hit.mac[4], hit.mac[5]);

    String cleanName = "";
    if (strlen(hit.name) > 0 && strcmp(hit.name, "WiFi") != 0) {
        for (size_t i = 0; i < strlen(hit.name) && i < 32; i++) {
            char c = hit.name[i];
            if (c >= 32 && c <= 126) {
                cleanName += c;
            }
        }
    }

    char mesh_msg[MAX_MESH_SIZE];
    memset(mesh_msg, 0, sizeof(mesh_msg));

    String baseMsg = String(nodeId) + ": Target: " + String(mac_str) +
                     " RSSI:" + String(hit.rssi) +
                     " Type:" + (hit.isBLE ? "BLE" : "WiFi");

    if (cleanName.length() > 0) {
        baseMsg += " Name:" + cleanName;
    }

    if (gpsValid) {
        baseMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }

    int msg_len = snprintf(mesh_msg, sizeof(mesh_msg), "%s", baseMsg.c_str());

    if (msg_len > 0 && msg_len <= (int)sizeof(mesh_msg) - 1) {
        Serial.printf("[MESH] %s\n", mesh_msg);
        meshEnqueuePrio(String(mesh_msg), PRIO_EVENT);
    }
}

struct MeshTxItem {
    char msg[MAX_MESH_SIZE + 8];
    MeshPriority prio;
};

// Phase 2: three priority queues replace the single FIFO. Drain order CTRL > EVENT > BULK.
// Total depth 256 (16+32+208) matches the prior MESH_TX_QUEUE_DEPTH = 256 PSRAM footprint.
static const uint16_t MESH_Q_DEPTH[3] = {16, 32, 208};
static QueueHandle_t meshQ[3] = {nullptr, nullptr, nullptr};

// Legacy symbol kept for compatibility — points at BULK queue for any external reader.
QueueHandle_t meshTxQueue = nullptr;
TaskHandle_t meshTxTaskHandle = nullptr;
std::atomic<uint32_t> meshTxDepthHigh(0);
std::atomic<uint32_t> meshTxSentLifetime(0);
std::atomic<uint32_t> meshTxDroppedFull(0);

// Phase 1: consumer-task tick. ~80 ms inter-frame cadence, leaky-bucket pacing.
// 80 ms * 50 B/msg ≈ 625 B/s ceiling, well under 115200 baud and within token-bucket sustained 167 B/s.
static uint32_t meshTxTickMs = 80;
static const uint32_t MESH_BULK_INTERVAL_MS = 2200;

static MeshPriority classifyMeshMessage(const String &msg) {
    // Fast path: DEVICE-discovery dumps dominate the queue. Up-front check skips the 29-keyword scan
    // for the common case AND prevents an SSID/name containing a keyword (a network named "ATTACK")
    // from misclassifying a bulk device row into the EVENT queue. No control/event frame contains "DEVICE:".
    if (msg.indexOf("DEVICE:") >= 0) return PRIO_BULK;
    // CONTROL: triangulation control + data frames (parsed/honored by peer triangulation FSM)
    if (msg.indexOf("T_F:") >= 0 || msg.indexOf("T_C:") >= 0 || msg.indexOf("T_D:") >= 0 ||
        msg.indexOf("STOP_ACK") >= 0 || msg.indexOf("TRI_START_ACK") >= 0 ||
        msg.indexOf("TRIANGULATE_START") >= 0 || msg.indexOf("TRIANGULATE_STOP") >= 0 ||
        msg.indexOf("TRI_CYCLE_START") >= 0) {
        return PRIO_CONTROL;
    }
    // EVENT: alerts, detections, status changes — caller may also pass priority=true to land here
    if (msg.indexOf("ATTACK") >= 0 || msg.indexOf("DEAUTH") >= 0 || msg.indexOf("DETECT") >= 0 ||
        msg.indexOf("EAPOL") >= 0 || msg.indexOf("HSHK") >= 0 || msg.indexOf("KARMA") >= 0 ||
        msg.indexOf("BLETRACK") >= 0 || msg.indexOf("VIBRATION") >= 0 || msg.indexOf("GPS:") >= 0 ||
        msg.indexOf("RTC_SYNC") >= 0 || msg.indexOf("STARTUP") >= 0 || msg.indexOf("Target:") >= 0 ||
        msg.indexOf("EVILTWIN") >= 0 || msg.indexOf("PMKID") >= 0 || msg.indexOf("OWE_ABUSE") >= 0 ||
        msg.indexOf("KRACK") >= 0 || msg.indexOf("PWNAGOTCHI") >= 0 || msg.indexOf("PROBE_FLOOD") >= 0 ||
        msg.indexOf("BLE_ATTACK") >= 0 || msg.indexOf("ATTACKER_HUNT") >= 0 || msg.indexOf("TRK_LINK") >= 0 ||
        msg.indexOf("IDHASH") >= 0 || msg.indexOf("BLOOM") >= 0 || msg.indexOf("RECON") >= 0 ||
        msg.indexOf("FRAGATTACK") >= 0 || msg.indexOf("SSID_CONFUSION") >= 0 || msg.indexOf("SAE_DOS") >= 0 ||
        msg.indexOf("BLE_MALFORMED") >= 0) {
        return PRIO_EVENT;
    }
    // BULK: DEVICE, SCAN_DONE, heartbeat, any other periodic dump
    return PRIO_BULK;
}

uint32_t meshMsgUnits(const String &msg) {
    int count = 0, idx = 0;
    while ((idx = msg.indexOf("DEVICE:", idx)) >= 0) { count++; idx += 7; }
    return count > 0 ? (uint32_t)count : 1;
}

bool meshEnqueuePrio(const String &msg, MeshPriority prio) {
    if (msg.length() == 0 || msg.length() > MAX_MESH_SIZE) return false;
    if (meshQ[prio] == nullptr) {
        return sendToSerial1(msg, false);
    }
    MeshTxItem item;
    strncpy(item.msg, msg.c_str(), sizeof(item.msg) - 1);
    item.msg[sizeof(item.msg) - 1] = '\0';
    item.prio = prio;

    bool enqueued = (xQueueSend(meshQ[prio], &item, 0) == pdTRUE);

    // Review fix C (corrected): cross-queue eviction was incorrect — evicting BULK does NOT
    // free a slot in meshQ[CTRL]/meshQ[EVENT] since they're independent FreeRTOS queues.
    // The right backpressure here is to let the consumer drain. CTRL=16/EVENT=32 depths are
    // sized so this is rare; meshTxDroppedFull surfaces it when it does happen.

    if (!enqueued) {
        meshTxDroppedFull.fetch_add(1);
        Serial.printf("[MESH] Queue full (prio=%u), dropped: %s\n", (unsigned)prio, msg.substring(0, 50).c_str());
        return false;
    }

    meshDrainTotal.fetch_add(meshMsgUnits(msg));
    uint32_t depth = meshTxQueueDepth();
    uint32_t prev = meshTxDepthHigh.load();
    while (depth > prev && !meshTxDepthHigh.compare_exchange_weak(prev, depth)) {}
    meshTxDraining.store(depth > 0);
    return true;
}

bool meshEnqueue(const String &msg, bool priority) {
    // Legacy 2-arg API: classify by content. `priority=true` forces CONTROL only if the message
    // is recognized as a control frame; otherwise classifier picks (EVENT for alerts, BULK for periodic).
    MeshPriority p = classifyMeshMessage(msg);
    if (priority && p == PRIO_BULK) {
        // Caller signaled priority but classifier sees no control/event keyword — treat as EVENT
        p = PRIO_EVENT;
    }
    return meshEnqueuePrio(msg, p);
}

uint32_t meshTxQueueDepth() {
    uint32_t d = 0;
    for (int i = 0; i < 3; i++) {
        if (meshQ[i]) d += uxQueueMessagesWaiting(meshQ[i]);
    }
    return d;
}

uint32_t meshTxDroppedCount() {
    return meshTxDroppedFull.load();
}

void meshTxFlushQueue() {
    for (int i = 0; i < 3; i++) {
        if (meshQ[i]) xQueueReset(meshQ[i]);
    }
    meshTxDepthHigh.store(0);
    meshTxDraining.store(false);
    meshDrainSent.store(0);
    meshDrainTotal.store(0);
    Serial.println("[MESH] TX queue flushed");
}

static bool drainOne(QueueHandle_t q) {
    if (q == nullptr) return false;
    MeshTxItem item;
    if (xQueueReceive(q, &item, 0) != pdTRUE) return false;
    String msg(item.msg);
    uint32_t units = meshMsgUnits(msg);
    // canDelay=false: sendToSerial1 no longer blocks on rate-limit; if tokens insufficient it drops + counts.
    // Consumer task owns pacing via vTaskDelayUntil below.
    if (sendToSerial1(msg, false)) {
        meshTxSentLifetime.fetch_add(1);
        meshDrainSent.fetch_add(units);
    } else {
        // Review fix B: send failed (rate-limit/buf-full/mutex timeout). The dequeue already
        // happened so msg is lost. Keep meshDrainTotal in sync so the end-of-drain cleanup
        // (sent >= total) fires correctly and depthHigh/Sent/Total reset.
        uint32_t total = meshDrainTotal.load();
        while (total >= units && !meshDrainTotal.compare_exchange_weak(total, total - units)) {}
    }
    return true;
}

static void meshTxTask(void *pv) {
    (void)pv;
    Serial.println("[MESH] TX task started");
    for (;;) {
        if (stopMeshDrain.load()) {
            meshTxFlushQueue();
            stopMeshDrain.store(false);
        }
        // Drain priority order: CONTROL preempts EVENT preempts BULK.
        // CONTROL (triangulation) is latency-critical and bypasses the send interval.
        // EVENT (alerts) is paced at meshSendInterval. BULK (device dumps) drains fast at
        // MESH_BULK_INTERVAL_MS so a big device-scan backlog clears quickly; the LoRa rate
        // limiter still caps physical throughput so frames are not dropped.
        bool drainedControl = drainOne(meshQ[PRIO_CONTROL]);
        bool drainedEvent = false, drainedBulk = false;
        if (!drainedControl) {
            drainedEvent = drainOne(meshQ[PRIO_EVENT]);
            if (!drainedEvent) drainedBulk = drainOne(meshQ[PRIO_BULK]);
        }

        uint32_t depth = meshTxQueueDepth();
        if (depth == 0) {
            meshTxDraining.store(false);
            uint32_t sent = meshDrainSent.load();
            uint32_t total = meshDrainTotal.load();
            if (sent >= total && total > 0 && !scanning.load()) {
                meshTxDepthHigh.store(0);
                meshDrainSent.store(0);
                meshDrainTotal.store(0);
            }
        } else {
            meshTxDraining.store(true);
        }

        // CONTROL fast; EVENT honors meshSendInterval; BULK drains at MESH_BULK_INTERVAL_MS.
        uint32_t waitMs;
        if (drainedControl) waitMs = meshTxTickMs;
        else if (drainedEvent) waitMs = (uint32_t)meshSendInterval;
        else if (drainedBulk) waitMs = MESH_BULK_INTERVAL_MS;
        else waitMs = meshTxTickMs;
        if (waitMs < meshTxTickMs) waitMs = meshTxTickMs;
        vTaskDelay(pdMS_TO_TICKS(waitMs));
    }
}

void initializeMesh() {
    if (serial1Mutex == nullptr) {
        serial1Mutex = xSemaphoreCreateMutex();
    }

    Serial1.end();
    delay(100);

    Serial1.setRxBufferSize(2048);
    Serial1.setTxBufferSize(4096);
    Serial1.begin(115200, SERIAL_8N1, MESH_RX_PIN, MESH_TX_PIN);
    Serial1.setTimeout(100);

    delay(100);
    while (Serial1.available()) {
        Serial1.read();
    }

    delay(500);

    for (int i = 0; i < 3; i++) {
        if (meshQ[i] == nullptr) {
            meshQ[i] = xQueueCreateWithCaps(MESH_Q_DEPTH[i], sizeof(MeshTxItem), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (meshQ[i] == nullptr) {
                Serial.printf("[MESH] PSRAM queue alloc failed for prio=%d, falling back to internal heap\n", i);
                meshQ[i] = xQueueCreate(MESH_Q_DEPTH[i], sizeof(MeshTxItem));
            }
        }
    }
    // Legacy alias points at BULK queue (the prior single-queue behavior most closely matched BULK semantics).
    meshTxQueue = meshQ[PRIO_BULK];

    if (meshTxTaskHandle == nullptr && meshQ[PRIO_BULK] != nullptr) {
        xTaskCreatePinnedToCore(meshTxTask, "meshTx", 6144, nullptr, 1, &meshTxTaskHandle, 1);
    }

    Serial.println("[MESH] UART initialized");
    Serial.printf("[MESH] Config: 115200 baud on GPIO RX=%d TX=%d, queues=[ctrl:%u event:%u bulk:%u] tick=%ums\n",
                  MESH_RX_PIN, MESH_TX_PIN, MESH_Q_DEPTH[0], MESH_Q_DEPTH[1], MESH_Q_DEPTH[2], meshTxTickMs);
}

// --- Command Handlers ---

static void handleConfigChannels(const String &command)
{
  String channels = command.substring(16);
  prefs.putString("channels", channels);
  if (!(scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive)) {
      parseChannelsCSV(channels);
  }
  saveConfiguration();
  Serial.printf("[MESH] Updated channels: %s\n", channels.c_str());
  sendToSerial1(nodeId + ": CONFIG_ACK:CHANNELS:" + channels, true);
}

static void handleConfigTargets(const String &command)
{
  String targets = command.substring(15);
  prefs.putString("maclist", targets);
  if (!(scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive)) {
      saveTargetsList(targets);
  }
  Serial.printf("[MESH] Updated targets list\n");
  sendToSerial1(nodeId + ": CONFIG_ACK:TARGETS:OK", true);
}

static void handleConfigDedupTtl(const String &command)
{
  long ttl = command.substring(17).toInt();
  if (ttl < 0 || ttl > (long)MESH_DEDUP_TTL_MAX_S) {
    sendToSerial1(nodeId + ": CONFIG_ACK:DEDUP_TTL:INVALID", true);
    return;
  }
  setMeshDedupTtlSec((uint32_t)ttl);
  prefs.putUInt("meshDedupTtl", (uint32_t)ttl);
  saveConfiguration();
  Serial.printf("[MESH] Mesh dedup TTL set to %lds\n", ttl);
  sendToSerial1(nodeId + ": CONFIG_ACK:DEDUP_TTL:" + String(ttl), true);
}

static void handleConfigNodeId(const String &command)
{
  Serial.printf("[DEBUG] CONFIG_NODEID block ENTERED\n");
  String nodeID = command.substring(14);
  Serial.printf("[DEBUG] nodeID='%s' length=%d\n", nodeID.c_str(), nodeID.length());

  if (nodeID.length() >= 2 && nodeID.length() <= 5) {
    bool valid = true;
    for (int i = 0; i < nodeID.length(); i++) {
      if (!isalnum(nodeID[i])) {
        valid = false;
        break;
      }
    }

    if (valid) {
      setNodeId(nodeID);
      saveConfiguration();
      Serial.printf("[MESH] Updated Node ID\n");
      sendToSerial1(nodeId + ": CONFIG_ACK:NODE_ID:OK", true);
    } else {
      Serial.printf("[DEBUG] INVALID_CHARS\n");
      sendToSerial1(nodeId + ": CONFIG_ACK:NODE_ID:INVALID_CHARS", true);
    }
  } else {
    Serial.printf("[DEBUG] INVALID_LENGTH (got %d)\n", nodeID.length());
    sendToSerial1(nodeId + ": CONFIG_ACK:NODE_ID:INVALID_LENGTH", true);
  }
}

static void handleConfigRssi(const String &command)
{
  String rssiThresh = command.substring(12);
  int value = rssiThresh.toInt();
  if (value >= -128 && value <= -10) {
    setGlobalRssiThreshold((int8_t)value);
    saveConfiguration();
    Serial.printf("[MESH] Updated RSSI threshold\n");
    sendToSerial1(nodeId + ": CONFIG_ACK:RSSI:OK", true);
  } else {
    sendToSerial1(nodeId + ": CONFIG_ACK:RSSI:INVALID_RANGE", true);
  }
}

static void handleScanStart(const String &command)
{
  String params = command.substring(11);
  int modeDelim = params.indexOf(':');
  int secsDelim = params.indexOf(':', modeDelim + 1);
  int channelDelim = params.indexOf(':', secsDelim + 1);

  if (modeDelim > 0 && secsDelim > 0)
  {
    int mode = params.substring(0, modeDelim).toInt();
    int secs = params.substring(modeDelim + 1, secsDelim).toInt();
    if (secs < 0) secs = 0;
    if (secs > 86400) secs = 86400;
    String channels = (channelDelim > 0) ? params.substring(secsDelim + 1, channelDelim) : "1,6,11";
    bool forever = (channelDelim > 0 && params.substring(channelDelim + 1) == "FOREVER");

    if (mode >= 0 && mode <= 2)
    {
      if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
        Serial.println("[MESH] Radio busy, rejecting SCAN_START");
        sendToSerial1(nodeId + ": SCAN_ACK:BUSY", true);
      } else {
        currentScanMode = (ScanMode)mode;
        parseChannelsCSV(channels);
        stopRequested = false;
        scanning = true;
        ahCreateTask(listScanTask, "scan", 8192,
                                reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
        Serial.printf("[MESH] Started scan via mesh command\n");
        sendToSerial1(nodeId + ": SCAN_ACK:STARTED", true);
      }
    }
  }
}

static void handleBaselineStart(const String &command)
{
  String params = command.substring(15);
  int durationDelim = params.indexOf(':');
  int secs = params.substring(0, durationDelim > 0 ? durationDelim : params.length()).toInt();
  bool forever = (durationDelim > 0 && params.substring(durationDelim + 1) == "FOREVER");

  if (secs < 0)
    secs = 0;
  if (secs > 86400)
    secs = 86400;
  // Minimum 60 seconds to prevent rapid cycling and message flooding
  if (!forever && secs > 0 && secs < 60) {
    Serial.printf("[MESH] Warning: baseline duration %ds too short, using 60s minimum\n", secs);
    secs = 60;
  }

  if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
    Serial.println("[MESH] Radio busy, rejecting BASELINE_START");
    sendToSerial1(nodeId + ": BASELINE_ACK:BUSY", true);
  } else {
    stopRequested = false;
    scanning = true;
    ahCreateTask(baselineDetectionTask, "baseline", 12288,
                            reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
    Serial.printf("[MESH] Started baseline detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": BASELINE_ACK:STARTED", true);
  }
}

static void handleBaselineStatus(const String &command)
{
  (void)command;
  char status_msg[MAX_MESH_SIZE];

  bool snapScanning;
  bool snapPhase1Complete;
  bool snapEstablished;
  uint32_t snapDeviceCount;
  uint32_t snapAnomalyCount;
  {
    std::lock_guard<std::mutex> lock(baselineMutex);
    snapScanning = baselineStats.isScanning;
    snapPhase1Complete = baselineStats.phase1Complete;
    snapEstablished = baselineEstablished;
    snapDeviceCount = baselineDeviceCount;
    snapAnomalyCount = anomalyCount;
  }

  const char* phase1Status;
  if (!snapScanning) {
    phase1Status = "INACTIVE";
  } else if (!snapPhase1Complete) {
    phase1Status = "ACTIVE";
  } else {
    phase1Status = "COMPLETE";
  }

  snprintf(status_msg, sizeof(status_msg),
           "%s: BASELINE_STATUS: Scanning:%s Established:%s Devices:%u Anomalies:%u Phase1:%s",
           nodeId.c_str(),
           snapScanning ? "YES" : "NO",
           snapEstablished ? "YES" : "NO",
           snapDeviceCount,
           snapAnomalyCount,
           phase1Status);
  sendToSerial1(String(status_msg), true);
}

static void handleDeviceScanStart(const String &command)
{
  String params = command.substring(18);
  int modeDelim = params.indexOf(':');
  int mode = params.substring(0, modeDelim > 0 ? modeDelim : params.length()).toInt();
  int secs = 60;
  bool forever = false;

  if (modeDelim > 0)
  {
    int secsDelim = params.indexOf(':', modeDelim + 1);
    secs = params.substring(modeDelim + 1, secsDelim > 0 ? secsDelim : params.length()).toInt();
    if (secsDelim > 0 && params.substring(secsDelim + 1) == "FOREVER")
    {
      forever = true;
    }
  }

  if (secs < 0) secs = 0;
  if (secs > 86400) secs = 86400;

  if (mode >= 0 && mode <= 2)
  {
    if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
      Serial.println("[MESH] Radio busy, rejecting DEVICE_SCAN_START");
      sendToSerial1(nodeId + ": DEVICE_SCAN_ACK:BUSY", true);
    } else {
      currentScanMode = (ScanMode)mode;
      stopRequested = false;
      scanning = true;
      ahCreateTask(snifferScanTask, "sniffer", 12288,
                              reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
      Serial.printf("[MESH] Started device scan via mesh command (%ds)\n", secs);
      sendToSerial1(nodeId + ": DEVICE_SCAN_ACK:STARTED", true);
    }
  }
}

static void handleDroneStart(const String &command)
{
  String params = command.substring(12);
  int secs = params.toInt();
  bool forever = false;

  int colonPos = params.indexOf(':');
  if (colonPos > 0)
  {
    secs = params.substring(0, colonPos).toInt();
    if (params.substring(colonPos + 1) == "FOREVER")
    {
      forever = true;
    }
  }

  if (secs < 0) secs = 0;
  if (secs > 86400) secs = 86400;

  if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
    Serial.println("[MESH] Radio busy, rejecting DRONE_START");
    sendToSerial1(nodeId + ": DRONE_ACK:BUSY", true);
  } else {
    currentScanMode = SCAN_WIFI;
    stopRequested = false;
    scanning = true;
    ahCreateTask(droneDetectorTask, "drone", 12288,
                            reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
    Serial.printf("[MESH] Started drone detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": DRONE_ACK:STARTED", true);
  }
}

static void handleDeauthStart(const String &command)
{
  String params = command.substring(13);
  int secs = params.toInt();
  bool forever = false;

  int colonPos = params.indexOf(':');
  if (colonPos > 0)
  {
    secs = params.substring(0, colonPos).toInt();
    if (params.substring(colonPos + 1) == "FOREVER")
    {
      forever = true;
    }
  }

  if (secs < 0) secs = 0;
  if (secs > 86400) secs = 86400;

  if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
    Serial.println("[MESH] Radio busy, rejecting DEAUTH_START");
    sendToSerial1(nodeId + ": DEAUTH_ACK:BUSY", true);
  } else {
    stopRequested = false;
    scanning = true;
    ahCreateTask(blueTeamTask, "blueteam", 12288,
                            reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &blueTeamTaskHandle, 1);
    Serial.printf("[MESH] Started deauth detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": DEAUTH_ACK:STARTED", true);
  }
}

static void handleRandomizationStart(const String &command)
{
  String params = command.substring(20);
  int modeDelim = params.indexOf(':');
  int mode = params.substring(0, modeDelim > 0 ? modeDelim : params.length()).toInt();
  int secs = 60;
  bool forever = false;

  if (modeDelim > 0)
  {
    int secsDelim = params.indexOf(':', modeDelim + 1);
    secs = params.substring(modeDelim + 1, secsDelim > 0 ? secsDelim : params.length()).toInt();
    if (secsDelim > 0 && params.substring(secsDelim + 1) == "FOREVER")
    {
      forever = true;
    }
  }

  if (secs < 0) secs = 0;
  if (secs > 86400) secs = 86400;

  if (mode >= 0 && mode <= 2)
  {
    if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
      Serial.println("[MESH] Radio busy, rejecting RANDOMIZATION_START");
      sendToSerial1(nodeId + ": RANDOMIZATION_ACK:BUSY", true);
    } else {
      currentScanMode = (ScanMode)mode;
      stopRequested = false;
      scanning = true;
      ahCreateTask(randomizationDetectionTask, "randdetect", 8192,
                              reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
      Serial.printf("[MESH] Started randomization detection via mesh command (%ds)\n", secs);
      sendToSerial1(nodeId + ": RANDOMIZATION_ACK:STARTED", true);
    }
  }
}

static void handleProbeStart(const String &command)
{
  // Format: PROBE_START:<mode>:<secs>[:FOREVER][:+ALL]
  // Flags after secs are order-independent.
  int fieldIdx = 0;
  int mode = 0;
  int secs = 60;
  bool forever = false;
  bool broadcastAll = false;

  // Split on ':' starting after "PROBE_START:"
  int pos = 12;
  while (pos < (int)command.length()) {
    int sep = command.indexOf(':', pos);
    String field = (sep >= 0) ? command.substring(pos, sep) : command.substring(pos);
    field.trim();

    if (fieldIdx == 0) {
      mode = field.toInt();
    } else if (fieldIdx == 1) {
      secs = field.toInt();
    } else {
      String upper = field;
      upper.toUpperCase();
      if (upper == "FOREVER") forever = true;
      else if (upper == "+ALL") broadcastAll = true;
    }
    fieldIdx++;
    if (sep < 0) break;
    pos = sep + 1;
  }

  if (secs < 1 && !forever) secs = 1;
  if (secs > 86400) secs = 86400;

  if (mode < 0 || mode > 2) return;

  if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
    Serial.println("[MESH] Radio busy, rejecting PROBE_START");
    sendToSerial1(nodeId + ": PROBE_ACK:BUSY", true);
  } else {
    currentScanMode = static_cast<ScanMode>(mode);
    stopRequested = false;
    scanning = true;
    probeBroadcastAll.store(broadcastAll, std::memory_order_relaxed);
    ahCreateTask(probeDetectionTask, "probedet", 8192,
                            reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
    Serial.printf("[MESH] Started probe detection via mesh (%ds, all=%d)\n", secs, broadcastAll);
    sendToSerial1(nodeId + ": PROBE_ACK:STARTED", true);
  }
}

static void handleProbeStop(const String &command)
{
  (void)command;
  stopRequested = true;
  Serial.println("[MESH] Probe stop command received via mesh");
  sendToSerial1(nodeId + ": PROBE_ACK:STOPPED", true);
}

static void handleProbeHit(const String &command)
{
  // Received a PROBE_HIT from another node — log it to terminal
  // Full message format: "PROBE_HIT AA:BB:CC:DD:EE:FF Apple RSSI=-42 CH=6 SSID=\"HomeNet\""
  String payload = command.substring(10);
  Serial.printf("[MESH] PROBE_HIT received: %s\n", payload.c_str());
}

static void handleStop(const String &command)
{
  (void)command;
  stopRequested = true;
  if (meshTxDraining.load() || meshTxQueueDepth() > 0) {
    stopMeshDrain.store(true);
  }
  Serial.println("[MESH] Stop command received via mesh");
  sendToSerial1(nodeId + ": STOP_ACK:OK", true);
}

static void handleStatus(const String &command)
{
  (void)command;
  float esp_temp = temperatureRead();
  String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE"
                                                                                            : "WiFi+BLE";
  uint32_t uptime_secs = millis() / 1000;
  uint32_t uptime_mins = uptime_secs / 60;
  uint32_t uptime_hours = uptime_mins / 60;
  char status_msg[MAX_MESH_SIZE];
  int written = snprintf(status_msg, sizeof(status_msg),
                        "%s: STATUS: Mode:%s Scan:%s Hits:%d Temp:%.1fC Up:%02d:%02d:%02d",
                        nodeId.c_str(),
                        modeStr.c_str(),
                        scanning.load() ? "ACTIVE" : "IDLE",
                        totalHits.load(),
                        esp_temp,
                        (int)uptime_hours, (int)(uptime_mins % 60), (int)(uptime_secs % 60));
  if (gpsValid && written > 0 && written <= sizeof(status_msg) - 1)
  {
    float hdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.9;
    snprintf(status_msg + written, sizeof(status_msg) - written,
            " GPS:%.6f,%.6f HDOP=%.1f",
            gpsLat, gpsLon, hdop);
  }
  sendToSerial1(String(status_msg), true);
}

static void handleVibrationStatus(const String &command)
{
  (void)command;
  char buf[64];
  if (lastVibrationTime > 0) {
    snprintf(buf, sizeof(buf), "%s Last:%lus",
             vibrationEnabled ? "ENABLED" : "DISABLED",
             (millis() - lastVibrationTime) / 1000);
  } else {
    snprintf(buf, sizeof(buf), "%s Last:never",
             vibrationEnabled ? "ENABLED" : "DISABLED");
  }
  sendToSerial1(nodeId + ": VIBRATION_STATUS: " + buf, true);
}

static void setVibrationEnabled(bool enabled)
{
  vibrationEnabled = enabled;
  lastSaveTime = 0;
  saveConfiguration();
  const char *label = enabled ? "enabled" : "disabled";
  Serial.printf("[VIB] Vibration broadcasts %s\n", label);
  sendToSerial1(nodeId + (enabled ? ": VIBRATION_ON_ACK:OK" : ": VIBRATION_OFF_ACK:OK"), true);
}

static void handleVibrationOn(const String &command)
{
  (void)command;
  setVibrationEnabled(true);
}

static void handleVibrationOff(const String &command)
{
  (void)command;
  setVibrationEnabled(false);
}

static void handleTriangulateStart(const String &command, const String &targetId)
{
  String params = command.substring(18);
  String myNodeId = getNodeId();
  bool isDirectedToMe = !targetId.isEmpty() && targetId != "ALL" && targetId == myNodeId;

  if (isDirectedToMe) {
    // Parse format: TRIANGULATE_START:target:duration[:rfEnv]
    // Note: target can be MAC (XX:XX:XX:XX:XX:XX) or identity (T-XXXX)

    String target;
    int duration;
    uint8_t rfEnv = RF_ENV_INDOOR;
    int targetEnd = 0;

    // Determine target length based on format
    if (params.startsWith("T-")) {
      // Identity format: T-XXXX:duration[:rfEnv]
      targetEnd = params.indexOf(':', 2);
      if (targetEnd < 0) {
        Serial.println("[TRIANGULATE] Invalid directed command format - no duration");
        return;
      }
    } else {
      // MAC format: XX:XX:XX:XX:XX:XX:duration[:rfEnv] (MAC is 17 chars)
      if (params.length() >= 17 && params.charAt(2) == ':' && params.charAt(5) == ':') {
        targetEnd = 17;
      } else {
        Serial.println("[TRIANGULATE] Invalid directed command format - bad MAC");
        return;
      }
    }

    target = params.substring(0, targetEnd);
    String remainder = params.substring(targetEnd + 1);  // After target:

    float wifiPwr = 1.0f;
    float blePwr = 1.0f;

    int envDelim = remainder.indexOf(':');
    if (envDelim > 0) {
      duration = remainder.substring(0, envDelim).toInt();
      String afterDuration = remainder.substring(envDelim + 1);

      int pwrDelim = afterDuration.indexOf(':');
      if (pwrDelim > 0) {
        rfEnv = afterDuration.substring(0, pwrDelim).toInt();
        String afterRfEnv = afterDuration.substring(pwrDelim + 1);

        int blePwrDelim = afterRfEnv.indexOf(':');
        if (blePwrDelim > 0) {
          wifiPwr = afterRfEnv.substring(0, blePwrDelim).toFloat();
          blePwr = afterRfEnv.substring(blePwrDelim + 1).toFloat();
        } else {
          wifiPwr = afterRfEnv.toFloat();
        }
      } else {
        rfEnv = afterDuration.toInt();
      }

      if (rfEnv > RF_ENV_INDUSTRIAL) rfEnv = RF_ENV_INDOOR;
      if (wifiPwr < 0.1f || wifiPwr > 5.0f) wifiPwr = 1.0f;
      if (blePwr < 0.1f || blePwr > 5.0f) blePwr = 1.0f;
    } else {
      duration = remainder.toInt();
    }

    if (target.length() < 6 || duration <= 0) {
      Serial.printf("[TRIANGULATE] Invalid parameters - target='%s' duration=%d\n",
                   target.c_str(), duration);
      return;
    }

    uint8_t dMac[6];
    if (!parseMac6(target, dMac)) {
      Serial.printf("[TRIANGULATE] Invalid target MAC '%s' - ignoring directed command\n", target.c_str());
      return;
    }

    if (duration < 10) duration = 10;
    if (duration > 3600) duration = 3600;

    setRFEnvironment((RFEnvironment)rfEnv);

    distanceTuning.wifi_multiplier = wifiPwr;
    distanceTuning.ble_multiplier = blePwr;
    distanceTuning.enabled = (wifiPwr != 1.0f || blePwr != 1.0f);

    Serial.printf("[TRIANGULATE] Directed command received - becoming initiator for %s (%ds, rfEnv=%d)\n",
                 target.c_str(), duration, rfEnv);

    // Call startTriangulation which will set up as initiator and broadcast to mesh
    startTriangulation(target, duration);
    return;
  }

  // This is a broadcast message - process as participant (or ignore if we're the initiator)
  // Parse format: TRIANGULATE_START:target:duration[:initiatorNodeId]
  // Note: target can be a MAC (XX:XX:XX:XX:XX:XX with colons) or identity (T-XXXX)

  String target;
  int duration;
  String initiatorNodeId = "";
  int targetEnd = 0;

  // Determine target length based on format
  if (params.startsWith("T-")) {
    targetEnd = params.indexOf(':', 2);
    if (targetEnd < 0) targetEnd = params.length();
  } else {
    if (params.length() >= 17 && params.charAt(2) == ':' && params.charAt(5) == ':') {
      targetEnd = 17;
    } else {
      int colonCount = 0;
      for (int i = 0; i < params.length(); i++) {
        if (params.charAt(i) == ':') {
          colonCount++;
          if (colonCount == 6) {
            targetEnd = i;
            break;
          }
        }
      }
      if (targetEnd == 0) {
        targetEnd = params.indexOf(':');
      }
    }
  }

  target = params.substring(0, targetEnd);
  String remainder = params.substring(targetEnd + 1);

  int durationDelim = remainder.indexOf(':');
  uint8_t rfEnv = RF_ENV_INDOOR;
  float wifiPwr = 1.0f;
  float blePwr = 1.0f;

  if (durationDelim > 0) {
    duration = remainder.substring(0, durationDelim).toInt();
    String afterDuration = remainder.substring(durationDelim + 1);

    int initiatorDelim = afterDuration.indexOf(':');
    if (initiatorDelim > 0) {
      initiatorNodeId = afterDuration.substring(0, initiatorDelim);
      String afterInitiator = afterDuration.substring(initiatorDelim + 1);

      int envDelim = afterInitiator.indexOf(':');
      if (envDelim > 0) {
        rfEnv = afterInitiator.substring(0, envDelim).toInt();
        String afterEnv = afterInitiator.substring(envDelim + 1);

        int blePwrDelim = afterEnv.indexOf(':');
        if (blePwrDelim > 0) {
          wifiPwr = afterEnv.substring(0, blePwrDelim).toFloat();
          blePwr = afterEnv.substring(blePwrDelim + 1).toFloat();
        } else {
          wifiPwr = afterEnv.toFloat();
        }
      } else {
        rfEnv = afterInitiator.toInt();
      }

      if (rfEnv > RF_ENV_INDUSTRIAL) rfEnv = RF_ENV_INDOOR;
      if (wifiPwr < 0.1f || wifiPwr > 5.0f) wifiPwr = 1.0f;
      if (blePwr < 0.1f || blePwr > 5.0f) blePwr = 1.0f;
    } else {
      initiatorNodeId = afterDuration;
    }
  } else {
    duration = remainder.toInt();
  }

  if (duration < 10) duration = 10;
  if (duration > 3600) duration = 3600;

  setRFEnvironment((RFEnvironment)rfEnv);

  distanceTuning.wifi_multiplier = wifiPwr;
  distanceTuning.ble_multiplier = blePwr;
  distanceTuning.enabled = (wifiPwr != 1.0f || blePwr != 1.0f);

  bool isIdentityId = target.startsWith("T-");
  uint8_t macBytes[6];

  if (!isIdentityId) {
    if (!parseMac6(target, macBytes)) {
      Serial.printf("[TRIANGULATE] Invalid MAC format: %s - ignoring command\n", target.c_str());
      return;
    }
  }

  if (workerTaskHandle) {
    stopRequested = true;
    uint32_t triStopWait = millis();
    while (workerTaskHandle && (millis() - triStopWait) < 5000) {
      vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (workerTaskHandle) {
      Serial.println("[TRIANGULATE] Worker task did not stop in time, aborting start");
      sendToSerial1(nodeId + ": TRI_ACK:BUSY", true);
      return;
    }
  }

  if (isIdentityId) {
    strncpy(triangulationTargetIdentity, target.c_str(), sizeof(triangulationTargetIdentity) - 1);
    triangulationTargetIdentity[sizeof(triangulationTargetIdentity) - 1] = '\0';
    memset(triangulationTarget, 0, 6);
  } else {
    memcpy(triangulationTarget, macBytes, 6);
    memset(triangulationTargetIdentity, 0, sizeof(triangulationTargetIdentity));
  }

  // Determine if this node is the initiator (from broadcast)
  bool isInitiator = false;
  if (initiatorNodeId.length() > 0) {
    isInitiator = (myNodeId == initiatorNodeId);
    Serial.printf("[TRIANGULATE] Broadcast received - Initiator: %s (I am %s: %s)\n",
                 initiatorNodeId.c_str(),
                 isInitiator ? "INITIATOR" : "participant",
                 myNodeId.c_str());
  } else {
    Serial.printf("[TRIANGULATE] No initiator specified, acting as participant\n");
  }

  if (isInitiator) {
    Serial.println("[TRIANGULATE] Ignoring broadcast - already running as initiator");
    return;
  }

  // Participant node setup
  triangulationInitiator = false;
  triangulationActive = true;
  triangulationStart = millis();
  triangulationDuration = duration;
  currentScanMode = SCAN_BOTH;
  stopRequested = false;

  Serial.printf("[TRIANGULATE] Participant node started scanning for %s (%ds)\n", target.c_str(), duration);

  // Stagger ACK responses to prevent simultaneous mesh traffic
  // Use node ID hash to generate unique delay (0-2000ms)
  uint32_t nodeHash = 0;
  for (size_t i = 0; i < nodeId.length(); i++) {
    nodeHash = nodeHash * 31 + nodeId.charAt(i);
  }
  uint32_t ackDelay = (nodeHash % 2000);  // 0-2000ms spread
  Serial.printf("[TRIANGULATE] Staggered ACK delay: %ums\n", ackDelay);
  vTaskDelay(pdMS_TO_TICKS(ackDelay));

  // Flush rate limiter to ensure ACK can be sent immediately
  rateLimiter.flush();

  // Send acknowledgment to coordinator
  sendToSerial1(nodeId + ": TRI_START_ACK", true);
  Serial.println("[TRIANGULATE] ACK sent to coordinator");
  Serial.println("[TRIANGULATE] Waiting for TRI_CYCLE_START before scanning...");
}

static void handleTriangulateStop(const String &command)
{
  (void)command;
  Serial.println("[MESH] TRIANGULATE_STOP received");
  stopRequested = true;

  if (triangulationActive && !triangulationInitiator) {
    rateLimiter.flush();
    Serial.println("[MESH] Rate limiter flushed for final reports");

    String myNodeId = getNodeId();
    if (myNodeId.length() == 0) {
      myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
    }

    String macStr = macFmt6(triangulationTarget);
    bool sentReport = false;

    int wifiHitCount, bleHitCount;
    int8_t wifiAvgRssi = -128, bleAvgRssi = -128;
    float lat, lon, hdop;
    bool hasGPS;

    {
      std::lock_guard<std::mutex> lock(triAccumMutex);

      // Fix for dual-radio devices showing as two types
      if (triAccum.wifiHitCount > 0 && triAccum.bleHitCount > 0) {
        Serial.printf("[TRI-FINAL-MIXED] WARNING: Device %s has BOTH WiFi (%d) and BLE (%d) hits!\n",
                     macStr.c_str(), triAccum.wifiHitCount, triAccum.bleHitCount);

        if (triAccum.wifiHitCount >= triAccum.bleHitCount) {
          Serial.printf("[TRI-FINAL-MIXED] Keeping WiFi, clearing BLE\n");
          triAccum.bleHitCount = 0;
          triAccum.bleRssiSum = 0.0f;
        } else {
          Serial.printf("[TRI-FINAL-MIXED] Keeping BLE, clearing WiFi\n");
          triAccum.wifiHitCount = 0;
          triAccum.wifiRssiSum = 0.0f;
        }
      }

      wifiHitCount = triAccum.wifiHitCount;
      bleHitCount = triAccum.bleHitCount;
      if (wifiHitCount > 0) {
        wifiAvgRssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
      }
      if (bleHitCount > 0) {
        bleAvgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
      }
      lat = triAccum.lat;
      lon = triAccum.lon;
      hdop = triAccum.hdop;
      hasGPS = triAccum.hasGPS;
    }

    if (wifiHitCount > 0) {
      String wifiMsg = myNodeId + ": T_D: " + macStr +
                      " RSSI:" + String(wifiAvgRssi) +
                      " Hits=" + String(wifiHitCount) +
                      " Type:WiFi";
      if (hasGPS) {
        wifiMsg += " GPS=" + String(lat, 6) + "," + String(lon, 6) +
                " HDOP=" + String(hdop, 1);
      }
      sendToSerial1(wifiMsg, true);
      Serial.printf("[TRIANGULATE] Final WiFi report sent: %d hits, RSSI=%d\n",
                   wifiHitCount, wifiAvgRssi);
      sentReport = true;
    }

    if (bleHitCount > 0) {
      String bleMsg = myNodeId + ": T_D: " + macStr +
                      " RSSI:" + String(bleAvgRssi) +
                      " Hits=" + String(bleHitCount) +
                      " Type:BLE";
      if (hasGPS) {
        bleMsg += " GPS=" + String(lat, 6) + "," + String(lon, 6) +
                " HDOP=" + String(hdop, 1);
      }
      sendToSerial1(bleMsg, true);
      Serial.printf("[TRIANGULATE] Final BLE report sent: %d hits, RSSI=%d\n",
                   bleHitCount, bleAvgRssi);
      sentReport = true;
    }

    // If no hits at all, still send a 0-hit report so initiator knows we're done
    if (!sentReport) {
      String noHitMsg = myNodeId + ": T_D: " + macStr +
                      " RSSI:-128" +
                      " Hits=0" +
                      " Type:WiFi";  // Default to WiFi type for 0-hit reports
      if (gpsValid) {
        noHitMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
        if (gps.hdop.isValid()) {
          noHitMsg += " HDOP=" + String(gps.hdop.hdop(), 1);
        }
      }
      sendToSerial1(noHitMsg, true);
      Serial.println("[TRIANGULATE] Final 0-hit report sent (no detections)");
    }

    // Mark as stopped and let scanner task exit naturally
    markTriangulationStopFromMesh();
    triangulationActive = false;
    Serial.println("[TRIANGULATE] Child node marked inactive, scanner will exit");
  }

  sendToSerial1(nodeId + ": TRIANGULATE_STOP_ACK", true);
}

static void handleTriCycleStart(const String &command)
{
  // Format: TRI_CYCLE_START:timestamp:node1,node2,node3...
  String params = command.substring(16);
  int colonPos = params.indexOf(':');

  if (colonPos > 0) {
    // New format with node list
    uint32_t cycleStartMs = params.substring(0, colonPos).toInt();
    String nodeListStr = params.substring(colonPos + 1);

    // Clear and rebuild reporting schedule with all nodes in coordinator's order
    reportingSchedule.reset();

    // Parse comma-separated node list
    int startIdx = 0;
    int commaIdx = nodeListStr.indexOf(',');

    while (commaIdx >= 0) {
      String node = nodeListStr.substring(startIdx, commaIdx);
      reportingSchedule.addNode(node);
      startIdx = commaIdx + 1;
      commaIdx = nodeListStr.indexOf(',', startIdx);
    }

    // Add last node (after final comma)
    if (startIdx < nodeListStr.length()) {
      String node = nodeListStr.substring(startIdx);
      reportingSchedule.addNode(node);
    }

    // Initialize cycle start time
    reportingSchedule.cycleStartMs = cycleStartMs;

    Serial.printf("[MESH] TRI_CYCLE_START received: %u ms, nodes: %s\n",
                  cycleStartMs, nodeListStr.c_str());
  } else {
    // Old format - just timestamp (for backward compatibility)
    uint32_t cycleStartMs = params.toInt();
    reportingSchedule.addNode(nodeId);
    reportingSchedule.cycleStartMs = cycleStartMs;
    Serial.printf("[MESH] TRI_CYCLE_START received (legacy): %u ms\n", cycleStartMs);
  }

  // Participant nodes: now start scanning (coordinator handles its own scan task creation)
  if (triangulationActive && !triangulationInitiator) {
    if (workerTaskHandle || blueTeamTaskHandle) {
      Serial.println("[TRIANGULATE] Radio busy, cannot start triangulation scan task");
    } else {
      scanning = true;
      Serial.printf("[TRIANGULATE] TRI_CYCLE_START received - starting scan task (duration=%us)\n", triangulationDuration);
      ahCreateTask(listScanTask, "triangulate", 8192,
                             reinterpret_cast<void*>(static_cast<intptr_t>(triangulationDuration)), 1, &workerTaskHandle, 1);
    }
  }
}

static void handleTriangulateResults(const String &command)
{
  (void)command;
  bool hasNodes;
  {
    std::lock_guard<std::mutex> lock(triangulationMutex);
    hasNodes = (triangulationNodes.size() > 0);
  }
  if (hasNodes) {
    String results = calculateTriangulation();
    sendToSerial1(nodeId + ": TRIANGULATE_RESULTS_START", true);
    sendToSerial1(results, true);
    sendToSerial1(nodeId + ": TRIANGULATE_RESULTS_END", true);
  } else {
    sendToSerial1(nodeId + ": TRIANGULATE_RESULTS:NO_DATA", true);
  }
}

static void handleEraseForce(const String &command)
{
  String credential = command.substring(12);
  bool ok = (erasePSK.length() > 0) ? validateEraseResponse(credential)
                                    : validateEraseToken(credential);
  if (ok)
  {
    executeSecureErase("Force command");
    sendToSerial1(nodeId + ": ERASE_ACK:COMPLETE", true);
  }
  else
  {
    sendToSerial1(nodeId + ": ERASE_ACK:DENIED", true);
  }
}

static bool meshEraseAuthorized(const String &credential)
{
  if (erasePSK.length() == 0) return true;
  return validateEraseResponse(credential);
}

static void handleConfigErasePsk(const String &command)
{
  String key = command.substring(17);
  setErasePSK(key);
  saveConfiguration();
  Serial.printf("[ERASE] PSK %s\n", key.length() ? "set (HMAC auth enabled)" : "cleared (legacy token mode)");
  sendToSerial1(nodeId + ": CONFIG_ACK:ERASE_PSK:" + String(key.length() ? "SET" : "CLEARED"), true);
}

static void handleEraseCancel(const String &command)
{
  String credential = (command.length() > 13 && command.charAt(12) == ':') ? command.substring(13) : "";
  if (!meshEraseAuthorized(credential)) {
    sendToSerial1(nodeId + ": ERASE_ACK:DENIED", true);
    return;
  }
  cancelTamperErase();
  sendToSerial1(nodeId + ": ERASE_ACK:CANCELLED", true);
}

static void handleEraseRequest(const String &command)
{
  (void)command;
  tamperAuthToken = generateEraseToken();
  Serial.println("[ERASE] Challenge nonce issued (valid 300s)");
  sendToSerial1(nodeId + ": ERASE_TOKEN:" + tamperAuthToken + " Expires:300s", true);
}

static void handleFactoryReset(const String &command)
{
  String rest = command.substring(14);
  int colon = rest.indexOf(':');
  if (colon <= 0) {
    sendToSerial1(nodeId + ": FACTORY_RESET_ACK:BAD_FORMAT", true);
    return;
  }
  String tier = rest.substring(0, colon);
  String credential = rest.substring(colon + 1);
  if (erasePSK.length() == 0) {
    sendToSerial1(nodeId + ": FACTORY_RESET_ACK:DENIED_NO_PSK", true);
    return;
  }
  if (!validateEraseResponse(credential)) {
    sendToSerial1(nodeId + ": FACTORY_RESET_ACK:DENIED", true);
    return;
  }
  if (tier != "FULL" && tier != "CONFIG" && tier != "DATA") {
    sendToSerial1(nodeId + ": FACTORY_RESET_ACK:BAD_TIER", true);
    return;
  }
  if (g_eraseWipeBusy.exchange(true)) {
    sendToSerial1(nodeId + ": FACTORY_RESET_ACK:BUSY", true);
    return;
  }
  sendToSerial1(nodeId + ": FACTORY_RESET_ACK:" + tier + " - rebooting", true);
  String* tierPtr = new String(tier);
  if (xTaskCreate([](void* param) {
    String* tp = static_cast<String*>(param);
    String t = *tp;
    delete tp;
    delay(800);
    Serial.printf("[FACTORY] Mesh reset: %s\n", t.c_str());
    bool ok;
    if (t == "CONFIG")    ok = performConfigReset();
    else if (t == "DATA") ok = performDataReset();
    else                  ok = performSecureWipe();
    Serial.printf("[FACTORY] Reset %s %s - rebooting\n", t.c_str(), ok ? "OK" : "FAILED");
    delay(300);
    ESP.restart();
  }, "factory_reset", 8192, tierPtr, 1, NULL) != pdPASS) {
    delete tierPtr;
    g_eraseWipeBusy.store(false);
  }
}

static void handleAutoeraseEnable(const String &command)
{
  String body = command;
  if (erasePSK.length() > 0) {
    int lastColon = body.lastIndexOf(':');
    String credential = (lastColon >= 16) ? body.substring(lastColon + 1) : "";
    if (!validateEraseResponse(credential)) {
      sendToSerial1(nodeId + ": AUTOERASE_ACK:DENIED", true);
      return;
    }
    body = body.substring(0, lastColon);
  }
  // Format: AUTOERASE_ENABLE[:setupDelay:eraseDelay:vibrationsRequired:detectionWindow:cooldown]
  if (body.length() > 16 && body.charAt(16) == ':') {
    // Parse parameters
    String params = body.substring(17);
    int idx1 = params.indexOf(':');
    int idx2 = params.indexOf(':', idx1 + 1);
    int idx3 = params.indexOf(':', idx2 + 1);
    int idx4 = params.indexOf(':', idx3 + 1);

    if (idx1 > 0 && idx2 > 0 && idx3 > 0 && idx4 > 0) {
      setupDelay = params.substring(0, idx1).toInt() * 1000;
      autoEraseDelay = params.substring(idx1 + 1, idx2).toInt() * 1000;
      vibrationsRequired = params.substring(idx2 + 1, idx3).toInt();
      detectionWindow = params.substring(idx3 + 1, idx4).toInt() * 1000;
      autoEraseCooldown = params.substring(idx4 + 1).toInt() * 1000;

      // Validate ranges
      if (setupDelay < 30000) setupDelay = 30000;
      if (setupDelay > 600000) setupDelay = 600000;
      if (autoEraseDelay < 10000) autoEraseDelay = 10000;
      if (autoEraseDelay > 300000) autoEraseDelay = 300000;
      if (vibrationsRequired < 2) vibrationsRequired = 2;
      if (vibrationsRequired > 5) vibrationsRequired = 5;
      if (detectionWindow < 10000) detectionWindow = 10000;
      if (detectionWindow > 60000) detectionWindow = 60000;
      if (autoEraseCooldown < 300000) autoEraseCooldown = 300000;
      if (autoEraseCooldown > 3600000) autoEraseCooldown = 3600000;
    }
  }

  autoEraseEnabled = true;
  inSetupMode = true;
  setupStartTime = millis();
  saveConfiguration();

  String response = nodeId + ": AUTOERASE_ACK:ENABLED Setup:" + String(setupDelay/1000) +
                    "s Erase:" + String(autoEraseDelay/1000) + "s Vibs:" + String(vibrationsRequired) +
                    " Window:" + String(detectionWindow/1000) + "s Cooldown:" + String(autoEraseCooldown/1000) + "s";
  sendToSerial1(response, true);
  Serial.printf("[AUTOERASE] Enabled - setup mode active for %us\n", setupDelay/1000);

  // Send SETUP_MODE alert
  String setupModeAlert = nodeId + ": SETUP_MODE: Auto-erase activates in " + String(setupDelay/1000) + "s";
  sendToSerial1(setupModeAlert, false);
}

static void handleAutoeraseDisable(const String &command)
{
  String credential = (command.length() > 18 && command.charAt(17) == ':') ? command.substring(18) : "";
  if (!meshEraseAuthorized(credential)) {
    sendToSerial1(nodeId + ": AUTOERASE_ACK:DENIED", true);
    return;
  }
  autoEraseEnabled = false;
  inSetupMode = false;
  saveConfiguration();
  sendToSerial1(nodeId + ": AUTOERASE_ACK:DISABLED", true);
  Serial.println("[AUTOERASE] Disabled");
}

static void handleAutoeraseStatus(const String &command)
{
  (void)command;
  updateSetupModeStatus();
  String status = nodeId + ": AUTOERASE_STATUS: ";
  status += "Enabled:" + String(autoEraseEnabled ? "YES" : "NO");

  if (autoEraseEnabled) {
    if (inSetupMode) {
      uint32_t timeLeft = (setupDelay - (millis() - setupStartTime)) / 1000;
      status += " SetupMode:ACTIVE Activates:" + String(timeLeft) + "s";
    } else {
      status += " SetupMode:COMPLETE";
    }

    if (tamperEraseActive) {
      uint32_t eraseTime = (autoEraseDelay - (millis() - tamperSequenceStart)) / 1000;
      status += " TamperActive:YES EraseIn:" + String(eraseTime) + "s";
    } else {
      status += " TamperActive:NO";
    }

    status += " Setup:" + String(setupDelay/1000) + "s";
    status += " Erase:" + String(autoEraseDelay/1000) + "s";
    status += " Vibs:" + String(vibrationsRequired);
    status += " Window:" + String(detectionWindow/1000) + "s";
    status += " Cooldown:" + String(autoEraseCooldown/1000) + "s";
  }

  sendToSerial1(status, true);
}

static void handleBatterySaverStart(const String &command)
{
  uint32_t intervalMinutes = 5;  // Default 5 minutes

  // Parse optional interval: BATTERY_SAVER_START:10 (for 10 minutes)
  if (command.length() > 19 && command.charAt(19) == ':') {
    intervalMinutes = command.substring(20).toInt();
    if (intervalMinutes < 1) intervalMinutes = 1;
    if (intervalMinutes > 30) intervalMinutes = 30;
  }

  uint32_t intervalMs = intervalMinutes * 60000;
  enterBatterySaver(intervalMs);
  sendToSerial1(nodeId + ": BATTERY_SAVER_ACK:STARTED Interval:" + String(intervalMinutes) + "min", true);
  Serial.printf("[MESH] Battery saver started with %u minute heartbeat\n", intervalMinutes);
}

static void handleBatterySaverStop(const String &command)
{
  (void)command;
  exitBatterySaver();
  sendToSerial1(nodeId + ": BATTERY_SAVER_ACK:STOPPED", true);
  Serial.println("[MESH] Battery saver stopped");
}

static void handleBatterySaverStatus(const String &command)
{
  (void)command;
  String status = getBatterySaverStatus();
  sendToSerial1(status, true);
}

static void handleHbOn(const String &command)
{
  (void)command;
  hbEnabled = true;
  prefs.putBool("hbEnabled", true);
  lastSaveTime = 0;
  saveConfiguration();
  sendToSerial1(nodeId + ": HB_ACK:ENABLED", true);
}

static void handleHbOff(const String &command)
{
  (void)command;
  hbEnabled = false;
  prefs.putBool("hbEnabled", false);
  lastSaveTime = 0;
  saveConfiguration();
  sendToSerial1(nodeId + ": HB_ACK:DISABLED", true);
}

static void handleHbInterval(const String &command)
{
  uint32_t minutes = command.substring(12).toInt();
  if (minutes < 1) minutes = 1;
  if (minutes > 60) minutes = 60;
  hbInterval = minutes * 60000;
  prefs.putUInt("hbInterval", hbInterval);
  sendToSerial1(nodeId + ": HB_ACK:INTERVAL " + String(minutes) + "min", true);
}

static void handleSentinelOn(const String &command)
{
  (void)command;
  sentinel_setUserEnabled(true);
  sendToSerial1(nodeId + ": SENTINEL_ACK:ON run=" + String(sentinel_isRunning() ? 1 : 0), true);
}

static void handleSentinelOff(const String &command)
{
  (void)command;
  sentinel_setUserEnabled(false);
  sendToSerial1(nodeId + ": SENTINEL_ACK:OFF", true);
}

static void handleSentinelStatus(const String &command)
{
  (void)command;
  sendToSerial1(nodeId + ": SENTINEL_STATUS: en=" + String(sentinel_isUserEnabled() ? 1 : 0) +
                " run=" + String(sentinel_isRunning() ? 1 : 0), true);
}

static void handleSentinelMode(const String &command)
{
  String v = command.substring(strlen("SENTINEL_MODE:"));
  v.trim();
  bool scan = v.equalsIgnoreCase("scan");
  bool ok = detect_setConfigFromJson(String("{\"sentinel_scan\":") + (scan ? "true" : "false") + "}");
  sendToSerial1(nodeId + ": SENTINEL_MODE_ACK:" + (ok ? (scan ? "scan" : "defend") : "FAIL"), true);
}

static void handleSentinelBoot(const String &command)
{
  String v = command.substring(strlen("SENTINEL_BOOT:"));
  v.trim();
  bool on = (v.toInt() != 0) || v.equalsIgnoreCase("on");
  Preferences p;
  if (p.begin("antihunter", false)) { p.putBool("sentBoot", on); p.end(); }
  sendToSerial1(nodeId + ": SENTINEL_BOOT_ACK:" + (on ? "on" : "off"), true);
}

void processCommand(const String &command, const String &targetId = "")
{
  Serial.printf("[DEBUG_RAW] Command length: %d, starts with: '%.30s'\n",
                command.length(), command.c_str());
  if (command.startsWith("CONFIG_CHANNELS:"))          handleConfigChannels(command);
  else if (command.startsWith("CONFIG_ERASE_PSK:"))     handleConfigErasePsk(command);
  else if (command.startsWith("CONFIG_DEDUP_TTL:"))     handleConfigDedupTtl(command);
  else if (command.startsWith("CONFIG_TARGETS:"))       handleConfigTargets(command);
  else if (command.startsWith("CONFIG_NODEID:"))        handleConfigNodeId(command);
  else if (command.startsWith("CONFIG_RSSI:"))          handleConfigRssi(command);
  else if (command.startsWith("SCAN_START:"))           handleScanStart(command);
  else if (command.startsWith("BASELINE_START:"))       handleBaselineStart(command);
  else if (command.startsWith("BASELINE_STATUS"))       handleBaselineStatus(command);
  else if (command.startsWith("DEVICE_SCAN_START:"))    handleDeviceScanStart(command);
  else if (command.startsWith("DRONE_START:"))          handleDroneStart(command);
  else if (command.startsWith("DEAUTH_START:"))         handleDeauthStart(command);
  else if (command.startsWith("RANDOMIZATION_START:"))  handleRandomizationStart(command);
  else if (command.startsWith("PROBE_START:"))          handleProbeStart(command);
  else if (command.startsWith("PROBE_STOP"))            handleProbeStop(command);
  else if (command.startsWith("PROBE_HIT "))            handleProbeHit(command);
  else if (command.startsWith("STOP"))                  handleStop(command);
  else if (command == "SENTINEL_ON")                    handleSentinelOn(command);
  else if (command == "SENTINEL_OFF")                   handleSentinelOff(command);
  else if (command.startsWith("SENTINEL_STATUS"))       handleSentinelStatus(command);
  else if (command.startsWith("SENTINEL_MODE:"))        handleSentinelMode(command);
  else if (command.startsWith("SENTINEL_BOOT:"))        handleSentinelBoot(command);
  else if (command.startsWith("STATUS"))                handleStatus(command);
  else if (command.startsWith("VIBRATION_STATUS"))      handleVibrationStatus(command);
  else if (command == "VIBRATION_ON")                   handleVibrationOn(command);
  else if (command == "VIBRATION_OFF")                  handleVibrationOff(command);
  else if (command.startsWith("TRIANGULATE_START:"))    handleTriangulateStart(command, targetId);
  else if (command == "TRIANGULATE_STOP")               handleTriangulateStop(command);
  else if (command.startsWith("TRI_CYCLE_START:"))      handleTriCycleStart(command);
  else if (command.startsWith("TRIANGULATE_RESULTS"))   handleTriangulateResults(command);
  else if (command.startsWith("ERASE_FORCE:"))          handleEraseForce(command);
  else if (command.startsWith("ERASE_CANCEL"))          handleEraseCancel(command);
  else if (command == "ERASE_REQUEST")                  handleEraseRequest(command);
  else if (command.startsWith("FACTORY_RESET:"))        handleFactoryReset(command);
  else if (command.startsWith("AUTOERASE_ENABLE"))      handleAutoeraseEnable(command);
  else if (command.startsWith("AUTOERASE_DISABLE"))     handleAutoeraseDisable(command);
  else if (command == "AUTOERASE_STATUS")               handleAutoeraseStatus(command);
  else if (command.startsWith("BATTERY_SAVER_START"))   handleBatterySaverStart(command);
  else if (command == "BATTERY_SAVER_STOP")             handleBatterySaverStop(command);
  else if (command == "BATTERY_SAVER_STATUS")           handleBatterySaverStatus(command);
  else if (command == "HB_ON")                          handleHbOn(command);
  else if (command == "HB_OFF")                         handleHbOff(command);
  else if (command.startsWith("HB_INTERVAL:"))          handleHbInterval(command);
}

void sendMeshCommand(const String &command) {
    if (!meshEnabled) return;

    bool sent = sendToSerial1(command, true);
    if (sent) {
        Serial.printf("[MESH] Command sent: %s\n", command.c_str());
    } else {
        Serial.printf("[MESH] Command failed: %s\n", command.c_str());
    }
}

void setNodeId(const String &id) {
    nodeId = id;
    prefs.putString("nodeId", nodeId);
    Serial.printf("[MESH] Node ID set to: %s\n", nodeId.c_str());
}

String getNodeId() {
    return nodeId;
}

void processMeshMessage(const String &message) {
    if (message.length() == 0 || message.length() > MAX_MESH_SIZE) return;
    
    String cleanMessage = "";
    for (size_t i = 0; i < message.length(); i++) {
        char c = message[i];
        if (c >= 32 && c <= 126) cleanMessage += c;
    }
    if (cleanMessage.length() == 0) return;

    int colonPos = cleanMessage.indexOf(':');
    if (colonPos > 0) {
        String sendingNode = cleanMessage.substring(0, colonPos);
        if (sendingNode == getNodeId()) {
            return;
        }
    }
    
    Serial.printf("[MESH] Processing message: '%s'\n", cleanMessage.c_str());

    // Handle TRI_START_ACK from child nodes (coordinator only)
    if (colonPos > 0 && triangulationInitiator) {
        String sendingNode = cleanMessage.substring(0, colonPos);
        String content = cleanMessage.substring(colonPos + 2);

        if (content == "TRI_START_ACK") {
            Serial.printf("[TRIANGULATE] ACK received from %s\n", sendingNode.c_str());
            // Track which nodes have acknowledged - add to triangulateAcks if not already present
            {
                std::lock_guard<std::mutex> lock(triangulationMutex);
                auto ackIt = std::find_if(triangulateAcks.begin(), triangulateAcks.end(),
                    [&](const TriangulateAckInfo& a) { return a.nodeId == sendingNode; });
                if (ackIt != triangulateAcks.end()) {
                    ackIt->ackTimestamp = millis();
                } else if (triangulateAcks.size() < MAX_ACK_INFO) {
                    TriangulateAckInfo newAck;
                    newAck.nodeId = sendingNode;
                    newAck.ackTimestamp = millis();
                    newAck.reportReceived = false;  // Will be set to true when data arrives
                    newAck.reportTimestamp = 0;
                    triangulateAcks.push_back(newAck);

                    // Register node in reporting schedule to assign time slot
                    reportingSchedule.addNode(sendingNode);

                    Serial.printf("[TRIANGULATE] Node %s added to ACK tracking (%d total nodes)\n",
                                 sendingNode.c_str(), triangulateAcks.size());
                }
            }
        }

    }

    // Process T_D messages during active triangulation or while waiting for final reports
    if ((triangulationActive || waitingForFinalReports) && colonPos > 0) {
        String sendingNode = cleanMessage.substring(0, colonPos);
        String content = cleanMessage.substring(colonPos + 2);

        // T_D from child nodes
        if (content.startsWith("T_D:")) {
            String payload = content.substring(5);
            Serial.printf("[T_D_DEBUG] Sender=%s Payload='%s'\n", sendingNode.c_str(), payload.c_str());

            int macEnd = payload.indexOf(' ');
            if (macEnd > 0) {
                String reportedMac = payload.substring(0, macEnd);
                uint8_t mac[6];
                
                if (parseMac6(reportedMac, mac) && memcmp(mac, triangulationTarget, 6) == 0) {
                    int hitsIdx = payload.indexOf("Hits=");
                    int rssiIdx = payload.indexOf("RSSI:");
                    int gpsIdx = payload.indexOf("GPS=");
                    int hdopIdx = payload.indexOf("HDOP=");

                    if (rssiIdx > 0) {
                        int hits = -1;  // -1 means no Hits field present, keep existing value
                        if (hitsIdx > 0) {
                            hits = payload.substring(hitsIdx + 5, payload.indexOf(' ', hitsIdx)).toInt();
                        }

                        int rssiEnd = payload.length();
                        int spaceAfterRssi = payload.indexOf(' ', rssiIdx + 5);
                        if (spaceAfterRssi > 0) rssiEnd = spaceAfterRssi;

                        int rangeIdx = payload.indexOf("Range:", rssiIdx);
                        if (rangeIdx > 0 && rangeIdx < rssiEnd) {
                            rssiEnd = rangeIdx - 1;
                        }

                        int8_t rssi = payload.substring(rssiIdx + 5, rssiEnd).toInt();

                        // Grab device type right from payload
                        bool isBLE = false;
                        int typeIdx = payload.indexOf("Type:");
                        if (typeIdx > 0) {
                            int typeEnd = payload.indexOf(' ', typeIdx + 5);
                            if (typeEnd < 0) typeEnd = payload.length();
                            String typeStr = payload.substring(typeIdx + 5, typeEnd);
                            typeStr.trim();
                            isBLE = (typeStr == "BLE");
                        }

                        float lat = 0.0, lon = 0.0, hdop = 99.9;
                        bool hasGPS = false;

                        if (gpsIdx > 0) {
                            int commaIdx = payload.indexOf(',', gpsIdx);
                            if (commaIdx > 0) {
                                lat = payload.substring(gpsIdx + 4, commaIdx).toFloat();
                                int spaceAfterLon = payload.indexOf(' ', commaIdx);
                                lon = payload.substring(commaIdx + 1, spaceAfterLon > 0 ? spaceAfterLon : payload.length()).toFloat();
                                hasGPS = true;

                                if (hdopIdx > 0) {
                                    hdop = payload.substring(hdopIdx + 5).toFloat();
                                }
                            }
                        }

                        {
                            std::lock_guard<std::mutex> lock(triangulationMutex);

                            auto nodeIt = std::find_if(triangulationNodes.begin(), triangulationNodes.end(),
                                [&](const TriangulationNode& n) { return n.nodeId == sendingNode; });

                            if (nodeIt != triangulationNodes.end()) {
                                updateNodeRSSI(*nodeIt, rssi);
                                if (hits >= 0) {
                                    nodeIt->hitCount = hits;
                                }
                                nodeIt->isBLE = isBLE;
                                if (hasGPS) {
                                    nodeIt->lat = lat;
                                    nodeIt->lon = lon;
                                    nodeIt->hasGPS = true;
                                    nodeIt->hdop = hdop;
                                }
                                nodeIt->distanceEstimate = rssiToDistance(*nodeIt, !nodeIt->isBLE);
                                Serial.printf("[TRIANGULATE] Updated child %s: hits=%d avgRSSI=%ddBm Type=%s GPS=%s\n",
                                            sendingNode.c_str(), nodeIt->hitCount, rssi,
                                            nodeIt->isBLE ? "BLE" : "WiFi",
                                            hasGPS ? "YES" : "NO");
                            } else {
                            TriangulationNode newNode;
                            newNode.nodeId = sendingNode;
                            newNode.lat = lat;
                            newNode.lon = lon;
                            newNode.rssi = rssi;
                            newNode.hitCount = (hits >= 0) ? hits : 1;  // Default to 1 for new nodes if no Hits field
                            newNode.hasGPS = hasGPS;
                            newNode.hdop = hdop;
                            newNode.isBLE = isBLE;
                            newNode.lastUpdate = millis();
                            initNodeKalmanFilter(newNode);
                            updateNodeRSSI(newNode, rssi);
                            newNode.distanceEstimate = rssiToDistance(newNode, !newNode.isBLE);
                            if (triangulationNodes.size() < MAX_TRIANGULATION_NODES) {
                                triangulationNodes.push_back(newNode);
                                Serial.printf("[TRIANGULATE] Added child %s: hits=%d avgRSSI=%ddBm Type=%s\n",
                                        sendingNode.c_str(), hits, rssi,
                                        newNode.isBLE ? "BLE" : "WiFi");
                            } else {
                                Serial.printf("[TRIANGULATE] Node cap (%u) reached - dropping %s\n",
                                        (unsigned)MAX_TRIANGULATION_NODES, sendingNode.c_str());
                            }
                        }

                        // Mark this node as having reported (coordinator only)
                        // Also handle late T_D from nodes whose ACK was lost
                        if (triangulationInitiator && (waitingForFinalReports || triangulationActive)) {
                            auto ackIt2 = std::find_if(triangulateAcks.begin(), triangulateAcks.end(),
                                [&](const TriangulateAckInfo& a) { return a.nodeId == sendingNode; });
                            bool foundInAcks = (ackIt2 != triangulateAcks.end());
                            if (foundInAcks && !ackIt2->reportReceived) {
                                ackIt2->reportReceived = true;
                                ackIt2->reportTimestamp = millis();
                                Serial.printf("[TRIANGULATE] Node %s marked as reported (%s data)\n",
                                             sendingNode.c_str(), isBLE ? "BLE" : "WiFi");
                            }

                            // Node sent T_D but wasn't in our ACK list - their ACK was lost
                            // Add them to tracking so we wait for their data
                            if (!foundInAcks && triangulateAcks.size() < MAX_ACK_INFO) {
                                TriangulateAckInfo lateAck;
                                lateAck.nodeId = sendingNode;
                                lateAck.ackTimestamp = millis();
                                lateAck.reportReceived = true;  // Already have their report
                                lateAck.reportTimestamp = millis();
                                triangulateAcks.push_back(lateAck);

                                // Also add to reporting schedule
                                reportingSchedule.addNode(sendingNode);

                                Serial.printf("[TRIANGULATE] Late T_D from node %s (ACK was lost) - added to tracking (%d total nodes)\n",
                                             sendingNode.c_str(), triangulateAcks.size());
                            }
                        }
                    }
                }
            }
            return;
        }
      }

      if (content.startsWith("Target:")) {
            int macStart = content.indexOf(' ', 7) + 1;
            int macEnd = content.indexOf(' ', macStart);
            
            if (macEnd > macStart) {
                String macStr = content.substring(macStart, macEnd);
                uint8_t mac[6];
                
                bool targetSet = false;
                for (int i = 0; i < 6; i++) {
                    if (triangulationTarget[i] != 0) {
                        targetSet = true;
                        break;
                    }
                }

                if (!targetSet) {
                    Serial.println("[TRIANGULATE] WARNING: Target not set, ignoring report");
                    return;
                }
                
                if (parseMac6(macStr, mac) && memcmp(mac, triangulationTarget, 6) == 0) {
                    int rssiIdx = content.indexOf("RSSI:");
                    int rssi = -127;
                    if (rssiIdx > 0) {
                        int rssiEnd = content.indexOf(' ', rssiIdx + 5);
                        if (rssiEnd < 0) rssiEnd = content.length();
                        rssi = content.substring(rssiIdx + 5, rssiEnd).toInt();
                    }

                    float lat = 0, lon = 0;
                    bool hasGPS = false;
                    float hdop = 99.9;
                    int gpsIdx = content.indexOf("GPS=");
                    if (gpsIdx > 0) {
                        int commaIdx = content.indexOf(',', gpsIdx);
                        if (commaIdx > 0) {
                            lat = content.substring(gpsIdx + 4, commaIdx).toFloat();
                            
                            int hdopIdx = content.indexOf("HDOP=", commaIdx);
                            int lonEnd;
                            if (hdopIdx > 0) {
                                lonEnd = hdopIdx - 1;
                            } else {
                                lonEnd = content.indexOf(' ', commaIdx);
                                if (lonEnd < 0) lonEnd = content.length();
                            }
                            
                            lon = content.substring(commaIdx + 1, lonEnd).toFloat();
                            
                            if (hdopIdx > 0) {
                                int hdopEnd = content.indexOf(' ', hdopIdx);
                                if (hdopEnd < 0) hdopEnd = content.length();
                                hdop = content.substring(hdopIdx + 5, hdopEnd).toFloat();
                            }
                            
                            hasGPS = true;
                        }
                    }

                    bool isBLE = false;
                    int typeIdx = content.indexOf("Type:");
                    if (typeIdx > 0) {
                        int typeEnd = content.indexOf(' ', typeIdx + 5);
                        if (typeEnd < 0) typeEnd = content.length();
                        String typeStr = content.substring(typeIdx + 5, typeEnd);
                        typeStr.trim();
                        isBLE = (typeStr == "BLE");
                    }

                    {
                    std::lock_guard<std::mutex> lock(triangulationMutex);
                    auto nodeIt2 = std::find_if(triangulationNodes.begin(), triangulationNodes.end(),
                        [&](const TriangulationNode& n) { return n.nodeId == sendingNode; });

                    if (nodeIt2 != triangulationNodes.end()) {
                        updateNodeRSSI(*nodeIt2, rssi);
                        nodeIt2->hitCount++;
                        nodeIt2->isBLE = isBLE;
                        if (hasGPS) {
                            nodeIt2->lat = lat;
                            nodeIt2->lon = lon;
                            nodeIt2->hasGPS = true;
                        }
                        nodeIt2->distanceEstimate = rssiToDistance(*nodeIt2, !nodeIt2->isBLE);
                        Serial.printf("[TRIANGULATE] Updated %s: RSSI=%d->%.1f Type=%s dist=%.1fm Q=%.2f\n",
                                    sendingNode.c_str(), rssi, nodeIt2->filteredRssi,
                                    nodeIt2->isBLE ? "BLE" : "WiFi",
                                    nodeIt2->distanceEstimate, nodeIt2->signalQuality);
                    } else {
                      TriangulationNode newNode;
                      newNode.nodeId = sendingNode;
                      newNode.lat = lat;
                      newNode.lon = lon;
                      newNode.hdop = hdop;
                      newNode.rssi = rssi;
                      newNode.hitCount = 1;
                      newNode.hasGPS = hasGPS;
                      newNode.isBLE = isBLE;
                      newNode.lastUpdate = millis();
                      initNodeKalmanFilter(newNode);
                      updateNodeRSSI(newNode, rssi);
                      newNode.distanceEstimate = rssiToDistance(newNode, !newNode.isBLE);
                      if (triangulationNodes.size() < MAX_TRIANGULATION_NODES) {
                          triangulationNodes.push_back(newNode);
                          Serial.printf("[TRIANGULATE] New node %s: RSSI=%d dist=%.1fm\n",
                                    sendingNode.c_str(), rssi, newNode.distanceEstimate);
                      }
                  }
                  }
                }
            }
        }


        if (content.startsWith("T_F:")) {
            String payload = content.substring(4);

            int gpsIdx = payload.indexOf("GPS=");
            int confIdx = payload.indexOf("CONF=");
            int uncIdx = payload.indexOf("UNC=");

            if (gpsIdx > 0 && confIdx > 0 && uncIdx > 0) {
                String gpsStr = payload.substring(gpsIdx + 4, confIdx - 1);
                int comma = gpsStr.indexOf(',');
                {
                    std::lock_guard<std::mutex> lock(triangulationMutex);
                    if (comma > 0) {
                        apFinalResult.latitude = gpsStr.substring(0, comma).toFloat();
                        apFinalResult.longitude = gpsStr.substring(comma + 1).toFloat();
                    }
                    apFinalResult.confidence = payload.substring(confIdx + 5, uncIdx - 1).toFloat() / 100.0;
                    apFinalResult.uncertainty = payload.substring(uncIdx + 4).toFloat();
                    apFinalResult.hasResult = true;
                    apFinalResult.timestamp = millis();
                    apFinalResult.coordinatorNodeId = sendingNode;  // Store which node sent the final result
                }

                Serial.printf("[TRIANGULATE] Received coordinator final result from %s: %.6f,%.6f conf=%.1f%% unc=%.1fm\n",
                            apFinalResult.coordinatorNodeId.c_str(),
                            apFinalResult.latitude,
                            apFinalResult.longitude,
                            apFinalResult.confidence * 100.0,
                            apFinalResult.uncertainty);
            }
        }

        if (content.startsWith("T_C:")) {
            // Parse and log the complete message with URL
            String payload = content.substring(4);

            int macIdx = payload.indexOf("MAC=");
            int nodesIdx = payload.indexOf("Nodes=");
            int gpsIdx = payload.indexOf("GPS=");
            int urlIdx = payload.indexOf("URL=");

            if (macIdx >= 0 && nodesIdx > 0) {
                int nodeCount = 0;
                int spaceAfterNodes = payload.indexOf(' ', nodesIdx + 6);
                if (spaceAfterNodes > 0) {
                    nodeCount = payload.substring(nodesIdx + 6, spaceAfterNodes).toInt();
                } else {
                    nodeCount = payload.substring(nodesIdx + 6).toInt();
                }

                String logMsg = "[TRIANGULATE] Complete from " + sendingNode + ": " + String(nodeCount) + " nodes";

                if (gpsIdx > 0) {
                    int gpsEnd = payload.length();
                    if (urlIdx > gpsIdx) {
                        gpsEnd = payload.indexOf(' ', gpsIdx);
                        if (gpsEnd < 0 || gpsEnd > urlIdx) gpsEnd = urlIdx - 1;
                    }
                    String gpsStr = payload.substring(gpsIdx + 4, gpsEnd);
                    logMsg += ", GPS=" + gpsStr;
                }

                if (urlIdx > 0) {
                    String urlStr = payload.substring(urlIdx + 4);
                    logMsg += ", URL=" + urlStr;
                }

                Serial.println(logMsg);
            }
        }

        if (content.startsWith("TIME_SYNC_REQ:")) {
          int firstColon = content.indexOf(':', 14);
          if (firstColon > 0) {
              int secondColon = content.indexOf(':', firstColon + 1);
              if (secondColon > 0) {
                  int thirdColon = content.indexOf(':', secondColon + 1);
                  if (thirdColon > 0) {
                      time_t theirTime = strtoul(content.substring(14, firstColon).c_str(), nullptr, 10);
                      uint32_t theirMicros = strtoul(content.substring(secondColon + 1, thirdColon).c_str(), nullptr, 10);

                      handleTimeSyncResponse(sendingNode, theirTime, theirMicros);
                      
                      time_t myTime = getRTCEpoch();
                      int64_t myMicros = getCorrectedMicroseconds();
                      uint16_t mySubsec = (myMicros % 1000000) / 10000;
                      
                      String response = getNodeId() + ": TIME_SYNC_RESP:" + 
                                      String((unsigned long)myTime) + ":" + 
                                      String(mySubsec) + ":" +
                                      String((unsigned long)(myMicros & 0xFFFFFFFF)) + ":" +
                                      String(0);
                      sendToSerial1(response, false);
                  }
              }
          }
      }
        
      if (content.startsWith("TIME_SYNC_RESP:")) {
        int firstColon = content.indexOf(':', 15);
        if (firstColon > 0) {
            int secondColon = content.indexOf(':', firstColon + 1);
            if (secondColon > 0) {
                int thirdColon = content.indexOf(':', secondColon + 1);
                if (thirdColon > 0) {
                    int fourthColon = content.indexOf(':', thirdColon + 1);
                    if (fourthColon > 0) {
                        time_t theirTime = strtoul(content.substring(15, firstColon).c_str(), nullptr, 10);
                        uint32_t theirMicros = strtoul(content.substring(secondColon + 1, thirdColon).c_str(), nullptr, 10);

                        handleTimeSyncResponse(sendingNode, theirTime, theirMicros);
                    }
                }
            }
        }
      }
    }    

    if (cleanMessage.startsWith("@")) {
      int spaceIndex = cleanMessage.indexOf(' ');
      if (spaceIndex > 0) {
          String targetId = cleanMessage.substring(1, spaceIndex);
          if (targetId != nodeId && targetId != "ALL") return;
          String command = cleanMessage.substring(spaceIndex + 1);
          processCommand(command, targetId);
      }
    } else {
        processCommand(cleanMessage, "");
    }
}

void processUSBToMesh() {
    static String usbBuffer = "";

    while (Serial.available()) {
        char c = Serial.read();
        Serial.write(c);
        // Only process printable ASCII characters and line endings for mesh
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r') {
            if (c == '\n' || c == '\r') {
                if (usbBuffer.length() > 5 && usbBuffer.length() <= MAX_MESH_SIZE) {
                    Serial.printf("[MESH RX] %s\n", usbBuffer.c_str());
                    processMeshMessage(usbBuffer.c_str());
                } else if (usbBuffer.length() > 0) {
                    Serial.println("[MESH] Ignoring invalid message length");
                }
                usbBuffer = "";
            } else {
                usbBuffer += c;
            }
        } else {
            // ecchooooo
        }
        
        // Prevent buffer overflow at mesh limit
        if (usbBuffer.length() > MAX_MESH_SIZE) {
            Serial.println("[MESH] at 200 chars, clearing");
            usbBuffer = "";
        }
    }
}
