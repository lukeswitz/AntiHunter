#include "network.h"
#include "baseline.h"
#include "triangulation.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include <RTClib.h>
#include <esp_timer.h>

extern "C"
{
#include "esp_wifi_types.h"
#include "esp_coexist.h"
}

// LoRa RF Config
bool meshEnabled = true;
static unsigned long lastMeshSend = 0;
unsigned long meshSendInterval = 3000;
const int MAX_MESH_SIZE = 200; // T114 tests allow 200char per 3s
static String nodeId = "";

// Scanner vars
extern volatile bool scanning;
extern volatile int totalHits;
extern std::set<String> uniqueMacs;
bool triangulationOrchestratorAssigned = false;

// Module refs
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t workerTaskHandle;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void parseChannelsCSV(const String &csv);
extern void randomizeMacAddress();

// Mesh serial processing
SerialRateLimiter rateLimiter;
SerialRateLimiter::SerialRateLimiter() : tokens(MAX_TOKENS), lastRefill(millis()) {}

bool SerialRateLimiter::canSend(size_t messageLength) {
    refillTokens();
    return tokens >= messageLength;
}

void SerialRateLimiter::consume(size_t messageLength) {
    if (tokens >= messageLength) {
        tokens -= messageLength;
    }
}

void SerialRateLimiter::refillTokens() {
    unsigned long now = millis();
    if (now - lastRefill >= REFILL_INTERVAL) {
        tokens = min(tokens + TOKENS_PER_REFILL, MAX_TOKENS);
        lastRefill = now;
    }
}

void SerialRateLimiter::flush() {
    tokens = MAX_TOKENS;
    lastRefill = millis();
    Serial.println("[MESH] Rate limiter flushed");
}

uint32_t SerialRateLimiter::waitTime(size_t messageLength) {
    refillTokens();
    if (tokens >= messageLength) return 0;
    
    uint32_t needed = messageLength - tokens;
    return (needed * REFILL_INTERVAL) / TOKENS_PER_REFILL;
}

bool sendToSerial1(const String &message, bool canDelay) {
    // Priority messages bypass rate limiting
    bool isPriority = message.indexOf("TRIANGULATE_STOP") >= 0 || 
                      message.indexOf("STOP_ACK") >= 0;
    
    size_t msgLen = message.length() + 2;
    
    if (!isPriority && !rateLimiter.canSend(msgLen)) {
        if (canDelay) {
            uint32_t wait = rateLimiter.waitTime(msgLen);
            if (wait > 0 && wait < meshSendInterval) { 
                Serial.printf("[MESH] Rate limit: waiting %ums\n", wait);
                delay(wait);
                rateLimiter.refillTokens();
            } else {
                Serial.printf("[MESH] Rate limit: dropping message (wait=%ums too long)\n", wait);
                return false; 
            }
        } else {
            Serial.printf("[MESH] Rate limit: cannot send without delay\n");
            return false;
        }
    }
    
    if (Serial1.availableForWrite() < msgLen) {
        Serial.printf("[MESH] Serial1 buffer full (%d/%d bytes)\n", Serial1.availableForWrite(), msgLen);
        return false;
    }
    
    Serial1.println(message);
    
    if (!isPriority) {
        rateLimiter.consume(msgLen);
    }
    
    return true;
}

// ------------- Network ------------- 

void initializeNetwork()
{ 
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  Serial.println("Initializing mesh UART...");
  initializeMesh();
  delay(150);
  
  randomizeMacAddress();
  delay(50);
  
  Serial.println("Headless mesh mode ready");
}

void setMeshSendInterval(unsigned long interval) {
    if (interval >= 1500 && interval <= 50000) {
        meshSendInterval = interval;
        prefs.putULong("meshInterval", interval);
        Serial.printf("[MESH] Send interval set to %lums\n", interval);
    } else {
        Serial.println("[MESH] Invalid interval (1500-50000ms)");
    }
}

unsigned long getMeshSendInterval() {
    return meshSendInterval;
}

void initializeMesh() {
    Serial1.end();
    delay(100);
  
    Serial1.setRxBufferSize(2048);
    Serial1.setTxBufferSize(1024);
    Serial1.begin(115200, SERIAL_8N1, MESH_RX_PIN, MESH_TX_PIN);
    Serial1.setTimeout(100);
    
    // Clear any garbage data
    delay(100);
    while (Serial1.available()) {
        Serial1.read();
    }
    
    delay(500);

    Serial.println("[MESH] UART initialized");
    Serial.printf("[MESH] Config: 115200 baud on GPIO RX=%d TX=%d\n", MESH_RX_PIN, MESH_TX_PIN);
}

void processCommand(const String &command, const String &targetId = "")
{
  Serial.printf("[DEBUG_RAW] Command length: %d, starts with: '%.30s'\n", 
                command.length(), command.c_str());
  if (command.startsWith("CONFIG_CHANNELS:")) 
  {
    String channels = command.substring(16);
    parseChannelsCSV(channels);
    prefs.putString("channels", channels);
    saveConfiguration();
    Serial.printf("[MESH] Updated channels: %s\n", channels.c_str());
    sendToSerial1(nodeId + ": CONFIG_ACK:CHANNELS:" + channels, true);
  }
  else if (command.startsWith("CONFIG_TARGETS:"))
  {
    String targets = command.substring(15);
    saveTargetsList(targets);
    Serial.printf("[MESH] Updated targets list\n");
    sendToSerial1(nodeId + ": CONFIG_ACK:TARGETS:OK", true);
  }
  else if (command.startsWith("CONFIG_NODEID:"))
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
  else if (command.startsWith("CONFIG_RSSI:"))
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
  else if (command.startsWith("SCAN_START:"))
  {
    String params = command.substring(11);
    int modeDelim = params.indexOf(':');
    int secsDelim = params.indexOf(':', modeDelim + 1);
    int channelDelim = params.indexOf(':', secsDelim + 1);

    if (modeDelim > 0 && secsDelim > 0)
    {
      int mode = params.substring(0, modeDelim).toInt();
      int secs = params.substring(modeDelim + 1, secsDelim).toInt();
      String channels = (channelDelim > 0) ? params.substring(secsDelim + 1, channelDelim) : "1,6,11";
      bool forever = (channelDelim > 0 && params.substring(channelDelim + 1) == "FOREVER");

      if (mode >= 0 && mode <= 2)
      {
        currentScanMode = (ScanMode)mode;
        parseChannelsCSV(channels);
        stopRequested = false;

        if (!workerTaskHandle)
        {
          xTaskCreatePinnedToCore(listScanTask, "scan", 8192,
                                  (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
        }
        Serial.printf("[MESH] Started scan via mesh command\n");
        sendToSerial1(nodeId + ": SCAN_ACK:STARTED", true);
      }
    }
  }
  else if (command.startsWith("BASELINE_START:"))
  {
    String params = command.substring(15);
    int durationDelim = params.indexOf(':');
    int secs = params.substring(0, durationDelim > 0 ? durationDelim : params.length()).toInt();
    bool forever = (durationDelim > 0 && params.substring(durationDelim + 1) == "FOREVER");

    if (secs < 0)
      secs = 0;
    if (secs > 86400)
      secs = 86400;

    stopRequested = false;

    if (!workerTaskHandle)
    {
      xTaskCreatePinnedToCore(baselineDetectionTask, "baseline", 12288,
                              (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
    }
    Serial.printf("[MESH] Started baseline detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": BASELINE_ACK:STARTED", true);
  }
  else if (command.startsWith("BASELINE_STATUS"))
  {
    char status_msg[MAX_MESH_SIZE];
    const char* phase1Status;
    if (!baselineStats.isScanning) {
      phase1Status = "INACTIVE";
    } else if (!baselineStats.phase1Complete) {
      phase1Status = "ACTIVE";
    } else {
      phase1Status = "COMPLETE";
    }

    snprintf(status_msg, sizeof(status_msg),
             "%s: BASELINE_STATUS: Scanning:%s Established:%s Devices:%d Anomalies:%d Phase1:%s",
             nodeId.c_str(),
             baselineStats.isScanning ? "YES" : "NO",
             baselineEstablished ? "YES" : "NO",
             baselineDeviceCount,
             anomalyCount,
             phase1Status);
    sendToSerial1(String(status_msg), true);
  }
  else if (command.startsWith("DEVICE_SCAN_START:"))
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
      currentScanMode = (ScanMode)mode;
      stopRequested = false;

      if (!workerTaskHandle)
      {
        xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288,
                                (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
      }
      Serial.printf("[MESH] Started device scan via mesh command (%ds)\n", secs);
      sendToSerial1(nodeId + ": DEVICE_SCAN_ACK:STARTED", true);
    }
  }
  else if (command.startsWith("DRONE_START:"))
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

    currentScanMode = SCAN_WIFI;
    stopRequested = false;

    if (!workerTaskHandle)
    {
      xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288,
                              (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
    }
    Serial.printf("[MESH] Started drone detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": DRONE_ACK:STARTED", true);
  }
  else if (command.startsWith("DEAUTH_START:"))
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

    stopRequested = false;

    if (!blueTeamTaskHandle)
    {
      xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 12288,
                              (void *)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
    Serial.printf("[MESH] Started deauth detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": DEAUTH_ACK:STARTED", true);
  }
  else if (command.startsWith("RANDOMIZATION_START:"))
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
      currentScanMode = (ScanMode)mode;
      stopRequested = false;

      if (!workerTaskHandle)
      {
        xTaskCreatePinnedToCore(randomizationDetectionTask, "randdetect", 8192,
                                (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
      }
      Serial.printf("[MESH] Started randomization detection via mesh command (%ds)\n", secs);
      sendToSerial1(nodeId + ": RANDOMIZATION_ACK:STARTED", true);
    }
  }
  else if (command.startsWith("STOP"))
  {
    stopRequested = true;
    Serial.println("[MESH] Stop command received via mesh");
    sendToSerial1(nodeId + ": STOP_ACK:OK", true);
  }
  else if (command.startsWith("STATUS"))
    {
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
                            scanning ? "ACTIVE" : "IDLE",
                            totalHits,
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
  else if (command.startsWith("VIBRATION_STATUS"))
  {
    String status = lastVibrationTime > 0 ? ("Last vibration: " + String(lastVibrationTime) + "ms (" + String((millis() - lastVibrationTime) / 1000) + "s ago)") : "No vibrations detected";
    sendToSerial1(nodeId + ": VIBRATION_STATUS: " + status, true);
  }
  else if (command.startsWith("TRIANGULATE_START:")) {
    String params = command.substring(18);
    int colonPos = params.lastIndexOf(':');
    String target = params.substring(0, colonPos);
    int duration = params.substring(colonPos + 1).toInt();
    
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
        vTaskDelay(pdMS_TO_TICKS(500));
        workerTaskHandle = nullptr;
    }
    
    if (isIdentityId) {
        strncpy(triangulationTargetIdentity, target.c_str(), sizeof(triangulationTargetIdentity) - 1);
        triangulationTargetIdentity[sizeof(triangulationTargetIdentity) - 1] = '\0';
        memset(triangulationTarget, 0, 6);
    } else {
        memcpy(triangulationTarget, macBytes, 6);
        memset(triangulationTargetIdentity, 0, sizeof(triangulationTargetIdentity));
    }
    
    triangulationInitiator = false;  // Child nodes are NEVER initiators
    triangulationActive = true;
    triangulationStart = millis();
    triangulationDuration = duration;
    currentScanMode = SCAN_BOTH;
    stopRequested = false;

    Serial.printf("[TRIANGULATE] Child node started scanning for %s (%ds)\n", target.c_str(), duration);

    // Send acknowledgment to coordinator
    sendToSerial1(nodeId + ": TRI_START_ACK", true);

    if (!workerTaskHandle) {
        xTaskCreatePinnedToCore(listScanTask, "triangulate", 8192,
                               (void *)(intptr_t)duration, 1, &workerTaskHandle, 1);
    }
  }
  else if (command == "TRIANGULATE_STOP")
  {
    Serial.println("[MESH] TRIANGULATE_STOP received");
    stopRequested = true;

    if (triangulationActive) {
        markTriangulationStopFromMesh();
        stopTriangulation();
    }

    sendToSerial1(nodeId + ": TRIANGULATE_STOP_ACK", true);
  }
  else if (command.startsWith("TRI_CYCLE_START:"))
  {
    // Receive synchronized cycle start time from coordinator for slot coordination
    String cycleStartStr = command.substring(16);
    uint32_t cycleStartMs = cycleStartStr.toInt();

    // Initialize the reporting schedule with the coordinator's cycle start time
    reportingSchedule.cycleStartMs = cycleStartMs;
    Serial.printf("[MESH] TRI_CYCLE_START received: %u ms (GPS-synced from coordinator)\n", cycleStartMs);
  }
  else if (command.startsWith("TRIANGULATE_RESULTS"))
  {
    if (triangulationNodes.size() > 0) {
      String results = calculateTriangulation();
      sendToSerial1(nodeId + ": TRIANGULATE_RESULTS_START", true);
      sendToSerial1(results, true);
      sendToSerial1(nodeId + ": TRIANGULATE_RESULTS_END", true);
    } else {
      sendToSerial1(nodeId + ": TRIANGULATE_RESULTS:NO_DATA", true);
    }
  }
  else if (command.startsWith("ERASE_FORCE:"))
  {
    String token = command.substring(12);
    if (validateEraseToken(token))
    {
      executeSecureErase("Force command");
      sendToSerial1(nodeId + ": ERASE_ACK:COMPLETE", true);
    }
  }
  else if (command == "ERASE_CANCEL")
  {
    cancelTamperErase();
    sendToSerial1(nodeId + ": ERASE_ACK:CANCELLED", true);
  }
  else if (command == "ERASE_REQUEST")
  {
    // Generate token without starting countdown - countdown only starts on ERASE_FORCE
    if (tamperAuthToken.length() == 0) {
      tamperAuthToken = generateEraseToken();
      Serial.printf("[ERASE] Token generated on request: %s\n", tamperAuthToken.c_str());
    }

    sendToSerial1(nodeId + ": ERASE_TOKEN:" + tamperAuthToken + " Expires:300s", true);
    Serial.printf("[ERASE] Token provided - valid for 5 minutes\n");
  }
  else if (command.startsWith("AUTOERASE_ENABLE"))
  {
    // Format: AUTOERASE_ENABLE[:setupDelay:eraseDelay:vibrationsRequired:detectionWindow:cooldown]
    if (command.length() > 16 && command.charAt(16) == ':') {
      // Parse parameters
      String params = command.substring(17);
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
  }
  else if (command == "AUTOERASE_DISABLE")
  {
    autoEraseEnabled = false;
    inSetupMode = false;
    saveConfiguration();
    sendToSerial1(nodeId + ": AUTOERASE_ACK:DISABLED", true);
    Serial.println("[AUTOERASE] Disabled");
  }
  else if (command == "AUTOERASE_STATUS")
  {
    // Update setup mode status before reporting
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
            bool found = false;
            for (auto& ack : triangulateAcks) {
                if (ack.nodeId == sendingNode) {
                    found = true;
                    ack.ackTimestamp = millis();  // Update timestamp
                    break;
                }
            }
            if (!found) {
                TriangulateAckInfo newAck;
                newAck.nodeId = sendingNode;
                newAck.ackTimestamp = millis();
                newAck.reportReceived = false;  // Will be set to true when data arrives
                newAck.reportTimestamp = 0;
                triangulateAcks.push_back(newAck);
                Serial.printf("[TRIANGULATE] Node %s added to ACK tracking (%d total nodes)\n",
                             sendingNode.c_str(), triangulateAcks.size());
            }
        }

    }

    if (triangulationActive && colonPos > 0) {
        String sendingNode = cleanMessage.substring(0, colonPos);
        String content = cleanMessage.substring(colonPos + 2);

        // TARGET_DATA from child nodes
        if (content.startsWith("TARGET_DATA:")) {
            String payload = content.substring(13);
            
            int macEnd = payload.indexOf(' ');
            if (macEnd > 0) {
                String reportedMac = payload.substring(0, macEnd);
                uint8_t mac[6];
                
                if (parseMac6(reportedMac, mac) && memcmp(mac, triangulationTarget, 6) == 0) {
                    int hitsIdx = payload.indexOf("Hits=");
                    int rssiIdx = payload.indexOf("RSSI:");
                    int gpsIdx = payload.indexOf("GPS=");
                    int hdopIdx = payload.indexOf("HDOP=");
                    int tsIdx = payload.indexOf("TS=");

                    if (rssiIdx > 0) {
                        int hits = 1;  // Default if no Hits field present
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

                        // Extract detection timestamp
                        int64_t detectionTimestamp = 0;
                        if (tsIdx > 0) {
                            int tsEnd = payload.indexOf(' ', tsIdx + 3);
                            if (tsEnd < 0) tsEnd = payload.length();
                            double timestampSec = payload.substring(tsIdx + 3, tsEnd).toDouble();
                            detectionTimestamp = (int64_t)(timestampSec * 1000000.0);  // Convert to microseconds
                        }
                        
                        bool found = false;
                        for (auto &node : triangulationNodes) {
                            if (node.nodeId == sendingNode) {
                                updateNodeRSSI(node, rssi);
                                node.hitCount = hits;
                                node.isBLE = isBLE;
                                if (hasGPS) {
                                    node.lat = lat;
                                    node.lon = lon;
                                    node.hasGPS = true;
                                    node.hdop = hdop;
                                }
                                // Update detection timestamp
                                if (detectionTimestamp > 0) {
                                    node.detectionTimestamp = detectionTimestamp;
                                }
                                node.distanceEstimate = rssiToDistance(node, !node.isBLE);
                                found = true;
                                Serial.printf("[TRIANGULATE] Updated child %s: hits=%d avgRSSI=%ddBm Type=%s GPS=%s\n",
                                            sendingNode.c_str(), hits, rssi,
                                            node.isBLE ? "BLE" : "WiFi",
                                            hasGPS ? "YES" : "NO");
                                break;
                            }
                        }
                        
                        if (!found) {
                            TriangulationNode newNode;
                            newNode.nodeId = sendingNode;
                            newNode.lat = lat;
                            newNode.lon = lon;
                            newNode.rssi = rssi;
                            newNode.hitCount = hits;
                            newNode.hasGPS = hasGPS;
                            newNode.hdop = hdop;
                            newNode.isBLE = isBLE;
                            newNode.lastUpdate = millis();
                            newNode.detectionTimestamp = detectionTimestamp;
                            initNodeKalmanFilter(newNode);
                            updateNodeRSSI(newNode, rssi);
                            newNode.distanceEstimate = rssiToDistance(newNode, !newNode.isBLE);
                            triangulationNodes.push_back(newNode);
                            Serial.printf("[TRIANGULATE] Added child %s: hits=%d avgRSSI=%ddBm Type=%s\n",
                                        sendingNode.c_str(), hits, rssi,
                                        newNode.isBLE ? "BLE" : "WiFi");
                        }

                        // Mark this node as having reported (coordinator only)
                        if (triangulationInitiator && waitingForFinalReports) {
                            for (auto& ack : triangulateAcks) {
                                if (ack.nodeId == sendingNode) {
                                    if (!ack.reportReceived) {
                                        ack.reportReceived = true;
                                        ack.reportTimestamp = millis();
                                        Serial.printf("[TRIANGULATE] Node %s marked as reported (%s data)\n",
                                                     sendingNode.c_str(), isBLE ? "BLE" : "WiFi");
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            return;  // Message processed
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

                    bool found = false;
                    for (auto &node : triangulationNodes) {
                        if (node.nodeId == sendingNode) {
                            updateNodeRSSI(node, rssi);
                            node.hitCount++;
                            node.isBLE = isBLE;
                            if (hasGPS) {
                                node.lat = lat;
                                node.lon = lon;
                                node.hasGPS = true;
                            }
                            node.distanceEstimate = rssiToDistance(node, !node.isBLE);
                            found = true;
                            Serial.printf("[TRIANGULATE] Updated %s: RSSI=%d->%.1f Type=%s dist=%.1fm Q=%.2f\n",
                                        sendingNode.c_str(), rssi, node.filteredRssi,
                                        node.isBLE ? "BLE" : "WiFi",
                                        node.distanceEstimate, node.signalQuality);
                            break;
                        }
                    }

                    if (!found) {
                      bool isBLE = false;
                      int typeIdx = content.indexOf("Type:");
                      if (typeIdx > 0) {
                          String typeStr = content.substring(typeIdx + 5, content.indexOf(' ', typeIdx + 5));
                          if (typeStr.length() == 0) typeStr = content.substring(typeIdx + 5);
                          isBLE = (typeStr == "BLE");
                      }
                      
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
                      triangulationNodes.push_back(newNode);
                      Serial.printf("[TRIANGULATE] New node %s: RSSI=%d dist=%.1fm\n",
                                    sendingNode.c_str(), rssi, newNode.distanceEstimate);
                  }
                }
            }
        }


        if (content.startsWith("TRIANGULATION_FINAL:")) {
            // Parse: MAC=XX:XX:XX:XX:XX:XX GPS=lat,lon CONF=85.5 UNC=12.3
            String payload = content.substring(20);

            int gpsIdx = payload.indexOf("GPS=");
            int confIdx = payload.indexOf("CONF=");
            int uncIdx = payload.indexOf("UNC=");

            if (gpsIdx > 0 && confIdx > 0 && uncIdx > 0) {
                String gpsStr = payload.substring(gpsIdx + 4, confIdx - 1);
                int comma = gpsStr.indexOf(',');
                if (comma > 0) {
                    apFinalResult.latitude = gpsStr.substring(0, comma).toFloat();
                    apFinalResult.longitude = gpsStr.substring(comma + 1).toFloat();
                }

                apFinalResult.confidence = payload.substring(confIdx + 5, uncIdx - 1).toFloat() / 100.0;
                apFinalResult.uncertainty = payload.substring(uncIdx + 4).toFloat();
                apFinalResult.hasResult = true;
                apFinalResult.timestamp = millis();
                apFinalResult.coordinatorNodeId = sendingNode;  // Store which node sent the final result

                Serial.printf("[TRIANGULATE] Received coordinator final result from %s: %.6f,%.6f conf=%.1f%% unc=%.1fm\n",
                            apFinalResult.coordinatorNodeId.c_str(),
                            apFinalResult.latitude,
                            apFinalResult.longitude,
                            apFinalResult.confidence * 100.0,
                            apFinalResult.uncertainty);
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
                      uint16_t theirSubsec = content.substring(firstColon + 1, secondColon).toInt();
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
                        uint16_t theirSubsec = content.substring(firstColon + 1, secondColon).toInt();
                        uint32_t theirMicros = strtoul(content.substring(secondColon + 1, thirdColon).c_str(), nullptr, 10);
                        uint32_t propDelay = strtoul(content.substring(thirdColon + 1, fourthColon).c_str(), nullptr, 10);
                        
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

void sendMeshNotification(const Hit &hit) {
    if (triangulationActive) return;
    
    if (!meshEnabled || millis() - lastMeshSend < meshSendInterval) return;
    lastMeshSend = millis();
    
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
    
    extern float gpsLat, gpsLon;
    extern bool gpsValid;
    if (gpsValid) {
        baseMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    int msg_len = snprintf(mesh_msg, sizeof(mesh_msg), "%s", baseMsg.c_str());

    if (msg_len > 0 && msg_len <= sizeof(mesh_msg) - 1) {
        delay(10);
        Serial.printf("[MESH] %s\n", mesh_msg);
        sendToSerial1(String(mesh_msg), false);
    }
}