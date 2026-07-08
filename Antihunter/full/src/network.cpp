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

// Network and LoRa
AsyncWebServer *server = nullptr;
static String customApSsid = "";
static String customApPass = "";
const int MAX_RETRIES = 10;
bool meshEnabled = true;
bool hbEnabled = false;
uint32_t hbInterval = 600000;
// Runtime gate for vibration mesh broadcasts (NVS key: "vibEnabled").
// Detection and USB logging always run; this only controls Serial1 TX.
bool vibrationEnabled = true;
unsigned long meshSendInterval = 3000;
std::atomic<bool> g_eraseWipeBusy{false};
volatile uint32_t apScanSuppressUntilMs = 0;
bool triangulationOrchestratorAssigned = false;


// Scanner vars
extern std::atomic<bool> scanning;
extern std::atomic<int> totalHits;
extern UniqueMacsSet uniqueMacs;

// Module refs
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


// T114 handling
SerialRateLimiter rateLimiter;
SemaphoreHandle_t serial1Mutex = nullptr;
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



bool sendToSerial1(const String &message, bool canDelay) {
    {
        int sep = message.indexOf(": ");
        String body = (sep > 0) ? message.substring(sep + 2) : message;
        detect_logIncident(body, "local");
    }
    if (serial1Mutex == nullptr) {
        return false;
    }

    bool isTriangulationMessage = message.indexOf("STOP_ACK") >= 0 ||
                                  message.indexOf("TRI_START_ACK") >= 0 ||
                                  message.indexOf("@ALL TRIANGULATE_START") >= 0 ||
                                  message.indexOf("@ALL TRI_CYCLE_START") >= 0 ||
                                  message.indexOf("TRIANGULATE_STOP") >= 0 ||
                                  message.indexOf(": T_F:") >= 0 ||
                                  message.indexOf(": T_C:") >= 0 ||
                                  message.indexOf(": T_D:") >= 0;

    if (triangulationActive && !isTriangulationMessage) {
        meshTxDroppedTriGate.fetch_add(1);
        return false;
    }

    bool isPriority = isTriangulationMessage;
    size_t msgLen = message.length() + 2;

    TickType_t timeout = isPriority ? pdMS_TO_TICKS(5000) : pdMS_TO_TICKS(1000);
    if (xSemaphoreTake(serial1Mutex, timeout) != pdTRUE) {
        Serial.printf("[MESH] Mutex timeout\n");
        return false;
    }

    // Phase 1 + review fix A: rate-limit check INSIDE mutex so canSend/consume are atomic.
    // Two concurrent senders could otherwise both pass canSend then both consume, oversubscribing the bucket.
    if (!isPriority && !rateLimiter.canSend(msgLen)) {
        meshTxDroppedRateLimit.fetch_add(1);
        xSemaphoreGive(serial1Mutex);
        return false;
    }

    if (isPriority) {
        uint32_t waitStart = millis();
        while (Serial1.availableForWrite() < (int)msgLen) {
            if (millis() - waitStart > 5000) {
                Serial.printf("[MESH] Priority message timeout waiting for buffer space\n");
                xSemaphoreGive(serial1Mutex);
                return false;
            }
            xSemaphoreGive(serial1Mutex);
            delay(10);
            if (xSemaphoreTake(serial1Mutex, timeout) != pdTRUE) {
                Serial.printf("[MESH] Mutex timeout on retry\n");
                return false;
            }
        }
    } else {
        if (Serial1.availableForWrite() < (int)msgLen) {
            meshTxDroppedBufFull.fetch_add(1);
            xSemaphoreGive(serial1Mutex);
            return false;
        }
    }

    Serial1.println(message);
    Serial.printf("[MESH TX] %s\n", message.c_str());

    Serial1.flush();

    // Review fix A (completion): consume INSIDE mutex so canSend/consume are fully atomic.
    if (!isPriority) {
        rateLimiter.consume(msgLen);
    }

    xSemaphoreGive(serial1Mutex);

    return true;
}

// ------------- Network ------------- 

void restart_callback(void* arg) {
  ESP.restart();
}

void initializeNetwork()
{
  esp_coex_preference_set(ESP_COEX_PREFER_WIFI);
  Serial.println("Initializing mesh UART...");
  initializeMesh();

  Serial.println("Starting AP...");
  randomizeMacAddress();
  delay(50);

  WiFi.mode(WIFI_AP_STA);
  delay(100);
  
  customApSsid = prefs.getString("apSsid", AP_SSID);
  customApPass = prefs.getString("apPass", AP_PASS);
  
  if (customApSsid.length() == 0) customApSsid = AP_SSID;
  if (customApPass.length() < 8) customApPass = AP_PASS;
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  bool apOk = WiFi.softAP(customApSsid.c_str(), customApPass.c_str(),
                          AP_CHANNEL, 0, 4, false,
                          WIFI_AUTH_WPA2_WPA3_PSK);
  {
    wifi_config_t apCfg = {};
    if (esp_wifi_get_config(WIFI_IF_AP, &apCfg) == ESP_OK) {
      apCfg.ap.pmf_cfg.capable = false;
      apCfg.ap.pmf_cfg.required = false;
      esp_wifi_set_config(WIFI_IF_AP, &apCfg);
    }
  }
  Serial.printf("[WIFI] AP WPA2/WPA3-PSK mixed mode start (PMF off): %s\n", apOk ? "OK" : "FAIL");
  delay(500);
  WiFi.setHostname("antihunter");
  delay(100);


  WiFi.onEvent([](arduino_event_t *e) {
      if (e->event_id == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
          const auto &d = e->event_info.wifi_ap_stadisconnected;
          Serial.printf("[AP] STA disconnect mac=%02X:%02X:%02X:%02X:%02X:%02X aid=%u reason=%u\n",
                        d.mac[0],d.mac[1],d.mac[2],d.mac[3],d.mac[4],d.mac[5],
                        (unsigned)d.aid, (unsigned)d.reason);
          detect_onSoftApDisconnect(d.mac, (uint8_t)d.reason);
          if (d.reason != 8) apScanSuppressUntilMs = millis() + 5000;
      } else if (e->event_id == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
          detect_onSoftApConnect(e->event_info.wifi_ap_staconnected.mac);
          apScanSuppressUntilMs = millis() + 5000;
      } else if (e->event_id == ARDUINO_EVENT_WIFI_AP_PROBEREQRECVED) {
          const uint8_t *mac = e->event_info.wifi_ap_probereqrecved.mac;
          int8_t rssi = e->event_info.wifi_ap_probereqrecved.rssi;
          detect_onSoftApProbeReq(mac, rssi);
      }
  });

  esp_wifi_set_ps(WIFI_PS_NONE);

  Serial.println("Starting web server...");
  startWebServer();
}

// ------------- AP HTML -------------

#include "web_index_html.h"

void registerRemainingRoutes();

void startWebServer()
{
  if (!server)
    server = new AsyncWebServer(80);

    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type");

  server->on("/", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        // ETag revalidation: 336KB page returns a tiny 304 on repeat loads, re-sent only on new fw
        static const char *ETAG = "\"" __DATE__ __TIME__ "\"";
        if (r->hasHeader("If-None-Match") && r->header("If-None-Match") == ETAG) { r->send(304); return; }
        AsyncWebServerResponse* res = r->beginResponse(200, "text/html", reinterpret_cast<const uint8_t*>(INDEX_HTML), strlen_P(INDEX_HTML));
        res->addHeader("ETag", ETAG);
        res->addHeader("Cache-Control", "no-cache");
        r->send(res); });

  server->on("/export", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getTargetsList()); });

  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (randomizationDetectionEnabled) {
          static String cachedRand = "";
          static uint32_t lastRandCalc = 0;
          if (millis() - lastRandCalc >= 2000) {
              cachedRand = getRandomizationResults();
              lastRandCalc = millis();
          }
          r->send(200, "text/plain", cachedRand);
          return;
      }

      std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
      String results = antihunter::lastResults.empty() ? "None yet." : String(antihunter::lastResults.c_str());

      if (triangulationActive) {
          static String cachedTriResults = "";
          static uint32_t lastTriCalc = 0;

          if (millis() - lastTriCalc >= 2000) {
              cachedTriResults = calculateTriangulation();
              lastTriCalc = millis();
          }

          if (results.indexOf("=== Triangulation Results") >= 0) {
              results = cachedTriResults;
          } else {
              results += "\n\n" + cachedTriResults;
          }
      }

      r->send(200, "text/plain", results);
  });

  server->on("/save", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (!req->hasParam("list", true)) {
            req->send(400, "text/plain", "Missing 'list'");
            return;
        }
        String txt = req->getParam("list", true)->value();
        saveTargetsList(txt);
        saveConfiguration();
        req->send(200, "text/plain", "Saved"); });

  server->on("/node-id", HTTP_POST, [](AsyncWebServerRequest *req) {
      String id = req->hasParam("id", true) ?
          req->getParam("id", true)->value() : "";
      id.trim();
      id.toUpperCase();
      
      if (id.length() < 2 || id.length() > 5) {
          req->send(400, "text/plain", "Node ID must be 2-5 characters");
          return;
      }
      
      for (size_t i = 0; i < id.length(); i++) {
          if (!isalnum(id[i])) {
              req->send(400, "text/plain", "Only alphanumeric characters (A-Z, 0-9) allowed");
              return;
          }
      }
      
      setNodeId(id);
      saveConfiguration();
      req->send(200, "text/plain", "Node ID updated to " + id);
  });

  server->on("/node-id", HTTP_GET, [](AsyncWebServerRequest *r)
             {
    String j = "{\"nodeId\":\"" + getNodeId() + "\"}";
    r->send(200, "application/json", j); });

  server->on("/scan", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
          req->send(409, "text/plain", "Radio busy - stop current scan first");
          return;
      }

      int secs = 60;
      bool forever = false;
      ScanMode mode = SCAN_WIFI;
      
      if (req->hasParam("forever", true)) forever = true;
      if (req->hasParam("secs", true)) {
          int v = req->getParam("secs", true)->value().toInt();
          if (v < 0) v = 0;
          if (v > 86400) v = 86400;
          secs = v;
      }
      if (req->hasParam("mode", true)) {
          int m = req->getParam("mode", true)->value().toInt();
          if (m >= 0 && m <= 2) mode = (ScanMode)m;
      }
      if (req->hasParam("ch", true)) {
          String ch = req->getParam("ch", true)->value();
          parseChannelsCSV(ch);
      }
      saveConfiguration();
      currentScanMode = mode;
      stopRequested = false; 
      
      if (req->hasParam("triangulate", true) && req->hasParam("targetMac", true)) {
          String targetMac = req->getParam("targetMac", true)->value();
          uint8_t rfEnv = RF_ENV_INDOOR;
          if (req->hasParam("rfEnv", true)) {
              rfEnv = req->getParam("rfEnv", true)->value().toInt();
              if (rfEnv > RF_ENV_INDUSTRIAL) rfEnv = RF_ENV_INDOOR;
          }
          setRFEnvironment((RFEnvironment)rfEnv);

          distanceTuning.wifi_multiplier = 1.0f;
          distanceTuning.ble_multiplier = 1.0f;
          distanceTuning.enabled = false;

          if (req->hasParam("wifiPwr", true)) {
              float wifiPwr = req->getParam("wifiPwr", true)->value().toFloat();
              if (wifiPwr >= 0.1f && wifiPwr <= 5.0f) {
                  distanceTuning.wifi_multiplier = wifiPwr;
                  distanceTuning.enabled = true;
              }
          }

          if (req->hasParam("blePwr", true)) {
              float blePwr = req->getParam("blePwr", true)->value().toFloat();
              if (blePwr >= 0.1f && blePwr <= 5.0f) {
                  distanceTuning.ble_multiplier = blePwr;
                  distanceTuning.enabled = true;
              }
          }

          startTriangulation(targetMac, secs);
          String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
          String response = "Triangulation starting for " + String(secs) + "s - " + modeStr + " (env=" + String(rfEnv);
          if (distanceTuning.enabled) {
              response += ", WiFi=" + String(distanceTuning.wifi_multiplier, 1) + "x, BLE=" + String(distanceTuning.ble_multiplier, 1) + "x";
          }
          response += ")";
          req->send(200, "text/plain", response);
          return;
      }
      
      String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
      req->send(200, "text/plain", forever ? ("Scan starting (forever) - " + modeStr) : ("Scan starting for " + String(secs) + "s - " + modeStr));
      
      if (!workerTaskHandle) {
          scanning = true;
          ahCreateTask(listScanTask, "scan", 8192, reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
      }
  });

  server->on("/baseline/status", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = "{";
      json += "\"scanning\":" + String(scanning ? "true" : "false") + ",";
      {
          std::lock_guard<std::mutex> lock(baselineMutex);
          json += "\"established\":" + String(baselineEstablished ? "true" : "false") + ",";
          json += "\"devices\":" + String(baselineDeviceCount);
      }
      json += "}";

      req->send(200, "application/json", json);
  });

  server->on("/baseline/stats", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = "{";
      {
          std::lock_guard<std::mutex> lock(baselineMutex);
          json += "\"scanning\":" + String(baselineStats.isScanning ? "true" : "false") + ",";
          json += "\"phase1Complete\":" + String(baselineStats.phase1Complete ? "true" : "false") + ",";
          json += "\"established\":" + String(baselineEstablished ? "true" : "false") + ",";
          json += "\"wifiDevices\":" + String(baselineStats.wifiDevices) + ",";
          json += "\"bleDevices\":" + String(baselineStats.bleDevices) + ",";
          json += "\"totalDevices\":" + String(baselineStats.totalDevices) + ",";
          json += "\"wifiHits\":" + String(baselineStats.wifiHits) + ",";
          json += "\"bleHits\":" + String(baselineStats.bleHits) + ",";
          json += "\"anomalies\":" + String(anomalyCount) + ",";
          json += "\"elapsedTime\":" + String(baselineStats.elapsedTime) + ",";
          json += "\"totalDuration\":" + String(baselineStats.totalDuration);
      }
      json += "}";

      req->send(200, "application/json", json);
  });

server->on("/baseline/config", HTTP_GET, [](AsyncWebServerRequest *req)
        {
    String json = "{";
    json += "\"rssiThreshold\":" + String(getBaselineRssiThreshold()) + ",";
    json += "\"baselineDuration\":" + String(baselineDuration / 1000) + ",";
    json += "\"ramCacheSize\":" + String(getBaselineRamCacheSize()) + ",";
    json += "\"sdMaxDevices\":" + String(getBaselineSdMaxDevices()) + ",";
    json += "\"absenceThreshold\":" + String(getDeviceAbsenceThreshold() / 1000) + ",";
    json += "\"reappearanceWindow\":" + String(getReappearanceAlertWindow() / 1000) + ",";
    json += "\"rssiChangeDelta\":" + String(getSignificantRssiChange()) + ",";
    json += "\"enabled\":" + String(baselineDetectionEnabled ? "true" : "false") + ",";
    {
        std::lock_guard<std::mutex> lock(baselineMutex);
        json += "\"established\":" + String(baselineEstablished ? "true" : "false") + ",";
        json += "\"deviceCount\":" + String(baselineDeviceCount) + ",";
        json += "\"anomalyCount\":" + String(anomalyCount);
    }
    json += "}";

    req->send(200, "application/json", json);
  });

 server->on("/baseline/config", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (req->hasParam("rssiThreshold", true)) {
          int8_t threshold = req->getParam("rssiThreshold", true)->value().toInt();
          setBaselineRssiThreshold(threshold);
          prefs.putInt("blRssi", threshold);
      }
      
      if (req->hasParam("baselineDuration", true)) {
          int v = req->getParam("baselineDuration", true)->value().toInt();
          if (v < 0) v = 0;
          if (v > 86400) v = 86400;
          baselineDuration = (uint32_t)v * 1000;
          prefs.putUInt("blDuration", baselineDuration);
      }
      
      if (req->hasParam("ramCacheSize", true)) {
          uint32_t ramSize = req->getParam("ramCacheSize", true)->value().toInt();
          setBaselineRamCacheSize(ramSize);
          prefs.putUInt("blRamSize", ramSize);
      }
      
      if (req->hasParam("sdMaxDevices", true)) {
          uint32_t sdMax = req->getParam("sdMaxDevices", true)->value().toInt();
          setBaselineSdMaxDevices(sdMax);
          prefs.putUInt("blSdMax", sdMax);
      }
      
      if (req->hasParam("absenceThreshold", true)) {
          uint32_t absence = req->getParam("absenceThreshold", true)->value().toInt() * 1000;
          setDeviceAbsenceThreshold(absence);
          prefs.putUInt("absenceThresh", absence);
      }
      
      if (req->hasParam("reappearanceWindow", true)) {
          uint32_t reappear = req->getParam("reappearanceWindow", true)->value().toInt() * 1000;
          setReappearanceAlertWindow(reappear);
          prefs.putUInt("reappearWin", reappear);
      }
      
      if (req->hasParam("rssiChangeDelta", true)) {
          int8_t delta = req->getParam("rssiChangeDelta", true)->value().toInt();
          setSignificantRssiChange(delta);
          prefs.putInt("rssiChange", delta);
      }
      
      saveConfiguration();
      req->send(200, "text/plain", "Baseline configuration updated");
  });

  server->on("/baseline/reset", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        resetBaselineDetection();
        req->send(200, "text/plain", "Baseline reset complete"); });

  server->on("/gps", HTTP_GET, [](AsyncWebServerRequest *r)
             {
    String gpsInfo = "GPS Data: " + getGPSData() + "\n";
    if (gpsValid) {
        gpsInfo += "Latitude: " + String(gpsLat, 6) + "\n";
        gpsInfo += "Longitude: " + String(gpsLon, 6) + "\n";
    } else {
        gpsInfo += "GPS: No valid fix\n";
    }
    r->send(200, "text/plain", gpsInfo); });

  server->on("/sd-status", HTTP_GET, [](AsyncWebServerRequest *r)
             {
    String status;
    if (!sdAvailable) {
        status = "SD card: Not available";
    } else {
        uint64_t cardSize = SD.cardSize() / (1024 * 1024);

        uint32_t logSize = 0;
        File logFile = SafeSD::open("/antihunter.log", FILE_READ);
        if (logFile) {
            logSize = logFile.size();
            logFile.close();
        }

        status = "SD Card: Available\n";
        status += "Card Size: " + String(cardSize) + " MB\n";
        status += "Log File Size: " + String(logSize / 1024) + " KB (" + String(logSize) + " bytes)";
    }
    r->send(200, "text/plain", status); });

  server->on("/stop", HTTP_GET, [](AsyncWebServerRequest *req) {
      stopRequested = true;

      if (triangulationActive) {
          stopTriangulation();
      }

      scanning = false;

      if (meshTxDraining.load() || meshTxQueueDepth() > 0) {
          stopMeshDrain.store(true);
      }

      req->send(200, "text/plain", "Scan stopped");
  });
  registerRemainingRoutes();
}


void registerRemainingRoutes() {
  server->on("/api/time", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (!req->hasParam("epoch", true)) {
          req->send(400, "text/plain", "Missing epoch");
          return;
      }
      
      time_t epoch = req->getParam("epoch", true)->value().toInt();
      
      if (epoch < 1609459200 || epoch > 2147483647) {
          req->send(400, "text/plain", "Invalid epoch");
          return;
      }
      
      if (setRTCTimeFromEpoch(epoch)) {
          req->send(200, "text/plain", "OK");
      } else {
          req->send(500, "text/plain", "Failed");
      }
  });

  server->on("/config/autoerase", HTTP_GET, [](AsyncWebServerRequest *req)
             {
    // Update setup mode status before sending response
    updateSetupModeStatus();

    String response = "{";
    response += "\"enabled\":" + String(autoEraseEnabled ? "true" : "false") + ",";
    response += "\"delay\":" + String(autoEraseDelay) + ",";
    response += "\"cooldown\":" + String(autoEraseCooldown) + ",";
    response += "\"vibrationsRequired\":" + String(vibrationsRequired) + ",";
    response += "\"detectionWindow\":" + String(detectionWindow) + ",";
    response += "\"setupDelay\":" + String(setupDelay) + ",";
    response += "\"inSetupMode\":" + String(inSetupMode ? "true" : "false") + ",";
    response += "\"setupStartTime\":" + String(setupStartTime) + ",";
    response += "\"currentTime\":" + String(millis()) + ",";
    response += "\"tamperActive\":" + String(tamperEraseActive ? "true" : "false");
    response += "}";
    req->send(200, "application/json", response); });

  server->on("/config/autoerase", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    Serial.println("\n==================== [AUTOERASE] POST HANDLER CALLED ====================");
    Serial.printf("[AUTOERASE] Total params: %d\n", req->params());

    // Debug all parameters
    for(int i=0; i<req->params(); i++){
      const AsyncWebParameter* p = req->getParam(i);
      Serial.printf("[AUTOERASE] Param[%d]: name='%s' value='%s' isPost=%d\n", i, p->name().c_str(), p->value().c_str(), p->isPost());
    }

    if (!req->hasParam("enabled", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing enabled parameter");
        req->send(400, "text/plain", "Missing enabled parameter");
        return;
    }
    if (!req->hasParam("delay", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing delay parameter");
        req->send(400, "text/plain", "Missing delay parameter");
        return;
    }
    if (!req->hasParam("cooldown", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing cooldown parameter");
        req->send(400, "text/plain", "Missing cooldown parameter");
        return;
    }
    if (!req->hasParam("vibrationsRequired", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing vibrationsRequired parameter");
        req->send(400, "text/plain", "Missing vibrationsRequired parameter");
        return;
    }
    if (!req->hasParam("detectionWindow", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing detectionWindow parameter");
        req->send(400, "text/plain", "Missing detectionWindow parameter");
        return;
    }
    if (!req->hasParam("setupDelay", true)) {
        Serial.println("[AUTOERASE] ERROR: Missing setupDelay parameter");
        req->send(400, "text/plain", "Missing setupDelay parameter");
        return;
    }

    String enabledParam = req->getParam("enabled", true)->value();
    Serial.printf("[AUTOERASE] Received enabled parameter: '%s'\n", enabledParam.c_str());

    autoEraseEnabled = (enabledParam == "true" || enabledParam == "1" || enabledParam == "on");
    autoEraseDelay = req->getParam("delay", true)->value().toInt();
    autoEraseCooldown = req->getParam("cooldown", true)->value().toInt();
    vibrationsRequired = req->getParam("vibrationsRequired", true)->value().toInt();
    detectionWindow = req->getParam("detectionWindow", true)->value().toInt();
    setupDelay = req->getParam("setupDelay", true)->value().toInt();

    Serial.printf("[AUTOERASE] autoEraseEnabled set to: %s\n", autoEraseEnabled ? "TRUE" : "FALSE");

    // Validate ranges
    autoEraseDelay = max(10000, min(300000, (int)autoEraseDelay));
    autoEraseCooldown = max(60000, min(3600000, (int)autoEraseCooldown));
    vibrationsRequired = max(2, min(10, (int)vibrationsRequired));
    detectionWindow = max(5000, min(120000, (int)detectionWindow));
    setupDelay = max(30000, min(600000, (int)setupDelay));  // 30s - 10min

    // Start setup mode when auto-erase is enabled
    if (autoEraseEnabled) {
        inSetupMode = true;
        setupStartTime = millis();

        Serial.printf("[SETUP] Setup mode started - auto-erase activates in %us\n", setupDelay/1000);

        String setupMsg = getNodeId() + ": SETUP_MODE: Auto-erase activates in " + String(setupDelay/1000) + "s";
        sendToSerial1(setupMsg, false);
    } else {
        // Clear setup mode and tamper state when disabled
        inSetupMode = false;
        setupStartTime = 0;
        tamperEraseActive = false;
        tamperSequenceStart = 0;

        Serial.println("[SETUP] Auto-erase disabled - clearing setup mode and tamper state");
    }

    saveConfiguration();
    Serial.printf("[AUTOERASE] After save - autoEraseEnabled is: %s\n", autoEraseEnabled ? "TRUE" : "FALSE");
    req->send(200, "text/plain", "Auto-erase config updated"); });

  server->on("/config", HTTP_GET, [](AsyncWebServerRequest *r) {
      extern RFScanConfig rfConfig;
      
      String configJson = "{\n";
      configJson += "\"nodeId\":\"" + prefs.getString("nodeId", "") + "\",\n";
      configJson += "\"scanMode\":" + String(currentScanMode) + ",\n";
      configJson += "\"channels\":\"" + rfConfig.wifiChannels + "\",\n";
      configJson += "\"targets\":\"" + prefs.getString("maclist", "") + "\"\n";
      configJson += "}";
      
      r->send(200, "application/json", configJson);
  });

  server->on("/config", HTTP_POST, [](AsyncWebServerRequest *req)
             {
      if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
          req->send(409, "text/plain", "Radio busy - stop scan before changing config");
          return;
      }
      if (!req->hasParam("channels", true) || !req->hasParam("targets", true)) {
          req->send(400, "text/plain", "Missing parameters");
          return;
      }

      String channelsCSV = req->getParam("channels", true)->value();
      parseChannelsCSV(channelsCSV);
      prefs.putString("channels", channelsCSV);

      String targets = req->getParam("targets", true)->value();
      saveTargetsList(targets);
      prefs.putString("maclist", targets);

      saveConfiguration();
      req->send(200, "text/plain", "Configuration updated"); });

  server->on("/drone", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        // Radio-busy guard: reject if any scan task is already running
        if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
            req->send(409, "text/plain", "Radio busy - stop current scan first");
            return;
        }

        int secs = 60;
        bool forever = false;

        if (req->hasParam("forever", true)) forever = true;
        if (req->hasParam("secs", true)) {
            int v = req->getParam("secs", true)->value().toInt();
            if (v < 0) v = 0;
            if (v > 86400) v = 86400;
            secs = v;
        }
        
        currentScanMode = SCAN_WIFI;  
        stopRequested = false;
        
        req->send(200, "text/plain", forever ?
                  "Drone detection starting (forever)" :
                  ("Drone detection starting for " + String(secs) + "s")); 
        
        if (!workerTaskHandle) {
            scanning = true;
            ahCreateTask(droneDetectorTask, "drone", 12288,
                                  reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                  1, &workerTaskHandle, 1);
        } });

  server->on("/drone-results", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getDroneDetectionResults()); });

  server->on("/drone-log", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "application/json", getDroneEventLog()); });

  server->on("/drone/status", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        String status = "{";
        status += "\"enabled\":" + String(droneDetectionEnabled ? "true" : "false") + ",";
        status += "\"count\":" + String(droneDetectionCount) + ",";
        size_t uniqueN;
        { std::lock_guard<std::mutex> lock(detectedDronesMutex); uniqueN = detectedDrones.size(); }
        status += "\"unique\":" + String(uniqueN);
        status += "}";
        r->send(200, "application/json", status); });

  server->on("/mesh", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (req->hasParam("enabled", true)) {
            meshEnabled = req->getParam("enabled", true)->value() == "true";
            Serial.printf("[MESH] %s\n", meshEnabled ? "Enabled" : "Disabled");
            req->send(200, "text/plain", meshEnabled ? "Mesh enabled" : "Mesh disabled");
        } else {
            req->send(400, "text/plain", "Missing enabled parameter");
        } });

  server->on("/vibration", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (req->hasParam("enabled", true)) {
            vibrationEnabled = req->getParam("enabled", true)->value() == "true";
            lastSaveTime = 0;
            saveConfiguration();
            Serial.printf("[VIB] Vibration alerts %s via web UI\n", vibrationEnabled ? "enabled" : "disabled");
            req->send(200, "text/plain", vibrationEnabled ? "Vibration alerts enabled" : "Vibration alerts disabled");
        } else {
            req->send(400, "text/plain", "Missing enabled parameter");
        } });

  server->on("/mesh-hb", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (req->hasParam("enabled", true)) {
            hbEnabled = req->getParam("enabled", true)->value() == "true";
            prefs.putBool("hbEnabled", hbEnabled);
            lastSaveTime = 0;
            saveConfiguration();
            Serial.printf("[HB] Status heartbeat %s\n", hbEnabled ? "ENABLED" : "DISABLED");
            req->send(200, "text/plain", hbEnabled ? "Heartbeat enabled" : "Heartbeat disabled");
        } else {
            req->send(400, "text/plain", "Missing enabled parameter");
        } });

  server->on("/mesh-hb-interval", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (req->hasParam("interval", true)) {
            uint32_t minutes = req->getParam("interval", true)->value().toInt();
            if (minutes < 1) minutes = 1;
            if (minutes > 60) minutes = 60;
            hbInterval = minutes * 60000;
            prefs.putUInt("hbInterval", hbInterval);
            saveConfiguration();
            Serial.printf("[HB] Interval set to %u min\n", minutes);
            req->send(200, "text/plain", "Heartbeat interval set to " + String(minutes) + " min");
        } else {
            req->send(400, "text/plain", "Missing interval parameter");
        } });

  server->on("/mesh-test", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        char test_msg[] = "Antihunter: Test mesh notification";
        Serial.printf("[MESH] Test: %s\n", test_msg);
        sendToSerial1(test_msg);
        r->send(200, "text/plain", "Test message sent to mesh"); });

  server->on("/mesh-interval", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!req->hasParam("interval", true)) {
        req->send(400, "text/plain", "Missing interval parameter");
        return;
    }
    
    unsigned long interval = req->getParam("interval", true)->value().toInt();
    
    if (interval < 1500 || interval > 30000) {
        req->send(400, "text/plain", "Interval must be 1500-30000ms");
        return;
    }
    
    meshSendInterval = interval;
    prefs.putULong("meshInterval", interval);
    saveConfiguration();
    
    req->send(200, "text/plain", "Mesh interval updated to " + String(interval) + "ms");
  });

  server->on("/mesh-interval", HTTP_GET, [](AsyncWebServerRequest *req) {
    String json = "{\"interval\":" + String(meshSendInterval) + "}";
    req->send(200, "application/json", json);
  });

  server->on("/mesh-dedup-ttl", HTTP_GET, [](AsyncWebServerRequest *req) {
    String json = "{\"ttl\":" + String(getMeshDedupTtlSec()) +
                  ",\"min\":" + String(MESH_DEDUP_TTL_MIN_S) +
                  ",\"max\":" + String(MESH_DEDUP_TTL_MAX_S) +
                  ",\"count\":" + String(meshDedupCount()) + "}";
    req->send(200, "application/json", json);
  });

  server->on("/mesh-dedup-ttl", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!req->hasParam("ttl", true)) {
      req->send(400, "text/plain", "Missing ttl parameter (0=disabled, 1-3600 seconds)");
      return;
    }
    long ttl = req->getParam("ttl", true)->value().toInt();
    if (ttl < 0 || ttl > (long)MESH_DEDUP_TTL_MAX_S) {
      req->send(400, "text/plain", "ttl must be 0-3600 (0=disable, value=seconds)");
      return;
    }
    setMeshDedupTtlSec((uint32_t)ttl);
    prefs.putUInt("meshDedupTtl", (uint32_t)ttl);
    saveConfiguration();
    String msg = "Mesh dedup TTL set to " + String(ttl) + "s";
    if (ttl == 0) msg += " (dedup DISABLED — every scan broadcasts every device)";
    req->send(200, "text/plain", msg);
  });

  server->on("/mesh-dedup-clear", HTTP_POST, [](AsyncWebServerRequest *req) {
    meshDedupClear();
    req->send(200, "text/plain", "Dedup cache cleared");
  });

  server->on("/mesh/drain/status", HTTP_GET, [](AsyncWebServerRequest *req) {
    String json = "{\"draining\":" + String(meshTxDraining.load() ? "true" : "false") +
                  ",\"sent\":" + String(meshDrainSent.load()) +
                  ",\"total\":" + String(meshDrainTotal.load()) +
                  ",\"dedupCount\":" + String(meshDedupCount()) + "}";
    req->send(200, "application/json", json);
  });

  server->on("/diag", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        String s = getDiagnostics();
        r->send(200, "text/plain", s); });

  server->on("/erase/psk-status", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = String("{\"pskSet\":") + (erasePSK.length() > 0 ? "true" : "false") + "}";
      req->send(200, "application/json", json);
  });

  server->on("/erase/status", HTTP_GET, [](AsyncWebServerRequest *req) {
      String status;
      
      if (eraseStatus == "COMPLETED") {
          status = "COMPLETED";
      }
      else if (eraseInProgress) {
          status = eraseStatus;
      }
      else if (tamperEraseActive) {
          uint32_t timeLeft = autoEraseDelay - (millis() - tamperSequenceStart);
          status = "ACTIVE - Tamper erase countdown: " + String(timeLeft / 1000) + " seconds remaining";
      } else {
          status = "INACTIVE";
      }
      
      req->send(200, "text/plain", status);
  });

  server->on("/erase/request", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    if (!req->hasParam("confirm", true)) {
        req->send(400, "text/plain", "Missing confirmation");
        return;
    }
    
    String confirm = req->getParam("confirm", true)->value();
    bool authed = (erasePSK.length() > 0) ? (confirm == erasePSK) : (confirm == "WIPE_ALL_DATA");
    if (!authed) {
        req->send(403, "text/plain", "Invalid confirmation");
        return;
    }

    if (g_eraseWipeBusy.exchange(true)) {
        req->send(409, "text/plain", "Erase/wipe already in progress");
        return;
    }
    String reason = req->hasParam("reason", true) ? req->getParam("reason", true)->value() : "Manual web request";
    req->send(200, "text/plain", "Secure erase initiated");

    String* reasonPtr = new String(reason);
    if (xTaskCreate([](void* param) {
        String* rp = static_cast<String*>(param);
        delay(1000); // Give web server time to send response
        bool success = executeSecureErase(*rp);
        Serial.println(success ? "Erase completed" : "Erase failed");
        delete rp;
        g_eraseWipeBusy.store(false);
        vTaskDelete(NULL);
    }, "secure_erase", 8192, reasonPtr, 1, NULL) != pdPASS) {
        delete reasonPtr;
        g_eraseWipeBusy.store(false);
    } });

  server->on("/erase/cancel", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    cancelTamperErase();
    req->send(200, "text/plain", "Tamper erase cancelled"); });

  server->on("/factory-wipe", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!req->hasParam("confirm", true)) {
        req->send(400, "text/plain", "Missing confirm");
        return;
    }
    String confirm = req->getParam("confirm", true)->value();
    bool authed = (erasePSK.length() > 0) ? (confirm == erasePSK) : (confirm == "FACTORY_WIPE");
    if (!authed) {
        req->send(403, "text/plain", "Invalid confirm code");
        return;
    }
    String tier = req->hasParam("tier", true) ? req->getParam("tier", true)->value() : "full";
    if (tier != "full" && tier != "config" && tier != "data") {
        req->send(400, "text/plain", "Invalid tier");
        return;
    }
    if (g_eraseWipeBusy.exchange(true)) {
        req->send(409, "text/plain", "Erase/wipe already in progress");
        return;
    }
    req->send(200, "text/plain", "Factory reset (" + tier + ") initiated — device will reboot");
    String* tierPtr = new String(tier);
    if (xTaskCreate([](void* param) {
        String* tp = static_cast<String*>(param);
        String t = *tp;
        delete tp;
        delay(800); // let response flush
        Serial.printf("[FACTORY] Reset requested: %s\n", t.c_str());
        bool ok;
        if (t == "config")      ok = performConfigReset();
        else if (t == "data")   ok = performDataReset();
        else                    ok = performSecureWipe();
        Serial.printf("[FACTORY] Reset %s %s — rebooting\n", t.c_str(), ok ? "OK" : "FAILED");
        delay(300);
        ESP.restart();
    }, "factory_wipe", 8192, tierPtr, 1, NULL) != pdPASS) {
        delete tierPtr;
        g_eraseWipeBusy.store(false);
    }
  });

  server->on("/secure/status", HTTP_GET, [](AsyncWebServerRequest *req) {
      String status = tamperEraseActive ? 
          "TAMPER_ACTIVE:" + String((autoEraseDelay - (millis() - tamperSequenceStart))/1000) + "s" : 
          "INACTIVE";
      req->send(200, "text/plain", status);
  });

  server->on("/secure/abort", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    cancelTamperErase();
    req->send(200, "text/plain", "Cancelled"); });

  // Battery Saver endpoint
  server->on("/battery-saver", HTTP_GET, [](AsyncWebServerRequest *req) {
    String action = req->hasParam("action") ? req->getParam("action")->value() : "status";

    if (action == "start") {
      uint32_t intervalMinutes = req->hasParam("interval") ? req->getParam("interval")->value().toInt() : 5;
      if (intervalMinutes < 1) intervalMinutes = 1;
      if (intervalMinutes > 30) intervalMinutes = 30;
      enterBatterySaver(intervalMinutes * 60000);
      req->send(200, "text/plain", "Battery saver enabled");
    } else if (action == "stop") {
      exitBatterySaver();
      req->send(200, "text/plain", "Battery saver disabled");
    } else {
      // status
      String json = "{\"enabled\":" + String(batterySaverEnabled ? "true" : "false");
      json += ",\"interval\":" + String(batterySaverHeartbeatInterval / 60000);
      uint32_t nextHB = 0;
      if (batterySaverEnabled && lastBatterySaverHeartbeat > 0) {
        uint32_t elapsed = millis() - lastBatterySaverHeartbeat;
        if (elapsed < batterySaverHeartbeatInterval) {
          nextHB = (batterySaverHeartbeatInterval - elapsed) / 1000;
        }
      }
      json += ",\"nextHeartbeat\":" + String(nextHB) + "}";
      req->send(200, "application/json", json);
    }
  });

  server->on("/sniffer", HTTP_POST, [](AsyncWebServerRequest *req) {
        // Radio-busy guard: reject if any scan task is already running
        if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
            req->send(409, "text/plain", "Radio busy - stop current scan first");
            return;
        }

        String detection = req->hasParam("detection", true) ? req->getParam("detection", true)->value() : "device-scan";
        int secs = req->hasParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 60;
        bool forever = req->hasParam("forever", true);
        
        if (detection == "deauth") {
            if (secs < 0) secs = 0; 
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", forever ? "Deauth detection starting (forever)" : ("Deauth detection starting for " + String(secs) + "s"));
            
            if (!blueTeamTaskHandle) {
                scanning = true;
                ahCreateTask(blueTeamTask, "blueteam", 12288, reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &blueTeamTaskHandle, 1);
            }

        } else if (detection == "baseline") {
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;

            stopRequested = false;
            req->send(200, "text/plain",
                    forever ? "Baseline detection starting (forever)" :
                    ("Baseline detection starting for " + String(secs) + "s"));

            if (!workerTaskHandle) {
                currentScanMode = SCAN_BOTH;
                scanning = true;
                ahCreateTask(baselineDetectionTask, "baseline", 12288,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }
            
        } else if (detection == "randomization-detection") {
            int scanMode = SCAN_BOTH;
            if (req->hasParam("randomizationMode", true)) {
                int mode = req->getParam("randomizationMode", true)->value().toInt();
                if (mode >= 0 && mode <= 2) {
                    scanMode = mode;
                }
            }
            
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;

            stopRequested = false;

            String modeStr = (scanMode == SCAN_WIFI) ? "WiFi" :
                            (scanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

            req->send(200, "text/plain",
                    forever ? ("Randomization detection starting (forever) - " + modeStr) :
                    ("Randomization detection starting for " + String(secs) + "s - " + modeStr));

            if (!workerTaskHandle) {
                currentScanMode = (ScanMode)scanMode;
                scanning = true;
                {
                    std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                    antihunter::lastResults = "MAC Randomization Detection Results\nActive Sessions: 0\nDevice Identities: 0\n\n(Starting...)\n";
                }
                ahCreateTask(randomizationDetectionTask, "randdetect", 8192,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }
            
        } else if (detection == "device-scan") {
            int scanMode = SCAN_BOTH;
            if (req->hasParam("deviceScanMode", true)) {
                int mode = req->getParam("deviceScanMode", true)->value().toInt();
                if (mode >= 0 && mode <= 2) {
                    scanMode = mode;
                }
            }
            
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;

            stopRequested = false;

            String modeStr = (scanMode == SCAN_WIFI) ? "WiFi" :
                            (scanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

            req->send(200, "text/plain",
                    forever ? ("Device scan starting (forever) - " + modeStr) :
                    ("Device scan starting for " + String(secs) + "s - " + modeStr));

            if (!workerTaskHandle) {
                currentScanMode = (ScanMode)scanMode;

                if (req->hasParam("captureProbes", true)) {
                    probeDetectionEnabled = true;
                    if (probeRequestQueue == nullptr) {
                        probeRequestQueue = xQueueCreateWithCaps(256, sizeof(ProbeRequestEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    } else {
                        xQueueReset(probeRequestQueue);
                    }
                }

                scanning = true;
                ahCreateTask(snifferScanTask, "sniffer", 12288,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }

        } else if (detection == "probe-scan") {
            int scanMode = SCAN_BOTH;
            if (req->hasParam("probeScanMode", true)) {
                int mode = req->getParam("probeScanMode", true)->value().toInt();
                if (mode >= 0 && mode <= 2) {
                    scanMode = mode;
                }
            }

            bool broadcastAll = req->hasParam("broadcastAll", true);

            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;

            stopRequested = false;

            String modeStr = (scanMode == SCAN_WIFI) ? "WiFi" :
                            (scanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

            req->send(200, "text/plain",
                    forever ? ("Probe scan starting (forever) - " + modeStr + (broadcastAll ? " [ALL]" : "")) :
                    ("Probe scan starting for " + String(secs) + "s - " + modeStr + (broadcastAll ? " [ALL]" : "")));

            if (!workerTaskHandle) {
                currentScanMode = (ScanMode)scanMode;
                scanning = true;
                probeBroadcastAll.store(broadcastAll);
                ahCreateTask(probeDetectionTask, "probedet", 8192,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }

        } else if (detection == "drone-detection") {
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;

            stopRequested = false;
            req->send(200, "text/plain",
                    forever ? "Drone detection starting (forever)" :
                    ("Drone detection starting for " + String(secs) + "s"));

            if (!workerTaskHandle) {
                currentScanMode = SCAN_WIFI;
                scanning = true;
                ahCreateTask(droneDetectorTask, "drone", 12288,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }
            
        } else {
            req->send(400, "text/plain", "Unknown detection mode");
        }
    });

  server->on("/deauth-results", HTTP_GET, [](AsyncWebServerRequest *r) {
      std::lock_guard<std::mutex> lock(deauthLogMutex);
      String results = "Deauth Attack Detection Results\n\n";
      results += "Deauth frames: " + String(deauthCount) + "\n";
      results += "Disassoc frames: " + String(disassocCount) + "\n";
      results += "Total attacks: " + String(deauthLog.size()) + "\n\n";
      
      if (deauthLog.empty()) {
          results += "No attacks detected.\n";
      } else {
          results += "Attack Details:\n";
          results += "===============\n\n";
          
          int show = min((int)deauthLog.size(), 100);
          for (int i = 0; i < show; i++) {
              const auto &hit = deauthLog[i];
              
              results += String(hit.isDisassoc ? "DISASSOCIATION" : "DEAUTHENTICATION");
              
              if (hit.isBroadcast) {
                  results += " [BROADCAST ATTACK]\n";
              } else {
                  results += " [TARGETED]\n";
              }
              
              results += "  From: " + macFmt6(hit.srcMac) + "\n";
              results += "  To: " + macFmt6(hit.destMac) + "\n";
              results += "  Network: " + macFmt6(hit.bssid) + "\n";
              results += "  Signal: " + String(hit.rssi) + " dBm\n";
              results += "  Channel: " + String(hit.channel) + "\n";
              results += "  Reason: " + getDeauthReasonText(hit.reasonCode) + "\n";
              
              uint32_t age = (millis() - hit.timestamp) / 1000;
              if (age < 60) {
                  results += "  Time: " + String(age) + " seconds ago\n";
              } else {
                  results += "  Time: " + String(age / 60) + " minutes ago\n";
              }
              results += "\n";
          }
          
          if ((int)deauthLog.size() > show) {
              results += "... (" + String(deauthLog.size() - show) + " more)\n";
          }
      }
      
      r->send(200, "text/plain", results);
  });

  server->on("/sniffer-cache", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getSnifferCache()); });

    server->on("/randomization-results", HTTP_GET, [](AsyncWebServerRequest *r) {
      static String cachedRandResults = "";
      static uint32_t lastRandCalc = 0;

      // Increased cache to 5 seconds to reduce mutex contention
      if (millis() - lastRandCalc >= 5000) {
          cachedRandResults = getRandomizationResults();
          lastRandCalc = millis();
      }

      r->send(200, "text/plain", cachedRandResults);
  });

  server->on("/randomization/reset", HTTP_POST, [](AsyncWebServerRequest *r) {
      if (scanning || workerTaskHandle) {
          r->send(409, "text/plain", "Radio busy - stop detection before reset");
          return;
      }
      resetRandomizationDetection();
      r->send(200, "text/plain", "Randomization detection reset");
  });

  server->on("/randomization/clear-old", HTTP_POST, [](AsyncWebServerRequest *req) {
      uint32_t now = millis();
      uint32_t ageThreshold = 3600000; // 1 hour

      if (req->hasParam("age", true)) {
          ageThreshold = req->getParam("age", true)->value().toInt() * 1000;
      }

      size_t removed = 0;
      {
          std::lock_guard<std::mutex> lock(randMutex);
          std::vector<String> toRemove;
          for (const auto& entry : deviceIdentities) {
              if (entry.second.lastSeen == 0 || (now - entry.second.lastSeen) > ageThreshold) {
                  toRemove.push_back(entry.first);
              }
          }
          for (const auto& key : toRemove) {
              deviceIdentities.erase(key);
          }
          removed = toRemove.size();
      }

      saveDeviceIdentities();

      Serial.printf("[RAND] Clear-old removed %u identities\n", (unsigned)removed);
      req->send(200, "text/plain", "Removed " + String(removed) + " old identities");
  });

  server->on("/randomization/identities", HTTP_GET, [](AsyncWebServerRequest *r) {
      std::lock_guard<std::mutex> lock(randMutex);
      
      String json = "[";
      bool first = true;
      
      for (const auto& entry : deviceIdentities) {
          if (!first) json += ",";
          first = false;
          
          const DeviceIdentity& track = entry.second;
          
          int16_t avgRssi = 0;
          if (track.signature.rssiHistoryCount > 0) {
              int32_t sum = 0;
              for (uint8_t i = 0; i < track.signature.rssiHistoryCount; i++) {
                  sum += track.signature.rssiHistory[i];
              }
              avgRssi = sum / track.signature.rssiHistoryCount;
          }
          
          String deviceType = track.isBLE ? "BLE Device" : "WiFi Device";
          
          json += "{";
          json += "\"identityId\":\"" + String(track.identityId) + "\",";
          json += "\"sessions\":" + String(track.observedSessions) + ",";
          json += "\"confidence\":" + String(track.confidence, 2) + ",";
          json += "\"avgRssi\":" + String(avgRssi) + ",";
          json += "\"deviceType\":\"" + deviceType + "\",";
          json += "\"sequenceTracking\":" + String(track.sequenceValid ? "true" : "false") + ",";
          json += "\"hasFullSig\":" + String(track.signature.hasFullSignature ? "true" : "false") + ",";
          json += "\"hasMinimalSig\":" + String(track.signature.hasMinimalSignature ? "true" : "false") + ",";
          json += "\"intervalConsistency\":" + String(track.signature.intervalConsistency, 2) + ",";
          json += "\"rssiConsistency\":" + String(track.signature.rssiConsistency, 2) + ",";
          json += "\"observations\":" + String(track.signature.observationCount) + ",";
          
          if (track.hasKnownGlobalMac) {
              json += "\"globalMac\":\"" + macFmt6(track.knownGlobalMac) + "\",";
          }
          
          json += "\"macs\":[";
          for (size_t i = 0; i < track.macs.size(); i++) {
              if (i > 0) json += ",";
              const uint8_t* mac = track.macs[i].bytes.data();
              char macStr[18];
              snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
              json += "\"" + String(macStr) + "\"";
          }
          json += "]}";
      }
      
      json += "]";
      r->send(200, "application/json", json);
  });

  server->on("/api/identity-map", HTTP_GET, [](AsyncWebServerRequest *r) {
      std::lock_guard<std::mutex> lock(randMutex);
      String json = "{";
      bool first = true;
      for (const auto& entry : deviceIdentities) {
          const DeviceIdentity& id = entry.second;
          for (const auto& mac : id.macs) {
              if (!first) json += ",";
              first = false;
              json += "\"" + macFmt6(mac.bytes.data()) + "\":\"" + String(id.identityId) + "\"";
          }
          if (id.hasKnownGlobalMac) {
              if (!first) json += ",";
              first = false;
              json += "\"" + macFmt6(id.knownGlobalMac) + "\":\"" + String(id.identityId) + "\"";
          }
      }
      json += "}";
      AsyncWebServerResponse* res = r->beginResponse(200, "application/json", json);
      res->addHeader("Cache-Control", "no-store");
      r->send(res);
  });

  server->on("/allowlist-export", HTTP_GET, [](AsyncWebServerRequest *r)
           { r->send(200, "text/plain", getAllowlistText()); });

  server->on("/allowlist-save", HTTP_POST, [](AsyncWebServerRequest *req)
            {
        if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
            req->send(409, "text/plain", "Radio busy - stop scan before changing allowlist");
            return;
        }
        if (!req->hasParam("list", true)) {
            req->send(400, "text/plain", "Missing 'list'");
            return;
        }
        String txt = req->getParam("list", true)->value();
        saveAllowlist(txt);
        saveConfiguration();
        req->send(200, "text/plain", "Allowlist saved"); });

  server->on("/triangulate/start", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (scanning || workerTaskHandle || blueTeamTaskHandle || triangulationActive) {
          req->send(409, "text/plain", "Radio busy - stop current scan first");
          return;
      }

      if (!req->hasParam("mac", true) || !req->hasParam("duration", true)) {
        req->send(400, "text/plain", "Missing mac or duration parameter");
        return;
      }

      String targetMac = req->getParam("mac", true)->value();
      int duration = req->getParam("duration", true)->value().toInt();

      if (duration < 20) {
        req->send(400, "text/plain", "Error: Triangulation requires minimum 20 seconds duration");
        return;
      }

      uint8_t macBytes[6];
      if (!parseMac6(targetMac, macBytes)) {
        req->send(400, "text/plain", "Error: Invalid MAC address format");
        return;
      }

      // Set RF environment if specified (0=OpenSky, 1=Suburban, 2=Indoor, 3=IndoorDense, 4=Industrial)
      uint8_t rfEnv = RF_ENV_INDOOR;
      if (req->hasParam("rfEnv", true)) {
          rfEnv = req->getParam("rfEnv", true)->value().toInt();
          if (rfEnv > RF_ENV_INDUSTRIAL) rfEnv = RF_ENV_INDOOR;
      }
      setRFEnvironment((RFEnvironment)rfEnv);

      distanceTuning.wifi_multiplier = 1.0f;
      distanceTuning.ble_multiplier = 1.0f;
      distanceTuning.enabled = false;

      if (req->hasParam("wifiPwr", true)) {
          float wifiPwr = req->getParam("wifiPwr", true)->value().toFloat();
          if (wifiPwr >= 0.1f && wifiPwr <= 5.0f) {
              distanceTuning.wifi_multiplier = wifiPwr;
              distanceTuning.enabled = true;
          }
      }

      if (req->hasParam("blePwr", true)) {
          float blePwr = req->getParam("blePwr", true)->value().toFloat();
          if (blePwr >= 0.1f && blePwr <= 5.0f) {
              distanceTuning.ble_multiplier = blePwr;
              distanceTuning.enabled = true;
          }
      }

      startTriangulation(targetMac, duration);

      String response = "Triangulation started for " + targetMac + " (" + String(duration) + "s, env=" + String(rfEnv);
      if (distanceTuning.enabled) {
          response += ", WiFi=" + String(distanceTuning.wifi_multiplier, 2) + "x, BLE=" + String(distanceTuning.ble_multiplier, 2) + "x";
      }
      response += ")";
      req->send(200, "text/plain", response);
  });

  server->on("/triangulate/stop", HTTP_POST, [](AsyncWebServerRequest *req) {
    stopTriangulation();
    req->send(200, "text/plain", "Triangulation stopped");
  });

  server->on("/triangulate/status", HTTP_GET, [](AsyncWebServerRequest *req) {
    size_t nodeCount;
    {
        std::lock_guard<std::mutex> lock(triangulationMutex);
        nodeCount = triangulationNodes.size();
    }
    String json = "{";
    json += "\"active\":" + String(triangulationActive ? "true" : "false") + ",";
    json += "\"target\":\"" + macFmt6(triangulationTarget) + "\",";
    json += "\"duration\":" + String(triangulationDuration) + ",";
    json += "\"elapsed\":" + String((millis() - triangulationStart) / 1000) + ",";
    json += "\"nodes\":" + String(nodeCount);
    json += "}";
    req->send(200, "application/json", json);
  });

  server->on("/triangulate/results", HTTP_GET, [](AsyncWebServerRequest *req) {
    bool noNodes;
    {
        std::lock_guard<std::mutex> lock(triangulationMutex);
        noNodes = (triangulationNodes.size() == 0);
    }
    if (noNodes) {
      req->send(200, "text/plain", "No triangulation data available");
      return;
    }

    static String cachedTriResults = "";
    static uint32_t lastTriCalc = 0;

    // Recalculate every 1 second for more responsive updates during active triangulation
    if (millis() - lastTriCalc >= 1000) {
      cachedTriResults = calculateTriangulation();
      lastTriCalc = millis();
    }

    req->send(200, "text/plain", cachedTriResults);
  });

  server->on("/triangulate/calibrate", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (!req->hasParam("mac", true) || !req->hasParam("distance", true)) {
          req->send(400, "text/plain", "Missing mac or distance parameter");
          return;
      }

      String targetMac = req->getParam("mac", true)->value();
      float distance = req->getParam("distance", true)->value().toFloat();

      calibratePathLoss(targetMac, distance);
      req->send(200, "text/plain", "Path loss calibration started for " + targetMac + " at " + String(distance) + "m");
  });

  server->on("/triangulate/nodes", HTTP_GET, [](AsyncWebServerRequest *req) {
      // Return triangulation node data as JSON for map display
      String json = "{";
      json += "\"target\":\"" + macFmt6(triangulationTarget) + "\",";
      json += "\"active\":" + String(triangulationActive ? "true" : "false") + ",";

      // Add final result if available
      {
          std::lock_guard<std::mutex> lock(triangulationMutex);
          if (apFinalResult.hasResult) {
              json += "\"finalResult\":{";
              json += "\"lat\":" + String(apFinalResult.latitude, 6) + ",";
              json += "\"lon\":" + String(apFinalResult.longitude, 6) + ",";
              json += "\"confidence\":" + String(apFinalResult.confidence * 100.0, 1) + ",";
              json += "\"uncertainty\":" + String(apFinalResult.uncertainty, 1) + ",";
              json += "\"coordinator\":\"" + apFinalResult.coordinatorNodeId + "\"";
              json += "},";
          }
      }

      // Add nodes array
      std::vector<TriangulationNode> nodesSnapshot;
      {
          std::lock_guard<std::mutex> lock(triangulationMutex);
          nodesSnapshot = triangulationNodes;
      }
      json += "\"nodes\":[";
      for (size_t i = 0; i < nodesSnapshot.size(); i++) {
          const auto& node = nodesSnapshot[i];
          json += "{";
          json += "\"id\":\"" + node.nodeId + "\",";
          json += "\"hasGPS\":" + String(node.hasGPS ? "true" : "false") + ",";
          if (node.hasGPS) {
              json += "\"lat\":" + String(node.lat, 6) + ",";
              json += "\"lon\":" + String(node.lon, 6) + ",";
              json += "\"hdop\":" + String(node.hdop, 1) + ",";
          }
          json += "\"rssi\":" + String(node.filteredRssi, 1) + ",";
          json += "\"hits\":" + String(node.hitCount) + ",";
          json += "\"quality\":" + String(node.signalQuality * 100.0, 1) + ",";
          json += "\"type\":\"" + String(node.isBLE ? "BLE" : "WiFi") + "\",";
          json += "\"distance\":" + String(node.distanceEstimate, 1);
          json += "}";
          if (i < nodesSnapshot.size() - 1) {
              json += ",";
          }
      }
      json += "]";
      json += "}";

      req->send(200, "application/json", json);
  });

  server->on("/rf-config", HTTP_GET, [](AsyncWebServerRequest *req) {
    extern RFScanConfig rfConfig;
    
    String channelsCSV = "";
    for (size_t i = 0; i < CHANNELS.size(); i++) {
        channelsCSV += String(CHANNELS[i]);
        if (i < CHANNELS.size() - 1) {
            channelsCSV += ",";
        }
    }
    
    String json = "{";
    json += "\"preset\":" + String(rfConfig.preset) + ",";
    json += "\"wifiChannelTime\":" + String(rfConfig.wifiChannelTime) + ",";
    json += "\"wifiScanInterval\":" + String(rfConfig.wifiScanInterval) + ",";
    json += "\"bleScanInterval\":" + String(rfConfig.bleScanInterval) + ",";
    json += "\"bleScanDuration\":" + String(rfConfig.bleScanDuration) + ",";
    json += "\"wifiChannels\":\"" + rfConfig.wifiChannels + "\",";
    json += "\"globalRssiThreshold\":" + String(rfConfig.globalRssiThreshold);
    json += "}";
    req->send(200, "application/json", json);
  });

  server->on("/rf-config", HTTP_POST, [](AsyncWebServerRequest *req) {
    bool updated = false;
    
    if (req->hasParam("preset", true)) {
        uint8_t preset = req->getParam("preset", true)->value().toInt();
        if (preset <= 2) {
            setRFPreset(preset);
            updated = true;
            
            if (req->hasParam("globalRssiThreshold", true)) {
                int8_t threshold = req->getParam("globalRssiThreshold", true)->value().toInt();
                rfConfig.globalRssiThreshold = constrain(threshold, -100, -10);
                prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
            }
        }
    } else if (req->hasParam("wifiChannelTime", true)) {
        uint32_t wct = req->getParam("wifiChannelTime", true)->value().toInt();
        uint32_t wsi = req->hasParam("wifiScanInterval", true) ?
                       (uint32_t)req->getParam("wifiScanInterval", true)->value().toInt() : rfConfig.wifiScanInterval;
        uint32_t bsi = req->hasParam("bleScanInterval", true) ?
                       (uint32_t)req->getParam("bleScanInterval", true)->value().toInt() : rfConfig.bleScanInterval;
        uint32_t bsd = req->hasParam("bleScanDuration", true) ?
                       (uint32_t)req->getParam("bleScanDuration", true)->value().toInt() : rfConfig.bleScanDuration;
        int8_t rssiThreshold = req->hasParam("globalRssiThreshold", true) ? 
                              req->getParam("globalRssiThreshold", true)->value().toInt() : rfConfig.globalRssiThreshold;
        String channels = req->hasParam("wifiChannels", true) ? 
                        req->getParam("wifiChannels", true)->value() : rfConfig.wifiChannels;
        setCustomRFConfig(wct, wsi, bsi, bsd, channels, rssiThreshold);
        updated = true;
    } else if (req->hasParam("globalRssiThreshold", true)) {
        int8_t threshold = req->getParam("globalRssiThreshold", true)->value().toInt();
        rfConfig.globalRssiThreshold = constrain(threshold, -100, -10);
        prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
        updated = true;
    }
    
    if (updated) {
        saveConfiguration();
        
        String json = "{";
        json += "\"preset\":" + String(rfConfig.preset) + ",";
        json += "\"wifiChannelTime\":" + String(rfConfig.wifiChannelTime) + ",";
        json += "\"wifiScanInterval\":" + String(rfConfig.wifiScanInterval) + ",";
        json += "\"bleScanInterval\":" + String(rfConfig.bleScanInterval) + ",";
        json += "\"bleScanDuration\":" + String(rfConfig.bleScanDuration) + ",";
        json += "\"wifiChannels\":\"" + String(rfConfig.wifiChannels) + "\",";
        json += "\"globalRssiThreshold\":" + String(rfConfig.globalRssiThreshold);
        json += "}";
        req->send(200, "application/json", json);
    } else {
        req->send(400, "text/plain", "Missing parameters");
    }
  });

  server->on("/wifi-config", HTTP_GET, [](AsyncWebServerRequest *req) {
    String ssid = prefs.getString("apSsid", AP_SSID);
    String pass = prefs.getString("apPass", AP_PASS);
    
    if (ssid.length() == 0) ssid = AP_SSID;
    if (pass.length() == 0) pass = AP_PASS;
    
    String json = "{";
    json += "\"ssid\":\"" + ssid + "\",";
    json += "\"pass\":\"" + pass + "\"";
    json += "}";
    req->send(200, "application/json", json);
  });

  server->on("/clear-results", HTTP_POST, [](AsyncWebServerRequest *req) {
      {
          std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
          antihunter::lastResults.clear();
      }
      req->send(200, "text/plain", "Results cleared");
  });

  // Probe database endpoints
  server->on("/api/probedb", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = getProbeDBJson();
      req->send(200, "application/json", json);
  });

  server->on("/api/probedb/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      clearProbeDB();
      req->send(200, "text/plain", "Probe database cleared");
  });

  server->on("/api/probes.jsonl", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/probes.jsonl")) {
          req->send(SD, "/probes.jsonl", "application/x-ndjson");
      } else {
          req->send(404, "text/plain", "No probe log file");
      }
  });

  server->on("/api/probes/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      SafeSD::remove("/probes.jsonl");
      SafeSD::remove("/probes_old.jsonl");
      req->send(200, "text/plain", "Probe log cleared");
  });

  // --- Data tab API endpoints ---

  server->on("/api/deauth.jsonl", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/deauth.jsonl")) {
          req->send(SD, "/deauth.jsonl", "application/x-ndjson");
      } else {
          req->send(404, "text/plain", "No deauth log file");
      }
  });

  server->on("/api/deauth/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      { std::lock_guard<std::mutex> lock(deauthLogMutex); deauthLog.clear(); }
      deauthCount = 0;
      disassocCount = 0;
      SafeSD::remove("/deauth.jsonl");
      SafeSD::remove("/deauth_old.jsonl");
      req->send(200, "text/plain", "Deauth log cleared");
  });

  server->on("/api/drones.jsonl", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/drones.jsonl")) {
          req->send(SD, "/drones.jsonl", "application/x-ndjson");
      } else {
          req->send(404, "text/plain", "No drone log file");
      }
  });

  server->on("/api/drones/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      { std::lock_guard<std::mutex> lock(detectedDronesMutex); droneEventLog.clear(); detectedDrones.clear(); }
      droneDetectionCount = 0;
      SafeSD::remove("/drones.jsonl");
      SafeSD::remove("/drones_old.jsonl");
      req->send(200, "text/plain", "Drone log cleared");
  });

  server->on("/api/vibrations.jsonl", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/vibrations.jsonl")) {
          req->send(SD, "/vibrations.jsonl", "application/x-ndjson");
      } else {
          req->send(404, "text/plain", "No vibration log file");
      }
  });

  server->on("/api/vibrations/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      SafeSD::remove("/vibrations.jsonl");
      SafeSD::remove("/vibrations_old.jsonl");
      req->send(200, "text/plain", "Vibration log cleared");
  });

  server->on("/api/antihunter.log", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/antihunter.log")) {
          req->send(SD, "/antihunter.log", "text/plain");
      } else {
          req->send(404, "text/plain", "No system log file");
      }
  });

  server->on("/api/antihunter.log/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      SafeSD::remove("/antihunter.log");
      req->send(200, "text/plain", "System log cleared");
  });

  server->on("/wifi-config", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (!req->hasParam("ssid", true)) {
          req->send(400, "text/plain", "Missing SSID parameter");
          return;
      }
      
      String ssid = req->getParam("ssid", true)->value();
      ssid.trim();
      
      if (ssid.length() == 0 || ssid.length() > 32) {
          req->send(400, "text/plain", "SSID must be 1-32 characters");
          return;
      }
      
      String pass = "";
      if (req->hasParam("pass", true)) {
          pass = req->getParam("pass", true)->value();
          if (pass.length() > 0 && (pass.length() < 8 || pass.length() > 63)) {
              req->send(400, "text/plain", "Password must be 8-63 characters or empty");
              return;
          }
      }
      
      prefs.putString("apSsid", ssid);
      if (pass.length() > 0) {
          prefs.putString("apPass", pass);
      }
      
      saveConfiguration();
      
      req->send(200, "text/plain", "WiFi settings saved. Restarting in 3s...");
      esp_timer_handle_t timer;
      esp_timer_create_args_t timer_args = {
        .callback = restart_callback,
        .arg = NULL,
      };
      esp_timer_create(&timer_args, &timer);
      esp_timer_start_once(timer, 3000000);
  });

  // Onboarding disclaimer — persisted in NVS
  server->on("/api/onboarding", HTTP_GET, [](AsyncWebServerRequest *r) {
      bool done = prefs.getBool("obDone", false);
      r->send(200, "application/json", done ? "{\"accepted\":true}" : "{\"accepted\":false}");
  });
  server->on("/api/onboarding", HTTP_POST, [](AsyncWebServerRequest *r) {
      prefs.putBool("obDone", true);
      r->send(200, "application/json", "{\"accepted\":true}");
  });

  // ====== Phase 1-3: /detect endpoints ======

  // Phase 1: attack-signature jsonl getters (RAM log, recent events)
  server->on("/api/pmkid.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getPmkidJsonl());
  });
  server->on("/api/eviltwin.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getEvilTwinJsonl());
  });
  server->on("/api/ssid_confusion.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getSsidConfusionJsonl());
  });
  server->on("/api/sae_dos.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getSaeDosJsonl());
  });
  server->on("/api/owe_abuse.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getOweAbuseJsonl());
  });
  server->on("/api/fragattack.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getFragAttackJsonl());
  });
  server->on("/api/ble_malformed.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", detect_getBleMalformedJsonl());
  });
  server->on("/api/jamming.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/jamming.jsonl")) r->send(SD, "/jamming.jsonl", "application/x-ndjson");
      else r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/jamming/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/jamming.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/meshguard.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/meshguard.jsonl")) r->send(SD, "/meshguard.jsonl", "application/x-ndjson");
      else r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/meshguard/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/meshguard.jsonl"); r->send(200, "text/plain", "cleared");
  });

  // === tool / tool tool-fingerprint logs (NEW) ===
  server->on("/api/ble_attack.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/ble_attack.jsonl"))    r->send(SD, "/ble_attack.jsonl",    "application/x-ndjson");
      else                                   r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/probe_flood.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/probe_flood.jsonl"))   r->send(SD, "/probe_flood.jsonl",   "application/x-ndjson");
      else                                   r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/assoc_sleep.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/assoc_sleep.jsonl"))   r->send(SD, "/assoc_sleep.jsonl",   "application/x-ndjson");
      else                                   r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/pmkid_forge.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/pmkid_forge.jsonl"))   r->send(SD, "/pmkid_forge.jsonl",   "application/x-ndjson");
      else                                   r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/eapol_bait.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/eapol_bait.jsonl"))    r->send(SD, "/eapol_bait.jsonl",    "application/x-ndjson");
      else                                   r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/deauth_flood.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/deauth_flood.jsonl")) r->send(SD, "/deauth_flood.jsonl", "application/x-ndjson");
      else                                  r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/deauth_flood/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/deauth_flood.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/deauth_ap.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/deauth_ap.jsonl")) r->send(SD, "/deauth_ap.jsonl", "application/x-ndjson");
      else                               r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/probe_ap.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/probe_ap.jsonl")) r->send(SD, "/probe_ap.jsonl", "application/x-ndjson");
      else                              r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/apclients.json", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getApClientsJson());
  });
  server->on("/api/ble_attack/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/ble_attack.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/probe_flood/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/probe_flood.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/assoc_sleep/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/assoc_sleep.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/pmkid_forge/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/pmkid_forge.jsonl"); r->send(200, "text/plain", "cleared");
  });
  server->on("/api/eapol_bait/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/eapol_bait.jsonl"); r->send(200, "text/plain", "cleared");
  });

  // === Unified incidents log (all detector events local+peer) ===
  server->on("/api/incidents.json", HTTP_GET, [](AsyncWebServerRequest *r) {
      size_t maxN = 200;
      if (r->hasParam("limit")) {
          int v = r->getParam("limit")->value().toInt();
          if (v > 0 && v <= 200) maxN = (size_t)v;
      }
      r->send(200, "application/json", detect_getIncidentsJson(maxN));
  });
  server->on("/api/incidents.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      if (SD.exists("/incidents.jsonl")) r->send(SD, "/incidents.jsonl", "application/x-ndjson");
      else                               r->send(200, "application/x-ndjson", "");
  });
  server->on("/api/incidents", HTTP_DELETE, [](AsyncWebServerRequest *r) {
      detect_clearIncidents();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/incidents/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_clearIncidents();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/sentinel/status", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"enabled\":") + (sentinel_isUserEnabled() ? "true" : "false") +
                 ",\"running\":" + (sentinel_isRunning() ? "true" : "false") +
                 ",\"scanning\":" + (scanning.load() ? "true" : "false") + "}";
      r->send(200, "application/json", j);
  });
  server->on("/api/sentinel/start", HTTP_POST, [](AsyncWebServerRequest *r) {
      if (scanning.load()) {
          r->send(409, "text/plain", "cannot start: scan active");
          return;
      }
      sentinel_setUserEnabled(true);
      r->send(200, "text/plain", "started (WiFi-only — BLE separate endpoint)");
  });
  server->on("/api/sentinel/ble/start", HTTP_POST, [](AsyncWebServerRequest *r) {
      if (ESP.getFreeHeap() < 60000) {
          r->send(409, "text/plain", "insufficient heap for BLE controller init");
          return;
      }
      extern void radioStartBLE();
      radioStartBLE();
      r->send(200, "text/plain", "BLE scan started");
  });
  server->on("/api/sentinel/stop", HTTP_POST, [](AsyncWebServerRequest *r) {
      sentinel_setUserEnabled(false);
      r->send(200, "text/plain", "stopped");
  });

  server->on("/api/sentinel/boot", HTTP_GET, [](AsyncWebServerRequest *r) {
      Preferences p; bool b = false;
      if (p.begin("antihunter", true)) { b = p.getBool("sentBoot", false); p.end(); }
      r->send(200, "application/json", String("{\"boot\":") + (b ? "true" : "false") + "}");
  });
  server->on("/api/sentinel/boot", HTTP_POST, [](AsyncWebServerRequest *r) {
      bool on = false;
      if (r->hasParam("on", true)) on = r->getParam("on", true)->value().toInt() != 0;
      Preferences p;
      if (p.begin("antihunter", false)) { p.putBool("sentBoot", on); p.end(); }
      Serial.printf("[SENTINEL] Boot auto-start set %s\n", on ? "ON" : "OFF");
      r->send(200, "application/json", String("{\"boot\":") + (on ? "true" : "false") + "}");
  });

  server->on("/api/detect/verbose", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"verbose\":") + (detect_isVerbose() ? "true" : "false") +
                 ",\"mesh_peers\":" + String((unsigned)detect_meshPeerCount()) + "}";
      r->send(200, "application/json", j);
  });
  server->on("/api/detect/verbose/on", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_setVerbose(true);
      r->send(200, "text/plain", "verbose on");
  });
  server->on("/api/detect/verbose/off", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_setVerbose(false);
      r->send(200, "text/plain", "verbose off");
  });
  server->on("/api/eviltwin/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      SafeSD::remove("/eviltwin.jsonl"); r->send(200, "text/plain", "cleared");
  });

  // Phase 2 mesh / quorum / bloom / channel
  server->on("/api/quorum", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getQuorumStatusJson());
  });
  server->on("/api/quorum/config", HTTP_POST, [](AsyncWebServerRequest *r) {
      String type = r->hasParam("type", true) ? r->getParam("type", true)->value() : "";
      int n = r->hasParam("n", true) ? r->getParam("n", true)->value().toInt() : 0;
      if (type.length() == 0 || n <= 0) { r->send(400, "text/plain", "type+n required"); return; }
      quorum_setRequired(type, (uint8_t)n);
      r->send(200, "application/json", "{\"ok\":true}");
  });
  server->on("/api/bloom", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getBloomStatsJson());
  });
  server->on("/api/rid_claims", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getRidClaimsJson());
  });
  server->on("/api/channel_partition", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getChannelAssignmentJson());
  });
  server->on("/api/channel_partition", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_assignChannelPartition();
      r->send(200, "application/json", detect_getChannelAssignmentJson());
  });
  server->on("/api/pps", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"locked\":") + (ppsLocked() ? "true" : "false") +
                 ",\"last_edge\":" + String(ppsLastEdgeMicros()) +
                 ",\"disciplined_us\":" + String((unsigned long long)getDisciplinedMicros()) + "}";
      r->send(200, "application/json", j);
  });

  // Phase 3 BLE perimeter / recon / OUI
  server->on("/api/ble_tracker", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getBleTrackerJson());
  });
  server->on("/api/ble_tracker/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_clearBleTracker();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/recon", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getReconJson());
  });
  server->on("/api/recon/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_clearRecon();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/oui/reload", HTTP_POST, [](AsyncWebServerRequest *r) {
      bool ok = loadOuiTable();
      r->send(200, "application/json", ok ? "{\"loaded\":true}" : "{\"loaded\":false}");
  });
  server->on("/api/detect/clear_all", HTTP_POST, [](AsyncWebServerRequest *r) {
      detect_clearAll();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/detect/health", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getHealthJson());
  });
  server->on("/api/detect/config", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", detect_getConfigJson());
  });
  server->on("/api/detect/config", HTTP_POST,
    [](AsyncWebServerRequest *r) {
        r->send(200, "application/json", "{\"ok\":true}");
    },
    NULL,
    [](AsyncWebServerRequest *r, uint8_t *data, size_t len, size_t index, size_t total) {
        if (index == 0) {
            if (r->_tempObject) { free(r->_tempObject); r->_tempObject = nullptr; }
            if (total == 0 || total > 8192) return;
            r->_tempObject = malloc(total + 1);
        }
        char* acc = static_cast<char*>(r->_tempObject);
        if (!acc || index + len > total) return;
        memcpy(acc + index, data, len);
        if (index + len == total) {
            acc[total] = '\0';
            String json(acc);
            free(acc);
            r->_tempObject = nullptr;
            detect_setConfigFromJson(json);
            detect_persistTunables();
        }
    });

  server->on("/api/probegraph", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", pg_getGraphJson());
  });
  server->on("/api/probegraph/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      pg_clear();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/tracker_chains", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", tracker_getChainsJson());
  });
  server->on("/api/tracker_chains/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      tracker_clearChains();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/airtag_presence", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", airtag_getPresenceJson());
  });
  server->on("/api/airtag_presence/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      airtag_clear();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/handshakes", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", hshk_getReconJson());
  });
  server->on("/api/handshakes/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      hshk_clear();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/handshakes/stats", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"count\":") + String(hshk_count()) +
                 ",\"krack_events\":" + String(hshk_krackEvents()) + "}";
      r->send(200, "application/json", j);
  });

  server->on("/api/attacker_hunts", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", attacker_getActiveHuntsJson());
  });
  server->on("/api/attacker_hunts/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      attacker_clearHunts();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/tof", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", tof_getPeersJson());
  });
  server->on("/api/tof/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      tof_clear();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/tof/ping", HTTP_POST, [](AsyncWebServerRequest *r) {
      String tgt = "*";
      if (r->hasParam("target", true)) tgt = r->getParam("target", true)->value();
      tof_ping(tgt.c_str());
      r->send(200, "application/json", "{\"ok\":true}");
  });

  server->on("/api/tsf_skew", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", tsf_getSkewJson());
  });
  server->on("/api/tsf_skew/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      tsf_clear();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/karma", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", karma_getJson());
  });
  server->on("/api/karma/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      karma_clear();
      r->send(200, "text/plain", "cleared");
  });
  server->on("/api/karma/enable", HTTP_POST, [](AsyncWebServerRequest *r) {
      bool on = true;
      if (r->hasParam("on", true)) on = r->getParam("on", true)->value().toInt() != 0;
      karma_setEnabled(on);
      r->send(200, "application/json", on ? "{\"enabled\":true}" : "{\"enabled\":false}");
  });
  server->on("/api/karma/stats", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"enabled\":") + (karma_isEnabled() ? "true" : "false") +
                 ",\"candidates\":" + String(karma_candidateCount()) +
                 ",\"confirmed\":" + String(karma_confirmedCount()) + "}";
      r->send(200, "application/json", j);
  });

  server->on("/api/pwnagotchi", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", pwnagotchi_getJson());
  });
  server->on("/api/pwnagotchi/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      pwnagotchi_clear();
      r->send(200, "text/plain", "cleared");
  });

  server->on("/api/attacker_hunts/cooldown", HTTP_POST, [](AsyncWebServerRequest *r) {
      uint32_t ms = 60000;
      if (r->hasParam("ms", true)) ms = (uint32_t)r->getParam("ms", true)->value().toInt();
      attacker_setCooldown(ms);
      r->send(200, "application/json", "{\"ok\":true}");
  });

  // Minimal /detect UI page — single-page dashboard for all detectors.
  // Full UI integration into existing HTML tabs follows the same pattern as
  // /baseline/stats / /api/probes.jsonl polling already in the main HTML.
  server->on("/detect", HTTP_GET, [](AsyncWebServerRequest *r) {
      static const char HTML[] PROGMEM = R"HTML(<!doctype html><html><head>
<meta charset=utf-8><title>AntiHunter - Detect</title>
<style>
body{background:#0a0e14;color:#b3d1ff;font:14px/1.4 monospace;margin:0;padding:1em}
h1,h2{color:#ffae00}
section{border:1px solid #2a3f5f;padding:.5em;margin:.5em 0;background:#0d1622}
pre{white-space:pre-wrap;max-height:260px;overflow:auto;background:#000a14;padding:.4em;font-size:12px}
.row{display:flex;flex-wrap:wrap;gap:.5em}
.row>section{flex:1 1 320px}
.k{color:#7fc7ff}.v{color:#fff}
button{background:#23314a;color:#b3d1ff;border:1px solid #3b557d;padding:.3em .7em;cursor:pointer}
button:hover{background:#2f4163}
nav a{color:#ffae00;text-decoration:none;margin-right:1em}
</style></head><body>
<nav><a href="/">Main</a><a href="/detect">Detect</a></nav>
<h1>Detection Engine</h1>
<div class=row>
<section><h2>Attack signatures</h2>
<div><span class=k>PMKID burst:</span> <span id=cnt-pmkid class=v>-</span></div>
<div><span class=k>Evil-twin:</span> <span id=cnt-et class=v>-</span></div>
<div><span class=k>SSID confusion:</span> <span id=cnt-sc class=v>-</span></div>
<div><span class=k>SAE DoS:</span> <span id=cnt-sae class=v>-</span></div>
<div><span class=k>OWE abuse:</span> <span id=cnt-owe class=v>-</span></div>
<div><span class=k>FragAttacks:</span> <span id=cnt-frag class=v>-</span></div>
<div><span class=k>BLE malformed:</span> <span id=cnt-blem class=v>-</span></div>
<button onclick="clearAll()">Clear all</button>
<pre id=stream></pre>
</section>
<section><h2>Mesh defense</h2>
<div><span class=k>PPS lock:</span> <span id=pps class=v>-</span></div>
<div><span class=k>Bloom local bits:</span> <span id=bl class=v>-</span></div>
<div><span class=k>Bloom neighbor bits:</span> <span id=bn class=v>-</span></div>
<div><span class=k>Quorum candidates:</span> <span id=qc class=v>-</span></div>
<button onclick="assignChannels()">Assign channel partition</button>
<pre id=quorum></pre>
<h2>Remote ID claims</h2>
<pre id=rid></pre>
</section>
<section><h2>BLE perimeter</h2>
<div><span class=k>Trackers seen:</span> <span id=trk class=v>-</span></div>
<div><span class=k>Recon flagged:</span> <span id=rec class=v>-</span></div>
<button onclick="fetch('/api/ble_tracker/clear',{method:'POST'})">Clear trackers</button>
<button onclick="fetch('/api/recon/clear',{method:'POST'})">Clear recon</button>
<pre id=trkpre></pre>
<pre id=recpre></pre>
</section>
</div>
<script>
async function jget(u){const r=await fetch(u);try{return await r.json()}catch(e){return await r.text()}}
async function tick(){
 const [pm,et,sc,sa,ow,fr,bm,q,b,p,rid,tr,rc]=await Promise.all([
  fetch('/api/pmkid.jsonl').then(r=>r.text()),
  fetch('/api/eviltwin.jsonl').then(r=>r.text()),
  fetch('/api/ssid_confusion.jsonl').then(r=>r.text()),
  fetch('/api/sae_dos.jsonl').then(r=>r.text()),
  fetch('/api/owe_abuse.jsonl').then(r=>r.text()),
  fetch('/api/fragattack.jsonl').then(r=>r.text()),
  fetch('/api/ble_malformed.jsonl').then(r=>r.text()),
  jget('/api/quorum'),jget('/api/bloom'),jget('/api/pps'),
  jget('/api/rid_claims'),jget('/api/ble_tracker'),jget('/api/recon')
 ]);
 const c=t=>t.split('\n').filter(l=>l.trim()).length;
 cnt_pmkid.textContent=c(pm);cnt_et.textContent=c(et);cnt_sc.textContent=c(sc);
 cnt_sae.textContent=c(sa);cnt_owe.textContent=c(ow);cnt_frag.textContent=c(fr);cnt_blem.textContent=c(bm);
 stream.textContent=[pm,et,sc,sa,ow,fr,bm].join('---\n').slice(-4000);
 pps.textContent=(p.locked?'YES':'no')+' edge='+p.last_edge;
 bl.textContent=b.local_bits_set+' / '+b.capacity_bits;
 bn.textContent=b.neighbor_bits_set+' / '+b.capacity_bits;
 qc.textContent=(q.candidates||[]).length;
 quorum.textContent=JSON.stringify(q,null,2);
 rid_.textContent=JSON.stringify(rid,null,2);
 trk.textContent=(tr||[]).length;
 rec.textContent=(rc||[]).length;
 trkpre.textContent=JSON.stringify(tr,null,2);
 recpre.textContent=JSON.stringify(rc,null,2);
}
const rid_=document.getElementById('rid');
async function clearAll(){await fetch('/api/detect/clear_all',{method:'POST'});tick()}
async function assignChannels(){await fetch('/api/channel_partition',{method:'POST'});tick()}
tick();setInterval(tick,3000);
</script></body></html>)HTML";
      r->send(200, "text/html", reinterpret_cast<const uint8_t*>(HTML), strlen_P(HTML));
  });

  server->begin();
  Serial.println("[WEB] Server started.");
}


void handleEraseRequest(AsyncWebServerRequest *request) {
    if (!request->hasParam("confirm") || !request->hasParam("reason")) {
        request->send(400, "text/plain", "Missing parameters");
        return;
    }
    
    String confirm = request->getParam("confirm")->value();
    String reason = request->getParam("reason")->value();
    
    if (confirm != "WIPE_ALL_DATA") {
        request->send(400, "text/plain", "Invalid confirmation");
        return;
    }

    tamperAuthToken = generateEraseToken();
    
    String response = "Emergency Erase Token Generated: " + tamperAuthToken + "\n\n";
    response += "INSTRUCTIONS:\n";
    response += "1. This will execute immediately\n";
    response += "2. This will PERMANENTLY DESTROY ALL DATA\n\n";
    response += "Reason: " + reason + "\n";
    
    executeSecureErase("Manual web request: " + reason);
    
    request->send(200, "text/plain", response);
}

void handleEraseCancel(AsyncWebServerRequest *request) {
    cancelTamperErase();
    request->send(200, "text/plain", "Tamper erase sequence cancelled");
}
