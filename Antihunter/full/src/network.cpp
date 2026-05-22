#include "network.h"
#include "baseline.h"
#include "triangulation.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include "detect.h"
#include <AsyncTCP.h>
#include <AsyncWebSocket.h>
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
static unsigned long lastMeshSend = 0;
unsigned long meshSendInterval = 3000;
const int MAX_MESH_SIZE = 200; // T114 tests allow 200char/3s in sequence
static String nodeId = "";
bool triangulationOrchestratorAssigned = false;

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

// Scanner vars
extern std::atomic<bool> scanning;
extern std::atomic<int> totalHits;
extern std::set<String> uniqueMacs;

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

// WebSocket for terminal
AsyncWebSocket ws("/terminal");
static std::deque<String> terminalBuffer;
static const size_t TERMINAL_BUFFER_SIZE = 500;
static bool terminalClientsConnected = false;

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

uint32_t SerialRateLimiter::waitTime(size_t messageLength) {
    refillTokens();
    if (tokens >= messageLength) return 0;
    
    uint32_t needed = messageLength - tokens;
    return (needed * REFILL_INTERVAL) / TOKENS_PER_REFILL;
}


void broadcastToTerminal(const String &message) {
    if (!terminalClientsConnected || ws.count() == 0) return;
    
    String timestamped = "[" + getRTCTimeString() + "] " + message;
    ws.textAll(timestamped);
    
    terminalBuffer.push_back(timestamped);
    if (terminalBuffer.size() > TERMINAL_BUFFER_SIZE) {
        terminalBuffer.pop_front();
    }
}

void onTerminalEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, 
                     AwsEventType type, void *arg, uint8_t *data, size_t len) {
    if (type == WS_EVT_CONNECT) {
        Serial.printf("[TERMINAL] Client connected: %u\n", client->id());
        terminalClientsConnected = true;
        
        for (const auto &line : terminalBuffer) {
            client->text(line);
        }
    } else if (type == WS_EVT_DISCONNECT) {
        Serial.printf("[TERMINAL] Client disconnected: %u\n", client->id());
        if (ws.count() == 0) {
            terminalClientsConnected = false;
        }
    }
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
        static uint32_t lastBlockLog = 0;
        if (millis() - lastBlockLog > 10000) {
            Serial.printf("[MESH-BLOCK] Dropping non-triangulation message during active scan: %s\n",
                         message.substring(0, 50).c_str());
            lastBlockLog = millis();
        }
        return false;
    }

    bool isPriority = isTriangulationMessage;
    size_t msgLen = message.length() + 2;

    if (!isPriority && !rateLimiter.canSend(msgLen)) {
        if (canDelay) {
            uint32_t wait = rateLimiter.waitTime(msgLen);
            if (wait > 0 && wait < meshSendInterval) {
                Serial.printf("[MESH] Rate limit: waiting %ums\n", wait);
                broadcastToTerminal("[MESH] Rate limit: waiting..");
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

    TickType_t timeout = isPriority ? pdMS_TO_TICKS(5000) : pdMS_TO_TICKS(100);
    if (xSemaphoreTake(serial1Mutex, timeout) != pdTRUE) {
        Serial.printf("[MESH] Mutex timeout\n");
        return false;
    }

    if (isPriority) {
        uint32_t waitStart = millis();
        while (Serial1.availableForWrite() < msgLen) {
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
        if (Serial1.availableForWrite() < msgLen) {
            Serial.printf("[MESH] Serial1 buffer full (%d/%d bytes)\n", Serial1.availableForWrite(), msgLen);
            xSemaphoreGive(serial1Mutex);
            return false;
        }
    }

    Serial1.println(message);
    Serial.printf("[MESH TX] %s\n", message.c_str());
    broadcastToTerminal("[TX] " + message);

    Serial1.flush();
    delay(50);

    xSemaphoreGive(serial1Mutex);

    if (!isPriority) {
        rateLimiter.consume(msgLen);
    }

    return true;
}

// ------------- Network ------------- 

void restart_callback(void* arg) {
  ESP.restart();
}

void initializeNetwork()
{
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  Serial.println("Initializing mesh UART...");
  initializeMesh();

  Serial.println("Starting AP...");
  WiFi.mode(WIFI_AP_STA);
  delay(100);
  
  randomizeMacAddress();
  delay(50);
  
  customApSsid = prefs.getString("apSsid", AP_SSID);
  customApPass = prefs.getString("apPass", AP_PASS);
  
  if (customApSsid.length() == 0) customApSsid = AP_SSID;
  if (customApPass.length() < 8) customApPass = AP_PASS;
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  bool apOk = WiFi.softAP(customApSsid.c_str(), customApPass.c_str(),
                          AP_CHANNEL, 0, 4, false,
                          WIFI_AUTH_WPA2_WPA3_PSK);
  Serial.printf("[WIFI] AP WPA2/WPA3-PSK mixed mode start: %s\n", apOk ? "OK" : "FAIL");
  delay(500);
  WiFi.setHostname("antihunter");
  delay(100);


  WiFi.onEvent([](arduino_event_t *e) {
      if (e->event_id == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
          const uint8_t *mac = e->event_info.wifi_ap_stadisconnected.mac;
          uint8_t aid = e->event_info.wifi_ap_stadisconnected.aid;
          detect_onSoftApDisconnect(mac, aid);
      } else if (e->event_id == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
          detect_onSoftApConnect(e->event_info.wifi_ap_staconnected.mac);
      } else if (e->event_id == ARDUINO_EVENT_WIFI_AP_PROBEREQRECVED) {
          const uint8_t *mac = e->event_info.wifi_ap_probereqrecved.mac;
          int8_t rssi = e->event_info.wifi_ap_probereqrecved.rssi;
          detect_onSoftApProbeReq(mac, rssi);
      }
  });

  // Configure WiFi to preserve AP during scans
  wifi_config_t conf;
  esp_wifi_get_config(WIFI_IF_AP, &conf);
  esp_wifi_set_config(WIFI_IF_AP, &conf);

  // Set WiFi power save to minimum to maintain AP stability during scans
  esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

  Serial.println("[WIFI] AP configured with scan coexistence enabled");
  Serial.println("Starting web server...");
  startWebServer();
}

void setMeshSendInterval(unsigned long interval) {
    if (interval >= 1500 && interval <= 30000) {
        meshSendInterval = interval;
        prefs.putULong("meshInterval", interval);
        Serial.printf("[MESH] Send interval set to %lums\n", interval);
    } else {
        Serial.println("[MESH] Invalid interval (1500-30000ms)");
    }
}

unsigned long getMeshSendInterval() {
    return meshSendInterval;
}

// ------------- AP HTML -------------

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html data-theme="light">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>AntiHunter</title>
    <style>
      :root{--t:0.2s;--blur:12px}
      [data-theme="light"]{--bg:linear-gradient(135deg,#edf1f6 0%,#e2e8ef 100%);--surf:rgba(255,255,255,0.9);--surf-hover:rgba(255,255,255,0.95);--bord:rgba(0,0,0,0.08);--bord-focus:rgba(72,136,204,0.35);--txt:#1a2030;--mut:#6878a0;--acc:#4080c8;--acch:#3068a8;--accbg:rgba(64,128,200,0.07);--succ:#4080c8;--warn:#a07830;--dang:#a05848;--shad:0 8px 32px rgba(0,0,0,0.06);--shad-hover:0 12px 48px rgba(0,0,0,0.1);--glow:0 0 20px rgba(64,128,200,0.12);--backdrop:blur(12px) saturate(180%);--c-ble:#7882a0;--c-ble-bg:rgba(120,130,160,0.1);--c-wifi:#4080c8;--c-wifi-bg:rgba(64,128,200,0.08);--c-rand:#6878a0;--c-known:#4080c8;--c-away:#a07830;--c-away-bg:rgba(160,120,48,0.07);--c-ap:#4080c8;--c-alert:#a07830;--c-alert-bg:rgba(160,120,48,0.05);--c-ok:#4080c8;--c-err:#a05848;--c-err-bg:rgba(160,88,72,0.05)}
      [data-theme="dark"]{--bg:linear-gradient(135deg,#0a0e16 0%,#0e1420 100%);--surf:rgba(14,20,34,0.85);--surf-hover:rgba(18,26,42,0.95);--bord:rgba(96,160,224,0.12);--bord-focus:rgba(96,160,224,0.35);--txt:#c8d4e0;--mut:#6878a0;--acc:#60a0e0;--acch:#4888cc;--accbg:rgba(96,160,224,0.08);--succ:#60a0e0;--warn:#c09040;--dang:#b86050;--shad:0 8px 32px rgba(0,0,0,0.6);--shad-hover:0 12px 48px rgba(0,0,0,0.8);--glow:0 0 24px rgba(96,160,224,0.15),0 0 48px rgba(96,160,224,0.05);--backdrop:blur(16px) saturate(180%);--c-ble:#7882a0;--c-ble-bg:rgba(120,130,160,0.12);--c-wifi:#60a0e0;--c-wifi-bg:rgba(96,160,224,0.1);--c-rand:#6878a0;--c-known:#60a0e0;--c-away:#c09040;--c-away-bg:rgba(192,144,64,0.08);--c-ap:#60a0e0;--c-alert:#c09040;--c-alert-bg:rgba(192,144,64,0.06);--c-ok:#60a0e0;--c-err:#b86050;--c-err-bg:rgba(184,96,80,0.06)}
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:var(--bg);background-attachment:fixed;color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.6;transition:background var(--t),color var(--t);min-height:100vh}
      .header{padding:18px 28px;border-bottom:1px solid var(--bord);background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);display:flex;align-items:center;gap:18px;box-shadow:var(--shad);flex-wrap:wrap;position:sticky;top:0;z-index:100}
      .header-right{display:flex;align-items:center;gap:16px;margin-left:auto}
      h1{font-size:20px;font-weight:700;flex-shrink:0;letter-spacing:-0.02em;background:linear-gradient(135deg,var(--acc) 0%,var(--acch) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
      h3{margin:0 0 18px;font-size:16px;font-weight:600;letter-spacing:-0.01em;color:var(--txt)}
      .container{max-width:1400px;margin:0 auto;padding:28px}
      .card{background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);border:1px solid var(--bord);border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:var(--shad);transition:all 0.3s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden}
      .card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent 0%,var(--acc) 50%,transparent 100%);opacity:0;transition:opacity 0.3s}
      .card:hover{box-shadow:var(--shad-hover);border-color:var(--bord-focus);transform:translateY(-2px)}
      .card:hover::before{opacity:0.6}
      label{display:block;margin:10px 0 8px;color:var(--mut);font-size:13px;font-weight:600;letter-spacing:0.01em;text-transform:uppercase}
      input,select,textarea{width:100%;background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--bord);border-radius:8px;color:var(--txt);padding:12px 16px;font:inherit;font-size:14px;transition:all 0.2s cubic-bezier(0.4,0,0.2,1);box-shadow:inset 0 1px 3px rgba(0,0,0,0.05)}
      input:hover,select:hover,textarea:hover{border-color:var(--bord-focus)}
      input:focus,select:focus,textarea:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 4px var(--accbg),var(--glow);transform:translateY(-1px)}
      input::placeholder{color:var(--mut);opacity:0.6}
      select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2394a3b8' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}
      [data-theme="dark"] select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234a90e2' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E")}
      textarea{min-height:80px;resize:vertical;line-height:1.5}
      input[type="checkbox"]{width:20px;height:20px;cursor:pointer;position:relative;appearance:none;border:2px solid var(--bord);border-radius:4px;transition:all 0.2s;flex-shrink:0}
      input[type="checkbox"]:checked{background:var(--acc);border-color:var(--acc);box-shadow:var(--glow)}
      input[type="checkbox"]:checked::after{content:'✓';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#fff;font-size:14px;font-weight:bold}
      input[type="number"]{-moz-appearance:textfield}
      input[type="number"]::-webkit-outer-spin-button,input[type="number"]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
      .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 20px;border-radius:8px;border:2px solid var(--bord);background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:var(--txt);text-decoration:none;cursor:pointer;font-size:14px;font-weight:600;transition:all 0.2s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden;white-space:nowrap}
      .btn::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;border-radius:50%;background:rgba(255,255,255,0.1);transform:translate(-50%,-50%);transition:width 0.4s,height 0.4s}
      .btn:hover::before{width:300px;height:300px}
      .btn:hover{transform:translateY(-2px);box-shadow:var(--shad-hover);border-color:var(--bord-focus)}
      .btn:active{transform:translateY(0)}
      .btn.primary{background:linear-gradient(135deg,var(--acc) 0%,var(--acch) 100%);border-color:var(--acc);color:#fff;box-shadow:var(--glow)}
      .btn.primary:hover{box-shadow:var(--glow),var(--shad-hover);filter:brightness(1.1)}
      .btn.alt{color:var(--acc);border-color:var(--acc);background:transparent}
      .btn.danger{background:var(--dang);border-color:var(--dang);color:#fff;box-shadow:0 0 24px rgba(184,96,80,0.3)}
      .btn.danger:hover{filter:brightness(1.15)}
      .theme-toggle{width:48px;height:28px;background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--acc);border-radius:14px;cursor:pointer;position:relative;transition:all 0.3s;margin-left:auto;display:flex;align-items:center;justify-content:center;overflow:hidden;box-shadow:var(--glow)}
      .theme-toggle:hover{transform:scale(1.05);box-shadow:var(--glow),var(--shad)}
      .theme-toggle svg{width:18px;height:18px;position:absolute;transition:opacity 0.3s,transform 0.3s;stroke:var(--acc);fill:var(--acc)}
      .theme-toggle .sun{opacity:1;transform:rotate(0deg) scale(1)}
      .theme-toggle .moon{opacity:0;transform:rotate(90deg) scale(0);stroke:none}
      [data-theme="dark"] .theme-toggle .sun{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="dark"] .theme-toggle .moon{opacity:1;transform:rotate(0deg) scale(1)}
      pre{background:rgba(0,0,0,0.3);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid var(--bord);border-radius:8px;padding:16px;font-size:12px;overflow-x:auto;font-family:monospace;line-height:1.6}
      hr{border:0;border-top:1px solid var(--bord);margin:20px 0}
      .banner{color:var(--dang);border:2px solid var(--dang);padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:600;background:var(--c-err-bg);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      #toast{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:12px;z-index:9999}
      .toast{background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);border:2px solid var(--bord);padding:14px 18px;border-radius:8px;box-shadow:var(--shad-hover);opacity:0;transform:translateY(12px);transition:opacity 0.3s,transform 0.3s;font-size:14px;min-width:280px}
      .toast.show{opacity:1;transform:none}
      .toast.success{border-color:var(--succ);box-shadow:0 0 24px rgba(96,160,224,0.2)}
      .toast.error{border-color:var(--dang);box-shadow:0 0 24px rgba(184,96,80,0.2)}
      .toast.warning{border-color:var(--warn);box-shadow:0 0 24px rgba(192,144,64,0.2)}
      .status-bar{display:flex;gap:10px;align-items:center;flex-shrink:0}
      .status-item{background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--bord);padding:8px 14px;border-radius:6px;font-size:12px;font-weight:600;color:var(--mut);transition:all 0.3s;text-transform:uppercase;letter-spacing:0.05em;position:relative}
      .status-item.idle{border-color:rgba(80,180,120,0.4);background:rgba(80,180,120,0.08);color:#50b478;box-shadow:0 0 12px rgba(80,180,120,0.15),0 0 4px rgba(80,180,120,0.1)}
      .status-item.active{border-color:var(--acc);background:var(--accbg);color:var(--acc);box-shadow:var(--glow);animation:scanPulse 2s ease-in-out infinite}
      @keyframes scanPulse{0%,100%{box-shadow:var(--glow)}50%{box-shadow:0 0 20px rgba(96,160,224,0.3),0 0 40px rgba(96,160,224,0.1)}}
      .tab-buttons{display:flex;gap:6px;margin-bottom:18px;background:rgba(0,0,0,0.1);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:6px;border-radius:10px;border:1px solid var(--bord)}
      .tab-btn{padding:10px 18px;background:transparent;border:none;border-radius:6px;cursor:pointer;color:var(--mut);font-size:13px;font-weight:600;transition:all 0.2s;flex:1;text-align:center}
      .tab-btn.active{background:var(--surf);color:var(--txt);box-shadow:0 2px 8px rgba(0,0,0,0.1)}
      .tab-btn:hover:not(.active){color:var(--acc)}
      .tab-content{display:none}
      .tab-content.active{display:block}
      .stat-item{background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--bord);padding:18px;border-radius:10px;transition:all 0.2s}
      .stat-item:hover{border-color:var(--bord-focus);transform:translateY(-2px);box-shadow:var(--glow)}
      .stat-label{color:var(--mut);font-size:11px;text-transform:uppercase;margin-bottom:8px;font-weight:700;letter-spacing:0.05em}
      .stat-value{color:var(--txt);font-size:24px;font-weight:800;letter-spacing:-0.02em}
      .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
      .card-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none;margin-bottom:18px;padding:4px 0}
      .card-header:hover h3{color:var(--acc)}
      .card-header h3{margin:0;transition:color 0.2s}
      .collapse-icon{transition:transform 0.3s cubic-bezier(0.4,0,0.2,1);font-size:14px;color:var(--mut)}
      .collapse-icon.open{transform:rotate(90deg)}
      .card-body{overflow:hidden;transition:max-height 0.4s cubic-bezier(0.4,0,0.2,1)}
      .card-body.collapsed{max-height:0!important;margin:0;padding:0}
      details>summary{list-style:none;cursor:pointer;font-weight:600;color:var(--acc);margin-bottom:12px;font-size:13px;padding:10px 0;transition:all 0.2s;border-radius:6px}
      details>summary:hover{padding-left:8px;color:var(--acch)}
      details>summary::-webkit-details-marker{display:none}
      @media(min-width:900px){.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:24px}.grid-node-diag{display:grid;grid-template-columns:minmax(300px,auto) 1fr;gap:24px}.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
      @media(max-width:899px){.grid-2,.grid-node-diag{display:flex;flex-direction:column;gap:20px}.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.container{padding:20px}.card{padding:18px}h1{font-size:18px}}
      @media(max-width:600px){.header{padding:12px 16px;gap:10px}.header h1{font-size:16px}.header-right{width:100%;order:3;justify-content:space-between}.page-tabs{order:2;width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}.page-tabs::-webkit-scrollbar{display:none}.page-tab-btn{padding:7px 12px;font-size:12px}.status-bar{gap:6px;flex-wrap:wrap}.status-item{font-size:10px;padding:5px 8px}.theme-toggle{flex-shrink:0}.stat-grid,.diag-grid{grid-template-columns:1fr}input,select,textarea{font-size:16px;padding:10px 14px}.btn{padding:10px 16px;font-size:13px}.container{padding:12px}.card{padding:14px}.tab-btn{padding:8px 12px;font-size:12px}#toast{right:12px;bottom:12px;left:12px}.toast{min-width:0;font-size:13px}}
      .diag-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
      [data-theme="cyber"]{--bg:#000;--surf:rgba(0,20,0,0.8);--surf-hover:rgba(0,30,0,0.9);--bord:#00cc66;--bord-focus:#00ff88;--txt:#00dd77;--mut:#008855;--acc:#00cc66;--acch:#00ff88;--accbg:rgba(0,204,102,0.1);--succ:#00cc66;--warn:#ffcc00;--dang:#ff4444;--shad:0 0 20px rgba(0,204,102,0.3);--shad-hover:0 0 30px rgba(0,204,102,0.5);--glow:0 0 20px rgba(0,204,102,0.4);--backdrop:none;--c-ble:#008855;--c-ble-bg:rgba(0,136,85,0.15);--c-wifi:#00cc66;--c-wifi-bg:rgba(0,204,102,0.1);--c-rand:#008855;--c-known:#00cc66;--c-away:#ffcc00;--c-away-bg:rgba(255,204,0,0.1);--c-ap:#00cc66;--c-alert:#ffcc00;--c-alert-bg:rgba(255,204,0,0.1);--c-ok:#00cc66;--c-err:#ff4444;--c-err-bg:rgba(255,68,68,0.1)}
      [data-theme="cyber"] body{font-family:'Courier New',monospace;text-shadow:0 0 2px rgba(0,255,0,0.7)}
      .theme-toggle .terminal{opacity:0;transform:scale(0);stroke:var(--acc);fill:none}
      [data-theme="cyber"] .theme-toggle .sun{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="cyber"] .theme-toggle .moon{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="cyber"] .theme-toggle .terminal{opacity:1;transform:scale(1)}
      .page-tabs{display:flex;gap:4px;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:4px;border-radius:8px;border:1px solid var(--bord)}
      .page-tab-btn{padding:8px 16px;background:transparent;border:none;border-radius:6px;cursor:pointer;color:var(--mut);font-size:13px;font-weight:600;transition:all 0.2s;white-space:nowrap}
      .page-tab-btn.active{background:var(--surf);color:var(--txt);box-shadow:0 2px 8px rgba(0,0,0,0.1)}
      .page-tab-btn:hover:not(.active){color:var(--acc)}
      .page-tab{display:none}
      .page-tab.active{display:block}
      #page-results #r{min-height:calc(100vh - 200px);overflow-y:auto}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
      #data-table{width:100%;border-collapse:collapse;font-size:12px}
      #data-table th{position:sticky;top:0;background:var(--surf);border-bottom:2px solid var(--bord);padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:var(--mut);cursor:pointer;user-select:none;white-space:nowrap}
      #data-table th:hover{color:var(--acc)}
      #data-table th .sort-arrow{margin-left:4px;font-size:9px}
      #data-table td{padding:6px 10px;border-bottom:1px solid var(--bord);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
      #data-table tr:hover{background:var(--accbg)}
      .data-header{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
      .data-header select{width:auto;min-width:160px;padding:8px 32px 8px 12px;font-size:13px}
      .data-header input[type="text"]{flex:1;min-width:120px;padding:8px 12px;font-size:13px}
      .data-pager{display:flex;align-items:center;justify-content:center;gap:12px;margin-top:12px;font-size:12px;color:var(--mut)}
      .data-pager button{padding:6px 12px}
      .rssi-good{color:var(--succ)}.rssi-mid{color:var(--warn)}.rssi-bad{color:var(--dang)}
      .rand-yes{color:var(--warn);font-weight:600}
      .data-empty{text-align:center;padding:40px 20px;color:var(--mut);font-size:14px}
    </style>
    <script>
      let toggleHistory=[];
      function toggleTheme(){const e=document.documentElement,t=e.getAttribute('data-theme'),now=Date.now();toggleHistory.push(now);toggleHistory=toggleHistory.filter(time=>now-time<2000);if(t==='cyber'){const n=localStorage.getItem('prevTheme')||'light';e.setAttribute('data-theme',n);localStorage.setItem('theme',n);localStorage.removeItem('cyberMode');localStorage.removeItem('prevTheme');toggleHistory=[];return}if(toggleHistory.length>=4&&!localStorage.getItem('cyberMode')){localStorage.setItem('prevTheme',t);e.setAttribute('data-theme','cyber');localStorage.setItem('theme','cyber');localStorage.setItem('cyberMode','1');toggleHistory=[];return}const n='dark'===t?'light':'dark';e.setAttribute('data-theme',n);localStorage.setItem('theme',n)}
      (function(){const e=localStorage.getItem('theme');e?document.documentElement.setAttribute('data-theme',e):document.documentElement.setAttribute('data-theme','light')})();
    </script>
  </head>
  <body>
    <!-- Onboarding disclaimer overlay -->
    <div id="ob-overlay" style="display:none;position:fixed;inset:0;z-index:10000;background:#0b0e14;align-items:center;justify-content:center;flex-direction:column">
      <div style="width:min(460px,92vw);max-height:90vh;display:flex;flex-direction:column">
        <div style="text-align:center;padding:32px 0 20px;flex-shrink:0">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:12px"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/><path d="M8 12a4 4 0 0 0 4 4M16 12a4 4 0 0 0-4-4" opacity="0.5"/></svg>
          <div style="font-size:22px;font-weight:700;color:#e8ecf0;letter-spacing:-0.02em">Welcome to AntiHunter</div>
          <div style="font-size:13px;color:#6878a0;margin-top:4px">WiFi/BLE Detection Node</div>
        </div>
        <div id="ob-scroll" style="flex:1;overflow-y:auto;padding:0 24px 16px;-webkit-overflow-scrolling:touch">
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Authorized Use Only</div><div style="font-size:13px;color:#8898b8;line-height:1.5">For use on networks and systems you own or have explicit written permission to assess. Comply with all local privacy, radio, and telecom laws.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#c09040" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">No Warranty</div><div style="font-size:13px;color:#8898b8;line-height:1.5">Provided "AS IS" without warranty of any kind. Detection accuracy is not guaranteed. Do not rely on this for safety-critical decisions.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Privacy and Data</div><div style="font-size:13px;color:#8898b8;line-height:1.5">All data is stored locally on your device. You are responsible for securing collected data and complying with data protection laws (e.g., GDPR) in your jurisdiction.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Your Responsibility</div><div style="font-size:13px;color:#8898b8;line-height:1.5">By continuing, you accept full responsibility for your actions and agree to indemnify the authors and contributors against any claims arising from your use.</div></div>
          </div>
        </div>
        <div style="padding:12px 24px 28px;flex-shrink:0;text-align:center">
          <div id="ob-hint" style="font-size:11px;color:#6878a0;margin-bottom:10px;transition:opacity 0.3s">Scroll to review all sections</div>
          <button id="ob-btn" disabled onclick="obAccept()" style="width:100%;padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.06);color:#6878a0;font-size:15px;font-weight:600;cursor:not-allowed;transition:all 0.5s cubic-bezier(0.4,0,0.2,1)">Continue</button>
        </div>
      </div>
    </div>
    <style>
      @keyframes ob-glow{0%,100%{box-shadow:0 0 0 0 rgba(64,180,100,0.4)}50%{box-shadow:0 0 24px 4px rgba(64,180,100,0.15)}}
      #ob-btn.ready{background:linear-gradient(135deg,#38a860,#2e8c50);border-color:#38a860;color:#fff;cursor:pointer;animation:ob-glow 2.5s ease-in-out infinite}
      #ob-btn.ready:hover{filter:brightness(1.15);transform:scale(1.02)}
      #ob-scroll::-webkit-scrollbar{width:4px}
      #ob-scroll::-webkit-scrollbar-track{background:transparent}
      #ob-scroll::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.12);border-radius:2px}
    </style>
    <script>
    (function(){
      var ov=document.getElementById('ob-overlay');
      var sc=document.getElementById('ob-scroll');
      var bt=document.getElementById('ob-btn');
      var hn=document.getElementById('ob-hint');
      function chkScroll(){
        if(sc.scrollTop+sc.clientHeight>=sc.scrollHeight-10){
          bt.disabled=false;bt.classList.add('ready');hn.style.opacity='0';
        }
      }
//    fetch('/api/onboarding').then(function(r){return r.json()}).then(function(d){
//      if(!d.accepted){ov.style.display='flex';setTimeout(chkScroll,100)}
//    }).catch(function(){ov.style.display='flex';setTimeout(chkScroll,100)});
//    sc.addEventListener('scroll',chkScroll);
//    window.obAccept=function(){
//      if(bt.disabled)return;
//      fetch('/api/onboarding',{method:'POST'}).then(function(){
//        ov.style.opacity='0';ov.style.transition='opacity 0.4s';
//        setTimeout(function(){ov.style.display='none'},400);
//      });
//    };
    })();
    </script>
    <div id="toast"></div>
    <div class="header">
      <h1>AntiHunter</h1>
      <div class="page-tabs">
        <div class="page-tab-btn active" onclick="switchPage('scan')">Scan</div>
        <div class="page-tab-btn" onclick="switchPage('results')">Results</div>
        <div class="page-tab-btn" onclick="switchPage('system')">System</div>
        <div class="page-tab-btn" onclick="switchPage('data')">Data</div>
        <div class="page-tab-btn" onclick="switchPage('detect')">Sentinel</div>
      </div>
      <div class="header-right">
        <div class="status-bar">
          <div class="status-item" id="modeStatus">WiFi</div>
          <div class="status-item idle" id="scanStatus">Idle</div>
          <div class="status-item" id="sentStatusHdr" onclick="sentinelToggleHdr()" style="cursor:pointer;" title="Click to toggle Sentinel">SENTINEL OFF</div>
          <div class="status-item" id="gpsStatus">GPS</div>
          <div class="status-item" id="rtcStatus">RTC</div>
        </div>
        <div class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
          </svg>
          <svg class="moon" viewBox="0 0 24 24" fill="currentColor">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
          <svg class="terminal" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
            <polyline points="6 8 10 12 6 16"/>
            <line x1="12" y1="12" x2="18" y2="12"/>
          </svg>
        </div>
      </div>
      <a class="btn danger" href="/stop" id="stopAllBtn" style="display:none;">STOP</a>
    </div>
    <div class="container">
      <div class="page-tab active" id="page-scan">

      <!-- Scanning & Targets + Detection Grid -->
      <div class="grid-2" style="margin-bottom:16px;">
        
        <!-- Scanning & Targets -->
        <div class="card">
          <div class="card-header" onclick="toggleCollapse('scanCard')">
            <h3>Scanning & Targets</h3>
            <span class="collapse-icon open" id="scanCardIcon">▶</span>
          </div>
          <div class="card-body" id="scanCardBody">
            
            <!-- Target List -->
            <details open>
              <summary style="cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;"><span>▶</span> Target List</summary>
              <form id="f" method="POST" action="/save">
                <textarea id="list" name="list" placeholder="MAC, OUI, or SSID (one per line)&#10;AA:BB:CC:DD:EE:FF&#10;AA:BB:CC&#10;MyHomeWiFi" rows="3"></textarea>
                <div id="targetCount" style="margin:4px 0 8px;color:var(--mut);font-size:11px;">0 targets</div>
                <div style="display:flex;gap:8px;">
                  <button class="btn primary" type="submit">Save</button>
                  <a class="btn alt" href="/export" download="targets.txt" data-ajax="false">Export</a>
                </div>
              </form>
            </details>
            
            <!-- Allowlist -->
            <details style="margin-top:12px;">
              <summary style="cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;"><span>▶</span> Allow List</summary>
              <form id="af" method="POST" action="/allowlist-save">
                <textarea id="wlist" name="list" placeholder="DD:EE:FF&#10;11:22:33:44:55:66" rows="3"></textarea>
                <div id="allowlistCount" style="margin:4px 0 8px;color:var(--mut);font-size:11px;">0 allowlisted</div>
                <div style="display:flex;gap:8px;">
                  <button class="btn primary" type="submit">Save</button>
                  <a class="btn alt" href="/allowlist-export" download="allowlist.txt" data-ajax="false">Export</a>
                </div>
              </form>
            </details>
            
            <!-- Scan Controls -->
            <form id="s" method="POST" action="/scan">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                <div>
                  <label style="font-size:11px;">Mode</label>
                  <select name="mode">
                    <option value="0">WiFi</option>
                    <option value="1">BLE</option>
                    <option value="2" selected>WiFi+BLE</option>
                  </select>
                </div>
                <div>
                  <label style="font-size:11px;">Duration (s)</label>
                  <input type="number" name="secs" min="0" max="86400" value="60">
                </div>
              </div>
              
              <div style="display:flex;gap:16px;margin-bottom:12px;">
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;">
                  <input type="checkbox" id="forever" name="forever" value="1">Forever
                </label>
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;">
                  <input type="checkbox" id="triangulate" name="triangulate" value="1">Triangulate
                </label>
              </div>
              
              <div id="triangulateOptions" style="display:none;margin-bottom:8px;">
                <input type="text" name="targetMac" placeholder="Target MAC">
                <label style="font-size:11px;margin-top:8px;">RF Environment</label>
                <select name="rfEnv" id="rfEnvSelect">
                  <option value="0">Open Sky</option>
                  <option value="1">Suburban</option>
                  <option value="2" selected>Indoor</option>
                  <option value="3">Indoor Dense</option>
                  <option value="4">Industrial</option>
                </select>

                <label style="font-size:11px;margin-top:12px;display:block;">Distance Tuning</label>
                <div style="margin-bottom:6px;">
                  <label style="font-size:10px;color:var(--mut);">WiFi: <span id="wifiPwrDisplay">1.0x</span></label>
                  <input type="range" name="wifiPwr" id="wifiPwrSlider" min="0.1" max="5.0" step="0.1" value="1.0"
                        oninput="document.getElementById('wifiPwrDisplay').innerText = this.value + 'x'"
                        style="width:100%;">
                </div>
                <div style="margin-bottom:4px;">
                  <label style="font-size:10px;color:var(--mut);">BLE: <span id="blePwrDisplay">1.0x</span></label>
                  <input type="range" name="blePwr" id="blePwrSlider" min="0.1" max="5.0" step="0.1" value="1.0"
                        oninput="document.getElementById('blePwrDisplay').innerText = this.value + 'x'"
                        style="width:100%;">
                </div>
                <p style="font-size:9px;color:var(--mut);margin:4px 0 0 0;"><1.0 closer | >1.0 farther</p>
              </div>
              
              <button class="btn primary" type="submit" style="width:100%;">Start Scan</button>
            </form>
          </div>
        </div>
        
        <!-- Detection & Analysis -->
        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detectionCard')">
            <h3>Detection & Analysis</h3>
            <span class="collapse-icon open" id="detectionCardIcon">▶</span>
          </div>
          <div class="card-body" id="detectionCardBody"> <!-- Add this wrapper -->
            <form id="sniffer" method="POST" action="/sniffer">
              <label>Method</label>
              <select name="detection" id="detectionMode">
                <option value="device-scan" selected>Device Discovery</option>
                <option value="baseline">Baseline Anomaly Sniffer</option>
                <option value="randomization-detection">Randomized Device Tracer</option>
                <option value="deauth">Deauthentication Attack Detection</option>
                <option value="drone-detection">Drone RID Detection (WiFi)</option>
                <option value="probe-scan">Probe Request Scanner</option>
              </select>

              <div id="probeScanModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="probeScanMode" name="probeScanMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
                <label style="font-size:11px;margin-top:6px;display:block;"><input type="checkbox" name="broadcastAll" value="1" style="margin-right:4px;">Broadcast All Probes (mesh)</label>
              </div>
              <div id="randomizationModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="randomizationMode" name="randomizationMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
              </div>
              <div id="deviceScanModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="deviceScanMode" name="deviceScanMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
                <label style="font-size:11px;margin-top:6px;display:block;"><input type="checkbox" name="captureProbes" value="1" style="margin-right:4px;">Capture Probes</label>
              </div>
              <div id="standardDurationControls" style="margin-top:10px;">
                <div style="display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end;">
                  <div>
                    <label style="font-size:11px;">Duration (s)</label>
                    <input type="number" name="secs" min="0" max="86400" value="60" id="detectionDuration">
                  </div>
                  <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;">
                    <input type="checkbox" id="forever3" name="forever" value="1">Forever
                  </label>
                </div>
              </div>
              
              <div id="baselineConfigControls" style="display:none;margin-top:10px;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:11px;">RSSI</label>
                    <select id="baselineRssiThreshold" name="rssiThreshold">
                      <option value="-40">-40</option>
                      <option value="-50">-50</option>
                      <option value="-60" selected>-60</option>
                      <option value="-70">-70</option>
                      <option value="-80">-80</option>
                    </select>
                  </div>
                  <div>
                    <label style="font-size:11px;">Baseline</label>
                    <select id="baselineDuration" name="baselineDuration">
                      <option value="300" selected>5m</option>
                      <option value="600">10m</option>
                      <option value="900">15m</option>
                    </select>
                  </div>
                </div>
                
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:11px;">RAM Cache (Non-SD defaults to 1500)</label>
                    <input type="number" id="baselineRamSize" name="ramCacheSize" min="200" max="500" value="400" style="padding:6px;">
                  </div>
                  <div>
                    <label style="font-size:11px;">SD Device Storage</label>
                    <input type="number" id="baselineSdMax" name="sdMaxDevices" min="1000" max="100000" value="50000" step="1000" style="padding:6px;">
                  </div>
                </div>
                
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Time a device must be unseen before marked as disappeared from baseline">Marked Absent (s)</label>
                    <input type="number" id="absenceThreshold" min="30" max="600" value="120" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Window after disappearance during which reappearance triggers an anomaly alert">Seen Reappear (s)</label>
                    <input type="number" id="reappearanceWindow" min="60" max="1800" value="300" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Minimum RSSI change in dBm to flag as significant signal strength variation">RSSI Variation dB</label>
                    <input type="number" id="rssiChangeDelta" min="5" max="50" value="20" style="padding:4px;font-size:11px;">
                  </div>
                </div>
                
                <label style="font-size:11px;">Monitor (s)</label>
                <input type="number" name="secs" min="0" max="86400" value="300" id="baselineMonitorDuration" style="margin-bottom:8px;">
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;color:var(--txt);">
                  <input type="checkbox" id="foreverBaseline" name="forever" value="1" style="width:auto;margin:0;">
                  <span>Forever</span>
                </label>
              </div>
              
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;">
                <button class="btn primary" type="submit" id="startDetectionBtn" style="flex:1;min-width:80px;">Start</button>
                <a class="btn alt" href="/sniffer-cache" data-ajax="false" id="cacheBtn" style="display:none;">Cache</a>
                <button class="btn alt" type="button" onclick="resetBaseline()" style="display:none;" id="resetBaselineBtn">Reset</button>
                <button type="button" class="btn" id="clearOldBtn" style="display:none;" onclick="clearOldIdentities()">Clear Old</button>
                <button type="button" class="btn" id="resetRandBtn" style="display:none;" onclick="resetRandomizationDetection()">Reset All</button>
              </div>
             
            </form>
          </div>
        </div>
      </div>
      </div>

      <div class="page-tab" id="page-results">
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:12px;">
          <h3 style="margin:0;">Scan Results</h3>
          <div style="display:flex;gap:8px;align-items:center;">
            <label style="font-size:11px;color:var(--mut);">Sort:</label>
            <select id="sortBy" onchange="applySorting()" style="padding:6px 8px;border-radius:6px;font-size:11px;">
              <option value="default">Default</option>
              <option value="rssi-desc">RSSI (Strongest)</option>
              <option value="rssi-asc">RSSI (Weakest)</option>
              <option value="confidence-desc">Confidence (High)</option>
              <option value="sessions-desc">Sessions (Most)</option>
              <option value="lastseen-asc">Last Seen (Recent)</option>
              <option value="name-asc">Name (A-Z)</option>
              <option value="type-asc">Type (WiFi/BLE)</option>
              <option value="channel-asc">Channel (Low-High)</option>
            </select>
            <button class="btn alt" type="button" onclick="toggleSortOrder()" style="padding:6px 10px;font-size:11px;line-height:1;" title="Reverse sort"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="14" viewBox="0 0 10 14" fill="currentColor"><path d="M5 0L10 5H0Z"/><path d="M5 14L0 9H10Z"/></svg></button>
            <button class="btn alt" type="button" onclick="clearResults()" style="padding:6px 10px;font-size:11px;">Clear</button>
            <button class="btn" id="privacyBtn" type="button" onclick="togglePrivacy()" style="padding:6px 10px;font-size:11px;white-space:nowrap;flex-shrink:0;"></button>
          </div>
        </div>
        <div id="baselineStatus" style="display:none;padding:12px;background:var(--surf);border:2px solid var(--acc);border-radius:8px;font-size:12px;margin-bottom:12px;">
          <div style="color:var(--mut);">No baseline data</div>
        </div>
        <div id="r" style="margin:0;">No scan data yet.</div>
      </div>
      </div>

      <div class="page-tab" id="page-system">

      <div class="card" style="margin-bottom:16px;">
          <h3>System Diagnostics</h3>
          <div class="tab-buttons">
            <div class="tab-btn active" onclick="switchTab('overview')">Overview</div>
            <div class="tab-btn" onclick="switchTab('hardware')">Hardware</div>
            <div class="tab-btn" onclick="switchTab('network')">Network</div>
          </div>
          <div id="overview" class="tab-content active">
            <div class="stat-grid">
              <div class="stat-item"><div class="stat-label">Uptime</div><div class="stat-value" id="uptime">--:--:--</div></div>
              <div class="stat-item"><div class="stat-label">WiFi Frames</div><div class="stat-value" id="wifiFrames">0</div></div>
              <div class="stat-item"><div class="stat-label">BLE Frames</div><div class="stat-value" id="bleFrames">0</div></div>
              <div class="stat-item"><div class="stat-label">Target Hits</div><div class="stat-value" id="totalHits">0</div></div>
              <div class="stat-item"><div class="stat-label">Unique Devices</div><div class="stat-value" id="uniqueDevices">0</div></div>
              <div class="stat-item"><div class="stat-label">CPU Temp</div><div class="stat-value" id="temperature">--C</div></div>
            </div>
          </div>
          <div id="hardware" class="tab-content"><div id="hardwareDiag">Loading...</div></div>
          <div id="network" class="tab-content"><div id="networkDiag">Loading...</div></div>
      </div>

    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h3>RF Settings</h3>
        <div class="" id="detectionCardBody">
          <label style="font-size:11px;">Global RSSI Filter (dBm)</label>
          <div style="display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:12px;align-items:center;">
            <input type="range" id="globalRssiSlider" min="-100" max="-10" value="-95" 
                  oninput="document.getElementById('globalRssiValue').innerText = this.value + ' dBm'">
            <span id="globalRssiValue" style="font-size:12px;min-width:70px;">-95 dBm</span>
          </div>
          <p style="font-size:10px;color:var(--mut);margin-bottom:12px;">Filters weak signals (triangulation exempt)</p>

          <hr style="margin:12px 0;border:none;border-top:1px solid var(--bord);">

          <select id="rfPreset" onchange="updateRFPresetUI()">
            <option value="0">Relaxed (Stealthy)</option>
            <option value="1">Balanced (Default)</option>
            <option value="2">Aggressive (Fast)</option>
            <option value="3">Custom</option>
          </select>
          
          <div id="customRFSettings" style="display:none;margin-top:10px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--mut);">WiFi Channel Time (ms)</label>
                <input type="number" id="wifiChannelTime" min="110" max="300" value="120" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--mut);">WiFi Scan Interval (ms)</label>
                <input type="number" id="wifiScanInterval" min="1000" max="10000" value="4000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--mut);">BLE Scan Duration (ms)</label>
                <input type="number" id="bleScanDuration" min="1000" max="5000" value="2000" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--mut);">BLE Scan Interval (ms)</label>
                <input type="number" id="bleScanInterval" min="1000" max="10000" value="2000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="margin-bottom:8px;">
              <label style="font-size:10px;color:var(--mut);">WiFi Channels</label>
              <input type="text" id="wifiChannels" placeholder="1..14" value="1..14" style="padding:4px;font-size:11px;">
            </div>
          </div>
        </div>
        <button class="btn primary" type="button" onclick="saveRFConfig()" style="width:100%;margin-top:8px;">Save RF Settings</button>

        <hr style="margin:16px 0;border:none;border-top:1px solid var(--bord);">
        <div class="card-header" onclick="toggleCollapse('wifiApCard')" style="cursor:pointer;padding:0;margin-bottom:12px;border:none;background:none;box-shadow:none;">
            <h4 style="margin:0;font-size:13px;">WiFi Access Point</h4>
            <span class="collapse-icon" id="wifiApCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="wifiApCardBody" style="max-height:0;">
            <label style="font-size:11px;">SSID</label>
            <input type="text" id="apSsid" maxlength="32" placeholder="Antihunter" style="margin-bottom:8px;">
            
            <label style="font-size:11px;">Password</label>
            <input type="password" id="apPass" minlength="8" maxlength="63" placeholder="Min 8 characters" style="margin-bottom:8px;">
            
            <button class="btn primary" type="button" onclick="saveWiFiConfig()" style="width:100%;margin-top:8px;">Save WiFi Settings</button>
          </div>
        </div>

      <div class="card">
          <h3>Node Configuration</h3>
          <form id="nodeForm" method="POST" action="/node-id" novalidate>
            <label>Node ID</label>
            <input type="text" id="nodeId" name="id" minlength="2" maxlength="5" placeholder="AH01" pattern="^[A-Z0-9]{2,5}$" style="text-transform:uppercase;">
            <button class="btn primary" type="submit" style="margin-top:8px;width:100%;">Update</button>
          </form>
          
          <hr>
          
          <div style="margin-top:12px;">
            <label>Mesh Communications</label>
            <div style="display:flex;gap:8px;margin-bottom:12px;">
              <button class="btn" id="meshToggleBtn" onclick="toggleMesh()" style="flex:1;"></button>
            </div>
            
            <div id="meshControls" style="display:none;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <input type="checkbox" id="hbEnabledCb" onchange="toggleHb()" style="width:20px;height:20px;">
                <label style="margin:0;font-size:13px;cursor:pointer;" for="hbEnabledCb">Status Heartbeat</label>
              </div>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
                <input type="number" id="hbIntervalInput" min="1" max="60" step="1" value="10" style="flex:1;">
                <label style="margin:0;font-size:12px;color:var(--mut);white-space:nowrap;">min interval</label>
                <button class="btn" onclick="saveHbInterval()">Save</button>
              </div>
              <label>Mesh Send Interval (ms)</label>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
                <input type="number" id="meshInterval" min="1500" max="30000" step="100" value="5000" style="flex:1;">
                <button class="btn" onclick="saveMeshInterval()">Save</button>
              </div>
              
              <div style="display:flex;gap:8px;">
                <a class="btn alt" href="/mesh-test" data-ajax="true" style="flex:1;">Test</a>
                <a class="btn" href="/gps" data-ajax="false" style="flex:1;">GPS</a>
              </div>
            </div>
          </div>

          <hr>

          <div style="margin-top:12px;">
            <label>Vibration Sensor Alerts</label>
            <div style="display:flex;gap:8px;margin-bottom:4px;">
              <button class="btn" id="vibToggleBtn" onclick="toggleVibration()" style="flex:1;"></button>
            </div>
            <div style="font-size:10px;color:var(--mut);">Controls mesh broadcast alerts when vibration is detected</div>
          </div>
        </div>
      </div>

      <!-- Secure Data Destruction -->
      <div class="card">
        <div class="card-header" onclick="toggleCollapse('secureDataCard')">
          <h3>Secure Data Destruction</h3>
          <span class="collapse-icon" id="secureDataCardIcon">▶</span>
        </div>
        <div class="card-body collapsed" id="secureDataCardBody">
          <div class="banner">WARNING: Permanent data wipe</div>
          
          <form id="eraseForm" style="margin-top:12px;">
            <label>Confirmation Code</label>
            <input type="text" id="eraseConfirm" placeholder="WIPE_ALL_DATA">
            
            <div style="display:flex;gap:8px;margin-top:10px;">
              <button class="btn danger" type="button" onclick="requestErase()">WIPE</button>
              <button class="btn alt" type="button" onclick="cancelErase()">ABORT</button>
            </div>
          </form>
          
          <div id="eraseStatus" style="display:none;margin-top:10px;padding:8px;background:var(--surf);border:1px solid var(--bord);border-radius:6px;font-size:12px;"></div>
          
          <div style="margin-top:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
              <span style="font-weight:bold;color:var(--acc);">Auto-Erase Configuration</span>
              <span style="cursor:help;padding:2px 6px;background:var(--accbg);border:1px solid var(--acc);border-radius:4px;font-size:10px;" onclick="showAutoEraseHelp()" title="Click for help">?</span>
            </div>
            
            <label style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
              <input type="checkbox" id="autoEraseEnabled">
              <span>Enable auto-erase on tampering</span>
            </label>
            
            <div style="margin-bottom:16px;">
              <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Setup Period</label>
              <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">Grace period after enabling before tamper detection becomes active</label>
              <select id="setupDelay">
                <option value="30000">30 seconds</option>
                <option value="60000">1 minute</option>
                <option value="120000" selected>2 minutes</option>
                <option value="300000">5 minutes</option>
                <option value="600000">10 minutes</option>
              </select>
            </div>
            
            <div style="margin-bottom:16px;">
              <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Erase Countdown</label>
              <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">Time you have to cancel after tamper detection</label>
              <select id="autoEraseDelay">
                <option value="10000">10 seconds</option>
                <option value="30000" selected>30 seconds</option>
                <option value="60000">1 minute</option>
                <option value="120000">2 minutes</option>
                <option value="300000">5 minutes</option>
              </select>
            </div>
            
            <div style="margin-bottom:16px;">
              <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Trigger Cooldown</label>
              <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">Minimum time before another tamper event can trigger erase</label>
              <select id="autoEraseCooldown">
                <option value="60000">1 minute</option>
                <option value="300000" selected>5 minutes</option>
                <option value="600000">10 minutes</option>
                <option value="1800000">30 minutes</option>
                <option value="3600000">1 hour</option>
              </select>
            </div>
            
            <div style="padding:10px;background:rgba(0,0,0,0.2);border:1px solid var(--bord);border-radius:6px;margin-bottom:16px;">
              <div style="font-size:10px;font-weight:bold;color:var(--mut);margin-bottom:8px;">ADVANCED SETTINGS</div>
              
              <div style="margin-bottom:12px;">
                <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Vibrations Required</label>
                <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">Number of vibrations needed within detection window to trigger</label>
                <select id="vibrationsRequired">
                  <option value="2">2</option>
                  <option value="3" selected>3</option>
                  <option value="4">4</option>
                  <option value="5">5</option>
                </select>
              </div>
              
              <div style="margin-bottom:0;">
                <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Detection Window</label>
                <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">Time window for counting required vibrations</label>
                <select id="detectionWindow">
                  <option value="5000">5 seconds</option>
                  <option value="10000">10 seconds</option>
                  <option value="20000" selected>20 seconds</option>
                  <option value="30000">30 seconds</option>
                  <option value="60000">1 minute</option>
                </select>
              </div>
            </div>
            
            <button class="btn primary" type="button" onclick="saveAutoEraseConfig()" style="width:100%;">Save Configuration</button>
            <div id="autoEraseStatus" style="margin-top:8px;padding:6px;border-radius:4px;font-size:11px;text-align:center;">DISABLED</div>
          </div>

        </div>
      </div>

      <!-- Battery Saver Mode -->
      <div class="card">
        <div class="card-header" onclick="toggleCollapse('batterySaverCard')">
          <h3>Battery Saver Mode</h3>
          <span class="collapse-icon" id="batterySaverCardIcon">&#9654;</span>
        </div>
        <div class="card-body collapsed" id="batterySaverCardBody">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
            <span style="cursor:help;padding:2px 6px;background:var(--accbg);border:1px solid var(--acc);border-radius:4px;font-size:10px;" onclick="showBatterySaverHelp()" title="Click for help">?</span>
          </div>

          <p style="font-size:11px;color:var(--mut);margin-bottom:12px;">
            Reduces power consumption by stopping WiFi/BLE scanning, lowering CPU frequency, and sending only periodic heartbeats. WiFi AP and web UI remain active. Mesh UART remains active for receiving commands.
          </p>

          <div style="margin-bottom:16px;">
            <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Heartbeat Interval</label>
            <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">How often to send status heartbeats while in battery saver mode</label>
            <select id="batterySaverInterval">
              <option value="1">1 minute</option>
              <option value="2">2 minutes</option>
              <option value="5" selected>5 minutes</option>
              <option value="10">10 minutes</option>
              <option value="15">15 minutes</option>
              <option value="30">30 minutes</option>
            </select>
          </div>

          <div style="display:flex;gap:8px;">
            <button class="btn primary" type="button" onclick="enableBatterySaver()" style="flex:1;">Enable Battery Saver</button>
            <button class="btn alt" type="button" onclick="disableBatterySaver()" style="flex:1;">Disable</button>
          </div>
          <div id="batterySaverStatus" style="margin-top:8px;padding:6px;border-radius:4px;font-size:11px;text-align:center;background:rgba(0,0,0,0.2);">INACTIVE</div>
        </div>
      </div>

      <!--
      <div id="terminalToggle">TERMINAL</div>
      <div id="terminalWindow">
        <div id="terminalHeader">
          <span id="terminalTitle">SERIAL MONITOR</span>
          <span id="terminalClose">×</span>
        </div>
        <div id="terminalContent"></div>
      </div>
      -->
      </div>

      <div class="page-tab" id="page-data">
      <div class="card">
        <h3>Data Explorer</h3>
        <div class="data-header">
          <select id="dataSet" onchange="loadDataSet()">
            <option value="probedb">Probe Devices</option>
            <option value="probes">Probe Events</option>
            <option value="deauth">Deauth Attacks</option>
            <option value="drones">Drone Detections</option>
            <option value="vibrations">Vibration Events</option>
            <option value="baseline">Baseline Stats</option>
            <option value="syslog">System Log</option>
            <option value="incidents">Sentinel Incidents (all sessions)</option>
          </select>
          <input type="text" id="dataSearch" placeholder="Search..." oninput="onDataSearch()">
          <button class="btn alt" onclick="loadDataSet()" style="padding:8px 14px;font-size:12px;" title="Refresh">Refresh</button>
          <a class="btn alt" id="dataExport" download style="padding:8px 14px;font-size:12px;">Export</a>
          <button class="btn danger" id="dataClear" onclick="clearDataSet()" style="padding:8px 14px;font-size:12px;">Clear</button>
        </div>
        <div id="dataArea" style="overflow-x:auto;">
          <div class="data-empty">Select a dataset to view.</div>
        </div>
        <div class="data-pager" id="dataPager" style="display:none;">
          <button class="btn alt" onclick="dataPagePrev()" id="dataPrevBtn">Prev</button>
          <span id="dataPageInfo">--</span>
          <button class="btn alt" onclick="dataPageNext()" id="dataNextBtn">Next</button>
        </div>
      </div>
      <div class="card">
        <h3>Sentinel Analysis <span style="font-size:11px;color:var(--mut);">(all sessions)</span></h3>
        <div class="data-header">
          <select id="saType" onchange="loadSentinelAnalysis()"><option value="ALL">All types</option></select>
          <input type="text" id="saSearch" placeholder="Search..." oninput="loadSentinelAnalysis()">
          <button class="btn alt" onclick="refreshSentinelAnalysis()" style="padding:8px 14px;font-size:12px;">Refresh</button>
          <a class="btn alt" href="/api/incidents.jsonl" download style="padding:8px 14px;font-size:12px;">Export</a>
          <button class="btn danger" onclick="clearSentinelAnalysis()" style="padding:8px 14px;font-size:12px;">Clear</button>
        </div>
        <div id="saArea" style="overflow-x:auto;"><div class="data-empty">Open to load sentinel incidents.</div></div>
      </div>
      </div>

      <!-- ===== DETECT TAB ===== -->
      <div class="page-tab" id="page-detect">
        <style>
          #page-detect .sev{display:inline-block;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;margin-right:6px;vertical-align:middle}
          #page-detect .sev.crit{background:#7f1d1d;color:#fff}
          #page-detect .sev.high{background:#ea580c;color:#fff}
          #page-detect .sev.med{background:#ca8a04;color:#fff}
          #page-detect .sev.info{background:#334155;color:#cbd5e1}
          #page-detect .card.hidden{display:none}
          #page-detect details>summary{cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;list-style:none}
          #page-detect details>summary::-webkit-details-marker{display:none}
          #page-detect details>summary>span:first-child{display:inline-block;width:10px;transition:transform .15s}
          #page-detect details[open]>summary>span:first-child{transform:rotate(90deg)}
          #page-detect .det-row{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:12px;border-bottom:1px solid var(--bord)}
          #page-detect .det-row:last-child{border-bottom:0}
          #page-detect .det-row .name{flex:1;color:var(--txt)}
          #page-detect .det-row label{display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--mut);margin:0;cursor:pointer}
          #page-detect .det-row input[type=checkbox]{margin:0;cursor:pointer}
          #page-detect .num{font-family:monospace;color:var(--acc);font-weight:700}
          #page-detect .log-pre{max-height:240px;overflow:auto;font-size:11px;background:var(--surf2,rgba(0,0,0,.15));color:var(--txt);padding:8px;border:1px solid var(--bord);border-radius:4px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
          #page-detect input[type=number],#page-detect input[type=text]{padding:4px 8px;font-size:12px}
          #det-filter{flex:1;min-width:180px;max-width:400px}
          #det-banner{display:none;background:linear-gradient(90deg,rgba(127,29,29,.18),rgba(234,88,12,.10));border:1px solid #7f1d1d;border-radius:6px;padding:8px 10px;margin-bottom:10px}
          #det-banner.show{display:block}
          #det-banner .bn-row{display:flex;gap:8px;align-items:center;font-size:12px;padding:3px 0;cursor:pointer}
          #det-banner .bn-row:hover{background:rgba(255,255,255,0.04)}
          #det-banner .bn-when{color:var(--mut);font-size:10px;min-width:60px}
          #det-banner .bn-msg{flex:1;color:var(--txt)}
          .det-chips{display:flex;gap:6px;flex-wrap:wrap}
          .det-chip{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;user-select:none;text-transform:uppercase;letter-spacing:.3px}
          .det-chip.all{background:var(--surf);color:var(--mut);border-color:var(--bord)}
          .det-chip.crit{background:rgba(127,29,29,.25);color:#fca5a5;border-color:#7f1d1d}
          .det-chip.high{background:rgba(234,88,12,.22);color:#fdba74;border-color:#ea580c}
          .det-chip.med{background:rgba(202,138,4,.22);color:#fde68a;border-color:#ca8a04}
          .det-chip.info{background:rgba(51,65,85,.4);color:#cbd5e1;border-color:#334155}
          .det-chip.firing{box-shadow:0 0 0 2px rgba(255,255,255,.15) inset}
          .det-chip.off{opacity:.35}
          #page-detect table.dt{width:100%;border-collapse:collapse;font-size:11px;margin:4px 0}
          #page-detect table.dt th{text-align:left;padding:4px 6px;color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:.3px;border-bottom:1px solid var(--bord);cursor:pointer;user-select:none;white-space:nowrap}
          #page-detect table.dt th:hover{color:var(--acc)}
          #page-detect table.dt td{padding:4px 6px;border-bottom:1px solid var(--bord);font-family:monospace;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
          #page-detect table.dt tr:hover td{background:rgba(255,255,255,.03)}
          #page-detect table.dt .empty{color:var(--mut);font-style:italic;text-align:center;padding:10px}
          .det-quick{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}
          .det-quick button{padding:3px 9px;font-size:11px}
          #det-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:12px;align-items:start}
          #det-grid>.card{margin:0}
          #det-grid .log-pre{max-height:180px}
          @media (max-width:720px){#det-grid{grid-template-columns:1fr}}
        </style>

        <div style="margin-bottom:12px;padding:14px 16px;background:linear-gradient(135deg,rgba(127,29,29,.15),rgba(234,88,12,.08));border:1px solid var(--bord);border-radius:10px;">
          <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;">
            <h2 style="margin:0;font-size:20px;letter-spacing:-0.01em;color:var(--txt);">Sentinel</h2>
            <span style="font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.3px;font-weight:600;">Counterintel Engine</span>
          </div>
          <div style="font-size:11px;color:var(--mut);margin-top:6px;line-height:1.5;">
            Persistent RF surveillance with adversary tracking. Beyond signal detection: validates Remote ID claims via mesh geometry, scores hostile recon behavior, correlates BLE tracker rotation chains, audits handshake captures, fingerprints attacker tools, cross-verifies threats across mesh nodes.
          </div>
        </div>

        <div id="det-banner"><div style="font-size:10px;color:#fca5a5;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">ACTIVE ALERTS</div><div id="det-banner-body"></div></div>

        <div id="det-tabs" style="display:flex;gap:2px;margin-bottom:12px;border-bottom:1px solid var(--bord);">
          <button data-dtab="live" class="dtab active" onclick="detSetTab('live')">Live</button>
          <button data-dtab="detectors" class="dtab" onclick="detSetTab('detectors')">Detectors</button>
          <button data-dtab="details" class="dtab" onclick="detSetTab('details')">Details</button>
        </div>
        <style>
          #det-tabs button.dtab{background:transparent;color:var(--mut);border:none;border-bottom:2px solid transparent;padding:8px 14px;font-size:13px;cursor:pointer;font-weight:500;}
          #det-tabs button.dtab:hover{color:var(--txt);background:rgba(255,255,255,.03);}
          #det-tabs button.dtab.active{color:var(--txt);border-bottom-color:#ea580c;}
          .dtab-hidden{display:none !important;}
          .det-empty-hidden{display:none !important;}
          .dpill{display:inline-block;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;letter-spacing:.4px;text-transform:uppercase;margin-left:6px;vertical-align:middle;}
          .dpill.verify{background:rgba(34,197,94,.18);color:#86efac;border:1px solid #16a34a;}
          .dpill.unver{background:rgba(234,179,8,.15);color:#fde047;border:1px solid #ca8a04;}
          .dpill.off{background:rgba(156,163,175,.12);color:#9ca3af;border:1px solid #4b5563;}
          .dpill.fire{background:rgba(239,68,68,.2);color:#fca5a5;border:1px solid #dc2626;animation:dpulse 1.2s ease-in-out infinite;}
          @keyframes dpulse{0%,100%{opacity:1}50%{opacity:.45}}
        </style>

        <div style="margin-bottom:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;" data-dtab-target="detectors">
          <input id="det-filter" placeholder="Filter (e.g. csi, airtag, karma)" oninput="detApplyFilters()">
          <div class="det-chips" id="det-chips">
            <span class="det-chip all" data-sev="all">All</span>
            <span class="det-chip crit" data-sev="crit">Crit</span>
            <span class="det-chip high" data-sev="high">High</span>
            <span class="det-chip med" data-sev="med">Med</span>
            <span class="det-chip info" data-sev="info">Info</span>
            <span class="det-chip" data-sev="firing" style="background:rgba(34,197,94,.2);color:#86efac;border:1px solid #16a34a;">Firing</span>
          </div>
        </div>

        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detOverviewCard')">
            <h3><span class="sev info">overview</span>Detection Overview</h3>
            <span class="collapse-icon open" id="detOverviewCardIcon">▶</span>
          </div>
          <div class="card-body" id="detOverviewCardBody">
            <div class="stat-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:10px;">
              <div class="stat" data-cfg="always"><div class="stat-label">Deauth</div><div class="stat-value" id="d-dauth">0</div></div>
              <div class="stat" data-cfg="pmkid"><div class="stat-label">PMKID</div><div class="stat-value" id="d-pmkid">0</div></div>
              <div class="stat" data-cfg="eviltwin"><div class="stat-label">Evil-Twin</div><div class="stat-value" id="d-et">0</div></div>
              <div class="stat" data-cfg="ssid_confusion"><div class="stat-label">SSID Conf</div><div class="stat-value" id="d-sc">0</div></div>
              <div class="stat" data-cfg="sae"><div class="stat-label">SAE DoS</div><div class="stat-value" id="d-sae">0</div></div>
              <div class="stat" data-cfg="owe"><div class="stat-label">OWE Abuse</div><div class="stat-value" id="d-owe">0</div></div>
              <div class="stat" data-cfg="frag"><div class="stat-label">FragAttacks</div><div class="stat-value" id="d-frag">0</div></div>
              <div class="stat" data-cfg="ble_malformed"><div class="stat-label">BLE Malformed</div><div class="stat-value" id="d-blem">0</div></div>
              <div class="stat" data-cfg="tracker,airtag"><div class="stat-label">BLE Trackers</div><div class="stat-value" id="d-trk">0</div></div>
              <div class="stat" data-cfg="pmkid,probe_flood,hshk"><div class="stat-label">Recon</div><div class="stat-value" id="d-rec">0</div></div>
              <div class="stat" data-cfg="attacker_trilat"><div class="stat-label">Hunts</div><div class="stat-value" id="d-ah-n">0</div></div>
              <div class="stat" data-cfg="always"><div class="stat-label">KRACK</div><div class="stat-value" id="d-hs-krack">0</div></div>
              <div class="stat" data-cfg="karma"><div class="stat-label">Karma</div><div class="stat-value" id="d-karma">0</div></div>
              <div class="stat" data-cfg="always"><div class="stat-label">Auth Flood</div><div class="stat-value" id="d-authflood">0</div></div>
              <div class="stat" data-cfg="eviltwin"><div class="stat-label">Beacon Flood</div><div class="stat-value" id="d-beaconflood">0</div></div>
            </div>
            <div style="font-size:11px;color:var(--mut);margin-bottom:8px;">
              <span class="lbl">Heap:</span><span id="d-heap" class="num">--</span>
              <span class="lbl" style="margin-left:10px;">Drops:</span><span id="d-drops" class="num">--</span>
              <span class="lbl" style="margin-left:10px;">Mesh-gated:</span><span id="d-mgated" class="num">--</span>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <button class="btn alt" onclick="detectClearAll()">Clear All State</button>
              <button class="btn alt" onclick="detectReloadOui()">Reload OUI</button>
            </div>
          </div>
        </div>

        <div class="card" data-key="apclients">
          <div class="card-header" onclick="toggleCollapse('apClientsCard')">
            <h3><span class="sev" style="background:#14532d;color:#bbf7d0;">clients</span>AP Clients <span style="font-size:11px;color:var(--mut);">(associated with this AP — not threats)</span></h3>
            <span class="collapse-icon open" id="apClientsCardIcon">▶</span>
          </div>
          <div class="card-body" id="apClientsCardBody">
            <div id="apClientsArea" style="overflow-x:auto;"><div style="color:var(--mut);font-size:12px;">No clients yet.</div></div>
          </div>
        </div>

        <div class="card" data-key="dctl">
          <div class="card-header" onclick="toggleCollapse('detCtlCard')">
            <h3><span class="sev info">control</span>Sentinel Control</h3>
            <span class="collapse-icon open" id="detCtlCardIcon">▶</span>
          </div>
          <div class="card-body" id="detCtlCardBody">
            <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap;">
              <span style="font-size:12px;">Sentinel:</span>
              <span id="sentStatus2" style="font-weight:600;color:#888;font-size:13px;">--</span>
              <button id="sentToggleBtn" class="btn primary" onclick="sentinelToggleHdr()">Start</button>
              <span style="font-size:11px;color:var(--mut);margin-left:8px;">Radio:</span>
              <div style="display:flex;gap:0;border:1px solid var(--bd);border-radius:6px;overflow:hidden;">
                <button id="dos-mode-defend" class="btn" style="border-radius:0;margin:0;" onclick="detScanMode(false)">Defend this AP</button>
                <button id="dos-mode-scan" class="btn alt" style="border-radius:0;margin:0;" onclick="detScanMode(true)">Scan all channels</button>
              </div>
            </div>
            <div id="dos-mode-desc" style="font-size:11px;color:var(--mut);margin:-4px 0 10px;"></div>
            <div id="dctl-quick" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:6px;margin-bottom:10px;"></div>
            <p style="font-size:11px;color:var(--mut);margin:2px 0 4px;">Toggle a group:</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:6px;margin-bottom:8px;">
              <button id="grpchip-dos" class="btn alt" onclick="detGroupToggle('dos')">DoS</button>
              <button id="grpchip-rogue_ap" class="btn alt" onclick="detGroupToggle('rogue_ap')">Rogue AP</button>
              <button id="grpchip-recon" class="btn alt" onclick="detGroupToggle('recon')">Recon</button>
              <button id="grpchip-physical" class="btn alt" onclick="detGroupToggle('physical')">Physical</button>
            </div>
            <div class="det-quick">
              <button class="btn alt" onclick="detPreset('all-on')">All On</button>
              <button class="btn alt" onclick="detPreset('all-off')">All Off</button>
              <button class="btn alt" onclick="detPreset('quiet')">Quiet</button>
            </div>
          </div>
        </div>

        <div class="card" data-key="dos">
          <div class="card-header" onclick="toggleCollapse('detDosCard')">
            <h3><span class="sev high">dos</span>DoS Defense</h3>
            <span class="collapse-icon open" id="detDosCardIcon">▶</span>
          </div>
          <div class="card-body" id="detDosCardBody">
            <div style="display:flex;gap:6px;margin-bottom:8px;">
              <button class="btn alt" onclick="detGroup('dos',true)">All On</button>
              <button class="btn alt" onclick="detGroup('dos',false)">All Off</button>
            </div>
            <div id="dos-rows" style="font-size:12px;"></div>
          </div>
        </div>

        <div class="card" data-key="rogue">
          <div class="card-header" onclick="toggleCollapse('detRogueCard')">
            <h3><span class="sev high">rogue</span>Rogue AP</h3>
            <span class="collapse-icon open" id="detRogueCardIcon">▶</span>
          </div>
          <div class="card-body" id="detRogueCardBody">
            <div style="display:flex;gap:6px;margin-bottom:8px;">
              <button class="btn alt" onclick="detGroup('rogue_ap',true)">All On</button>
              <button class="btn alt" onclick="detGroup('rogue_ap',false)">All Off</button>
            </div>
            <div id="rogue-rows"></div>
          </div>
        </div>

        <div class="card" data-key="recongrp">
          <div class="card-header" onclick="toggleCollapse('detReconGrpCard')">
            <h3><span class="sev high">recon</span>Recon / Harvest</h3>
            <span class="collapse-icon open" id="detReconGrpCardIcon">▶</span>
          </div>
          <div class="card-body" id="detReconGrpCardBody">
            <div style="display:flex;gap:6px;margin-bottom:8px;">
              <button class="btn alt" onclick="detGroup('recon',true)">All On</button>
              <button class="btn alt" onclick="detGroup('recon',false)">All Off</button>
            </div>
            <div id="recon-rows"></div>
          </div>
        </div>

        <div class="card" data-key="physical">
          <div class="card-header" onclick="toggleCollapse('detPhysCard')">
            <h3><span class="sev info">phys</span>Physical Layer</h3>
            <span class="collapse-icon open" id="detPhysCardIcon">▶</span>
          </div>
          <div class="card-body" id="detPhysCardBody">
            <div style="display:flex;gap:6px;margin-bottom:8px;">
              <button class="btn alt" onclick="detGroup('physical',true)">All On</button>
              <button class="btn alt" onclick="detGroup('physical',false)">All Off</button>
            </div>
            <div id="physical-rows"></div>
          </div>
        </div>

        <div class="card" data-key="meshcfg">
          <div class="card-header" onclick="toggleCollapse('detConfigCard')">
            <h3><span class="sev info">config</span>Mesh &amp; Thresholds</h3>
            <span class="collapse-icon" id="detConfigCardIcon">▶</span>
          </div>
          <div class="card-body" id="detConfigCardBody">
            <p style="font-size:11px;color:var(--mut);margin:0 0 6px;">Detector on/off lives in the group cards (Detectors tab). Here: mesh broadcast + thresholds.</p>
            <div class="det-quick" style="margin-bottom:6px;">
              <button class="btn alt" onclick="detPreset('mesh-all')">Mesh All On</button>
              <button class="btn alt" onclick="detPreset('mesh-silent')">Mesh Silent</button>
            </div>
            <details open>
              <summary><span>▶</span> Mesh Broadcast (forward detections to peers)</summary>
              <div id="cfg-mesh"></div>
            </details>
            <details>
              <summary><span>▶</span> Thresholds &amp; Timing</summary>
              <div id="cfg-thresh" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px;"></div>
              <button class="btn primary" onclick="detSaveThresh()" style="margin-top:8px;">Save Thresholds</button>
            </details>
          </div>
        </div>

        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detMeshCard')">
            <h3><span class="sev info">mesh</span>Mesh Defense</h3>
            <span class="collapse-icon open" id="detMeshCardIcon">▶</span>
          </div>
          <div class="card-body" id="detMeshCardBody">
            <div style="font-size:12px;line-height:1.7;">
              <div><span class="lbl">PPS Lock:</span><span id="d-pps" class="num">--</span></div>
              <div><span class="lbl">Bloom Local:</span><span id="d-bl" class="num">--</span></div>
              <div><span class="lbl">Bloom Neighbor:</span><span id="d-bn" class="num">--</span></div>
              <div><span class="lbl">Quorum Candidates:</span><span id="d-qc" class="num">0</span></div>
            </div>
            <details style="margin-top:10px;">
              <summary><span>▶</span> Quorum Status</summary>
              <pre id="d-quorum" class="log-pre">--</pre>
            </details>
            <details style="margin-top:6px;">
              <summary><span>▶</span> Channel Partition</summary>
              <button class="btn alt" onclick="detectAssignChannels()" style="margin-bottom:6px;">Reassign</button>
              <pre id="d-chan" class="log-pre">--</pre>
            </details>
          </div>
        </div>

        <div id="det-grid">
        <div class="card" data-key="rid" data-sev="high">
          <div class="card-header" onclick="toggleCollapse('detRidCard')">
            <h3><span class="sev high">high</span>Remote ID Spoof Validator</h3>
            <span class="collapse-icon" id="detRidCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detRidCardBody"><pre id="d-rid" class="log-pre">--</pre></div>
        </div>

        <div class="card" data-key="recon" data-sev="high">
          <div class="card-header" onclick="toggleCollapse('detReconCard')">
            <h3><span class="sev high">high</span>Hostile Recon Scoring</h3>
            <span class="collapse-icon" id="detReconCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detReconCardBody">
            <button class="btn alt" onclick="detectClearRecon()" style="margin-bottom:6px;">Clear</button>
            <pre id="d-recpre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="trackers" data-sev="med">
          <div class="card-header" onclick="toggleCollapse('detTrackerCard')">
            <h3><span class="sev med">med</span>BLE Trackers</h3>
            <span class="collapse-icon" id="detTrackerCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detTrackerCardBody">
            <button class="btn alt" onclick="detectClearTrackers()" style="margin-bottom:6px;">Clear Watchlist</button>
            <details open><summary><span>▶</span> Watchlist (latest)</summary><pre id="d-trkpre" class="log-pre">--</pre></details>
            <details><summary><span>▶</span> Rotation Chains <span class="num" id="trk-n">0</span></summary>
              <button class="btn alt" onclick="trkClear()" style="margin:6px 0;">Clear Chains</button>
              <pre id="trk-pre" class="log-pre">--</pre>
            </details>
          </div>
        </div>

        <div class="card" data-key="airtag" data-sev="med">
          <div class="card-header" onclick="toggleCollapse('detAirtagCard')">
            <h3><span class="sev med">med</span>AirTag Owner-Presence <span class="num" id="at-n">0</span></h3>
            <span class="collapse-icon" id="detAirtagCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detAirtagCardBody">
            <button class="btn alt" onclick="atClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="at-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="csi" data-sev="med">
          <div class="card-header" onclick="toggleCollapse('detCsiCard')">
            <h3><span class="sev med">med</span>CSI Presence &amp; Motion</h3>
            <span class="collapse-icon" id="detCsiCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detCsiCardBody">
            <div class="stat-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:10px;">
              <div class="stat"><div class="stat-label">Enabled</div><div class="stat-value" id="csi-on">--</div></div>
              <div class="stat"><div class="stat-label">Packets</div><div class="stat-value" id="csi-pk">0</div></div>
              <div class="stat"><div class="stat-label">Motion</div><div class="stat-value" id="csi-mv">0</div></div>
              <div class="stat"><div class="stat-label">Thresh Q8</div><div class="stat-value" id="csi-th">--</div></div>
              <div class="stat"><div class="stat-label">FPs</div><div class="stat-value" id="csi-fp">0</div></div>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;">
              <input id="csi-thresh-in" type="number" min="100" max="10000" placeholder="Threshold" style="width:130px;">
              <button class="btn alt" onclick="csiSetThresh()">Set</button>
              <button class="btn alt" onclick="csiClear()">Clear</button>
            </div>
            <details><summary><span>▶</span> Motion Events</summary><pre id="csi-motion" class="log-pre">--</pre></details>
            <details><summary><span>▶</span> RF Fingerprints</summary><pre id="csi-fp-pre" class="log-pre">--</pre></details>
          </div>
        </div>

        <div class="card" data-key="karma" data-sev="crit">
          <div class="card-header" onclick="toggleCollapse('detKarmaCard')">
            <h3><span class="sev crit">crit</span>KARMA Probe-Bait</h3>
            <span class="collapse-icon" id="detKarmaCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detKarmaCardBody">
            <div style="font-size:12px;line-height:1.7;">
              <span class="lbl">Bait:</span><span id="km-on" class="num">--</span>
              <span class="lbl" style="margin-left:10px;">Candidates:</span><span id="km-c" class="num">0</span>
              <span class="lbl" style="margin-left:10px;">Confirmed:</span><span id="km-x" class="num">0</span>
            </div>
            <button class="btn alt" onclick="kmClear()" style="margin:6px 0;">Clear</button>
            <pre id="km-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="hunts" data-sev="crit">
          <div class="card-header" onclick="toggleCollapse('detHuntCard')">
            <h3><span class="sev crit">crit</span>Attacker Reverse-Trilat <span class="num" id="ah-n">0</span></h3>
            <span class="collapse-icon" id="detHuntCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detHuntCardBody">
            <button class="btn alt" onclick="ahClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="ah-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="handshake" data-sev="crit">
          <div class="card-header" onclick="toggleCollapse('detHshkCard')">
            <h3><span class="sev crit">crit</span>Handshakes + KRACK <span class="num" id="hs-n">0</span></h3>
            <span class="collapse-icon" id="detHshkCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detHshkCardBody">
            <button class="btn alt" onclick="hsClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="hs-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="bcnforge" data-sev="high" title="Beacon spam fingerprints: static TSF 83 51 F7 8F, BI=1000 TU + LAA src, multicast src MAC, CSA count=0xFF, Espressif Evil-Portal, SSID rotate >=3 distinct/30s same BSSID">
          <div class="card-header" onclick="toggleCollapse('detBcnForgeCard')">
            <h3><span class="sev high">high</span>Beacon Forgery <span class="num" id="bf-n">0</span></h3>
            <span class="collapse-icon" id="detBcnForgeCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detBcnForgeCardBody">
            <button class="btn alt" onclick="bfClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="bf-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="pmkidforge" data-sev="crit" title="tool forged PMKID: KDE DD 14 00 0F AC 04 + fixed bytes 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 11">
          <div class="card-header" onclick="toggleCollapse('detPmkidForgeCard')">
            <h3><span class="sev crit">crit</span>PMKID Forgery <span class="num" id="pf-n">0</span></h3>
            <span class="collapse-icon" id="detPmkidForgeCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detPmkidForgeCardBody">
            <button class="btn alt" onclick="pfClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="pf-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="eapolbait" data-sev="crit" title="EAPOL capture-bait: single targeted deauth (<=3 frames) followed by EAPOL handshake from same STA. high confidence if latency <=2s">
          <div class="card-header" onclick="toggleCollapse('detEapolBaitCard')">
            <h3><span class="sev crit">crit</span>EAPOL Capture-Bait <span class="num" id="eb-n">0</span></h3>
            <span class="collapse-icon" id="detEapolBaitCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detEapolBaitCardBody">
            <button class="btn alt" onclick="ebClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="eb-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="probeflood" data-sev="high" title="tool probe attack: seqCtrl=0x0001 + HT-Cap IE 0x2D in probe-req. Behavioral fallback: >=40 distinct src MACs probing same SSID within 5s window">
          <div class="card-header" onclick="toggleCollapse('detProbeFloodCard')">
            <h3><span class="sev high">high</span>Probe Flood <span class="num" id="pfl-n">0</span></h3>
            <span class="collapse-icon" id="detProbeFloodCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detProbeFloodCardBody">
            <button class="btn alt" onclick="pflClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="pfl-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="assocsleep" data-sev="high" title="tool assoc-sleep: assoc-request frames with PM bit set in FC byte 1. Fires if >=4 distinct src MACs send to same BSSID within 5s">
          <div class="card-header" onclick="toggleCollapse('detAssocSleepCard')">
            <h3><span class="sev high">high</span>Assoc-Sleep <span class="num" id="as-n">0</span></h3>
            <span class="collapse-icon" id="detAssocSleepCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detAssocSleepCardBody">
            <button class="btn alt" onclick="asClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="as-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="bleattack" data-sev="high" title="tool/tool BLE attack tool fingerprints: SourApple FF 4C 00 0F 05 C0/C1, AppleJuice 4C 00 04 04 2A, Samsung FF 75 00 01 00 02, SwiftPair FF 06 00 03 00 80, FastPair 16 2C FE 00 B7 27, Flipper 0x0FBA, AirTag replay (same payload from >=2 MACs)">
          <div class="card-header" onclick="toggleCollapse('detBleAttackCard')">
            <h3><span class="sev high">high</span>BLE Attack Tools <span class="num" id="ba-n">0</span></h3>
            <span class="collapse-icon" id="detBleAttackCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detBleAttackCardBody">
            <button class="btn alt" onclick="baClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="ba-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="probegraph" data-sev="info">
          <div class="card-header" onclick="toggleCollapse('detPgCard')">
            <h3><span class="sev info">info</span>Probe-Graph (mesh) <span class="num" id="pg-n">0</span></h3>
            <span class="collapse-icon" id="detPgCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detPgCardBody">
            <button class="btn alt" onclick="pgClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="pg-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="tsf" data-sev="info">
          <div class="card-header" onclick="toggleCollapse('detTsfCard')">
            <h3><span class="sev info">info</span>TSF Clock-Skew <span class="num" id="tsf-n">0</span></h3>
            <span class="collapse-icon" id="detTsfCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detTsfCardBody">
            <button class="btn alt" onclick="tsfClear()" style="margin-bottom:6px;">Clear</button>
            <pre id="tsf-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="tof" data-sev="info">
          <div class="card-header" onclick="toggleCollapse('detTofCard')">
            <h3><span class="sev info">info</span>Mesh Link RTT <span class="num" id="tof-n">0</span></h3>
            <span class="collapse-icon" id="detTofCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detTofCardBody">
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px;">
              <input id="tof-target-in" type="text" placeholder="nodeId or *" style="width:140px;">
              <button class="btn" onclick="tofPing()">Ping</button>
              <button class="btn alt" onclick="tofClear()">Clear</button>
            </div>
            <pre id="tof-pre" class="log-pre">--</pre>
          </div>
        </div>

        <div class="card" data-key="events" data-sev="high">
          <div class="card-header" onclick="toggleCollapse('detEventsCard')">
            <h3><span class="sev high">high</span>Incidents (Session)</h3>
            <span class="collapse-icon" id="detEventsCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detEventsCardBody">
            <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center;">
              <label style="font-size:12px;opacity:0.7;">Filter:</label>
              <select id="incFilter" style="background:#0a0a0a;color:#e8e8e8;border:1px solid #3a3a4a;padding:4px 8px;">
                <option value="">ALL</option>
                <option>DEAUTH_FORGE</option>
                <option>DEAUTH_FLOOD</option>
                <option>EVILTWIN</option>
                <option>KARMA_CAND</option>
                <option>KARMA_CONFIRMED</option>
                <option>BEACON_FORGE</option>
                <option>PMKID_HARVEST</option>
                <option>PMKID_FORGE</option>
                <option>EAPOL_BAIT</option>
                <option>PROBE_FLOOD</option>
                <option>ASSOC_SLEEP</option>
                <option>BLE_ATTACK</option>
                <option>BLETRACK</option>
                <option>SAE_DOS</option>
                <option>OWE_ABUSE</option>
                <option>SSID_CONFUSION</option>
                <option>FRAG</option>
                <option>KRACK</option>
                <option>PWNAGOTCHI</option>
                <option>ATTACKER_HUNT</option>
                <option>RECON</option>
              </select>
              <label style="font-size:12px;opacity:0.7;">Source:</label>
              <select id="incSrc" style="background:#0a0a0a;color:#e8e8e8;border:1px solid #3a3a4a;padding:4px 8px;">
                <option value="">ALL</option>
                <option value="local">Local only</option>
                <option value="peer">Peers only</option>
              </select>
              <button onclick="loadIncidents()" style="background:#1a2a3a;color:#9bf;border:1px solid #3a4a5a;padding:4px 10px;cursor:pointer;">Refresh</button>
              <button onclick="downloadIncidents()" style="background:#1a2a3a;color:#9bf;border:1px solid #3a4a5a;padding:4px 10px;cursor:pointer;">Download .jsonl</button>
              <button onclick="clearIncidents()" style="background:#3a1a1a;color:#f99;border:1px solid #5a3a3a;padding:4px 10px;cursor:pointer;">Clear All</button>
              <span id="incCount" style="font-size:12px;opacity:0.6;margin-left:auto;">--</span>
            </div>
            <div style="max-height:380px;overflow-y:auto;border:1px solid #2a2a3a;">
              <table id="incTable" style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace;">
                <thead style="position:sticky;top:0;background:#0a0a14;">
                  <tr>
                    <th style="text-align:left;padding:6px;border-bottom:1px solid #3a3a4a;width:80px;">Uptime</th>
                    <th style="text-align:left;padding:6px;border-bottom:1px solid #3a3a4a;width:50px;">Node</th>
                    <th style="text-align:left;padding:6px;border-bottom:1px solid #3a3a4a;width:50px;">Src</th>
                    <th style="text-align:left;padding:6px;border-bottom:1px solid #3a3a4a;width:170px;">Type</th>
                    <th style="text-align:left;padding:6px;border-bottom:1px solid #3a3a4a;">Raw</th>
                  </tr>
                </thead>
                <tbody id="incBody"><tr><td colspan="5" style="padding:12px;opacity:0.5;">Loading…</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
        </div><!-- /det-grid -->
      </div>
      <!-- ===== /DETECT TAB ===== -->

      <div align="center" class="footer">v0.9.5 | Node: <span id="footerNodeId">--</span></div>
    
      <script>
      let tickRunning = false;
      let selectedMode = '0';
      let baselineUpdateInterval = null;
      let lastScanningState = false;
      let lastResultsText = '';
      let meshEnabled = true;
      let vibrationEnabled = true;
      let hbEnabled = false;
      let privacyMode = localStorage.getItem('privacyMode') === '1';
      let lastScanStartTime = 0;
      let radioBusy = false;
      let radioBusyTask = '';
      let prevUniqueDevices = 0;


      function isRadioBusy() {
        if (radioBusy) {
          toast('Radio busy — ' + (radioBusyTask || 'scan') + ' in progress. Stop it first.', 'warning');
          return true;
        }
        return false;
      }

      function switchPage(pageName) {
        if (document.activeElement) document.activeElement.blur();
        document.querySelectorAll('.page-tab-btn').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.page-tab').forEach(function(p) { p.classList.remove('active'); });
        var btn = document.querySelector('.page-tab-btn[onclick*="' + pageName + '"]');
        if (btn) btn.classList.add('active');
        var pg = document.getElementById('page-' + pageName);
        if (pg) pg.classList.add('active');
        window.scrollTo(0, 0);
        if (pageName === 'data' && typeof loadDataSet === 'function') loadDataSet();
        if (pageName === 'data' && typeof loadSentinelAnalysis === 'function') { _saData=null; loadSentinelAnalysis(); }
      }

      function switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        event.target.classList.add('active');
        document.getElementById(tabName).classList.add('active');
      }

      async function ajaxForm(form, okMsg) {
        const fd = new FormData(form);
        try {
          const r = await fetch(form.action, {
            method: 'POST',
            body: fd
          });
          const t = await r.text();
          toast(okMsg || t);
        } catch (e) {
          toast('Error: ' + e.message);
        }
      }

      async function load() {
        try {
          const [exportResp, resultsResp] = await Promise.all([
            fetch('/export'),
            fetch('/results')
          ]);
          
          const text = await exportResp.text();
          document.getElementById('list').value = text;
          const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          document.getElementById('targetCount').innerText = lines.length + ' targets';
          
          const resultsText = await resultsResp.text();
          document.getElementById('r').innerHTML = parseAndStyleResults(resultsText);
          
          loadNodeId();
          loadRFConfig();
          loadWiFiConfig();
          loadMeshInterval();
        } catch (e) {}
      }

      async function loadNodeId() {
        try {
          const r = await fetch('/node-id');
          const data = await r.json();
          document.getElementById('nodeId').value = data.nodeId;
          document.getElementById('footerNodeId').innerText = data.nodeId;
        } catch (e) {}
      }
      
      function toggleCollapse(cardId) {
        const body = document.getElementById(cardId + 'Body');
        const icon = document.getElementById(cardId + 'Icon');
        
        if (!body) return;
        
        if (body.classList.contains('collapsed')) {
          body.classList.remove('collapsed');
          body.style.maxHeight = body.scrollHeight + 'px';
          if (icon) icon.classList.add('open');
        } else {
          body.style.maxHeight = body.scrollHeight + 'px';
          setTimeout(() => {
            body.classList.add('collapsed');
            body.style.maxHeight = '0';
          }, 10);
          if (icon) icon.classList.remove('open');
        }
      }

      async function loadRFConfig() {
          try {
            const r = await fetch('/rf-config');
            const cfg = await r.json();
            document.getElementById('globalRssiSlider').value = cfg.globalRssiThreshold || -95;
            document.getElementById('globalRssiValue').innerText = (cfg.globalRssiThreshold || -95) + ' dBm';
            document.getElementById('rfPreset').value = cfg.preset;
            document.getElementById('wifiChannelTime').value = cfg.wifiChannelTime;
            document.getElementById('wifiScanInterval').value = cfg.wifiScanInterval;
            document.getElementById('bleScanInterval').value = cfg.bleScanInterval;
            document.getElementById('bleScanDuration').value = cfg.bleScanDuration;
            document.getElementById('wifiChannels').value = cfg.wifiChannels || '1..14';
            
            // If custom not preset
            const customDiv = document.getElementById('customRFSettings');
            if (customDiv) {
              customDiv.style.display = cfg.preset === 3 ? 'block' : 'none';
            }
          } catch(e) {}
      }

      async function updateRFPresetUI() {
        const preset = parseInt(document.getElementById('rfPreset').value);
        const customDiv = document.getElementById('customRFSettings');
        
        if (!customDiv) return;
        
        customDiv.style.display = preset === 3 ? 'block' : 'none';
        
        if (preset <= 2) {
          const fd = new FormData();
          fd.append('preset', preset);
          
          try {
            await fetch('/rf-config', {method: 'POST', body: fd});
            await loadRFConfig();
          } catch(e) {
            console.error('Failed to apply preset:', e);
          }
        }
      }

      async function loadMeshInterval() {
        try {
          const r = await fetch('/mesh-interval');
          const data = await r.json();
          document.getElementById('meshInterval').value = data.interval;
        } catch(e) {
          console.error('[CONFIG] Failed to load mesh interval:', e);
        }
      }

      async function saveMeshInterval() {
        const interval = document.getElementById('meshInterval').value;
        if (interval < 1500 || interval > 30000) {
          toast('Invalid interval: must be 1500-30000ms', 'error');
          return;
        }
        
        try {
          const r = await fetch('/mesh-interval', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'interval=' + interval
          });
          const data = await r.text();
          toast(data, 'success');
        } catch(e) {
          toast('Failed to save mesh interval', 'error');
        }
      }

      function togglePrivacy() {
        privacyMode = !privacyMode;
        localStorage.setItem('privacyMode', privacyMode ? '1' : '0');
        updatePrivacyBtn();
        const resultsElement = document.getElementById('r');
        if (privacyMode) {
          if (resultsElement && lastResultsText) {
            resultsElement.innerHTML = parseAndStyleResults(lastResultsText);
          }
          applyPrivacyToElement(document.body);
          document.querySelectorAll('textarea').forEach(ta => {
            ta.value = ta.value.replace(/\b([A-F0-9]{2}:){5}[A-F0-9]{2}\b/gi, 'XX:XX:XX:XX:XX:XX');
            ta.value = ta.value.replace(/(?:probes:|AP=|SSID:\s*)~?"([^"]+)"/g, (m, s) => m.replace(s, ssidHash(s)));
          });
        } else {
          if (resultsElement && lastResultsText) {
            resultsElement.innerHTML = parseAndStyleResults(lastResultsText);
          }
          load();
        }
      }

      function updatePrivacyBtn() {
        const btn = document.getElementById('privacyBtn');
        if (!btn) return;
        if (privacyMode) {
          btn.textContent = 'Privacy: ON';
          btn.style.background = 'var(--succ)';
          btn.style.borderColor = 'var(--succ)';
          btn.style.color = '#fff';
        } else {
          btn.textContent = 'Privacy: OFF';
          btn.style.background = 'var(--dang)';
          btn.style.borderColor = 'var(--dang)';
          btn.style.color = '#fff';
        }
      }

      async function toggleMesh() {
        meshEnabled = !meshEnabled;
        updateMeshUI();
        try {
          const r = await fetch('/mesh', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + meshEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update mesh status', 'error');
          meshEnabled = !meshEnabled;
          updateMeshUI();
        }
      }
      
      function updateMeshUI() {
        const btn = document.getElementById('meshToggleBtn');
        const controls = document.getElementById('meshControls');
        
        if (!btn) return;
        
        if (meshEnabled) {
          btn.textContent = 'Mesh: Enabled';
          btn.classList.add('primary');
          btn.style.background = 'var(--succ)';
          btn.style.borderColor = 'var(--succ)';
          btn.style.color = '#fff';
          if (controls) controls.style.display = 'block';
        } else {
          btn.textContent = 'Mesh: Disabled';
          btn.classList.remove('primary');
          btn.style.background = 'var(--dang)';
          btn.style.borderColor = 'var(--dang)';
          btn.style.color = '#fff';
          if (controls) controls.style.display = 'none';
        }
      }
      
      async function toggleVibration() {
        vibrationEnabled = !vibrationEnabled;
        updateVibrationUI();
        try {
          const r = await fetch('/vibration', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + vibrationEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update vibration status', 'error');
          vibrationEnabled = !vibrationEnabled;
          updateVibrationUI();
        }
      }

      function updateVibrationUI() {
        const btn = document.getElementById('vibToggleBtn');
        if (!btn) return;
        if (vibrationEnabled) {
          btn.textContent = 'Alerts: Enabled';
          btn.style.background = 'var(--succ)';
          btn.style.borderColor = 'var(--succ)';
          btn.style.color = '#fff';
        } else {
          btn.textContent = 'Alerts: Disabled';
          btn.style.background = 'var(--dang)';
          btn.style.borderColor = 'var(--dang)';
          btn.style.color = '#fff';
        }
      }

      function updateHbUI() {
        const cb = document.getElementById('hbEnabledCb');
        if (cb) cb.checked = hbEnabled;
      }

      async function toggleHb() {
        hbEnabled = document.getElementById('hbEnabledCb').checked;
        try {
          const r = await fetch('/mesh-hb', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + hbEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update heartbeat', 'error');
          hbEnabled = !hbEnabled;
          updateHbUI();
        }
      }

      async function saveHbInterval() {
        const minutes = parseInt(document.getElementById('hbIntervalInput').value);
        if (isNaN(minutes) || minutes < 1 || minutes > 60) { toast('Interval must be 1–60 min', 'error'); return; }
        try {
          const r = await fetch('/mesh-hb-interval', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'interval=' + minutes
          });
          toast(await r.text(), 'success');
        } catch(e) { toast('Failed to set interval', 'error'); }
      }

      function loadMeshStatus() {
        updateMeshUI();
      }

      async function saveRFConfig() {
        const preset = parseInt(document.getElementById('rfPreset').value);
        const threshold = parseInt(document.getElementById('globalRssiSlider').value);
        const fd = new FormData();
        
        fd.append('globalRssiThreshold', threshold);
        
        if (preset === 3) {
          fd.append('wifiChannelTime', document.getElementById('wifiChannelTime').value);
          fd.append('wifiScanInterval', document.getElementById('wifiScanInterval').value);
          fd.append('bleScanInterval', document.getElementById('bleScanInterval').value);
          fd.append('bleScanDuration', document.getElementById('bleScanDuration').value);
          fd.append('wifiChannels', document.getElementById('wifiChannels').value);
        } else {
          fd.append('preset', preset);
        }
        
        try {
          const r = await fetch('/rf-config', {method: 'POST', body: fd});
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to save RF config', 'error');
        }
      }

      async function saveWiFiConfig() {
        const ssid = document.getElementById('apSsid').value.trim();
        const pass = document.getElementById('apPass').value;
        
        if (ssid.length === 0) {
          toast('SSID cannot be empty');
          return;
        }
        
        if (pass.length > 0 && pass.length < 8) {
          toast('Password must be at least 8 characters');
          return;
        }
        
        const fd = new FormData();
        fd.append('ssid', ssid);
        fd.append('pass', pass);
        
        try {
          const r = await fetch('/wifi-config', {method: 'POST', body: fd});
          const msg = await r.text();
          toast(msg);
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function loadWiFiConfig() {
        try {
          const r = await fetch('/wifi-config');
          const cfg = await r.json();
          document.getElementById('apSsid').value = cfg.ssid;
          document.getElementById('apPass').value = cfg.pass;
        } catch(e) {}
      }
      
      function toggleCard(cardId) {
        const card = document.getElementById(cardId);
        const toggle = document.getElementById(cardId.replace('Card', 'Toggle'));
        if (card.style.display === 'none') {
          card.style.display = 'block';
          toggle.style.transform = 'rotate(0deg)';
        } else {
          card.style.display = 'none';
          toggle.style.transform = 'rotate(-90deg)';
        }
      }
           
      async function loadBaselineAnomalyConfig() {
        try {
          const r = await fetch('/baseline/config');
          const data = await r.json();
          if (data.rssiThreshold !== undefined) {
            document.getElementById('baselineRssiThreshold').value = data.rssiThreshold;
          }
          if (data.baselineDuration !== undefined) {
            document.getElementById('baselineDuration').value = data.baselineDuration;
          }
          if (data.ramCacheSize !== undefined) {
            document.getElementById('baselineRamSize').value = data.ramCacheSize;
          }
          if (data.sdMaxDevices !== undefined) {
            document.getElementById('baselineSdMax').value = data.sdMaxDevices;
          }
          if (data.absenceThreshold !== undefined) {
            document.getElementById('absenceThreshold').value = data.absenceThreshold;
          }
          if (data.reappearanceWindow !== undefined) {
            document.getElementById('reappearanceWindow').value = data.reappearanceWindow;
          }
          if (data.rssiChangeDelta !== undefined) {
            document.getElementById('rssiChangeDelta').value = data.rssiChangeDelta;
          }
        } catch(error) {
          console.error('Error loading baseline config:', error);
        }
        
        try {
          const r = await fetch('/allowlist-export');
          const t = await r.text();
          document.getElementById('wlist').value = t;
          document.getElementById('allowlistCount').textContent = t.split('\n').filter(x => x.trim()).length + ' entries';
        } catch(error) {
          console.error('Error loading allowlist:', error);
        }
      }

      async function clearOldIdentities() {
        if (!confirm('Clear device identities older than 1 hour?')) return;
        try {
          const response = await fetch('/randomization/clear-old', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'age=3600'
          });
          const data = await response.text();
          toast(data, 'success');
        } catch (error) {
          toast('Error: ' + error, 'error');
        }
      }

      let baselineUpdating = false;
      async function updateBaselineStatus() {
        if (baselineUpdating) return;
        const detectionMode = document.getElementById('detectionMode');
        const statusDiv = document.getElementById('baselineStatus');
        if (!detectionMode || detectionMode.value !== 'baseline') {
          if (statusDiv) statusDiv.style.display = 'none';
          if (baselineUpdateInterval) {
            clearInterval(baselineUpdateInterval);
            baselineUpdateInterval = null;
          }
          return;
        }
        if (statusDiv) statusDiv.style.display = '';
        baselineUpdating = true;
        try {
          const response = await fetch('/baseline/stats');
          const stats = await response.json();
          const statusDiv = document.getElementById('baselineStatus');
          if (!statusDiv) return;
          let statusHTML = '';
          let progressHTML = '';
          if (stats.scanning && !stats.phase1Complete) {
            // Phase 1: Establishing baseline
            const progress = Math.min(100, (stats.elapsedTime / stats.totalDuration) * 100);
            statusHTML = '<div style="color:var(--succ);font-weight:bold;">⬤ Phase 1: Establishing Baseline...</div>';
            progressHTML = '<div style="margin-top:10px;">' + '<div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px;">' + '<span>Progress</span>' + '<span>' + Math.floor(progress) + '%</span>' + '</div>' + '<div style="width:100%;height:6px;background:var(--bord);border-radius:3px;overflow:hidden;">' + '<div style="height:100%;width:' + progress + '%;background:linear-gradient(90deg,var(--succ),var(--acc));transition:width 0.5s;"></div>' + '</div>' + '</div>';
          } else if (stats.scanning && stats.phase1Complete) {
            // Phase 2: Monitoring - add active status indicator
            statusHTML = '<div style="color:var(--acc);font-weight:bold;">⬤ Phase 2: Monitoring for Anomalies</div>';
            // Add elapsed time indicator for Phase 2
            const monitorTime = Math.floor(stats.elapsedTime / 1000);
            const monitorMins = Math.floor(monitorTime / 60);
            const monitorSecs = monitorTime % 60;
            progressHTML = '<div style="margin-top:10px;color:var(--succ);font-size:11px;">' + 'Active monitoring: ' + monitorMins + 'm ' + monitorSecs + 's' + '</div>';
          } else if (stats.established) {
            // Complete
            statusHTML = '<div style="color:var(--succ);">✓ Baseline Complete</div>';
          } else {
            statusHTML = '<div style="color:var(--mut);">No baseline data</div>';
          }
          let statsHTML = '';
          if (stats.scanning) {
            const cur = stats.totalDevices;
            const newBadge = (cur > prevUniqueDevices && prevUniqueDevices > 0) ? ' <span style="color:var(--succ);font-size:10px;font-weight:normal;">(+' + (cur - prevUniqueDevices) + ' new)</span>' : '';
            statsHTML = '<div style="margin-top:12px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">' + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px;">' + '<div>' + '<div style="color:var(--mut);">WiFi Devices</div>' + '<div style="color:var(--txt);font-size:16px;font-weight:bold;">' + stats.wifiDevices + '</div>' + '<div style="color:var(--mut);font-size:10px;">' + stats.wifiHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">BLE Devices</div>' + '<div style="color:var(--txt);font-size:16px;font-weight:bold;">' + stats.bleDevices + '</div>' + '<div style="color:var(--mut);font-size:10px;">' + stats.bleHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">Total Devices</div>' + '<div style="color:var(--acc);font-size:16px;font-weight:bold;">' + cur + newBadge + '</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">Anomalies</div>' + '<div style="color:' + (stats.anomalies > 0 ? 'var(--dang)' : 'var(--txt)') + ';font-size:16px;font-weight:bold;">' + stats.anomalies + '</div>' + '</div>' + '</div>' + '</div>';
            // Also update system overview unique devices
            const el = document.getElementById('uniqueDevices');
            if (el) {
              if (cur > prevUniqueDevices && prevUniqueDevices > 0) {
                el.innerHTML = cur + ' <span style="color:var(--succ);font-size:11px;font-weight:normal;">(+' + (cur - prevUniqueDevices) + ' new)</span>';
                el.style.transition = 'color 0.3s';
                el.style.color = 'var(--succ)';
                setTimeout(() => { el.style.color = ''; }, 2000);
              } else {
                el.innerText = cur;
              }
            }
            prevUniqueDevices = cur;
          }
          statusDiv.innerHTML = statusHTML + progressHTML + statsHTML;

          // Always refresh results while scanning — keeps results in sync with phases card
          if (stats.scanning) {
            try {
              const rr = await fetch('/results');
              const rt = await rr.text();
              // Don't regress to empty/placeholder while scanning
              if (rt && rt.trim() !== '' && !rt.includes('None yet') && !rt.includes('No scan data') && rt !== lastResultsText) {
                lastResultsText = rt;
                const re = document.getElementById('r');
                if (re) re.innerHTML = parseAndStyleResults(rt);
              }
            } catch(e) {}
          }

          const startDetectionBtn = document.getElementById('startDetectionBtn');
          const detectionMode = document.getElementById('detectionMode')?.value;
          const cacheBtn = document.getElementById('cacheBtn');
          const clearOldBtn = document.getElementById('clearOldBtn');
          
          if (cacheBtn) cacheBtn.style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
          if (clearOldBtn) clearOldBtn.style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
          
           if (detectionMode === 'baseline' && stats.scanning) {
            startDetectionBtn.textContent = stats.phase1Complete ? 'Stop Monitoring' : 'Stop Baseline';
            startDetectionBtn.classList.remove('primary');
            startDetectionBtn.classList.add('danger');
            startDetectionBtn.type = 'button';
            startDetectionBtn.onclick = async function(e) {
              e.preventDefault();
              try {
                const response = await fetch('/stop');
                const text = await response.text();
                toast(text);
                setTimeout(updateBaselineStatus, 500);
              } catch (error) {
                console.error('Stop error:', error);
              }
            };
          } else if (detectionMode === 'baseline' && !stats.scanning) {
            startDetectionBtn.textContent = 'Start Scan';
            startDetectionBtn.classList.remove('danger');
            startDetectionBtn.classList.add('primary');
            startDetectionBtn.type = 'submit';
            startDetectionBtn.onclick = null;
          }    
          // Polling from scan state
          if (stats.scanning && !baselineUpdateInterval) {
            baselineUpdateInterval = setInterval(updateBaselineStatus, 2000);
          } else if (!stats.scanning && baselineUpdateInterval) {
            clearInterval(baselineUpdateInterval);
            baselineUpdateInterval = null;
            prevUniqueDevices = 0;
          }
        } catch(error) {
          console.error('Status update error:', error);
        } finally {
          baselineUpdating = false;
        }
      }

      // Initial load
      updateBaselineStatus();
      // Poll every 2 seconds when not actively scanning
      setInterval(() => {
        const detectionMode = document.getElementById('detectionMode');
        if (detectionMode && detectionMode.value === 'baseline' && !baselineUpdateInterval) {
          updateBaselineStatus();
        }
      }, 2000);
      
      async function saveBaselineConfig() {
        const rssiThreshold = document.getElementById('baselineRssiThreshold').value;
        const duration = document.getElementById('baselineDuration').value;
        const ramSize = document.getElementById('baselineRamSize').value;
        const sdMax = document.getElementById('baselineSdMax').value;
        
        try {
          const response = await fetch('/baseline/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `rssiThreshold=${rssiThreshold}&baselineDuration=${duration}&ramCacheSize=${ramSize}&sdMaxDevices=${sdMax}`
          });
          const data = await response.text();
          toast('Baseline configuration saved', 'success');
          await updateBaselineStatus();
        } catch (error) {
          toast('Error saving config: ' + error, 'error');
        }
      }
      
      async function resetBaseline() {
        if (!confirm('Are you sure you want to reset the baseline? This will clear all collected data.')) return;
        try {
          const response = await fetch('/baseline/reset', { method: 'POST' });
          const data = await response.text();
          toast(data, 'success');
          await updateBaselineStatus();
        } catch (error) {
          toast('Error resetting baseline: ' + error, 'error');
        }
      }

      function clearResults() {
        if (!confirm('Clear scan results?')) return;
        
        fetch('/clear-results', { method: 'POST' })
          .then(r => r.text())
          .then(() => {
            document.getElementById('r').innerText = 'No scan data yet.';
            toast('Results cleared', 'info');
          })
          .catch(err => {
            console.error('Clear failed:', err);
            toast('Failed to clear results', 'error');
          });
      }
      
      let currentSort = 'default';
      let sortReverse = false;

      function applySorting() {
        currentSort = document.getElementById('sortBy').value;
        sortResultsDisplay();
      }

      function applyPrivacyToElement(el) {
        // Replace MAC addresses in all text nodes
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null, false);
        const textNodes = [];
        while (walker.nextNode()) textNodes.push(walker.currentNode);
        textNodes.forEach(node => {
          node.nodeValue = node.nodeValue.replace(
            /\b([A-F0-9]{2}:){5}[A-F0-9]{2}\b/gi,
            'XX:XX:XX:XX:XX:XX'
          );
        });

        // Replace device names — <strong> whose parent div starts with "Name:"
        el.querySelectorAll('strong').forEach(strong => {
          if (strong.parentElement?.textContent.startsWith('Name:')) {
            strong.textContent = 'REDACTED';
          }
        });

        // Replace GPS coordinates — leaf divs containing only a float with 4+ decimals
        el.querySelectorAll('div').forEach(div => {
          if (div.children.length === 0 &&
              /^-?\d{1,3}\.\d{4,}$/.test(div.textContent.trim())) {
            div.textContent = 'REDACTED';
          }
        });

        // Redact SSIDs — all elements with data-ssid attribute
        el.querySelectorAll('[data-ssid]').forEach(elem => {
          const original = elem.getAttribute('data-ssid');
          const hashed = ssidHash(original);
          const sup = elem.querySelector('sup');
          if (sup) {
            const supText = sup.textContent;
            elem.textContent = '';
            elem.appendChild(document.createTextNode(hashed + ' '));
            const newSup = document.createElement('sup');
            newSup.textContent = supText;
            elem.appendChild(newSup);
          } else {
            elem.textContent = hashed;
          }
          elem.title = 'REDACTED';
        });

        // Redact AP responded SSIDs
        el.querySelectorAll('[data-ap-ssid]').forEach(div => {
          const strong = div.querySelector('strong');
          if (strong) strong.textContent = ssidHash(div.getAttribute('data-ap-ssid'));
        });
      }

      function ssidHash(ssid) {
        if (!ssid || ssid.length === 0) return '?';
        let h = 0x811c9dc5;
        for (let i = 0; i < ssid.length; i++) {
          h ^= ssid.charCodeAt(i);
          h = Math.imul(h, 0x01000193);
        }
        return 'net#' + ((h >>> 0) & 0xFFFF).toString(16).padStart(4, '0');
      }

      function toggleSortOrder() {
        sortReverse = !sortReverse;
        sortResultsDisplay();
      }

      function sortResultsDisplay() {
        const resultsElement = document.getElementById('r');
        
        if (currentSort === 'default') {
          return;
        }
        
        const isRandomization = resultsElement.textContent.includes('MAC RANDOMIZATION DETECTION');
        const isBaseline = resultsElement.textContent.includes('Baseline') || resultsElement.querySelector('.baseline-marker');
        const isDeauth = resultsElement.textContent.includes('Deauth Attack Detection');
        const isDrone = resultsElement.textContent.includes('Drone Detection');
        const isDeviceScan = resultsElement.textContent.includes('Device Discovery');
        
        let items = [];
        const preservedElements = [];
        
        if (isRandomization) {
          Array.from(resultsElement.children).forEach(child => {
            if (child.tagName === 'DETAILS') {
              const summary = child.querySelector('summary');
              if (!summary) {
                preservedElements.push(child);
                return;
              }
              
              const macElement = summary.querySelector('[style*="monospace"]');
              const mac = macElement ? macElement.textContent.trim() : '';
              
              const summaryText = summary.textContent;
              const confidenceMatch = summaryText.match(/(\d+)%/);
              const confidence = confidenceMatch ? parseInt(confidenceMatch[1]) : 0;
              
              const rssiMatch = summaryText.match(/([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : -999;
              
              const detailsContent = child.textContent;
              const sessionsMatch = detailsContent.match(/SESSIONS\s*(\d+)/);
              const sessions = sessionsMatch ? parseInt(sessionsMatch[1]) : 0;
              
              const lastSeenMatch = detailsContent.match(/LAST SEEN\s*(\d+)s/);
              const lastSeen = lastSeenMatch ? parseInt(lastSeenMatch[1]) : 999999;
              
              const trackIdMatch = detailsContent.match(/TRACK ID\s*([A-Z0-9-]+)/);
              const trackId = trackIdMatch ? trackIdMatch[1].trim() : '';
              
              const deviceType = child.getAttribute('data-type') || '';
              
              items.push({
                element: child,
                mac, confidence, rssi, sessions, lastSeen, trackId, deviceType,
                sortKey: currentSort,
                type: 'randomization'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isBaseline) {
          var baselineContainer = null;
          Array.from(resultsElement.children).forEach(child => {
            if (child.classList.contains('device-card')) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const rssiMatch = child.textContent.match(/RSSI:\s*([-\d]+)\s*dBm/);
              const nameMatch = child.textContent.match(/Name:\s*([^\n]+)/);
              items.push({
                element: child,
                mac: macMatch ? macMatch[1] : '',
                rssi: rssiMatch ? parseInt(rssiMatch[1]) : 0,
                name: nameMatch ? nameMatch[1].trim() : '',
                sortKey: currentSort,
                type: 'baseline'
              });
            } else if (child.tagName === 'DETAILS') {
              baselineContainer = child.querySelector('div');
              if (baselineContainer) {
                Array.from(baselineContainer.children).forEach(card => {
                  if (card.classList.contains('device-card')) {
                    const macMatch = card.textContent.match(/([A-F0-9:]+)/);
                    const rssiMatch = card.textContent.match(/RSSI:\s*([-\d]+)\s*dBm/);
                    const nameMatch = card.textContent.match(/Name:\s*([^\n]+)/);
                    items.push({
                      element: card,
                      mac: macMatch ? macMatch[1] : '',
                      rssi: rssiMatch ? parseInt(rssiMatch[1]) : 0,
                      name: nameMatch ? nameMatch[1].trim() : '',
                      sortKey: currentSort,
                      type: 'baseline'
                    });
                  }
                });
              }
              preservedElements.push(child);
            } else {
              preservedElements.push(child);
            }
          });
          if (baselineContainer && items.length > 0) {
            items.sort((a, b) => {
              let cmp = 0;
              switch(currentSort) {
                case 'rssi-desc': cmp = b.rssi - a.rssi; break;
                case 'rssi-asc': cmp = a.rssi - b.rssi; break;
                case 'name-asc': cmp = (a.name || a.mac).localeCompare(b.name || b.mac); break;
                case 'type-asc': cmp = (a.element.getAttribute('data-type') || '').localeCompare(b.element.getAttribute('data-type') || ''); break;
                case 'channel-asc': cmp = parseInt(a.element.getAttribute('data-channel') || '0') - parseInt(b.element.getAttribute('data-channel') || '0'); break;
                default: cmp = 0;
              }
              return sortReverse ? -cmp : cmp;
            });
            baselineContainer.innerHTML = '';
            items.forEach(item => baselineContainer.appendChild(item.element));
            return;
          }
        } else if (isDeauth) {
          Array.from(resultsElement.children).forEach(child => {
            const hasDeauthBorder = child.getAttribute('style')?.includes('border:1px solid var(--warn)');
            if (hasDeauthBorder) {
              const macMatch = child.textContent.match(/([A-F0-9:]+|\[BROADCAST\])/);
              const mac = macMatch ? macMatch[1] : '';
              
              const totalMatch = child.textContent.match(/Total Attacks[\s\S]*?(\d+)/);
              const attacks = totalMatch ? parseInt(totalMatch[1]) : 0;
              
              const rssiMatch = child.textContent.match(/Signal[\s\S]*?([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              items.push({
                element: child,
                mac, attacks, rssi,
                sortKey: currentSort,
                type: 'deauth'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isDrone) {
          Array.from(resultsElement.children).forEach(child => {
            const hasDroneBorder = child.getAttribute('style')?.includes('border:1px solid var(--acc)');
            if (hasDroneBorder) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const mac = macMatch ? macMatch[1] : '';
              
              const rssiMatch = child.textContent.match(/RSSI:\s*([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              items.push({
                element: child,
                mac, rssi,
                sortKey: currentSort,
                type: 'drone'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isDeviceScan) {
          Array.from(resultsElement.children).forEach(child => {
            if (child.classList.contains('device-card')) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const mac = macMatch ? macMatch[1] : '';
              
              const rssiMatch = child.textContent.match(/RSSI:\s*([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              const nameMatch = child.textContent.match(/Name:\s*([^\n]+)/);
              const name = nameMatch ? nameMatch[1].trim() : '';
              
              const deviceType = child.getAttribute('data-type') || '';
              const channel = parseInt(child.getAttribute('data-channel') || '0', 10);

              items.push({
                element: child,
                mac, rssi, name, deviceType, channel,
                sortKey: currentSort,
                type: 'device'
              });
            } else {
              preservedElements.push(child);
            }
          });
        }
        
        if (items.length === 0) {
          return;
        }
        
        items.sort((a, b) => {
          let cmp = 0;
          
          switch(currentSort) {
            case 'rssi-desc':
              cmp = b.rssi - a.rssi;
              break;
            case 'rssi-asc':
              cmp = a.rssi - b.rssi;
              break;
            case 'confidence-desc':
              cmp = (b.confidence || 0) - (a.confidence || 0);
              break;
            case 'sessions-desc':
              cmp = (b.sessions || 0) - (a.sessions || 0);
              break;
            case 'lastseen-asc':
              cmp = (a.lastSeen || 0) - (b.lastSeen || 0);
              break;
            case 'name-asc':
              cmp = (a.name || a.mac).localeCompare(b.name || b.mac);
              break;
            case 'type-asc':
              cmp = (a.deviceType || '').localeCompare(b.deviceType || '');
              break;
            case 'channel-asc':
              cmp = (a.channel || 0) - (b.channel || 0);
              break;
            default:
              cmp = 0;
          }
          
          return sortReverse ? -cmp : cmp;
        });
        
        resultsElement.innerHTML = '';
        
        preservedElements.forEach(el => {
          resultsElement.appendChild(el);
        });
        
        items.forEach(item => {
          resultsElement.appendChild(item.element);
        });
      }

      // Override the parseAndStyleResults to reset sort after reload
      const originalParseAndStyleResults = window.parseAndStyleResults;
      window.parseAndStyleResults = function(text) {
        const html = originalParseAndStyleResults.call(this, text);
        if (!privacyMode) return html;
        const temp = document.createElement('div');
        temp.innerHTML = html;
        applyPrivacyToElement(temp);
        return temp.innerHTML;
      };
      
      const scanTaskLabels = {
        scan: 'List Scan', sniffer: 'Device Scan', drone: 'Drone Detect',
        blueteam: 'Blue Team', baseline: 'Baseline', randdetect: 'Rand Detect',
        probedet: 'Probe Detect', triangulate: 'Triangulate'
      };
      function setScanStatus(label, state) {
        const el = document.getElementById('scanStatus');
        if (!el) return;
        el.innerText = label;
        el.classList.remove('idle', 'active');
        if (state) el.classList.add(state);
      }
      function updateStatusIndicators(diagText) {
        const taskTypeMatch = diagText.match(/Task Type: ([^\n]+)/);
        const taskType = taskTypeMatch ? taskTypeMatch[1].trim() : 'none';
        const isScanning = diagText.includes('Scanning: yes');
        const isTriangulating = diagText.includes('Triangulating: yes');
        const detectionMode = document.getElementById('detectionMode')?.value;

        document.getElementById('cacheBtn').style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
        document.getElementById('clearOldBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
        document.getElementById('resetRandBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';

        if (isScanning || isTriangulating) {
            const label = scanTaskLabels[taskType] || (isTriangulating ? 'Triangulate' : 'Scanning');
            setScanStatus(label, 'active');
            
            const startScanBtn = document.querySelector('#s button');
            if (startScanBtn && taskType === 'scan') {
                startScanBtn.textContent = 'Stop Scanning';
                startScanBtn.classList.remove('primary');
                startScanBtn.classList.add('danger');
                startScanBtn.type = 'button';
                startScanBtn.onclick = function(e) {
                    e.preventDefault();
                    lastScanStartTime = 0;
                    fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                        setTimeout(async () => {
                            const refreshedDiag = await fetch('/diag').then(r => r.text());
                            updateStatusIndicators(refreshedDiag);
                        }, 500);
                    });
                };
            }

            if (taskType === 'triangulate') {
                const triangulateBtn = document.querySelector('#s button');
                if (triangulateBtn) {
                    triangulateBtn.textContent = 'Stop Scan';
                    triangulateBtn.classList.remove('primary');
                    triangulateBtn.classList.add('danger');
                    triangulateBtn.type = 'button';
                    triangulateBtn.onclick = function(e) {
                        e.preventDefault();
                        lastScanStartTime = 0;
                        fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                            setTimeout(async () => {
                                const refreshedDiag = await fetch('/diag').then(r => r.text());
                                updateStatusIndicators(refreshedDiag);
                            }, 500);
                        });
                    };
                }
            }

            if (taskType === 'sniffer' || taskType === 'drone' || taskType === 'randdetect' || taskType === 'blueteam' || taskType === 'probedet') {
                const startDetectionBtn = document.getElementById('startDetectionBtn');
                if (startDetectionBtn) {
                    startDetectionBtn.textContent = 'Stop Scanning';
                    startDetectionBtn.classList.remove('primary');
                    startDetectionBtn.classList.add('danger');
                    startDetectionBtn.type = 'button';
                    startDetectionBtn.onclick = function(e) {
                        e.preventDefault();
                        lastScanStartTime = 0;
                        fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                            setTimeout(async () => {
                                const refreshedDiag = await fetch('/diag').then(r => r.text());
                                updateStatusIndicators(refreshedDiag);
                            }, 500);
                        });
                    };
                }
            }
        } else {
            const isWithinGracePeriod = (Date.now() - lastScanStartTime) < 3000;

            if (!isWithinGracePeriod) {
                setScanStatus('Idle', 'idle');

                const startScanBtn = document.querySelector('#s button');
                if (startScanBtn) {
                    startScanBtn.textContent = 'Start Scan';
                    startScanBtn.classList.remove('danger');
                    startScanBtn.classList.add('primary');
                    startScanBtn.type = 'submit';
                    startScanBtn.onclick = null;
                    startScanBtn.style.background = '';
                }

                const detectionMode = document.getElementById('detectionMode')?.value;
                if (detectionMode !== 'baseline') {
                    const startDetectionBtn = document.getElementById('startDetectionBtn');
                    if (startDetectionBtn) {
                        startDetectionBtn.textContent = 'Start Scan';
                        startDetectionBtn.classList.remove('danger');
                        startDetectionBtn.classList.add('primary');
                        startDetectionBtn.type = 'submit';
                        startDetectionBtn.onclick = null;
                    }
                }
            }
        }

        const modeMatch = diagText.match(/Scan Mode: ([^\n]+)/);
        if (modeMatch) {
            document.getElementById('modeStatus').innerText = modeMatch[1];
        }
        
        if (diagText.includes('GPS: Locked')) {
            document.getElementById('gpsStatus').classList.add('active');
            document.getElementById('gpsStatus').innerText = 'GPS Lock';
        } else {
            document.getElementById('gpsStatus').classList.remove('active');
            document.getElementById('gpsStatus').innerText = 'GPS';
        }
        
        if (diagText.includes('RTC: Synced')) {
            document.getElementById('rtcStatus').classList.add('active');
            document.getElementById('rtcStatus').innerText = 'RTC OK';
        } else if (diagText.includes('RTC: Not')) {
            document.getElementById('rtcStatus').classList.remove('active');
            document.getElementById('rtcStatus').innerText = 'RTC';
        }
      }
        
      function updateModeStatus() {
        const scanModeSelect = document.querySelector('#s select[name="mode"]');
        const detectionModeSelect = document.getElementById('detectionMode');
        const randomizationModeSelect = document.getElementById('randomizationMode');
        const deviceScanModeSelect = document.getElementById('deviceScanMode');
        const probeScanModeSelect = document.getElementById('probeScanMode');
        const modeStatus = document.getElementById('modeStatus');

        let currentMode = '0';

        const detectionMethod = detectionModeSelect?.value;

        if (detectionMethod === 'randomization-detection' && randomizationModeSelect?.offsetParent !== null) {
          currentMode = randomizationModeSelect.value;
        } else if (detectionMethod === 'device-scan' && deviceScanModeSelect?.offsetParent !== null) {
          currentMode = deviceScanModeSelect.value;
        } else if (detectionMethod === 'probe-scan' && probeScanModeSelect?.offsetParent !== null) {
          currentMode = probeScanModeSelect.value;
        } else if (scanModeSelect) {
          currentMode = scanModeSelect.value;
        }
        
        const modeText = {
          '0': 'WiFi',
          '1': 'BLE',
          '2': 'WiFi+BLE'
        };
        
        if (modeStatus) {
          modeStatus.innerText = modeText[currentMode] || 'WiFi';
        }
      }
      
      async function saveAutoEraseConfig() {
      try {
        const enabled = document.getElementById('autoEraseEnabled').checked;
        const delay = document.getElementById('autoEraseDelay').value;
        const cooldown = document.getElementById('autoEraseCooldown').value;
        const vibrationsRequired = document.getElementById('vibrationsRequired').value;
        const detectionWindow = document.getElementById('detectionWindow').value;
        const setupDelay = document.getElementById('setupDelay').value;

        console.log('[AUTOERASE] Sending:', {enabled, delay, cooldown, vibrationsRequired, detectionWindow, setupDelay});

        const fd = new FormData();
        fd.append('enabled', enabled);
        fd.append('delay', delay);
        fd.append('cooldown', cooldown);
        fd.append('vibrationsRequired', vibrationsRequired);
        fd.append('detectionWindow', detectionWindow);
        fd.append('setupDelay', setupDelay);

        const response = await fetch('/config/autoerase', {
          method: 'POST',
          body: fd
        });

        console.log('[AUTOERASE] Response status:', response.status);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.text();
        console.log('[AUTOERASE] Success:', data);
        document.getElementById('autoEraseStatus').textContent = 'Config saved: ' + data;
        toast('Configuration saved', 'success');
        updateAutoEraseStatus();
      } catch (error) {
        console.error('[AUTOERASE] Error:', error);
        document.getElementById('autoEraseStatus').textContent = 'ERROR: ' + error.message;
        toast('Failed to save: ' + error.message, 'error');
      }
    }
      
      function updateEraseProgress(message, percentage) {
        const progressBar = document.getElementById('eraseProgressBar');
        const progressText = document.getElementById('eraseProgressText');
        const progressDetails = document.getElementById('eraseProgressDetails');
        if (progressBar) {
          progressBar.style.width = percentage + '%';
        }
        if (progressText) {
          progressText.textContent = message;
        }
        if (progressDetails) {
          progressDetails.innerHTML += `<div>${new Date().toLocaleTimeString()}: ${message}</div>`;
          progressDetails.scrollTop = progressDetails.scrollHeight;
        }
      }
      
      function pollEraseProgress() {
        const poll = setInterval(() => {
          fetch('/erase/progress').then(response => response.json()).then(data => {
            updateEraseProgress(data.message, data.percentage);
            if (data.status === 'COMPLETE') {
              clearInterval(poll);
              finalizeEraseProcess(true);
            } else if (data.status === 'ERROR') {
              clearInterval(poll);
              finalizeEraseProcess(false, data.error);
            } else if (data.status === 'CANCELLED') {
              clearInterval(poll);
              hideEraseProgressModal();
              toast('Secure erase cancelled', 'info');
            }
          }).catch(error => {
            clearInterval(poll);
            finalizeEraseProcess(false, 'Communication error');
          });
        }, 1000);
      }
      
      function finalizeEraseProcess(success, error = null) {
        if (success) {
          updateEraseProgress('Secure erase completed successfully', 100);
          toast('All data has been securely destroyed', 'success');
          setTimeout(() => {
            hideEraseProgressModal();
            window.location.reload();
          }, 3000);
        } else {
          updateEraseProgress('Secure erase failed: ' + error, 0);
          toast('Erase operation failed: ' + error, 'error');
          setTimeout(() => {
            hideEraseProgressModal();
          }, 5000);
        }
      }
      
      function hideEraseProgressModal() {
        const modal = document.getElementById('eraseProgressModal');
        if (modal) {
          document.body.removeChild(modal);
        }
      }

      function rssiColorFor(rssi) {
        const v = parseInt(rssi);
        if (v >= -50) return 'var(--succ)';
        if (v >= -70) return 'var(--txt)';
        return 'var(--mut)';
      }

      function parseAndStyleResults(text) {
        if (!text || text.trim() === '' || text.includes('None yet') || text.includes('No scan data')) {
          return '<div style="color:var(--mut);padding:20px;text-align:center;">No scan data yet.</div>';
        }

        let html = '';

        if (text.includes('=== Triangulation Results') || text.includes('Weighted GPS Trilateration')) {
          html = parseTriangulationResults(text);
        } else if(text.includes('MAC Randomization Detection Results')) {
          html = parseRandomizationResults(text);
        } else if (text.includes('Baseline not yet established') || text.includes('Baseline Detection Results')) {
          html = parseBaselineResults(text);
        } else if (text.includes('Deauth Detection Results') || text.includes('Deauth Attack Detection Results')) {
          html = parseDeauthResults(text);
        } else if (text.includes('Drone Detection Results')) {
          html = parseDroneResults(text);
        } else if (text.includes('Probes:') && text.includes('SSIDs:')) {
          html = parseProbeResults(text);
        } else if (text.includes('Target Hits:') || text.match(/^(WiFi|BLE)\s+[A-F0-9:]/m)) {
          html = parseDeviceScanResults(text);
        } else {
          html = '<div style="margin:0;background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:12px;color:var(--txt);font-size:11px;overflow-x:auto;">' + text + '</div>';
        }
        
        return html;
      }

      function parseTriangulationResults(text) {
        let html = '<div style="font-size:13px;">';
        
        const headerSection = text.split('---')[0];
        if (headerSection.includes('=== Triangulation Results ===')) {
          const targetMatch = headerSection.match(/Target MAC: ([A-F0-9:]+)/);
          const durationMatch = headerSection.match(/Duration: (\d+)s/);
          const elapsedMatch = headerSection.match(/Elapsed: (\d+)s/);
          const nodesMatch = headerSection.match(/Reporting Nodes: (\d+)/);
          const syncMatch = headerSection.match(/Clock Sync: (.+)/);
          
          html += '<div style="padding:16px;background:var(--surf);border:2px solid var(--acc);border-radius:12px;margin-bottom:16px;backdrop-filter:var(--backdrop);box-shadow:var(--shad);">';
          html += '<div style="font-weight:700;font-size:16px;color:var(--txt);margin-bottom:12px;letter-spacing:-0.01em;">Triangulation Results</div>';
          
          if (targetMatch) {
            html += '<div style="margin:8px 0;padding:10px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;font-family:monospace;color:var(--acc);font-size:13px;font-weight:600;">';
            html += 'TARGET: ' + targetMatch[1];
            html += '</div>';
          }
          
          html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:12px;">';
          if (durationMatch && elapsedMatch) {
            html += '<div style="background:var(--bg);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;">Duration</div>';
            html += '<div style="color:var(--txt);font-weight:700;font-size:18px;">' + durationMatch[1] + 's</div>';
            html += '</div>';
            
            html += '<div style="background:var(--bg);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;">Elapsed</div>';
            html += '<div style="color:var(--txt);font-weight:700;font-size:18px;">' + elapsedMatch[1] + 's</div>';
            html += '</div>';
          }
          
          if (nodesMatch) {
            html += '<div style="background:var(--bg);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;">Nodes</div>';
            html += '<div style="color:var(--txt);font-weight:700;font-size:18px;">' + nodesMatch[1] + '</div>';
            html += '</div>';
          }
          html += '</div>';
          
          if (syncMatch) {
            const syncVerified = syncMatch[1].includes('VERIFIED');
            const syncColor = syncVerified ? 'var(--succ)' : 'var(--warn)';
            html += '<div style="margin-top:12px;padding:8px;background:var(--bg);border-left:3px solid ' + syncColor + ';border-radius:4px;font-size:11px;color:var(--mut);">';
            html += '⏱ Clock Sync: ' + syncMatch[1];
            html += '</div>';
          }
          html += '</div>';
        }

        // // Check for error/warning states and display them prominently
        // if (text.includes('Insufficient GPS') || (text.includes('GPS nodes:') && text.includes('required'))) {
        //   const gpsCountMatch = text.match(/GPS nodes:\s*(\d+)\/(\d+)\s*required/);
        //   const totalNodesMatch = text.match(/Total nodes:\s*(\d+)/);
        //   html += '<div style="padding:20px;background:var(--warn-bg,#fef3c7);border:2px solid var(--warn,#f59e0b);border-radius:12px;margin-bottom:16px;">';
        //   html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">';
        //   html += '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn,#f59e0b)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
        //   html += '<div style="font-weight:700;font-size:16px;color:#78350f;">Insufficient GPS Nodes</div>';
        //   html += '</div>';
        //   if (gpsCountMatch) {
        //     html += '<div style="color:#78350f;font-size:14px;margin-bottom:8px;">Need ' + gpsCountMatch[2] + ' GPS nodes, but only ' + gpsCountMatch[1] + ' available.</div>';
        //     const needed = parseInt(gpsCountMatch[2]) - parseInt(gpsCountMatch[1]);
        //     html += '<div style="color:#78350f;font-size:13px;margin-bottom:16px;">Add ' + needed + ' more GPS-equipped node(s) to enable triangulation.</div>';
        //   } else {
        //     html += '<div style="color:#78350f;font-size:14px;margin-bottom:16px;">At least 3 GPS-equipped nodes are required for triangulation.</div>';
        //   }

        //   // Parse and display current GPS nodes
        //   const gpsNodesSection = text.split('Current GPS nodes:')[1]?.split('Non-GPS nodes:')[0];
        //   if (gpsNodesSection) {
        //     html += '<div style="margin-top:12px;padding:14px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;">';
        //     html += '<div style="color:#15803d;font-size:12px;font-weight:700;margin-bottom:10px;">GPS-Equipped Nodes</div>';
        //     const gpsNodeLines = gpsNodesSection.split('\n').filter(l => l.trim().startsWith('•'));
        //     gpsNodeLines.forEach(line => {
        //       const nodeMatch = line.match(/•\s*([^\s@]+)\s*@\s*([-\d.]+),([-\d.]+)/);
        //       if (nodeMatch) {
        //         html += '<div style="padding:10px;background:rgba(255,255,255,0.6);border-radius:6px;margin-bottom:6px;">';
        //         html += '<div style="color:#15803d;font-weight:700;font-size:12px;margin-bottom:4px;">' + nodeMatch[1] + '</div>';
        //         html += '<div style="color:#6b7280;font-family:monospace;font-size:11px;">' + nodeMatch[2] + ', ' + nodeMatch[3] + '</div>';
        //         html += '</div>';
        //       }
        //     });
        //     html += '</div>';
        //   }

        //   // Parse and display non-GPS nodes
        //   const nonGpsNodesSection = text.split('Non-GPS nodes:')[1]?.split('===')[0];
        //   if (nonGpsNodesSection) {
        //     html += '<div style="margin-top:12px;padding:14px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;">';
        //     html += '<div style="color:#991b1b;font-size:12px;font-weight:700;margin-bottom:10px;">Nodes Without GPS</div>';
        //     const nonGpsNodeLines = nonGpsNodesSection.split('\n').filter(l => l.trim().startsWith('•'));
        //     nonGpsNodeLines.forEach(line => {
        //       const nodeMatch = line.match(/•\s*([^\s(]+)/);
        //       if (nodeMatch) {
        //         html += '<div style="padding:10px;background:rgba(255,255,255,0.6);border-radius:6px;margin-bottom:6px;">';
        //         html += '<div style="color:#991b1b;font-weight:700;font-size:12px;margin-bottom:2px;">' + nodeMatch[1] + '</div>';
        //         html += '<div style="color:#6b7280;font-style:italic;font-size:10px;">GPS disabled or no fix</div>';
        //         html += '</div>';
        //       }
        //     });
        //     html += '</div>';
        //   }

        //   html += '</div>';
        // }

        // Show warning banners but continue parsing - don't block other sections
        if (text.includes('No Mesh Nodes Responding')) {
          html += '<div style="padding:20px;background:var(--c-err-bg);border:2px solid var(--dang);border-radius:12px;margin-bottom:16px;">';
          html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">';
          html += '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--dang)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
          html += '<div style="font-weight:700;font-size:16px;color:var(--dang);">No Mesh Nodes Responding</div>';
          html += '</div>';
          html += '<div style="color:var(--txt);font-size:14px;">No mesh nodes responded to the triangulation request. Check mesh connectivity.</div>';
          html += '</div>';
        }

        if (text.includes('TRIANGULATION IMPOSSIBLE') || text.includes('none have GPS')) {
          html += '<div style="padding:20px;background:var(--c-alert-bg);border:2px solid var(--warn);border-radius:12px;margin-bottom:16px;">';
          html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">';
          html += '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
          html += '<div style="font-weight:700;font-size:16px;color:var(--warn);">Triangulation Impossible</div>';
          html += '</div>';
          html += '<div style="color:var(--txt);font-size:14px;">Nodes responded but none have GPS coordinates. Enable GPS on at least 3 nodes.</div>';
          html += '</div>';
        }

        if (text.includes('Insufficient GPS Nodes')) {
          html += '<div style="padding:20px;background:var(--c-alert-bg);border:2px solid var(--warn);border-radius:12px;margin-bottom:16px;">';
          html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">';
          html += '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
          html += '<div style="font-weight:700;font-size:16px;color:var(--warn);">Waiting for More GPS Nodes</div>';
          html += '</div>';
          html += '<div style="color:var(--txt);font-size:14px;">Triangulation requires at least 3 GPS-equipped nodes. Collecting data...</div>';
          html += '</div>';
        }

        const nodeSection = text.split('--- Node Reports ---')[1]?.split('---')[0];
        if (nodeSection) {
          html += '<details open style="margin-bottom:16px;background:var(--surf);border:1px solid var(--bord);border-radius:12px;padding:16px;backdrop-filter:var(--backdrop);box-shadow:var(--shad);">';
          html += '<summary style="cursor:pointer;color:var(--acc);font-weight:700;user-select:none;list-style:none;display:flex;align-items:center;gap:10px;font-size:14px;margin-bottom:14px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>Node Reports';
          html += '</summary>';
          html += '<div style="display:grid;gap:12px;">';

          const nodeLines = nodeSection.split('\n').filter(l => l.trim() && l.includes(':'));
          nodeLines.forEach(line => {
            const nodeMatch = line.match(/^([^:]+):/);
            if (nodeMatch) {
              // Support both "Filtered=" (final results) and "RSSI=" (in-progress)
              let rssiMatch = line.match(/Filtered=([-\d.]+)dBm/);
              if (!rssiMatch) {
                rssiMatch = line.match(/RSSI=([-\d.]+)dBm/);
              }
              const hitsMatch = line.match(/Hits=(\d+)/);
              const signalMatch = line.match(/Signal=([\d.]+)%/);

              // Skip lines that don't have node data fields (like header fields: "Target MAC:", "Duration:", etc.)
              if (!rssiMatch && !hitsMatch && !signalMatch) {
                return;
              }

              const nodeId = nodeMatch[1].trim();
              const gpsMatch = line.match(/GPS=([-\d.]+),([-\d.]+)/);
              const hdopMatch = line.match(/HDOP=([\d.]+)/);
              const isGPS = gpsMatch !== null;
              const distMatch = line.match(/Dist=([\d.]+)m/);
              
              html += '<div style="padding:14px;background:var(--bg);border:1px solid var(--bord);border-radius:8px;transition:all 0.2s;">';
              
              html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">';
              html += '<div style="color:var(--txt);font-weight:700;font-size:13px;">' + nodeId + '</div>';
              if (isGPS) {
                html += '<div style="background:linear-gradient(135deg,var(--succ) 0%,var(--acc) 100%);color:#fff;padding:4px 10px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;">GPS</div>';
              } else {
                html += '<div style="background:var(--surf);color:var(--mut);padding:4px 10px;border-radius:4px;font-size:10px;font-weight:600;border:1px solid var(--bord);">NO GPS</div>';
              }
              html += '</div>';
              
              html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-top:10px;">';
              if (rssiMatch) {
                const rssiVal = parseFloat(rssiMatch[1]);
                const rssiColor = rssiVal > -60 ? 'var(--succ)' : rssiVal > -75 ? 'var(--warn)' : 'var(--dang)';
                html += '<div style="background:var(--surf);padding:8px;border-radius:6px;border:1px solid var(--bord);">';
                html += '<div style="color:var(--mut);font-size:9px;text-transform:uppercase;letter-spacing:0.05em;">RSSI</div>';
                html += '<div style="color:' + rssiColor + ';font-weight:700;font-size:14px;">' + rssiMatch[1] + ' dBm</div>';
                html += '</div>';
              }
              if (hitsMatch) {
                html += '<div style="background:var(--surf);padding:8px;border-radius:6px;border:1px solid var(--bord);">';
                html += '<div style="color:var(--mut);font-size:9px;text-transform:uppercase;letter-spacing:0.05em;">Hits</div>';
                html += '<div style="color:var(--txt);font-weight:700;font-size:14px;">' + hitsMatch[1] + '</div>';
                html += '</div>';
              }
              if (signalMatch) {
                const sigVal = parseFloat(signalMatch[1]);
                const sigColor = sigVal >= 70 ? 'var(--succ)' : sigVal >= 50 ? 'var(--warn)' : 'var(--dang)';
                html += '<div style="background:var(--surf);padding:8px;border-radius:6px;border:1px solid var(--bord);">';
                html += '<div style="color:var(--mut);font-size:9px;text-transform:uppercase;letter-spacing:0.05em;">Quality</div>';
                html += '<div style="color:' + sigColor + ';font-weight:700;font-size:14px;">' + signalMatch[1] + '%</div>';
                html += '</div>';
              }
              if (distMatch) {
                html += '<div style="background:var(--surf);padding:8px;border-radius:6px;border:1px solid var(--bord);">';
                html += '<div style="color:var(--mut);font-size:9px;text-transform:uppercase;letter-spacing:0.05em;">Distance</div>';
                html += '<div style="color:var(--txt);font-weight:700;font-size:14px;">' + distMatch[1] + 'm</div>';
                html += '</div>';
              }
              html += '</div>';
              
              if (isGPS) {
                html += '<div style="margin-top:10px;padding:10px;background:var(--surf);border:1px solid var(--acc);border-radius:6px;font-size:10px;font-family:monospace;">';
                html += '<span style="color:var(--mut);">Location:</span> ';
                html += '<span style="color:var(--acc);font-weight:600;">' + gpsMatch[1] + ', ' + gpsMatch[2] + '</span>';
                if (hdopMatch) {
                  html += '<span style="color:var(--mut);margin-left:12px;">HDOP: <span style="color:var(--txt);font-weight:600;">' + hdopMatch[1] + '</span></span>';
                }
                html += '</div>';
              }
              
              html += '</div>';
            }
          });
          
          html += '</div></details>';
        }
        
        const validationSection = text.split('--- GPS-RSSI Distance Validation ---')[1]?.split('---')[0];
        if (validationSection) {
          html += '<details open style="margin-bottom:16px;background:var(--surf);border:1px solid var(--bord);border-radius:12px;padding:16px;backdrop-filter:var(--backdrop);box-shadow:var(--shad);">';
          html += '<summary style="cursor:pointer;color:var(--acc);font-weight:700;user-select:none;list-style:none;display:flex;align-items:center;gap:10px;font-size:14px;margin-bottom:14px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>GPS-RSSI Validation';
          html += '</summary>';
          html += '<div style="display:grid;gap:8px;">';
          
          const valLines = validationSection.split('\n').filter(l => l.trim() && (l.includes('<->') || l.includes('Avg error')));
          valLines.forEach(line => {
            if (line.includes('<->')) {
              const checkMark = line.includes('✓') ? '✓' : '✗';
              const color = line.includes('✓') ? 'var(--succ)' : 'var(--dang)';
              const cleanLine = line.replace(/✓|✗/g, '').trim();
              html += '<div style="padding:10px;background:var(--bg);border-left:3px solid ' + color + ';border-radius:6px;font-size:11px;color:var(--txt);">';
              html += '<span style="color:' + color + ';font-weight:bold;margin-right:8px;">' + checkMark + '</span>' + cleanLine;
              html += '</div>';
            } else if (line.includes('Avg error')) {
              const errorMatch = line.match(/([\d.]+)%/);
              const qualityMatch = line.match(/\(([^)]+)\)/);
              if (errorMatch) {
                const errVal = parseFloat(errorMatch[1]);
                const errColor = errVal < 25 ? 'var(--succ)' : errVal < 50 ? 'var(--warn)' : 'var(--dang)';
                html += '<div style="margin-top:8px;padding:14px;background:var(--bg);border:2px solid ' + errColor + ';border-radius:8px;">';
                html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;">Average Error</div>';
                html += '<div style="color:' + errColor + ';font-weight:700;font-size:20px;margin-bottom:4px;">' + errorMatch[1] + '%</div>';
                if (qualityMatch) {
                  html += '<div style="color:var(--txt);font-size:12px;font-weight:600;">' + qualityMatch[1] + '</div>';
                }
                html += '</div>';
              }
            }
          });
          
          html += '</div></details>';
        }
        
        // Match ESTIMATED POSITION with optional qualifiers like (TDOA), (RSSI), or (TDOA + RSSI)
        const positionMatch = text.match(/ESTIMATED POSITION[^:]*:([\s\S]*?)(?:===|$)/);
        const positionSection = positionMatch ? positionMatch[1] : null;
        if (positionSection) {
          const latMatch = positionSection.match(/Latitude:\s*([-\d.]+)/);
          const lonMatch = positionSection.match(/Longitude:\s*([-\d.]+)/);
          const confMatch = positionSection.match(/Confidence:\s*([\d.]+)%/);
          const uncertaintyMatch = positionSection.match(/Uncertainty.*?±([\d.]+)m/);
          const methodMatch = positionSection.match(/Method:\s*([^\n]+)/);
          
          html += '<div style="padding:20px;background:var(--surf);border:2px solid var(--acc);border-radius:12px;margin-bottom:16px;backdrop-filter:var(--backdrop);box-shadow:var(--shad);">';
          html += '<div style="font-weight:700;font-size:16px;color:var(--txt);margin-bottom:16px;letter-spacing:-0.01em;display:flex;align-items:center;gap:8px;">';
          html += '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--acc)" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
          html += 'Position Estimated</div>';
          
          if (latMatch && lonMatch) {
            html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">';
            
            html += '<div style="background:var(--bg);padding:12px;border-radius:8px;border:1px solid var(--bord);">';
            html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">Latitude</div>';
            html += '<div style="color:var(--txt);font-weight:700;font-size:16px;font-family:monospace;">' + latMatch[1] + '</div>';
            html += '</div>';
            
            html += '<div style="background:var(--bg);padding:12px;border-radius:8px;border:1px solid var(--bord);">';
            html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">Longitude</div>';
            html += '<div style="color:var(--txt);font-weight:700;font-size:16px;font-family:monospace;">' + lonMatch[1] + '</div>';
            html += '</div>';
            
            html += '</div>';
            
            html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:12px;">';
            
            if (confMatch) {
              const confVal = parseFloat(confMatch[1]);
              const confColor = confVal >= 70 ? 'var(--succ)' : confVal >= 50 ? 'var(--warn)' : 'var(--dang)';
              html += '<div style="background:var(--bg);padding:12px;border-radius:8px;border:1px solid var(--bord);">';
              html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">Confidence</div>';
              html += '<div style="color:' + confColor + ';font-weight:700;font-size:18px;">' + confMatch[1] + '%</div>';
              html += '</div>';
            }
            
            if (uncertaintyMatch) {
              html += '<div style="background:var(--bg);padding:12px;border-radius:8px;border:1px solid var(--bord);">';
              html += '<div style="color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">Uncertainty (CEP68)</div>';
              html += '<div style="color:var(--txt);font-weight:700;font-size:18px;">±' + uncertaintyMatch[1] + 'm</div>';
              html += '</div>';
            }
            
            html += '</div>';
            
            if (methodMatch) {
              html += '<div style="padding:10px;background:var(--bg);border-left:3px solid var(--acc);border-radius:4px;font-size:11px;color:var(--mut);margin-bottom:12px;">';
              html += '<span style="font-weight:600;color:var(--txt);">Method:</span> ' + methodMatch[1];
              html += '</div>';
            }
            
            const mapsUrl = 'https://www.google.com/maps?q=' + latMatch[1] + ',' + lonMatch[1];
            html += '<a href="' + mapsUrl + '" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 20px;background:var(--acc);border:2px solid var(--acc);border-radius:8px;color:#fff;text-decoration:none;font-weight:600;font-size:13px;transition:all 0.2s;box-shadow:var(--glow);">';
            html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
            html += 'Open in Google Maps';
            html += '</a>';
          }
          
          html += '</div>';
        }
        html += '</div>';
        return html;
      }

      function parseRandomizationResults(text) {
        const headerMatch = text.match(/Active Sessions: (\d+)/);
        const identitiesMatch = text.match(/Device Identities: (\d+)/);

        let html = '<div style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
        html += '<div style="font-size:13px;color:var(--txt);margin-bottom:10px;font-weight:600;letter-spacing:0.5px;">MAC RANDOMIZATION DETECTION</div>';
        html += '<div style="display:flex;gap:20px;font-size:11px;color:var(--mut);">';
        if (headerMatch) html += '<span>Sessions: <strong style="color:var(--txt);">' + headerMatch[1] + '</strong></span>';
        if (identitiesMatch) html += '<span>Identities: <strong style="color:var(--txt);">' + identitiesMatch[1] + '</strong></span>';
        html += '</div></div>';

        const trackBlocks = text.split(/(?=Track ID:)/g).filter(b => b.includes('Track ID'));

        trackBlocks.forEach((block) => {
          const trackMatch       = block.match(/Track ID:\s*([^\n]+)/);
          const typeMatch        = block.match(/Type:\s*([^\n]+)/);
          const nameMatch        = block.match(/Name:\s*([^\n]+)/);
          const ssidMatch        = block.match(/SSID:\s*([^\n]+)/);
          const rssiMatch        = block.match(/RSSI: avg ([-\d]+) dBm\s+min ([-\d]+)\s+max ([-\d]+)/);
          const channelMatch     = block.match(/Channel:\s*(\d+)/);
          const probesMatch      = block.match(/Probes:\s*(\d+)/);
          const macsMatch        = block.match(/MACs linked:\s*(\d+)/);
          const confMatch        = block.match(/Confidence:\s*([\d.]+)/);
          const sessionsMatch    = block.match(/Sessions:\s*(\d+)/);
          const intervalConMatch = block.match(/Interval consistency:\s*([\d.]+)/);
          const rssiConMatch     = block.match(/RSSI consistency:\s*([\d.]+)/);
          const channelsMatch    = block.match(/Channels:\s*(\d+)/);
          const channelSeqMatch  = block.match(/Channel sequence:\s*(.+)/);
          const seqTrackMatch    = block.match(/Sequence tracking:\s*(.+)/);
          const firstSeenMatch   = block.match(/First seen:\s*(\d+)s ago/);
          const lastSeenMatch    = block.match(/Last seen:\s*(\d+)s ago/);
          const realMacMatch     = block.match(/Real MAC:\s*([A-F0-9:]+)/);
          const vendorMatch      = block.match(/Vendor:\s*([^\n]+)/);
          const mfrDataMatch     = block.match(/Mfr data:\s*([^\n]+)/);
          const macsListMatch    = block.match(/MACs:\s*(.+)/);

          if (!trackMatch) return;

          const trackId  = trackMatch[1].trim();
          const isBLE    = typeMatch && typeMatch[1].trim() === 'BLE';
          const deviceType = isBLE ? 'BLE' : 'WiFi';
          const macCount = macsMatch ? macsMatch[1] : '0';
          const confidence = confMatch ? (parseFloat(confMatch[1]) * 100).toFixed(0) : '0';

          const anchorMacMatch = block.match(/Anchor MAC:\s*([A-F0-9:]+)/);
          const anchorMac = anchorMacMatch ? anchorMacMatch[1] : (macsListMatch ? macsListMatch[1].split(',')[0].trim() : '');

          const avgRssi = rssiMatch ? parseInt(rssiMatch[1]) : null;
          const rssiColor = avgRssi !== null
            ? (avgRssi >= -50 ? 'var(--succ)' : avgRssi >= -70 ? 'var(--warn)' : 'var(--dang)')
            : 'var(--mut)';

          const confVal = parseInt(confidence);
          const confColor = confVal >= 75 ? 'var(--succ)' : confVal >= 50 ? 'var(--warn)' : 'var(--dang)';

          html += '<details data-type="' + deviceType + '" style="background:var(--surf);border:1px solid var(--bord);border-radius:6px;margin-bottom:10px;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'var(--acc)\'" onmouseout="this.style.borderColor=\'var(--bord)\'">';
          html += '<summary style="padding:14px;cursor:pointer;user-select:none;list-style:none;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:nowrap;">';
          html += '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;flex-wrap:wrap;">';
          if (anchorMac) html += '<span style="font-family:monospace;font-size:11px;color:var(--acc);font-weight:600;white-space:nowrap;">' + anchorMac + '</span>';
          html += '<span style="background:' + (isBLE ? 'var(--c-ble-bg)' : 'var(--c-wifi-bg)') + ';color:' + (isBLE ? 'var(--c-ble)' : 'var(--c-wifi)') + ';padding:2px 7px;border-radius:3px;font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;">' + deviceType + '</span>';
          if (nameMatch) html += '<span style="color:var(--txt);font-size:11px;font-weight:500;white-space:nowrap;">' + nameMatch[1].trim() + '</span>';
          if (ssidMatch) html += '<span style="color:var(--acc);font-size:10px;white-space:nowrap;">&quot;' + ssidMatch[1].trim() + '&quot;</span>';
          if (vendorMatch) html += '<span style="color:var(--mut);font-size:10px;white-space:nowrap;">' + vendorMatch[1].trim() + '</span>';
          html += '<span style="color:var(--mut);font-size:10px;white-space:nowrap;">' + macCount + ' MAC' + (macCount !== '1' ? 's' : '') + '</span>';
          html += '</div>';
          html += '<div style="display:flex;align-items:center;gap:14px;flex-shrink:0;">';
          if (avgRssi !== null) {
            html += '<div style="text-align:right;">';
            html += '<div style="font-size:8px;color:var(--mut);text-transform:uppercase;letter-spacing:0.5px;">RSSI</div>';
            html += '<div style="font-size:13px;color:' + rssiColor + ';font-weight:700;">' + avgRssi + '<span style="font-size:9px;margin-left:1px;">dBm</span></div>';
            html += '</div>';
          }
          html += '<div style="text-align:right;">';
          html += '<div style="font-size:8px;color:var(--mut);text-transform:uppercase;letter-spacing:0.5px;">Conf</div>';
          html += '<div style="font-size:13px;color:' + confColor + ';font-weight:700;">' + confidence + '<span style="font-size:9px;">%</span></div>';
          html += '</div>';
          html += '<span style="color:var(--mut);font-size:18px;">▶</span>';
          html += '</div></summary>';

          html += '<div style="padding:0 14px 14px 14px;border-top:1px solid var(--bord);">';
          html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:12px;">';

          if (sessionsMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">SESSIONS</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + sessionsMatch[1] + '</div>';
            html += '</div>';
          }
          if (probesMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">PROBES</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + probesMatch[1] + '</div>';
            html += '</div>';
          }
          if (channelMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">CHANNEL</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + channelMatch[1] + '</div>';
            html += '</div>';
          }
          if (rssiMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">RSSI min/avg/max</div>';
            html += '<div style="font-size:11px;color:' + rssiColor + ';font-weight:600;">' + rssiMatch[2] + ' / ' + rssiMatch[1] + ' / ' + rssiMatch[3] + ' dBm</div>';
            html += '</div>';
          }
          if (lastSeenMatch) {
            const seenTxt = firstSeenMatch ? firstSeenMatch[1] + 's ago &rarr; ' + lastSeenMatch[1] + 's ago' : lastSeenMatch[1] + 's ago';
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">SEEN</div>';
            html += '<div style="font-size:10px;color:var(--txt);font-weight:600;">' + seenTxt + '</div>';
            html += '</div>';
          }
          if (intervalConMatch) {
            const pct = (parseFloat(intervalConMatch[1]) * 100).toFixed(0);
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">INTERVAL CONSISTENCY</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + pct + '%</div>';
            html += '</div>';
          }
          if (rssiConMatch) {
            const pct = (parseFloat(rssiConMatch[1]) * 100).toFixed(0);
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">RSSI STABILITY</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + pct + '%</div>';
            html += '</div>';
          }
          if (channelsMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">UNIQUE CHANNELS</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + channelsMatch[1] + '</div>';
            html += '</div>';
          }
          if (realMacMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--dang);">';
            html += '<div style="font-size:8px;color:var(--dang);margin-bottom:3px;">REAL MAC LEAKED</div>';
            html += '<div style="font-size:10px;color:var(--dang);font-family:monospace;font-weight:600;">' + realMacMatch[1] + '</div>';
            html += '</div>';
          }
          html += '</div>';

          if (channelSeqMatch) {
            html += '<div style="margin-top:10px;padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:4px;">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">CHANNEL SEQUENCE</div>';
            html += '<div style="font-size:10px;color:var(--txt);font-family:monospace;">' + channelSeqMatch[1].trim() + '</div>';
            html += '</div>';
          }
          if (seqTrackMatch) {
            html += '<div style="margin-top:6px;padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:4px;">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">SEQUENCE TRACKING</div>';
            html += '<div style="font-size:10px;color:var(--txt);font-family:monospace;">' + seqTrackMatch[1].trim() + '</div>';
            html += '</div>';
          }
          if (vendorMatch || mfrDataMatch) {
            html += '<div style="margin-top:6px;padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:4px;">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">MANUFACTURER</div>';
            if (vendorMatch) html += '<div style="font-size:11px;color:var(--txt);font-weight:600;">' + vendorMatch[1].trim() + '</div>';
            if (mfrDataMatch) html += '<div style="font-size:9px;color:var(--mut);font-family:monospace;margin-top:2px;">' + mfrDataMatch[1].trim() + '</div>';
            html += '</div>';
          }

          html += '<div style="margin-top:10px;padding:8px;background:var(--bg);border:1px solid var(--succ);border-radius:4px;">';
          html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">TRACK ID</div>';
          html += '<div style="font-size:11px;color:var(--acc);font-family:monospace;font-weight:600;">' + trackId + '</div>';
          html += '</div>';

          if (macsListMatch) {
            const macsList = macsListMatch[1];
            const moreMatch = macsList.match(/\(\+(\d+) more\)/);
            const cleanMacs = macsList.replace(/\s*\(\+\d+ more\)/, '');
            const macs = cleanMacs.split(',').map(m => m.trim()).filter(m => m.length > 0);
            html += '<details style="margin-top:10px;" open>';
            html += '<summary style="font-size:9px;color:var(--mut);cursor:pointer;padding:6px 0;list-style:none;user-select:none;">MAC ADDRESSES (' + (moreMatch ? macCount : macs.length) + ')</summary>';
            html += '<div style="display:grid;gap:4px;margin-top:6px;">';
            macs.forEach((mac) => {
              const isFirst = mac === anchorMac;
              html += '<div style="background:var(--surf);border:1px solid var(--bord);border-radius:3px;padding:6px 8px;font-family:monospace;font-size:10px;color:' + (isFirst ? 'var(--acc)' : 'var(--mut)') + ';display:flex;justify-content:space-between;align-items:center;">';
              html += '<span>' + mac + '</span>';
              if (isFirst) html += '<span style="font-size:7px;padding:2px 5px;background:var(--bg);border:1px solid var(--succ);border-radius:2px;color:var(--succ);font-weight:600;">ANCHOR</span>';
              html += '</div>';
            });
            if (moreMatch) html += '<div style="padding:6px;text-align:center;color:var(--mut);font-size:10px;font-style:italic;">+ ' + moreMatch[1] + ' more</div>';
            html += '</div></details>';
          }

          html += '</div></details>';
        });

        return html;
      }

      function toggleTrackCollapse(cardId) {
        const content = document.getElementById(cardId + 'Content');
        const icon = document.getElementById(cardId + 'Icon');
        
        if (content.style.display === 'none') {
          content.style.display = 'block';
          icon.style.transform = 'rotate(0deg)';
          icon.textContent = '▼';
        } else {
          content.style.display = 'none';
          icon.style.transform = 'rotate(-90deg)';
          icon.textContent = '▶';
        }
      }

      function parseBaselineResults(text) {
        function makeDeviceCard(type, mac, rssi, channel, name) {
          const typeColor = type === 'BLE' ? 'var(--c-ble)' : 'var(--acc)';
          let c = '<div class="device-card" data-type="' + type + '" data-channel="' + (channel || '0') + '" style="margin-bottom:10px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
          c += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:6px;">';
          c += '<div>';
          c += '<div style="font-family:monospace;font-size:13px;color:var(--txt);margin-bottom:4px;">' + mac + '</div>';
          if (name && name !== 'Unknown') c += '<div style="font-size:12px;color:' + typeColor + ';margin-bottom:2px;">Name: <strong>' + name + '</strong></div>';
          c += '<div style="font-size:11px;color:' + typeColor + ';">Type: <strong>' + type + '</strong></div>';
          c += '</div>';
          c += '<div style="text-align:right;">';
          c += '<div style="font-size:12px;color:' + rssiColorFor(rssi) + ';font-weight:600;">RSSI: ' + rssi + ' dBm</div>';
          if (channel) c += '<div style="font-size:11px;color:var(--mut);margin-top:2px;">CH: ' + channel + '</div>';
          c += '</div></div></div>';
          return c;
        }

        let html = '';

        var isEstablishing = text.includes('Baseline not yet established');
        if (isEstablishing) {
          const devSection = text.split('=== BASELINE DEVICES (Cached in RAM) ===')[1];
          const deviceLines = devSection ? devSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/)) : [];
          if (deviceLines.length === 0) {
            return '<div style="padding:20px;text-align:center;color:var(--mut);font-size:13px;">Cataloging devices...</div>';
          }
          html += '<div class="baseline-marker" style="display:none;"></div>';
          deviceLines.forEach(line => {
            const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:[-\d]+dBm\s+Max:[-\d]+dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
            if (m) html += makeDeviceCard(m[1], m[2], m[3], m[5], m[6]);
          });
          return html;
        }

        const anomalyCountMatch = text.match(/Total anomalies: (\d+)/);
        const anomalyCount = anomalyCountMatch ? parseInt(anomalyCountMatch[1]) : 0;

        if (anomalyCount > 0) {
          html += '<div style="margin-bottom:14px;padding:12px 16px;background:var(--surf);border:1px solid var(--dang);border-radius:8px;display:flex;align-items:center;gap:12px;">';
          html += '<div style="font-size:26px;font-weight:bold;color:var(--dang);">' + anomalyCount + '</div>';
          html += '<div style="font-size:13px;color:var(--mut);">anomal' + (anomalyCount === 1 ? 'y' : 'ies') + ' detected</div>';
          html += '</div>';

          const anomalySection = text.split('=== ANOMALIES DETECTED ===')[1];
          if (anomalySection) {
            anomalySection.split('\n').filter(l => l.trim() && !l.includes('Total anomalies')).forEach(line => {
              const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI:([-\d]+)dBm(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?\s+-\s+(.+)$/);
              if (!m) return;
              const [_, type, mac, rssi, channel, name, reason] = m;
              const typeColor = type === 'BLE' ? 'var(--c-ble)' : 'var(--acc)';
              html += '<div class="device-card" data-type="' + type + '" data-channel="' + (channel || '0') + '" style="background:var(--surf);padding:14px;border-radius:8px;border:1px solid var(--warn);margin-bottom:10px;">';
              html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:8px;">';
              html += '<div style="font-family:monospace;font-size:14px;color:var(--txt);">' + mac + '</div>';
              html += '<span style="background:' + typeColor + ';color:#000;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:bold;">' + type + '</span>';
              html += '</div>';
              html += '<div style="display:flex;gap:16px;font-size:12px;color:var(--mut);margin-bottom:10px;flex-wrap:wrap;">';
              html += '<span>RSSI: <strong style="color:' + rssiColorFor(rssi) + ';">' + rssi + ' dBm</strong></span>';
              if (channel) html += '<span>CH: <strong style="color:var(--txt);">' + channel + '</strong></span>';
              if (name) html += '<span>Name: <strong style="color:var(--txt);">' + name + '</strong></span>';
              html += '</div>';
              html += '<div style="padding:8px 10px;background:var(--bg);border:1px solid var(--bord);border-left:3px solid var(--warn);border-radius:4px;font-size:12px;color:var(--warn);">' + reason + '</div>';
              html += '</div>';
            });
          }
        } else {
          html += '<div style="padding:20px;text-align:center;color:var(--mut);font-size:13px;">No anomalies detected</div>';
        }

        const baselineSection = text.split('=== BASELINE DEVICES (Cached in RAM) ===')[1]?.split('===')[0];
        if (baselineSection) {
          const deviceLines = baselineSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/));
          if (deviceLines.length > 0) {
            html += '<details style="margin-top:14px;">';
            html += '<summary style="cursor:pointer;color:var(--acc);user-select:none;padding:8px 0;font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;">';
            html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>';
            html += 'Baseline Devices (' + deviceLines.length + ' cached)';
            html += '</summary>';
            html += '<div style="margin-top:10px;">';
            deviceLines.forEach(line => {
              const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:[-\d]+dBm\s+Max:[-\d]+dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
              if (m) html += makeDeviceCard(m[1], m[2], m[3], m[5], m[6]);
            });
            html += '</div></details>';
          }
        }

        return html;
      }

      function parseDeauthResults(text) {
        let html = '';
        
        const durationMatch = text.match(/Duration: (.+)/);
        const deauthMatch = text.match(/Deauth frames: (\d+)/);
        const disassocMatch = text.match(/Disassoc frames: (\d+)/);
        const totalMatch = text.match(/Total attacks: (\d+)/);
        const targetsMatch = text.match(/Targets attacked: (\d+)/);
        
        html += '<div style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
        html += '<div style="font-size:14px;color:var(--txt);margin-bottom:10px;font-weight:bold;">⚠ Deauth Attack Detection Results</div>';
        html += '<div style="display:flex;gap:20px;font-size:12px;color:var(--mut);flex-wrap:wrap;">';
        if (durationMatch) html += '<span>Duration: <strong style="color:var(--txt);">' + durationMatch[1] + '</strong></span>';
        if (deauthMatch) html += '<span>Deauth: <strong style="color:var(--dang);">' + deauthMatch[1] + '</strong></span>';
        if (disassocMatch) html += '<span>Disassoc: <strong style="color:var(--dang);">' + disassocMatch[1] + '</strong></span>';
        if (totalMatch) html += '<span>Total: <strong style="color:var(--dang);">' + totalMatch[1] + '</strong></span>';
        if (targetsMatch) html += '<span>Targets: <strong style="color:var(--txt);">' + targetsMatch[1] + '</strong></span>';
        html += '</div></div>';
        
        if (text.includes('No attacks detected')) {
          html += '<div style="padding:20px;text-align:center;color:var(--mut);font-size:13px;">No attacks detected</div>';
          return html;
        }
        
        const lines = text.split('\n');
        let currentTarget = null;
        let currentTargetHtml = '';
        let inSourcesList = false;
        
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          
          const targetMatch = line.match(/^([A-F0-9:]+|\[BROADCAST\])\s+Total=(\d+)\s+Broadcast=(\d+)\s+Targeted=(\d+)\s+LastRSSI=([-\d]+)dBm\s+CH=(\d+)/);
          if (targetMatch) {
            if (currentTarget) {
              html += currentTargetHtml + '</div>';
            }
            
            const [_, target, total, broadcast, targeted, rssi, channel] = targetMatch;
            const isBroadcast = target === '[BROADCAST]';
            
            currentTargetHtml = '<div style="background:var(--surf);padding:16px;border-radius:8px;border:1px solid var(--warn);margin-bottom:12px;">';
            currentTargetHtml += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:10px;">';
            currentTargetHtml += '<div style="font-family:monospace;font-size:15px;color:var(--warn);">' + target + '</div>';
            if (isBroadcast) {
              currentTargetHtml += '<span style="background:var(--warn);color:#000;padding:4px 10px;border-radius:4px;font-size:10px;font-weight:bold;">BROADCAST ATTACK</span>';
            }
            currentTargetHtml += '</div>';
            
            currentTargetHtml += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:10px;font-size:12px;">';
            currentTargetHtml += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;">';
            currentTargetHtml += '<div style="color:var(--mut);font-size:10px;margin-bottom:2px;">Total Attacks</div>';
            currentTargetHtml += '<div style="color:var(--dang);font-size:16px;font-weight:bold;">' + total + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;">';
            currentTargetHtml += '<div style="color:var(--mut);font-size:10px;margin-bottom:2px;">Broadcast</div>';
            currentTargetHtml += '<div style="color:var(--dang);font-size:16px;font-weight:bold;">' + broadcast + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;">';
            currentTargetHtml += '<div style="color:var(--mut);font-size:10px;margin-bottom:2px;">Targeted</div>';
            currentTargetHtml += '<div style="color:var(--warn);font-size:16px;font-weight:bold;">' + targeted + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;">';
            currentTargetHtml += '<div style="color:var(--mut);font-size:10px;margin-bottom:2px;">Signal / Channel</div>';
            currentTargetHtml += '<div style="color:var(--txt);font-size:14px;font-weight:bold;">' + rssi + ' dBm / CH' + channel + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '</div>';
            
            currentTargetHtml += '<div style="margin-top:10px;padding:10px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;">';
            currentTargetHtml += '<div style="font-size:11px;color:var(--mut);margin-bottom:8px;font-weight:bold;">Attack Sources:</div>';
            
            currentTarget = target;
            inSourcesList = true;
            continue;
          }
          
          if (inSourcesList && line.trim().startsWith('←')) {
            const sourceMatch = line.match(/← ([A-F0-9:]+) \((\d+)x\)/);
            if (sourceMatch) {
              const [_, source, count] = sourceMatch;
              currentTargetHtml += '<div style="padding:6px;font-family:monospace;font-size:12px;color:var(--txt);border-bottom:1px solid var(--bord);">';
              currentTargetHtml += '<span style="color:var(--warn);">←</span> ' + source + ' <span style="color:var(--mut);">(' + count + ' attacks)</span>';
              currentTargetHtml += '</div>';
            }
          }
          
          if (inSourcesList && line.trim().startsWith('...')) {
            const moreMatch = line.match(/\((\d+) more attackers\)/);
            if (moreMatch) {
              currentTargetHtml += '<div style="padding:8px;text-align:center;color:var(--mut);font-size:11px;">+ ' + moreMatch[1] + ' more attackers</div>';
            }
          }
          
          if (line.trim() === '' && currentTarget) {
            currentTargetHtml += '</div>';
            html += currentTargetHtml;
            currentTarget = null;
            currentTargetHtml = '';
            inSourcesList = false;
          }
        }
        
        if (currentTarget) {
          currentTargetHtml += '</div>';
          html += currentTargetHtml;
        }
        
        const finalMoreMatch = text.match(/\.\.\. \((\d+) more targets\)/);
        if (finalMoreMatch) {
          html += '<div style="padding:12px;text-align:center;color:var(--mut);font-size:12px;border:1px dashed var(--bord);border-radius:6px;">+ ' + finalMoreMatch[1] + ' more targets</div>';
        }
        
        return html;
      }

      function parseDroneResults(text) {
        let html = '';
        
        const totalMatch = text.match(/Total detections: (\d+)/);
        const uniqueMatch = text.match(/Unique drones: (\d+)/);
        
        html += '<div style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
        html += '<div style="font-size:14px;color:var(--txt);margin-bottom:10px;font-weight:bold;">Drone Detection Results</div>';
        html += '<div style="display:flex;gap:20px;font-size:12px;color:var(--mut);">';
        if (totalMatch) html += '<span>Total: <strong style="color:var(--txt);">' + totalMatch[1] + '</strong></span>';
        if (uniqueMatch) html += '<span>Unique: <strong style="color:var(--txt);">' + uniqueMatch[1] + '</strong></span>';
        html += '</div></div>';
        
        const droneBlocks = text.split(/(?=MAC:)/g).filter(b => b.includes('MAC:'));
        droneBlocks.forEach(block => {
          const macMatch = block.match(/MAC: ([A-F0-9:]+)/);
          const uavMatch = block.match(/UAV ID: (.+)/);
          const rssiMatch = block.match(/RSSI: ([-\d]+) dBm/);
          const locMatch = block.match(/Location: ([-\d.]+), ([-\d.]+)/);
          const altMatch = block.match(/Altitude: ([\d.]+)m/);
          const speedMatch = block.match(/Speed: ([\d.]+) m\/s/);
          const opLocMatch = block.match(/Operator Location: ([-\d.]+), ([-\d.]+)/);
          
          if (!macMatch) return;
          
          html += '<div style="background:var(--surf);padding:18px;border-radius:8px;border:1px solid var(--acc);margin-bottom:12px;">';
          html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:10px;">';
          html += '<div style="font-family:monospace;font-size:15px;color:var(--acc);">' + macMatch[1] + '</div>';
          if (rssiMatch) html += '<span style="color:var(--mut);font-size:12px;">RSSI: <strong style="color:var(--txt);">' + rssiMatch[1] + ' dBm</strong></span>';
          html += '</div>';
          
          if (uavMatch) {
            html += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;margin-bottom:8px;font-size:12px;color:var(--acc);">';
            html += 'UAV ID: <strong>' + uavMatch[1] + '</strong>';
            html += '</div>';
          }
          
          if (locMatch) {
            html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;font-size:11px;color:var(--mut);margin-top:8px;">';
            html += '<div>Location: <strong style="color:var(--txt);">' + locMatch[1] + ', ' + locMatch[2] + '</strong></div>';
            if (altMatch) html += '<div>Altitude: <strong style="color:var(--txt);">' + altMatch[1] + 'm</strong></div>';
            if (speedMatch) html += '<div>Speed: <strong style="color:var(--txt);">' + speedMatch[1] + ' m/s</strong></div>';
            html += '</div>';
          }
          
          if (opLocMatch) {
            html += '<div style="margin-top:8px;padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;font-size:11px;color:var(--mut);">';
            html += 'Operator: <strong style="color:var(--txt);">' + opLocMatch[1] + ', ' + opLocMatch[2] + '</strong>';
            html += '</div>';
          }
          
          html += '</div>';
        });
        
        return html;
      }

      function parseProbeResults(text) {
        let html = '';
        savedDevicesLoaded = false;
        const lines = text.split('\n');
        const headerLine = lines[0] || '';
        const statsLine = lines[1] || '';
        const inProgress = headerLine.includes('IN PROGRESS');

        const devMatch = statsLine.match(/Devices:\s*(\d+)/);
        const probeMatch = statsLine.match(/Probes:\s*(\d+)/);
        const ssidMatch = statsLine.match(/SSIDs:\s*(\d+)/);
        const savedMatch = statsLine.match(/Saved:\s*(\d+)/);

        // Stats bar
        html += '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:12px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;align-items:center;">';
        if (inProgress) html += '<span style="color:var(--acc);font-weight:bold;animation:pulse 1.5s ease-in-out infinite;">SCANNING</span>';
        if (devMatch) html += '<span>Devices: <strong>' + devMatch[1] + '</strong></span>';
        if (probeMatch) html += '<span>Probes: <strong>' + probeMatch[1] + '</strong></span>';
        if (ssidMatch) html += '<span>SSIDs: <strong>' + ssidMatch[1] + '</strong></span>';
        html += '</div>';

        // Collapsible saved devices dropdown
        if (savedMatch && parseInt(savedMatch[1]) > 0) {
          html += '<div id="savedDevicesPanel" style="margin-bottom:12px;">';
          html += '<div id="savedDevicesToggle" onclick="toggleSavedDevices()" style="cursor:pointer;padding:8px 12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;display:flex;align-items:center;gap:8px;font-size:11px;color:var(--mut);user-select:none;">';
          html += '<span id="savedDevicesArrow" style="transition:transform 0.2s;display:inline-block;">&#9654;</span>';
          html += '<span>Saved Devices (' + savedMatch[1] + ')</span>';
          html += '</div>';
          html += '<div id="savedDevicesList" style="display:none;margin-top:4px;max-height:300px;overflow-y:auto;border:1px solid var(--bord);border-radius:8px;background:var(--bg);"></div>';
          html += '</div>';
        }

        let deviceLines = [];
        let ssidSection = '';
        let inSsidSection = false;

        for (let i = 2; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          if (line.startsWith('SSIDs seen')) {
            inSsidSection = true;
            continue;
          }
          if (inSsidSection) {
            if (line.startsWith('WiFi') || line.startsWith('BLE')) { inSsidSection = false; }
            else { ssidSection += line + '\n'; continue; }
          }
          if (line.startsWith('WiFi') || line.startsWith('BLE')) {
            deviceLines.push(line);
          }
        }

        // Device cards
        if (deviceLines.length > 0) {
          html += '<div style="display:flex;flex-direction:column;gap:6px;">';

          for (const line of deviceLines) {
            const isKnown = line.includes('[KNOWN:');
            const macM = line.match(/([A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2})/);
            const rssiM = line.match(/RSSI=(-?\d+)dBm/);
            const chM = line.match(/CH=(\d+)/);
            const wildcard = line.includes('(wildcard)');
            const countM = line.match(/\sx(\d+)/);

            // Parse vendor: word after CH=N
            let vendor = '';
            const vendorM = line.match(/CH=\d+\s+(\w+)/);
            if (vendorM && vendorM[1] !== 'probes' && vendorM[1] !== 'AP') vendor = vendorM[1];

            // Parse all SSIDs from probes:~"Ghost","Local" format (~prefix = ghost network)
            let ssids = [];
            const probesM = line.match(/probes:((?:~?"[^"]*",?)+)/);
            if (probesM) {
              const matches = probesM[1].matchAll(/(~?)"([^"]*)"/g);
              for (const m of matches) ssids.push({name: m[2], ghost: m[1] === '~'});
            }

            // Parse responding AP (SSID + optional BSSID)
            const apM = line.match(/AP="([^"]*)"/);
            const apBssidM = line.match(/APBSSID=([A-Fa-f0-9:]+)/);

            // Parse KNOWN history
            const knownM = line.match(/\[KNOWN:seen=(\d+)\s+sessions=(\d+)\s+last=([^\]]+)\]/);

            // Card styling
            let borderColor = 'var(--bord)';
            let bgColor = 'var(--surf)';
            if (isKnown) { borderColor = 'var(--c-known)'; bgColor = 'var(--accbg)'; }

            html += '<div style="padding:8px 12px;background:' + bgColor + ';border:1px solid ' + borderColor + ';border-radius:8px;font-size:11px;">';

            // Top row: MAC + vendor + status badges
            html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">';
            html += '<span style="font-family:monospace;font-weight:bold;color:var(--txt);">' + (macM ? macM[1] : '') + '</span>';
            if (vendor === 'Randomized') {
              html += '<span style="background:var(--c-rand);color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;">RAND</span>';
            } else if (vendor) {
              html += '<span style="color:var(--mut);">' + vendor + '</span>';
            }
            html += '<span style="color:var(--mut);">' + (rssiM ? rssiM[1] + 'dBm' : '') + '</span>';
            if (chM) html += '<span style="color:var(--mut);">CH' + chM[1] + '</span>';
            if (countM && parseInt(countM[1]) > 1) html += '<span style="color:var(--acc);">x' + countM[1] + '</span>';
            if (isKnown) html += '<span style="background:var(--c-known);color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;">KNOWN</span>';
            html += '</div>';

            // Second row: SSIDs this device is probing for
            if (ssids.length > 0) {
              html += '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px;">';
              html += '<span style="color:var(--mut);font-size:10px;">Probing:</span>';
              for (const s of ssids) {
                if (s.ghost) {
                  html += '<span data-ssid="' + s.name + '" title="Not nearby - saved/home network" style="background:var(--c-away-bg);border:1px dashed var(--c-away);padding:1px 6px;border-radius:4px;font-size:10px;color:var(--c-away);">' + s.name + ' <sup style="font-size:8px;opacity:0.7;">away</sup></span>';
                } else {
                  html += '<span data-ssid="' + s.name + '" style="background:var(--bg);border:1px solid var(--bord);padding:1px 6px;border-radius:4px;font-size:10px;color:var(--txt);">' + s.name + '</span>';
                }
              }
              html += '</div>';
            } else if (wildcard) {
              html += '<div style="margin-top:4px;color:var(--mut);font-size:10px;font-style:italic;">Broadcast probe (no specific SSID)</div>';
            }

            // Third row: Responding AP (from probe response intelligence)
            if (apM) {
              html += '<div data-ap-ssid="' + apM[1] + '" style="margin-top:3px;font-size:10px;color:var(--c-ap);">AP responded: <strong>' + apM[1] + '</strong>';
              if (apBssidM) html += ' <span style="color:var(--mut);font-family:monospace;">(' + apBssidM[1] + ')</span>';
              html += '</div>';
            }

            // Fourth row: Historical intelligence
            if (knownM) {
              html += '<div style="margin-top:3px;font-size:10px;color:var(--c-known);">Seen ' + knownM[1] + ' times across ' + knownM[2] + ' sessions, last: ' + knownM[3] + '</div>';
            }

            html += '</div>';
          }
          html += '</div>';
        }

        // SSID intelligence panel
        if (ssidSection.trim()) {
          const ssidLines = ssidSection.trim().split('\n');
          let nearbyCount = 0, ghostCount = 0;
          for (const sl of ssidLines) {
            if (sl.trim().startsWith('~')) ghostCount++; else nearbyCount++;
          }
          html += '<div style="margin-top:12px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
          html += '<div style="font-weight:bold;color:var(--acc);margin-bottom:8px;">Network Intelligence (' + ssidLines.length + ' SSIDs';
          if (ghostCount > 0) html += ', ' + ghostCount + ' away';
          html += ')</div>';
          html += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
          for (const sl of ssidLines) {
            const trimmed = sl.trim();
            const isGhost = trimmed.startsWith('~');
            const sm = trimmed.match(/~?"([^"]+)"\s*\((\d+)\s+device/);
            if (sm) {
              const devCount = parseInt(sm[2]);
              const macsM = sl.match(/\[([^\]]+)\]/);
              let tooltip = sm[1] + ' (' + devCount + ' device' + (devCount > 1 ? 's' : '') + ')';
              if (isGhost) tooltip += ' - not nearby, saved/home network';
              if (macsM) tooltip += ': ' + macsM[1];
              if (isGhost) {
                html += '<span data-ssid="' + sm[1] + '" title="' + tooltip + '" style="background:var(--c-away-bg);color:var(--c-away);border:1px dashed var(--c-away);padding:3px 10px;border-radius:12px;font-size:11px;cursor:default;">' + sm[1] + ' <sup>' + sm[2] + '</sup> <span style="font-size:8px;opacity:0.7;">away</span></span>';
              } else {
                const opacity = Math.min(1, 0.4 + devCount * 0.2);
                html += '<span data-ssid="' + sm[1] + '" title="' + tooltip + '" style="background:rgba(46,204,113,' + opacity + ');color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:' + (devCount > 2 ? 'bold' : 'normal') + ';cursor:default;">' + sm[1] + ' <sup>' + sm[2] + '</sup></span>';
              }
            }
          }
          html += '</div></div>';
        }

        return html;
      }

      let savedDevicesLoaded = false;
      let savedDevicesOpen = false;
      function toggleSavedDevices() {
        const list = document.getElementById('savedDevicesList');
        const arrow = document.getElementById('savedDevicesArrow');
        if (!list || !arrow) return;
        savedDevicesOpen = !savedDevicesOpen;
        list.style.display = savedDevicesOpen ? 'block' : 'none';
        arrow.style.transform = savedDevicesOpen ? 'rotate(90deg)' : '';
        if (savedDevicesOpen && !savedDevicesLoaded) {
          list.innerHTML = '<div style="padding:12px;color:var(--mut);font-size:11px;">Loading...</div>';
          fetch('/api/probedb').then(r => r.json()).then(devices => {
            savedDevicesLoaded = true;
            if (!devices.length) {
              list.innerHTML = '<div style="padding:12px;color:var(--mut);font-size:11px;">No saved devices</div>';
              return;
            }
            let h = '';
            devices.sort((a, b) => b.last - a.last);
            for (const d of devices) {
              const isRand = d.rand;
              const border = isRand ? 'var(--c-rand)' : 'var(--bord)';
              h += '<div style="padding:6px 10px;border-bottom:1px solid var(--bord);font-size:11px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;">';
              h += '<span style="font-family:monospace;font-weight:bold;color:var(--txt);min-width:140px;">' + d.mac + '</span>';
              if (isRand) {
                h += '<span style="background:var(--c-rand);color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;">RAND</span>';
              } else if (d.vendor) {
                h += '<span style="color:var(--mut);font-size:10px;">' + d.vendor + '</span>';
              }
              h += '<span style="color:var(--mut);font-size:10px;">' + d.rssi + 'dBm</span>';
              h += '<span style="color:var(--mut);font-size:10px;">x' + d.seen + '</span>';
              h += '<span style="color:var(--mut);font-size:10px;">' + d.sessions + ' sess</span>';
              if (d.ssids && d.ssids.length > 0) {
                for (const s of d.ssids) {
                  h += '<span style="background:var(--surf);border:1px solid var(--bord);padding:1px 5px;border-radius:3px;font-size:9px;color:var(--txt);">' + s + '</span>';
                }
              }
              h += '</div>';
            }
            list.innerHTML = h;
          }).catch(() => {
            list.innerHTML = '<div style="padding:12px;color:var(--c-err);font-size:11px;">Failed to load</div>';
          });
        }
      }

      function parseDeviceScanResults(text) {
        let html = '';
        
        const modeMatch = text.match(/Mode: ([^\s]+)/);
        const durationMatch = text.match(/Duration: ([^\n]+)/);
        const hitsMatch = text.match(/Target Hits: (\d+)/);
        const uniqueMatch = text.match(/Unique devices: (\d+)/);
        
        if (modeMatch || durationMatch || hitsMatch || uniqueMatch) {
          html += '<div id="deviceScanHeader" style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
          html += '<div style="font-size:14px;color:var(--txt);margin-bottom:8px;font-weight:bold;">Device Discovery Scan Results</div>';
          html += '<div style="display:flex;gap:20px;font-size:12px;color:var(--mut);flex-wrap:wrap;">';
          if (modeMatch) html += '<span>Mode: <strong style="color:var(--txt);">' + modeMatch[1] + '</strong></span>';
          if (durationMatch) html += '<span>Duration: <strong style="color:var(--txt);">' + durationMatch[1] + '</strong></span>';
          if (hitsMatch) html += '<span>Target Hits: <strong style="color:var(--txt);">' + hitsMatch[1] + '</strong></span>';
          if (uniqueMatch) html += '<span>Unique: <strong style="color:var(--txt);">' + uniqueMatch[1] + '</strong></span>';
          html += '</div></div>';
        }
        
        const lines = text.split('\n');
        let inProbeSection = false;
        let probeLines = [];

        lines.forEach(line => {
          if (line.startsWith('--- Probe Intelligence')) {
            inProbeSection = true;
            return;
          }

          if (inProbeSection) {
            if (line.trim().length > 0) probeLines.push(line.trim());
            return;
          }

          const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI=([-\d]+)dBm(?:\s+CH=(\d+))?(?:\s+"([^"]*)")?/);
          if (!match) return;

          const type = match[1];
          const mac = match[2];
          const rssi = match[3];
          const channel = match[4] || '';
          const name = match[5] || 'Unknown';

          const typeColor = type === 'BLE' ? 'var(--c-ble)' : 'var(--acc)';
          const rssiColor = rssiColorFor(rssi);

          html += '<div class="device-card" data-type="' + type + '" data-channel="' + (channel || '0') + '" style="margin-bottom:10px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
          html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:6px;">';
          html += '<div>';
          html += '<div style="font-family:monospace;font-size:13px;color:var(--txt);margin-bottom:4px;">' + mac + '</div>';
          html += '<div style="font-size:12px;color:' + typeColor + ';margin-bottom:2px;">Name: <strong>' + name + '</strong></div>';
          html += '<div style="font-size:11px;color:' + typeColor + ';">Type: <strong>' + type + '</strong></div>';
          html += '</div>';
          html += '<div style="text-align:right;">';
          html += '<div style="font-size:12px;color:' + rssiColor + ';font-weight:600;">RSSI: ' + rssi + ' dBm</div>';
          if (channel) html += '<div style="font-size:11px;color:var(--mut);margin-top:2px;">CH: ' + channel + '</div>';
          html += '</div>';
          html += '</div>';
          html += '</div>';
        });

        // Render probe intelligence section if present
        if (probeLines.length > 0) {
          html += '<div style="margin-top:16px;padding:10px;background:var(--surf);border:1px solid var(--c-rand);border-radius:8px;">';
          html += '<div style="font-weight:bold;color:var(--c-rand);margin-bottom:8px;">Probe Intelligence (' + probeLines.length + ' probing devices)</div>';
          html += '<div style="display:flex;flex-direction:column;gap:4px;">';
          for (const pl of probeLines) {
            const macM = pl.match(/^([A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2})/);
            const isRand = pl.includes(' Rand');
            const probesM = pl.match(/probes:((?:~?"[^"]*",?)+)/);
            const apM = pl.match(/AP="([^"]*)"/);
            const apBssidM = pl.match(/APBSSID=([A-Fa-f0-9:]+)/);
            const countM = pl.match(/x(\d+)$/);
            const vendorM = pl.match(/^[A-F0-9:]+\s+(\w+)/);
            const vendor = vendorM && vendorM[1] !== 'Rand' && vendorM[1] !== 'probes' && vendorM[1] !== 'AP' ? vendorM[1] : '';

            html += '<div style="padding:6px 10px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;font-size:11px;">';
            html += '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">';
            if (macM) html += '<span style="font-family:monospace;font-weight:bold;">' + macM[1] + '</span>';
            if (isRand) html += '<span style="background:var(--c-rand);color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;">RAND</span>';
            else if (vendor) html += '<span style="color:var(--mut);">' + vendor + '</span>';
            if (countM) html += '<span style="color:var(--acc);">x' + countM[1] + '</span>';
            html += '</div>';
            if (probesM) {
              html += '<div style="margin-top:3px;display:flex;flex-wrap:wrap;gap:3px;">';
              html += '<span style="color:var(--mut);font-size:9px;">Probing:</span>';
              const ssids = probesM[1].matchAll(/(~?)"([^"]*)"/g);
              for (const s of ssids) {
                const ghost = s[1] === '~';
                if (ghost) {
                  html += '<span data-ssid="' + s[2] + '" title="Not nearby - saved/home network" style="background:var(--c-away-bg);border:1px dashed var(--c-away);padding:1px 5px;border-radius:3px;font-size:9px;color:var(--c-away);">' + s[2] + ' <sup style="font-size:7px;opacity:0.7;">away</sup></span>';
                } else {
                  html += '<span data-ssid="' + s[2] + '" style="background:var(--surf);border:1px solid var(--bord);padding:1px 5px;border-radius:3px;font-size:9px;">' + s[2] + '</span>';
                }
              }
              html += '</div>';
            }
            if (apM) {
              html += '<div data-ap-ssid="' + apM[1] + '" style="margin-top:2px;font-size:9px;color:var(--c-ap);">AP responded: <strong>' + apM[1] + '</strong>';
              if (apBssidM) html += ' <span style="color:var(--mut);font-family:monospace;">(' + apBssidM[1] + ')</span>';
              html += '</div>';
            }
            html += '</div>';
          }
          html += '</div></div>';
        }

        return html;
      }

      let terminalWs = null;
      let terminalVisible = false;
      let terminalDragging = false;
      let terminalDragOffset = {x: 0, y: 0};

      function initTerminal() {
        const toggle = document.getElementById('terminalToggle');
        const window = document.getElementById('terminalWindow');
        
        if (!toggle || !window) {
          console.log('[TERMINAL] Elements not found, feature disabled');
          return;
        }
        
        const close = document.getElementById('terminalClose');
        const header = document.getElementById('terminalHeader');
        const content = document.getElementById('terminalContent');
        
        toggle.addEventListener('click', () => {
          terminalVisible = !terminalVisible;
          if (terminalVisible) {
            window.classList.add('visible');
            toggle.classList.add('active');
            connectTerminal();
          } else {
            window.classList.remove('visible');
            toggle.classList.remove('active');
            if (terminalWs) {
              terminalWs.close();
              terminalWs = null;
            }
          }
        });
        
        close.addEventListener('click', () => {
          terminalVisible = false;
          window.classList.remove('visible');
          toggle.classList.remove('active');
          if (terminalWs) {
            terminalWs.close();
            terminalWs = null;
          }
        });
        
        header.addEventListener('mousedown', (e) => {
          terminalDragging = true;
          terminalDragOffset.x = e.clientX - window.offsetLeft;
          terminalDragOffset.y = e.clientY - window.offsetTop;
          window.style.position = 'fixed';
        });
        
        document.addEventListener('mousemove', (e) => {
          if (!terminalDragging) return;
          const x = e.clientX - terminalDragOffset.x;
          const y = e.clientY - terminalDragOffset.y;
          window.style.left = Math.max(0, Math.min(x, window.innerWidth - window.offsetWidth)) + 'px';
          window.style.top = Math.max(0, Math.min(y, window.innerHeight - window.offsetHeight)) + 'px';
          window.style.right = 'auto';
          window.style.bottom = 'auto';
        });
        
        document.addEventListener('mouseup', () => {
          terminalDragging = false;
        });
      }

      function connectTerminal() {
        if (terminalWs) return;
        
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        terminalWs = new WebSocket(protocol + '//' + location.host + '/terminal');
        
        terminalWs.onopen = () => {
          console.log('[TERMINAL] Connected');
        };
        
        terminalWs.onmessage = (event) => {
          const content = document.getElementById('terminalContent');
          const line = document.createElement('div');
          line.className = 'terminal-line';
          
          if (event.data.includes('[TX]')) {
            line.classList.add('tx');
          } else if (event.data.includes('[RX]')) {
            line.classList.add('rx');
          }
          
          line.textContent = event.data;
          content.appendChild(line);
          
          while (content.children.length > 500) {
            content.removeChild(content.firstChild);
          }
          
          content.scrollTop = content.scrollHeight;
        };
        
        terminalWs.onerror = (error) => {
          console.error('[TERMINAL] Error:', error);
        };
        
        terminalWs.onclose = () => {
          console.log('[TERMINAL] Disconnected');
          terminalWs = null;
          if (terminalVisible) {
            setTimeout(connectTerminal, 2000);
          }
        };
      }

      function resetRandomizationDetection() {
        if (!confirm('Reset all randomization detection data?')) return;
        
        fetch('/randomization/reset', { method: 'POST' })
          .then(r => r.text())
          .then(data => {
            toast(data, 'success');
          })
          .catch(err => toast('Error: ' + err, 'error'));
      }

      function toast(msg, type = 'info') {
        const wrap = document.getElementById('toast');
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        const typeLabels = {
          'success': 'SUCCESS',
          'error': 'ERROR',
          'warning': 'WARNING',
          'info': 'INFO'
        };
        el.innerHTML = `<div class="toast-content"><div class="toast-title">[${typeLabels[type] || typeLabels.info}]</div><div class="toast-message">${msg}</div></div>`;
        wrap.appendChild(el);
        requestAnimationFrame(() => el.classList.add('show'));
        const duration = type === 'success' ? 10000 : (type === 'error' ? 8000 : 4000);
        setTimeout(() => {
          el.classList.remove('show');
          setTimeout(() => wrap.removeChild(el), 300);
        }, duration);
      }
      
      function updateAutoEraseStatus() {
        fetch('/config/autoerase').then(response => response.json()).then(data => {
          const statusDiv = document.getElementById('autoEraseStatus');
          let statusText = '';
          let statusClass = '';

          // Sync checkbox with server state
          const checkbox = document.getElementById('autoEraseEnabled');
          if (checkbox) {
            checkbox.checked = data.enabled;
          }

          if (!data.enabled) {
            statusText = 'DISABLED - Manual erase only';
            statusClass = 'status-disabled';
          } else if (data.inSetupMode) {
            const elapsed = data.currentTime - data.setupStartTime;
            const remaining = Math.max(0, Math.floor((data.setupDelay - elapsed) / 1000));
            statusText = `SETUP MODE - Activating in ${remaining}s`;
            statusClass = 'status-setup';
          } else if (data.tamperActive) {
            statusText = 'TAMPER DETECTED - Auto-erase in progress';
            statusClass = 'status-danger';
          } else {
            statusText = 'ACTIVE - Monitoring for tampering';
            statusClass = 'status-active';
          }
          statusDiv.textContent = statusText;
          statusDiv.className = statusClass;
        }).catch(error => {
          document.getElementById('autoEraseStatus').textContent = 'Status unavailable';
        });
      }
      
      async function cancelErase() {
        const response = await fetch('/erase/cancel', { method: 'POST' });
        const data = await response.text();
        document.getElementById('eraseStatus').innerHTML = '<pre>' + data + '</pre>';
      }
      
      function pollEraseStatus() {
        const poll = setInterval(() => {
          fetch('/erase/status').then(response => response.text()).then(status => {
            document.getElementById('eraseStatus').innerHTML = '<pre>Status: ' + status + '</pre>';
            if (status === 'COMPLETED') {
              clearInterval(poll);
              // Show persistent success message
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:var(--c-ok);font-weight:bold;">SUCCESS: Secure erase completed successfully</pre>';
              toast('All data has been securely destroyed', 'success');
              // Clear the form
              document.getElementById('eraseConfirm').value = '';
            } else if (status.startsWith('FAILED')) {
              clearInterval(poll);
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:var(--c-err);font-weight:bold;">FAILED: ' + status + '</pre>';
              toast('Secure erase failed: ' + status, 'error');
            }
          }).catch(error => {
            clearInterval(poll);
            toast('Status check failed: ' + error, 'error');
          });
        }, 1000); // Check every second for faster feedback
      }
      
      function requestErase() {
        const confirm = document.getElementById('eraseConfirm').value;
        if (confirm !== 'WIPE_ALL_DATA') {
          toast('Please type "WIPE_ALL_DATA" exactly to confirm', 'error');
          return;
        }
        if (!window.confirm('FINAL WARNING: This will permanently destroy all data. Are you absolutely sure?')) {
          return;
        }
        toast('Initiating secure erase operation...', 'warning');
        fetch('/erase/request', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `confirm=${encodeURIComponent(confirm)}`
        }).then(response => response.text()).then(data => {
          document.getElementById('eraseStatus').style.display = 'block';
          document.getElementById('eraseStatus').innerHTML = '<pre>' + data + '</pre>';
          toast('Secure erase started', 'info');
          // Start polling for status
          pollEraseStatus();
        }).catch(error => {
          toast('Network error: ' + error, 'error');
        });
      }

      function formatDiagnostics(text) {
        if (!text || text.trim() === '') return '<div style="color:var(--mut);padding:20px;text-align:center;">No data</div>';
        
        const lines = text.trim().split('\n');
        let html = '<div class="stat-grid">';
        
        lines.forEach(line => {
          const parts = line.split(':');
          if (parts.length >= 2) {
            const label = parts[0].trim();
            const value = parts.slice(1).join(':').trim();
            
            html += '<div class="stat-item">';
            html += '<div class="stat-label">' + label + '</div>';
            html += '<div class="stat-value">' + value + '</div>';
            html += '</div>';
          }
        });
        
        html += '</div>';
        return html;
      }

      function formatDiagGrid(text,type){
        if(!text||text.trim()==='')return'<div style="color:var(--mut);text-align:center;padding:20px;">No data</div>';
        let html='<div class="diag-grid">';
        const lines=text.trim().split('\n');
        lines.forEach(line=>{
          const parts=line.split(':');
          if(parts.length<2)return;
          const label=parts[0].trim();
          const value=parts.slice(1).join(':').trim();
          html+='<div class="stat-item">';
          html+='<div class="stat-label">'+label+'</div>';
          html+='<div class="stat-value" style="font-size:14px;">'+value+'</div>';
          html+='</div>';
        });
        html+='</div>';
        return html;
      }

      let tickStart = 0;
      async function tick() {
        if (tickRunning) {
          if (Date.now() - tickStart > 15000) tickRunning = false;
          else return;
        }
        tickRunning = true;
        tickStart = Date.now();
        try {
          const diagResponse = await fetch('/diag').catch(() => null);
          if (!diagResponse) return;
          const diagText = await diagResponse.text();
          const isScanning = diagText.includes('Scanning: yes');
          const isTriActive = diagText.includes('Triangulating: yes');
          radioBusy = isScanning || isTriActive;
          const taskMatch = diagText.match(/Task Type: ([^\n]+)/);
          radioBusyTask = taskMatch ? taskMatch[1].trim() : '';
          const sections = diagText.split('\n');
          meshEnabled = diagText.includes('Mesh: Enabled');
          updateMeshUI();
          const hbMatch = diagText.match(/Heartbeat: \w+ (\d+)min/);
          hbEnabled = diagText.includes('Heartbeat: Enabled');
          if (hbMatch) { const inp = document.getElementById('hbIntervalInput'); if (inp && document.activeElement !== inp) inp.value = hbMatch[1]; }
          updateHbUI();
          vibrationEnabled = diagText.includes('Vibration Broadcasts: Enabled');
          updateVibrationUI();

          // --- System page updates: immediately after /diag, no extra fetches ---
          let hardware = '';
          let network = '';
          sections.forEach(line => {
            if (line.includes('WiFi Frames')) {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('wifiFrames').innerText = match[1];
            }
            if (line.includes('BLE Frames')) {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('bleFrames').innerText = match[1];
            }
            if (line.includes('Devices Found')) {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('totalHits').innerText = match[1];
            }
            if (line.includes('Unique devices') && radioBusyTask !== 'baseline') {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('uniqueDevices').innerText = match[1];
            }
            if (line.includes('ESP32 Temp')) {
              const match = line.match(/([\d.]+)C/);
              if (match) document.getElementById('temperature').innerText = match[1] + 'C';
            }
            if (line.includes('SD Card') || line.includes('GPS') || line.includes('RTC') || line.includes('Vibration')) {
              hardware += line + '\n';
            } else if (line.includes('AP IP') || line.includes('Mesh') || line.includes('WiFi Channels')) {
              network += line + '\n';
            }
          });
          document.getElementById('hardwareDiag').innerHTML = formatDiagGrid(hardware, 'hardware');
          document.getElementById('networkDiag').innerHTML = formatDiagGrid(network, 'network');
          const uptimeMatch = diagText.match(/Up:(\d+):(\d+):(\d+)/);
          if (uptimeMatch) {
            document.getElementById('uptime').innerText = uptimeMatch[1] + ':' + uptimeMatch[2] + ':' + uptimeMatch[3];
          }
          updateStatusIndicators(diagText);

          // --- Optional fetches: only when needed, skip what baseline already handles ---
          const droneActive = diagText.includes('Drone Detection: Active');
          const baselineHandling = !!baselineUpdateInterval;
          const fetchPromises = [];
          if (droneActive) fetchPromises.push(fetch('/drone/status').catch(() => null));
          else fetchPromises.push(Promise.resolve(null));
          if (!baselineHandling && (isScanning || (lastScanningState && !isScanning))) fetchPromises.push(fetch('/results').catch(() => null));
          else fetchPromises.push(Promise.resolve(null));
          const [droneResponse, resultsResponse] = await Promise.all(fetchPromises);
          if (droneResponse) {
            try {
              const droneData = await droneResponse.json();
              document.getElementById('droneStatus').innerText = 'Drone Detection: Active (' + droneData.unique + ' drones)';
              document.getElementById('droneStatus').classList.add('active');
            } catch (e) {}
          }
          if (radioBusyTask === 'baseline' && !baselineHandling) {
            try {
              const bsResp = await fetch('/baseline/stats');
              const bs = await bsResp.json();
              const el = document.getElementById('uniqueDevices');
              const cur = bs.totalDevices;
              if (cur > prevUniqueDevices && prevUniqueDevices > 0) {
                const diff = cur - prevUniqueDevices;
                el.innerHTML = cur + ' <span style="color:var(--succ);font-size:11px;font-weight:normal;">(+' + diff + ' new)</span>';
                el.style.transition = 'color 0.3s';
                el.style.color = 'var(--succ)';
                setTimeout(() => { el.style.color = ''; }, 2000);
              } else {
                el.innerText = cur;
              }
              prevUniqueDevices = cur;
            } catch(e) {}
          }
          const stopAllBtn = document.getElementById('stopAllBtn');
          if (stopAllBtn) {
            stopAllBtn.style.display = isScanning ? 'inline-block' : 'none';
          }
          const resultsElement = document.getElementById('r');
          if (resultsElement && !resultsElement.contains(document.activeElement)) {
            if ((isScanning || (lastScanningState && !isScanning)) && resultsResponse) {
              const resultsText = await resultsResponse.text();
              // Don't regress to empty/placeholder while scanning — server may briefly clear lastResults during task init
              if (isScanning && (!resultsText || resultsText.trim() === '' || resultsText.includes('None yet') || resultsText.includes('No scan data'))) {
                // skip — keep current results visible
              } else if (resultsText !== lastResultsText) {
                lastResultsText = resultsText;
                if (isScanning) {
                  setTimeout(() => {
                    const expandedCards = new Set();
                    const expandedDetails = new Map();
                    const contents = resultsElement.querySelectorAll('[id$="Content"]');
                    for (const content of contents) {
                      if (content.style.display !== 'none') {
                        expandedCards.add(content.id);
                      }
                    }
                    const openDetails = resultsElement.querySelectorAll('details[open]');
                    for (const details of openDetails) {
                      const summary = details.querySelector('summary');
                      if (summary && summary.textContent) {
                        expandedDetails.set(summary.textContent.trim(), true);
                      }
                    }
                    resultsElement.innerHTML = parseAndStyleResults(resultsText);
                    for (const contentId of expandedCards) {
                      const content = document.getElementById(contentId);
                      if (content) {
                        const iconId = contentId.replace('Content', 'Icon');
                        const icon = document.getElementById(iconId);
                        content.style.display = 'block';
                        if (icon) {
                          icon.style.transform = 'rotate(0deg)';
                          icon.textContent = '▼';
                        }
                      }
                    }
                    const allDetails = resultsElement.querySelectorAll('details');
                    for (const details of allDetails) {
                      const summary = details.querySelector('summary');
                      if (summary) {
                        const summaryText = summary.textContent.trim();
                        if (expandedDetails.has(summaryText)) {
                          details.open = true;
                          const spans = summary.querySelectorAll('span');
                          const arrow = spans[spans.length - 1];
                          if (arrow) arrow.style.transform = 'rotate(90deg)';
                        }
                      }
                      details.addEventListener('toggle', () => {
                        const spans = details.querySelectorAll('summary span');
                        const arrow = spans[spans.length - 1];
                        if (arrow) {
                          arrow.style.transform = details.open ? 'rotate(90deg)' : 'rotate(0deg)';
                        }
                      });
                    }
                    if (currentSort !== 'default') sortResultsDisplay();
                  }, 0);
                } else {
                  resultsElement.innerHTML = parseAndStyleResults(resultsText);
                  if (currentSort !== 'default') sortResultsDisplay();
                }
              }
            }
          }
          lastScanningState = isScanning;
        } catch (e) {
          console.error('Tick error:', e);
        } finally {
          tickRunning = false;
        }
      }

      // === Incidents panel ===
      function fmtIncUptime(ms){
        const s = Math.floor(ms/1000), h=Math.floor(s/3600), m=Math.floor((s%3600)/60), ss=s%60;
        if (h>0) return h+':'+String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0');
        return String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0');
      }
      function esc(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
      async function loadIncidents(){
        try {
          const r = await fetch('/api/incidents.json?limit=200');
          if (!r.ok) return;
          const arr = await r.json();
          const ftype = document.getElementById('incFilter').value;
          const fsrc  = document.getElementById('incSrc').value;
          const body = document.getElementById('incBody');
          const filtered = arr.slice().reverse().filter(e =>
            (!ftype || e.type === ftype) &&
            (!fsrc  || (fsrc === 'local' ? e.src === 'local' : e.src !== 'local'))
          );
          document.getElementById('incCount').textContent = filtered.length + ' / ' + arr.length + ' total';
          if (filtered.length === 0) {
            body.innerHTML = '<tr><td colspan="5" style="padding:12px;opacity:0.5;">No incidents</td></tr>';
            return;
          }
          let html = '';
          for (const e of filtered) {
            const isPeer = e.src && e.src !== 'local';
            const srcColor = isPeer ? '#fc6' : '#9bf';
            const typeColor = e.type.startsWith('DEAUTH') ? '#f99'
                            : e.type.startsWith('EVILTWIN') ? '#fc6'
                            : e.type.startsWith('KARMA') ? '#f9f'
                            : e.type.startsWith('PMKID') ? '#9fc'
                            : e.type.startsWith('BLE') ? '#9cf'
                            : '#ccc';
            html += '<tr style="border-bottom:1px solid #1a1a2a;">'
                  + '<td style="padding:4px 6px;color:#888;">'+ fmtIncUptime(e.ts) +'</td>'
                  + '<td style="padding:4px 6px;color:#ccc;">'+ esc(e.node) +'</td>'
                  + '<td style="padding:4px 6px;color:'+srcColor+';">'+ esc(e.src) +'</td>'
                  + '<td style="padding:4px 6px;color:'+typeColor+';">'+ esc(e.type) +'</td>'
                  + '<td style="padding:4px 6px;color:#bbb;word-break:break-all;">'+ esc(e.raw) +'</td>'
                  + '</tr>';
          }
          body.innerHTML = html;
        } catch(e){ console.error('loadIncidents', e); }
      }
      function downloadIncidents(){ window.open('/api/incidents.jsonl', '_blank'); }
      async function clearIncidents(){
        if (!confirm('Clear all incidents (RAM ring + SD file)?')) return;
        await fetch('/api/incidents', {method:'DELETE'});
        loadIncidents();
      }
      document.getElementById('incFilter').addEventListener('change', loadIncidents);
      document.getElementById('incSrc').addEventListener('change', loadIncidents);
      setInterval(loadIncidents, 2000);
      loadIncidents();

      async function sentinelRefresh(){
        try {
          const r = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!r.ok) return;
          const j = await r.json();
          let txt='DISABLED', col='#888';
          if (j.scanning){txt='KILLED (scan active)';col='#f99';}
          else if (j.running){txt='RUNNING';col='#9f9';}
          else if (j.enabled){txt='enabled, task not running';col='#fc6';}
          const el2=document.getElementById('sentStatus2');
          if(el2){el2.textContent=txt;el2.style.color=col;}
          const tb=document.getElementById('sentToggleBtn');
          if(tb){tb.textContent=j.enabled?'Stop':'Start';tb.className=j.enabled?'btn alt':'btn primary';}
        } catch(e){ console.error('sentinelRefresh', e); }
      }
      async function sentinelStart(){
        const r = await fetch('/api/sentinel/start', {method:'POST'});
        if (!r.ok) alert('Start failed: ' + await r.text());
        sentinelRefresh();
      }
      async function sentinelStop(){
        await fetch('/api/sentinel/stop', {method:'POST'});
        sentinelRefresh();
      }
      setInterval(sentinelRefresh, 4000);
      sentinelRefresh();

      document.getElementById('triangulate').addEventListener('change', e => {
        document.getElementById('triangulateOptions').style.display = e.target.checked ? 'block' : 'none';
        const secsInput = document.querySelector('input[name="secs"]');
        if (e.target.checked) {
          if (parseInt(secsInput.value) < 20) {
            secsInput.value = 20;
            toast('Triangulation requires minimum 20 seconds');
          }
          secsInput.setAttribute('min', '20');
        } else {
          secsInput.setAttribute('min', '0');
        }
      });

      document.getElementById('f').addEventListener('submit', e => {
        e.preventDefault();
        ajaxForm(e.target, 'Targets saved ✓');
        setTimeout(load, 500);
      });

      document.getElementById('af').addEventListener('submit', e => {
        e.preventDefault();
        ajaxForm(e.target, 'Allowlist saved ✓');
        setTimeout(() => {
          fetch('/allowlist-export').then(r => r.text()).then(t => {
            document.getElementById('wlist').value = t;
            document.getElementById('allowlistCount').textContent = t.split('\n').filter(x => x.trim()).length + ' entries';
          });
        }, 500);
      });

      document.getElementById('nodeForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('nodeId');
        const value = input.value.trim().toUpperCase();
        input.value = value;
        
        if (value === '') {
            toast('Node ID required: 2-5 alphanumeric characters (examples: AB, A1C, XYZ99)', 'error');
            return;
        }
        
        if (value.length < 2) {
            toast('Node ID too short - minimum 2 characters', 'error');
            return;
        }
        
        if (value.length > 5) {
            toast('Node ID too long - maximum 5 characters', 'error');
            return;
        }
        
        if (!/^[A-Z0-9]+$/.test(value)) {
            toast('Only alphanumeric characters (A-Z, 0-9) allowed', 'error');
            return;
        }
        
        ajaxForm(e.target, 'Node ID updated');
        setTimeout(loadNodeId, 500);
      });

      // Debounce state for scan forms
      const scanDebounce = {
        listScan: { inProgress: false, lastSubmit: 0, cooldown: 1000 },
        sniffer: { inProgress: false, lastSubmit: 0, cooldown: 1000 }
      };

      document.getElementById('s').addEventListener('submit', e => {
          e.preventDefault();

          if (isRadioBusy()) return;

          const now = Date.now();
          const state = scanDebounce.listScan;

          // Prevent double-submission
          if (state.inProgress) {
              toast('Scan already in progress', 'warning');
              return;
          }

          // Enforce cooldown period
          if (now - state.lastSubmit < state.cooldown) {
              const remaining = Math.ceil((state.cooldown - (now - state.lastSubmit)) / 1000);
              toast(`Please wait ${remaining}s before starting another scan`, 'warning');
              return;
          }

          const fd = new FormData(e.target);
          const submitBtn = e.target.querySelector('button[type="submit"]');

          // Mark as in progress
          state.inProgress = true;
          state.lastSubmit = now;

          // Check if triangulation mode is selected
          const isTriangulation = fd.has('triangulate') && fd.get('triangulate') === '1';

          lastScanStartTime = now;

          // Immediately update UI to show scanning state for ALL scan types
          setScanStatus(isTriangulation ? 'Triangulate' : 'List Scan', 'active');

          // Update button immediately for all scan types
          if (submitBtn) {
              submitBtn.textContent = 'Stop Scan';
              submitBtn.classList.remove('primary');
              submitBtn.classList.add('danger');
              submitBtn.disabled = false;  // Keep enabled so they can stop
              submitBtn.style.opacity = '1';
              submitBtn.style.cursor = 'pointer';
              submitBtn.type = 'button';
              submitBtn.onclick = function(e) {
                  e.preventDefault();
                  lastScanStartTime = 0;
                  fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                      setTimeout(async () => {
                          const refreshedDiag = await fetch('/diag').then(r => r.text());
                          updateStatusIndicators(refreshedDiag);
                      }, 500);
                  });
              };
          }

          const resultsElScan = document.getElementById('r');
          if (resultsElScan && !resultsElScan.contains(document.activeElement)) {
              lastResultsText = '';
              const modeVal = parseInt(document.querySelector('#s select[name="mode"]')?.value ?? '2');
              const modeLabel = ['WiFi', 'BLE', 'WiFi+BLE'][modeVal] ?? 'WiFi+BLE';
              resultsElScan.innerHTML = parseAndStyleResults('Target scan starting...\nMode: ' + modeLabel + '\n');
              switchPage('results');
          }

          fetch('/scan', {
            method: 'POST',
            body: fd
          }).then(r => {
            console.log('[SCAN] Response received at', new Date().toISOString());
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            console.log('[SCAN] Response text:', t, 'at', new Date().toISOString());
            toast(t);
            console.log('[SCAN] Forcing tick() at', new Date().toISOString());
            setTimeout(() => {
              console.log('[SCAN] tick() executing at', new Date().toISOString());
              tick();
            }, 100);
          }).catch(err => {
            console.error('[SCAN] Error at', new Date().toISOString(), err);
            toast('Error: ' + err.message, 'error');
          }).finally(() => {
            setTimeout(() => {
              state.inProgress = false;
              // Don't reset button state - we updated it immediately on click
              // and tick() will sync it with the actual backend state
              console.log('[SCAN] State reset at', new Date().toISOString());
            }, 500);
          });
        });

      document.getElementById('detectionMode').addEventListener('change', function() {
        const selectedMethod = this.value;
        const standardControls = document.getElementById('standardDurationControls');
        const baselineControls = document.getElementById('baselineConfigControls');
        const randomizationModeControls = document.getElementById('randomizationModeControls');
        const deviceScanModeControls = document.getElementById('deviceScanModeControls');
        const probeScanModeControls = document.getElementById('probeScanModeControls');
        const cacheBtn = document.getElementById('cacheBtn');
        const resetBaselineBtn = document.getElementById('resetBaselineBtn');
        const clearOldBtn = document.getElementById('clearOldBtn');
        const resetRandBtn = document.getElementById('resetRandBtn');

        cacheBtn.style.display = 'none';
        resetBaselineBtn.style.display = 'none';
        clearOldBtn.style.display = 'none';
        resetRandBtn.style.display = 'none';
        standardControls.style.display = 'none';
        baselineControls.style.display = 'none';
        randomizationModeControls.style.display = 'none';
        deviceScanModeControls.style.display = 'none';
        probeScanModeControls.style.display = 'none';
        document.getElementById('baselineStatus').style.display = 'none';

        if (selectedMethod === 'baseline') {
          baselineControls.style.display = 'block';
          resetBaselineBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = true;
          document.getElementById('baselineMonitorDuration').disabled = false;
          updateBaselineStatus();
          
        } else if (selectedMethod === 'randomization-detection') {
          standardControls.style.display = 'block';
          randomizationModeControls.style.display = 'block';
          clearOldBtn.style.display = 'inline-block';
          resetRandBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
          
        } else if (selectedMethod === 'device-scan') {
          standardControls.style.display = 'block';
          deviceScanModeControls.style.display = 'block';
          cacheBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
          
        } else if (selectedMethod === 'drone-detection') {
          standardControls.style.display = 'block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;

        } else if (selectedMethod === 'probe-scan') {
          standardControls.style.display = 'block';
          probeScanModeControls.style.display = 'block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;

        } else {
          standardControls.style.display = 'block';
          cacheBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
        }
      });

      document.getElementById('sniffer').addEventListener('submit', e => {
        e.preventDefault();

        if (isRadioBusy()) return;

        const now = Date.now();
        const state = scanDebounce.sniffer;

        if (state.inProgress) {
          toast('Detection/scan already in progress', 'warning');
          return;
        }

        if (now - state.lastSubmit < state.cooldown) {
          const remaining = Math.ceil((state.cooldown - (now - state.lastSubmit)) / 1000);
          toast(`Please wait ${remaining}s before starting another scan`, 'warning');
          return;
        }

        const fd = new FormData(e.target);
        const detectionMethod = fd.get('detection');
        const submitBtn = document.getElementById('startDetectionBtn');
        let endpoint = '/sniffer';

        state.inProgress = true;
        state.lastSubmit = now;
        lastScanStartTime = now;

        const detMethodLabels = {
          'device-scan': 'Device Scan', 'drone-detection': 'Drone Detect',
          'blue-team': 'Blue Team', 'baseline': 'Baseline',
          'randomization-detection': 'Rand Detect', 'probe-detection': 'Probe Detect'
        };
        setScanStatus(detMethodLabels[detectionMethod] || 'Scanning', 'active');

        if (submitBtn) {
            submitBtn.textContent = 'Stop Scanning';
            submitBtn.classList.remove('primary');
            submitBtn.classList.add('danger');
            submitBtn.disabled = false;
            submitBtn.style.opacity = '1';
            submitBtn.style.cursor = 'pointer';
            submitBtn.type = 'button';
            submitBtn.onclick = function(e) {
                e.preventDefault();
                lastScanStartTime = 0;
                fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                    setTimeout(async () => {
                        const refreshedDiag = await fetch('/diag').then(r => r.text());
                        updateStatusIndicators(refreshedDiag);
                    }, 500);
                });
            };
        }

        if (detectionMethod === 'randomization-detection') {
          const randMode = document.getElementById('randomizationMode').value;
          fd.append('randomizationMode', randMode);
        }
        if (detectionMethod === 'drone-detection') {
          endpoint = '/drone';
          fd.delete('detection');
        }

        const resetState = () => {
          setTimeout(() => {
            state.inProgress = false;
          }, 500);
        };

        const resultsElSniffer = document.getElementById('r');
        if (resultsElSniffer && !resultsElSniffer.contains(document.activeElement)) {
            lastResultsText = '';
            resultsElSniffer.innerHTML = parseAndStyleResults('Scan starting...\n');
            switchPage('results');
        }

        if (detectionMethod === 'baseline') {
          setTimeout(updateBaselineStatus, 500);
          const rssiThreshold = document.getElementById('baselineRssiThreshold').value;
          const duration = document.getElementById('baselineDuration').value;
          const ramSize = document.getElementById('baselineRamSize').value;
          const sdMax = document.getElementById('baselineSdMax').value;
          const absence = document.getElementById('absenceThreshold').value;
          const reappear = document.getElementById('reappearanceWindow').value;
          const rssiDelta = document.getElementById('rssiChangeDelta').value;

          fetch('/baseline/config', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `rssiThreshold=${rssiThreshold}&baselineDuration=${duration}&ramCacheSize=${ramSize}&sdMaxDevices=${sdMax}&absenceThreshold=${absence}&reappearanceWindow=${reappear}&rssiChangeDelta=${rssiDelta}`
          }).then(() => {
            return fetch(endpoint, {
              method: 'POST',
              body: fd
            });
          }).then(r => {
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            toast(t, 'success');
            setTimeout(() => { tick(); }, 100);
            updateBaselineStatus();
          }).catch(err => {
            toast('Error: ' + err, 'error');
          }).finally(resetState);
        } else {
          fetch(endpoint, {
            method: 'POST',
            body: fd
          }).then(r => {
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            toast(t, 'success');
            setTimeout(() => { tick(); }, 100);
          }).catch(err => {
            toast('Error: ' + err, 'error');
          }).finally(resetState);
        }
      });

      document.addEventListener('click', e => {
        const a = e.target.closest('a[href="/stop"]');
        if (!a) return;
        e.preventDefault();
        fetch('/stop').then(r => r.text()).then(t => toast(t));
      });

      document.addEventListener('click', e => {
        const a = e.target.closest('a[href="/mesh-test"]');
        if (!a) return;
        e.preventDefault();
        fetch('/mesh-test').then(r => r.text()).then(t => toast('Mesh test sent'));
      });
        
      // Mode status updates
      document.querySelector('#s select[name="mode"]')?.addEventListener('change', updateModeStatus);
      document.getElementById('randomizationMode')?.addEventListener('change', updateModeStatus);
      document.getElementById('deviceScanMode')?.addEventListener('change', updateModeStatus);
      document.getElementById('detectionMode')?.addEventListener('change', updateModeStatus);

      function showAutoEraseHelp() {
        toast('Auto-Erase: 1) Setup period prevents wipe during install 2) Vibration triggers countdown 3) You can cancel 4) Cooldown prevents false triggers', 'info');
      }

      // Battery Saver Functions
      async function enableBatterySaver() {
        const interval = document.getElementById('batterySaverInterval').value;
        try {
          const r = await fetch('/battery-saver?action=start&interval=' + interval);
          const t = await r.text();
          toast('Battery saver enabled with ' + interval + ' min heartbeat');
          updateBatterySaverStatus();
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function disableBatterySaver() {
        try {
          const r = await fetch('/battery-saver?action=stop');
          const t = await r.text();
          toast('Battery saver disabled');
          updateBatterySaverStatus();
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function updateBatterySaverStatus() {
        try {
          const r = await fetch('/battery-saver?action=status');
          const data = await r.json();
          const el = document.getElementById('batterySaverStatus');
          if (data.enabled) {
            el.style.background = 'rgba(0,200,100,0.2)';
            el.style.color = 'var(--c-ok)';
            el.innerHTML = 'ACTIVE - Heartbeat every ' + data.interval + ' min | Next: ' + data.nextHeartbeat + 's';
          } else {
            el.style.background = 'rgba(0,0,0,0.2)';
            el.style.color = '#888';
            el.innerHTML = 'INACTIVE';
          }
        } catch(e) {}
      }

      function showBatterySaverHelp() {
        toast('Battery Saver: Disables WiFi/BLE scanning, reduces CPU to 80MHz, sends periodic heartbeats. Mesh UART stays active to receive commands like BATTERY_SAVER_STOP.', 'info');
      }

      // ---- Data Tab ----
      var dataRows=[],dataFiltered=[],dataCols=[],dataPage=0,dataSortCol=-1,dataSortAsc=false,dataSearchTimer=null;
      var DATA_PAGE_SIZE=50;
      var DATA_SETS={
        probedb:{url:'/api/probedb',clear:'/api/probedb/clear',fmt:'json',
          cols:['MAC','Vendor','RSSI','Sessions','Seen','First','Last','SSIDs','Rand'],
          keys:['mac','vendor','rssi','sessions','seen','first','last','ssids','rand']},
        probes:{url:'/api/probes.jsonl',clear:null,fmt:'jsonl',
          cols:['Time','MAC','RSSI','Ch','Count','Vendor','SSIDs','Rand','Hit'],
          keys:['t','mac','rssi','ch','cnt','v','ss','rand','hit']},
        deauth:{url:'/api/deauth.jsonl',clear:'/api/deauth/clear',fmt:'jsonl',
          cols:['Time','Src','Dst','BSSID','RSSI','Ch','Reason','Type'],
          keys:['t','src','dst','bssid','rssi','ch','reason','_type']},
        drones:{url:'/api/drones.jsonl',clear:'/api/drones/clear',fmt:'jsonl',
          cols:['Time','MAC','RSSI','UAV ID','Type','Lat','Lon'],
          keys:['timestamp','mac','rssi','uav_id','type','lat','lon']},
        vibrations:{url:'/api/vibrations.jsonl',clear:'/api/vibrations/clear',fmt:'jsonl',
          cols:['Time','Uptime','Lat','Lon'],
          keys:['t','uptime_ms','lat','lon']},
        baseline:{url:'/baseline/stats',clear:null,fmt:'baseline',cols:[],keys:[]},
        syslog:{url:'/api/antihunter.log',clear:'/api/antihunter.log/clear',fmt:'text',
          cols:['Time','Message'],keys:['_time','_msg']},
        incidents:{url:'/api/incidents.jsonl',clear:'/api/incidents/clear',fmt:'jsonl',
          cols:['Uptime','Node','Src','Type','Raw'],
          keys:['ts','node','src','type','raw']}
      };
      let _saData=null;
      function refreshSentinelAnalysis(){ _saData=null; loadSentinelAnalysis(); }
      async function clearSentinelAnalysis(){
        if(!confirm('Clear all sentinel incidents (RAM + SD)?'))return;
        await fetch('/api/incidents',{method:'DELETE'}); _saData=null; loadSentinelAnalysis();
      }
      async function loadSentinelAnalysis(){
        const area=document.getElementById('saArea'); if(!area)return;
        if(!_saData){
          const r=await fetch('/api/incidents.jsonl');
          const t=r.ok?await r.text():'';
          _saData=t.split('\n').filter(x=>x.trim()).map(x=>{try{return JSON.parse(x)}catch(_){return null}}).filter(x=>x);
          const sel=document.getElementById('saType'); const cur=sel?sel.value:'ALL';
          const types=[...new Set(_saData.map(x=>x.type).filter(Boolean))].sort();
          if(sel){sel.innerHTML='<option value="ALL">All types</option>'+types.map(t=>`<option>${t}</option>`).join(''); sel.value=cur||'ALL';}
        }
        const ty=(document.getElementById('saType')||{}).value||'ALL';
        const q=((document.getElementById('saSearch')||{}).value||'').toLowerCase();
        let rows=_saData.filter(x=>(ty==='ALL'||x.type===ty)&&(!q||JSON.stringify(x).toLowerCase().includes(q)));
        const total=rows.length; rows=rows.slice(-300).reverse();
        if(!rows.length){area.innerHTML='<div class="data-empty">No incidents.</div>';return;}
        area.innerHTML=`<div style="font-size:11px;color:var(--mut);margin-bottom:4px;">${total} incident${total!=1?'s':''}</div>`
          +'<table class="dt"><thead><tr><th>Uptime</th><th>Node</th><th>Type</th><th>Src</th><th>Raw</th></tr></thead><tbody>'
          +rows.map(r=>`<tr><td>${r.ts||''}</td><td>${r.node||''}</td><td style="color:#e08;">${r.type||''}</td><td>${r.src||''}</td><td>${String(r.raw||'').replace(/</g,'&lt;')}</td></tr>`).join('')
          +'</tbody></table>';
      }
      function loadDataSet(){
        var ds=document.getElementById('dataSet').value;
        var cfg=DATA_SETS[ds];
        var area=document.getElementById('dataArea');
        area.innerHTML='<div class="data-empty">Loading...</div>';
        document.getElementById('dataPager').style.display='none';
        document.getElementById('dataSearch').value='';
        var exp=document.getElementById('dataExport');
        exp.href=cfg.url;
        exp.download=ds+(cfg.fmt==='text'?'.log':cfg.fmt==='json'?'.json':'.jsonl');
        document.getElementById('dataClear').style.display=cfg.clear?'':'none';
        fetch(cfg.url).then(function(r){
          if(!r.ok) throw new Error(r.status);
          return r.text();
        }).then(function(text){
          if(cfg.fmt==='baseline'){renderBaseline(text);return;}
          if(cfg.fmt==='text'){parseLogData(text,cfg);return;}
          if(cfg.fmt==='json'){dataRows=JSON.parse(text);}
          else{var lines=text.trim().split('\n');dataRows=[];for(var i=0;i<lines.length;i++){if(lines[i].trim()){try{dataRows.push(JSON.parse(lines[i]));}catch(e){}}}}
          dataCols=cfg.keys;dataPage=0;dataSortCol=-1;dataSortAsc=false;
          dataFiltered=dataRows.slice();
          var tk=dataCols.indexOf('last')>=0?'last':dataCols.indexOf('timestamp')>=0?'timestamp':dataCols.indexOf('t')>=0?'t':null;
          if(tk){var ci=dataCols.indexOf(tk);dataSortCol=ci;dataSortAsc=false;dataFiltered.sort(function(a,b){return(getVal(b,tk)||0)-(getVal(a,tk)||0);});}
          renderDataTable(cfg);
        }).catch(function(e){area.innerHTML='<div class="data-empty">No data available.</div>';});
      }
      function getVal(row,key){
        if(key==='_type') return row.disassoc?'DISASSOC':'DEAUTH';
        return row[key];
      }
      function fmtCell(val,key){
        if(val===undefined||val===null) return '-';
        if(key==='t'||key==='timestamp'||key==='first'||key==='last'){
          if(typeof val==='number'&&val>946684800) return new Date(val*1000).toISOString().replace('T',' ').substring(0,19)+' UTC';
          if(typeof val==='number'&&val>0){var s=val%60,m=Math.floor(val/60)%60,h=Math.floor(val/3600);return (h?h+'h ':'')+(m?m+'m ':'')+s+'s (uptime)';}
          if(typeof val==='number') return '-';
          return String(val);
        }
        if(key==='rssi'){var cls=val>-50?'rssi-good':val>-70?'rssi-mid':'rssi-bad';return '<span class="'+cls+'">'+val+' dBm</span>';}
        if(key==='rand') return val?'<span class="rand-yes">Yes</span>':'No';
        if(key==='hit'||key==='dst') return val?'<span style="color:var(--dang);font-weight:600">Yes</span>':'No';
        if(key==='ss'||key==='ssids'){
          if(Array.isArray(val)){if(val.length===0) return '-';var shown=val.slice(0,2).join(', ');if(val.length>2) shown+=' +'+(val.length-2)+' more';return shown;}
          return String(val);
        }
        if(key==='uptime_ms'){var s=Math.floor(val/1000);var m=Math.floor(s/60);s=s%60;var h=Math.floor(m/60);m=m%60;return (h?h+'h ':'')+(m?m+'m ':'')+(s+'s');}
        if(key==='mac'||key==='src'||key==='dst'||key==='bssid'){
          if(typeof privacyMode!=='undefined'&&privacyMode&&typeof val==='string'&&val.length>=17) return val.substring(0,9)+'XX:XX'+val.substring(14);
        }
        if(key==='_type') return val;
        return String(val);
      }
      function renderDataTable(cfg){
        var area=document.getElementById('dataArea');
        if(!dataFiltered.length){area.innerHTML='<div class="data-empty">No records found.</div>';document.getElementById('dataPager').style.display='none';return;}
        var start=dataPage*DATA_PAGE_SIZE,end=Math.min(start+DATA_PAGE_SIZE,dataFiltered.length);
        var html='<table id="data-table"><thead><tr>';
        for(var c=0;c<cfg.cols.length;c++){
          var arrow='';if(dataSortCol===c) arrow='<span class="sort-arrow">'+(dataSortAsc?'&#9650;':'&#9660;')+'</span>';
          html+='<th onclick="sortDataCol('+c+')">'+cfg.cols[c]+arrow+'</th>';
        }
        html+='</tr></thead><tbody>';
        for(var i=start;i<end;i++){html+='<tr>';for(var c=0;c<dataCols.length;c++){html+='<td>'+fmtCell(getVal(dataFiltered[i],dataCols[c]),dataCols[c])+'</td>';}html+='</tr>';}
        html+='</tbody></table>';area.innerHTML=html;
        var pager=document.getElementById('dataPager');
        if(dataFiltered.length>DATA_PAGE_SIZE){
          pager.style.display='flex';
          document.getElementById('dataPageInfo').textContent=(start+1)+'-'+end+' of '+dataFiltered.length;
          document.getElementById('dataPrevBtn').disabled=dataPage===0;
          document.getElementById('dataNextBtn').disabled=end>=dataFiltered.length;
        } else { pager.style.display='none'; }
      }
      function sortDataCol(ci){
        var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
        if(dataSortCol===ci){dataSortAsc=!dataSortAsc;}else{dataSortCol=ci;dataSortAsc=true;}
        var key=dataCols[ci];
        dataFiltered.sort(function(a,b){
          var av=getVal(a,key),bv=getVal(b,key);
          if(av===undefined||av===null) av='';if(bv===undefined||bv===null) bv='';
          if(typeof av==='number'&&typeof bv==='number') return dataSortAsc?av-bv:bv-av;
          av=String(av).toLowerCase();bv=String(bv).toLowerCase();
          return dataSortAsc?av.localeCompare(bv):bv.localeCompare(av);
        });
        dataPage=0;renderDataTable(cfg);
      }
      function onDataSearch(){
        clearTimeout(dataSearchTimer);
        dataSearchTimer=setTimeout(function(){
          var q=document.getElementById('dataSearch').value.toLowerCase();
          var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
          if(!q){dataFiltered=dataRows.slice();}else{
            dataFiltered=dataRows.filter(function(row){
              for(var c=0;c<dataCols.length;c++){var v=getVal(row,dataCols[c]);if(v!==undefined&&v!==null&&String(v).toLowerCase().indexOf(q)>=0) return true;}
              return false;
            });
          }
          dataPage=0;renderDataTable(cfg);
        },300);
      }
      function dataPagePrev(){if(dataPage>0){dataPage--;renderDataTable(DATA_SETS[document.getElementById('dataSet').value]);}}
      function dataPageNext(){var ds=document.getElementById('dataSet').value;if((dataPage+1)*DATA_PAGE_SIZE<dataFiltered.length){dataPage++;renderDataTable(DATA_SETS[ds]);}}
      function clearDataSet(){
        var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
        if(!cfg.clear) return;
        if(!confirm('Clear all '+ds+' data? This cannot be undone.')) return;
        fetch(cfg.clear,{method:'POST'}).then(function(r){if(r.ok){toast('Data cleared','success');loadDataSet();}else toast('Clear failed','error');});
      }
      function parseLogData(text,cfg){
        dataRows=[];dataCols=cfg.keys;
        var lines=text.trim().split('\n');
        for(var i=0;i<lines.length;i++){var line=lines[i];var m=line.match(/^\[([^\]]+)\]\s*(.*)$/);if(m){dataRows.push({_time:m[1],_msg:m[2]});}else if(line.trim()){dataRows.push({_time:'',_msg:line});}}
        dataRows.reverse();dataFiltered=dataRows.slice();dataPage=0;dataSortCol=-1;dataSortAsc=false;renderDataTable(cfg);
      }
      function renderBaseline(text){
        var area=document.getElementById('dataArea');document.getElementById('dataPager').style.display='none';
        try{var d=JSON.parse(text);
          area.innerHTML='<div class="stat-grid">'
            +'<div class="stat-item"><div class="stat-label">Devices</div><div class="stat-value">'+(d.deviceCount||d.devices||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">RAM Cache</div><div class="stat-value">'+(d.ramSize||d.ram||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">SD Cache</div><div class="stat-value">'+(d.sdSize||d.sd||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">RSSI Threshold</div><div class="stat-value">'+(d.rssiThreshold||d.rssi||'-70')+' dBm</div></div>'
            +'<div class="stat-item"><div class="stat-label">Absence</div><div class="stat-value">'+(d.absenceThreshold||d.absence||'120')+'s</div></div>'
            +'<div class="stat-item"><div class="stat-label">Reappear Window</div><div class="stat-value">'+(d.reappearWindow||d.reappear||'300')+'s</div></div>'
            +'</div><div style="margin-top:16px;"><button class="btn danger" onclick="if(confirm(\'Reset all baseline data?\'))fetch(\'/baseline/reset\',{method:\'POST\'}).then(function(){toast(\'Baseline reset\',\'success\');loadDataSet();})">Reset Baseline</button></div>';
        }catch(e){area.innerHTML='<div class="data-empty">No baseline data available.</div>';}
      }

      // Initialize
      load();
      updatePrivacyBtn();
      setInterval(updateBatterySaverStatus, 5000);
      initTerminal();
      loadBaselineAnomalyConfig();
      loadMeshInterval();
      updateAutoEraseStatus();
      setInterval(tick, 2000);
      document.getElementById('detectionMode').dispatchEvent(new Event('change'));

      // ===== Detect tab logic =====
      function _safeParse(s){
        try{return JSON.parse(s);}
        catch(e){console.warn('detect: bad json line', e); return null;}
      }
      async function _jt(u){
        try{const r=await fetch(u);if(!r.ok)return '';return await r.text();}
        catch(e){console.warn('detect: fetch text failed', u, e); return '';}
      }
      async function _jj(u){
        try{const r=await fetch(u);return await r.json();}
        catch(e){console.warn('detect: fetch json failed', u, e); return null;}
      }
      function _countLines(s){if(!s)return 0;return s.split('\n').filter(l=>l.trim()).length}
      const GROUPS={
        dos:[['DEAUTH_FORGE','Deauth Forge',null],['DEAUTH_FLOOD','Deauth Flood',null],
          ['BEACON_FLOOD','Beacon Flood','eviltwin'],['AUTH_FLOOD','Auth Flood',null],
          ['ASSOC_SLEEP','Assoc Sleep','assoc_sleep'],['SAE_DOS','SAE DoS','sae'],
          ['DEAUTH_AP_TARGETED','AP Deauth (event)',null]],
        rogue:[['EVILTWIN','Evil Twin','eviltwin'],['OWE_ABUSE','OWE Abuse','owe'],
          [['KARMA_CAND','KARMA_CONFIRMED'],'Karma','karma']],
        recon:[[['PMKID_HARVEST','PMKID_FORGE'],'PMKID Harvest','pmkid'],
          ['PROBE_FLOOD','Probe Flood','probe_flood'],['HSHK','Handshake Capture','hshk']],
        physical:[['FRAG','FragAttacks','frag'],['TSF','TSF Clock-Skew','tsf'],['CSI_MOTION','CSI Motion','csi']]
      };
      function _grpRows(dets,inc,cfg,nowMs){
        const ago=t=>{if(!t)return '--';const s=Math.floor((nowMs-t)/1000);if(s<1)return 'now';if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h';};
        let h='<div style="display:grid;grid-template-columns:1fr 70px 60px 70px;gap:10px;'
             +'font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;'
             +'padding:0 0 6px;border-bottom:1px solid var(--bd);">'
             +'<span>Detector</span><span style="text-align:center;">Enabled</span>'
             +'<span style="text-align:right;">Hits</span><span style="text-align:right;">Last</span></div>';
        dets.forEach(d=>{
          const types=Array.isArray(d[0])?d[0]:[d[0]];
          const hits=inc.filter(x=>x&&types.includes(x.type));
          const cnt=hits.length;
          const last=cnt?Math.max(...hits.map(x=>x.ts||0)):0;
          const tog=d[2]?`<input type="checkbox" style="width:18px;height:18px;" ${cfg[d[2]]?'checked':''} onchange="detPostCfg({${d[2]}:this.checked});">`
                        :'<span style="opacity:.5;font-size:12px;">always</span>';
          const hot=cnt>0?'color:var(--bad,#e55);font-weight:700;':'';
          h+=`<div style="display:grid;grid-template-columns:1fr 70px 60px 70px;gap:10px;align-items:center;`
            +`padding:9px 0;border-bottom:1px solid var(--bd);font-size:14px;">`
            +`<span>${d[1]}</span><span style="text-align:center;">${tog}</span>`
            +`<span class="num" style="text-align:right;${hot}">${cnt}</span>`
            +`<span class="mut" style="text-align:right;font-size:12px;">${ago(last)}</span></div>`;
        });
        return h;
      }
      function _dosSyncMode(scan){
        const d=document.getElementById('dos-mode-defend'), s=document.getElementById('dos-mode-scan'),
              t=document.getElementById('dos-mode-desc');
        if(d)d.className=scan?'btn alt':'btn primary';
        if(s)s.className=scan?'btn primary':'btn alt';
        if(t)t.textContent=scan?'Hopping all channels — sees attacks anywhere, but your AP clients may drop.'
                               :'Locked to this AP’s channel — catches attacks against us, clients stay connected.';
      }
      async function detScanMode(scan){
        _dosSyncMode(scan);
        await detPostCfg({sentinel_scan:scan});
        if(_detCfg)_detCfg.sentinel_scan=scan;
      }
      function _grpChipState(cfg){
        if(typeof DET_GROUPS==='undefined')return;
        for(const g in DET_GROUPS){
          const c=document.getElementById('grpchip-'+g);
          if(c)c.className=DET_GROUPS[g].some(k=>(cfg||{})[k])?'btn primary':'btn alt';
        }
      }
      async function renderDos(){
        const inc=await _jj('/api/incidents.json?limit=200')||[];
        const cfg=_detCfg||{};
        _dosSyncMode(!!cfg.sentinel_scan);
        const nowMs=inc.reduce((m,x)=>Math.max(m,(x&&x.ts)||0),0);
        for(const gid in GROUPS){
          const el=document.getElementById(gid+'-rows');
          if(el)el.innerHTML=_grpRows(GROUPS[gid],inc,cfg,nowMs);
        }
        const GLBL={dos:'DoS',rogue:'Rogue AP',recon:'Recon',physical:'Physical'};
        let qv='';
        for(const gid in GROUPS){
          const dets=GROUPS[gid]; let en=0,ht=0;
          dets.forEach(d=>{
            if(d[2]?(cfg[d[2]]===true):true)en++;
            const types=Array.isArray(d[0])?d[0]:[d[0]];
            ht+=inc.filter(x=>x&&types.includes(x.type)).length;
          });
          const hot=ht>0?'border-color:var(--bad,#e55);':'';
          qv+=`<div style="border:1px solid var(--bd);border-radius:6px;padding:6px 8px;${hot}">`
            +`<div style="font-size:11px;color:var(--mut);">${GLBL[gid]||gid}</div>`
            +`<div style="font-size:13px;"><b>${en}/${dets.length}</b> on · <span style="${ht>0?'color:var(--bad,#e55);font-weight:700;':''}">${ht} hit${ht!=1?'s':''}</span></div></div>`;
        }
        const qe=document.getElementById('dctl-quick'); if(qe)qe.innerHTML=qv;
        _grpChipState(cfg);
        const setc=(id,types)=>{const e=document.getElementById(id);if(e)e.textContent=inc.filter(x=>x&&types.includes(x.type)).length;};
        setc('d-karma',['KARMA_CAND','KARMA_CONFIRMED']);
        setc('d-authflood',['AUTH_FLOOD']);
        setc('d-beaconflood',['BEACON_FLOOD']);
        setc('d-dauth',['DEAUTH_FLOOD','DEAUTH_FORGE','DEAUTH_AP_TARGETED']);
        setc('d-pmkid',['PMKID_HARVEST','PMKID_FORGE']);
        setc('d-et',['EVILTWIN']);
        setc('d-sc',['SSID_CONFUSION']);
        setc('d-sae',['SAE_DOS']);
        setc('d-owe',['OWE_ABUSE']);
        setc('d-frag',['FRAG']);
        setc('d-blem',['BLE_MALFORMED']);
        setc('d-hs-krack',['KRACK']);
        _overviewVisibility(cfg);
      }
      // Hide overview stats whose detector is disabled AND has zero hits.
      // 'always' stats and any stat with a non-zero count stay visible.
      function _overviewVisibility(cfg){
        cfg=cfg||_detCfg||{};
        document.querySelectorAll('#detOverviewCardBody .stat[data-cfg]').forEach(el=>{
          const keys=el.dataset.cfg;
          const ve=el.querySelector('.stat-value');
          const cnt=ve?(parseInt(ve.textContent,10)||0):0;
          const enabled=keys==='always'||keys.split(',').some(k=>cfg[k]===true);
          el.style.display=(enabled||cnt>0)?'':'none';
        });
      }
      async function detectTick(){
        const tab=document.getElementById('page-detect');
        if(!tab||!tab.classList.contains('active'))return;
        const [pm,et,sc,sa,ow,fr,bm,df,q,b,p,rid,tr,rc,ch]=await Promise.all([
          _jt('/api/pmkid.jsonl'),_jt('/api/eviltwin.jsonl'),
          _jt('/api/ssid_confusion.jsonl'),_jt('/api/sae_dos.jsonl'),
          _jt('/api/owe_abuse.jsonl'),_jt('/api/fragattack.jsonl'),
          _jt('/api/ble_malformed.jsonl'),_jt('/api/deauth_flood.jsonl'),
          _jj('/api/quorum'),_jj('/api/bloom'),_jj('/api/pps'),
          _jj('/api/rid_claims'),_jj('/api/ble_tracker'),_jj('/api/recon'),
          _jj('/api/channel_partition')
        ]);
        const dEl = document.getElementById('d-dauth');
        if (dEl) dEl.textContent = _countLines(df);
        document.getElementById('d-pmkid').textContent=_countLines(pm);
        document.getElementById('d-et').textContent=_countLines(et);
        document.getElementById('d-sc').textContent=_countLines(sc);
        document.getElementById('d-sae').textContent=_countLines(sa);
        document.getElementById('d-owe').textContent=_countLines(ow);
        document.getElementById('d-frag').textContent=_countLines(fr);
        document.getElementById('d-blem').textContent=_countLines(bm);
        document.getElementById('d-trk').textContent=(tr||[]).length;
        document.getElementById('d-rec').textContent=(rc||[]).length;
        document.getElementById('d-pps').textContent=p?(p.locked?'YES':'no')+' edge='+p.last_edge:'--';
        document.getElementById('d-bl').textContent=b?(b.local_bits_set+' / '+b.capacity_bits):'--';
        document.getElementById('d-bn').textContent=b?(b.neighbor_bits_set+' / '+b.capacity_bits):'--';
        document.getElementById('d-qc').textContent=q?((q.candidates||[]).length):0;
        document.getElementById('d-quorum').textContent=q?JSON.stringify(q,null,2):'--';
        document.getElementById('d-chan').textContent=ch?JSON.stringify(ch,null,2):'--';
        document.getElementById('d-rid').textContent=rid?JSON.stringify(rid,null,2):'[]';
        detRenderTable('d-recpre',rc||[],[
          {key:'id',label:'TrackId'},{key:'score',label:'Score'},
          {key:'reasons',label:'Reasons'},{key:'ts',label:'Last',get:r=>_ago(r.ts)}
        ]);
        const evtRows=[];
        function parseLines(s,kind,sevHint){
          (s||'').split('\n').filter(l=>l.trim()).forEach(l=>{
            const o=_safeParse(l);
            if(o)evtRows.push({kind,sev:sevHint,ts:o.ts||0,raw:l,o});
          });
        }
        parseLines(pm,'PMKID','crit');parseLines(et,'EvilTwin','high');parseLines(sc,'SSIDConf','high');
        parseLines(sa,'SAE','high');parseLines(ow,'OWE','med');parseLines(fr,'Frag','med');
        parseLines(bm,'BLEMalformed','med');
        evtRows.sort((a,b)=>(b.ts||0)-(a.ts||0));
        detRenderTable('d-stream',evtRows.slice(0,40),[
          {key:'kind',label:'Type'},
          {key:'sev',label:'Sev',get:r=>r.sev.toUpperCase()},
          {key:'ts',label:'Age',get:r=>_ago(r.ts)},
          {key:'raw',label:'Detail',get:r=>r.raw}
        ]);
        if((rc||[]).length>0)detMarkActive('recon');
        if(_countLines(pm)>0||_countLines(et)>0||_countLines(sc)>0||_countLines(sa)>0)detMarkActive('rid');
        renderDos();
      }
      async function detectClearAll(){await fetch('/api/detect/clear_all',{method:'POST'});detectTick()}
      async function csiTick(){
        if(!detTabActive())return;
        const [stats,mot,fp]=await Promise.all([
          _jj('/api/csi/stats'),_jt('/api/csi/motion.jsonl'),_jj('/api/csi/fingerprints')
        ]);
        if(stats){
          document.getElementById('csi-on').textContent=stats.enabled?'YES':'no';
          document.getElementById('csi-pk').textContent=stats.pkts;
          document.getElementById('csi-mv').textContent=stats.motion_events;
          document.getElementById('csi-th').textContent=stats.thresh_q8;
        }
        document.getElementById('csi-fp').textContent=(fp||[]).length;
        const motionRows=(mot||'').split('\n').filter(l=>l.trim()).map(l=>{try{return JSON.parse(l)}catch(e){return null}}).filter(x=>x);
        detRenderTable('csi-motion',motionRows.slice(-25).reverse(),[
          {key:'ts',label:'Age',get:r=>_ago(r.ts)},
          {key:'src',label:'Source'},{key:'var',label:'Var Q8'},
          {key:'rssi',label:'RSSI'},{key:'ch',label:'Ch'},{key:'zone',label:'Zone'}
        ]);
        detRenderTable('csi-fp-pre',fp||[],[
          {key:'src',label:'Source'},{key:'hash',label:'Hash'},
          {key:'obs',label:'Obs'},{key:'avg_rssi',label:'Avg RSSI'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(motionRows.length>0)detMarkActive('csi');
      }
      async function csiToggle(on){
        const fd=new FormData();fd.append('on',on);
        await fetch('/api/csi/enable',{method:'POST',body:fd});csiTick();
      }
      async function csiSetThresh(){
        const v=document.getElementById('csi-thresh-in').value;
        if(!v)return;
        const fd=new FormData();fd.append('v',v);
        await fetch('/api/csi/threshold',{method:'POST',body:fd});csiTick();
      }
      async function csiClear(){await fetch('/api/csi/clear',{method:'POST'});csiTick();}
      async function pgTick(){
        if(!detTabActive())return;
        const pg=await _jj('/api/probegraph');
        const n=(pg||[]).length;
        document.getElementById('pg-n').textContent=n;
        detRenderTable('pg-pre',pg||[],[
          {key:'hash',label:'Hash'},{key:'local',label:'TrackId'},
          {key:'best_rssi',label:'Best RSSI'},{key:'sightings',label:'Sight'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(n>0)detMarkActive('probegraph');
      }
      async function pgClear(){await fetch('/api/probegraph/clear',{method:'POST'});pgTick();}
      async function trkTick(){
        if(!detTabActive())return;
        const [chains,watch]=await Promise.all([_jj('/api/tracker_chains'),_jj('/api/ble_tracker')]);
        const n=(chains||[]).length;
        document.getElementById('trk-n').textContent=n;
        detRenderTable('trk-pre',chains||[],[
          {key:'chain',label:'Chain'},{key:'vendor',label:'Vendor'},
          {key:'links',label:'Links'},{key:'avg_rssi',label:'Avg RSSI'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        detRenderTable('d-trkpre',watch||[],[
          {key:'addr',label:'Addr'},{key:'vendor',label:'Vendor'},
          {key:'sightings',label:'Sight'},{key:'avg_rssi',label:'RSSI'},
          {key:'score',label:'Score'},{key:'last_seen',label:'Last',get:r=>_ago(r.last_seen)}
        ]);
        if(n>0||(watch||[]).length>0)detMarkActive('trackers');
      }
      async function trkClear(){await fetch('/api/tracker_chains/clear',{method:'POST'});trkTick();}
      async function atTick(){
        if(!detTabActive())return;
        const a=await _jj('/api/airtag_presence');
        const n=(a||[]).length;
        document.getElementById('at-n').textContent=n;
        detRenderTable('at-pre',a||[],[
          {key:'addr',label:'Addr'},{key:'owner_nearby',label:'Owner'},
          {key:'battery',label:'Battery'},{key:'observations',label:'Obs'},
          {key:'last_rssi',label:'RSSI'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(n>0)detMarkActive('airtag');
      }
      async function atClear(){await fetch('/api/airtag_presence/clear',{method:'POST'});atTick();}
      async function hsTick(){
        if(!detTabActive())return;
        const [r,s]=await Promise.all([_jj('/api/handshakes'),_jj('/api/handshakes/stats')]);
        if(s){
          document.getElementById('hs-n').textContent=s.count;
          const ko=document.getElementById('d-hs-krack'); if(ko)ko.textContent=s.krack_events;
        }
        const rows=(r||[]).map(x=>Object.assign({mask:['','M1','M2','M3','M4','M1M2','M1M3','M1-3','M4o','M1M4','M2M4','M1-3M4','M3M4','M1M3M4','M2-4','M1-4'][x.seen_mask&15]||x.seen_mask},x));
        detRenderTable('hs-pre',rows,[
          {key:'bssid',label:'BSSID'},{key:'sta',label:'STA'},
          {key:'mask',label:'Msgs'},{key:'complete',label:'Done'},
          {key:'krack_events',label:'KRACK'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(s&&s.krack_events>0)detMarkActive('handshake');
      }
      async function hsClear(){await fetch('/api/handshakes/clear',{method:'POST'});hsTick();}
      async function ahTick(){
        if(!detTabActive())return;
        const h=await _jj('/api/attacker_hunts');
        const n=(h||[]).length;
        document.getElementById('ah-n').textContent=n;
        const o=document.getElementById('d-ah-n'); if(o)o.textContent=n;
        detRenderTable('ah-pre',h||[],[
          {key:'mac',label:'MAC'},{key:'type',label:'Type'},
          {key:'started',label:'Started',get:r=>_ago(r.started)},
          {key:'last_kick',label:'Last Kick',get:r=>_ago(r.last_kick)}
        ]);
        if(n>0)detMarkActive('hunts');
      }
      async function ahClear(){await fetch('/api/attacker_hunts/clear',{method:'POST'});ahTick();}
      async function kmTick(){
        if(!detTabActive())return;
        const [s,c]=await Promise.all([_jj('/api/karma/stats'),_jj('/api/karma')]);
        if(s){document.getElementById('km-on').textContent=s.enabled?'YES':'no';
              document.getElementById('km-c').textContent=s.candidates;
              document.getElementById('km-x').textContent=s.confirmed;}
        detRenderTable('km-pre',c||[],[
          {key:'bssid',label:'BSSID'},{key:'distinct_ssids',label:'SSIDs'},
          {key:'bait_emitted',label:'Bait'},{key:'confirmed',label:'Confirmed'},
          {key:'last_ssid',label:'Last SSID'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(s&&s.confirmed>0)detMarkActive('karma');
      }
      async function kmToggle(on){const fd=new FormData();fd.append('on',on);await fetch('/api/karma/enable',{method:'POST',body:fd});kmTick();}
      async function kmClear(){await fetch('/api/karma/clear',{method:'POST'});kmTick();}
      async function tsfTick(){
        if(!detTabActive())return;
        const t=await _jj('/api/tsf_skew');
        document.getElementById('tsf-n').textContent=(t||[]).length;
        detRenderTable('tsf-pre',t||[],[
          {key:'bssid',label:'BSSID'},{key:'ssid',label:'SSID'},
          {key:'ppm',label:'PPM'},{key:'samples',label:'N'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
      }
      async function tsfClear(){await fetch('/api/tsf_skew/clear',{method:'POST'});tsfTick();}
      async function tofTick(){
        if(!detTabActive())return;
        const t=await _jj('/api/tof');
        document.getElementById('tof-n').textContent=(t||[]).length;
        detRenderTable('tof-pre',t||[],[
          {key:'node',label:'Node'},{key:'last_rtt_us',label:'Last RTT us'},
          {key:'best_rtt_us',label:'Best us'},{key:'avg_rtt_us',label:'Avg us'},
          {key:'samples',label:'N'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
      }
      async function tofPing(){
        const tgt=document.getElementById('tof-target-in').value||'*';
        const fd=new FormData();fd.append('target',tgt);
        await fetch('/api/tof/ping',{method:'POST',body:fd});tofTick();
      }
      async function tofClear(){await fetch('/api/tof/clear',{method:'POST'});tofTick();}
      const _detLastActivity={};
      let _detSev='all';
      function detApplyFilters(){
        const q=(document.getElementById('det-filter').value||'').toLowerCase().trim();
        document.querySelectorAll('#page-detect .card').forEach(c=>{
          const h=c.querySelector('.card-header h3');
          const t=h?h.textContent.toLowerCase():'';
          const sev=c.dataset.sev||'';
          const key=c.dataset.key||'';
          let show=true;
          if(q && !t.includes(q)) show=false;
          if(_detSev==='crit'&&sev!=='crit') show=false;
          else if(_detSev==='high'&&!(sev==='crit'||sev==='high')) show=false;
          else if(_detSev==='med'&&!(sev==='crit'||sev==='high'||sev==='med')) show=false;
          else if(_detSev==='info'&&sev!=='info') show=false;
          else if(_detSev==='firing'&&!_detLastActivity[key]) show=false;
          c.classList.toggle('hidden', !show);
        });
        detSortByActivity();
      }
      function detSortByActivity(){
        const parent=document.getElementById('page-detect');
        if(!parent)return;
        const cards=[...parent.querySelectorAll('.card[data-key]')];
        cards.sort((a,b)=>{
          const aa=_detLastActivity[a.dataset.key]||0;
          const bb=_detLastActivity[b.dataset.key]||0;
          return bb-aa;
        });
        cards.forEach(c=>parent.appendChild(c));
      }
      const _detPageLoadMs = Date.now();

      let _sentToggleBusy=false;
      async function sentinelToggleHdr(){
        if(_sentToggleBusy) return;
        _sentToggleBusy=true;
        try {
          const sr = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!sr.ok) return;
          const s = await sr.json();
          const url = s.enabled ? '/api/sentinel/stop' : '/api/sentinel/start';
          const rr = await fetch(url, {method:'POST',cache:'no-store'});
          if (!rr.ok) alert('Sentinel toggle failed: ' + await rr.text());
          await new Promise(r=>setTimeout(r,500));
          await sentinelHdrRefresh();
          if (typeof sentinelRefresh==='function') await sentinelRefresh();
        } catch (err) {
          console.warn('sentinelToggleHdr failed', err);
        } finally { _sentToggleBusy=false; }
      }
      async function sentinelHdrRefresh(){
        try {
          const r = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!r.ok) return;
          const s = await r.json();
          const el = document.getElementById('sentStatusHdr');
          if (!el) return;
          if (s.scanning) {
            el.textContent = 'SENT KILL';
            el.style.color = '#fca5a5';
            el.style.borderColor = '#dc2626';
          } else if (s.running) {
            el.textContent = 'SENTINEL ON';
            el.style.color = '#86efac';
            el.style.borderColor = '#16a34a';
          } else {
            el.textContent = 'SENTINEL IDLE';
            el.style.color = '';
            el.style.borderColor = '';
          }
        } catch (err) {
          console.warn('sentinelHdrRefresh failed', err);
        }
      }
      setInterval(()=>{sentinelHdrRefresh(); if(typeof sentinelRefresh==='function')sentinelRefresh();}, 4000);
      setTimeout(sentinelHdrRefresh, 700);
      function detMarkActive(key){
        _detLastActivity[key]=Date.now();
        if (Date.now() - _detPageLoadMs < 10000) return;
        const card=document.querySelector('#page-detect .card[data-key="'+key+'"]');
        if(card){const sev=card.dataset.sev||'';if(sev==='crit'||sev==='high')detPushAlert(key,card);}
      }

      const VERIFIED_DETECTORS = new Set(['events','sentinel','overview','mesh','pmkid','eviltwin']);
      const DETECTOR_TOGGLE_KEYS = {
        'pmkid':'pmkidOn','eviltwin':'etwOn','ssidconf':'scnOn','saedos':'saeOn',
        'oweabuse':'oweOn','frag':'fragOn','blemal':'blemOn','karma':'karmaOn',
        'pwna':'pwnaOn','trackers':'trkOn','airtag':'atgOn','tsf':'tsfOn',
        'rid':'ridOn','probeflood':'pflOn','assocsleep':'aslOn','bleattack':'blatkOn',
        'pmkidforge':'pmkidOn','beaconforge':'etwOn','eapolbait':'pmkidOn',
        'handshake':'hshkOn','krack':'krackOn','hunts':'trlOn','csi':'csiOn'
      };
      let _detToggleState = {};
      async function detRefreshToggleState(){
        try {
          const r = await fetch('/api/detect/config');
          if (!r.ok) return;
          _detToggleState = await r.json();
          detApplyStatusPills();
        } catch (fetchErr) {
          console.warn('detRefreshToggleState failed', fetchErr);
        }
      }
      function detApplyStatusPills(){
        document.querySelectorAll('#page-detect .card[data-key] .dpill').forEach(p=>p.remove());
      }
      setInterval(detRefreshToggleState, 10000);
      setTimeout(detRefreshToggleState, 600);
      const _detAlerts=[];
      function detPushAlert(key,card){
        const title=card.querySelector('.card-header h3');
        let txt=key;
        if(title){
          const clone=title.cloneNode(true);
          clone.querySelectorAll('.sev,.num,.dpill').forEach(n=>n.remove());
          txt=clone.textContent.replace(/\\s+/g,' ').trim();
          if(!txt)txt=key;
        }
        const toggleKey=DETECTOR_TOGGLE_KEYS[key];
        if(toggleKey){
          if(!_detToggleState || Object.keys(_detToggleState).length===0)return;
          if(_detToggleState[toggleKey]!==true)return;
        }
        const sev=card.dataset.sev||'med';
        const exists=_detAlerts.find(a=>a.key===key);
        if(exists){exists.ts=Date.now();return;}
        _detAlerts.unshift({key,txt,sev,ts:Date.now()});
        while(_detAlerts.length>5)_detAlerts.pop();
        detRenderBanner();
      }
      function detRenderBanner(){
        const b=document.getElementById('det-banner');const bd=document.getElementById('det-banner-body');
        if(!b||!bd)return;
        if(_detAlerts.length===0){b.classList.remove('show');bd.innerHTML='';return;}
        const now=Date.now();
        const fresh=_detAlerts.filter(a=>now-a.ts<300000).slice(0,3);
        if(fresh.length===0){b.classList.remove('show');return;}
        b.classList.add('show');
        bd.innerHTML = fresh.map(a => {
          const secs = Math.floor((now - a.ts) / 1000);
          const when = secs < 60 ? `${secs}s ago` : `${Math.floor(secs / 60)}m ago`;
          const escapedKey = a.key.replace(/'/g, "\\'");
          
          return `<div class="bn-row" onclick="detJump('${escapedKey}')">` +
          `<span class="sev ${a.sev}" style="margin-right:6px;">${a.sev}</span>` +
          `<span class="bn-when" style="margin-right:8px;">${when}</span>` +
          `<span class="bn-msg">${a.txt}</span></div>`;
        }).join('');
      }
      setInterval(detRenderBanner,5000);

      const DETECTOR_TAB_MAP = {
        'events':'live','sentinel':'live','mesh':'config','config':'config',
        'overview':'live','apclients':'live',
        'dctl':'detectors','dos':'detectors','rogue':'detectors','recongrp':'detectors',
        'blegrp':'detectors','dronegrp':'detectors','physical':'detectors','meshcfg':'detectors',
        'rid':'details','recon':'details','trackers':'details',
        'airtag':'details','csi':'details','karma':'details','hunts':'details',
        'handshake':'details','bcnforge':'details','pmkidforge':'details',
        'eapolbait':'details','probeflood':'details','assocsleep':'details',
        'bleattack':'details','probegraph':'details','tsf':'details','tof':'details',
        'pmkid':'details','eviltwin':'details','ssidconf':'details',
        'saedos':'details','oweabuse':'details','frag':'details','blemal':'details',
        'pwna':'details','krack':'details'
      };

      function _detCardTab(c){
        const key=c.dataset.key||'';
        let cardTab=DETECTOR_TAB_MAP[key];
        if(!cardTab){
          const txt=(c.querySelector('h3')?.textContent||'').toLowerCase();
          if(txt.includes('detector controls')||txt.includes('threshold'))cardTab='config';
          else if(txt.includes('overview'))cardTab='live';
          else if(txt.includes('mesh defense'))cardTab='config';
          else if(c.dataset.sev&&key!=='events')cardTab='details';
          else cardTab='detectors';
        }
        return cardTab;
      }
      function detSetTab(tab){
        document.querySelectorAll('#det-tabs button.dtab').forEach(b=>{
          b.classList.toggle('active', b.dataset.dtab===tab);
        });
        document.querySelectorAll('#page-detect .card').forEach(c=>{
          c.classList.toggle('dtab-hidden', _detCardTab(c)!==tab);
        });
        document.querySelectorAll('[data-dtab-target]').forEach(el=>{
          const allowed=el.dataset.dtabTarget.split(',');
          el.classList.toggle('dtab-hidden', !allowed.includes(tab));
        });
        if (window.localStorage) {
          try {
            localStorage.setItem('detTab', tab);
          } catch (storageErr) {
            console.warn('detSetTab: localStorage write failed (private mode?)', storageErr);
          }
        }
      }
      function detTabRestore(){
        let saved = 'live';
        if (window.localStorage) {
          try {
            saved = localStorage.getItem('detTab') || 'live';
          } catch (storageErr) {
            console.warn('detSetTab: localStorage read failed (private mode?)', storageErr);
          }
        }
        if (saved !== 'live' && saved !== 'detectors' && saved !== 'details') saved = 'live';
        setTimeout(()=>detSetTab(saved), 50);
      }
      detTabRestore();

      function detJump(key){
        const card=document.querySelector('#page-detect .card[data-key="'+key+'"]');
        if(!card)return;
        const body=card.querySelector('.card-body');
        if(body&&body.classList.contains('collapsed')){
          const id=card.querySelector('.card-header').getAttribute('onclick');
          if(id){const m=id.match(/toggleCollapse\\(['"]([^'"]+)['"]\\)/);if(m)toggleCollapse(m[1]);}
        }
        card.scrollIntoView({behavior:'smooth',block:'start'});
      }
      document.querySelectorAll('#det-chips .det-chip').forEach(c=>{
        c.addEventListener('click',()=>{
          _detSev=c.dataset.sev;
          document.querySelectorAll('#det-chips .det-chip').forEach(x=>x.classList.remove('firing'));
          c.classList.add('firing');
          detApplyFilters();
        });
      });
        function detRenderTable(elId, rows, cols) {
          const el = document.getElementById(elId);
          if (!el) return;
          
          if (!rows || rows.length === 0) {
            el.innerHTML = '<table class="dt"><tr><td class="empty">(none)</td></tr></table>';
            return;
          }
          
          const thead = cols
          .map((c, i) => `<th onclick="detTableSort('${elId}', ${i})">${c.label}</th>`)
          .join('');
          
          const tbody = rows
          .map(r => {
            const tds = cols
            .map(c => {
              const v = c.get ? c.get(r) : r[c.key];
              const val = v === undefined || v === null ? '-' : v;
              const escaped = String(val).replace(/"/g, '&quot;');
              return `<td title="${escaped}">${val}</td>`;
            })
            .join('');
            return `<tr>${tds}</tr>`;
          })
          .join('');
          
          el.innerHTML = `<table class="dt"><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table>`;
          el._detRows = rows;
          el._detCols = cols;
        }
        function detTableSort(id,colIdx){
        const el=document.getElementById(id);if(!el||!el._detRows)return;
        const c=el._detCols[colIdx];const k=c.key;
        const prev=el._detSortK===k?el._detSortAsc:false;
        el._detSortK=k;el._detSortAsc=!prev;
        el._detRows.sort((a,b)=>{
          const av=c.get?c.get(a):a[k],bv=c.get?c.get(b):b[k];
          if(av<bv)return prev?1:-1;if(av>bv)return prev?-1:1;return 0;
        });
        detRenderTable(id,el._detRows,el._detCols);
      }
      function _ago(ms){
        if(!ms)return '-';
        const s=Math.floor((Date.now()-ms)/1000);
        if(s<60)return s+'s';
        if(s<3600)return Math.floor(s/60)+'m';
        return Math.floor(s/3600)+'h';
      }
      const DET_FEATURES_LOCAL=[
        ['pmkid','PMKID Harvest'],['eviltwin','Evil-Twin / Beacon Forgery'],['ssid_confusion','SSID Confusion'],
        ['sae','SAE DoS'],['owe','OWE Abuse'],['frag','FragAttacks'],
        ['ble_malformed','BLE Malformed'],['hshk','Handshake Reconstruction'],
        ['tracker','BLE Tracker'],['airtag','AirTag (+ Replay)'],
        ['tsf','TSF Clock-Skew'],['rid_spoof','RID Spoof Validator'],
        ['bloom_gossip','Bloom Gossip'],['attacker_trilat','Attacker Trilat'],
        ['karma','KARMA Bait'],['csi','CSI Presence'],
        ['probe_flood','Probe Flood'],['assoc_sleep','Assoc Sleep'],
        ['ble_attack','BLE Attack Tools']
      ];
      const DET_FEATURES_MESH=[
        ['mesh_pmkid','PMKID'],['mesh_eviltwin','Evil-Twin'],['mesh_ssid_confusion','SSID Conf'],
        ['mesh_sae','SAE'],['mesh_frag','FragAttacks'],['mesh_ble_malformed','BLE Malformed'],
        ['mesh_hshk','Handshakes'],['mesh_krack','KRACK'],['mesh_tracker','Tracker'],
        ['mesh_karma','KARMA'],['mesh_recon','Recon'],
        ['mesh_csi_motion','CSI Motion'],['mesh_attacker_hunt','Attacker Hunt']
      ];
      const DET_THRESHOLDS=[
        ['csi_thresh','CSI Threshold Q8',100,10000],
        ['pmkid_window','PMKID Window (ms)',1000,60000],
        ['pmkid_min_bssids','PMKID Min BSSIDs',2,10],
        ['sae_window','SAE Window (ms)',1000,60000],
        ['sae_unmatched_thresh','SAE Unmatched',3,50],
        ['frag_reuse_thresh','FragAttacks Reuse Count',2,32],
        ['probe_single_thresh','Probe Flood: 1-MAC probes /5s',10,500],
        ['probe_rand_total','Probe Flood: randomized total /5s',10,1000],
        ['probe_rand_distinct','Probe Flood: randomized distinct MACs /5s',5,500],
        ['hunt_cooldown_ms','Hunt Cooldown (ms)',5000,600000]
      ];
      let _detCfg=null;
      function detRenderConfig(){
        if(!_detCfg)return;
        // Tool-fingerprint detectors (tool/tool byte/behavior matches) split out
        // for clarity. Re-classifying probe_flood + assoc_sleep + ble_attack here.
        const toolKeys=['probe_flood','assoc_sleep','ble_attack'];
        const wifiKeys=['pmkid','eviltwin','ssid_confusion','sae','owe','frag','hshk','attacker_trilat','rid_spoof'];
        const bleKeys=['ble_malformed','tracker','airtag','karma','csi'];
        const meshKeys=DET_FEATURES_MESH.map(x=>x[0]);
        const tsfKey='tsf';const bloomKey='bloom_gossip';
        function rowHtml(k,label){
          const on=_detCfg[k]===true;
          return `<div class="det-row"><div class="name">${label}</div>
            <label><input type="checkbox" data-cfg="${k}" ${on?'checked':''}> enabled</label></div>`;
        }
        function rowMesh(k,label){
          const on=_detCfg[k]===true;
          return `<div class="det-row"><div class="name">${label}</div>
            <label><input type="checkbox" data-cfg="${k}" ${on?'checked':''}> broadcast</label></div>`;
        }
        const meshEl=document.getElementById('cfg-mesh');
        if(meshEl)meshEl.innerHTML=DET_FEATURES_MESH.map(p=>rowMesh(p[0],p[1])).join('');
        const threshEl=document.getElementById('cfg-thresh');
        if(threshEl){
          let threshHtml='';
          DET_THRESHOLDS.forEach(t=>{
            const v=_detCfg[t[0]]||t[2];
            threshHtml+=`<div><label style="font-size:11px;color:var(--mut);">${t[1]}</label>
              <input type="number" data-thr="${t[0]}" value="${v}" min="${t[2]}" max="${t[3]}" style="width:100%"></div>`;
          });
          threshEl.innerHTML=threshHtml;
        }
        document.querySelectorAll('#cfg-mesh input').forEach(el=>{
          el.addEventListener('change',()=>detPostCfg({[el.dataset.cfg]:el.checked}));
        });
      }
      async function detPostCfg(patch){
        Object.assign(_detCfg||(_detCfg={}),patch);
        if(typeof renderDos==='function')renderDos();
        await fetch('/api/detect/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
      }
      // Threat-scenario groups. Keys map to existing detector toggles.
      // ssid_confusion intentionally excluded: CVE-2023-52424 is a client-side
      // supplicant flaw, not observable from an AP-side sniffer (see docs/detector-verification.md).
      // bloom_gossip + attacker_trilat are infra/response actions, not detectors -> excluded from groups.
      // NOTE: deauth detection is unconditional (no toggle); WPS/WPA3/evil_portal detectors
      // are staged and will get their own toggle keys during the detector build.
      const DET_GROUPS={
        dos:      ['eviltwin','sae','assoc_sleep'],
        rogue_ap: ['eviltwin','owe','karma'],
        recon:    ['pmkid','probe_flood','hshk'],
        physical: ['frag','tsf','csi']
      };
      const DET_ALL_LOCAL=['pmkid','eviltwin','sae','owe','frag','hshk',
        'tsf','karma','csi','probe_flood','assoc_sleep'];
      const DET_ALL_MESH=['mesh_pmkid','mesh_eviltwin','mesh_sae','mesh_frag','mesh_ble_malformed',
        'mesh_hshk','mesh_krack','mesh_tracker','mesh_karma','mesh_recon','mesh_csi_motion','mesh_attacker_hunt'];
      // Turn a single threat group on or off (members only; leaves other detectors untouched).
      async function detGroupToggle(group){
        const members=DET_GROUPS[group]; if(!members) return;
        const cfg=_detCfg||{};
        const anyOn=members.some(k=>cfg[k]);
        await detGroup(group, !anyOn);
      }
      async function detGroup(group,on){
        const members=DET_GROUPS[group]; if(!members) return;
        const patch={}; members.forEach(k=>patch[k]=!!on);
        await detPostCfg(patch); await detLoadCfg();
      }
      async function detPreset(name){
        let patch={};
        if(name==='all-on'){DET_ALL_LOCAL.forEach(k=>patch[k]=true);DET_ALL_MESH.forEach(k=>patch[k]=true);}
        else if(name==='all-off'){DET_ALL_LOCAL.forEach(k=>patch[k]=false);DET_ALL_MESH.forEach(k=>patch[k]=false);}
        else if(name==='quiet'){patch={frag:false,ble_malformed:false,tsf:false,csi:false,mesh_frag:false,mesh_ble_malformed:false,mesh_hshk:false,mesh_csi_motion:false};}
        else if(name==='mesh-silent'){DET_ALL_MESH.forEach(k=>patch[k]=false);}
        else if(name==='mesh-all'){DET_ALL_MESH.forEach(k=>patch[k]=true);}
        await detPostCfg(patch);
        await detLoadCfg();
      }
      function detSaveThresh(){
        const patch={};
        document.querySelectorAll('input[data-thr]').forEach(el=>{
          const v=parseInt(el.value,10);
          if(!isNaN(v))patch[el.dataset.thr]=v;
        });
        detPostCfg(patch);
      }
      async function detLoadCfg(){
        _detCfg=await _jj('/api/detect/config');
        detRenderConfig();
        if(typeof renderDos==='function')renderDos();
      }
      async function detHealthTick(){
        const tab=document.getElementById('page-detect');
        if(!tab||!tab.classList.contains('active'))return;
        const h=await _jj('/api/detect/health');
        if(!h)return;
        document.getElementById('d-heap').textContent=Math.round(h.heap_free/1024)+'K (min '+Math.round(h.heap_min/1024)+'K)';
        document.getElementById('d-drops').textContent='wifi:'+h.drops.wifi+' ble:'+h.drops.ble+' csi:'+h.drops.csi;
        document.getElementById('d-mgated').textContent=h.drops.mesh_gated;
      }
      function detTabActive(){
        const tab=document.getElementById('page-detect');
        return tab&&tab.classList.contains('active');
      }
      function renderDetailsVisibility(){
        try{
          document.querySelectorAll('#page-detect .card').forEach(c=>{
            if(_detCardTab(c)!=='details')return;
            const body=c.querySelector('.card-body'); if(!body)return;
            let txt='';
            body.querySelectorAll('pre,table,.det-table').forEach(e=>txt+=e.textContent||'');
            const t=txt.trim();
            const empty=(t===''||/^[-\s\[\]]*$/.test(t));
            c.classList.toggle('det-empty-hidden', empty);
          });
        }catch(e){console.warn('renderDetailsVisibility',e);}
      }
      async function apClientsTick(){
        try{
          const r=await fetch('/api/apclients.json'); if(!r.ok)return;
          const a=await r.json(); const el=document.getElementById('apClientsArea'); if(!el)return;
          if(!a.length){el.innerHTML='<div style="color:var(--mut);font-size:12px;">No clients yet.</div>';return;}
          const ago=ms=>ms<60000?Math.round(ms/1000)+'s':Math.round(ms/60000)+'m';
          el.innerHTML='<table class="dt"><thead><tr><th>Client MAC</th><th>Assoc #</th><th>First</th><th>Last</th></tr></thead><tbody>'
            +a.map(c=>`<tr><td style="color:#bbf7d0;">${c.mac}</td><td>${c.assoc}</td><td>${ago(c.first_ms_ago)} ago</td><td>${ago(c.last_ms_ago)} ago</td></tr>`).join('')
            +'</tbody></table>';
        }catch(e){console.warn('apClientsTick',e);}
      }
      function detAllTicks(){
        if(!detTabActive())return;
        detectTick();csiTick();pgTick();trkTick();atTick();hsTick();
        ahTick();kmTick();tsfTick();tofTick();detHealthTick();
        bfTick();pfTick();ebTick();pflTick();asTick();baTick();apClientsTick();
        setTimeout(renderDetailsVisibility,300);
      }
      async function _jsonl(path){
        try{const r=await fetch(path);if(!r.ok)return [];const t=await r.text();
          return t.split('\n').filter(x=>x.trim()).map(x=>{try{return JSON.parse(x)}catch(_){return null}}).filter(x=>x);}
        catch(_){return []}
      }
      function _renderJsonl(elId,arr,cols){
        const el=document.getElementById(elId);if(!el)return;
        if(arr.length===0){el.textContent='--';return;}
        const rows=arr.slice(-50).reverse().map(r=>cols.map(c=>{const v=r[c];return v===undefined?'':String(v)}).join(' | '));
        el.textContent=cols.join(' | ')+'\n'+rows.join('\n');
      }
      async function bfTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/eviltwin.jsonl');
        const forge=a.filter(r=>r.reason&&r.reason.indexOf('FORGE_')===0);
        document.getElementById('bf-n').textContent=forge.length;
        _renderJsonl('bf-pre',forge,['ts','bssid','ssid','reason','rssi','ch']);
        if(forge.length>0)detMarkActive('bcnforge');
      }
      async function bfClear(){await fetch('/api/eviltwin/clear',{method:'POST'});bfTick();}
      async function pfTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/pmkid_forge.jsonl');
        document.getElementById('pf-n').textContent=a.length;
        _renderJsonl('pf-pre',a,['ts','src','sta','keyinfo','rssi','ch']);
        if(a.length>0)detMarkActive('pmkidforge');
      }
      async function pfClear(){await fetch('/api/pmkid_forge/clear',{method:'POST'});pfTick();}
      async function ebTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/eapol_bait.jsonl');
        document.getElementById('eb-n').textContent=a.length;
        _renderJsonl('eb-pre',a,['ts','src','sta','deauth_count','latency_ms','confidence','rssi']);
        if(a.length>0)detMarkActive('eapolbait');
      }
      async function ebClear(){await fetch('/api/eapol_bait/clear',{method:'POST'});ebTick();}
      async function pflTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/probe_flood.jsonl');
        document.getElementById('pfl-n').textContent=a.length;
        _renderJsonl('pfl-pre',a,['ts','ssid','hits','distinct_src','rssi','reason']);
        if(a.length>0)detMarkActive('probeflood');
      }
      async function pflClear(){await fetch('/api/probe_flood/clear',{method:'POST'});pflTick();}
      async function asTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/assoc_sleep.jsonl');
        document.getElementById('as-n').textContent=a.length;
        _renderJsonl('as-pre',a,['ts','bssid','distinct_src','rssi','ch']);
        if(a.length>0)detMarkActive('assocsleep');
      }
      async function asClear(){await fetch('/api/assoc_sleep/clear',{method:'POST'});asTick();}
      async function baTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/ble_attack.jsonl');
        document.getElementById('ba-n').textContent=a.length;
        _renderJsonl('ba-pre',a,['ts','tool','addr','family','rssi','reason']);
        if(a.length>0)detMarkActive('bleattack');
      }
      async function baClear(){await fetch('/api/ble_attack/clear',{method:'POST'});baTick();}
      async function detectAssignChannels(){await fetch('/api/channel_partition',{method:'POST'});detectTick()}
      async function detectClearTrackers(){await fetch('/api/ble_tracker/clear',{method:'POST'});detectTick()}
      async function detectClearRecon(){await fetch('/api/recon/clear',{method:'POST'});detectTick()}
      async function detectReloadOui(){await fetch('/api/oui/reload',{method:'POST'});detectTick()}
      detLoadCfg();
      setInterval(detAllTicks,5000);
      detAllTicks();
    </script>
  </body>
</html>
)HTML";

void startWebServer()
{
  if (!server)
    server = new AsyncWebServer(80);

    ws.onEvent(onTerminalEvent);
    server->addHandler(&ws);

    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type");

  server->on("/", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        AsyncWebServerResponse* res = r->beginResponse(200, "text/html", reinterpret_cast<const uint8_t*>(INDEX_HTML), strlen_P(INDEX_HTML));
        res->addHeader("Cache-Control", "no-store");
        r->send(res); });

  server->on("/export", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getTargetsList()); });

  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r) {
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
      // Radio-busy guard: reject if any scan task is already running
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
          xTaskCreatePinnedToCore(listScanTask, "scan", 8192, reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
      }
  });

  server->on("/baseline/status", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = "{";
      json += "\"scanning\":" + String(scanning ? "true" : "false") + ",";
      json += "\"established\":" + String(baselineEstablished ? "true" : "false") + ",";
      json += "\"devices\":" + String(baselineDeviceCount);
      json += "}";
      
      req->send(200, "application/json", json);
  });

  server->on("/baseline/stats", HTTP_GET, [](AsyncWebServerRequest *req) {
      String json = "{";
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
    json += "\"established\":" + String(baselineEstablished ? "true" : "false") + ",";
    json += "\"deviceCount\":" + String(baselineDeviceCount) + ",";
    json += "\"anomalyCount\":" + String(anomalyCount);
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
          baselineDuration = req->getParam("baselineDuration", true)->value().toInt() * 1000;
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
        uint64_t totalBytes = SD.totalBytes();
        uint64_t usedBytes = SD.usedBytes();
        uint64_t freeBytes = totalBytes - usedBytes;

        // Get log file size
        uint32_t logSize = 0;
        File logFile = SafeSD::open("/antihunter.log", FILE_READ);
        if (logFile) {
            logSize = logFile.size();
            logFile.close();
        }

        status = "SD Card: Available\n";
        status += "Card Size: " + String(cardSize) + " MB\n";
        status += "Total Space: " + String(totalBytes / (1024 * 1024)) + " MB\n";
        status += "Used Space: " + String(usedBytes / (1024 * 1024)) + " MB\n";
        status += "Free Space: " + String(freeBytes / (1024 * 1024)) + " MB\n";
        status += "Log File Size: " + String(logSize / 1024) + " KB (" + String(logSize) + " bytes)";
    }
    r->send(200, "text/plain", status); });

  server->on("/stop", HTTP_GET, [](AsyncWebServerRequest *req) {
      stopRequested = true;

      // Stop triangulation if active
      if (triangulationActive) {
          stopTriangulation();
      }

      scanning = false;

      req->send(200, "text/plain", "Scan stopped");
  });

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
      if (!req->hasParam("channels") || !req->hasParam("targets")) {
          req->send(400, "text/plain", "Missing parameters");
          return;
      }

      String channelsCSV = req->getParam("channels")->value();
      parseChannelsCSV(channelsCSV);
      prefs.putString("channels", channelsCSV);

      String targets = req->getParam("targets")->value();
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
            xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288,
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
        status += "\"unique\":" + String(detectedDrones.size());
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

  server->on("/diag", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        String s = getDiagnostics();
        r->send(200, "text/plain", s); });

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
    if (confirm != "WIPE_ALL_DATA") {
        req->send(400, "text/plain", "Invalid confirmation");
        return;
    }
    
    String reason = req->hasParam("reason", true) ? req->getParam("reason", true)->value() : "Manual web request";
    req->send(200, "text/plain", "Secure erase initiated");
    
    xTaskCreate([](void* param) {
        String* reasonPtr = static_cast<String*>(param);
        delay(1000); // Give web server time to send response
        bool success = executeSecureErase(*reasonPtr);
        Serial.println(success ? "Erase completed" : "Erase failed");
        delete reasonPtr;
        vTaskDelete(NULL);
    }, "secure_erase", 8192, new String(reason), 1, NULL); });

  server->on("/erase/cancel", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    cancelTamperErase();
    req->send(200, "text/plain", "Tamper erase cancelled"); });

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
                xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 12288, reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &blueTeamTaskHandle, 1);
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
                xTaskCreatePinnedToCore(baselineDetectionTask, "baseline", 12288,
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
                xTaskCreatePinnedToCore(randomizationDetectionTask, "randdetect", 8192,
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
                        probeRequestQueue = xQueueCreate(256, sizeof(ProbeRequestEvent));
                    } else {
                        xQueueReset(probeRequestQueue);
                    }
                }

                scanning = true;
                xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288,
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
                xTaskCreatePinnedToCore(probeDetectionTask, "probedet", 8192,
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
                xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288,
                                    reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)),
                                    1, &workerTaskHandle, 1);
            }
            
        } else {
            req->send(400, "text/plain", "Unknown detection mode");
        }
    });

  server->on("/deauth-results", HTTP_GET, [](AsyncWebServerRequest *r) {
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
      resetRandomizationDetection();
      r->send(200, "text/plain", "Randomization detection reset");
  });

  server->on("/randomization/clear-old", HTTP_POST, [](AsyncWebServerRequest *req) {
      std::lock_guard<std::mutex> lock(randMutex);
      
      uint32_t now = millis();
      uint32_t ageThreshold = 3600000; // 1 hour
      
      if (req->hasParam("age", true)) {
          ageThreshold = req->getParam("age", true)->value().toInt() * 1000;
      }
      
      std::vector<String> toRemove;
      for (const auto& entry : deviceIdentities) {
          if ((now - entry.second.lastSeen) > ageThreshold) {
              toRemove.push_back(entry.first);
          }
      }
      
      for (const auto& key : toRemove) {
          deviceIdentities.erase(key);
      }
      
      saveDeviceIdentities();
      
      req->send(200, "text/plain", "Removed " + String(toRemove.size()) + " old identities");
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
          json += "\"channelSeqLen\":" + String(track.signature.channelSeqLength) + ",";
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

  server->on("/allowlist-export", HTTP_GET, [](AsyncWebServerRequest *r)
           { r->send(200, "text/plain", getAllowlistText()); });

  server->on("/allowlist-save", HTTP_POST, [](AsyncWebServerRequest *req)
            {
        if (!req->hasParam("list", true)) {
            req->send(400, "text/plain", "Missing 'list'");
            return;
        }
        String txt = req->getParam("list", true)->value();
        saveAllowlist(txt);
        saveConfiguration();
        req->send(200, "text/plain", "Allowlist saved"); });

  server->on("/triangulate/start", HTTP_POST, [](AsyncWebServerRequest *req) {
      // Radio-busy guard: reject if any scan task is already running
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
    String json = "{";
    json += "\"active\":" + String(triangulationActive ? "true" : "false") + ",";
    json += "\"target\":\"" + macFmt6(triangulationTarget) + "\",";
    json += "\"duration\":" + String(triangulationDuration) + ",";
    json += "\"elapsed\":" + String((millis() - triangulationStart) / 1000) + ",";
    json += "\"nodes\":" + String(triangulationNodes.size());
    json += "}";
    req->send(200, "application/json", json);
  });

  server->on("/triangulate/results", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (triangulationNodes.size() == 0) {
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
      if (apFinalResult.hasResult) {
          json += "\"finalResult\":{";
          json += "\"lat\":" + String(apFinalResult.latitude, 6) + ",";
          json += "\"lon\":" + String(apFinalResult.longitude, 6) + ",";
          json += "\"confidence\":" + String(apFinalResult.confidence * 100.0, 1) + ",";
          json += "\"uncertainty\":" + String(apFinalResult.uncertainty, 1) + ",";
          json += "\"coordinator\":\"" + apFinalResult.coordinatorNodeId + "\"";
          json += "},";
      }

      // Add nodes array
      json += "\"nodes\":[";
      for (size_t i = 0; i < triangulationNodes.size(); i++) {
          const auto& node = triangulationNodes[i];
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
          if (i < triangulationNodes.size() - 1) {
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
        uint32_t wsi = req->getParam("wifiScanInterval", true)->value().toInt();
        uint32_t bsi = req->getParam("bleScanInterval", true)->value().toInt();
        uint32_t bsd = req->getParam("bleScanDuration", true)->value().toInt();
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

  // --- Data tab API endpoints ---

  server->on("/api/deauth.jsonl", HTTP_GET, [](AsyncWebServerRequest *req) {
      if (SD.exists("/deauth.jsonl")) {
          req->send(SD, "/deauth.jsonl", "application/x-ndjson");
      } else {
          req->send(404, "text/plain", "No deauth log file");
      }
  });

  server->on("/api/deauth/clear", HTTP_POST, [](AsyncWebServerRequest *req) {
      deauthLog.clear();
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
      droneEventLog.clear();
      detectedDrones.clear();
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
        static String acc;
        if (index == 0) acc = "";
        for (size_t i = 0; i < len; ++i) acc += (char)data[i];
        if (index + len == total) {
            detect_setConfigFromJson(acc);
            detect_persistTunables();
            acc = "";
        }
    });

  server->on("/api/csi/motion.jsonl", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/x-ndjson", csi_getMotionJsonl());
  });
  server->on("/api/csi/fingerprints", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "application/json", csi_getFingerprintJson());
  });
  server->on("/api/csi/stats", HTTP_GET, [](AsyncWebServerRequest *r) {
      String j = String("{\"enabled\":") + (csi_isEnabled() ? "true" : "false") +
                 ",\"pkts\":" + String(csi_packetsObserved()) +
                 ",\"motion_events\":" + String(csi_motionEvents()) +
                 ",\"thresh_q8\":" + String(csi_getMotionThreshold()) + "}";
      r->send(200, "application/json", j);
  });
  server->on("/api/csi/enable", HTTP_POST, [](AsyncWebServerRequest *r) {
      bool on = true;
      if (r->hasParam("on", true)) on = r->getParam("on", true)->value().toInt() != 0;
      csi_enable(on);
      r->send(200, "application/json", on ? "{\"enabled\":true}" : "{\"enabled\":false}");
  });
  server->on("/api/csi/threshold", HTTP_POST, [](AsyncWebServerRequest *r) {
      uint16_t v = 1500;
      if (r->hasParam("v", true)) v = (uint16_t)r->getParam("v", true)->value().toInt();
      csi_setMotionThreshold(v);
      r->send(200, "application/json", "{\"ok\":true}");
  });
  server->on("/api/csi/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
      csi_clear();
      r->send(200, "text/plain", "cleared");
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
      r->send(200, "text/html", (const uint8_t*)HTML, strlen_P(HTML));
  });

  server->begin();
  Serial.println("[WEB] Server started.");
}

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

    if (msg_len > 0 && msg_len <= sizeof(mesh_msg) - 1) {
        delay(10);
        Serial.printf("[MESH] %s\n", mesh_msg);
        sendToSerial1(String(mesh_msg), false);
    }
}

void initializeMesh() {
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

    serial1Mutex = xSemaphoreCreateMutex();

    Serial.println("[MESH] UART initialized");
    Serial.printf("[MESH] Config: 115200 baud on GPIO RX=%d TX=%d\n", MESH_RX_PIN, MESH_TX_PIN);
}

// --- Command Handlers ---

static void handleConfigChannels(const String &command)
{
  String channels = command.substring(16);
  parseChannelsCSV(channels);
  prefs.putString("channels", channels);
  saveConfiguration();
  Serial.printf("[MESH] Updated channels: %s\n", channels.c_str());
  sendToSerial1(nodeId + ": CONFIG_ACK:CHANNELS:" + channels, true);
}

static void handleConfigTargets(const String &command)
{
  String targets = command.substring(15);
  saveTargetsList(targets);
  Serial.printf("[MESH] Updated targets list\n");
  sendToSerial1(nodeId + ": CONFIG_ACK:TARGETS:OK", true);
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
        xTaskCreatePinnedToCore(listScanTask, "scan", 8192,
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
    xTaskCreatePinnedToCore(baselineDetectionTask, "baseline", 12288,
                            reinterpret_cast<void*>(static_cast<intptr_t>(forever ? 0 : secs)), 1, &workerTaskHandle, 1);
    Serial.printf("[MESH] Started baseline detection via mesh command (%ds)\n", secs);
    sendToSerial1(nodeId + ": BASELINE_ACK:STARTED", true);
  }
}

static void handleBaselineStatus(const String &command)
{
  (void)command;
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
           "%s: BASELINE_STATUS: Scanning:%s Established:%s Devices:%u Anomalies:%u Phase1:%s",
           nodeId.c_str(),
           baselineStats.isScanning ? "YES" : "NO",
           baselineEstablished ? "YES" : "NO",
           baselineDeviceCount,
           anomalyCount,
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
      xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288,
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
    xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288,
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
    xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 12288,
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
      xTaskCreatePinnedToCore(randomizationDetectionTask, "randdetect", 8192,
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
    xTaskCreatePinnedToCore(probeDetectionTask, "probedet", 8192,
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
  broadcastToTerminal("[PROBE_HIT] " + payload);
}

static void handleStop(const String &command)
{
  (void)command;
  stopRequested = true;
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
  char msg[48];
  snprintf(msg, sizeof(msg), "[VIB] Vibration broadcasts %s", label);
  broadcastToTerminal(msg);
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
    while (workerTaskHandle) {
      vTaskDelay(pdMS_TO_TICKS(100));
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
      extern std::mutex triAccumMutex;  // cppcheck-suppress shadowVariable
      // cppcheck-suppress localMutex
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
      xTaskCreatePinnedToCore(listScanTask, "triangulate", 8192,
                             reinterpret_cast<void*>(static_cast<intptr_t>(triangulationDuration)), 1, &workerTaskHandle, 1);
    }
  }
}

static void handleTriangulateResults(const String &command)
{
  (void)command;
  if (triangulationNodes.size() > 0) {
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
  String token = command.substring(12);
  if (validateEraseToken(token))
  {
    executeSecureErase("Force command");
    sendToSerial1(nodeId + ": ERASE_ACK:COMPLETE", true);
  }
}

static void handleEraseCancel(const String &command)
{
  (void)command;
  cancelTamperErase();
  sendToSerial1(nodeId + ": ERASE_ACK:CANCELLED", true);
}

static void handleEraseRequest(const String &command)
{
  (void)command;
  // Generate token without starting countdown - countdown only starts on ERASE_FORCE
  if (tamperAuthToken.length() == 0) {
    tamperAuthToken = generateEraseToken();
    Serial.printf("[ERASE] Token generated on request: %s\n", tamperAuthToken.c_str());
  }

  sendToSerial1(nodeId + ": ERASE_TOKEN:" + tamperAuthToken + " Expires:300s", true);
  Serial.printf("[ERASE] Token provided - valid for 5 minutes\n");
}

static void handleAutoeraseEnable(const String &command)
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

  // Send SETUP_MODE alert
  String setupModeAlert = nodeId + ": SETUP_MODE: Auto-erase activates in " + String(setupDelay/1000) + "s";
  sendToSerial1(setupModeAlert, false);
}

static void handleAutoeraseDisable(const String &command)
{
  (void)command;
  autoEraseEnabled = false;
  inSetupMode = false;
  saveConfiguration();
  sendToSerial1(nodeId + ": AUTOERASE_ACK:DISABLED", true);
  Serial.println("[AUTOERASE] Disabled");
}

static void handleAutoeraseStatus(const String &command)
{
  (void)command;
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
  broadcastToTerminal("[BATTERY_SAVER] Started with " + String(intervalMinutes) + " minute heartbeat");
}

static void handleBatterySaverStop(const String &command)
{
  (void)command;
  exitBatterySaver();
  sendToSerial1(nodeId + ": BATTERY_SAVER_ACK:STOPPED", true);
  Serial.println("[MESH] Battery saver stopped");
  broadcastToTerminal("[BATTERY_SAVER] Stopped");
}

static void handleBatterySaverStatus(const String &command)
{
  (void)command;
  String status = getBatterySaverStatus();
  sendToSerial1(status, true);
  broadcastToTerminal(status);
}

static void handleHbOn(const String &command)
{
  (void)command;
  hbEnabled = true;
  prefs.putBool("hbEnabled", true);
  lastSaveTime = 0;
  saveConfiguration();
  sendToSerial1(nodeId + ": HB_ACK:ENABLED", true);
  broadcastToTerminal("[HB] Status heartbeat enabled");
}

static void handleHbOff(const String &command)
{
  (void)command;
  hbEnabled = false;
  prefs.putBool("hbEnabled", false);
  lastSaveTime = 0;
  saveConfiguration();
  sendToSerial1(nodeId + ": HB_ACK:DISABLED", true);
  broadcastToTerminal("[HB] Status heartbeat disabled");
}

static void handleHbInterval(const String &command)
{
  uint32_t minutes = command.substring(12).toInt();
  if (minutes < 1) minutes = 1;
  if (minutes > 60) minutes = 60;
  hbInterval = minutes * 60000;
  prefs.putUInt("hbInterval", hbInterval);
  sendToSerial1(nodeId + ": HB_ACK:INTERVAL " + String(minutes) + "min", true);
  broadcastToTerminal("[HB] Interval set to " + String(minutes) + " min");
}

void processCommand(const String &command, const String &targetId = "")
{
  Serial.printf("[DEBUG_RAW] Command length: %d, starts with: '%.30s'\n",
                command.length(), command.c_str());
  if (command.startsWith("CONFIG_CHANNELS:"))          handleConfigChannels(command);
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
  else if (command.startsWith("STATUS"))                handleStatus(command);
  else if (command.startsWith("VIBRATION_STATUS"))      handleVibrationStatus(command);
  else if (command == "VIBRATION_ON")                   handleVibrationOn(command);
  else if (command == "VIBRATION_OFF")                  handleVibrationOff(command);
  else if (command.startsWith("TRIANGULATE_START:"))    handleTriangulateStart(command, targetId);
  else if (command == "TRIANGULATE_STOP")               handleTriangulateStop(command);
  else if (command.startsWith("TRI_CYCLE_START:"))      handleTriCycleStart(command);
  else if (command.startsWith("TRIANGULATE_RESULTS"))   handleTriangulateResults(command);
  else if (command.startsWith("ERASE_FORCE:"))          handleEraseForce(command);
  else if (command == "ERASE_CANCEL")                   handleEraseCancel(command);
  else if (command == "ERASE_REQUEST")                  handleEraseRequest(command);
  else if (command.startsWith("AUTOERASE_ENABLE"))      handleAutoeraseEnable(command);
  else if (command == "AUTOERASE_DISABLE")              handleAutoeraseDisable(command);
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
    broadcastToTerminal("[RX] " + cleanMessage);

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
                } else {
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
                            triangulationNodes.push_back(newNode);
                            Serial.printf("[TRIANGULATE] Added child %s: hits=%d avgRSSI=%ddBm Type=%s\n",
                                        sendingNode.c_str(), hits, rssi,
                                        newNode.isBLE ? "BLE" : "WiFi");
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
                            if (!foundInAcks) {
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
                      triangulationNodes.push_back(newNode);
                      Serial.printf("[TRIANGULATE] New node %s: RSSI=%d dist=%.1fm\n",
                                    sendingNode.c_str(), rssi, newNode.distanceEstimate);
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
                broadcastToTerminal(logMsg);
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

void handleEraseStatus(AsyncWebServerRequest *request) {
    String status;
    if (tamperEraseActive) {
        uint32_t timeLeft = autoEraseDelay - (millis() - tamperSequenceStart);
        status = "ACTIVE - Tamper erase countdown\n";
        status += "Time remaining: " + String(timeLeft / 1000) + " seconds\n";
        status += "Send ERASE_CANCEL to abort";
    } else {
        status = "INACTIVE";
    }
    
    request->send(200, "text/plain", status);
}

void handleEraseCancel(AsyncWebServerRequest *request) {
    cancelTamperErase();
    request->send(200, "text/plain", "Tamper erase sequence cancelled");
}
