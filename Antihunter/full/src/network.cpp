#include "network.h"
#include "baseline.h"
#include "triangulation.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include <AsyncTCP.h>
#include <AsyncWebSocket.h>
#include <RTClib.h>
#include <esp_timer.h>

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
static unsigned long lastMeshSend = 0;
unsigned long meshSendInterval = 3000;
const int MAX_MESH_SIZE = 220;
static String nodeId = "";

// Scanner vars
extern volatile bool scanning;
extern volatile int totalHits;
extern std::set<String> uniqueMacs;

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

// WebSocket for terminal
AsyncWebSocket ws("/terminal");
static std::vector<String> terminalBuffer;
static const size_t TERMINAL_BUFFER_SIZE = 500;
static bool terminalClientsConnected = false;

// T114 handling
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


void broadcastToTerminal(const String &message) {
    if (!terminalClientsConnected || ws.count() == 0) return;
    
    String timestamped = "[" + getRTCTimeString() + "] " + message;
    ws.textAll(timestamped);
    
    terminalBuffer.push_back(timestamped);
    if (terminalBuffer.size() > TERMINAL_BUFFER_SIZE) {
        terminalBuffer.erase(terminalBuffer.begin());
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
    // Priority messages bypass rate limiting
    bool isPriority = message.indexOf("TRIANGULATE_STOP") >= 0 || 
                      message.indexOf("STOP_ACK") >= 0;
    
    size_t msgLen = message.length() + 2;
    
    if (!isPriority && !rateLimiter.canSend(msgLen)) {
        if (canDelay) {
            uint32_t wait = rateLimiter.waitTime(msgLen);
            if (wait > 0 && wait < 5000) { 
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
    
    if (Serial1.availableForWrite() < msgLen) {
        Serial.printf("[MESH] Serial1 buffer full (%d/%d bytes)\n", Serial1.availableForWrite(), msgLen);
        return false;
    }
    
    Serial1.println(message);
    broadcastToTerminal("[TX] " + message);
    
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
  WiFi.mode(WIFI_AP);
  delay(100);
  
  randomizeMacAddress();
  delay(50);
  
  customApSsid = prefs.getString("apSsid", AP_SSID);
  customApPass = prefs.getString("apPass", AP_PASS);
  
  if (customApSsid.length() == 0) customApSsid = AP_SSID;
  if (customApPass.length() < 8) customApPass = AP_PASS;
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(customApSsid.c_str(), customApPass.c_str(), AP_CHANNEL, 0);
  delay(500);
  WiFi.setHostname("antihunter");
  delay(100);
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
      [data-theme="light"]{--bg:linear-gradient(135deg,#f0f4f8 0%,#e8eef3 100%);--surf:rgba(255,255,255,0.85);--surf-hover:rgba(255,255,255,0.95);--bord:rgba(59,130,246,0.15);--bord-focus:rgba(59,130,246,0.4);--txt:#1a202c;--mut:#64748b;--acc:#3b82f6;--acch:#2563eb;--accbg:rgba(59,130,246,0.08);--succ:#10b981;--warn:#f59e0b;--dang:#ef4444;--shad:0 8px 32px rgba(0,0,0,0.08);--shad-hover:0 12px 48px rgba(0,0,0,0.12);--glow:0 0 24px rgba(59,130,246,0.2);--backdrop:blur(12px) saturate(180%)}
      [data-theme="dark"]{--bg:linear-gradient(135deg,#0a0e14 0%,#0f1419 100%);--surf:rgba(26,31,46,0.7);--surf-hover:rgba(26,31,46,0.9);--bord:rgba(74,144,226,0.25);--bord-focus:rgba(74,144,226,0.5);--txt:#e8f0f7;--mut:#94a3b8;--acc:#4a90e2;--acch:#5b9bd5;--accbg:rgba(74,144,226,0.1);--succ:#10b981;--warn:#ffaa00;--dang:#ff6b35;--shad:0 8px 32px rgba(0,0,0,0.5);--shad-hover:0 12px 48px rgba(0,0,0,0.7);--glow:0 0 32px rgba(74,144,226,0.25),0 0 64px rgba(74,144,226,0.1);--backdrop:blur(16px) saturate(180%)}
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:var(--bg);background-attachment:fixed;color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.6;transition:background var(--t),color var(--t);min-height:100vh}
      .header{padding:18px 28px;border-bottom:1px solid var(--bord);background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);display:flex;align-items:center;gap:18px;box-shadow:var(--shad);flex-wrap:wrap;position:sticky;top:0;z-index:100}
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
      .btn.danger{background:var(--dang);border-color:var(--dang);color:#fff;box-shadow:0 0 24px rgba(239,68,68,0.3)}
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
      .banner{color:var(--dang);border:2px solid var(--dang);padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:600;background:rgba(239,68,68,0.05);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      #toast{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:12px;z-index:9999}
      .toast{background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);border:2px solid var(--bord);padding:14px 18px;border-radius:8px;box-shadow:var(--shad-hover);opacity:0;transform:translateY(12px);transition:opacity 0.3s,transform 0.3s;font-size:14px;min-width:280px}
      .toast.show{opacity:1;transform:none}
      .toast.success{border-color:var(--succ);box-shadow:0 0 24px rgba(16,185,129,0.3)}
      .toast.error{border-color:var(--dang);box-shadow:0 0 24px rgba(239,68,68,0.3)}
      .toast.warning{border-color:var(--warn);box-shadow:0 0 24px rgba(245,158,11,0.3)}
      .status-bar{display:flex;gap:10px;align-items:center;flex-shrink:0}
      .status-item{background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--bord);padding:8px 14px;border-radius:6px;font-size:12px;font-weight:600;color:var(--mut);transition:all 0.2s;text-transform:uppercase;letter-spacing:0.05em}
      .status-item.active{border-color:var(--acc);background:var(--accbg);color:var(--acc);box-shadow:var(--glow)}
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
      @media(max-width:600px){.stat-grid,.diag-grid{grid-template-columns:1fr}.status-item{font-size:11px;padding:6px 10px}input,select,textarea{font-size:13px;padding:10px 14px}.btn{padding:10px 16px;font-size:13px}}
.diag-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
    </style>
    <script>
      function toggleTheme(){const e=document.documentElement,t=e.getAttribute('data-theme'),n='dark'===t?'light':'dark';e.setAttribute('data-theme',n),localStorage.setItem('theme',n)}
      (function(){const e=localStorage.getItem('theme');e?document.documentElement.setAttribute('data-theme',e):document.documentElement.setAttribute('data-theme','light')})();
    </script>
  </head>
  <body>
    <div id="toast"></div>
    <div class="header">
      <h1>AntiHunter</h1>
      <div style="display:flex;align-items:center;gap:16px;margin-left:auto;">
        <div class="status-bar">
          <div class="status-item" id="modeStatus">WiFi</div>
          <div class="status-item" id="scanStatus">Idle</div>
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
        </div>
      </div>
      <a class="btn danger" href="/stop" id="stopAllBtn" style="display:none;">STOP</a>
    </div>
    <div class="container">
      
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
              <summary style="cursor:pointer;font-weight:bold;color:var(--accent);margin-bottom:8px;"><span>▶</span> Target List</summary>
              <form id="f" method="POST" action="/save">
                <textarea id="list" name="list" placeholder="AA:BB:CC&#10;AA:BB:CC:DD:EE:FF" rows="3"></textarea>
                <div id="targetCount" style="margin:4px 0 8px;color:var(--muted);font-size:11px;">0 targets</div>
                <div style="display:flex;gap:8px;">
                  <button class="btn primary" type="submit">Save</button>
                  <a class="btn alt" href="/export" download="targets.txt" data-ajax="false">Export</a>
                </div>
              </form>
            </details>
            
            <!-- Allowlist -->
            <details style="margin-top:12px;">
              <summary style="cursor:pointer;font-weight:bold;color:var(--accent);margin-bottom:8px;"><span>▶</span> Allow List</summary>
              <form id="af" method="POST" action="/allowlist-save">
                <textarea id="wlist" name="list" placeholder="DD:EE:FF&#10;11:22:33:44:55:66" rows="3"></textarea>
                <div id="allowlistCount" style="margin:4px 0 8px;color:var(--muted);font-size:11px;">0 allowlisted</div>
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
                  <input type="checkbox" id="triangulate">Triangulate
                </label>
              </div>
              
              <div id="triangulateOptions" style="display:none;margin-bottom:8px;">
                <input type="text" name="targetMac" placeholder="Target MAC">
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
                <option value="device-scan">Device Discovery Scan</option>
                <option value="baseline" selected>Baseline Anomaly Sniffer</option>
                <option value="randomization-detection">MAC Randomization Analyzer</option>
                <option value="deauth">Deauthentication Attack Detection</option>
                <option value="drone-detection">Drone RID Detection (WiFi)</option>
              </select>

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
                    <label style="font-size:10px;color:var(--muted);" title="Time a device must be unseen before marked as disappeared from baseline">Marked Absent (s)</label>
                    <input type="number" id="absenceThreshold" min="30" max="600" value="120" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--muted);" title="Window after disappearance during which reappearance triggers an anomaly alert">Seen Reappear (s)</label>
                    <input type="number" id="reappearanceWindow" min="60" max="1800" value="300" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--muted);" title="Minimum RSSI change in dBm to flag as significant signal strength variation">RSSI Variation dB</label>
                    <input type="number" id="rssiChangeDelta" min="5" max="50" value="20" style="padding:4px;font-size:11px;">
                  </div>
                </div>
                
                <label style="font-size:11px;">Monitor (s)</label>
                <input type="number" name="secs" min="0" max="86400" value="300" id="baselineMonitorDuration" style="margin-bottom:8px;">
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;color:var(--txt);">
                  <input type="checkbox" id="foreverBaseline" name="forever" value="1" style="width:auto;margin:0;">
                  <span>Forever</span>
                </label>
                <div id="baselineStatus" style="padding:8px;background:var(--card);border:1px solid #888;border-radius:6px;font-size:11px;margin-bottom:8px;">
                  <div style="color:#888;">No baseline data</div>
                </div>
              </div>
              
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;">
                <button class="btn primary" type="submit" id="startDetectionBtn" style="flex:1;min-width:80px;">Start</button>
                <a class="btn alt" href="/sniffer-cache" data-ajax="false" id="cacheBtn" style="display:none;">Cache</a>
                <a class="btn" href="/baseline-results" data-ajax="false" style="display:none;" id="baselineResultsBtn">Results</a>
                <button class="btn alt" type="button" onclick="resetBaseline()" style="display:none;" id="resetBaselineBtn">Reset</button>
                <button type="button" class="btn" id="clearOldBtn" style="display:none;" onclick="clearOldIdentities()">Clear Old</button>
                <button type="button" class="btn" id="resetRandBtn" style="display:none;" onclick="resetRandomizationDetection()">Reset All</button>
              </div>
             
            </form>
          </div>
        </div>
      </div>
      
    <div class="grid-node-diag" style="margin-bottom:16px;">
      <div class="card" style="min-width:280px;">
        <h3>RF Settings</h3>
        <div class="" id="detectionCardBody">
          <select id="rfPreset" onchange="updateRFPresetUI()">
            <option value="0">Relaxed (Stealthy)</option>
            <option value="1">Balanced (Default)</option>
            <option value="2">Aggressive (Fast)</option>
            <option value="3">Custom</option>
          </select>
          
          <div id="customRFSettings" style="display:none;margin-top:10px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--muted);">WiFi Channel Time (ms)</label>
                <input type="number" id="wifiChannelTime" min="110" max="300" value="120" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--muted);">WiFi Scan Interval (ms)</label>
                <input type="number" id="wifiScanInterval" min="1000" max="10000" value="4000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--muted);">BLE Scan Duration (ms)</label>
                <input type="number" id="bleScanDuration" min="1000" max="5000" value="2000" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--muted);">BLE Scan Interval (ms)</label>
                <input type="number" id="bleScanInterval" min="1000" max="10000" value="2000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="margin-bottom:8px;">
              <label style="font-size:10px;color:var(--muted);">WiFi Channels</label>
              <input type="text" id="wifiChannels" placeholder="1..14" value="1..14" style="padding:4px;font-size:11px;">
            </div>
          </div>
        </div>
        <button class="btn primary" type="button" onclick="saveRFConfig()" style="width:100%;margin-top:8px;">Save RF Settings</button>

        <hr style="margin:16px 0;border:none;border-top:1px solid var(--border);">
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
      
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:12px;">
          <h3 style="margin:0;">Scan Results</h3>
          <div style="display:flex;gap:8px;align-items:center;">
            <label style="font-size:11px;color:var(--muted);">Sort:</label>
            <select id="sortBy" onchange="applySorting()" style="padding:6px 8px;border-radius:6px;font-size:11px;">
              <option value="default">Default</option>
              <option value="rssi-desc">RSSI (Strongest)</option>
              <option value="rssi-asc">RSSI (Weakest)</option>
              <option value="confidence-desc">Confidence (High)</option>
              <option value="sessions-desc">Sessions (Most)</option>
              <option value="lastseen-asc">Last Seen (Recent)</option>
              <option value="name-asc">Name (A-Z)</option>
              <option value="type-asc">Type (WiFi/BLE)</option>
            </select>
            <button class="btn alt" type="button" onclick="toggleSortOrder()" style="padding:6px 10px;font-size:11px;">↕</button>
            <button class="btn alt" type="button" onclick="clearResults()" style="padding:6px 10px;font-size:11px;">Clear</button>
          </div>
        </div>
        <div id="r" style="margin:0;">No scan data yet.</div>
      </div>
    </div>
    
      
      <!-- Bottom Grid: Node + Diagnostics -->
      <div class="grid-node-diag" style="margin-bottom:16px;">
        
        <div class="card" style="min-width:280px;">
          <h3>Node Configuration</h3>
          <form id="nodeForm" method="POST" action="/node-id">
            <label>Node ID</label>
            <input type="text" id="nodeId" name="id" minlength="3" maxlength="16" placeholder="AH01" pattern="^AH.*" required>
            <button class="btn primary" type="submit" style="margin-top:8px;width:100%;">Update</button>
          </form>
          
          <hr>
          
          <div style="margin-top:12px;">
            <label>Mesh Communications</label>
            <div style="display:flex;gap:8px;margin-bottom:12px;">
              <button class="btn" id="meshToggleBtn" onclick="toggleMesh()" style="flex:1;"></button>
            </div>
            
            <div id="meshControls" style="display:none;">
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
        </div>
        
        <div class="card">
          <h3>System Diagnostics</h3>
          <div class="tab-buttons">
            <div class="tab-btn active" onclick="switchTab('overview')">Overview</div>
            <div class="tab-btn" onclick="switchTab('hardware')">Hardware</div>
            <div class="tab-btn" onclick="switchTab('network')">Network</div>
          </div>
          
          <div id="overview" class="tab-content active">
            <div class="stat-grid">
              <div class="stat-item">
                <div class="stat-label">Uptime</div>
                <div class="stat-value" id="uptime">--:--:--</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">WiFi Frames</div>
                <div class="stat-value" id="wifiFrames">0</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">BLE Frames</div>
                <div class="stat-value" id="bleFrames">0</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Target Hits</div>
                <div class="stat-value" id="totalHits">0</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">Unique Devices</div>
                <div class="stat-value" id="uniqueDevices">0</div>
              </div>
              <div class="stat-item">
                <div class="stat-label">CPU Temp</div>
                <div class="stat-value" id="temperature">--°C</div>
              </div>
            </div>
          </div>
          
         <div id="hardware" class="tab-content">
            <div id="hardwareDiag">Loading...</div>
          </div>

          <div id="network" class="tab-content">
            <div id="networkDiag">Loading...</div>
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
          
          <div id="eraseStatus" style="display:none;margin-top:10px;padding:8px;background:var(--card);border:1px solid #003b24;border-radius:6px;font-size:12px;"></div>
          
          <div style="margin-top:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
              <span style="font-weight:bold;color:var(--accent);">Auto-Erase Configuration</span>
              <span style="cursor:help;padding:2px 6px;background:rgba(74,144,226,0.2);border:1px solid #4a90e2;border-radius:4px;font-size:10px;" onclick="showAutoEraseHelp()" title="Click for help">?</span>
            </div>
            
            <label style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
              <input type="checkbox" id="autoEraseEnabled">
              <span>Enable auto-erase on tampering</span>
            </label>
            
            <div style="margin-bottom:16px;">
              <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Setup Period</label>
              <label style="font-size:10px;color:#888;margin-bottom:6px;display:block;">Grace period after enabling before tamper detection becomes active</label>
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
              <label style="font-size:10px;color:#888;margin-bottom:6px;display:block;">Time you have to cancel after tamper detection</label>
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
              <label style="font-size:10px;color:#888;margin-bottom:6px;display:block;">Minimum time before another tamper event can trigger erase</label>
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
                <label style="font-size:10px;color:#888;margin-bottom:6px;display:block;">Number of vibrations needed within detection window to trigger</label>
                <select id="vibrationsRequired">
                  <option value="2">2</option>
                  <option value="3" selected>3</option>
                  <option value="4">4</option>
                  <option value="5">5</option>
                </select>
              </div>
              
              <div style="margin-bottom:0;">
                <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Detection Window</label>
                <label style="font-size:10px;color:#888;margin-bottom:6px;display:block;">Time window for counting required vibrations</label>
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
      </div>      <!-- 
      <div id="terminalToggle">TERMINAL</div>
      <div id="terminalWindow">
        <div id="terminalHeader">
          <span id="terminalTitle">SERIAL MONITOR</span>
          <span id="terminalClose">×</span>
        </div>
        <div id="terminalContent"></div>
      </div>
      -->
    
      <script>
      let selectedMode = '0';
      let baselineUpdateInterval = null;
      let lastScanningState = false;
      let meshEnabled = true;

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
            const r = await fetch('/export');
            const text = await r.text();
            document.getElementById('list').value = text;
            const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
            document.getElementById('targetCount').innerText = lines.length + ' targets';
            const rr = await fetch('/results');
            const resultsText = await rr.text();
            document.getElementById('r').innerHTML = parseAndStyleResults(resultsText);
            loadNodeId();
            loadRFConfig();
            loadWiFiConfig();
            loadMeshStatus();
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
        if (body.classList.contains('collapsed')) {
          body.classList.remove('collapsed');
          body.style.maxHeight = body.scrollHeight + 'px';
          icon.classList.add('open');
        } else {
          body.style.maxHeight = body.scrollHeight + 'px';
          setTimeout(() => {
            body.classList.add('collapsed');
            body.style.maxHeight = '0';
          }, 10);
          icon.classList.remove('open');
        }
      }

      async function loadRFConfig() {
        try {
          const r = await fetch('/rf-config');
          const cfg = await r.json();
          document.getElementById('rfPreset').value = cfg.preset;
          document.getElementById('wifiChannelTime').value = cfg.wifiChannelTime;
          document.getElementById('wifiScanInterval').value = cfg.wifiScanInterval;
          document.getElementById('bleScanInterval').value = cfg.bleScanInterval;
          document.getElementById('bleScanDuration').value = cfg.bleScanDuration;
          document.getElementById('wifiChannels').value = cfg.channels || '1..14';
          updateRFPresetUI();
        } catch(e) {}
      }

      function updateRFPresetUI() {
        const preset = document.getElementById('rfPreset').value;
        const customDiv = document.getElementById('customRFSettings');
        customDiv.style.display = (preset === '3') ? 'block' : 'none';
      }

      function loadMeshInterval() {
        fetch('/mesh-interval').then(r => r.json()).then(data => {
          document.getElementById('meshInterval').value = data.interval;
        }).catch(e => console.error('[CONFIG] Failed to load mesh interval:', e));
      }

      function saveMeshInterval() {
        const interval = document.getElementById('meshInterval').value;
        if (interval < 1500 || interval > 30000) {
          toast('Invalid interval: must be 1500-30000ms', 'error');
          return;
        }
        
        fetch('/mesh-interval', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'interval=' + interval
        }).then(r => r.text()).then(data => {
          toast(data, 'success');
        }).catch(e => {
          toast('Failed to save mesh interval', 'error');
        });
      }
      
      
      
      function toggleMesh() {
        meshEnabled = !meshEnabled;
        
        fetch('/mesh', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'enabled=' + meshEnabled
        }).then(r => r.text()).then(msg => {
          updateMeshUI();
          toast(msg, 'success');
        }).catch(e => {
          toast('Failed to update mesh status', 'error');
          meshEnabled = !meshEnabled;
          updateMeshUI();
        });
        
        updateMeshUI();
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
      
      async function loadMeshStatus() {
        try {
          const r = await fetch('/diag');
          const text = await r.text();
          console.log('[MESH] Full diag:', text);
          meshEnabled = text.includes('Mesh: Enabled');
          console.log('[MESH] Enabled:', meshEnabled);
        } catch(e) {
          console.error('[MESH] Failed to load:', e);
        }
        updateMeshUI();
      }

      async function saveRFConfig() {
        const preset = document.getElementById('rfPreset').value;
        const fd = new FormData();
        
        if (preset === '3') {
          fd.append('wifiChannelTime', document.getElementById('wifiChannelTime').value);
          fd.append('wifiScanInterval', document.getElementById('wifiScanInterval').value);
          fd.append('bleScanInterval', document.getElementById('bleScanInterval').value);
          fd.append('bleScanDuration', document.getElementById('bleScanDuration').value);
          fd.append('channels', document.getElementById('wifiChannels').value);
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
           
      function loadBaselineAnomalyConfig() {
        fetch('/baseline/config').then(response => response.json()).then(data => {
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
        }).catch(error => console.error('Error loading baseline config:', error));
        
        fetch('/allowlist-export').then(r => r.text()).then(t => {
          document.getElementById('wlist').value = t;
          document.getElementById('allowlistCount').textContent = t.split('\n').filter(x => x.trim()).length + ' entries';
        }).catch(error => console.error('Error loading allowlist:', error));
      }

      function clearOldIdentities() {
        if (!confirm('Clear device identities older than 1 hour?')) return;
          fetch('/randomization/clear-old', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'age=3600'
          }).then(r => r.text()).then(t => {
            toast(t, 'success');
          }).catch(err => toast('Error: ' + err, 'error'));
      }

      function updateBaselineStatus() {
        fetch('/baseline/stats').then(response => response.json()).then(stats => {
          const statusDiv = document.getElementById('baselineStatus');
          if (!statusDiv) return;
          let statusHTML = '';
          let progressHTML = '';
          if (stats.scanning && !stats.phase1Complete) {
            // Phase 1: Establishing baseline
            const progress = Math.min(100, (stats.elapsedTime / stats.totalDuration) * 100);
            statusHTML = '<div style="color:#00cc66;font-weight:bold;">⬤ Phase 1: Establishing Baseline...</div>';
            progressHTML = '<div style="margin-top:10px;">' + '<div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px;">' + '<span>Progress</span>' + '<span>' + Math.floor(progress) + '%</span>' + '</div>' + '<div style="width:100%;height:6px;background:#001a10;border-radius:3px;overflow:hidden;">' + '<div style="height:100%;width:' + progress + '%;background:linear-gradient(90deg,#00cc66,#0aff9d);transition:width 0.5s;"></div>' + '</div>' + '</div>';
          } else if (stats.scanning && stats.phase1Complete) {
            // Phase 2: Monitoring - add active status indicator
            statusHTML = '<div style="color:#0aff9d;font-weight:bold;">⬤ Phase 2: Monitoring for Anomalies</div>';
            // Add elapsed time indicator for Phase 2
            const monitorTime = Math.floor(stats.elapsedTime / 1000);
            const monitorMins = Math.floor(monitorTime / 60);
            const monitorSecs = monitorTime % 60;
            progressHTML = '<div style="margin-top:10px;color:#00cc66;font-size:11px;">' + 'Active monitoring: ' + monitorMins + 'm ' + monitorSecs + 's' + '</div>';
          } else if (stats.established) {
            // Complete
            statusHTML = '<div style="color:#00cc66;">✓ Baseline Complete</div>';
          } else {
            statusHTML = '<div style="color:#888;">No baseline data</div>';
          }
          let statsHTML = '';
          if (stats.scanning) {
            statsHTML = '<div style="margin-top:12px;padding:10px;background:#000;border:1px solid #003b24;border-radius:8px;">' + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px;">' + '<div>' + '<div style="color:var(--muted);">WiFi Devices</div>' + '<div style="color:var(--fg);font-size:16px;font-weight:bold;">' + stats.wifiDevices + '</div>' + '<div style="color:var(--muted);font-size:10px;">' + stats.wifiHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--muted);">BLE Devices</div>' + '<div style="color:var(--fg);font-size:16px;font-weight:bold;">' + stats.bleDevices + '</div>' + '<div style="color:var(--muted);font-size:10px;">' + stats.bleHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--muted);">Total Devices</div>' + '<div style="color:var(--accent);font-size:16px;font-weight:bold;">' + stats.totalDevices + '</div>' + '</div>' + '<div>' + '<div style="color:var(--muted);">Anomalies</div>' + '<div style="color:' + (stats.anomalies > 0 ? '#ff6666' : 'var(--fg)') + ';font-size:16px;font-weight:bold;">' + stats.anomalies + '</div>' + '</div>' + '</div>' + '</div>';
          }
          statusDiv.innerHTML = statusHTML + progressHTML + statsHTML;
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
            startDetectionBtn.onclick = function(e) {
                e.preventDefault();
                fetch('/stop').then(r=>r.text()).then(t=>{
                    toast(t);
                    setTimeout(updateBaselineStatus, 500);
                });
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
            baselineUpdateInterval = setInterval(updateBaselineStatus, 1000);
          } else if (!stats.scanning && baselineUpdateInterval) {
            clearInterval(baselineUpdateInterval);
            baselineUpdateInterval = null;
          }
        }).catch(error => console.error('Status update error:', error));
      }

      // Initial load
      updateBaselineStatus();
      // Poll every 2 seconds when not actively scanning
      setInterval(() => {
        if (!baselineUpdateInterval) {
          updateBaselineStatus();
        }
      }, 2000);
      
      function saveBaselineConfig() {
        const rssiThreshold = document.getElementById('baselineRssiThreshold').value;
        const duration = document.getElementById('baselineDuration').value;
        const ramSize = document.getElementById('baselineRamSize').value;
        const sdMax = document.getElementById('baselineSdMax').value;
        fetch('/baseline/config', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `rssiThreshold=${rssiThreshold}&baselineDuration=${duration}&ramCacheSize=${ramSize}&sdMaxDevices=${sdMax}`
        }).then(response => response.text()).then(data => {
          toast('Baseline configuration saved', 'success');
          updateBaselineStatus();
        }).catch(error => {
          toast('Error saving config: ' + error, 'error');
        });
      }
      
      function resetBaseline() {
        if (!confirm('Are you sure you want to reset the baseline? This will clear all collected data.')) return;
        fetch('/baseline/reset', {
          method: 'POST'
        }).then(response => response.text()).then(data => {
          toast(data, 'success');
          updateBaselineStatus();
        }).catch(error => {
          toast('Error resetting baseline: ' + error, 'error');
        });
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
        const isBaseline = resultsElement.textContent.includes('Baseline');
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
          Array.from(resultsElement.children).forEach(child => {
            const hasBackgroundStyle = child.getAttribute('style')?.includes('background:#000');
            if (hasBackgroundStyle && child.textContent.match(/[A-F0-9:]{17}/)) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const mac = macMatch ? macMatch[1] : '';
              
              const rssiMatch = child.textContent.match(/RSSI:\s*([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              const nameMatch = child.textContent.match(/Name:\s*"([^"]+)"/);
              const name = nameMatch ? nameMatch[1] : '';
              
              items.push({
                element: child,
                mac, rssi, name,
                sortKey: currentSort,
                type: 'baseline'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isDeauth) {
          Array.from(resultsElement.children).forEach(child => {
            const hasDeauthBorder = child.getAttribute('style')?.includes('border:1px solid #ff4444');
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
            const hasDroneBorder = child.getAttribute('style')?.includes('border:1px solid #0aff9d');
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
              
              items.push({
                element: child,
                mac, rssi, name, deviceType,
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
        currentSort = 'default';
        sortReverse = false;
        if (document.getElementById('sortBy')) {
          document.getElementById('sortBy').value = 'default';
        }
        return originalParseAndStyleResults.call(this, text);
      };
      
      function updateStatusIndicators(diagText) {
        const taskTypeMatch = diagText.match(/Task Type: ([^\n]+)/);
        const taskType = taskTypeMatch ? taskTypeMatch[1].trim() : 'none';
        const isScanning = diagText.includes('Scanning: yes');
        const detectionMode = document.getElementById('detectionMode')?.value;
        
        document.getElementById('cacheBtn').style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
        document.getElementById('clearOldBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
        document.getElementById('resetRandBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
        
        if (isScanning) {
            document.getElementById('scanStatus').innerText = 'Active';
            document.getElementById('scanStatus').classList.add('active');
            
            const startScanBtn = document.querySelector('#s button');
            if (startScanBtn && taskType === 'scan') {
                startScanBtn.textContent = 'Stop Scanning';
                startScanBtn.classList.remove('primary');
                startScanBtn.classList.add('danger');
                startScanBtn.type = 'button';
                startScanBtn.onclick = function(e) {
                    e.preventDefault();
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
                        fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                            setTimeout(async () => {
                                const refreshedDiag = await fetch('/diag').then(r => r.text());
                                updateStatusIndicators(refreshedDiag);
                            }, 500);
                        });
                    };
                }
            }

            if (taskType === 'sniffer' || taskType === 'drone' || taskType === 'randdetect' || taskType === 'blueteam') {
                const startDetectionBtn = document.getElementById('startDetectionBtn');
                if (startDetectionBtn) {
                    startDetectionBtn.textContent = 'Stop Scanning';
                    startDetectionBtn.classList.remove('primary');
                    startDetectionBtn.classList.add('danger');
                    startDetectionBtn.type = 'button';
                    startDetectionBtn.onclick = function(e) {
                        e.preventDefault();
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
            document.getElementById('scanStatus').innerText = 'Idle';
            document.getElementById('scanStatus').classList.remove('active');

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
        const modeStatus = document.getElementById('modeStatus');
        
        let currentMode = '0';
        
        // Check which form is active and visible
        const detectionMethod = detectionModeSelect?.value;
        
        if (detectionMethod === 'randomization-detection' && randomizationModeSelect?.offsetParent !== null) {
          currentMode = randomizationModeSelect.value;
        } else if (detectionMethod === 'device-scan' && deviceScanModeSelect?.offsetParent !== null) {
          currentMode = deviceScanModeSelect.value;
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
      
      function saveAutoEraseConfig() {
        const enabled = document.getElementById('autoEraseEnabled').checked;
        const delay = document.getElementById('autoEraseDelay').value;
        const cooldown = document.getElementById('autoEraseCooldown').value;
        const vibrationsRequired = document.getElementById('vibrationsRequired').value;
        const detectionWindow = document.getElementById('detectionWindow').value;
        const setupDelay = document.getElementById('setupDelay').value;
        fetch('/config/autoerase', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `enabled=${enabled}&delay=${delay}&cooldown=${cooldown}&vibrationsRequired=${vibrationsRequired}&detectionWindow=${detectionWindow}&setupDelay=${setupDelay}`
        }).then(response => response.text()).then(data => {
          document.getElementById('autoEraseStatus').textContent = 'Config saved: ' + data;
          updateAutoEraseStatus();
        });
      }
      
      function updateAutoEraseStatus() {
        fetch('/config/autoerase').then(response => response.json()).then(data => {
          if (data.enabled) {
            if (data.inSetupMode) {
              document.getElementById('autoEraseStatus').textContent = 'SETUP MODE - Activating soon...';
            } else {
              document.getElementById('autoEraseStatus').textContent = 'ACTIVE - Monitoring for tampering';
            }
          } else {
            document.getElementById('autoEraseStatus').textContent = 'DISABLED - Manual erase only';
          }
        });
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

      function parseAndStyleResults(text) {
        if (!text || text.trim() === '' || text.includes('None yet') || text.includes('No scan data')) {
          return '<div style="color:var(--mut);padding:20px;text-align:center;">No scan data yet.</div>';
        }

        let html = '';

        if (text.includes('=== Triangulation Results ===') || text.includes('Weighted GPS Trilateration')) {
          html = parseTriangulationResults(text);
        } else if(text.includes('MAC Randomization Detection Results')) {
          html = parseRandomizationResults(text);
        } else if (text.includes('Baseline not yet established') || text.includes('BASELINE ESTABLISHED')) {
          html = parseBaselineResults(text);
        } else if (text.includes('Deauth Detection Results') || text.includes('Deauth Attack Detection Results')) {
          html = parseDeauthResults(text);
        } else if (text.includes('Drone Detection Results')) {
          html = parseDroneResults(text);
        } else if (text.includes('Target Hits:') || text.match(/^(WiFi|BLE)\s+[A-F0-9:]/m)) {
          html = parseDeviceScanResults(text);
        } else {
          html = '<div style="margin:0;background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:12px;color:var(--txt);font-size:11px;overflow-x:auto;">' + text + '</div>';
        }
        
        return html;
      }

      function parseTriangulationResults(text) {
        let html = '';
        
        const targetMatch = text.match(/Target MAC: ([A-F0-9:]+)/);
        const durationMatch = text.match(/Duration: (\d+)s/);
        const elapsedMatch = text.match(/Elapsed: (\d+)s/);
        const nodesMatch = text.match(/Reporting Nodes: (\d+)/);
        const syncMatch = text.match(/Clock Sync: ([^\n]+)/);
        
        html += '<div style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
        html += '<div style="font-size:14px;color:var(--acc);margin-bottom:10px;font-weight:bold;">TRIANGULATION RESULTS</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;font-size:11px;color:var(--mut);">';
        if (targetMatch) html += '<span>Target: <strong style="color:var(--acc);">' + targetMatch[1] + '</strong></span>';
        if (durationMatch) html += '<span>Duration: <strong style="color:var(--txt);">' + durationMatch[1] + 's</strong></span>';
        if (elapsedMatch) html += '<span>Elapsed: <strong style="color:var(--txt);">' + elapsedMatch[1] + 's</strong></span>';
        if (nodesMatch) html += '<span>Nodes: <strong style="color:var(--txt);">' + nodesMatch[1] + '</strong></span>';
        html += '</div>';
        if (syncMatch) {
          const syncColor = syncMatch[1].includes('VERIFIED') ? 'var(--succ)' : 'var(--warn)';
          html += '<div style="margin-top:8px;font-size:10px;color:' + syncColor + ';">⏱ ' + syncMatch[1] + '</div>';
        }
        html += '</div>';
        
        if (text.includes('No Mesh Nodes Responding')) {
          html += '<div style="padding:16px;background:var(--surf);border:1px solid var(--dang);border-radius:8px;text-align:center;color:var(--dang);">';
          html += '⚠ No mesh nodes responded to triangulation request';
          html += '</div>';
          return html;
        }
        
        if (text.includes('TRIANGULATION IMPOSSIBLE')) {
          html += '<div style="padding:16px;background:var(--surf);border:1px solid var(--dang);border-radius:8px;color:var(--dang);">';
          html += '<div style="font-weight:bold;margin-bottom:8px;">⚠ Triangulation Impossible</div>';
          const reasonMatch = text.match(/node\(s\) reporting, but none have GPS/);
          if (reasonMatch) {
            html += '<div style="font-size:12px;">None of the reporting nodes have GPS enabled.</div>';
            html += '<div style="font-size:11px;margin-top:4px;color:var(--warn);">Enable GPS on at least 3 nodes to enable triangulation.</div>';
          }
          html += '</div>';
          return html;
        }
        
        if (text.includes('Insufficient GPS Nodes')) {
          const gpsMatch = text.match(/GPS nodes: (\d+)\/3/);
          const totalMatch = text.match(/Total nodes: (\d+)/);
          
          html += '<div style="padding:16px;background:var(--surf);border:1px solid var(--warn);border-radius:8px;color:var(--warn);">';
          html += '<div style="font-weight:bold;margin-bottom:8px;">⚠ Insufficient GPS Nodes</div>';
          if (gpsMatch && totalMatch) {
            html += '<div style="font-size:12px;">GPS nodes: <strong>' + gpsMatch[1] + '</strong>/3 required</div>';
            html += '<div style="font-size:12px;margin-top:4px;">Total nodes: <strong>' + totalMatch[1] + '</strong></div>';
          }
          html += '</div>';
          
          const gpsNodesSection = text.split('Current GPS nodes:')[1];
          if (gpsNodesSection) {
            html += '<div style="margin-top:12px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
            html += '<div style="font-size:11px;color:var(--mut);margin-bottom:8px;font-weight:bold;">GPS NODES AVAILABLE</div>';
            const gpsLines = gpsNodesSection.split('\n').filter(l => l.includes('•')).slice(0, 5);
            gpsLines.forEach(line => {
              const match = line.match(/• ([^\s]+) @ ([-\d.]+),([-\d.]+)/);
              if (match) {
                html += '<div style="padding:6px;margin-bottom:4px;background:var(--surf);border-radius:4px;font-size:10px;color:var(--mut);">';
                html += '<strong style="color:var(--acc);">' + match[1] + '</strong> @ ' + match[2] + ', ' + match[3];
                html += '</div>';
              }
            });
            html += '</div>';
          }
          return html;
        }
        
        const nodeReportsSection = text.split('--- Node Reports ---')[1]?.split('---')[0];
        if (nodeReportsSection) {
          html += '<details style="margin-top:12px;margin-bottom:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:12px;" open>';
          html += '<summary style="cursor:pointer;color:var(--acc);font-weight:bold;user-select:none;list-style:none;display:flex;align-items:center;gap:8px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▼</span>NODE REPORTS';
          html += '</summary>';
          html += '<div style="margin-top:10px;display:grid;gap:8px;">';
          
          const nodeLines = nodeReportsSection.split('\n').filter(l => l.trim() && l.includes(':') && !l.includes('---'));
          nodeLines.forEach(line => {
            const match = line.match(/^([^\s:]+): (.+)/);
            if (match) {
              const nodeId = match[1];
              const data = match[2];
              
              const rssiMatch = data.match(/Filtered=([-\d.]+)dBm/);
              const hitsMatch = data.match(/Hits=(\d+)/);
              const signalMatch = data.match(/Signal=([\d.]+)%/);
              const typeMatch = data.match(/Type=(WiFi|BLE)/);
              const gpsMatch = data.match(/GPS=([-\d.,]+|NO)/);
              const distMatch = data.match(/Dist=([\d.]+)m/);
              const hdopMatch = data.match(/HDOP=([\d.]+)/);
              
              const isGPS = gpsMatch && gpsMatch[1] !== 'NO';
              const borderColor = isGPS ? 'var(--succ)' : 'var(--bord)';
              
              html += '<div style="background:var(--bg);padding:12px;border:1px solid ' + borderColor + ';border-radius:6px;">';
              html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:10px;">';
              html += '<div style="font-family:monospace;font-size:11px;color:' + (isGPS ? 'var(--acc)' : 'var(--mut)') + ';">' + nodeId + (isGPS ? ' ✓' : '') + '</div>';
              
              if (typeMatch) {
                const color = typeMatch[1] === 'BLE' ? '#d896ff' : '#6ab7ff';
                html += '<span style="background:var(--bg);color:' + color + ';padding:2px 6px;border-radius:3px;font-size:9px;border:1px solid ' + color + ';">' + typeMatch[1] + '</span>';
              }
              
              html += '</div>';
              
              html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:6px;font-size:10px;">';
              if (rssiMatch) {
                const rssiVal = parseFloat(rssiMatch[1]);
                const rssiColor = rssiVal >= -50 ? 'var(--succ)' : rssiVal >= -70 ? 'var(--warn)' : 'var(--dang)';
                html += '<div style="background:var(--surf);padding:6px;border-radius:4px;">';
                html += '<div style="color:var(--mut);font-size:8px;">RSSI</div>';
                html += '<div style="color:' + rssiColor + ';font-weight:600;">' + rssiMatch[1] + ' dBm</div>';
                html += '</div>';
              }
              if (hitsMatch) {
                html += '<div style="background:var(--surf);padding:6px;border-radius:4px;">';
                html += '<div style="color:var(--mut);font-size:8px;">HITS</div>';
                html += '<div style="color:var(--txt);font-weight:600;">' + hitsMatch[1] + '</div>';
                html += '</div>';
              }
              if (signalMatch) {
                const sigVal = parseFloat(signalMatch[1]);
                const sigColor = sigVal >= 70 ? 'var(--succ)' : sigVal >= 50 ? 'var(--warn)' : 'var(--dang)';
                html += '<div style="background:var(--surf);padding:6px;border-radius:4px;">';
                html += '<div style="color:var(--mut);font-size:8px;">QUALITY</div>';
                html += '<div style="color:' + sigColor + ';font-weight:600;">' + signalMatch[1] + '%</div>';
                html += '</div>';
              }
              if (distMatch) {
                html += '<div style="background:var(--surf);padding:6px;border-radius:4px;">';
                html += '<div style="color:var(--mut);font-size:8px;">DISTANCE</div>';
                html += '<div style="color:var(--txt);font-weight:600;">' + distMatch[1] + 'm</div>';
                html += '</div>';
              }
              html += '</div>';
              
              if (isGPS) {
                html += '<div style="margin-top:8px;padding:8px;background:var(--surf);border:1px solid var(--succ);border-radius:4px;font-size:9px;color:var(--acc);">';
                html += '@ ' + gpsMatch[1];
                if (hdopMatch) html += ' | HDOP: ' + hdopMatch[1];
                html += '</div>';
              }
              
              html += '</div>';
            }
          });
          
          html += '</div></details>';
        }
        
        const validationSection = text.split('--- GPS-RSSI Distance Validation ---')[1]?.split('---')[0];
        if (validationSection) {
          html += '<details style="margin-bottom:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:12px;">';
          html += '<summary style="cursor:pointer;color:var(--mut);font-weight:600;user-select:none;list-style:none;display:flex;align-items:center;gap:8px;font-size:12px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>GPS-RSSI Validation';
          html += '</summary>';
          html += '<div style="margin-top:10px;display:grid;gap:6px;">';
          
          const valLines = validationSection.split('\n').filter(l => l.trim() && (l.includes('<->') || l.includes('Avg error')));
          valLines.forEach(line => {
            if (line.includes('<->')) {
              const checkMark = line.includes('✓') ? '✓' : '✗';
              const color = line.includes('✓') ? 'var(--succ)' : 'var(--dang)';
              const cleanLine = line.replace(/✓|✗/g, '').trim();
              html += '<div style="padding:6px;background:var(--bg);border-left:3px solid ' + color + ';font-size:10px;color:var(--mut);">';
              html += '<span style="color:' + color + ';font-weight:bold;">' + checkMark + '</span> ' + cleanLine;
              html += '</div>';
            } else if (line.includes('Avg error')) {
              const errorMatch = line.match(/([\d.]+)%/);
              let quality = 'POOR';
              let color = 'var(--dang)';
              if (errorMatch) {
                const error = parseFloat(errorMatch[1]);
                if (error < 25) { quality = 'GOOD'; color = 'var(--succ)'; }
                else if (error < 50) { quality = 'FAIR'; color = 'var(--warn)'; }
              }
              html += '<div style="padding:8px;background:var(--bg);border:1px solid ' + color + ';border-radius:4px;margin-top:8px;color:' + color + ';font-weight:600;">';
              html += line.trim() + ' - <span style="font-style:italic;">' + quality + '</span>';
              html += '</div>';
            }
          });
          
          html += '</div></details>';
        }
        
        const trilaterSection = text.split('--- Weighted GPS Trilateration ---')[1]?.split('===')[0];
        if (trilaterSection && trilaterSection.includes('ESTIMATED POSITION')) {
          const latMatch = trilaterSection.match(/Latitude:\s*([-\d.]+)/);
          const lonMatch = trilaterSection.match(/Longitude:\s*([-\d.]+)/);
          const confMatch = trilaterSection.match(/Confidence:\s*([\d.]+)%/);
          const cepMatch = trilaterSection.match(/Uncertainty \(CEP68\):\s*±([\d.]+)m/);
          const uncMatch = trilaterSection.match(/Uncertainty \(95%\):\s*±([\d.]+)m/);
          const mapsMatch = trilaterSection.match(/(https:\/\/www\.google\.com\/maps[^\s]+)/);
          
          html += '<div style="margin-top:12px;padding:16px;background:var(--bg);border:2px solid var(--succ);border-radius:8px;">';
          html += '<div style="font-size:14px;color:var(--succ);margin-bottom:12px;font-weight:bold;">✓ POSITION ESTIMATED</div>';
          
          html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:12px;">';
          
          if (latMatch) {
            html += '<div style="background:var(--surf);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="font-size:9px;color:var(--mut);margin-bottom:4px;">LATITUDE</div>';
            html += '<div style="font-family:monospace;font-size:12px;color:var(--acc);">' + latMatch[1] + '</div>';
            html += '</div>';
          }
          
          if (lonMatch) {
            html += '<div style="background:var(--surf);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="font-size:9px;color:var(--mut);margin-bottom:4px;">LONGITUDE</div>';
            html += '<div style="font-family:monospace;font-size:12px;color:var(--acc);">' + lonMatch[1] + '</div>';
            html += '</div>';
          }
          
          if (confMatch) {
            const confVal = parseFloat(confMatch[1]);
            const confColor = confVal >= 75 ? 'var(--succ)' : confVal >= 50 ? 'var(--warn)' : 'var(--dang)';
            html += '<div style="background:var(--surf);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="font-size:9px;color:var(--mut);margin-bottom:4px;">CONFIDENCE</div>';
            html += '<div style="font-size:14px;color:' + confColor + ';font-weight:bold;">' + confMatch[1] + '%</div>';
            html += '</div>';
          }
          
          html += '</div>';
          
          html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:12px;">';
          
          if (cepMatch) {
            html += '<div style="background:var(--surf);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="font-size:9px;color:var(--mut);margin-bottom:4px;">CEP68 ±</div>';
            html += '<div style="font-size:13px;color:var(--warn);font-weight:600;">' + cepMatch[1] + 'm</div>';
            html += '</div>';
          }
          
          if (uncMatch) {
            html += '<div style="background:var(--surf);padding:10px;border-radius:6px;border:1px solid var(--bord);">';
            html += '<div style="font-size:9px;color:var(--mut);margin-bottom:4px;">95% Confidence ±</div>';
            html += '<div style="font-size:13px;color:var(--warn);font-weight:600;">' + uncMatch[1] + 'm</div>';
            html += '</div>';
          }
          
          html += '</div>';
          
          if (mapsMatch) {
            html += '<a href="' + mapsMatch[1] + '" target="_blank" style="display:inline-block;background:var(--succ);color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:12px;margin-top:8px;">';
            html += '@ Open in Google Maps';
            html += '</a>';
          }
          
          html += '</div>';
        }
        
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
        
        trackBlocks.forEach((block, index) => {
          const trackMatch = block.match(/Track ID:\s*([^\n]+)/);
          const typeMatch = block.match(/Type:\s*([^\n]+)/);
          const macsMatch = block.match(/MACs linked: (\d+)/);
          const confMatch = block.match(/Confidence: ([\d.]+)/);
          const sessionsMatch = block.match(/Sessions: (\d+)/);
          const intervalMatch = block.match(/Interval consistency: ([\d.]+)/);
          const rssiMatch = block.match(/RSSI consistency: ([\d.]+)/);
          const channelsMatch = block.match(/Channels: (\d+)/);
          const channelSeqMatch = block.match(/Channel sequence: (.+)/);
          const anchorMacMatch = block.match(/Anchor MAC: ([A-F0-9:]+)/);
          const lastSeenMatch = block.match(/Last seen: (\d+)s ago/);
          const macsListMatch = block.match(/MACs: (.+)/);
          
          if (!trackMatch || !anchorMacMatch) return;
          
          const trackId = trackMatch[1];
          const anchorMac = anchorMacMatch[1];
          const macCount = macsMatch ? macsMatch[1] : '0';
          const confidence = confMatch ? (parseFloat(confMatch[1]) * 100).toFixed(0) : '0';
          const sessions = sessionsMatch ? sessionsMatch[1] : '0';
          const isBLE = typeMatch && typeMatch[1] === 'BLE Device';
          const deviceType = isBLE ? 'BLE' : 'WiFi';
          
          const rssiList = macsListMatch ? macsListMatch[1].match(/([-\d]+)dBm/g) : null;
          let avgRssi = null;
          if (rssiList && rssiList.length > 0) {
            const rssiValues = rssiList.map(r => parseInt(r.match(/([-\d]+)/)[1]));
            avgRssi = Math.round(rssiValues.reduce((a, b) => a + b, 0) / rssiValues.length);
          }
          
          html += '<details data-type="' + deviceType + '" style="background:var(--surf);border:1px solid var(--bord);border-radius:6px;margin-bottom:10px;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'var(--acc)\'" onmouseout="this.style.borderColor=\'var(--bord)\'">';
          html += '<summary style="padding:14px;cursor:pointer;user-select:none;list-style:none;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:nowrap;">';
          html += '<div style="display:flex;align-items:center;gap:12px;flex:1;min-width:0;flex-wrap:wrap;">';
          html += '<span style="font-family:monospace;font-size:12px;color:var(--acc);font-weight:600;white-space:nowrap;">' + anchorMac + '</span>';
          html += '<span style="background:' + (isBLE ? '#4a1a4a' : '#1a2a4a') + ';color:' + (isBLE ? '#d896ff' : '#6ab7ff') + ';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;">' + (isBLE ? 'BLE' : 'WiFi') + '</span>';
          html += '<span style="color:var(--mut);font-size:10px;white-space:nowrap;">' + macCount + ' MAC' + (macCount !== '1' ? 's' : '') + '</span>';
          html += '</div>';
          html += '<div style="display:flex;align-items:center;gap:14px;flex-shrink:0;">';
          
          if (avgRssi !== null) {
            const rssiColor = avgRssi >= -50 ? 'var(--succ)' : avgRssi >= -70 ? 'var(--warn)' : 'var(--dang)';
            html += '<div style="text-align:right;">';
            html += '<div style="font-size:8px;color:var(--mut);text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;">RSSI</div>';
            html += '<div style="font-size:13px;color:' + rssiColor + ';font-weight:700;white-space:nowrap;">' + avgRssi + '<span style="font-size:9px;margin-left:1px;">dBm</span></div>';
            html += '</div>';
          }
          
          const confVal = parseInt(confidence);
          const confColor = confVal >= 75 ? 'var(--succ)' : confVal >= 50 ? 'var(--warn)' : 'var(--dang)';
          html += '<div style="text-align:right;">';
          html += '<div style="font-size:8px;color:var(--mut);text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;">Confidence</div>';
          html += '<div style="font-size:13px;color:' + confColor + ';font-weight:700;white-space:nowrap;">' + confidence + '<span style="font-size:9px;">%</span></div>';
          html += '</div>';
          
          html += '<span style="color:var(--mut);font-size:18px;">▶</span>';
          html += '</div>';
          html += '</summary>';
          
          html += '<div style="padding:0 14px 14px 14px;border-top:1px solid var(--bord);">';
          html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-top:12px;">';
          
          html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
          html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">SESSIONS</div>';
          html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + sessions + '</div>';
          html += '</div>';
          
          if (rssiMatch) {
            const rssiConPct = (parseFloat(rssiMatch[1]) * 100).toFixed(0);
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">RSSI STABILITY</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + rssiConPct + '%</div>';
            html += '</div>';
          }
          
          if (channelsMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">CHANNELS</div>';
            html += '<div style="font-size:14px;color:var(--txt);font-weight:600;">' + channelsMatch[1] + '</div>';
            html += '</div>';
          }
          
          if (lastSeenMatch) {
            html += '<div style="background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--bord);">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:3px;">LAST SEEN</div>';
            html += '<div style="font-size:11px;color:var(--txt);font-weight:600;">' + lastSeenMatch[1] + 's</div>';
            html += '</div>';
          }
          
          html += '</div>';
          
          if (channelSeqMatch) {
            html += '<div style="margin-top:10px;padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:4px;">';
            html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">CHANNEL SEQUENCE</div>';
            html += '<div style="font-size:10px;color:var(--txt);font-family:monospace;">' + channelSeqMatch[1].trim() + '</div>';
            html += '</div>';
          }
          
          html += '<div style="margin-top:10px;padding:8px;background:var(--bg);border:1px solid var(--succ);border-radius:4px;">';
          html += '<div style="font-size:8px;color:var(--mut);margin-bottom:4px;">TRACK ID</div>';
          html += '<div style="font-size:11px;color:var(--acc);font-family:monospace;font-weight:600;">' + trackId + '</div>';
          html += '</div>';
          
          if (macsListMatch) {
            const macsList = macsListMatch[1];
            const moreMatch = macsList.match(/\(\+(\d+) more\)/);
            const cleanMacsList = macsList.replace(/\s*\(\+\d+ more\)/, '');
            const macs = cleanMacsList.split(',').map(m => m.trim()).filter(m => m.length > 0);
            
            html += '<details style="margin-top:10px;" open>';
            html += '<summary style="font-size:9px;color:var(--mut);cursor:pointer;padding:6px 0;list-style:none;user-select:none;">MAC ADDRESSES (' + (moreMatch ? macCount : macs.length) + ')</summary>';
            html += '<div style="display:grid;gap:4px;margin-top:6px;">';
            
            macs.forEach((mac, i) => {
              const isAnchor = mac.includes(anchorMac);
              html += '<div style="background:' + (isAnchor ? 'var(--bg)' : 'var(--surf)') + ';border:1px solid:' + (isAnchor ? 'var(--succ)' : 'var(--bord)') + ';border-radius:3px;padding:6px 8px;font-family:monospace;font-size:10px;color:' + (isAnchor ? 'var(--acc)' : 'var(--mut)') + ';display:flex;justify-content:space-between;align-items:center;">';
              html += '<span>' + mac.split(' ')[0] + '</span>';
              if (isAnchor) html += '<span style="font-size:7px;padding:2px 5px;background:var(--bg);border:1px solid var(--succ);border-radius:2px;color:var(--succ);font-weight:600;">ANCHOR</span>';
              html += '</div>';
            });
            
            if (moreMatch) {
              html += '<div style="padding:6px;text-align:center;color:var(--mut);font-size:10px;font-style:italic;">+ ' + moreMatch[1] + ' more</div>';
            }
            
            html += '</div></details>';
          }
          
          html += '</div>';
          html += '</details>';
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
        let html = '';
        
        const totalMatch = text.match(/Total devices in baseline: (\d+)/);
        const wifiMatch = text.match(/WiFi devices: (\d+)/);
        const bleMatch = text.match(/BLE devices: (\d+)/);
        const rssiThreshMatch = text.match(/RSSI threshold: ([-\d]+) dBm/);
        const anomalyCountMatch = text.match(/Total anomalies: (\d+)/);
        
        if (text.includes('Baseline not yet established')) {
          html += '<div style="padding:16px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;text-align:center;color:var(--mut);">';
          html += '<div style="font-size:14px;margin-bottom:8px;">Baseline Not Yet Established</div>';
          const devicesMatch = text.match(/Devices detected so far: (\d+)/);
          if (devicesMatch) {
            html += '<div style="font-size:12px;">Devices detected: <strong style="color:var(--txt);">' + devicesMatch[1] + '</strong></div>';
          }
          html += '</div>';
          return html;
        }
        
        html += '<div style="margin-bottom:16px;padding:12px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
        html += '<div style="font-size:14px;color:var(--txt);margin-bottom:10px;font-weight:bold;">Baseline Established</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;font-size:12px;color:var(--mut);">';
        if (totalMatch) html += '<span>Total: <strong style="color:var(--txt);">' + totalMatch[1] + '</strong></span>';
        if (wifiMatch) html += '<span>WiFi: <strong style="color:var(--txt);">' + wifiMatch[1] + '</strong></span>';
        if (bleMatch) html += '<span>BLE: <strong style="color:var(--txt);">' + bleMatch[1] + '</strong></span>';
        if (rssiThreshMatch) html += '<span>Threshold: <strong style="color:var(--txt);">' + rssiThreshMatch[1] + ' dBm</strong></span>';
        html += '</div></div>';
        
        if (anomalyCountMatch) {
          html += '<div style="margin-bottom:12px;padding:12px;background:var(--surf);border:1px solid var(--dang);border-radius:8px;">';
          html += '<div style="font-size:14px;color:var(--dang);font-weight:bold;">⚠ Anomalies Detected: ' + anomalyCountMatch[1] + '</div>';
          html += '</div>';
          
          const anomalySection = text.split('=== ANOMALIES DETECTED ===')[1];
          if (anomalySection) {
            const anomalyLines = anomalySection.split('\n').filter(l => l.trim() && !l.includes('Total anomalies'));
            anomalyLines.forEach(line => {
              const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI:([-\d]+)dBm(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?\s+-\s+(.+)$/);
              if (match) {
                const [_, type, mac, rssi, channel, name, reason] = match;
                
                html += '<div style="background:var(--surf);padding:14px;border-radius:8px;border:1px solid var(--warn);margin-bottom:10px;">';
                html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:10px;">';
                html += '<div style="font-family:monospace;font-size:15px;color:var(--warn);">' + mac + '</div>';
                html += '<span style="background:var(--warn);color:#000;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:bold;">' + type + '</span>';
                html += '</div>';
                html += '<div style="display:flex;gap:16px;font-size:12px;color:var(--mut);margin-bottom:8px;flex-wrap:wrap;">';
                html += '<span>RSSI: <strong style="color:var(--txt);">' + rssi + ' dBm</strong></span>';
                if (channel) html += '<span>Channel: <strong style="color:var(--txt);">' + channel + '</strong></span>';
                if (name) html += '<span>Name: <strong style="color:var(--txt);">' + name + '</strong></span>';
                html += '</div>';
                html += '<div style="padding:8px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;color:var(--warn);font-size:12px;">';
                html += reason;
                html += '</div>';
                html += '</div>';
              }
            });
          }
        }
        
        const baselineSection = text.split('=== BASELINE DEVICES (Cached in RAM) ===')[1]?.split('===')[0];
        if (baselineSection) {
          html += '<details style="margin-top:14px;">';
          html += '<summary style="cursor:pointer;color:var(--acc);user-select:none;padding:6px 0;font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>';
          html += 'Baseline Devices (Cached in RAM)';
          html += '</summary>';
          html += '<div style="margin-top:10px;padding:10px;background:var(--bg);border:1px solid var(--bord);border-radius:6px;max-height:400px;overflow-y:auto;">';
          
          const deviceLines = baselineSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/));
          deviceLines.forEach(line => {
            const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:([-\d]+)dBm\s+Max:([-\d]+)dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
            if (match) {
              const [_, type, mac, avg, min, max, hits, channel, name] = match;
              
              html += '<div style="padding:8px;margin-bottom:6px;background:var(--surf);border-radius:6px;border:1px solid var(--bord);">';
              html += '<div style="display:flex;justify-content:space-between;align-items:start;flex-wrap:wrap;gap:10px;">';
              html += '<div>';
              html += '<div style="font-family:monospace;font-size:12px;color:var(--txt);margin-bottom:3px;">' + mac + '</div>';
              if (name) html += '<div style="font-size:11px;color:var(--mut);">Name: ' + name + '</div>';
              html += '</div>';
              html += '<div style="text-align:right;">';
              html += '<div style="font-size:11px;color:var(--mut);">Avg: ' + avg + ' dBm</div>';
              html += '<div style="font-size:10px;color:var(--mut);">' + min + '→' + max + ' dBm</div>';
              html += '</div>';
              html += '</div>';
              html += '<div style="display:flex;gap:12px;font-size:10px;color:var(--mut);margin-top:4px;">';
              html += '<span>Type: <strong style="color:var(--txt);">' + type + '</strong></span>';
              html += '<span>Hits: <strong style="color:var(--txt);">' + hits + '</strong></span>';
              if (channel) html += '<span>CH: <strong style="color:var(--txt);">' + channel + '</strong></span>';
              html += '</div>';
              html += '</div>';
            }
          });
          
          html += '</div>';
          html += '</details>';
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
        lines.forEach(line => {
          const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI=([-\d]+)dBm(?:\s+CH=(\d+))?(?:\s+"([^"]*)")?/);
          if (!match) return;
          
          const type = match[1];
          const mac = match[2];
          const rssi = match[3];
          const channel = match[4] || '';
          const name = match[5] || 'Unknown';
          
          const typeColor = type === 'BLE' ? '#4da6ff' : 'var(--acc)';
          const rssiStrength = parseInt(rssi);
          let rssiColor = 'var(--mut)';
          if (rssiStrength >= -50) rssiColor = 'var(--succ)';
          else if (rssiStrength >= -70) rssiColor = 'var(--txt)';
          
          html += '<div class="device-card" data-type="' + type + '" style="margin-bottom:10px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">';
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
          if (!data.enabled) {
            statusText = 'DISABLED - Manual erase only';
            statusClass = 'status-disabled';
          } else if (data.inSetupMode) {
            const remaining = Math.max(0, Math.floor((data.setupDelay - (Date.now() - data.setupStartTime)) / 1000));
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
      
      function cancelErase() {
        fetch('/erase/cancel', {
          method: 'POST'
        }).then(response => response.text()).then(data => {
          document.getElementById('eraseStatus').innerHTML = '<pre>' + data + '</pre>';
        });
      }
      
      function pollEraseStatus() {
        const poll = setInterval(() => {
          fetch('/erase/status').then(response => response.text()).then(status => {
            document.getElementById('eraseStatus').innerHTML = '<pre>Status: ' + status + '</pre>';
            if (status === 'COMPLETED') {
              clearInterval(poll);
              // Show persistent success message
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:#00cc66;font-weight:bold;">SUCCESS: Secure erase completed successfully</pre>';
              toast('All data has been securely destroyed', 'success');
              // Clear the form
              document.getElementById('eraseConfirm').value = '';
            } else if (status.startsWith('FAILED')) {
              clearInterval(poll);
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:#ff4444;font-weight:bold;">FAILED: ' + status + '</pre>';
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

      async function tick() {
        if (document.activeElement && (document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA' || document.activeElement.tagName === 'SELECT' || document.activeElement.isContentEditable || window.getSelection().toString().length > 0)) return;
        
        try {
          const d = await fetch('/diag');
          const diagText = await d.text();
          const isScanning = diagText.includes('Scanning: yes');
          const sections = diagText.split('\n');
          
          try {
            const droneStatus = await fetch('/drone/status');
            const droneData = await droneStatus.json();
            if (droneData.enabled) {
              document.getElementById('droneStatus').innerText = 'Drone Detection: Active (' + droneData.unique + ' drones)';
              document.getElementById('droneStatus').classList.add('active');
            } else {
              document.getElementById('droneStatus').innerText = 'Drone Detection: Idle';
              document.getElementById('droneStatus').classList.remove('active');
            }
          } catch (e) {}
          
          let overview = '';
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
            if (line.includes('Unique devices')) {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('uniqueDevices').innerText = match[1];
            }
            if (line.includes('ESP32 Temp')) {
              const match = line.match(/([\d.]+)°C/);
              if (match) document.getElementById('temperature').innerText = match[1] + '°C';
            }
            if (line.includes('SD Card') || line.includes('GPS') || line.includes('RTC') || line.includes('Vibration')) {
              hardware += line + '\n';
            } else if (line.includes('AP IP') || line.includes('Mesh') || line.includes('WiFi Channels')) {
              network += line + '\n';
            } else {
              overview += line + '\n';
            }
          });

          document.getElementById('hardwareDiag').innerHTML=formatDiagGrid(hardware,'hardware');
          document.getElementById('networkDiag').innerHTML=formatDiagGrid(network,'network');
          
          const uptimeMatch = diagText.match(/Up:(\d+):(\d+):(\d+)/);
          if (uptimeMatch) {
            document.getElementById('uptime').innerText = uptimeMatch[1] + ':' + uptimeMatch[2] + ':' + uptimeMatch[3];
          }
          
          updateStatusIndicators(diagText);
          
          const stopAllBtn = document.getElementById('stopAllBtn');
          if (stopAllBtn) {
            stopAllBtn.style.display = isScanning ? 'inline-block' : 'none';
          }
          
          const resultsElement = document.getElementById('r');
          if (resultsElement && !resultsElement.contains(document.activeElement)) {
            if (isScanning) {
              const rr = await fetch('/results');
              const resultsText = await rr.text();
              
              const currentText = resultsElement.textContent || resultsElement.innerText || '';
              if (currentText !== resultsText) {
                const expandedCards = new Set();
                const expandedDetails = new Set();
                
                resultsElement.querySelectorAll('[id$="Content"]').forEach(content => {
                  if (content.style.display !== 'none') {
                    expandedCards.add(content.id);
                  }
                });
                
                resultsElement.querySelectorAll('details[open]').forEach(details => {
                  const summary = details.querySelector('summary');
                  if (summary && summary.textContent) {
                    expandedDetails.add(summary.textContent.trim());
                  }
                });
                
                resultsElement.innerHTML = parseAndStyleResults(resultsText);
                
                expandedCards.forEach(contentId => {
                  const content = document.getElementById(contentId);
                  const iconId = contentId.replace('Content', 'Icon');
                  const icon = document.getElementById(iconId);
                  
                  if (content && icon) {
                    content.style.display = 'block';
                    icon.style.transform = 'rotate(0deg)';
                    icon.textContent = '▼';
                  }
                });
                
                expandedDetails.forEach(summaryText => {
                  const details = Array.from(resultsElement.querySelectorAll('details')).find(d => {
                    const summary = d.querySelector('summary');
                    return summary && summary.textContent.trim() === summaryText;
                  });
                  if (details) {
                    details.open = true;
                    const spans = details.querySelectorAll('summary span');
                    const arrow = spans[spans.length - 1];
                    if (arrow) arrow.style.transform = 'rotate(90deg)';
                  }
                });
                
                resultsElement.querySelectorAll('details').forEach(details => {
                  details.addEventListener('toggle', () => {
                    const spans = details.querySelectorAll('summary span');
                    const arrow = spans[spans.length - 1];
                    if (arrow) {
                      arrow.style.transform = details.open ? 'rotate(90deg)' : 'rotate(0deg)';
                    }
                  });
                });
              }
            } else if (lastScanningState && !isScanning) {
              const rr = await fetch('/results');
              const resultsText = await rr.text();
              resultsElement.innerHTML = parseAndStyleResults(resultsText);
            }
          }
          
          lastScanningState = isScanning;
        } catch (e) {
          console.error('Tick error:', e);
        }
      }
      
      document.getElementById('triangulate').addEventListener('change', e => {
        document.getElementById('triangulateOptions').style.display = e.target.checked ? 'block' : 'none';
        const secsInput = document.querySelector('input[name="secs"]');
        if (e.target.checked) {
          if (parseInt(secsInput.value) < 60) {
            secsInput.value = 60;
            toast('Triangulation requires minimum 60 seconds');
          }
          secsInput.setAttribute('min', '60');
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

      document.getElementById('nodeForm').addEventListener('submit', e => {
        e.preventDefault();
        const idValue = document.getElementById('nodeId').value.trim();
        if (!idValue.startsWith('AH')) {
          toast('Node ID must start with AH prefix', 'error');
          return;
        }
        ajaxForm(e.target, 'Node ID updated');
        setTimeout(loadNodeId, 500);
      });

      document.getElementById('s').addEventListener('submit', e => {
          e.preventDefault();
          const fd = new FormData(e.target);
          const submitBtn = e.target.querySelector('button[type="submit"]');
          
          fetch('/scan', {
              method: 'POST',
              body: fd
          }).then(r => r.text()).then(t => {
              toast(t);
          }).catch(err => toast('Error: ' + err.message));
      });

      document.getElementById('detectionMode').addEventListener('change', function() {
        const selectedMethod = this.value;
        const standardControls = document.getElementById('standardDurationControls');
        const baselineControls = document.getElementById('baselineConfigControls');
        const randomizationModeControls = document.getElementById('randomizationModeControls');
        const deviceScanModeControls = document.getElementById('deviceScanModeControls');
        const cacheBtn = document.getElementById('cacheBtn');
        const baselineResultsBtn = document.getElementById('baselineResultsBtn');
        const resetBaselineBtn = document.getElementById('resetBaselineBtn');
        const clearOldBtn = document.getElementById('clearOldBtn');
        const resetRandBtn = document.getElementById('resetRandBtn');
        
        cacheBtn.style.display = 'none';
        baselineResultsBtn.style.display = 'none';
        resetBaselineBtn.style.display = 'none';
        clearOldBtn.style.display = 'none';
        resetRandBtn.style.display = 'none';
        standardControls.style.display = 'none';
        baselineControls.style.display = 'none';
        randomizationModeControls.style.display = 'none';
        deviceScanModeControls.style.display = 'none';
        
        if (selectedMethod === 'baseline') {
          baselineControls.style.display = 'block';
          baselineResultsBtn.style.display = 'inline-block';
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
          
        } else {
          standardControls.style.display = 'block';
          cacheBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
        }
      });

      document.getElementById('sniffer').addEventListener('submit', e => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const detectionMethod = fd.get('detection');
        let endpoint = '/sniffer';

        if (detectionMethod === 'randomization-detection') {
            const randMode = document.getElementById('randomizationMode').value;
            fd.append('randomizationMode', randMode);
        }   
        if (detectionMethod === 'drone-detection') {
          endpoint = '/drone';
          fd.delete('detection');
        }
        if (detectionMethod === 'baseline') {
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
          }).then(r => r.text()).then(t => {
            toast(t, 'success');
            updateBaselineStatus();
          }).catch(err => toast('Error: ' + err, 'error'));
        } else {
          fetch(endpoint, {
            method: 'POST',
            body: fd
          }).then(r => r.text()).then(t => toast(t, 'success')).catch(err => toast('Error: ' + err, 'error'));
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

      // Initialize
      load();
      initTerminal();
      loadBaselineAnomalyConfig();
      loadMeshInterval();
      setInterval(tick, 2000);
      document.getElementById('detectionMode').dispatchEvent(new Event('change'));
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
        AsyncWebServerResponse* res = r->beginResponse(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
        res->addHeader("Cache-Control", "no-store");
        r->send(res); });

  server->on("/export", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getTargetsList()); });

  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r) {
      std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
      String results = antihunter::lastResults.empty() ? "None yet." : String(antihunter::lastResults.c_str());
      
      if (triangulationActive) {
          results += "\n\n" + calculateTriangulation();
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

  server->on("/node-id", HTTP_POST, [](AsyncWebServerRequest *req)
            {
      String id = req->hasParam("id", true) ? req->getParam("id", true)->value() : "";
      id.trim();
      
      if (id.length() < 3 || id.length() > 16) {
          req->send(400, "text/plain", "Invalid ID length (3-16 chars required)");
          return;
      }
      
      if (!id.startsWith("AH")) {
          req->send(400, "text/plain", "Node ID must start with 'AH' prefix");
          return;
      }
      
      setNodeId(id);
      saveConfiguration();
      req->send(200, "text/plain", "Node ID updated");
  });

  server->on("/node-id", HTTP_GET, [](AsyncWebServerRequest *r)
             {
    String j = "{\"nodeId\":\"" + getNodeId() + "\"}";
    r->send(200, "application/json", j); });

  server->on("/scan", HTTP_POST, [](AsyncWebServerRequest *req) {
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
      delay(100); 
      
      // Ditch out here if triangulating
      if (req->hasParam("triangulate", true) && req->hasParam("targetMac", true)) {
          String targetMac = req->getParam("targetMac", true)->value();
          startTriangulation(targetMac, secs);
          String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
          req->send(200, "text/plain", "Triangulation starting for " + String(secs) + "s - " + modeStr);
          return;
      }
      
      String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
      req->send(200, "text/plain", forever ? ("Scan starting (forever) - " + modeStr) : ("Scan starting for " + String(secs) + "s - " + modeStr));
      
      if (!workerTaskHandle) {
          xTaskCreatePinnedToCore(listScanTask, "scan", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
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

 server->on("/baseline/config", HTTP_POST, [](AsyncWebServerRequest *req)
            {
        if (req->hasParam("rssiThreshold", true)) {
            int8_t threshold = req->getParam("rssiThreshold", true)->value().toInt();
            setBaselineRssiThreshold(threshold);
        }
        if (req->hasParam("baselineDuration", true)) {
            baselineDuration = req->getParam("baselineDuration", true)->value().toInt() * 1000;
        }
        if (req->hasParam("ramCacheSize", true)) {
            uint32_t ramSize = req->getParam("ramCacheSize", true)->value().toInt();
            setBaselineRamCacheSize(ramSize);
        }
        if (req->hasParam("sdMaxDevices", true)) {
            uint32_t sdMax = req->getParam("sdMaxDevices", true)->value().toInt();
            setBaselineSdMaxDevices(sdMax);
        }
        if (req->hasParam("absenceThreshold", true)) {
            uint32_t absence = req->getParam("absenceThreshold", true)->value().toInt() * 1000;
            setDeviceAbsenceThreshold(absence);
        }
        if (req->hasParam("reappearanceWindow", true)) {
            uint32_t reappear = req->getParam("reappearanceWindow", true)->value().toInt() * 1000;
            setReappearanceAlertWindow(reappear);
        }
        if (req->hasParam("rssiChangeDelta", true)) {
            int8_t delta = req->getParam("rssiChangeDelta", true)->value().toInt();
            setSignificantRssiChange(delta);
        }
        req->send(200, "text/plain", "Baseline configuration updated"); 
      });

  server->on("/baseline/reset", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        resetBaselineDetection();
        req->send(200, "text/plain", "Baseline reset complete"); });

  server->on("/baseline-results", HTTP_GET, [](AsyncWebServerRequest *req)
             { req->send(200, "text/plain", getBaselineResults()); });

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
    String status = sdAvailable ? "SD card: Available" : "SD card: Not available";
    r->send(200, "text/plain", status); });

  server->on("/stop", HTTP_GET, [](AsyncWebServerRequest *req) {
      stopRequested = true;
      
      // Stop triangulation if active
      if (triangulationActive) {
          stopTriangulation();
      }
      
      if (workerTaskHandle) {
          workerTaskHandle = nullptr;
      }
      if (blueTeamTaskHandle) {
          blueTeamTaskHandle = nullptr;
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

  server->on("/config", HTTP_GET, [](AsyncWebServerRequest *r)
             {
      String configJson = "{\n";
      configJson += "\"nodeId\":\"" + prefs.getString("nodeId", "") + "\",\n";
      configJson += "\"scanMode\":" + String(currentScanMode) + ",\n";
      configJson += "\"channels\":\"";
      
      String channelsCSV;
      for (size_t i = 0; i < CHANNELS.size(); i++) {
          channelsCSV += String(CHANNELS[i]);
          if (i < CHANNELS.size() - 1) {
              channelsCSV += ",";
          }
      }
      configJson += channelsCSV + "\",\n";
      configJson += "\"targets\":\"" + prefs.getString("maclist", "") + "\"\n";
      configJson += "}";
      
      r->send(200, "application/json", configJson); });

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
        delay(100); 
        
        if (!workerTaskHandle) {
            xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288, 
                                  (void*)(intptr_t)(forever ? 0 : secs), 
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
    setMeshSendInterval(interval);
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

  server->on("/secure/destruct", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    if (!req->hasParam("confirm", true) || req->getParam("confirm", true)->value() != "WIPE_ALL_DATA") {
        req->send(400, "text/plain", "Invalid confirmation");
        return;
    }
    
    tamperAuthToken = generateEraseToken();
    executeSecureErase("Manual web request");
    req->send(200, "text/plain", "Secure wipe executed"); });

  server->on("/secure/generate-token", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    if (!req->hasParam("target", true) || !req->hasParam("confirm", true)) {
        req->send(400, "text/plain", "Missing target node or confirmation");
        return;
    }
    
    String target = req->getParam("target", true)->value();
    String confirm = req->getParam("confirm", true)->value();
    
    if (confirm != "GENERATE_ERASE_TOKEN") {
        req->send(400, "text/plain", "Invalid confirmation");
        return;
    }
    
    // Use existing generateEraseToken() function
    String token = generateEraseToken();
    String command = "@" + target + " ERASE_FORCE:" + token;
    
    String response = "Mesh erase command generated:\n\n";
    response += command + "\n\n";
    response += "Token expires in 5 minutes\n";
    response += "Send this exact command via mesh to execute remote erase";
    
    req->send(200, "text/plain", response); });

  server->on("/config/autoerase", HTTP_GET, [](AsyncWebServerRequest *req)
             {
    String response = "{";
    response += "\"enabled\":" + String(autoEraseEnabled ? "true" : "false") + ",";
    response += "\"delay\":" + String(autoEraseDelay) + ",";
    response += "\"cooldown\":" + String(autoEraseCooldown) + ",";
    response += "\"vibrationsRequired\":" + String(vibrationsRequired) + ",";
    response += "\"detectionWindow\":" + String(detectionWindow) + ",";
    response += "\"setupDelay\":" + String(setupDelay) + ",";
    response += "\"inSetupMode\":" + String(inSetupMode ? "true" : "false") + ",";
    response += "\"setupStartTime\":" + String(setupStartTime) + ",";
    response += "\"tamperActive\":" + String(tamperEraseActive ? "true" : "false");
    response += "}";
    req->send(200, "application/json", response); });

  server->on("/config/autoerase", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    if (!req->hasParam("enabled", true) || !req->hasParam("delay", true) || 
        !req->hasParam("cooldown", true) || !req->hasParam("vibrationsRequired", true) ||
        !req->hasParam("detectionWindow", true)) {
        req->send(400, "text/plain", "Missing parameters");
        return;
    }
    if (!req->hasParam("setupDelay", true)) {
        req->send(400, "text/plain", "Missing setupDelay parameter");
        return;
    }
    
    autoEraseEnabled = req->getParam("enabled", true)->value() == "true";
    autoEraseDelay = req->getParam("delay", true)->value().toInt();
    autoEraseCooldown = req->getParam("cooldown", true)->value().toInt();
    vibrationsRequired = req->getParam("vibrationsRequired", true)->value().toInt();
    detectionWindow = req->getParam("detectionWindow", true)->value().toInt();
    setupDelay = req->getParam("setupDelay", true)->value().toInt();
    
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
    }
    
    saveConfiguration();
    req->send(200, "text/plain", "Auto-erase config updated"); });

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
        String* reasonPtr = (String*)param;
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

  server->on("/sniffer", HTTP_POST, [](AsyncWebServerRequest *req) {
        String detection = req->hasParam("detection", true) ? req->getParam("detection", true)->value() : "device-scan";
        int secs = req->hasParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 60;
        bool forever = req->hasParam("forever", true);
        
        if (detection == "deauth") {
            if (secs < 0) secs = 0; 
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", forever ? "Deauth detection starting (forever)" : ("Deauth detection starting for " + String(secs) + "s"));
            
            if (!blueTeamTaskHandle) {
                xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 12288, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
            }
            
        } else if (detection == "baseline") {
            currentScanMode = SCAN_BOTH;
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", 
                    forever ? "Baseline detection starting (forever)" : 
                    ("Baseline detection starting for " + String(secs) + "s"));
            
            if (!workerTaskHandle) {
                xTaskCreatePinnedToCore(baselineDetectionTask, "baseline", 12288, 
                                    (void*)(intptr_t)(forever ? 0 : secs), 
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
            
            currentScanMode = (ScanMode)scanMode;
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            
            String modeStr = (scanMode == SCAN_WIFI) ? "WiFi" : 
                            (scanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
            
            req->send(200, "text/plain", 
                    forever ? ("Randomization detection starting (forever) - " + modeStr) : 
                    ("Randomization detection starting for " + String(secs) + "s - " + modeStr));
            
            if (!workerTaskHandle) {
                xTaskCreatePinnedToCore(randomizationDetectionTask, "randdetect", 8192,
                                    (void*)(intptr_t)(forever ? 0 : secs),
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
            
            currentScanMode = (ScanMode)scanMode;
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            
            String modeStr = (scanMode == SCAN_WIFI) ? "WiFi" : 
                            (scanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
            
            req->send(200, "text/plain", 
                    forever ? ("Device scan starting (forever) - " + modeStr) : 
                    ("Device scan starting for " + String(secs) + "s - " + modeStr));
            
            if (!workerTaskHandle) {
                xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288, 
                                    (void*)(intptr_t)(forever ? 0 : secs), 
                                    1, &workerTaskHandle, 1);
            }
            
        } else if (detection == "drone-detection") {
            currentScanMode = SCAN_WIFI;
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain",
                    forever ? "Drone detection starting (forever)" :
                    ("Drone detection starting for " + String(secs) + "s"));
            
            if (!workerTaskHandle) {
                xTaskCreatePinnedToCore(droneDetectorTask, "drone", 12288,
                                    (void*)(intptr_t)(forever ? 0 : secs),
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
      r->send(200, "text/plain", getRandomizationResults());
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
      for (auto& entry : deviceIdentities) {
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
      if (!req->hasParam("mac", true) || !req->hasParam("duration", true)) {
        req->send(400, "text/plain", "Missing mac or duration parameter");
        return;
      }
      
      String targetMac = req->getParam("mac", true)->value();
      int duration = req->getParam("duration", true)->value().toInt();
      
      if (duration < 60) {
        req->send(400, "text/plain", "Error: Triangulation requires minimum 60 seconds duration");
        return;
      }
      
      uint8_t macBytes[6];
      if (!parseMac6(targetMac, macBytes)) {
        req->send(400, "text/plain", "Error: Invalid MAC address format");
        return;
      }
      
      startTriangulation(targetMac, duration);
      req->send(200, "text/plain", "Triangulation started for " + targetMac + " (" + String(duration) + "s)");
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
    req->send(200, "text/plain", calculateTriangulation());
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
    json += "\"channels\":\"" + channelsCSV + "\"";
    json += "}";
    req->send(200, "application/json", json);
  });

  server->on("/rf-config", HTTP_POST, [](AsyncWebServerRequest *req) {
      if (req->hasParam("preset", true)) {
          uint8_t preset = req->getParam("preset", true)->value().toInt();
          setRFPreset(preset);
          saveConfiguration();
          req->send(200, "text/plain", "RF preset updated");
      } else if (req->hasParam("wifiChannelTime", true) && req->hasParam("wifiScanInterval", true) &&
                req->hasParam("bleScanInterval", true) && req->hasParam("bleScanDuration", true)) {
          uint32_t wct = req->getParam("wifiChannelTime", true)->value().toInt();
          uint32_t wsi = req->getParam("wifiScanInterval", true)->value().toInt();
          uint32_t bsi = req->getParam("bleScanInterval", true)->value().toInt();
          uint32_t bsd = req->getParam("bleScanDuration", true)->value().toInt();
          String channels = req->hasParam("channels", true) ? 
                          req->getParam("channels", true)->value() : "1..14";
          setCustomRFConfig(wct, wsi, bsi, bsd, channels);
          saveConfiguration();
          req->send(200, "text/plain", "Custom RF config updated");
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

  server->begin();
  Serial.println("[WEB] Server started.");
}

// Mesh UART Message Sender
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
    
    if (gpsValid) {
        baseMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    int msg_len = snprintf(mesh_msg, sizeof(mesh_msg) - 1, "%s", baseMsg.c_str());
    
    if (msg_len > 0 && msg_len < MAX_MESH_SIZE) {
        mesh_msg[msg_len] = '\0';
        delay(10);
        Serial.printf("[MESH] %s\n", mesh_msg);
        sendToSerial1(String(mesh_msg), false);
    }
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

void processCommand(const String &command)
{
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
    snprintf(status_msg, sizeof(status_msg),
             "%s: BASELINE_STATUS: Scanning:%s Established:%s Devices:%d Anomalies:%d Phase1:%s",
             nodeId.c_str(),
             baselineStats.isScanning ? "YES" : "NO",
             baselineEstablished ? "YES" : "NO",
             baselineDeviceCount,
             anomalyCount,
             baselineStats.phase1Complete ? "COMPLETE" : "ACTIVE");
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
    float esp_temp_f = (esp_temp * 9.0 / 5.0) + 32.0;
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE"
                                                                                             : "WiFi+BLE";

    uint32_t uptime_secs = millis() / 1000;
    uint32_t uptime_mins = uptime_secs / 60;
    uint32_t uptime_hours = uptime_mins / 60;

    char status_msg[240];

    int written = snprintf(status_msg, sizeof(status_msg),
             "%s: STATUS: Mode:%s Scan:%s Hits:%d Unique:%d Temp:%.1fC/%.1fF Up:%02d:%02d:%02d",
             nodeId.c_str(),
             modeStr.c_str(),
             scanning ? "ACTIVE" : "IDLE",
             totalHits,
             (int)uniqueMacs.size(),
             esp_temp, esp_temp_f,
             (int)uptime_hours, (int)(uptime_mins % 60), (int)(uptime_secs % 60));

    if (gpsValid && written > 0 && written < MAX_MESH_SIZE)
    {
      snprintf(status_msg + written, sizeof(status_msg) - written,
               " GPS:%.6f,%.6f",
               gpsLat, gpsLon);
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
            Serial.printf("[TRIANGULATE] Invalid MAC format: %s\n", target.c_str());
            sendToSerial1(nodeId + ": TRIANGULATE_ACK:INVALID_FORMAT", true);
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
    
    triangulationActive = true;
    triangulationInitiator = false;
    triangulationStart = millis();
    triangulationDuration = duration;
    currentScanMode = SCAN_BOTH;
    stopRequested = false;
    
    if (!workerTaskHandle) {
        xTaskCreatePinnedToCore(listScanTask, "triangulate", 8192,
                               (void *)(intptr_t)duration, 1, &workerTaskHandle, 1);
    }
    
    Serial.printf("[TRIANGULATE] Child node started for %s (%ds)\n", target.c_str(), duration);
    sendToSerial1(nodeId + ": TRIANGULATE_ACK:" + target, true);
  }
  else if (command.startsWith("TRIANGULATE_STOP"))
  {
    Serial.println("[MESH] TRIANGULATE_STOP received");
    stopRequested = true;
    if (triangulationActive && !triangulationInitiator) {
        stopTriangulation();
    }
    sendToSerial1(nodeId + ": TRIANGULATE_STOP_ACK", true);
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
                    
                    if (hitsIdx > 0 && rssiIdx > 0) {
                        int hits = payload.substring(hitsIdx + 5, payload.indexOf(' ', hitsIdx)).toInt();
                        
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
                            initNodeKalmanFilter(newNode);
                            updateNodeRSSI(newNode, rssi);
                            newNode.distanceEstimate = rssiToDistance(newNode, !newNode.isBLE);
                            triangulationNodes.push_back(newNode);
                            Serial.printf("[TRIANGULATE] Added child %s: hits=%d avgRSSI=%ddBm Type=%s\n",
                                        sendingNode.c_str(), hits, rssi,
                                        newNode.isBLE ? "BLE" : "WiFi");
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

        if (content.startsWith("TRIANGULATE_ACK:")) {
            Serial.printf("[TRIANGULATE] Node %s acknowledged triangulation command\n", 
                          sendingNode.c_str());
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
            processCommand(command);
        }
    } else {
        processCommand(cleanMessage);
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
                if (usbBuffer.length() > 5 && usbBuffer.length() <= 240) {  // Mesh 240 char limit
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
        if (usbBuffer.length() > 240) {
            Serial.println("[MESH] at 240 chars, clearing");
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
