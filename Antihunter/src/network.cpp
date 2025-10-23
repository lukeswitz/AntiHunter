#include "network.h"
#include "baseline.h"
#include "triangulation.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include <AsyncTCP.h>
#include <RTClib.h>
#include "esp_task_wdt.h"

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
const int MAX_RETRIES = 10;
bool meshEnabled = true;
static unsigned long lastMeshSend = 0;
const unsigned long MESH_SEND_INTERVAL = 5000;
const int MAX_MESH_SIZE = 240;
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

  Serial.println("Starting AP...");
  WiFi.mode(WIFI_AP);
  delay(100);
  
  randomizeMacAddress();
  delay(50);
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
  delay(500);
  WiFi.setHostname("Antihunter");
  delay(100);
  Serial.println("Starting web server...");
  startWebServer();
}
// ------------- AP HTML -------------

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>AntiHunter</title>
    <style>
      :root{--bg:#000;--fg:#00ff7f;--fg2:#00cc66;--accent:#0aff9d;--card:#0b0b0b;--muted:#00ff7f99;--danger:#ff4444;--border:#003b24}
      *{box-sizing:border-box;margin:0;padding:0}
      body,html{height:100%;margin:0}
      body{background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;line-height:1.4}
      .header{padding:10px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,#001a10,#000);display:flex;flex-wrap:wrap;align-items:center;gap:7px}
      h1{font-size:16px;letter-spacing:0.5px}
      h3{margin:0 0 8px;color:var(--fg);font-size:14px}
      .container{max-width:1400px;margin:0 auto;padding:10px}
      .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:11px;margin-bottom: 16px;box-shadow:0 4px 20px rgba(0,255,127,.05)}
      label{display:block;margin:5px 0 3px;color:var(--muted);font-size:11px}
      input[type=number],input[type=text],select,textarea{width:100%;background:#000;border:1px solid var(--border);border-radius:6px;color:var(--fg);padding:7px;font-family:inherit;font-size:12px}
      input[type=number]{-moz-appearance:textfield}
      input[type=number]::-webkit-outer-spin-button,input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
      textarea{min-height:70px;resize:vertical}
      .btn{display:inline-block;padding:7px 11px;border-radius:6px;border:1px solid #004e2f;background:#001b12;color:var(--fg);text-decoration:none;cursor:pointer;font-size:11px;transition:all .2s;white-space:nowrap}
      .btn:hover{box-shadow:0 4px 14px rgba(10,255,157,.15);transform:translateY(-1px)}
      .btn.primary{background:#002417;border-color:#0c6}
      .btn.alt{background:#00140d;border-color:#004e2f;color:var(--accent)}
      .btn.danger{background:#300;border-color:#f44;color:#f66}
      .row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
      .small{opacity:.65;font-size:10px}
      pre{white-space:pre-wrap;background:#000;border:1px dashed var(--border);border-radius:6px;padding:8px;font-size:10px;line-height:1.3;overflow-x:auto;max-height:350px;overflow-y:auto}
      hr{border:0;border-top:1px dashed var(--border);margin:10px 0}
      .banner{font-size:10px;color:#0aff9d;border:1px dashed #004e2f;padding:5px 7px;border-radius:6px;background:#001108;margin-bottom:8px}
      #toast{position:fixed;right:12px;bottom:12px;display:flex;flex-direction:column;gap:5px;z-index:9999}
      .toast{background:#001d12;border:1px solid #0aff9d55;color:var(--fg);padding:8px 10px;border-radius:6px;box-shadow:0 6px 24px rgba(10,255,157,.2);opacity:0;transform:translateY(8px);transition:opacity .15s,transform .15s;font-size:11px}
      .toast.show{opacity:1;transform:none}
      .toast.success{border-color:#00cc66;background:#002200}
      .toast.error{border-color:#ff4444;background:#300}
      .toast.warning{border-color:#ffaa00;background:#332200}
      .footer{opacity:.7;font-size:10px;padding:6px;text-align:center;margin-top:12px}
      .logo{width:24px;height:24px}
      .status-bar{display:flex;flex-wrap:wrap;gap:5px;align-items:center;margin-left:auto;font-size:10px}
      .status-item{background:#001a10;border:1px solid var(--border);padding:3px 7px;border-radius:5px;font-size:9px;white-space:nowrap}
      .status-item.active{border-color:#0c6;background:#002417}
      .tab-buttons{display:flex;gap:5px;margin-bottom:8px;flex-wrap:wrap}
      .tab-btn{padding:6px 11px;background:#001b12;border:1px solid var(--border);border-radius:6px;cursor:pointer;color:var(--muted);font-size:11px;transition:all .2s}
      .tab-btn.active{background:#002417;border-color:#0c6;color:var(--fg)}
      .tab-content{display:none}
      .tab-content.active{display:block}
      .stat-item{background:#001108;border:1px solid var(--border);padding:8px;border-radius:6px}
      .stat-label{color:var(--muted);font-size:9px;text-transform:uppercase;margin-bottom:3px}
      .stat-value{color:var(--fg);font-size:15px;font-weight:700}
      details > summary{list-style:none;cursor:pointer;font-weight:bold;color:var(--accent);margin-bottom:7px;font-size:11px}
      details > summary::-webkit-details-marker{display:none}
      details[open] > summary > span:first-child{transform:rotate(90deg)}
      .card-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none;margin-bottom:10px}
      .card-header h3{margin:0}
      .collapse-icon{transition:transform 0.2s;font-size:13px;color:var(--muted)}
      .collapse-icon.open{transform:rotate(90deg)}
      .card-body{overflow:hidden;transition:max-height 0.3s ease}
      .card-body.collapsed{max-height:0!important;margin:0;padding:0}
      .section-divider{border-top:1px solid var(--border);margin:12px 0;padding-top:12px}
      
      
      @media (min-width:900px){
        .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
        .grid-2 > .card{align-self:stretch}
        .grid-node-diag{display:grid;grid-template-columns:minmax(280px,auto) 1fr;gap:10px}
        .stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
      }
      @media (max-width:899px){
        .grid-2,.grid-node-diag{display:flex;flex-direction:column;gap:10px}
        .stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:7px}
        .container{padding:8px}
        .card{padding:10px}
        h1{font-size:15px}
        .status-bar{width:100%;margin-left:0;margin-top:6px}
      }
      @media (max-width:600px){
        .stat-grid{grid-template-columns:1fr}
        .status-item{font-size:8px;padding:2px 5px}
        input[type=number],input[type=text],select{font-size:11px;padding:6px}
      }
    </style>
  </head>
  <body>
    <div id="toast"></div>
    <div class="header">
      <svg class="logo" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect x="6" y="6" width="52" height="52" rx="8" fill="#00180F" stroke="#00ff7f" stroke-width="2"/>
        <path d="M16 40 L32 16 L48 40" fill="none" stroke="#0aff9d" stroke-width="3"/>
        <circle cx="32" cy="44" r="3" fill="#00ff7f"/>
      </svg>
      <h1>AntiHunter</h1>
      <div class="status-bar">
        <div class="status-item" id="modeStatus">WiFi</div>
        <div class="status-item" id="scanStatus">Idle</div>
        <div class="status-item" id="gpsStatus">GPS</div>
        <div class="status-item" id="rtcStatus">RTC</div>
        <a class="btn danger" href="/stop" data-ajax="true" id="stopAllBtn" style="margin-left:auto;padding:6px 12px;font-size:11px;display:none;">STOP ALL</a>
      </div>
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
              <summary style="cursor:pointer;font-weight:bold;color:var(--accent);margin-bottom:8px;">Target List</summary>
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
              <summary style="cursor:pointer;font-weight:bold;color:var(--accent);margin-bottom:8px;">Allow List</summary>
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
              
              <label style="font-size:11px;">Channels</label>
              <input type="text" name="ch" placeholder="1..14" value="1..14" style="margin-bottom:8px;">
              
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
                <option value="randomization-detection">MAC Randomization Tracer</option>
                <option value="deauth">Deauth/Disassoc Detection</option>
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
                    <label style="font-size:11px;">RAM Device Cache</label>
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
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;">
                  <input type="checkbox" id="foreverBaseline" name="forever" value="1">Forever
                </label>
                <div id="baselineStatus" style="padding:8px;background:var(--card);border:1px solid #003b24;border-radius:6px;font-size:11px;margin-bottom:8px;">
                  <div style="color:#888;">No baseline data</div>
                </div>
              </div>
              
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;">
                <button class="btn primary" type="submit" id="startDetectionBtn" style="flex:1;min-width:80px;">Start</button>
                <a class="btn alt" href="/sniffer-cache" data-ajax="false" id="cacheBtn" style="display:none;">Cache</a>
                <a class="btn" href="/baseline-results" data-ajax="false" style="display:none;" id="baselineResultsBtn">Results</a>
                <button class="btn alt" type="button" onclick="resetBaseline()" style="display:none;" id="resetBaselineBtn">Reset</button>
                <button type="button" class="btn" id="randTracksBtn" style="display:none;" onclick="showDeviceIdentities()">View IDs</button>
                <button type="button" class="btn" id="clearOldBtn" style="display:none;" onclick="clearOldIdentities()">Clear Old</button>
              </div>              
            </form>
          </div>
        </div>
      </div>
      
    <div class="grid-node-diag" style="margin-bottom:16px;">
      <div class="card" style="min-width:280px;">
        <h3>RF Scan Settings</h3>
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
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
              <div>
                <label style="font-size:10px;color:var(--muted);">BLE Scan Duration (ms)</label>
                <input type="number" id="bleScanDuration" min="1000" max="5000" value="2000" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--muted);">BLE Scan Interval (ms)</label>
                <input type="number" id="bleScanInterval" min="1000" max="10000" value="2000" style="padding:4px;font-size:11px;">
              </div>
              
            </div>
          </div>
          
        </div>
        <button class="btn primary" type="button" onclick="saveRFConfig()" style="width:100%;margin-top:8px;">Save RF Settings</button>
      </div>
      
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
          <h3 style="margin:0;">Scan Results</h3>
          <button class="btn alt" type="button" onclick="clearResults()" style="padding:6px 12px;font-size:11px;">Clear</button>
        </div>
        <pre id="r" style="margin:0;">No scan data yet.</pre>
      </div>
    </div>
    
      
      <!-- Bottom Grid: Node + Diagnostics -->
      <div class="grid-node-diag" style="margin-bottom:16px;">
        
        <div class="card" style="min-width:280px;">
          <h3>Node Configuration</h3>
          <form id="nodeForm" method="POST" action="/node-id">
            <label>Node ID</label>
            <input type="text" id="nodeId" name="id" maxlength="16" placeholder="NODE_01">
            <button class="btn primary" type="submit" style="margin-top:8px;width:100%;">Update</button>
          </form>
          
          <hr>
          
          <label style="display:flex;align-items:center;gap:8px;margin:12px 0;">
            <input type="checkbox" id="meshEnabled" checked>
            <span style="font-size:13px;">Mesh Communications</span>
          </label>
          
          <div style="display:flex;gap:8px;">
            <a class="btn alt" href="/mesh-test" data-ajax="true" style="flex:1;">Test</a>
            <a class="btn" href="/gps" data-ajax="false" style="flex:1;">GPS</a>
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
            <pre id="hardwareDiag" style="margin:0;">Loading...</pre>
          </div>
          
          <div id="network" class="tab-content">
            <pre id="networkDiag" style="margin:0;">Loading...</pre>
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
          
          <!-- Auto-Erase Configuration -->
          <div style="margin-top:16px;">
            <label style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
              <input type="checkbox" id="autoEraseEnabled">
              <span>Enable auto-erase on tampering</span>
            </label>
            
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:11px;">Delay</label>
                <select id="autoEraseDelay">
                  <option value="30000" selected>30s</option>
                  <option value="60000">1m</option>
                  <option value="120000">2m</option>
                </select>
              </div>
              <div>
                <label style="font-size:11px;">Cooldown</label>
                <select id="autoEraseCooldown">
                  <option value="300000" selected>5m</option>
                  <option value="600000">10m</option>
                  <option value="1800000">30m</option>
                </select>
              </div>
            </div>
            
            <button class="btn primary" type="button" onclick="saveAutoEraseConfig()" style="width:100%;">Save Config</button>
            <div id="autoEraseStatus" style="margin-top:8px;padding:6px;border-radius:4px;font-size:11px;text-align:center;">DISABLED</div>
          </div>
        </details>
      </div>
      
      <div class="footer">© Team AntiHunter 2025 | Node: <span id="footerNodeId">--</span></div>
    <script>
      let selectedMode = '0';
      let baselineUpdateInterval = null;
      let lastScanningState = false;
      
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
          updateRFPresetUI();
        } catch(e) {}
      }

      function updateRFPresetUI() {
        const preset = document.getElementById('rfPreset').value;
        const customDiv = document.getElementById('customRFSettings');
        customDiv.style.display = (preset === '3') ? 'block' : 'none';
      }

      async function saveRFConfig() {
        const preset = document.getElementById('rfPreset').value;
        const fd = new FormData();
        
        if (preset === '3') {
          fd.append('wifiChannelTime', document.getElementById('wifiChannelTime').value);
          fd.append('wifiScanInterval', document.getElementById('wifiScanInterval').value);
          fd.append('bleScanInterval', document.getElementById('bleScanInterval').value);
          fd.append('bleScanDuration', document.getElementById('bleScanDuration').value);
        } else {
          fd.append('preset', preset);
        }
        
        try {
          const r = await fetch('/rf-config', {method: 'POST', body: fd});
          const msg = await r.text();
          toast(msg);
        } catch(e) {
          toast('Error: ' + e.message);
        }
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
        if (!confirm('Remove identities not seen in the last hour?')) return;
        
        fetch('/randomization/clear-old', { method: 'POST', body: 'age=3600' })
          .then(r => r.text())
          .then(data => {
            toast(data, 'success');
            load();
          })
          .catch(err => toast('Error: ' + err, 'error'));
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
          const detectionMode = document.getElementById('detectionMode').value;
          
          if (detectionMode === 'baseline' && stats.scanning) {
            startDetectionBtn.textContent = stats.phase1Complete ? 'Stop Monitoring' : 'Stop Baseline';
            startDetectionBtn.classList.remove('primary');
            startDetectionBtn.classList.add('danger');
            startDetectionBtn.type = 'button';
            startDetectionBtn.onclick = function(e) {
              e.preventDefault();
              fetch('/stop').then(r=>r.text()).then(t=>toast(t));
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
        if (!confirm('Clear scan results? This will only clear the display, not the actual data.')) return;
        document.getElementById('r').innerText = 'Results cleared.';
        toast('Results display cleared', 'info');
      }
      
      function updateStatusIndicators(diagText) {
          const taskTypeMatch = diagText.match(/Task Type: ([^\n]+)/);
          const taskType = taskTypeMatch ? taskTypeMatch[1].trim() : 'none';
          const isScanning = diagText.includes('Scanning: yes');
          
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

              if (taskType === 'sniffer' || taskType === 'drone' || taskType === 'randdetect' || taskType === 'blueteam' || taskType === 'baseline') {
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
                      
                      const detectionMode = document.getElementById('detectionMode')?.value;
                      document.getElementById('cacheBtn').style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
                      document.getElementById('randTracksBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
                      document.getElementById('clearOldBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
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

              const startDetectionBtn = document.getElementById('startDetectionBtn');
              if (startDetectionBtn) {
                  startDetectionBtn.textContent = 'Start Scan';
                  startDetectionBtn.classList.remove('danger');
                  startDetectionBtn.classList.add('primary');
                  startDetectionBtn.type = 'submit';
                  startDetectionBtn.onclick = null;
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

      function showDeviceIdentities() {
        fetch('/randomization/identities')
          .then(r => r.json())
          .then(identities => {
            const modal = document.createElement('div');
            modal.id = 'randTracksModal';
            modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;overflow:auto;';
            
            let content = '<div style="background:#1a1a1a;padding:24px;border-radius:8px;max-width:1200px;width:100%;max-height:90vh;overflow:auto;">';
            content += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">';
            content += '<h3 style="margin:0;">Ghost Traces: (' + identities.length + ')</h3>';
            content += '<button onclick="document.getElementById(\'randTracksModal\').remove()" style="background:none;border:none;color:#fff;font-size:24px;cursor:pointer;">&times;</button>';
            content += '</div>';
            content += '<div style="display:grid;gap:12px;">';
            
            identities.forEach(track => {
              content += '<div style="background:#0a0a0a;padding:16px;border-radius:4px;border-left:3px solid #4CAF50;">';
              content += '<div style="display:flex;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:8px;">';
              content += '<strong style="font-size:16px;color:#4CAF50;">' + track.identityId + '</strong>';
              content += '<div style="display:flex;gap:16px;font-size:14px;flex-wrap:wrap;">';
              content += '<span>Sessions: <strong>' + track.sessions + '</strong></span>';
              content += '<span>Confidence: <strong>' + (track.confidence * 100).toFixed(0) + '%</strong></span>';
              content += '</div>';
              content += '</div>';
              
              content += '<div style="display:flex;gap:16px;font-size:13px;color:#888;margin-bottom:8px;">';
              content += '<span>Type: <strong style="color:#4CAF50;">' + track.deviceType + '</strong></span>';
              content += '<span>Avg RSSI: <strong style="color:#4CAF50;">' + track.avgRssi + ' dBm</strong></span>';
              content += '</div>';
              
              content += '<details style="margin-top:14px;" onclick="this.querySelector(\'span\').style.transform = this.open ? \'rotate(90deg)\' : \'rotate(0deg)\'">';
              content += '<summary style="cursor:pointer;color:#0aff9d;user-select:none;padding:6px 0;font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;">';
              content += '<span style="display:inline-block;transition:transform 0.2s;font-size:11px;">▶</span>';
              content += 'Device MACs (' + track.macs.length + ')</summary>';
              content += '<div style="margin-top:8px;padding:8px;background:#1a1a1a;border-radius:4px;max-height:300px;overflow-y:auto;">';
              content += '</summary>';
              content += '<div style="margin-top:10px;padding:10px;background:#001108;border:1px solid #003b24;border-radius:6px;max-height:300px;overflow-y:auto;">';

              track.macs.forEach((mac, idx) => {
                const isRand = (parseInt(mac.substring(0, 2), 16) & 0x02) !== 0;
                const badge = isRand ? 
                  '<span style="background:#FF5722;padding:2px 6px;border-radius:3px;font-size:11px;margin-left:8px;">RANDOMIZED</span>' : 
                  '<span style="background:#2196F3;padding:2px 6px;border-radius:3px;font-size:11px;margin-left:8px;">STABLE</span>';
                content += '<div style="padding:4px 0;font-family:monospace;font-size:13px;">';
                content += mac + badge;
                content += '</div>';
              });
              
              content += '</div></details>';
              content += '</div>';
            });
            
            content += '</div></div>';
            modal.innerHTML = content;
            document.body.appendChild(modal);
          })
          .catch(err => toast('Error fetching fingerprints: ' + err, 'error'));
      }

      function parseAndStyleResults(text) {
        if (!text || text.trim() === '' || text.includes('None yet') || text.includes('No scan data')) {
          return '<div style="color:#00ff7f99;padding:20px;text-align:center;">No scan data yet.</div>';
        }
        
        let html = '';
        
        if (text.includes('MAC Randomization Detection Results')) {
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
          html = '<pre style="margin:0;background:#000;border:1px solid #003b24;border-radius:8px;padding:12px;color:#00ff7f;font-size:11px;overflow-x:auto;">' + text + '</pre>';
        }
        
        return html;
      }

      function parseRandomizationResults(text) {
        const headerMatch = text.match(/Active Sessions: (\d+)/);
        const identitiesMatch = text.match(/Device Identities: (\d+)/);
        
        let html = '<div style="margin-bottom:16px;padding:12px;background:#000;border:1px solid #003b24;border-radius:8px;">';
        html += '<div style="font-size:14px;color:#00ff7f;margin-bottom:8px;font-weight:bold;">MAC Randomization Detection Results</div>';
        html += '<div style="display:flex;gap:20px;font-size:12px;color:#00ff7f99;">';
        if (headerMatch) html += '<span>Active Sessions: <strong style="color:#00ff7f;">' + headerMatch[1] + '</strong></span>';
        if (identitiesMatch) html += '<span>Device Identities: <strong style="color:#00ff7f;">' + identitiesMatch[1] + '</strong></span>';
        html += '</div></div>';
        
        const trackBlocks = text.split(/(?=Track ID:)/g).filter(b => b.includes('Track ID'));
        
        trackBlocks.forEach(block => {
          const trackMatch = block.match(/Track ID: (T-\d+)/);
          const typeMatch = block.match(/Type: (WiFi Device|BLE Device)/);
          const macsMatch = block.match(/MACs linked: (\d+)/);
          const confMatch = block.match(/Confidence: ([\d.]+)/);
          const sessionsMatch = block.match(/Sessions: (\d+)/);
          const intervalMatch = block.match(/Interval consistency: ([\d.]+)/);
          const rssiMatch = block.match(/RSSI consistency: ([\d.]+)/);
          const channelsMatch = block.match(/Channels: (\d+)/);
          const globalMacMatch = block.match(/Global MAC: ([A-F0-9:]+)/);
          const lastSeenMatch = block.match(/Last seen: (\d+)s ago/);
          const macsListMatch = block.match(/MACs: (.+)/);
          
          if (!trackMatch) return;
          
          const trackId = trackMatch[1];
          const macCount = macsMatch ? macsMatch[1] : '0';
          const confidence = confMatch ? (parseFloat(confMatch[1]) * 100).toFixed(0) : '0';
          const sessions = sessionsMatch ? sessionsMatch[1] : '0';
          
          html += '<div style="background:#000;padding:18px;border-radius:8px;border:1px solid #003b24;margin-bottom:12px;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'#00cc66\'" onmouseout="this.style.borderColor=\'#003b24\'">';

          html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:10px;">';
          html += '<strong style="font-size:17px;color:#00ff7f;letter-spacing:0.5px;">' + trackId + '</strong>';
          html += '<div style="display:flex;gap:18px;font-size:13px;color:#00ff7f99;">';
          html += '<span>Sessions: <strong style="color:#00ff7f;">' + sessions + '</strong></span>';
          html += '<span>Confidence: <strong style="color:#00ff7f;">' + confidence + '%</strong></span>';
          html += '</div>';
          html += '</div>';
          
          html += '<div style="display:flex;gap:18px;font-size:12px;color:#00ff7f66;margin-bottom:10px;flex-wrap:wrap;">';
          const deviceType = typeMatch ? typeMatch[1] : 'Unknown';
          html += '<span>Type: <strong style="color:#00ff7f99;">' + deviceType + '</strong></span>';
          if (channelsMatch && parseInt(channelsMatch[1]) > 0) {
            html += '<span>Channels: <strong style="color:#00ff7f99;">' + channelsMatch[1] + '</strong></span>';
          }
          if (intervalMatch) {
            html += '<span>Interval: <strong style="color:#00ff7f99;">' + intervalMatch[1] + '</strong></span>';
          }
          if (rssiMatch) {
            html += '<span>RSSI: <strong style="color:#00ff7f99;">' + rssiMatch[1] + '</strong></span>';
          }
          if (lastSeenMatch) {
            html += '<span>Last: <strong style="color:#00ff7f99;">' + lastSeenMatch[1] + 's ago</strong></span>';
          }
          html += '</div>';
          
          if (globalMacMatch) {
            html += '<div style="margin-bottom:10px;padding:8px;background:#001108;border:1px solid #004e2f;border-radius:6px;font-family:monospace;font-size:12px;color:#0aff9d;">';
            html += 'Global MAC: <strong>' + globalMacMatch[1] + '</strong>';
            html += '</div>';
          }
          
          if (macsListMatch) {
            const macsList = macsListMatch[1].split(',').map(m => m.trim()).filter(m => m && m !== '');
            const moreMatch = macsListMatch[1].match(/\(\+(\d+) more\)/);
            
            html += '<details style="margin-top:14px;" onclick="this.querySelector(\'span\').style.transform = this.open ? \'rotate(90deg)\' : \'rotate(0deg)\'">';
            html += '<summary style="cursor:pointer;color:#0aff9d;user-select:none;padding:6px 0;font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;">';
            html += '<span style="display:inline-block;transition:transform 0.2s;font-size:11px;">▶</span>';
            html += '<strong>Device MACs (' + macCount + ')</strong>';
            html += '</summary>';
            html += '<div style="margin-top:10px;padding:10px;background:#001108;border:1px solid #003b24;border-radius:6px;max-height:300px;overflow-y:auto;">';
            
            macsList.forEach(mac => {
              if (mac.includes('(+')) return;
              const firstByte = parseInt(mac.substring(0, 2), 16);
              const isRand = (firstByte & 0x02) !== 0;
              const isGlobalLeak = !isRand && globalMacMatch && (globalMacMatch[1] === mac);
              let badge;
              if (isRand) {
                badge = '<span style="background:#FF5722;color:#fff;padding:3px 8px;border-radius:4px;font-size:10px;margin-left:10px;font-weight:bold;">RANDOMIZED</span>';
              } else if (isGlobalLeak) {
                badge = '<span style="background:#FF9800;color:#fff;padding:3px 8px;border-radius:4px;font-size:10px;margin-left:10px;font-weight:bold;">GLOBAL LEAK</span>';
              } else {
                badge = '<span style="background:#2196F3;color:#fff;padding:3px 8px;border-radius:4px;font-size:10px;margin-left:10px;font-weight:bold;">STABLE</span>';
              }
              html += '<div style="padding:6px 0;font-family:monospace;font-size:13px;color:#00ff7f;border-bottom:1px solid #003b24;display:flex;justify-content:space-between;align-items:center;">';
              html += '<span>' + mac + '</span>' + badge;
              html += '</div>';
            });
            
            if (moreMatch) {
              html += '<div style="padding:8px;text-align:center;color:#00ff7f99;font-size:11px;font-style:italic;">+ ' + moreMatch[1] + ' more addresses not shown</div>';
            }
            
            html += '</div></details>';
          }
          
          html += '</div>';
        });
        
        return html;
      }

      function parseBaselineResults(text) {
        let html = '';
        
        const totalMatch = text.match(/Total devices in baseline: (\d+)/);
        const wifiMatch = text.match(/WiFi devices: (\d+)/);
        const bleMatch = text.match(/BLE devices: (\d+)/);
        const rssiThreshMatch = text.match(/RSSI threshold: ([-\d]+) dBm/);
        const anomalyCountMatch = text.match(/Total anomalies: (\d+)/);
        
        if (text.includes('Baseline not yet established')) {
          html += '<div style="padding:16px;background:#001108;border:1px solid #004e2f;border-radius:8px;text-align:center;color:#00ff7f99;">';
          html += '<div style="font-size:14px;margin-bottom:8px;">Baseline Not Yet Established</div>';
          const devicesMatch = text.match(/Devices detected so far: (\d+)/);
          if (devicesMatch) {
            html += '<div style="font-size:12px;">Devices detected: <strong style="color:#00ff7f;">' + devicesMatch[1] + '</strong></div>';
          }
          html += '</div>';
          return html;
        }
        
        html += '<div style="margin-bottom:16px;padding:12px;background:#000;border:1px solid #003b24;border-radius:8px;">';
        html += '<div style="font-size:14px;color:#00ff7f;margin-bottom:10px;font-weight:bold;">Baseline Established</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;font-size:12px;color:#00ff7f99;">';
        if (totalMatch) html += '<span>Total: <strong style="color:#00ff7f;">' + totalMatch[1] + '</strong></span>';
        if (wifiMatch) html += '<span>WiFi: <strong style="color:#00ff7f;">' + wifiMatch[1] + '</strong></span>';
        if (bleMatch) html += '<span>BLE: <strong style="color:#00ff7f;">' + bleMatch[1] + '</strong></span>';
        if (rssiThreshMatch) html += '<span>Threshold: <strong style="color:#00ff7f;">' + rssiThreshMatch[1] + ' dBm</strong></span>';
        html += '</div></div>';
        
        if (anomalyCountMatch) {
          html += '<div style="margin-bottom:12px;padding:12px;background:#300;border:1px solid #ff4444;border-radius:8px;">';
          html += '<div style="font-size:14px;color:#ff4444;font-weight:bold;">⚠ Anomalies Detected: ' + anomalyCountMatch[1] + '</div>';
          html += '</div>';
          
          const anomalySection = text.split('=== ANOMALIES DETECTED ===')[1];
          if (anomalySection) {
            const anomalyLines = anomalySection.split('\n').filter(l => l.trim() && !l.includes('Total anomalies'));
            anomalyLines.forEach(line => {
              const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI:([-\d]+)dBm(?:\s+CH:(\d+))?\s*(?:"([^"]+)")?\s+-\s+(.+)$/);
              if (match) {
                const [_, type, mac, rssi, channel, name, reason] = match;
                
                html += '<div style="background:#000;padding:14px;border-radius:8px;border:1px solid #ff4444;margin-bottom:10px;">';
                html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:10px;">';
                html += '<div style="font-family:monospace;font-size:15px;color:#ff4444;">' + mac + '</div>';
                html += '<span style="background:#ff4444;color:#000;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:bold;">' + type + '</span>';
                html += '</div>';
                html += '<div style="display:flex;gap:16px;font-size:12px;color:#00ff7f66;margin-bottom:8px;flex-wrap:wrap;">';
                html += '<span>RSSI: <strong style="color:#00ff7f99;">' + rssi + ' dBm</strong></span>';
                if (channel) html += '<span>Channel: <strong style="color:#00ff7f99;">' + channel + '</strong></span>';
                if (name) html += '<span>Name: <strong style="color:#00ff7f99;">' + name + '</strong></span>';
                html += '</div>';
                html += '<div style="padding:8px;background:#001108;border:1px solid #004e2f;border-radius:6px;color:#ff6666;font-size:12px;">';
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
          html += '<summary style="cursor:pointer;color:#0aff9d;user-select:none;padding:6px 0;font-size:13px;list-style:none;display:flex;align-items:center;gap:6px;">';
          html += '<span style="display:inline-block;transition:transform 0.2s;">▶</span>';
          html += 'Baseline Devices (Cached in RAM)';
          html += '</summary>';
          html += '<div style="margin-top:10px;padding:10px;background:#001108;border:1px solid #003b24;border-radius:6px;max-height:400px;overflow-y:auto;">';
          
          const deviceLines = baselineSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/));
          deviceLines.forEach(line => {
            const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:([-\d]+)dBm\s+Max:([-\d]+)dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
            if (match) {
              const [_, type, mac, avg, min, max, hits, channel, name] = match;
              html += '<div style="padding:8px;border-bottom:1px solid #003b24;font-size:12px;color:#00ff7f;">';
              html += '<div style="font-family:monospace;margin-bottom:4px;">' + mac + ' <span style="background:#003b24;padding:2px 6px;border-radius:3px;font-size:10px;margin-left:8px;">' + type + '</span></div>';
              html += '<div style="color:#00ff7f66;font-size:11px;">Avg: ' + avg + 'dBm | Min: ' + min + 'dBm | Max: ' + max + 'dBm | Hits: ' + hits;
              if (channel) html += ' | CH: ' + channel;
              if (name) html += ' | "' + name + '"';
              html += '</div>';
              html += '</div>';
            }
          });
          
          html += '</div></details>';
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
        
        html += '<div style="margin-bottom:16px;padding:12px;background:#000;border:1px solid #003b24;border-radius:8px;">';
        html += '<div style="font-size:14px;color:#00ff7f;margin-bottom:10px;font-weight:bold;">⚠ Deauth Attack Detection Results</div>';
        html += '<div style="display:flex;gap:20px;font-size:12px;color:#00ff7f99;flex-wrap:wrap;">';
        if (durationMatch) html += '<span>Duration: <strong style="color:#00ff7f;">' + durationMatch[1] + '</strong></span>';
        if (deauthMatch) html += '<span>Deauth: <strong style="color:#ff4444;">' + deauthMatch[1] + '</strong></span>';
        if (disassocMatch) html += '<span>Disassoc: <strong style="color:#ff4444;">' + disassocMatch[1] + '</strong></span>';
        if (totalMatch) html += '<span>Total: <strong style="color:#ff4444;">' + totalMatch[1] + '</strong></span>';
        if (targetsMatch) html += '<span>Targets: <strong style="color:#00ff7f;">' + targetsMatch[1] + '</strong></span>';
        html += '</div></div>';
        
        if (text.includes('No attacks detected')) {
          html += '<div style="padding:20px;text-align:center;color:#00ff7f66;font-size:13px;">No attacks detected</div>';
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
            
            currentTargetHtml = '<div style="background:#000;padding:16px;border-radius:8px;border:1px solid #ff4444;margin-bottom:12px;">';
            currentTargetHtml += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:10px;">';
            currentTargetHtml += '<div style="font-family:monospace;font-size:15px;color:#ff4444;">' + target + '</div>';
            if (isBroadcast) {
              currentTargetHtml += '<span style="background:#ff6666;color:#000;padding:4px 10px;border-radius:4px;font-size:10px;font-weight:bold;">BROADCAST ATTACK</span>';
            }
            currentTargetHtml += '</div>';
            
            currentTargetHtml += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:10px;font-size:12px;">';
            currentTargetHtml += '<div style="padding:8px;background:#001108;border:1px solid #003b24;border-radius:6px;">';
            currentTargetHtml += '<div style="color:#00ff7f66;font-size:10px;margin-bottom:2px;">Total Attacks</div>';
            currentTargetHtml += '<div style="color:#ff4444;font-size:16px;font-weight:bold;">' + total + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:#001108;border:1px solid #003b24;border-radius:6px;">';
            currentTargetHtml += '<div style="color:#00ff7f66;font-size:10px;margin-bottom:2px;">Broadcast</div>';
            currentTargetHtml += '<div style="color:#ff6666;font-size:16px;font-weight:bold;">' + broadcast + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:#001108;border:1px solid #003b24;border-radius:6px;">';
            currentTargetHtml += '<div style="color:#00ff7f66;font-size:10px;margin-bottom:2px;">Targeted</div>';
            currentTargetHtml += '<div style="color:#ff8844;font-size:16px;font-weight:bold;">' + targeted + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div style="padding:8px;background:#001108;border:1px solid #003b24;border-radius:6px;">';
            currentTargetHtml += '<div style="color:#00ff7f66;font-size:10px;margin-bottom:2px;">Signal / Channel</div>';
            currentTargetHtml += '<div style="color:#00ff7f99;font-size:14px;font-weight:bold;">' + rssi + ' dBm / CH' + channel + '</div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '</div>';
            
            currentTargetHtml += '<div style="margin-top:10px;padding:10px;background:#001108;border:1px solid #003b24;border-radius:6px;">';
            currentTargetHtml += '<div style="font-size:11px;color:#00ff7f99;margin-bottom:8px;font-weight:bold;">Attack Sources:</div>';
            
            currentTarget = target;
            inSourcesList = true;
            continue;
          }
          
          if (inSourcesList && line.trim().startsWith('←')) {
            const sourceMatch = line.match(/← ([A-F0-9:]+) \((\d+)x\)/);
            if (sourceMatch) {
              const [_, source, count] = sourceMatch;
              currentTargetHtml += '<div style="padding:6px;font-family:monospace;font-size:12px;color:#00ff7f;border-bottom:1px solid #003b24;">';
              currentTargetHtml += '<span style="color:#ff8844;">←</span> ' + source + ' <span style="color:#00ff7f66;">(' + count + ' attacks)</span>';
              currentTargetHtml += '</div>';
            }
          }
          
          if (inSourcesList && line.trim().startsWith('...')) {
            const moreMatch = line.match(/\((\d+) more attackers\)/);
            if (moreMatch) {
              currentTargetHtml += '<div style="padding:8px;text-align:center;color:#00ff7f66;font-size:11px;">+ ' + moreMatch[1] + ' more attackers</div>';
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
          html += '<div style="padding:12px;text-align:center;color:#00ff7f66;font-size:12px;border:1px dashed #003b24;border-radius:6px;">+ ' + finalMoreMatch[1] + ' more targets</div>';
        }
        
        return html;
      }

      function parseDroneResults(text) {
        let html = '';
        
        const totalMatch = text.match(/Total detections: (\d+)/);
        const uniqueMatch = text.match(/Unique drones: (\d+)/);
        
        html += '<div style="margin-bottom:16px;padding:12px;background:#000;border:1px solid #003b24;border-radius:8px;">';
        html += '<div style="font-size:14px;color:#00ff7f;margin-bottom:10px;font-weight:bold;">🛸 Drone Detection Results</div>';
        html += '<div style="display:flex;gap:20px;font-size:12px;color:#00ff7f99;">';
        if (totalMatch) html += '<span>Total: <strong style="color:#00ff7f;">' + totalMatch[1] + '</strong></span>';
        if (uniqueMatch) html += '<span>Unique: <strong style="color:#00ff7f;">' + uniqueMatch[1] + '</strong></span>';
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
          
          html += '<div style="background:#000;padding:18px;border-radius:8px;border:1px solid #0aff9d;margin-bottom:12px;">';
          html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px;flex-wrap:wrap;gap:10px;">';
          html += '<div style="font-family:monospace;font-size:15px;color:#0aff9d;">' + macMatch[1] + '</div>';
          if (rssiMatch) html += '<span style="color:#00ff7f99;font-size:12px;">RSSI: <strong style="color:#00ff7f;">' + rssiMatch[1] + ' dBm</strong></span>';
          html += '</div>';
          
          if (uavMatch) {
            html += '<div style="padding:8px;background:#001108;border:1px solid #004e2f;border-radius:6px;margin-bottom:8px;font-size:12px;color:#0aff9d;">';
            html += 'UAV ID: <strong>' + uavMatch[1] + '</strong>';
            html += '</div>';
          }
          
          if (locMatch) {
            html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;font-size:11px;color:#00ff7f66;margin-top:8px;">';
            html += '<div>Location: <strong style="color:#00ff7f99;">' + locMatch[1] + ', ' + locMatch[2] + '</strong></div>';
            if (altMatch) html += '<div>Altitude: <strong style="color:#00ff7f99;">' + altMatch[1] + 'm</strong></div>';
            if (speedMatch) html += '<div>Speed: <strong style="color:#00ff7f99;">' + speedMatch[1] + ' m/s</strong></div>';
            html += '</div>';
          }
          
          if (opLocMatch) {
            html += '<div style="margin-top:8px;padding:8px;background:#001a10;border:1px solid #003b24;border-radius:6px;font-size:11px;color:#00ff7f66;">';
            html += 'Operator: <strong style="color:#00ff7f99;">' + opLocMatch[1] + ', ' + opLocMatch[2] + '</strong>';
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
          html += '<div style="margin-bottom:16px;padding:12px;background:#000;border:1px solid #003b24;border-radius:8px;">';
          html += '<div style="font-size:14px;color:#00ff7f;margin-bottom:8px;font-weight:bold;">Device Discovery Scan Results</div>';
          html += '<div style="display:flex;gap:20px;font-size:12px;color:#00ff7f99;flex-wrap:wrap;">';
          if (modeMatch) html += '<span>Mode: <strong style="color:#00ff7f;">' + modeMatch[1] + '</strong></span>';
          if (durationMatch) html += '<span>Duration: <strong style="color:#00ff7f;">' + durationMatch[1] + '</strong></span>';
          if (hitsMatch) html += '<span>Target Hits: <strong style="color:#00ff7f;">' + hitsMatch[1] + '</strong></span>';
          if (uniqueMatch) html += '<span>Unique: <strong style="color:#00ff7f;">' + uniqueMatch[1] + '</strong></span>';
          html += '</div></div>';
        }
        
        const lines = text.split('\n');
        lines.forEach(line => {
          const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI=([-\d]+)dBm(?:\s+CH=(\d+))?(?:\s+Name=(.+))?/);
          if (match) {
            const [_, type, mac, rssi, channel, name] = match;
            
            html += '<div style="background:#000;padding:14px;border-radius:8px;border:1px solid #003b24;margin-bottom:10px;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'#00cc66\'" onmouseout="this.style.borderColor=\'#003b24\'">';
            html += '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:10px;">';
            html += '<div style="font-family:monospace;font-size:15px;color:#00ff7f;">' + mac + '</div>';
            html += '<span style="background:#003b24;color:#00ff7f;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:bold;">' + type + '</span>';
            html += '</div>';
            html += '<div style="display:flex;gap:16px;font-size:12px;color:#00ff7f66;flex-wrap:wrap;">';
            html += '<span>RSSI: <strong style="color:#00ff7f99;">' + rssi + ' dBm</strong></span>';
            if (channel) html += '<span>Channel: <strong style="color:#00ff7f99;">' + channel + '</strong></span>';
            if (name) html += '<span>Name: <strong style="color:#00ff7f99;">' + name + '</strong></span>';
            html += '</div>';
            html += '</div>';
          }
        });
        
        const moreMatch = text.match(/\.\.\. \((\d+) more\)/);
        if (moreMatch) {
          html += '<div style="padding:12px;text-align:center;color:#00ff7f66;font-size:12px;border:1px dashed #003b24;border-radius:6px;">+ ' + moreMatch[1] + ' more devices</div>';
        }
        
        return html;
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

          document.getElementById('hardwareDiag').innerText = hardware || 'No hardware data';
          document.getElementById('networkDiag').innerText = network || 'No network data';
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
            if (isScanning || (lastScanningState && !isScanning)) {
              const rr = await fetch('/results');
              const resultsText = await rr.text();
              resultsElement.innerHTML = parseAndStyleResults(resultsText);
              
              resultsElement.querySelectorAll('details').forEach(details => {
                const summary = details.querySelector('summary');
                const arrow = summary?.querySelector('span');
                if (arrow) {
                  details.addEventListener('toggle', () => {
                    arrow.style.transform = details.open ? 'rotate(90deg)' : 'rotate(0deg)';
                  });
                }
              });
            }
          }
          lastScanningState = isScanning;
        } catch (e) {}
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
        const cacheBtn = document.getElementById('cacheBtn');
        const baselineResultsBtn = document.getElementById('baselineResultsBtn');
        const resetBaselineBtn = document.getElementById('resetBaselineBtn');
        const randTracksBtn = document.getElementById('randTracksBtn');
        const clearOldBtn = document.getElementById('clearOldBtn');
        
        // Hide all controls first
        cacheBtn.style.display = 'none';
        baselineResultsBtn.style.display = 'none';
        resetBaselineBtn.style.display = 'none';
        randTracksBtn.style.display = 'none';
        clearOldBtn.style.display = 'none';
        standardControls.style.display = 'none';
        baselineControls.style.display = 'none';
        randomizationModeControls.style.display = 'none';
        
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
            randTracksBtn.style.display = 'inline-block';
            clearOldBtn.style.display = 'inline-block';
            document.getElementById('detectionDuration').disabled = false;
            document.getElementById('baselineMonitorDuration').disabled = true;
            
        } else if (selectedMethod === 'device-scan') {
            standardControls.style.display = 'block';
            cacheBtn.style.display = 'inline-block';
            document.getElementById('detectionDuration').disabled = false;
            document.getElementById('baselineMonitorDuration').disabled = true;
            
        } else {
            // deauth, drone-detection, etc
            standardControls.style.display = 'block';
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

      // Initialize
      load();
      loadBaselineAnomalyConfig();
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
    if (id.length() > 0 && id.length() <= 16) {
        setNodeId(id);
        saveConfiguration();
        req->send(200, "text/plain", "Node ID updated");
    } else {
        req->send(400, "text/plain", "Invalid ID (1-16 chars)");
    } });

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

  server->on("/erase/status", HTTP_GET, [](AsyncWebServerRequest *req)
             {
    String status;
    
    if (eraseStatus == "COMPLETED") {
        status = "COMPLETED";
    }
    else if (eraseInProgress) {
        status = eraseStatus;
    }
    else if (tamperEraseActive) {
        uint32_t timeLeft = TAMPER_DETECTION_WINDOW - (millis() - tamperSequenceStart);
        status = "ACTIVE - Tamper erase countdown: " + String(timeLeft / 1000) + " seconds remaining";
    } else {
        status = "INACTIVE";
    }
    
    req->send(200, "text/plain", status); });

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

  server->on("/secure/status", HTTP_GET, [](AsyncWebServerRequest *req)
             {
    String status = tamperEraseActive ? 
        "TAMPER_ACTIVE:" + String((TAMPER_DETECTION_WINDOW - (millis() - tamperSequenceStart))/1000) + "s" : 
        "INACTIVE";
    req->send(200, "text/plain", status); });

  server->on("/secure/abort", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    cancelTamperErase();
    req->send(200, "text/plain", "Cancelled"); });

  server->on("/sniffer", HTTP_POST, [](AsyncWebServerRequest *req) {
    String detection = req->getParam("detection", true) ? req->getParam("detection", true)->value() : "device-scan";
    int secs = req->getParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 60;
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
                scanMode = mode;  // 0=WiFi, 1=BLE, 2=Both
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
            xTaskCreatePinnedToCore(randomizationDetectionTask, "randdetect", 12288,
                                  (void*)(intptr_t)(forever ? 0 : secs),
                                  1, &workerTaskHandle, 1);
        }
    } else if (detection == "device-scan") {
        currentScanMode = SCAN_BOTH;
        if (secs < 0) secs = 0;
        if (secs > 86400) secs = 86400;
        
        if (detection == "deauth") {
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", 
                      forever ? "Deauth detection starting (forever)" : 
                      ("Deauth detection starting for " + String(secs) + "s"));
            
            if (!blueTeamTaskHandle) {
                xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 12288, 
                                      (void*)(intptr_t)(forever ? 0 : secs), 
                                      1, &blueTeamTaskHandle, 1);
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
        } else if (detection == "device-scan") {
            currentScanMode = SCAN_BOTH;
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", 
                      forever ? "Device scan starting (forever)" : 
                      ("Device scan starting for " + String(secs) + "s"));
            
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
      RFScanConfig cfg = getRFConfig();
      String json = "{";
      json += "\"preset\":" + String(cfg.preset) + ",";
      json += "\"wifiChannelTime\":" + String(cfg.wifiChannelTime) + ",";
      json += "\"wifiScanInterval\":" + String(cfg.wifiScanInterval) + ",";
      json += "\"bleScanInterval\":" + String(cfg.bleScanInterval) + ",";
      json += "\"bleScanDuration\":" + String(cfg.bleScanDuration);
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
          setCustomRFConfig(wct, wsi, bsi, bsd);
          saveConfiguration();
          req->send(200, "text/plain", "Custom RF config updated");
      } else {
          req->send(400, "text/plain", "Missing parameters");
      }
  });

  server->begin();
  Serial.println("[WEB] Server started.");
}

// Mesh UART Message Sender
void sendMeshNotification(const Hit &hit) {
    
    if (triangulationActive) return;
    
    if (!meshEnabled || millis() - lastMeshSend < MESH_SEND_INTERVAL) return;
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
  else if (command.startsWith("STOP"))
  {
    stopRequested = true;
    Serial.println("[MESH] Stop command received via mesh");
    sendToSerial1(nodeId + ": STOP_ACK:OK", true);
  }
  else if (command.startsWith("STATUS"))
  {
    // Get current status info
    float esp_temp = temperatureRead();
    float esp_temp_f = (esp_temp * 9.0 / 5.0) + 32.0;
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE"
                                                                                             : "WiFi+BLE";

    uint32_t uptime_secs = millis() / 1000;
    uint32_t uptime_mins = uptime_secs / 60;
    uint32_t uptime_hours = uptime_mins / 60;

    char status_msg[MAX_MESH_SIZE];

    snprintf(status_msg, sizeof(status_msg),
            "%s: STATUS: Mode:%s Scan:%s Hits:%d Unique:%d Temp:%.1fC/%.1fF Up:%02d:%02d:%02d",
            nodeId.c_str(),
            modeStr.c_str(),
            scanning ? "ACTIVE" : "IDLE",
            totalHits,
            uniqueMacs.size(),
            esp_temp, esp_temp_f,
            uptime_hours, uptime_mins % 60, uptime_secs % 60);

    sendToSerial1(String(status_msg), true);
    
    if (gpsValid)
    {
      char gps_status[MAX_MESH_SIZE];
      snprintf(gps_status, sizeof(gps_status),
               "%s: GPS: %.6f,%.6f",
               nodeId.c_str(), gpsLat, gpsLon);
      sendToSerial1(String(gps_status), true);
    }
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
        uint32_t timeLeft = TAMPER_DETECTION_WINDOW - (millis() - tamperSequenceStart);
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
