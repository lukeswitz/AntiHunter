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
const unsigned long MESH_SEND_INTERVAL = 3500;
const int MAX_MESH_SIZE = 230;
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


// ------------- Network ------------- 

void initializeNetwork()
{ 
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  Serial.println("Initializing mesh UART...");
  initializeMesh();

  Serial.println("Starting AP...");
  WiFi.mode(WIFI_AP);
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
      :root{--bg:#000;--fg:#00ff7f;--fg2:#00cc66;--accent:#0aff9d;--card:#0b0b0b;--muted:#00ff7f99;--danger:#ff4444}
      *{box-sizing:border-box;margin:0;padding:0}
      body,html{height:100%;margin:0}
      body{background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;line-height:1.5}
      .header{padding:14px;border-bottom:1px solid #003b24;background:linear-gradient(180deg,#001a10,#000);display:flex;flex-wrap:wrap;align-items:center;gap:10px}
      h1{font-size:18px;letter-spacing:1px}
      h3{margin:0 0 10px;color:var(--fg);font-size:15px}
      .container{max-width:1400px;margin:0 auto;padding:12px}
      .card{background:var(--card);border:1px solid #003b24;border-radius:10px;padding:14px;box-shadow:0 4px 20px rgba(0,255,127,.05)}
      label{display:block;margin:6px 0 4px;color:var(--muted);font-size:12px}
      input[type=number],input[type=text],select,textarea{width:100%;background:#000;border:1px solid #003b24;border-radius:8px;color:var(--fg);padding:9px;font-family:inherit;font-size:13px}
      textarea{min-height:80px;resize:vertical}
      .btn{display:inline-block;padding:9px 13px;border-radius:8px;border:1px solid #004e2f;background:#001b12;color:var(--fg);text-decoration:none;cursor:pointer;font-size:12px;transition:all .2s}
      .btn:hover{box-shadow:0 4px 14px rgba(10,255,157,.15);transform:translateY(-1px)}
      .btn.primary{background:#002417;border-color:#0c6}
      .btn.alt{background:#00140d;border-color:#004e2f;color:var(--accent)}
      .btn.danger{background:#300;border-color:#f44;color:#f66}
      .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
      .small{opacity:.65;font-size:11px}
      pre{white-space:pre-wrap;background:#000;border:1px dashed #003b24;border-radius:8px;padding:10px;font-size:11px;line-height:1.4;overflow-x:auto;max-height:400px;overflow-y:auto}
      hr{border:0;border-top:1px dashed #003b24;margin:12px 0}
      .banner{font-size:11px;color:#0aff9d;border:1px dashed #004e2f;padding:6px 8px;border-radius:8px;background:#001108;margin-bottom:10px}
      #toast{position:fixed;right:14px;bottom:14px;display:flex;flex-direction:column;gap:6px;z-index:9999}
      .toast{background:#001d12;border:1px solid #0aff9d55;color:var(--fg);padding:9px 11px;border-radius:8px;box-shadow:0 6px 24px rgba(10,255,157,.2);opacity:0;transform:translateY(8px);transition:opacity .15s,transform .15s;font-size:12px}
      .toast.show{opacity:1;transform:none}
      .toast.success{border-color:#00cc66;background:#002200}
      .toast.error{border-color:#ff4444;background:#300}
      .toast.warning{border-color:#ffaa00;background:#332200}
      .footer{opacity:.7;font-size:11px;padding:8px;text-align:center;margin-top:16px}
      .logo{width:26px;height:26px}
      .status-bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-left:auto;font-size:11px}
      .status-item{background:#001a10;border:1px solid #003b24;padding:4px 9px;border-radius:6px;font-size:10px;white-space:nowrap}
      .status-item.active{border-color:#0c6;background:#002417}
      .tab-buttons{display:flex;gap:6px;margin-bottom:10px}
      .tab-btn{padding:7px 13px;background:#001b12;border:1px solid #003b24;border-radius:7px;cursor:pointer;color:var(--muted);font-size:12px;transition:all .2s}
      .tab-btn.active{background:#002417;border-color:#0c6;color:var(--fg)}
      .tab-content{display:none}
      .tab-content.active{display:block}
      .stat-item{background:#001108;border:1px solid #003b24;padding:10px;border-radius:7px}
      .stat-label{color:var(--muted);font-size:10px;text-transform:uppercase;margin-bottom:4px}
      .stat-value{color:var(--fg);font-size:16px;font-weight:700}
      
      @media (min-width:900px){
        .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
        .grid-2 > .card{align-self:start}
        .grid-node-diag{display:grid;grid-template-columns:minmax(280px,auto) 1fr;gap:14px}
        .stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
      }
      @media (max-width:899px){
        .grid-2,.grid-node-diag{display:flex;flex-direction:column;gap:14px}
        .stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
        .container{padding:10px}
        .card{padding:12px}
        h1{font-size:16px}
        .status-bar{width:100%;margin-left:0;margin-top:8px}
      }
      @media (max-width:600px){
        .stat-grid{grid-template-columns:1fr}
        .status-item{font-size:9px;padding:3px 6px}
      }
      /* Collapsible Cards */
      .card-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none;margin-bottom:12px}
      .card-header h3{margin:0}
      .collapse-icon{transition:transform 0.2s;font-size:14px;color:var(--muted)}
      .collapse-icon.open{transform:rotate(90deg)}
      .card-body{overflow:hidden;transition:max-height 0.3s ease}
      .card-body.collapsed{max-height:0!important;margin:0;padding:0}
      .section-divider{border-top:1px solid var(--border);margin:16px 0;padding-top:16px}
      .grid-2 > .card {align-self: stretch;}
    </style>
  </head>
  <body>
    <div id="toast"></div>
    <!-- STATUS BAR - Stop All only shows when scanning -->
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
          <div class="card-body" id="detectionCardBody">
            
            <form id="sniffer" method="POST" action="/sniffer">  
              <label>Method</label>
              <select name="detection" id="detectionMode">
                <option value="device-scan">Device Discovery Scan</option>
                <option value="baseline" selected>Baseline Anomaly Detection</option>
                <option value="drone-detection">Drone RID Detection (WiFi)</option>
              </select>
              
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
              </div>
            </form>
            
          </div>
        </div>
      </div>
      
      <!-- Full Width Results -->
      <div class="card" style="margin-top:16px;margin-bottom:16px;">
        <h3>Scan Results</h3>
        <pre id="r" style="margin:0;">No scan data yet.</pre>
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
        <h3>Secure Data Destruction</h3>
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
        
        <details style="margin-top:16px;">
          <summary style="cursor:pointer;font-weight:bold;color:var(--accent);">Auto-Erase Configuration</summary>
          <div style="margin-top:12px;">
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
      
      <div class="footer">© AntiHunter 2025 | Node: <span id="footerNodeId">--</span></div>
    </div>
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
          document.getElementById('r').innerText = await rr.text();
          loadNodeId();
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
          
          const detectionMode = document.getElementById('detectionMode')?.value;
          if (taskType === 'sniffer' || taskType === 'drone') {
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
              if (detectionMode === 'device-scan') {
                document.getElementById('cacheBtn').style.display = 'inline-block';
              }
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
              document.getElementById('cacheBtn').style.display = 'none';
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
              document.getElementById('r').innerText = await rr.text();
            }
          }
          lastScanningState = isScanning;
        } catch (e) {}
      }
      
      document.getElementById('triangulate').addEventListener('change', e => {
        document.getElementById('triangulateOptions').style.display = e.target.checked ? 'block' : 'none';
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
              if (submitBtn) {
                  submitBtn.textContent = 'Stop Scan';
                  submitBtn.style.background = 'var(--danger)';
              }
          }).catch(err => toast('Error: ' + err.message));
      });

      document.getElementById('detectionMode').addEventListener('change', function() {
        const selectedMethod = this.value;
        const standardControls = document.getElementById('standardDurationControls');
        const baselineControls = document.getElementById('baselineConfigControls');
        const cacheBtn = document.getElementById('cacheBtn');
        const baselineResultsBtn = document.getElementById('baselineResultsBtn');
        const resetBaselineBtn = document.getElementById('resetBaselineBtn');
        
        // Hide everything first
        cacheBtn.style.display = 'none';
        baselineResultsBtn.style.display = 'none';
        resetBaselineBtn.style.display = 'none';
        standardControls.style.display = 'none';
        baselineControls.style.display = 'none';
        
        // Show relevant controls
        if (selectedMethod === 'baseline') {
          baselineControls.style.display = 'block';
          baselineResultsBtn.style.display = 'inline-block';
          resetBaselineBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = true;
          document.getElementById('baselineMonitorDuration').disabled = false;
          updateBaselineStatus();
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

  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r)
             {
      std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
      String results = antihunter::lastResults.empty() ? "None yet." : String(antihunter::lastResults.c_str());
      
      // Add triangulation results if active
      if (triangulationActive || triangulationNodes.size() > 0) {
          results += "\n\n" + calculateTriangulation();
      }
      
      r->send(200, "text/plain", results); });

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
      
      if (req->hasParam("triangulate", true) && req->hasParam("targetMac", true)) {
          String targetMac = req->getParam("targetMac", true)->value();
          startTriangulation(targetMac, secs);
      } else {
          if (!workerTaskHandle) {
              xTaskCreatePinnedToCore(listScanTask, "scan", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
          }
      }
      
      String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
      req->send(200, "text/plain", forever ? ("Scan starting (forever) - " + modeStr) : ("Scan starting for " + String(secs) + "s - " + modeStr));
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
        Serial1.println(test_msg);
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
        if (Serial1.availableForWrite() >= setupMsg.length()) {
            Serial1.println(setupMsg);
        }
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

  server->on("/sniffer", HTTP_POST, [](AsyncWebServerRequest *req)
             {
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
  } else if (detection == "device-scan") {
      currentScanMode = SCAN_BOTH;
      if (secs < 0) secs = 0;
      if (secs > 86400) secs = 86400;
      
      stopRequested = false;
      req->send(200, "text/plain", forever ? "Device scan starting (forever)" : ("Device scan starting for " + String(secs) + "s"));
      
      if (!workerTaskHandle) {
          xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
      }
  } else {
    req->send(400, "text/plain", "Unknown detection mode");
  } });

  server->on("/deauth-results", HTTP_GET, [](AsyncWebServerRequest *r)
             {
  String results = "Deauth Detection Results\n";
  results += "Deauth frames: " + String(deauthCount) + "\n";
  results += "Disassoc frames: " + String(disassocCount) + "\n\n";
  
  int show = min((int)deauthLog.size(), 100);
  for (int i = 0; i < show; i++) {
    const auto &hit = deauthLog[i];
    results += String(hit.isDisassoc ? "DISASSOC" : "DEAUTH") + " ";
    results += macFmt6(hit.srcMac) + " -> " + macFmt6(hit.destMac);
    results += " BSSID:" + macFmt6(hit.bssid);
    results += " RSSI:" + String(hit.rssi) + "dBm";
    results += " CH:" + String(hit.channel);
    results += " Reason:" + String(hit.reasonCode) + "\n";
  }  
  r->send(200, "text/plain", results); });

  server->on("/sniffer-cache", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", getSnifferCache()); });

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
    
    startTriangulation(targetMac, duration);
    req->send(200, "text/plain", "Triangulation started for " + targetMac);
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

  server->begin();
  Serial.println("[WEB] Server started.");
}

// Mesh UART Message Sender
void sendMeshNotification(const Hit &hit) {
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
    
    int msg_len;
    
    String baseMsg = String(nodeId) + ": Target: " + String(mac_str) + 
                     " RSSI:" + String(hit.rssi) +
                     " Type:" + (hit.isBLE ? "BLE" : "WiFi");
    
    if (cleanName.length() > 0) {
        baseMsg += " Name:" + cleanName;
    }
    
    if (gpsValid) {
        baseMsg += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    msg_len = snprintf(mesh_msg, sizeof(mesh_msg) - 1, "%s", baseMsg.c_str());
    
    if (msg_len > 0 && msg_len < MAX_MESH_SIZE) {
        mesh_msg[msg_len] = '\0';
        
        delay(10);
        if (Serial1.availableForWrite() >= msg_len + 2) {
            Serial.printf("[MESH] %s\n", mesh_msg);
            Serial1.println(mesh_msg);
            Serial1.flush();
        }
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
    Serial1.println(nodeId + ": CONFIG_ACK:CHANNELS:" + channels);
  }
  else if (command.startsWith("CONFIG_TARGETS:"))
  {
    String targets = command.substring(15);
    saveTargetsList(targets);
    Serial.printf("[MESH] Updated targets list\n");
    Serial1.println(nodeId + ": CONFIG_ACK:TARGETS:OK");
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
        Serial1.println(nodeId + ": SCAN_ACK:STARTED");
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
    Serial1.println(nodeId + ": BASELINE_ACK:STARTED");
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
    Serial1.println(status_msg);
  }
  else if (command.startsWith("STOP"))
  {
    stopRequested = true;
    Serial.println("[MESH] Stop command received via mesh");
    Serial1.println(nodeId + ": STOP_ACK:OK");
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
             "%s: STATUS: Mode:%s Scan:%s Hits:%d Targets:%d Unique:%d Temp:%.1fC/%.1fF Up:%02d:%02d:%02d",
             nodeId.c_str(),
             modeStr.c_str(),
             scanning ? "YES" : "NO",
             totalHits,
             (int)getTargetCount(),
             (int)uniqueMacs.size(),
             esp_temp, esp_temp_f,
             (int)uptime_hours, (int)(uptime_mins % 60), (int)(uptime_secs % 60));

    Serial1.println(status_msg);
    if (gpsValid)
    {
      char gps_status[MAX_MESH_SIZE];
      snprintf(gps_status, sizeof(gps_status),
               "%s: GPS: %.6f,%.6f",
               nodeId.c_str(), gpsLat, gpsLon);
      Serial1.println(gps_status);
    }
  }
  else if (command.startsWith("VIBRATION_STATUS"))
  {
    String status = lastVibrationTime > 0 ? ("Last vibration: " + String(lastVibrationTime) + "ms (" + String((millis() - lastVibrationTime) / 1000) + "s ago)") : "No vibrations detected";
    Serial1.println(nodeId + ": VIBRATION_STATUS: " + status);
  }
  else if (command.startsWith("TRIANGULATE_START:"))
  {
    String params = command.substring(18);
    int colonPos = params.indexOf(':');
    String mac = params.substring(0, colonPos);
    int duration = params.substring(colonPos + 1).toInt();

    startTriangulation(mac, duration);
    Serial1.println(nodeId + ": TRIANGULATE_ACK:" + mac);
  }
  else if (command.startsWith("TRIANGULATE_STOP"))
  {
    stopTriangulation();
    Serial1.println(nodeId + ": TRIANGULATE_STOP_ACK");
  }
  else if (command.startsWith("TRIANGULATE_RESULTS"))
  {
    if (triangulationNodes.size() > 0) {
      String results = calculateTriangulation();
      Serial1.println(nodeId + ": TRIANGULATE_RESULTS_START");
      Serial1.print(results);
      Serial1.println(nodeId + ": TRIANGULATE_RESULTS_END");
    } else {
      Serial1.println(nodeId + ": TRIANGULATE_RESULTS:NO_DATA");
    }
  }
  else if (command.startsWith("ERASE_FORCE:"))
  {
    String token = command.substring(12);
    if (validateEraseToken(token))
    {
      executeSecureErase("Force command");
      Serial1.println(nodeId + ": ERASE_ACK:COMPLETE");
    }
  }
  else if (command == "ERASE_CANCEL")
  {
    cancelTamperErase();
    Serial1.println(nodeId + ": ERASE_ACK:CANCELLED");
  }
}

void sendMeshCommand(const String &command)
  {
    if (meshEnabled && Serial1.availableForWrite() >= command.length()) {
        Serial.printf("[MESH] Sending command: %s\n", command.c_str());
        Serial1.println(command);
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
    
    Serial.printf("[MESH] Processing message: '%s'\n", cleanMessage.c_str());
    
    // Triangulation data collection
    int colonPos = cleanMessage.indexOf(':');
    if (triangulationActive && colonPos > 0) {
        String sendingNode = cleanMessage.substring(0, colonPos);
        String content = cleanMessage.substring(colonPos + 2);
        
        if (content.startsWith("Target:")) {
            int macStart = content.indexOf(' ', 7) + 1;
            int macEnd = content.indexOf(' ', macStart);
            
            if (macEnd > macStart) {
                String macStr = content.substring(macStart, macEnd);
                uint8_t mac[6];
                
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
                    int gpsIdx = content.indexOf("GPS=");
                    if (gpsIdx > 0) {
                        int commaIdx = content.indexOf(',', gpsIdx);
                        if (commaIdx > 0) {
                            lat = content.substring(gpsIdx + 4, commaIdx).toFloat();
                            int gpsEnd = content.indexOf(' ', commaIdx);
                            if (gpsEnd < 0) gpsEnd = content.length();
                            lon = content.substring(commaIdx + 1, gpsEnd).toFloat();
                            hasGPS = true;
                        }
                    }
                    
                    bool found = false;
                    for (auto &node : triangulationNodes) {
                        if (node.nodeId == sendingNode) {
                            updateNodeRSSI(node, rssi);
                            node.hitCount++;
                            if (hasGPS) {
                                node.lat = lat;
                                node.lon = lon;
                                node.hasGPS = true;
                            }
                            node.distanceEstimate = rssiToDistance(node);
                            found = true;
                            Serial.printf("[TRIANGULATE] Updated %s: RSSI=%d->%.1f dist=%.1fm Q=%.2f\n",
                                        sendingNode.c_str(), rssi, node.filteredRssi, 
                                        node.distanceEstimate, node.signalQuality);
                            break;
                        }
                    }
                    
                    if (!found) {
                        TriangulationNode newNode;
                        newNode.nodeId = sendingNode;
                        newNode.lat = lat;
                        newNode.lon = lon;
                        newNode.rssi = rssi;
                        newNode.hitCount = 1;
                        newNode.hasGPS = hasGPS;
                        newNode.lastUpdate = millis();
                        initNodeKalmanFilter(newNode);
                        updateNodeRSSI(newNode, rssi);
                        newNode.distanceEstimate = rssiToDistance(newNode);
                        triangulationNodes.push_back(newNode);
                        Serial.printf("[TRIANGULATE] New node %s: RSSI=%d dist=%.1fm\n",
                                    sendingNode.c_str(), rssi, newNode.distanceEstimate);
                    }
                }
            }
        }
        if (content.startsWith("TIME_SYNC_REQ:")) {
            int firstColon = content.indexOf(':', 14);
            if (firstColon > 0) {
                int secondColon = content.indexOf(':', firstColon + 1);
                if (secondColon > 0) {
                    time_t theirTime = content.substring(14, firstColon).toInt();
                    uint32_t theirMillis = content.substring(firstColon + 1, secondColon).toInt();
                    
                    handleTimeSyncResponse(sendingNode, theirTime, theirMillis);
                    
                    time_t myTime = getRTCEpoch();
                    uint32_t myMillis = millis();
                    String response = getNodeId() + ": TIME_SYNC_RESP:" + 
                                    String((unsigned long)myTime) + ":" + 
                                    String(myMillis);
                    if (Serial1.availableForWrite() >= response.length()) {
                        Serial1.println(response);
                    }
                }
            }
        }
        if (content.startsWith("TIME_SYNC_RESP:")) {
            int firstColon = content.indexOf(':', 15);
            if (firstColon > 0) {
                int secondColon = content.indexOf(':', firstColon + 1);
                if (secondColon > 0) {
                    time_t theirTime = content.substring(15, firstColon).toInt();
                    uint32_t theirMillis = content.substring(firstColon + 1, secondColon).toInt();
                    handleTimeSyncResponse(sendingNode, theirTime, theirMillis);
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
