#include "network.h"
#include "hardware.h"
#include "scanner.h"
#include "main.h"
#include <AsyncTCP.h>
#include "esp_task_wdt.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_coexist.h"
}

// Network
AsyncWebServer *server = nullptr;
bool meshEnabled = true;
static unsigned long lastMeshSend = 0;
const unsigned long MESH_SEND_INTERVAL = 3500;
const int MAX_MESH_SIZE = 230;
static String nodeId = "";

// Scanner vars
extern volatile bool scanning;
extern volatile int totalHits;
extern volatile bool trackerMode;
extern std::set<String> uniqueMacs;

// Module refs
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t workerTaskHandle;
extern TaskHandle_t blueTeamTaskHandle;
TaskHandle_t karmaTaskHandle = nullptr;
TaskHandle_t probeFloodTaskHandle = nullptr;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void parseChannelsCSV(const String &csv);

static std::vector<TriangulationNode> triangulationNodes;
bool triangulationActive = false;
static uint8_t triangulationTarget[6];
static uint32_t triangulationStart = 0;
static uint32_t triangulationDuration = 0;


// Triangulation 

bool isTriangulationActive() {
    return triangulationActive;
}

float rssiToDistance(int8_t rssi) {
    return pow(10.0, (-59.0 - rssi) / (10.0 * 2.0));
}

String calculateTriangulation() {
    String results = "Triangulation Results\n";
    results += "Target: " + macFmt6(triangulationTarget) + "\n";
    results += "Duration: " + String(triangulationDuration) + "s\n";
    results += "Nodes reporting: " + String(triangulationNodes.size()) + "\n\n";
    
    std::vector<TriangulationNode> gpsNodes;
    for (const auto& node : triangulationNodes) {
        results += node.nodeId + ": RSSI=" + String(node.rssi) + "dBm Hits=" + String(node.hitCount);
        if (node.hasGPS) {
            results += " GPS=" + String(node.lat, 6) + "," + String(node.lon, 6);
            results += " Dist=" + String(rssiToDistance(node.rssi), 1) + "m";
            gpsNodes.push_back(node);
        }
        results += "\n";
    }
    
    if (gpsNodes.size() >= 3) {
        float x1 = gpsNodes[0].lat, y1 = gpsNodes[0].lon, r1 = rssiToDistance(gpsNodes[0].rssi);
        float x2 = gpsNodes[1].lat, y2 = gpsNodes[1].lon, r2 = rssiToDistance(gpsNodes[1].rssi);
        float x3 = gpsNodes[2].lat, y3 = gpsNodes[2].lon, r3 = rssiToDistance(gpsNodes[2].rssi);
        
        float A = 2 * (x2 - x1);
        float B = 2 * (y2 - y1);
        float C = pow(r1, 2) - pow(r2, 2) - pow(x1, 2) + pow(x2, 2) - pow(y1, 2) + pow(y2, 2);
        float D = 2 * (x3 - x2);
        float E = 2 * (y3 - y2);
        float F = pow(r2, 2) - pow(r3, 2) - pow(x2, 2) + pow(x3, 2) - pow(y2, 2) + pow(y3, 2);
        
        float denominator = A * E - B * D;
        if (abs(denominator) > 0.0001) {
            float estLat = (C * E - F * B) / denominator;
            float estLon = (A * F - D * C) / denominator;
            
            results += "\nEstimated Position:\n";
            results += "Latitude: " + String(estLat, 6) + "\n";
            results += "Longitude: " + String(estLon, 6) + "\n";
            results += "Method: GPS+RSSI Trilateration\n";
        } else {
            results += "\nTrilateration failed: nodes too close/collinear\n";
        }
    } else if (triangulationNodes.size() >= 3) {
        results += "\nRSSI-only fallback (less accurate)\n";
        results += "Need GPS coordinates for precise positioning\n";
    } else {
        results += "\nInsufficient nodes with GPS (" + String(triangulationNodes.size()) + "/3)\n";
    }
    
    return results;
}

String calculateTriangulationResults() {
    return calculateTriangulation();
}

// Main AP 
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

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Antihunter</title>
<style>
:root{--bg:#000;--fg:#00ff7f;--fg2:#00cc66;--accent:#0aff9d;--card:#0b0b0b;--muted:#00ff7f99;--danger:#ff4444}
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
.header{padding:22px 18px;border-bottom:1px solid #003b24;background:linear-gradient(180deg,#001a10,#000);display:flex;align-items:center;gap:14px}
h1{margin:0;font-size:22px;letter-spacing:1px}
h3{margin:12px 0 8px;color:var(--fg)}
.container{max-width:1400px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid #003b24;border-radius:12px;padding:16px;margin:16px 0;box-shadow:0 8px 30px rgba(0,255,127,.05)}
label{display:block;margin:6px 0 4px;color:var(--muted);font-size:13px}
textarea, input[type=text], input[type=number], select{width:100%;background:#000;border:1px solid #003b24;border-radius:10px;color:var(--fg);padding:10px 12px;outline:none;font-family:inherit;font-size:13px}
textarea{min-height:128px;resize:vertical}
select{cursor:pointer}
select option{background:#000;color:var(--fg)}
.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #004e2f;background:#001b12;color:var(--fg);text-decoration:none;cursor:pointer;transition:transform .05s ease, box-shadow .2s;font-size:13px}
.btn:hover{box-shadow:0 6px 18px rgba(10,255,157,.15);transform:translateY(-1px)}
.btn.primary{background:#002417;border-color:#00cc66}
.btn.alt{background:#00140d;border-color:#004e2f;color:var(--accent)}
.btn.danger{background:#330000;border-color:#ff4444;color:#ff6666}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.small{opacity:.65;font-size:12px} 
pre{white-space:pre-wrap;background:#000;border:1px dashed #003b24;border-radius:10px;padding:12px;font-size:12px;line-height:1.4;overflow-x:auto}
a{color:var(--accent)} hr{border:0;border-top:1px dashed #003b24;margin:14px 0}
.banner{font-size:12px;color:#0aff9d;border:1px dashed #004e2f;padding:8px;border-radius:10px;background:#001108}
.grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(380px, 1fr));gap:14px}
.grid-2col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.grid-2col{grid-template-columns:1fr}}
#toast{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{background:#001d12;border:1px solid #0aff9d55;color:var(--fg);padding:10px 12px;border-radius:10px;box-shadow:0 8px 30px rgba(10,255,157,.2);opacity:0;transform:translateY(8px);transition:opacity .15s, transform .15s}
.toast.show{opacity:1;transform:none}
.toast .title{color:#0aff9d;font-weight:bold}
.footer{opacity:.7;font-size:12px;padding:8px 16px;text-align:center}
.logo{width:28px;height:28px}
.status-bar{display:flex;gap:10px;align-items:center;margin-left:auto;font-size:12px}
.status-item{background:#001a10;border:1px solid #003b24;padding:6px 10px;border-radius:6px}
.status-item.active{border-color:#00cc66;background:#002417}
.status-item.error{border-color:#ff4444;background:#330000}
.tab-buttons{display:flex;gap:8px;margin-bottom:12px}
.tab-btn{padding:8px 16px;background:#001b12;border:1px solid #003b24;border-radius:8px;cursor:pointer;color:var(--muted)}
.tab-btn.active{background:#002417;border-color:#00cc66;color:var(--fg)}
.tab-content{display:none}
.tab-content.active{display:block}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:10px;margin:10px 0}
.stat-item{background:#001108;border:1px solid #003b24;padding:10px;border-radius:8px}
.stat-label{color:var(--muted);font-size:11px;text-transform:uppercase}
.stat-value{color:var(--fg);font-size:18px;font-weight:bold}
.diag-section{margin:8px 0}
.diag-label{color:var(--accent);font-weight:bold}
.scan-controls{display:grid;grid-template-columns:2fr 1fr;gap:10px}
</style></head><body>
<div class="header">
  <svg class="logo" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect x="6" y="6" width="52" height="52" rx="8" fill="#00180F" stroke="#00ff7f" stroke-width="2"/>
    <path d="M16 40 L32 16 L48 40" fill="none" stroke="#0aff9d" stroke-width="3"/>
    <circle cx="32" cy="44" r="3" fill="#00ff7f"/>
  </svg>
  <h1>Antihunter v5</h1>
  <div class="status-bar">
    <div class="status-item" id="modeStatus">WiFi</div>
    <div class="status-item" id="scanStatus">Idle</div>
    <div class="status-item" id="meshStatus">Mesh</div>
    <div class="status-item" id="gpsStatus">GPS</div>
    <div class="status-item" id="rtcStatus">RTC</div>
  </div>
</div>
<div id="toast"></div>
<div class="container">

<div class="grid">
  <div class="card">
    <h3>Target Configuration</h3>
    <div class="banner">Enter full MACs (<code>AA:BB:CC:DD:EE:FF</code>) or OUIs (<code>AA:BB:CC</code>), one per line.</div>
    <form id="f" method="POST" action="/save">
      <label for="list">Target MAC Addresses</label>
      <textarea id="list" name="list" placeholder="AA:BB:CC:DD:EE:FF&#10;DC:A6:32&#10;# Comments allowed"></textarea>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Save Targets</button>
        <a class="btn" href="/export" data-ajax="false">Export List</a>
        <span class="small" id="targetCount">0 targets</span>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Scanning Operations</h3>
    <form id="s" method="POST" action="/scan">
      <div class="scan-controls">
        <div>
          <label>Scan Mode</label>
          <select name="mode" id="scanMode">
            <option value="0">WiFi Only</option>
            <option value="1">BLE Only</option>
            <option value="2">WiFi + BLE Combined</option>
          </select>
        </div>
        <div>
          <label>Duration (seconds)</label>
          <input type="number" name="secs" min="0" max="86400" value="60" id="scanDuration">
        </div>
      </div>
      
      <div class="row" style="margin:10px 0">
        <input type="checkbox" id="forever1" name="forever" value="1">
        <label for="forever1" style="margin:0">Run Forever</label>
      </div>
      
      <label>WiFi Channels</label>
      <input type="text" name="ch" value="1,6,11" placeholder="1,6,11 or 1..14">
      
      <div class="row" style="margin-top:10px">
        <input type="checkbox" id="triangulate" name="triangulate" value="1">
        <label for="triangulate" style="margin:0">Triangulation Mode (Multi-node)</label>
      </div>
      
      <div id="triangulateOptions" style="display:none;margin-top:10px">
        <label>Target MAC for Triangulation</label>
        <input type="text" name="targetMac" placeholder="34:21:09:83:D9:51">
      </div>
      
      <div class="row" style="margin-top:12px">
        <button class="btn primary" type="submit">Start Scan</button>
        <!--
        <a class="btn danger" href="/stop" data-ajax="true">Stop All</a>
        -->
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Detection & Analysis</h3>
    <form id="sniffer" method="POST" action="/sniffer">  
      <label>Detection Method</label>
      <select name="detection" id="detectionMode">
        <option value="device-scan">Device Discovery (WiFi/BLE)</option>
        <!--
        <option value="deauth">Deauth Attack Detection</option>
        <option value="beacon-flood">Beacon Flood Detection</option>
        <option value="karma">Karma Attack Detection</option>
        <option value="probe-flood">Probe Flood Detection</option>
        <option value="ble-spam">BLE Spam Detection</option>
        -->
      </select>
      
      <div class="scan-controls" style="margin-top:10px">
        <div>
          <label>Duration (seconds)</label>
          <input type="number" name="secs" min="0" max="86400" value="60">
        </div>
        <div>
          <input type="checkbox" id="forever3" name="forever" value="1">
          <label for="forever3" style="margin:0">Run Forever</label>
        </div>
      </div>
      
      <div class="row" style="margin-top:12px">
        <button class="btn primary" type="submit">Start Detection</button>
        <a class="btn alt" href="/sniffer-cache" data-ajax="false">View Cache</a>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Node Configuration</h3>
    <form id="nodeForm" method="POST" action="/node-id">
      <label for="nodeId">Node Identifier</label>
      <input type="text" id="nodeId" name="id" maxlength="16" placeholder="NODE_01">
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Update Node ID</button>
      </div>
    </form>
    
    <hr>
    
    <div class="row" style="margin-top:10px">
      <input type="checkbox" id="meshEnabled" checked>
      <label for="meshEnabled" style="margin:0">Enable Mesh Communications</label>
    </div>
    
    <div class="row" style="margin-top:10px">
      <a class="btn alt" href="/mesh-test" data-ajax="true">Test Mesh</a>
      <a class="btn" href="/gps" data-ajax="false">GPS Status</a>
      <a class="btn" href="/sd-status" data-ajax="false">SD Card</a>
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
        <div class="stat-label">Total Hits</div>
        <div class="stat-value" id="totalHits">0</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Unique MACs</div>
        <div class="stat-value" id="uniqueDevices">0</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Temperature</div>
        <div class="stat-value" id="temperature">--°C</div>
      </div>
    </div>
  </div>
  
  <div id="hardware" class="tab-content">
    <pre id="hardwareDiag">Loading hardware info...</pre>
  </div>
  
  <div id="network" class="tab-content">
    <pre id="networkDiag">Loading network info...</pre>
  </div>
</div>
 
<div class="card">
  <h3>Scan Results</h3>
  <pre id="r">No scan data yet.</pre>
</div>

<div class="footer">© Team AntiHunter 2025 | Node: <span id="footerNodeId">--</span></div>
</div>
<script>
let selectedMode = '0';

function toast(msg){
  const wrap = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = '<div class="title">System</div><div class="msg">'+msg+'</div>';
  wrap.appendChild(el);
  requestAnimationFrame(()=>{ el.classList.add('show'); });
  setTimeout(()=>{ el.classList.remove('show'); setTimeout(()=>wrap.removeChild(el), 200); }, 3000);
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  event.target.classList.add('active');
  document.getElementById(tabName).classList.add('active');
}

async function ajaxForm(form, okMsg){
  const fd = new FormData(form);
  try{
    const r = await fetch(form.action, {method:'POST', body:fd});
    const t = await r.text();
    toast(okMsg || t);
  }catch(e){
    toast('Error: '+e.message);
  }
}

async function load(){
  try{
    const r = await fetch('/export'); 
    const text = await r.text();
    document.getElementById('list').value = text;
    const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    document.getElementById('targetCount').innerText = lines.length + ' targets';
    
    const rr = await fetch('/results'); 
    document.getElementById('r').innerText = await rr.text();
    loadNodeId();
  }catch(e){}
}

async function loadNodeId(){
  try{
    const r = await fetch('/node-id');
    const data = await r.json();
    document.getElementById('nodeId').value = data.nodeId;
    document.getElementById('footerNodeId').innerText = data.nodeId;
  }catch(e){}
}

function updateStatusIndicators(diagText) {
  // Scan status
  if (diagText.includes('Scanning: yes')) {
    document.getElementById('scanStatus').innerText = 'Active';
    document.getElementById('scanStatus').classList.add('active');
  } else {
    document.getElementById('scanStatus').innerText = 'Idle';
    document.getElementById('scanStatus').classList.remove('active');
  }
  
  // Mode status
  const modeMatch = diagText.match(/Scan Mode: (\w+)/);
  if (modeMatch) {
    document.getElementById('modeStatus').innerText = modeMatch[1];
  }
  
  // GPS status
  if (diagText.includes('GPS: Locked')) {
    document.getElementById('gpsStatus').classList.add('active');
    document.getElementById('gpsStatus').innerText = 'GPS Lock';
  } else {
    document.getElementById('gpsStatus').classList.remove('active');
    document.getElementById('gpsStatus').innerText = 'GPS';
  }
  
  // RTC status
  if (diagText.includes('RTC: Synced')) {
    document.getElementById('rtcStatus').classList.add('active');
    document.getElementById('rtcStatus').innerText = 'RTC OK';
  } else if (diagText.includes('RTC: Not')) {
    document.getElementById('rtcStatus').classList.remove('active');
    document.getElementById('rtcStatus').innerText = 'RTC';
  }
}

async function tick(){
  try{
    const d = await fetch('/diag'); 
    const diagText = await d.text();
    
    // Parse diagnostics for different sections
    const sections = diagText.split('\n');
    let overview = '';
    let hardware = '';
    let network = '';
    let currentSection = 'overview';
    
    sections.forEach(line => {
      if (line.includes('WiFi Frames')) {
        const match = line.match(/(\d+)/);
        if (match) document.getElementById('wifiFrames').innerText = match[1];
      }
      if (line.includes('BLE Frames')) {
        const match = line.match(/(\d+)/);
        if (match) document.getElementById('bleFrames').innerText = match[1];
      }
      if (line.includes('Total hits')) {
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
      
      // Build sections
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
    
    // Update uptime
    const uptimeMatch = diagText.match(/Up:(\d+):(\d+):(\d+)/);
    if (uptimeMatch) {
      document.getElementById('uptime').innerText = uptimeMatch[1] + ':' + uptimeMatch[2] + ':' + uptimeMatch[3];
    }
    
    updateStatusIndicators(diagText);
    
    const rr = await fetch('/results'); 
    document.getElementById('r').innerText = await rr.text();
  }catch(e){}
}

document.getElementById('triangulate').addEventListener('change', e=>{
  document.getElementById('triangulateOptions').style.display = e.target.checked ? 'block' : 'none';
});

document.getElementById('f').addEventListener('submit', e=>{ 
  e.preventDefault(); 
  ajaxForm(e.target, 'Targets saved ✓'); 
  setTimeout(load, 500);
});

document.getElementById('nodeForm').addEventListener('submit', e=>{
  e.preventDefault();
  ajaxForm(e.target, 'Node ID updated');
  setTimeout(loadNodeId, 500);
});

document.getElementById('s').addEventListener('submit', e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  fetch('/scan', {method:'POST', body:fd}).then(r=>r.text()).then(t=>toast(t))
    .catch(err=>toast('Error: '+err.message));
});

document.getElementById('meshEnabled').addEventListener('change', e=>{
  const enabled = e.target.checked;
  fetch('/mesh', {method:'POST', body: new URLSearchParams({enabled: enabled})})
    .then(r=>r.text())
    .then(t=>{
      toast(t);
      document.getElementById('meshStatus').classList.toggle('active', enabled);
    })
    .catch(err=>toast('Error: '+err.message));
});

document.getElementById('sniffer').addEventListener('submit', e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  fetch('/sniffer', {method:'POST', body:fd}).then(()=>toast('Detection started'))
    .catch(err=>toast('Error: '+err.message));
});

document.addEventListener('click', e=>{
  const a = e.target.closest('a[href="/stop"]');
  if (!a) return;
  e.preventDefault();
  fetch('/stop').then(r=>r.text()).then(t=>toast(t));
});

document.addEventListener('click', e=>{
  const a = e.target.closest('a[href="/mesh-test"]');
  if (!a) return;
  e.preventDefault();
  fetch('/mesh-test').then(r=>r.text()).then(t=>toast('Mesh test sent'));
});

// Initialize
load();
setInterval(tick, 2000);
</script>
</body></html>
)HTML";

void startWebServer()
{
  if (!server)
    server = new AsyncWebServer(80);

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
      
      // Add triangulation results if active
      if (triangulationActive || triangulationNodes.size() > 0) {
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
        req->send(200, "text/plain", "Saved"); });

  server->on("/node-id", HTTP_POST, [](AsyncWebServerRequest *req)
             {
    String id = req->hasParam("id", true) ? req->getParam("id", true)->value() : "";
    if (id.length() > 0 && id.length() <= 16) {
        setNodeId(id);
        req->send(200, "text/plain", "Node ID updated");
    } else {
        req->send(400, "text/plain", "Invalid ID (1-16 chars)");
    } });

  server->on("/node-id", HTTP_GET, [](AsyncWebServerRequest *r)
             {
    String j = "{\"nodeId\":\"" + getNodeId() + "\"}";
    r->send(200, "application/json", j); });

  server->on("/scan", HTTP_POST, [](AsyncWebServerRequest *req)
           {
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
        
        currentScanMode = mode;
        stopRequested = false;
        
        // triangulation handling
        if (req->hasParam("triangulate", true) && req->hasParam("targetMac", true)) {
            String targetMac = req->getParam("targetMac", true)->value();
            uint8_t tmp[6];
            if (!parseMac6(targetMac, tmp)) {
                req->send(400, "text/plain", "Invalid target MAC");
                return;
            }
            
            triangulationNodes.clear();
            triangulationActive = true;
            triangulationStart = millis();
            triangulationDuration = secs;
            memcpy(triangulationTarget, tmp, 6);
            
            String cmd = "@ALL TRIANGULATE_START:" + targetMac + ":" + String(secs);
            sendMeshCommand(cmd);
        }
        
        String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
        req->send(200, "text/plain", forever ? ("Scan starting (forever) - " + modeStr) : ("Scan starting for " + String(secs) + "s - " + modeStr));
        
        if (!workerTaskHandle) {
            xTaskCreatePinnedToCore(listScanTask, "scan", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
        } });

  server->on("/track", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        String mac = req->getParam("mac", true) ? req->getParam("mac", true)->value() : "";
        int secs = req->getParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 180;
        bool forever = req->hasParam("forever", true);
        ScanMode mode = SCAN_WIFI;
        
        if (req->hasParam("mode", true)) {
            int m = req->getParam("mode", true)->value().toInt();
            if (m >= 0 && m <= 2) mode = (ScanMode)m;
        }
        String ch = req->getParam("ch", true) ? req->getParam("ch", true)->value() : "6";
        
        uint8_t tmp[6];
        if (!parseMac6(mac, tmp)) {
            req->send(400, "text/plain", "Invalid MAC");
            return;
        }
        
        setTrackerMac(tmp);
        parseChannelsCSV(ch);
        currentScanMode = mode;
        stopRequested = false;
        
        String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
        req->send(200, "text/plain", forever ? ("Tracker starting (forever) - " + modeStr) : ("Tracker starting for " + String(secs) + "s - " + modeStr));
        
        if (!workerTaskHandle) {
            xTaskCreatePinnedToCore(trackerTask, "tracker", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
        } });

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

  server->on("/stop", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        stopRequested = true;
        r->send(200, "text/plain", "Stopping… (AP will return shortly)"); });

  server->on("/config", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        // TODO 
        r->send(200, "application/json", ""); });

  server->on("/config", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        saveConfiguration();
        req->send(200, "text/plain", "Config saved"); });

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
    
  } else if (detection == "beacon-flood") {
    if (secs < 0) secs = 0; 
    if (secs > 86400) secs = 86400;
    
    stopRequested = false;
    req->send(200, "text/plain", forever ? "Beacon flood detection starting (forever)" : ("Beacon flood detection starting for " + String(secs) + "s"));
    
    if (!blueTeamTaskHandle) {
      xTaskCreatePinnedToCore(beaconFloodTask, "beaconflood", 12288, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
  } else if (detection == "pwnagotchi") {
    stopRequested = false;
    req->send(200, "text/plain", "Pwnagotchi detection starting");
    if (!blueTeamTaskHandle) {
        xTaskCreatePinnedToCore(pwnagotchiDetectionTask, "pwn", 12288,
                              (void*)(intptr_t)(forever ? 0 : secs),
                              1, &blueTeamTaskHandle, 1);
    }
} else if (detection == "pineapple") {
    pineappleDetectionEnabled = true;
    stopRequested = false;
    req->send(200, "text/plain", forever ? "Pineapple detection starting (forever)" : 
             ("Pineapple detection starting for " + String(secs) + "s"));
    
    if (!blueTeamTaskHandle) {
        xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288, 
                              (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
}

else if (detection == "multi-ssid") {
    multissidDetectionEnabled = true;
    stopRequested = false;
    req->send(200, "text/plain", forever ? "Multi-SSID detection starting (forever)" : 
             ("Multi-SSID detection starting for " + String(secs) + "s"));
    
    if (!blueTeamTaskHandle) {
        xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288, 
                              (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
} else if (detection == "ble-spam") {
    if (secs < 0) secs = 0; 
    if (secs > 86400) secs = 86400;
    
    stopRequested = false;
    req->send(200, "text/plain", forever ? "BLE spam detection starting (forever)" : ("BLE spam detection starting for " + String(secs) + "s"));
    
    if (!blueTeamTaskHandle) {
        xTaskCreatePinnedToCore(bleScannerTask, "blescan", 12288, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
  
  } else if (detection == "device-scan") {
      if (secs < 0) secs = 0;
      if (secs > 86400) secs = 86400;
      
      stopRequested = false;
      req->send(200, "text/plain", forever ? "Device scan starting (forever)" : ("Device scan starting for " + String(secs) + "s"));
      
      if (!workerTaskHandle) {
          xTaskCreatePinnedToCore(snifferScanTask, "sniffer", 12288, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
      }
   } else if (detection == "karma") {
      karmaDetectionEnabled = true;
      stopRequested = false;
      req->send(200, "text/plain",
                forever ? "Karma detection starting (forever)" :
                ("Karma detection starting for " + String(secs) + "s"));

      if (!blueTeamTaskHandle) {
          xTaskCreatePinnedToCore(karmaDetectionTask, "karma", 12288,
                                  (void*)(intptr_t)(forever ? 0 : secs),
                                  1, &blueTeamTaskHandle, 1);
      }

  } else if (detection == "probe-flood") {
      probeFloodDetectionEnabled = true;
      stopRequested = false;
      req->send(200, "text/plain",
                forever ? "Probe flood detection starting (forever)" :
                ("Probe flood detection starting for " + String(secs) + "s"));

      if (!blueTeamTaskHandle) {
          xTaskCreatePinnedToCore(probeFloodDetectionTask, "probe", 12288,
                                  (void*)(intptr_t)(forever ? 0 : secs),
                                  1, &blueTeamTaskHandle, 1);
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

  server->on("/sniffer-cache", HTTP_GET, [](AsyncWebServerRequest *r) {
      r->send(200, "text/plain", getSnifferCache());
  });

  server->begin();
  Serial.println("[WEB] Server started.");
}

void startAPAndServer() {
    Serial.println("[SYS] Starting AP and web server...");
    
    if (server) {
        server->end();
        delay(1000);
        delete server;
        server = nullptr;
        delay(1000);
    }
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_set_promiscuous_filter(nullptr);
    delay(500);
    
    WiFi.persistent(false);
    WiFi.disconnect(true);
    WiFi.softAPdisconnect(true);
    delay(1000);
    
    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK) {
        // Serial.printf("[SYS] WiFi stop error: %d\n", err);
        delay(500);
    }
    
    // err = esp_wifi_deinit();
    // if (err != ESP_OK) {
    //     // Serial.printf("[SYS] WiFi deinit error: %d\n", err);
    //     esp_wifi_stop();
    //     delay(500);
    //     esp_wifi_deinit();
    // }
    
    WiFi.mode(WIFI_OFF);
    delay(3000);
    
    const int MAX_RETRIES = 3;
    bool apStarted = false;
    
    for (int attempt = 1; attempt <= MAX_RETRIES && !apStarted; attempt++) {
        Serial.printf("[SYS] AP start attempt %d/%d\n", attempt, MAX_RETRIES);
        
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        err = esp_wifi_init(&cfg);
        if (err != ESP_OK) {
            Serial.printf("[SYS] WiFi init failed: %d\n", err);
            delay(2000);
            continue;
        }
        
        WiFi.mode(WIFI_AP);
        delay(1500);
        
        IPAddress local_IP(192, 168, 4, 1);
        IPAddress gateway(192, 168, 4, 1);
        IPAddress subnet(255, 255, 255, 0);
        
        if (!WiFi.softAPConfig(local_IP, gateway, subnet)) {
            Serial.println("[SYS] AP Config failed");
            delay(1000);
        }
        
        int channel = (attempt == 3) ? 11 : AP_CHANNEL;
        apStarted = WiFi.softAP(AP_SSID, AP_PASS, channel, 0, 8);
        
        if (!apStarted) {
            WiFi.mode(WIFI_OFF);
            delay(2000);
        }
    }
    
    if (apStarted) {
        delay(3000);
        
        IPAddress ip = WiFi.softAPIP();
        for (int retries = 0; retries < 10 && ip == IPAddress(0,0,0,0); retries++) {
            delay(500);
            ip = WiFi.softAPIP();
        }
        
        Serial.printf("[SYS] AP started successfully. IP: %s\n", ip.toString().c_str());
        WiFi.setHostname("Antihunter");
        delay(2000);
        
        server = new AsyncWebServer(80);
        startWebServer();
        
    } else {
        Serial.println("[CRITICAL] Cannot start ANY AP mode!");
        Serial.println("[CRITICAL] Device will restart in 5 seconds...");
        delay(5000);
        ESP.restart();
    }
}

void stopAPAndServer() {
    Serial.println("[SYS] Stopping AP and web server...");
    
    if (server) {
        server->end();
        delay(500);
        delete server;
        server = nullptr;
        delay(500);
    }
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_set_promiscuous_filter(nullptr);
    delay(200);
    
    WiFi.softAPdisconnect(true);
    WiFi.disconnect(true);
    delay(1000);
    
    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK) {
        Serial.printf("[SYS] WiFi stop error: %d\n", err);
        delay(500);
        esp_wifi_stop();
    }
    
    err = esp_wifi_deinit();
    if (err != ESP_OK) {
        Serial.printf("[SYS] WiFi deinit error: %d\n", err);
        delay(500);
        esp_wifi_stop();
        delay(200);
        esp_wifi_deinit();
    }
    
    WiFi.mode(WIFI_OFF);
    delay(2000);
    WiFi.persistent(false);
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
    
    // Include GPS in ALL cases when available
    String baseMsg = String(nodeId) + ": Target: " + (hit.isBLE ? "BLE" : "WiFi") + 
                     " " + String(mac_str) + " RSSI:" + String(hit.rssi);
    
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

void sendTrackerMeshUpdate() {
    static unsigned long lastTrackerMesh = 0;
    const unsigned long trackerInterval = 15000;

    if (millis() - lastTrackerMesh < trackerInterval) return;
    lastTrackerMesh = millis();

    uint8_t trackerMac[6];
    int8_t trackerRssi;
    uint32_t trackerLastSeen, trackerPackets;
    getTrackerStatus(trackerMac, trackerRssi, trackerLastSeen, trackerPackets);

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             trackerMac[0], trackerMac[1], trackerMac[2],
             trackerMac[3], trackerMac[4], trackerMac[5]);

    char tracker_msg[MAX_MESH_SIZE];
    uint32_t ago = trackerLastSeen ? (millis() - trackerLastSeen) / 1000 : 999;

    int msg_len = snprintf(tracker_msg, sizeof(tracker_msg),
                          "%s: Tracking: %s RSSI:%ddBm LastSeen:%us Pkts:%u",
                          nodeId.c_str(), mac_str, (int)trackerRssi, ago, (unsigned)trackerPackets);

    if (Serial1.availableForWrite() >= msg_len) {
        Serial.printf("[MESH] %s\n", tracker_msg);
        Serial1.println(tracker_msg);
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
    Serial.printf("[MESH] Config: 115200 8N1 on RX=%d TX=%d\n", MESH_RX_PIN, MESH_TX_PIN);
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
  else if (command.startsWith("TRACK_START:"))
  {
    String params = command.substring(12);
    int macDelim = params.indexOf(':');
    int modeDelim = params.indexOf(':', macDelim + 1);
    int secsDelim = params.indexOf(':', modeDelim + 1);
    int channelDelim = params.indexOf(':', secsDelim + 1);

    if (macDelim > 0 && modeDelim > 0 && secsDelim > 0)
    {
      String mac = params.substring(0, macDelim);
      int mode = params.substring(macDelim + 1, modeDelim).toInt();
      int secs = params.substring(modeDelim + 1, secsDelim).toInt();
      String channels = (channelDelim > 0) ? params.substring(secsDelim + 1, channelDelim) : "6";
      bool forever = (channelDelim > 0 && params.indexOf("FOREVER", channelDelim) > 0);

      uint8_t trackerMac[6];
      if (parseMac6(mac, trackerMac) && mode >= 0 && mode <= 2)
      {
        setTrackerMac(trackerMac);
        currentScanMode = (ScanMode)mode;
        parseChannelsCSV(channels);
        stopRequested = false;

        if (!workerTaskHandle)
        {
          xTaskCreatePinnedToCore(trackerTask, "tracker", 8192,
                                  (void *)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1);
        }
        Serial.printf("[MESH] Started tracker via mesh command for %s\n", mac.c_str());
        Serial1.println(nodeId + ": TRACK_ACK:STARTED:" + mac);
      }
    }
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

    if (trackerMode)
    {
      uint8_t trackerMac[6];
      int8_t trackerRssi;
      uint32_t trackerLastSeen, trackerPackets;
      getTrackerStatus(trackerMac, trackerRssi, trackerLastSeen, trackerPackets);

      char tracker_status[MAX_MESH_SIZE];
      snprintf(tracker_status, sizeof(tracker_status),
               "%s: TRACKER: Target:%s RSSI:%ddBm Pkts:%u",
               nodeId.c_str(),
               macFmt6(trackerMac).c_str(),
               (int)trackerRssi,
               (unsigned)trackerPackets);
      Serial1.println(tracker_status);
    }
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

    if (parseMac6(mac, triangulationTarget))
    {
      triangulationNodes.clear();
      triangulationActive = true;
      triangulationStart = millis();
      triangulationDuration = duration;

      currentScanMode = SCAN_BOTH;
      stopRequested = false;
      if (!workerTaskHandle)
      {
        xTaskCreatePinnedToCore(listScanTask, "triangulate", 8192,
                                (void *)(intptr_t)duration, 1, &workerTaskHandle, 1);
      }

      Serial.printf("[TRIANGULATE] Started for %s (%ds)\n", mac.c_str(), duration);
      Serial1.println(nodeId + ": TRIANGULATE_ACK:" + mac);
    }
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
            int macStart = content.indexOf(' ', 8) + 1;
            int macEnd = content.indexOf(' ', macStart);
            if (macEnd > macStart) {
                String macStr = content.substring(macStart, macEnd);
                uint8_t mac[6];
                if (parseMac6(macStr, mac) && memcmp(mac, triangulationTarget, 6) == 0) {
                    int rssiIdx = content.indexOf("RSSI:");
                    if (rssiIdx > 0) {
                        int rssiEnd = content.indexOf(' ', rssiIdx + 5);
                        if (rssiEnd < 0) rssiEnd = content.length();
                        int rssi = content.substring(rssiIdx + 5, rssiEnd).toInt();
                        
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
                                node.rssi = rssi;
                                node.hitCount++;
                                if (hasGPS) {
                                    node.lat = lat;
                                    node.lon = lon;
                                    node.hasGPS = true;
                                }
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            TriangulationNode newNode = {sendingNode, lat, lon, (int8_t)rssi, 1, hasGPS};
                            triangulationNodes.push_back(newNode);
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

// void processUSBToMesh() {
//     static String usbBuffer = "";
//     while (Serial.available()) {
//     int ch = Serial.read();  // read a byte (returns -1 if none)
//     if (ch < 0) break;
//     char c = (char)ch;
//     Serial.write((uint8_t)c); // echo the byte back
//     if (c == '\n' || c == '\r' || c == ':') {
//         if (usbBuffer.length() > 0) {
//             // only log/process when we have a complete message
//             Serial.println(usbBuffer);
//             processMeshMessage(usbBuffer);
//             Serial.printf("[MESH RX] %s\n", usbBuffer.c_str());
//             usbBuffer = "";
//         }
//     } else {
//         usbBuffer += c;
//         if (usbBuffer.length() > 2048) {
//             usbBuffer = "";
//         }
//     }
// }