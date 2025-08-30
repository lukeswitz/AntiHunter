#include "network.h"
#include "hardware.h"
#include "scanner.h"
#include <AsyncTCP.h>

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_coexist.h"
}

AsyncWebServer *server = nullptr;
bool meshEnabled = true;
static unsigned long lastMeshSend = 0;
const unsigned long MESH_SEND_INTERVAL = 10000;
const int MAX_MESH_SIZE = 230;

// External references
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern int cfgBeeps, cfgGapMs;
extern String lastResults;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t workerTaskHandle;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern void parseChannelsCSV(const String &csv);

void initializeNetwork()
{
  Serial.println("Initializing mesh UART...");
  initializeMesh();

  Serial.println("Starting AP...");
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
  delay(100);
  WiFi.setHostname("Antihunter");

  Serial.println("Starting web server...");
  startWebServer();
}

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Antihunter</title>
<style>
:root{--bg:#000;--fg:#00ff7f;--fg2:#00cc66;--accent:#0aff9d;--card:#0b0b0b;--muted:#00ff7f99}
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
.header{padding:22px 18px;border-bottom:1px solid #003b24;background:linear-gradient(180deg,#001a10,#000);display:flex;align-items:center;gap:14px}
h1{margin:0;font-size:22px;letter-spacing:1px}
.container{max-width:1200px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid #003b24;border-radius:12px;padding:16px;margin:16px 0;box-shadow:0 8px 30px rgba(0,255,127,.05)}
label{display:block;margin:6px 0 4px;color:var(--muted)}
textarea, input[type=text], input[type=number], select{width:100%;background:#000;border:1px solid #003b24;border-radius:10px;color:var(--fg);padding:10px 12px;outline:none}
textarea{min-height:128px;resize:vertical}
select{cursor:pointer}
select option{background:#000;color:var(--fg)}
.btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #004e2f;background:#001b12;color:var(--fg);text-decoration:none;cursor:pointer;transition:transform .05s ease, box-shadow .2s}
.btn:hover{box-shadow:0 6px 18px rgba(10,255,157,.15);transform:translateY(-1px)}
.btn.primary{background:#002417;border-color:#00cc66}
.btn.alt{background:#00140d;border-color:#004e2f;color:var(--accent)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.small{opacity:.65} pre{white-space:pre-wrap;background:#000;border:1px dashed #003b24;border-radius:10px;padding:12px}
a{color:var(--accent)} hr{border:0;border-top:1px dashed #003b24;margin:14px 0}
.banner{font-size:12px;color:#0aff9d;border:1px dashed #004e2f;padding:8px;border-radius:10px;background:#001108}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:14px}
@media(max-width:1200px){.grid{grid-template-columns:1fr 1fr}}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
#toast{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{background:#001d12;border:1px solid #0aff9d55;color:var(--fg);padding:10px 12px;border-radius:10px;box-shadow:0 8px 30px rgba(10,255,157,.2);opacity:0;transform:translateY(8px);transition:opacity .15s, transform .15s}
.toast.show{opacity:1;transform:none}
.toast .title{color:#0aff9d}
.footer{opacity:.7;font-size:12px;padding:8px 16px;text-align:center}
.logo{width:28px;height:28px}
.mode-indicator{background:#001a10;border:1px solid #00cc66;padding:8px 12px;border-radius:8px;font-weight:bold;margin-left:auto}
</style></head><body>
<div class="header">
  <svg class="logo" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect x="6" y="6" width="52" height="52" rx="8" fill="#00180F" stroke="#00ff7f" stroke-width="2"/>
    <path d="M16 40 L32 16 L48 40" fill="none" stroke="#0aff9d" stroke-width="3"/>
    <circle cx="32" cy="44" r="3" fill="#00ff7f"/>
  </svg>
  <h1>Antihunter</h1>
  <div class="mode-indicator" id="modeIndicator">WiFi Mode</div>
</div>
<div id="toast"></div>
<div class="container">

<div class="grid">
  <div class="card">
    <div class="banner">Targets: full MACs (<code>AA:BB:CC:DD:EE:FF</code>) or OUIs (<code>AA:BB:CC</code>), one per line. Used in <b>List Scan</b>.</div>
    <form id="f" method="POST" action="/save">
      <label for="list">Targets</label>
      <textarea id="list" name="list" placeholder="AA:BB:CC:DD:EE:FF&#10;DC:A6:32"></textarea>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Save</button>
        <a class="btn" href="/export" data-ajax="false">Download</a>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>List Scan</h3>
    <form id="s" method="POST" action="/scan">
      <label>Scan Mode</label>
      <select name="mode" id="scanMode">
        <option value="0">WiFi Only</option>
        <option value="1">BLE Only</option>
        <option value="2">WiFi + BLE</option>
      </select>
      <label>Duration (seconds)</label>
      <input type="number" name="secs" min="0" max="86400" value="60">
      <div class="row"><input type="checkbox" id="forever1" name="forever" value="1"><label for="forever1">∞ Forever</label></div>
      <label>WiFi Channels CSV</label>
      <input type="text" name="ch" value="1,6,11">
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Start List Scan</button>
        <a class="btn alt" href="/beep" data-ajax="true">Test Buzzer</a>
        <a class="btn" href="/stop" data-ajax="true">Stop</a>
      </div>
      <p class="small">AP goes offline during scan and returns.</p>
    </form>
  </div>

  <div class="card">
    <h3>Tracker (single MAC "Geiger")</h3>
    <form id="t" method="POST" action="/track">
      <label>Scan Mode</label>
      <select name="mode">
        <option value="0">WiFi Only</option>
        <option value="1">BLE Only</option>
        <option value="2">WiFi + BLE</option>
      </select>
      <label>Target MAC (AA:BB:CC:DD:EE:FF)</label>
      <input type="text" name="mac" placeholder="34:21:09:83:D9:51">
      <label>Duration (seconds)</label>
      <input type="number" name="secs" min="0" max="86400" value="180">
      <div class="row"><input type="checkbox" id="forever2" name="forever" value="1"><label for="forever2">∞ Forever</label></div>
      <label>WiFi Channels CSV (use single channel for smoother tracking)</label>
      <input type="text" name="ch" value="6">
      <p class="small">Closer = faster & higher-pitch beeps. Lost = slow click.</p>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Start Tracker</button>
        <a class="btn" href="/stop" data-ajax="true">Stop</a>
      </div>
    </form>
  </div>

  <div class="card">
  <h3>WiFi Traffic Sniffers</h3>
  <form id="bt" method="POST" action="/blueteam">
    <label>Detection Mode</label>
    <select name="detection" id="detectionMode">
      <option value="deauth">Deauth/Disassoc Detection</option>
      <option value="beacon-flood">Beacon Flood Detection</option>
      <option value="evil-twin" disabled>Evil Twin (Coming Soon)</option>
    </select>
    
    <div id="deauthSettings">
      <label>Duration (seconds)</label>
      <input type="number" name="secs" min="0" max="86400" value="300">
      <div class="row"><input type="checkbox" id="forever3" name="forever" value="1"><label for="forever3">∞ Forever</label></div>
      <div class="row">
        <input type="checkbox" id="alertBeep" name="alertBeep" value="1" checked>
        <label for="alertBeep">Audio Alert on Detection</label>
      </div>
    </div>
    
    <div class="row" style="margin-top:10px">
      <button class="btn primary" type="submit">Start Detection</button>
      <a class="btn" href="/stop" data-ajax="true">Stop</a>
    </div>
    <p class="small">Monitors adversarial & suspicious WiFi traffic. AP goes offline during detection. </p>
  </form>
</div>

  <div class="card">
    <h3>Buzzer</h3>
    <form id="c" method="POST" action="/config">
      <label>Beeps per hit (List Scan)</label>
      <input type="number" id="beeps" name="beeps" min="1" max="10" value="2">
      <label>Gap between beeps (ms)</label>
      <input type="number" id="gap" name="gap" min="20" max="2000" value="80">
      <div class="row" style="margin-top:10px">
        <button class="btn primary" type="submit">Save Config</button>
        <a class="btn alt" href="/beep" data-ajax="true">Test Beep</a>
      </div>
    </form>
  </div>

  <div class="card">
  <h3>Mesh Network</h3>
  <div class="row">
    <input type="checkbox" id="meshEnabled" checked>
    <label for="meshEnabled">Enable Mesh Notifications</label>
  </div>
  <div class="row" style="margin-top:10px">
    <a class="btn alt" href="/mesh-test" data-ajax="true">Test Mesh</a>
  </div>
  <p class="small">Sends list and tracker target alerts over meshtastic.</p>
</div>

  <div class="card">
    <h3>Diagnostics</h3>
    <pre id="diag">Loading…</pre>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <h3>Last Results</h3>
  <pre id="r">None yet.</pre>
</div>

<div class="footer">© Team AntiHunter 2025</div>
</div>
<script>
let selectedMode = '0';

function toast(msg){
  const wrap = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = '<div class="title">Antihunter</div><div class="msg">'+msg+'</div>';
  wrap.appendChild(el);
  requestAnimationFrame(()=>{ el.classList.add('show'); });
  setTimeout(()=>{ el.classList.remove('show'); setTimeout(()=>wrap.removeChild(el), 200); }, 2500);
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
    document.getElementById('list').value = await r.text();
    const cfg = await fetch('/config').then(r=>r.json());
    document.getElementById('beeps').value = cfg.beeps;
    document.getElementById('gap').value = cfg.gap;
    const rr = await fetch('/results'); 
    document.getElementById('r').innerText = await rr.text();
  }catch(e){}
}

async function tick(){
  try{
    const d = await fetch('/diag'); 
    const diagText = await d.text();
    document.getElementById('diag').innerText = diagText;
    
    if (diagText.includes('Scanning: yes')) {
      const modeMatch = diagText.match(/Scan Mode: (\w+)/);
      if (modeMatch) {
        const serverMode = modeMatch[1];
        let modeValue = '0';
        if (serverMode === 'BLE') modeValue = '1';
        else if (serverMode === 'WiFi+BLE') modeValue = '2';
        
        if (modeValue !== selectedMode) {
          updateModeIndicator(modeValue);
        }
      }
    }
  }catch(e){}
}

function updateModeIndicator(mode) {
  selectedMode = mode;
  const indicator = document.getElementById('modeIndicator');
  switch(mode) {
    case '0': indicator.textContent = 'WiFi Mode'; break;
    case '1': indicator.textContent = 'BLE Mode'; break;
    case '2': indicator.textContent = 'WiFi+BLE Mode'; break;
    default: indicator.textContent = 'WiFi Mode';
  }
}

document.getElementById('f').addEventListener('submit', e=>{ e.preventDefault(); ajaxForm(e.target, 'Targets saved ✓'); });
document.getElementById('c').addEventListener('submit', e=>{ e.preventDefault(); ajaxForm(e.target, 'Config saved ✓'); });

document.getElementById('s').addEventListener('submit', e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  updateModeIndicator(fd.get('mode'));
  fetch('/scan', {method:'POST', body:fd}).then(()=>{
    toast('List scan started. AP will drop & return…');
  }).catch(err=>toast('Error: '+err.message));
});

document.getElementById('meshEnabled').addEventListener('change', e=>{
  const enabled = e.target.checked;
  fetch('/mesh', {method:'POST', body: new URLSearchParams({enabled: enabled})})
    .then(r=>r.text())
    .then(t=>toast(t))
    .catch(err=>toast('Error: '+err.message));
});

document.getElementById('bt').addEventListener('submit', e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  fetch('/blueteam', {method:'POST', body:fd}).then(()=>{
    toast('Blue team detection started. AP will drop & return…');
  }).catch(err=>toast('Error: '+err.message));
});

document.getElementById('t').addEventListener('submit', e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  updateModeIndicator(fd.get('mode'));
  fetch('/track', {method:'POST', body:fd}).then(()=>{
    toast('Tracker started. AP will drop & return…');
  }).catch(err=>toast('Error: '+err.message));
});

document.getElementById('scanMode').addEventListener('change', e=>{
  updateModeIndicator(e.target.value);
});

document.querySelector('#t select[name="mode"]').addEventListener('change', e=>{
  updateModeIndicator(e.target.value);
});

document.addEventListener('click', e=>{
  const a = e.target.closest('a[href="/stop"]');
  if (!a) return;
  e.preventDefault();
  fetch('/stop').then(r=>r.text()).then(t=>toast(t));
});

load();
setInterval(tick, 1000);
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

  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", lastResults.length() ? lastResults : String("None yet.")); });

  server->on("/save", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        if (!req->hasParam("list", true)) {
            req->send(400, "text/plain", "Missing 'list'");
            return;
        }
        String txt = req->getParam("list", true)->value();
        saveTargetsList(txt);
        req->send(200, "text/plain", "Saved"); });

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
        String ch = "1,6,11";
        if (req->hasParam("ch", true)) ch = req->getParam("ch", true)->value();
        
        parseChannelsCSV(ch);
        currentScanMode = mode;
        stopRequested = false;
        
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

  server->on("/blueteam", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        String detection = req->getParam("detection", true) ? req->getParam("detection", true)->value() : "deauth";
        int secs = req->getParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 300;
        bool forever = req->hasParam("forever", true);
        
        if (detection == "deauth") {
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", forever ? "Deauth detection starting (forever)" : ("Deauth detection starting for " + String(secs) + "s"));
            
            if (!blueTeamTaskHandle) {
                xTaskCreatePinnedToCore(deauthDetectionTask, "blueteam", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
            }
        } else if (detection == "beacon-flood") {
            if (secs < 0) secs = 0;
            if (secs > 86400) secs = 86400;
            
            stopRequested = false;
            req->send(200, "text/plain", forever ? "Beacon flood detection starting (forever)" : ("Beacon flood detection starting for " + String(secs) + "s"));
            
            if (!blueTeamTaskHandle) {
                xTaskCreatePinnedToCore(beaconFloodTask, "beaconflood", 10240, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
            }
        } else {
            req->send(400, "text/plain", "Detection mode not yet implemented");
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

  server->on("/beep", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        beepPattern(getBeepsPerHit(), getGapMs());
        r->send(200, "text/plain", "Beeped"); });

  server->on("/config", HTTP_GET, [](AsyncWebServerRequest *r)
             {
        String j = String("{\"beeps\":") + cfgBeeps + ",\"gap\":" + cfgGapMs + "}";
        r->send(200, "application/json", j); });

  server->on("/config", HTTP_POST, [](AsyncWebServerRequest *req)
             {
        int beeps = cfgBeeps, gap = cfgGapMs;
        if (req->hasParam("beeps", true)) beeps = req->getParam("beeps", true)->value().toInt();
        if (req->hasParam("gap", true)) gap = req->getParam("gap", true)->value().toInt();
        if (beeps < 1) beeps = 1;
        if (beeps > 10) beeps = 10;
        if (gap < 20) gap = 20;
        if (gap > 2000) gap = 2000;
        cfgBeeps = beeps;
        cfgGapMs = gap;
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

  server->begin();
  Serial.println("[WEB] Server started.");
}

void stopAPAndServer()
{
  Serial.println("[SYS] Stopping AP and web server...");
  if (server)
  {
    server->end();
    delete server;
    server = nullptr;
  }
  WiFi.softAPdisconnect(true);
  delay(100);
}

void startAPAndServer()
{
  Serial.println("[SYS] Starting AP and web server...");

  // Ensure server is completely cleaned up first
  if (server)
  {
    server->end();
    delete server;
    server = nullptr;
  }

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  for (int i = 0; i < 10; i++)
  {
    delay(100);
    yield();
  }

  WiFi.mode(WIFI_AP);
  delay(100);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  delay(100);

  bool apStarted = false;
  for (int attempt = 0; attempt < 3 && !apStarted; attempt++)
  {
    Serial.printf("AP start attempt %d...\n", attempt + 1);
    apStarted = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
    if (!apStarted)
    {
      delay(500); // Wait before retry
      WiFi.mode(WIFI_OFF);
      delay(500);
      WiFi.mode(WIFI_AP);
      delay(200);
    }
  }

  Serial.printf("AP restart %s\n", apStarted ? "SUCCESSFUL" : "FAILED");
  delay(200);
  WiFi.setHostname("Antihunter");

  // Only start server if AP started successfully
  if (apStarted)
  {
    startWebServer();
  }
}

// Mesh UART Messages
void sendMeshNotification(const Hit &hit)
{
  if (!meshEnabled || millis() - lastMeshSend < MESH_SEND_INTERVAL)
    return;
  lastMeshSend = millis();

  char mac_str[18];
  snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
           hit.mac[0], hit.mac[1], hit.mac[2], hit.mac[3], hit.mac[4], hit.mac[5]);

  char mesh_msg[MAX_MESH_SIZE];
  int msg_len = snprintf(mesh_msg, sizeof(mesh_msg),
                         "Target: %s %s RSSI:%d",
                         hit.isBLE ? "BLE" : "WiFi", mac_str, hit.rssi);

  if (msg_len < MAX_MESH_SIZE && hit.name.length() > 0 && hit.name != "WiFi")
  {
    msg_len += snprintf(mesh_msg + msg_len, sizeof(mesh_msg) - msg_len,
                        " Name:%s", hit.name.c_str());
  }

  if (Serial1.availableForWrite() >= msg_len)
  {
    Serial.printf("[MESH] %s\n", mesh_msg);
    Serial1.println(mesh_msg);
  }
}

void sendTrackerMeshUpdate()
{
  static unsigned long lastTrackerMesh = 0;
  const unsigned long trackerInterval = 15000;

  if (millis() - lastTrackerMesh < trackerInterval)
    return;
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
                         "Tracking: %s RSSI:%ddBm LastSeen:%us Pkts:%u",
                         mac_str, (int)trackerRssi, ago, (unsigned)trackerPackets);

  if (Serial1.availableForWrite() >= msg_len)
  {
    Serial.printf("[MESH] %s\n", tracker_msg);
    Serial1.println(tracker_msg);
  }
}

void initializeMesh()
{
  Serial1.begin(115200, SERIAL_8N1, MESH_RX_PIN, MESH_TX_PIN);
  Serial.println("Mesh UART communication initialized on Serial1");
}
