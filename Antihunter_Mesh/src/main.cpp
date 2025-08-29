#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <vector>
#include <set>
#include <pgmspace.h>

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_coexist.h"
}

#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#ifndef AP_SSID
#define AP_SSID "Antihunter"
#endif
#ifndef AP_PASS
#define AP_PASS "ouispy123"
#endif
#ifndef AP_CHANNEL
#define AP_CHANNEL 6
#endif
#ifndef COUNTRY
#define COUNTRY "NO"
#endif
#ifndef BUZZER_PIN
#define BUZZER_PIN 3
#endif
#ifndef BUZZER_IS_PASSIVE
#define BUZZER_IS_PASSIVE 1
#endif

// ----------------- Globals -----------------
Preferences prefs;
AsyncWebServer *server = nullptr;
TaskHandle_t workerTaskHandle = nullptr;

// ----------------- Blue Tools -----------------
struct DeauthHit
{
  uint8_t srcMac[6];
  uint8_t destMac[6];
  uint8_t bssid[6];
  int8_t rssi;
  uint8_t channel;
  uint16_t reasonCode;
  uint32_t timestamp;
  bool isDisassoc; // false for deauth, true for disassoc
};

static std::vector<DeauthHit> deauthLog;
static volatile uint32_t deauthCount = 0;
static volatile uint32_t disassocCount = 0;
static bool deauthDetectionEnabled = false;
static QueueHandle_t deauthQueue;
static TaskHandle_t blueTeamTaskHandle = nullptr;
static int blueTeamDuration = 300; // Default 5 minutes
static bool blueTeamForever = false;

// ---------- Beacon Flood Detection ----------
struct BeaconHit
{
  uint8_t srcMac[6];
  uint8_t bssid[6];
  int8_t rssi;
  uint8_t channel;
  uint32_t timestamp;
  String ssid;
  uint16_t beaconInterval;
};

static std::vector<BeaconHit> beaconLog;
static std::map<String, uint32_t> beaconCounts; // MAC -> beacon count
static std::map<String, uint32_t> beaconLastSeen; // MAC -> last seen time
static std::map<String, std::vector<uint32_t>> beaconTimings; // MAC -> timing intervals
static volatile uint32_t totalBeaconsSeen = 0;
static volatile uint32_t suspiciousBeacons = 0;
static bool beaconFloodDetectionEnabled = false;
static QueueHandle_t beaconQueue;

// Beacon flood detection thresholds
static const uint32_t BEACON_FLOOD_THRESHOLD = 50; // beacons per 10 seconds
static const uint32_t BEACON_TIMING_WINDOW = 10000; // 10 second window
static const uint32_t MIN_BEACON_INTERVAL = 50; // minimum ms between beacons
static const uint32_t MAX_SSIDS_PER_MAC = 10; // max SSIDs from single MAC

//  ----------------- Mesh  ----------------
static unsigned long lastMeshSend = 0;
const unsigned long MESH_SEND_INTERVAL = 10000; // 10 seconds between mesh sends
const int MAX_MESH_SIZE = 230;
static volatile bool stopRequested = false;
static bool meshEnabled = true;

// ---------- Config (beep count + gap) ----------
static int cfgBeeps = 2;  // beeps per hit (list mode)
static int cfgGapMs = 80; // gap between beeps (ms)

// ---------- Scan Mode Selection ----------
enum ScanMode
{
  SCAN_WIFI,
  SCAN_BLE,
  SCAN_BOTH
};
static ScanMode currentScanMode = SCAN_WIFI;

// ---------- Small helpers ----------
static String macFmt6(const uint8_t *m)
{
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(b);
}
static bool parseMac6(const String &in, uint8_t out[6])
{
  String t;
  for (size_t i = 0; i < in.length(); ++i)
  {
    char c = in[i];
    if (isxdigit((int)c))
      t += (char)toupper(c);
  }
  if (t.length() != 12)
    return false;
  for (int i = 0; i < 6; i++)
    out[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
  return true;
}
static inline uint16_t u16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static bool isZeroOrBroadcast(const uint8_t *mac)
{
  bool all0 = true, allF = true;
  for (int i = 0; i < 6; i++)
  {
    if (mac[i] != 0x00)
      all0 = false;
    if (mac[i] != 0xFF)
      allF = false;
  }
  return all0 || allF;
}
static inline int clampi(int v, int lo, int hi)
{
  if (v < lo)
    return lo;
  if (v > hi)
    return hi;
  return v;
}

// ---------- Watchlist ----------
struct Target
{
  uint8_t bytes[6];
  uint8_t len;
}; // len=6 for full, 3 for OUI
static std::vector<Target> targets;

static bool parseMacLike(const String &ln, Target &out)
{
  String t;
  for (size_t i = 0; i < ln.length(); ++i)
  {
    char c = ln[i];
    if (isxdigit((int)c))
      t += (char)toupper(c);
  }
  if (t.length() == 12)
  {
    for (int i = 0; i < 6; i++)
      out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    out.len = 6;
    return true;
  }
  if (t.length() == 6)
  {
    for (int i = 0; i < 3; i++)
      out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    out.len = 3;
    return true;
  }
  return false;
}
static String targetsToText()
{
  String out;
  for (auto &t : targets)
  {
    if (t.len == 6)
    {
      char b[18];
      snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", t.bytes[0], t.bytes[1], t.bytes[2], t.bytes[3], t.bytes[4], t.bytes[5]);
      out += b;
    }
    else
    {
      char b[9];
      snprintf(b, sizeof(b), "%02X:%02X:%02X", t.bytes[0], t.bytes[1], t.bytes[2]);
      out += b;
    }
    out += "\n";
  }
  return out;
}
static void loadTargetsFromNVS()
{
  String txt = prefs.getString("maclist", "");
  targets.clear();
  int start = 0;
  while (start < txt.length())
  {
    int nl = txt.indexOf('\n', start);
    if (nl < 0)
      nl = txt.length();
    String line = txt.substring(start, nl);
    line.trim();
    if (line.length())
    {
      Target t;
      if (parseMacLike(line, t))
        targets.push_back(t);
    }
    start = nl + 1;
  }
}
static void saveTargetsToNVS(const String &txt)
{
  prefs.putString("maclist", txt);
  loadTargetsFromNVS();
}

// ---------- Buzzer (PASSIVE: PWM 50% duty) ----------
#if BUZZER_IS_PASSIVE
static bool buzzerInit = false;
static void buzzerInitIfNeeded(uint32_t f)
{
  if (!buzzerInit)
  {
    ledcAttach(BUZZER_PIN, f, 10);
    buzzerInit = true;
  }
  else
  {
    // To change frequency, detach and reattach
    ledcDetach(BUZZER_PIN);
    ledcAttach(BUZZER_PIN, f, 10);
  }
}

static void buzzerTone(uint32_t f)
{
  buzzerInitIfNeeded(f);
  ledcWrite(BUZZER_PIN, 512); // 50% duty cycle for 10-bit resolution
}
static void buzzerOff()
{
  if (buzzerInit)
    ledcWrite(BUZZER_PIN, 0);
}
#else
static void buzzerTone(uint32_t)
{
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, HIGH);
}
static void buzzerOff() { digitalWrite(BUZZER_PIN, LOW); }
#endif
static void beepOnce(uint32_t freq = 3200, uint32_t ms = 80)
{
  buzzerTone(freq);
  delay(ms);
  buzzerOff();
}
static void beepPattern(int count, int gap_ms)
{
  if (count < 1)
    return;
  for (int i = 0; i < count; i++)
  {
    beepOnce();
    if (i != count - 1)
      delay(gap_ms);
  }
}

// ---------- Scan state / diagnostics ----------
struct Hit
{
  uint8_t mac[6];
  int8_t rssi;
  uint8_t ch;
  String name;
  bool isBLE;
};
static std::set<String> uniqueMacs;
static std::vector<Hit> hitsLog;
static QueueHandle_t macQueue;
static esp_timer_handle_t hopTimer = nullptr;
static std::vector<uint8_t> CHANNELS;
static String lastResults;
static volatile int totalHits = 0;
static volatile uint32_t framesSeen = 0;
static volatile bool scanning = false;
static uint32_t lastScanStart = 0, lastScanEnd = 0, lastScanSecs = 0;
static bool lastScanForever = false;

// BLE Scanner globals
BLEScan *pBLEScan = nullptr;
static volatile uint32_t bleFramesSeen = 0;

// Tracker (single MAC "geiger") state
static volatile bool trackerMode = false;
static uint8_t trackerMac[6] = {0};
static volatile int8_t trackerRssi = -127;
static volatile uint32_t trackerLastSeen = 0;
static volatile uint32_t trackerPackets = 0;

// Map RSSI (-90..-30) to period (1000..120 ms) and freq (2000..4500 Hz)
static int periodFromRSSI(int8_t rssi)
{
  const int rMin = -90, rMax = -30, pMin = 120, pMax = 1000;
  int r = clampi(rssi, rMin, rMax);
  float a = float(r - rMin) / float(rMax - rMin); // 0..1
  int period = (int)(pMax - a * (pMax - pMin));
  return period;
}
static int freqFromRSSI(int8_t rssi)
{
  const int rMin = -90, rMax = -30, fMin = 2000, fMax = 4500;
  int r = clampi(rssi, rMin, rMax);
  float a = float(r - rMin) / float(rMax - rMin); // 0..1
  int f = (int)(fMin + a * (fMax - fMin));
  return f;
}

// fwd decls
void startServer();
void listScanTask(void *pv);
void trackerTask(void *pv);
void blueTeamTask(void *pv);
void beaconFloodTask(void *pv);
void sendMeshNotification(const Hit &hit);
void sendTrackerMeshUpdate();

// Parse channel CSV
static void parseChannelsCSV(const String &csv)
{
  CHANNELS.clear();
  if (csv.indexOf("..") >= 0)
  {
    int a = csv.substring(0, csv.indexOf("..")).toInt();
    int b = csv.substring(csv.indexOf("..") + 2).toInt();
    for (int ch = a; ch <= b; ch++)
      if (ch >= 1 && ch <= 14)
        CHANNELS.push_back((uint8_t)ch);
  }
  else
  {
    int start = 0;
    while (start < csv.length())
    {
      int comma = csv.indexOf(',', start);
      if (comma < 0)
        comma = csv.length();
      int ch = csv.substring(start, comma).toInt();
      if (ch >= 1 && ch <= 14)
        CHANNELS.push_back((uint8_t)ch);
      start = comma + 1;
    }
  }
  if (CHANNELS.empty())
    CHANNELS = {1, 6, 11};
}
static void hopTimerCb(void *)
{
  static size_t idx = 0;
  if (CHANNELS.empty())
    return;
  idx = (idx + 1) % CHANNELS.size();
  esp_wifi_set_channel(CHANNELS[idx], WIFI_SECOND_CHAN_NONE);
}

// Watchlist match helper
static inline bool matchesMac(const uint8_t *mac)
{
  for (auto &t : targets)
  {
    if (t.len == 6)
    {
      bool eq = true;
      for (int i = 0; i < 6; i++)
        if (mac[i] != t.bytes[i])
        {
          eq = false;
          break;
        }
      if (eq)
        return true;
    }
    else
    {
      if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2])
        return true;
    }
  }
  return false;
}
static inline bool isTrackerTarget(const uint8_t *mac)
{
  for (int i = 0; i < 6; i++)
    if (mac[i] != trackerMac[i])
      return false;
  return true;
}

// ---------- Deauth/Disassoc Detection ----------
static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt)
{
  if (!deauthDetectionEnabled)
    return;

  const uint8_t *p = ppkt->payload;
  if (ppkt->rx_ctrl.sig_len < 26)
    return; // minimum for deauth/disassoc frame

  uint16_t fc = u16(p);
  uint8_t ftype = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;

  // Check if it's a deauth (subtype 12) or disassoc (subtype 10) frame
  if (ftype == 0 && (subtype == 12 || subtype == 10))
  {
    DeauthHit hit;

    memcpy(hit.destMac, p + 4, 6); // DA (Address 1)
    memcpy(hit.srcMac, p + 10, 6); // SA (Address 2)
    memcpy(hit.bssid, p + 16, 6);  // BSSID (Address 3)

    hit.rssi = ppkt->rx_ctrl.rssi;
    hit.channel = ppkt->rx_ctrl.channel;
    hit.timestamp = millis();
    hit.isDisassoc = (subtype == 10);

    if (ppkt->rx_ctrl.sig_len >= 26)
    {
      hit.reasonCode = u16(p + 24);
    }
    else
    {
      hit.reasonCode = 0;
    }

    if (hit.isDisassoc)
    {
      disassocCount + 1;
    }
    else
    {
      deauthCount++;
    }

    BaseType_t w = false;
    if (deauthQueue)
    {
      xQueueSendFromISR(deauthQueue, &hit, &w);
      if (w)
        portYIELD_FROM_ISR();
    }
  }
}

// ---------- BLE Scanner callbacks ----------
class MyBLEAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks
{
  void onResult(BLEAdvertisedDevice advertisedDevice)
  {
    bleFramesSeen++;

    // Extract MAC address
    uint8_t mac[6];
    String macStr = advertisedDevice.getAddress().toString();
    if (!parseMac6(macStr, mac))
      return;

    // Check if matches targets or tracker
    if (trackerMode)
    {
      if (isTrackerTarget(mac))
      {
        trackerRssi = advertisedDevice.getRSSI();
        trackerLastSeen = millis();
        trackerPackets++;
      }
    }
    else
    {
      if (matchesMac(mac))
      {
        Hit h;
        memcpy(h.mac, mac, 6);
        h.rssi = advertisedDevice.getRSSI();
        h.ch = 0; // BLE doesn't use WiFi channels
        h.name = advertisedDevice.getName().length() > 0 ? advertisedDevice.getName() : String("Unknown");
        h.isBLE = true;

        BaseType_t w = false;
        xQueueSendFromISR(macQueue, &h, &w);
        if (w)
          portYIELD_FROM_ISR();
      }
    }
  }
};

static void IRAM_ATTR detectBeaconFlood(const wifi_promiscuous_pkt_t *ppkt)
{
  if (!beaconFloodDetectionEnabled)
    return;

  const uint8_t *p = ppkt->payload;
  if (ppkt->rx_ctrl.sig_len < 36) // minimum beacon frame size
    return;

  uint16_t fc = u16(p);
  uint8_t ftype = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;

  // Check if it's a beacon frame (subtype 8)
  if (ftype == 0 && subtype == 8) 
  {
    BeaconHit hit;
    
    memcpy(hit.srcMac, p + 10, 6); // SA (Address 2)
    memcpy(hit.bssid, p + 16, 6);  // BSSID (Address 3)
    
    hit.rssi = ppkt->rx_ctrl.rssi;
    hit.channel = ppkt->rx_ctrl.channel;
    hit.timestamp = millis();
    hit.beaconInterval = 0;
    hit.ssid = "";
    
    // Extract beacon interval and SSID from beacon frame
    if (ppkt->rx_ctrl.sig_len >= 38) {
      hit.beaconInterval = u16(p + 32); // beacon interval at offset 32
      
      // Parse SSID from tagged parameters (starts at offset 36)
      const uint8_t *tags = p + 36;
      uint32_t remaining = ppkt->rx_ctrl.sig_len - 36;
      
      if (remaining >= 2 && tags[0] == 0) { // SSID tag
        uint8_t ssid_len = tags[1];
        if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
          char ssid_str[33] = {0};
          memcpy(ssid_str, tags + 2, ssid_len);
          hit.ssid = String(ssid_str);
        }
      }
    }
    
    totalBeaconsSeen++;
    
    // Detect flood patterns
    String macStr = macFmt6(hit.srcMac);
    uint32_t now = millis();
    
    beaconCounts[macStr]++;
    beaconLastSeen[macStr] = now;
    
    // Track timing patterns
    if (beaconTimings[macStr].size() > 20) {
      beaconTimings[macStr].erase(beaconTimings[macStr].begin());
    }
    beaconTimings[macStr].push_back(now);
    
    bool suspicious = false;
    
    // Check for rapid beaconing (flood)
    if (beaconTimings[macStr].size() >= 2) {
      uint32_t interval = now - beaconTimings[macStr][beaconTimings[macStr].size()-2];
      if (interval < MIN_BEACON_INTERVAL) {
        suspicious = true;
      }
    }
    
    // Check beacon count in time window
    uint32_t recentCount = 0;
    for (auto& timing : beaconTimings[macStr]) {
      if (now - timing <= BEACON_TIMING_WINDOW) {
        recentCount++;
      }
    }
    
    if (recentCount > BEACON_FLOOD_THRESHOLD) {
      suspicious = true;
    }
    
    // Check for beacon interval anomalies (too fast)
    if (hit.beaconInterval > 0 && hit.beaconInterval < 50) { // < 50 TUs (51.2ms)
      suspicious = true;
    }
    
    if (suspicious) {
      suspiciousBeacons++;
      BaseType_t w = false;
      if (beaconQueue) {
        xQueueSendFromISR(beaconQueue, &hit, &w);
        if (w) portYIELD_FROM_ISR();
      }
    }
  }
}

// ---------- WiFi Sniffer callback ----------
static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  detectDeauthFrame(ppkt);
  detectBeaconFlood(ppkt);
  framesSeen++;
  if (!ppkt)
    return;
  const uint8_t *p = ppkt->payload;
  if (ppkt->rx_ctrl.sig_len < 24)
    return; // too short for 802.11 header

  uint16_t fc = u16(p);            // frame control
  uint8_t ftype = (fc >> 2) & 0x3; // 0=mgmt,1=ctrl,2=data
  uint8_t tods = (fc >> 8) & 0x1;
  uint8_t fromds = (fc >> 9) & 0x1;

  const uint8_t *a1 = p + 4, *a2 = p + 10, *a3 = p + 16, *a4 = p + 24;
  uint8_t cand1[6], cand2[6];
  bool c1 = false, c2 = false;

  if (ftype == 0)
  { // mgmt: SA=a2, BSSID=a3
    if (!isZeroOrBroadcast(a2))
    {
      memcpy(cand1, a2, 6);
      c1 = true;
    }
    if (!isZeroOrBroadcast(a3))
    {
      memcpy(cand2, a3, 6);
      c2 = true;
    }
  }
  else if (ftype == 2)
  { // data
    if (!tods && !fromds)
    { // STA<->STA
      if (!isZeroOrBroadcast(a2))
      {
        memcpy(cand1, a2, 6);
        c1 = true;
      } // SA
      if (!isZeroOrBroadcast(a3))
      {
        memcpy(cand2, a3, 6);
        c2 = true;
      } // BSSID
    }
    else if (tods && !fromds)
    { // STA->AP
      if (!isZeroOrBroadcast(a2))
      {
        memcpy(cand1, a2, 6);
        c1 = true;
      } // SA (STA)
      if (!isZeroOrBroadcast(a1))
      {
        memcpy(cand2, a1, 6);
        c2 = true;
      } // BSSID
    }
    else if (!tods && fromds)
    { // AP->STA
      if (!isZeroOrBroadcast(a3))
      {
        memcpy(cand1, a3, 6);
        c1 = true;
      } // SA (STA)
      if (!isZeroOrBroadcast(a2))
      {
        memcpy(cand2, a2, 6);
        c2 = true;
      } // BSSID (AP)
    }
    else
    { // WDS
      if (!isZeroOrBroadcast(a2))
      {
        memcpy(cand1, a2, 6);
        c1 = true;
      }
      if (!isZeroOrBroadcast(a3))
      {
        memcpy(cand2, a3, 6);
        c2 = true;
      }
    }
  }
  else
  {
    return; // ignore control frames
  }

  // Tracker (single target)
  if (trackerMode && !currentScanMode == SCAN_BLE)
  {
    if (c1 && isTrackerTarget(cand1))
    {
      trackerRssi = ppkt->rx_ctrl.rssi;
      trackerLastSeen = millis();
      trackerPackets++;
    }
    if (c2 && isTrackerTarget(cand2))
    {
      trackerRssi = ppkt->rx_ctrl.rssi;
      trackerLastSeen = millis();
      trackerPackets++;
    }
  }
  else if (!trackerMode)
  {
    // Watchlist (multi-targets)
    if (c1 && matchesMac(cand1))
    {
      Hit h;
      memcpy(h.mac, cand1, 6);
      h.rssi = ppkt->rx_ctrl.rssi;
      h.ch = ppkt->rx_ctrl.channel;
      h.name = String("WiFi");
      h.isBLE = false;
      BaseType_t w = false;
      xQueueSendFromISR(macQueue, &h, &w);
      if (w)
        portYIELD_FROM_ISR();
    }
    if (c2 && matchesMac(cand2))
    {
      Hit h;
      memcpy(h.mac, cand2, 6);
      h.rssi = ppkt->rx_ctrl.rssi;
      h.ch = ppkt->rx_ctrl.channel;
      h.name = String("WiFi");
      h.isBLE = false;
      BaseType_t w = false;
      xQueueSendFromISR(macQueue, &h, &w);
      if (w)
        portYIELD_FROM_ISR();
    }
  }
}

// ---------- Web UI ----------
static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Antihunter by SirHaXalot</title>
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

/* Toast */
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
  <h1>Antihunter <span style="color:#0aff9d">by SirHaXalot</span></h1>
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
      <p class="small">AP goes offline during scan and returns when you stop.</p>
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
  <h3>Blue Team Detection</h3>
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
    <p class="small">Monitors for deauth attacks. AP goes offline during detection.</p>
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
  <p class="small">Sends target alerts over meshtastic (10s interval)</p>
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

<div class="footer">© Antihunter by SirHaXalot</div>
</div>
<script>
let selectedMode = '0'; // Track the selected mode globally

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
    
    // Only update mode indicator from server if we're actually scanning
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

// Stop button
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

// ---------- AP/server helpers ----------
static void startAP()
{
  WiFi.persistent(false);
  WiFi.disconnect(true, false);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  bool ok = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
  delay(100);
  WiFi.setHostname("Antihunter");
  Serial.printf("AP start: %s  SSID=%s  PASS=%s  CH=%d  IP=%s\n",
                ok ? "OK" : "FAIL", AP_SSID, AP_PASS, AP_CHANNEL,
                WiFi.softAPIP().toString().c_str());
}
static void stopAP()
{
  WiFi.softAPdisconnect(true);
  delay(100);
}

void startServer()
{
  if (!server)
    server = new AsyncWebServer(80);

  server->on("/", HTTP_GET, [](AsyncWebServerRequest *r)
             {
   AsyncWebServerResponse* res =
     r->beginResponse(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
   res->addHeader("Cache-Control", "no-store");
   r->send(res); });
  server->on("/export", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", prefs.getString("maclist", "")); });
  server->on("/results", HTTP_GET, [](AsyncWebServerRequest *r)
             { r->send(200, "text/plain", lastResults.length() ? lastResults : String("None yet.")); });
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
  Serial.println(test_msg);
  r->send(200, "text/plain", "Test message sent to mesh"); });

  // Update the /blueteam endpoint in startServer() function:
server->on("/blueteam", HTTP_POST, [](AsyncWebServerRequest *req)
           {
  String detection = req->getParam("detection", true) ? req->getParam("detection", true)->value() : "deauth";
  int secs = req->getParam("secs", true) ? req->getParam("secs", true)->value().toInt() : 300;
  bool forever = req->hasParam("forever", true);
  bool alertBeep = req->hasParam("alertBeep", true);
  
  if (detection == "deauth") {
    if (secs < 0) secs = 0; 
    if (secs > 86400) secs = 86400;
    
    deauthDetectionEnabled = true;
    stopRequested = false;
    
    req->send(200, "text/plain", forever ? "Deauth detection starting (forever)" : ("Deauth detection starting for " + String(secs) + "s"));
    
    if (!blueTeamTaskHandle) {
      xTaskCreatePinnedToCore(blueTeamTask, "blueteam", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &blueTeamTaskHandle, 1);
    }
  } else if (detection == "beacon-flood") {
    if (secs < 0) secs = 0; 
    if (secs > 86400) secs = 86400;
    
    beaconFloodDetectionEnabled = true;
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

  server->on("/save", HTTP_POST, [](AsyncWebServerRequest *req)
             {
   if (!req->hasParam("list", true)) { req->send(400, "text/plain", "Missing 'list'"); return; }
   String txt = req->getParam("list", true)->value();
   saveTargetsToNVS(txt);
   req->send(200, "text/plain", "Saved"); });
  server->on("/scan", HTTP_POST, [](AsyncWebServerRequest *req)
             {
   int secs = 60; bool forever=false;
   ScanMode mode = SCAN_WIFI;
   
   if (req->hasParam("forever", true)) forever = true;
   if (req->hasParam("secs", true)) {
     int v = req->getParam("secs", true)->value().toInt();
     if (v < 0) v = 0; if (v > 86400) v = 86400; secs = v;
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
   if (!workerTaskHandle) xTaskCreatePinnedToCore(listScanTask, "scan", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1); });
  server->on("/beep", HTTP_GET, [](AsyncWebServerRequest *r)
             {
   beepPattern(cfgBeeps, cfgGapMs);
   r->send(200, "text/plain", "Beeped"); });
  // Tracker start
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
   if (!parseMac6(mac, tmp)){ req->send(400, "text/plain", "Invalid MAC"); return; }
   memcpy((void*)trackerMac, tmp, 6);
   parseChannelsCSV(ch);
   currentScanMode = mode;
   stopRequested = false;
   
   String modeStr = (mode == SCAN_WIFI) ? "WiFi" : (mode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
   req->send(200, "text/plain", forever ? ("Tracker starting (forever) - " + modeStr) : ("Tracker starting for " + String(secs) + "s - " + modeStr));
   if (!workerTaskHandle) xTaskCreatePinnedToCore(trackerTask, "tracker", 8192, (void*)(intptr_t)(forever ? 0 : secs), 1, &workerTaskHandle, 1); });
  // Stop
  server->on("/stop", HTTP_GET, [](AsyncWebServerRequest *r)
             {
   stopRequested = true;
   r->send(200, "text/plain", "Stopping… (AP will return shortly)"); });
  // Config endpoints
  server->on("/config", HTTP_GET, [](AsyncWebServerRequest *r)
             {
   String j = String("{\"beeps\":") + cfgBeeps + ",\"gap\":" + cfgGapMs + "}";
   r->send(200, "application/json", j); });
  server->on("/config", HTTP_POST, [](AsyncWebServerRequest *req)
             {
   int beeps = cfgBeeps, gap = cfgGapMs;
   if (req->hasParam("beeps", true)) beeps = req->getParam("beeps", true)->value().toInt();
   if (req->hasParam("gap", true)) gap = req->getParam("gap", true)->value().toInt();
   if (beeps < 1) beeps = 1; if (beeps > 10) beeps = 10;
   if (gap < 20) gap = 20; if (gap > 2000) gap = 2000;
   cfgBeeps = beeps; cfgGapMs = gap;
   prefs.putInt("beeps", cfgBeeps);
   prefs.putInt("gap", cfgGapMs);
   req->send(200, "text/plain", "Config saved"); });
  // Diagnostics endpoint
  server->on("/diag", HTTP_GET, [](AsyncWebServerRequest *r)
             {
  String s;
  String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
  s += "Scan Mode: " + modeStr + "\n";
  s += String("Scanning: ") + (scanning ? "yes" : "no") + "\n";
  s += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
  s += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
  s += "Total hits: " + String(totalHits) + "\n";
  s += "Unique devices: " + String((int)uniqueMacs.size()) + "\n";
  s += "Targets: " + String((int)targets.size()) + "\n";
  s += "Country: " + String(COUNTRY) + "\n";
  s += "Current channel: " + String(WiFi.channel()) + "\n";
  s += "AP IP: " + WiFi.softAPIP().toString() + "\n";
  
  // ESP32 temperature
  float temp_c = temperatureRead();
  float temp_f = (temp_c * 9.0/5.0) + 32.0;
  s += "ESP32 Temp: " + String(temp_c, 1) + "°C / " + String(temp_f, 1) + "°F\n";
  
  s += "Beeps/Hit: " + String(cfgBeeps) + "  Gap(ms): " + String(cfgGapMs) + "\n";
  s += "Last scan secs: " + String((unsigned)lastScanSecs) + (lastScanForever ? " (forever)" : "") + "\n";
  s += "WiFi Channels: "; 
  for (auto c: CHANNELS){ s += String((int)c) + " "; } 
  s += "\n";
  
  if (trackerMode){
    s += "Tracker: target=" + macFmt6(trackerMac) + " lastRSSI=" + String((int)trackerRssi) + "dBm  lastSeen(ms ago)=" + String((unsigned)(millis() - trackerLastSeen)) + " pkts=" + String((unsigned)trackerPackets) + "\n";
  }
  
  r->send(200, "text/plain", s); });

  server->begin();
  Serial.println("[WEB] Server started.");
}

// ---------- AP Management Helpers ----------
static void stopAPAndServer()
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

static void startAPAndServer()
{
  Serial.println("[SYS] Starting AP and web server...");
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  // Reset delay
  for (int i = 0; i < 10; i++)
  {
    delay(100);
    yield();
  }

  // Start AP
  WiFi.mode(WIFI_AP);
  delay(100);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  delay(100);

  // Try AP start multiple times if needed
  bool apStarted = false;
  for (int attempt = 0; attempt < 3 && !apStarted; attempt++)
  {
    Serial.printf("AP start attempt %d...\n", attempt + 1);
    apStarted = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
    if (!apStarted)
    {
      delay(500);
      WiFi.mode(WIFI_OFF);
      delay(500);
      WiFi.mode(WIFI_AP);
      delay(200);
    }
  }

  Serial.printf("AP restart %s\n", apStarted ? "SUCCESSFUL" : "FAILED");
  delay(200);
  WiFi.setHostname("Antihunter");
  startServer();
}
// ---------- Radio common ----------
static void radioStartWiFi()
{
  WiFi.mode(WIFI_MODE_STA);
  wifi_country_t ctry = {.schan = 1, .nchan = 13, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
  memcpy(ctry.cc, COUNTRY, 2);
  ctry.cc[2] = 0;
  esp_wifi_set_country(&ctry);
  esp_wifi_start();

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_promiscuous(true);

  if (CHANNELS.empty())
    CHANNELS = {1, 6, 11};
  esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
  const esp_timer_create_args_t targs = {.callback = &hopTimerCb, .arg = nullptr, .dispatch_method = ESP_TIMER_TASK, .name = "hop"};
  esp_timer_create(&targs, &hopTimer);
  esp_timer_start_periodic(hopTimer, 300000); // 300ms
}

static void radioStartBLE()
{
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyBLEAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true); // More power but faster results
  pBLEScan->setInterval(100);    // 100ms intervals
  pBLEScan->setWindow(99);       // 99ms windows (must be <= interval)
}

static void radioStopWiFi()
{
  esp_wifi_set_promiscuous(false);
  if (hopTimer)
  {
    esp_timer_stop(hopTimer);
    esp_timer_delete(hopTimer);
    hopTimer = nullptr;
  }
  esp_wifi_stop();
}

static void radioStopBLE()
{
  if (pBLEScan)
  {
    pBLEScan->stop();
    BLEDevice::deinit(false);
    pBLEScan = nullptr;
  }
}

static void radioStartSTA()
{
  // Enable coexistence for WiFi+BLE
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);

  if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH)
  {
    radioStartWiFi();
  }
  if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH)
  {
    radioStartBLE();
  }
}

static void radioStopSTA()
{
  radioStopWiFi();
  radioStopBLE();
}

// ---------- Deauth/disassoc Task ----------
void blueTeamTask(void *pv) {
  int secs = (int)(intptr_t)pv;
  bool forever = (secs <= 0);
  
  Serial.printf("[BLUE] Deauth detection %s...\n", 
    forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str());

  stopAPAndServer();

  stopRequested = false;
  if (!deauthQueue) {
    deauthQueue = xQueueCreate(256, sizeof(DeauthHit));
  }

  deauthLog.clear();
  deauthCount = 0;
  disassocCount = 0;
  framesSeen = 0;
  scanning = true;
  uint32_t scanStart = millis();

  // Start WiFi monitoring
  radioStartWiFi();
  Serial.println("[BLUE] WiFi monitoring started for deauth/disassoc detection");

  DeauthHit hit;
  uint32_t lastAlert = 0;
  uint32_t nextStatus = millis() + 1000;

  while ((forever && !stopRequested) || 
         (!forever && (int)(millis() - scanStart) < secs * 1000 && !stopRequested)) {
    
    if ((int32_t)(millis() - nextStatus) >= 0) {
      Serial.printf("[BLUE] Monitoring... deauth=%u disassoc=%u frames=%u\n",
                    (unsigned)deauthCount, (unsigned)disassocCount, (unsigned)framesSeen);
      nextStatus += 1000;
    }

    if (xQueueReceive(deauthQueue, &hit, pdMS_TO_TICKS(100)) == pdTRUE) {
      deauthLog.push_back(hit);
      
      Serial.printf("[ATTACK] %s %s->%s BSSID:%s RSSI:%ddBm CH:%u Reason:%u\n",
        hit.isDisassoc ? "DISASSOC" : "DEAUTH",
        macFmt6(hit.srcMac).c_str(), macFmt6(hit.destMac).c_str(), 
        macFmt6(hit.bssid).c_str(), hit.rssi, hit.channel, hit.reasonCode);
      
      if (millis() - lastAlert > 3000) {
        beepPattern(4, 80);
        lastAlert = millis();
      }
      
      if (deauthLog.size() > 500) {
        deauthLog.erase(deauthLog.begin(), deauthLog.begin() + 250);
      }
    }
  }

  // Cleanup
  radioStopWiFi();
  scanning = false;
  deauthDetectionEnabled = false;

  // Build results
  lastResults = String("Blue Team Detection — Duration: ") + (forever ? "∞" : String(secs)) + "s\n";
  lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
  lastResults += "Deauth frames detected: " + String((unsigned)deauthCount) + "\n";
  lastResults += "Disassoc frames detected: " + String((unsigned)disassocCount) + "\n\n";
  
  int show = min((int)deauthLog.size(), 100);
  for (int i = 0; i < show; i++) {
    const auto &e = deauthLog[i];
    lastResults += String(e.isDisassoc ? "DISASSOC" : "DEAUTH") + " ";
    lastResults += macFmt6(e.srcMac) + " -> " + macFmt6(e.destMac);
    lastResults += " BSSID:" + macFmt6(e.bssid);
    lastResults += " RSSI:" + String(e.rssi) + "dBm";
    lastResults += " CH:" + String(e.channel);
    lastResults += " Reason:" + String(e.reasonCode) + "\n";
  }
  if ((int)deauthLog.size() > show) {
    lastResults += "... (" + String((int)deauthLog.size() - show) + " more)\n";
  }

  Serial.println("[BLUE] Deauth detection stopped, restoring AP...");
  startAPAndServer();
  
  blueTeamTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

void beaconFloodTask(void *pv) {
  int secs = (int)(intptr_t)pv;
  bool forever = (secs <= 0);
  
  Serial.printf("[BLUE] Beacon flood detection %s...\n", 
    forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str());

  stopAPAndServer();

  stopRequested = false;
  if (!beaconQueue) {
    beaconQueue = xQueueCreate(256, sizeof(BeaconHit));
  }

  beaconLog.clear();
  beaconCounts.clear();
  beaconLastSeen.clear();
  beaconTimings.clear();
  totalBeaconsSeen = 0;
  suspiciousBeacons = 0;
  framesSeen = 0;
  scanning = true;
  uint32_t scanStart = millis();

  // Start WiFi monitoring
  radioStartWiFi();
  Serial.println("[BLUE] WiFi monitoring started for beacon flood detection");

  BeaconHit hit;
  uint32_t lastAlert = 0;
  uint32_t nextStatus = millis() + 1000;
  uint32_t lastCleanup = millis();

  while ((forever && !stopRequested) || 
         (!forever && (int)(millis() - scanStart) < secs * 1000 && !stopRequested)) {
    
    if ((int32_t)(millis() - nextStatus) >= 0) {
      Serial.printf("[BLUE] Monitoring... beacons=%u suspicious=%u sources=%u\n",
                    (unsigned)totalBeaconsSeen, (unsigned)suspiciousBeacons, 
                    (unsigned)beaconCounts.size());
      nextStatus += 1000;
    }

    // Cleanup old timing data every 30 seconds
    if (millis() - lastCleanup > 30000) {
      uint32_t now = millis();
      for (auto& pair : beaconTimings) {
        auto& timings = pair.second;
        timings.erase(
          std::remove_if(timings.begin(), timings.end(),
            [now](uint32_t t) { return now - t > BEACON_TIMING_WINDOW * 3; }),
          timings.end()
        );
      }
      lastCleanup = now;
    }

    if (xQueueReceive(beaconQueue, &hit, pdMS_TO_TICKS(100)) == pdTRUE) {
      beaconLog.push_back(hit);
      
      String macStr = macFmt6(hit.srcMac);
      uint32_t count = beaconCounts[macStr];
      
      Serial.printf("[FLOOD] BEACON %s SSID:'%s' Count:%u RSSI:%ddBm CH:%u Interval:%u\n",
        macStr.c_str(), hit.ssid.c_str(), count,
        hit.rssi, hit.channel, hit.beaconInterval);
      
      // Alert on first detection and every 5 seconds after
      if (millis() - lastAlert > 5000) {
        beepPattern(3, 100); // 3 quick beeps
        lastAlert = millis();
      }
      
      // Limit log size
      if (beaconLog.size() > 200) {
        beaconLog.erase(beaconLog.begin(), beaconLog.begin() + 100);
      }
    }
  }

  // Cleanup
  radioStopWiFi();
  scanning = false;
  beaconFloodDetectionEnabled = false;

  // Build results
  lastResults = String("Beacon Flood Detection — Duration: ") + (forever ? "∞" : String(secs)) + "s\n";
  lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
  lastResults += "Total beacons: " + String((unsigned)totalBeaconsSeen) + "\n";
  lastResults += "Suspicious beacons: " + String((unsigned)suspiciousBeacons) + "\n";
  lastResults += "Unique sources: " + String((unsigned)beaconCounts.size()) + "\n\n";
  
  // Show top beacon sources
  lastResults += "Top Beacon Sources:\n";
  std::vector<std::pair<String, uint32_t>> sortedCounts(beaconCounts.begin(), beaconCounts.end());
  std::sort(sortedCounts.begin(), sortedCounts.end(), 
    [](const auto& a, const auto& b) { return a.second > b.second; });
  
  int show = min((int)sortedCounts.size(), 10);
  for (int i = 0; i < show; i++) {
    lastResults += sortedCounts[i].first + ": " + String(sortedCounts[i].second) + " beacons\n";
  }
  lastResults += "\n";
  
  // Show recent suspicious beacons
  show = min((int)beaconLog.size(), 50);
  lastResults += "Recent Suspicious Beacons:\n";
  for (int i = max(0, (int)beaconLog.size() - show); i < beaconLog.size(); i++) {
    const auto &e = beaconLog[i];
    lastResults += macFmt6(e.srcMac) + " '" + e.ssid + "' ";
    lastResults += "RSSI:" + String(e.rssi) + "dBm ";
    lastResults += "CH:" + String(e.channel) + " ";
    lastResults += "Int:" + String(e.beaconInterval) + "\n";
  }

  Serial.println("[BLUE] Beacon flood detection stopped, restoring AP...");
  startAPAndServer();
  
  blueTeamTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

// ---------- List scan task ----------
void listScanTask(void *pv)
{
  int secs = (int)(intptr_t)pv;
  bool forever = (secs <= 0);
  String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE"
                                                                                           : "WiFi+BLE";
  Serial.printf("[SCAN] List scan %s (%s)...\n", forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str(), modeStr.c_str());

  // Stop AP & web
  stopAPAndServer();

  stopRequested = false;
  if (macQueue)
  {
    vQueueDelete(macQueue);
    macQueue = nullptr;
  }
  macQueue = xQueueCreate(512, sizeof(Hit));

  uniqueMacs.clear();
  hitsLog.clear();
  totalHits = 0;
  framesSeen = 0;
  bleFramesSeen = 0;
  scanning = true;
  lastScanStart = millis();
  lastScanSecs = secs;
  lastScanForever = forever;

  radioStartSTA();
  Serial.printf("[SCAN] Mode: %s\n", modeStr.c_str());
  if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH)
  {
    Serial.printf("[SCAN] WiFi channel hop list: ");
    for (auto c : CHANNELS)
      Serial.printf("%d ", c);
    Serial.println();
  }

  uint32_t nextStatus = millis() + 1000;
  uint32_t nextBLEScan = millis();
  Hit h;

  while ((forever && !stopRequested) || (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested))
  {
    if ((int32_t)(millis() - nextStatus) >= 0)
    {
      Serial.printf("Status: Tracking %d active devices... WiFi frames=%u BLE frames=%u\n",
                    (int)uniqueMacs.size(), (unsigned)framesSeen, (unsigned)bleFramesSeen);
      nextStatus += 1000;
    }

    // Handle BLE scanning
    if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan)
    {
      if ((int32_t)(millis() - nextBLEScan) >= 0)
      {
        pBLEScan->start(1, false);     // 1 second scan, non-blocking
        nextBLEScan = millis() + 1100; // Scan every 1.1 seconds
      }
    }

    if (xQueueReceive(macQueue, &h, pdMS_TO_TICKS(50)) == pdTRUE)
    {
      totalHits++;
      hitsLog.push_back(h);
      uniqueMacs.insert(macFmt6(h.mac));
      Serial.printf("[HIT] %s %s RSSI=%ddBm ch=%u name=%s\n",
                    h.isBLE ? "BLE" : "WiFi",
                    macFmt6(h.mac).c_str(), (int)h.rssi, (unsigned)h.ch, h.name.c_str());
      beepPattern(cfgBeeps, cfgGapMs);

      sendMeshNotification(h);
    }
  }

  radioStopSTA(); // This handles esp_wifi_stop()
  scanning = false;
  lastScanEnd = millis();

  // Build results (truncate if huge)
  lastResults = String("List scan – Mode: ") + modeStr + " Duration: " + (forever ? "∞" : String(secs)) + "s\n";
  lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
  lastResults += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
  lastResults += "Total hits: " + String(totalHits) + "\n";
  lastResults += "Unique devices: " + String((int)uniqueMacs.size()) + "\n\n";
  int show = hitsLog.size();
  if (show > 500)
    show = 500;
  for (int i = 0; i < show; i++)
  {
    const auto &e = hitsLog[i];
    lastResults += String(e.isBLE ? "BLE " : "WiFi") + " " + macFmt6(e.mac) + "  RSSI=" + String((int)e.rssi) + "dBm";
    if (!e.isBLE)
      lastResults += "  ch=" + String((int)e.ch);
    if (e.name.length() > 0 && e.name != "WiFi")
      lastResults += "  name=" + e.name;
    lastResults += "\n";
  }
  if ((int)hitsLog.size() > show)
    lastResults += "... (" + String((int)hitsLog.size() - show) + " more)\n";

  // Bring AP back with thorough reset
  radioStopSTA();
  scanning = false;
  lastScanEnd = millis();

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  for (int i = 0; i < 10; i++)
  {
    delay(100);
    yield();
  }

  // Start AP
  WiFi.mode(WIFI_AP);
  delay(100);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  delay(100);

  // Try AP start multiple times if needed
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
  startServer();

  workerTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

// ---------- Tracker task (single MAC Geiger) ----------
void trackerTask(void *pv)
{
  int secs = (int)(intptr_t)pv;
  bool forever = (secs <= 0);
  String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : (currentScanMode == SCAN_BLE) ? "BLE"
                                                                                           : "WiFi+BLE";
  Serial.printf("[TRACK] Tracker %s (%s)... target=%s\n",
                forever ? "(forever)" : String(String("for ") + secs + " s").c_str(),
                modeStr.c_str(), macFmt6(trackerMac).c_str());

  stopAPAndServer();

  trackerMode = true;
  trackerPackets = 0;
  trackerRssi = -90;
  trackerLastSeen = 0;
  framesSeen = 0;
  bleFramesSeen = 0;
  scanning = true;
  lastScanStart = millis();
  lastScanSecs = secs;
  lastScanForever = forever;
  stopRequested = false;

  radioStartSTA();
  Serial.printf("[TRACK] Mode: %s\n", modeStr.c_str());
  if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH)
  {
    Serial.printf("[TRACK] WiFi channel hop list: ");
    for (auto c : CHANNELS)
      Serial.printf("%d ", c);
    Serial.println();
  }

  uint32_t nextStatus = millis() + 1000;
  uint32_t nextBeep = millis() + 400;
  uint32_t nextBLEScan = millis();
  float ema = -90.0f;

  while ((forever && !stopRequested) || (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested))
  {
    if ((int32_t)(millis() - nextStatus) >= 0)
    {
      uint32_t ago = trackerLastSeen ? (millis() - trackerLastSeen) : 0;
      Serial.printf("Status: WiFi frames=%u BLE frames=%u target_rssi=%ddBm seen_ago=%ums packets=%u\n",
                    (unsigned)framesSeen, (unsigned)bleFramesSeen, (int)trackerRssi, (unsigned)ago, (unsigned)trackerPackets);
      nextStatus += 1000;
    }

    // Handle BLE scanning for tracker
    if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan)
    {
      if ((int32_t)(millis() - nextBLEScan) >= 0)
      {
        pBLEScan->start(1, false);     // 1 second scan, non-blocking
        nextBLEScan = millis() + 1100; // Scan every 1.1 seconds
      }
    }

    uint32_t now = millis();
    bool gotRecent = trackerLastSeen && (now - trackerLastSeen) < 2000; // 2s recent window

    // Update EMA (if recent sample, pull towards that RSSI; otherwise decay toward -90)
    if (gotRecent)
      ema = 0.75f * ema + 0.25f * (float)trackerRssi;
    else
      ema = 0.995f * ema - 0.05f; // slow fade to lower signal when idle

    int period = gotRecent ? periodFromRSSI((int8_t)ema) : 1400; // slower when not seen
    int freq = gotRecent ? freqFromRSSI((int8_t)ema) : 2200;
    int dur = gotRecent ? 60 : 40;

    if ((int32_t)(now - nextBeep) >= 0)
    {
      beepOnce((uint32_t)freq, (uint32_t)dur);
      nextBeep = now + period;
    }

    // Mesh update
    if (trackerMode)
    {
      sendTrackerMeshUpdate();
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }

  radioStopSTA(); // This handles esp_wifi_stop()
  scanning = false;
  trackerMode = false;
  lastScanEnd = millis();

  lastResults = String("Tracker – Mode: ") + modeStr + " Duration: " + (forever ? "∞" : String(secs)) + "s\n";
  lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
  lastResults += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
  lastResults += "Target: " + macFmt6(trackerMac) + "\n";
  lastResults += "Packets from target: " + String((unsigned)trackerPackets) + "\n";
  lastResults += "Last RSSI: " + String((int)trackerRssi) + "dBm\n";

  startAPAndServer();

  workerTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

// ---------- Mesh Notificaions ----------

// Mesh notification (adapted from DragonNet's print_compact_message)
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

// Send tracker status over mesh
void sendTrackerMeshUpdate()
{
  static unsigned long lastTrackerMesh = 0;
  const unsigned long trackerInterval = 15000; // 15 seconds

  if (millis() - lastTrackerMesh < trackerInterval)
    return;
  lastTrackerMesh = millis();

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
  Serial1.begin(115200, SERIAL_8N1, 4, 5); // Pins RX/TX 4/5
  Serial.println("Mesh communication initialized on Serial1");
}

// ---------- Setup / Loop ----------
void setup()
{
  delay(1000);
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== Antihunter v4 Boot ===");
  Serial.println("WiFi+BLE dual-mode scanner");
  delay(1000);

  Serial.println("Initializing mesh UART...");
  initializeMesh();
  Serial.println("Mesh UART ready");
  delay(1000);

  Serial.println("Loading preferences...");
  prefs.begin("ouispy", false);
  loadTargetsFromNVS();
  delay(1000);

  cfgBeeps = prefs.getInt("beeps", cfgBeeps);
  cfgGapMs = prefs.getInt("gap", cfgGapMs);
  Serial.printf("Loaded %d targets, beeps=%d, gap=%dms\n", targets.size(), cfgBeeps, cfgGapMs);
  delay(1000);

  Serial.println("Starting AP...");
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0);
  delay(100);
  WiFi.setHostname("Antihunter");
  delay(1000);
  Serial.println("Starting web server...");
  startServer();

  Serial.println("=== Boot Complete ===");
  Serial.printf("Web UI: http://192.168.4.1/ (SSID: %s, PASS: %s)\n", AP_SSID, AP_PASS);
  Serial.println("Mesh: Serial1 @ 115200 baud on pins 7,6");
}
void loop()
{
  delay(1000);
}