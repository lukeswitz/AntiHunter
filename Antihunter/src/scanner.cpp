#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include <algorithm> 
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
}

// Target management
struct Target {
    uint8_t bytes[6];
    uint8_t len;
};
static std::vector<Target> targets;

// Tasks
QueueHandle_t macQueue = nullptr;
extern uint32_t lastScanSecs;
extern bool lastScanForever;

// Scan state
std::set<String> uniqueMacs;
std::vector<Hit> hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;

// NimBLE Scanner
NimBLEScan* pBLEScan;

// Tracker state
volatile bool trackerMode = false;
uint8_t trackerMac[6] = {0};
volatile int8_t trackerRssi = -127;
volatile uint32_t trackerLastSeen = 0;
volatile uint32_t trackerPackets = 0;

// Status variables
volatile bool scanning = false;
volatile int totalHits = 0;
volatile uint32_t framesSeen = 0;
volatile uint32_t bleFramesSeen = 0;

// External references
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern String lastResults;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern bool isZeroOrBroadcast(const uint8_t *mac);

// Helpers
inline uint16_t u16(const uint8_t *p) { 
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8); 
}

inline int clampi(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static bool parseMacLike(const String &ln, Target &out) {
    String t;
    for (size_t i = 0; i < ln.length(); ++i) {
        char c = ln[i];
        if (isxdigit((int)c)) t += (char)toupper(c);
    }
    if (t.length() == 12) {
        for (int i = 0; i < 6; i++) {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6) {
        for (int i = 0; i < 3; i++) {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 3;
        return true;
    }
    return false;
}

size_t getTargetCount() {
    return targets.size();
}

String getTargetsList() {
    String out;
    for (auto &t : targets) {
        if (t.len == 6) {
            char b[18];
            snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", 
                     t.bytes[0], t.bytes[1], t.bytes[2], t.bytes[3], t.bytes[4], t.bytes[5]);
            out += b;
        } else {
            char b[9];
            snprintf(b, sizeof(b), "%02X:%02X:%02X", t.bytes[0], t.bytes[1], t.bytes[2]);
            out += b;
        }
        out += "\n";
    }
    return out;
}

void saveTargetsList(const String &txt) {
    prefs.putString("maclist", txt);
    targets.clear();
    int start = 0;
    while (start < txt.length()) {
        int nl = txt.indexOf('\n', start);
        if (nl < 0) nl = txt.length();
        String line = txt.substring(start, nl);
        line.trim();
        if (line.length()) {
            Target t;
            if (parseMacLike(line, t)) {
                targets.push_back(t);
            }
        }
        start = nl + 1;
    }
}

void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets) {
    memcpy(mac, trackerMac, 6);
    rssi = trackerRssi;
    lastSeen = trackerLastSeen;
    packets = trackerPackets;
}

void setTrackerMac(const uint8_t mac[6]) {
    memcpy(trackerMac, mac, 6);
}

static inline bool matchesMac(const uint8_t *mac) {
    for (auto &t : targets) {
        if (t.len == 6) {
            bool eq = true;
            for (int i = 0; i < 6; i++) {
                if (mac[i] != t.bytes[i]) {
                    eq = false;
                    break;
                }
            }
            if (eq) return true;
        } else {
            if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2]) {
                return true;
            }
        }
    }
    return false;
}

static inline bool isTrackerTarget(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != trackerMac[i]) return false;
    }
    return true;
}

static void hopTimerCb(void *) {
    static size_t idx = 0;
    if (CHANNELS.empty()) return;
    idx = (idx + 1) % CHANNELS.size();
    esp_wifi_set_channel(CHANNELS[idx], WIFI_SECOND_CHAN_NONE);
}

// RSSI mapping functions
static int periodFromRSSI(int8_t rssi) {
    const int rMin = -90, rMax = -30, pMin = 120, pMax = 1000;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int period = (int)(pMax - a * (pMax - pMin));
    return period;
}

static int freqFromRSSI(int8_t rssi) {
    const int rMin = -90, rMax = -30, fMin = 2000, fMax = 4500;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int f = (int)(fMin + a * (fMax - fMin));
    return f;
}

// BLE Callback
class MyBLEAdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;

        String deviceName = "";
        
        // FIX: Don't use c_str() for conversion - it stops at null bytes!
        if (advertisedDevice->haveName()) {
            std::string nimbleName = advertisedDevice->getName();
            if (nimbleName.length() > 0) {
                // PROPER conversion that handles binary data:
                deviceName = "";
                for (size_t i = 0; i < nimbleName.length(); i++) {
                    uint8_t c = (uint8_t)nimbleName[i];
                    // Only add printable ASCII characters
                    if (c >= 32 && c <= 126) {
                        deviceName += (char)c;
                    }
                }
            }
        }
        
        // If we got an empty or invalid name, use a default
        if (deviceName.length() == 0) {
            deviceName = "Unknown";
        }

        // Rest of your code...
        if (trackerMode) {
            if (isTrackerTarget(mac)) {
                trackerRssi = advertisedDevice->getRSSI();
                trackerLastSeen = millis();
                trackerPackets = trackerPackets + 1;
            }
        } else {
            if (matchesMac(mac)) {
                Hit h;
                memcpy(h.mac, mac, 6);
                h.rssi = advertisedDevice->getRSSI();
                h.ch = 0;
                strncpy(h.name, deviceName.c_str(), sizeof(h.name) - 1);
                h.name[sizeof(h.name) - 1] = '\0';
                h.isBLE = true;

                if (macQueue) { 
                    xQueueSend(macQueue, &h, 0);
                }
            }
        }
    }
};

// Main WiFi Sniffer Callback
static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    framesSeen = framesSeen + 1;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 24) return;

    const uint8_t *p = ppkt->payload;
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t tods = (fc >> 8) & 0x1;
    uint8_t fromds = (fc >> 9) & 0x1;

    const uint8_t *a1 = p + 4, *a2 = p + 10, *a3 = p + 16, *a4 = p + 24;
    uint8_t cand1[6], cand2[6];
    bool c1 = false, c2 = false;

    if (ftype == 0) {
        if (!isZeroOrBroadcast(a2)) {
            memcpy(cand1, a2, 6);
            c1 = true;
        }
        if (!isZeroOrBroadcast(a3)) {
            memcpy(cand2, a3, 6);
            c2 = true;
        }
    } else if (ftype == 2) {
        if (!tods && !fromds) {
            if (!isZeroOrBroadcast(a2)) {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a3)) {
                memcpy(cand2, a3, 6);
                c2 = true;
            }
        } else if (tods && !fromds) {
            if (!isZeroOrBroadcast(a2)) {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a1)) {
                memcpy(cand2, a1, 6);
                c2 = true;
            }
        } else if (!tods && fromds) {
            if (!isZeroOrBroadcast(a3)) {
                memcpy(cand1, a3, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a2)) {
                memcpy(cand2, a2, 6);
                c2 = true;
            }
        } else {
            if (!isZeroOrBroadcast(a2)) {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a3)) {
                memcpy(cand2, a3, 6);
                c2 = true;
            }
        }
    } else {
        return;
    }

    if (trackerMode && currentScanMode != SCAN_BLE) {
        if (c1 && isTrackerTarget(cand1)) {
            trackerRssi = ppkt->rx_ctrl.rssi;
            trackerLastSeen = millis();
            trackerPackets = trackerPackets + 1;
        }
        if (c2 && isTrackerTarget(cand2)) {
            trackerRssi = ppkt->rx_ctrl.rssi;
            trackerLastSeen = millis();
            trackerPackets = trackerPackets + 1;
        }
    } else if (!trackerMode) {
        if (c1 && matchesMac(cand1)) {
            Hit h;
            memcpy(h.mac, cand1, 6);
            h.rssi = ppkt->rx_ctrl.rssi;
            h.ch = ppkt->rx_ctrl.channel;
            strncpy(h.name, "WiFi", sizeof(h.name) - 1);
            h.name[sizeof(h.name) - 1] = '\0';
            h.isBLE = false;
            
            BaseType_t w = false;
            if (macQueue) { 
                xQueueSendFromISR(macQueue, &h, &w);
                if (w) portYIELD_FROM_ISR();
            }
        }
        if (c2 && matchesMac(cand2)) {
            Hit h;
            memcpy(h.mac, cand2, 6);
            h.rssi = ppkt->rx_ctrl.rssi;
            h.ch = ppkt->rx_ctrl.channel;
            strncpy(h.name, "WiFi", sizeof(h.name) - 1);
            h.name[sizeof(h.name) - 1] = '\0';
            h.isBLE = false;
            
            BaseType_t w = false;
            if (macQueue) { 
                xQueueSendFromISR(macQueue, &h, &w);
                if (w) portYIELD_FROM_ISR();
            }
        }
    }
}
 
// ---------- Radio common ----------
static void radioStartWiFi()
{
  WiFi.mode(WIFI_MODE_STA);
  wifi_country_t ctry = {.schan = 1, .nchan = 11, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
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
  if (hopTimer)
  {
      esp_timer_stop(hopTimer); // Clear old timer
      esp_timer_delete(hopTimer);
      hopTimer = nullptr;
  }
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

void initializeScanner() {
    Serial.println("Loading targets...");
    String txt = prefs.getString("maclist", "");
    saveTargetsList(txt);
    Serial.printf("Loaded %d targets\n", targets.size());
}

// Task Functions
void listScanTask(void *pv) {
    int secs = (int)(intptr_t)pv;
    bool forever = (secs <= 0);
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
    
    Serial.printf("[SCAN] List scan %s (%s)...\n", 
                  forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str(), 
                  modeStr.c_str());

    // Only stop AP if we're doing WiFi scanning
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        stopAPAndServer();
    }

    stopRequested = false;
    if (macQueue) {
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
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        Serial.printf("[SCAN] WiFi channel hop list: ");
        for (auto c : CHANNELS) Serial.printf("%d ", c);
        Serial.println();
    }

    uint32_t nextStatus = millis() + 1000;
    uint32_t nextBLEScan = millis();
    Hit h;

    while ((forever && !stopRequested) || 
       (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {
    
    if ((int32_t)(millis() - nextStatus) >= 0) {
        Serial.printf("Status: Tracking %d devices... WiFi frames=%u BLE frames=%u\n",
                      (int)uniqueMacs.size(), (unsigned)framesSeen, (unsigned)bleFramesSeen);
        nextStatus += 1000;
    }

    if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
        // Scan for longer duration to catch scan responses
        pBLEScan->start(3, false);  // 3 seconds, don't restart
        pBLEScan->clearResults();
    }

    if (xQueueReceive(macQueue, &h, pdMS_TO_TICKS(50)) == pdTRUE) {
        totalHits = totalHits + 1;
        hitsLog.push_back(h);
        uniqueMacs.insert(macFmt6(h.mac));

        String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macFmt6(h.mac) +
                          " RSSI=" + String(h.rssi) + "dBm";
        if (gpsValid) {
            logEntry += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
        }

        String safeName = h.name;
        for (size_t i = 0; i < safeName.length(); i++) {
            if (safeName[i] < 32 || safeName[i] > 126) {
                safeName[i] = '?';
            }
        }

        Serial.printf("[HIT] %s ch=%u name=%s\n", logEntry.c_str(),
                    (unsigned)h.ch, safeName.c_str());
                    
        logToSD(logEntry);

        beepPattern(getBeepsPerHit(), getGapMs());
        sendMeshNotification(h);
    }
    
    delay(100);
}

    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    // Build results
    lastResults = String("List scan — Mode: ") + modeStr + " Duration: " + (forever ? "∞" : String(secs)) + "s\n";
    lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    lastResults += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
    lastResults += "Total hits: " + String(totalHits) + "\n";
    lastResults += "Unique devices: " + String((int)uniqueMacs.size()) + "\n\n";
    
    int show = hitsLog.size();
    if (show > 500) show = 500;
    for (int i = 0; i < show; i++) {
        const auto &e = hitsLog[i];
        lastResults += String(e.isBLE ? "BLE " : "WiFi") + " " + macFmt6(e.mac) + "  RSSI=" + String((int)e.rssi) + "dBm";
        if (!e.isBLE)
            lastResults += "  ch=" + String((int)e.ch);
        if (strlen(e.name) > 0 && strcmp(e.name, "WiFi") != 0)
        {
            lastResults += "  name=";
            lastResults += e.name;
        }
        lastResults += "\n";
    }
    if ((int)hitsLog.size() > show) {
        lastResults += "... (" + String((int)hitsLog.size() - show) + " more)\n";
    }

    startAPAndServer();
    extern TaskHandle_t workerTaskHandle;
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void trackerTask(void *pv) {
    int secs = (int)(intptr_t)pv;
    bool forever = (secs <= 0);
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
    
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
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        Serial.printf("[TRACK] WiFi channel hop list: ");
        for (auto c : CHANNELS) Serial.printf("%d ", c);
        Serial.println();
    }

    uint32_t nextStatus = millis() + 1000;
    uint32_t nextBeep = millis() + 400;
    uint32_t nextBLEScan = millis();
    float ema = -90.0f;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            uint32_t ago = trackerLastSeen ? (millis() - trackerLastSeen) : 0;
            Serial.printf("Status: WiFi frames=%u BLE frames=%u target_rssi=%ddBm seen_ago=%ums packets=%u\n",
                          (unsigned)framesSeen, (unsigned)bleFramesSeen, (int)trackerRssi, (unsigned)ago, (unsigned)trackerPackets);
            nextStatus += 1000;
        }


        uint32_t now = millis();
        bool gotRecent = trackerLastSeen && (now - trackerLastSeen) < 2000;

        if (gotRecent) {
            ema = 0.75f * ema + 0.25f * (float)trackerRssi;
        } else {
            ema = 0.995f * ema - 0.05f;
        }

        int period = gotRecent ? periodFromRSSI((int8_t)ema) : 1400;
        int freq = gotRecent ? freqFromRSSI((int8_t)ema) : 2200;
        int dur = gotRecent ? 60 : 40;

        if ((int32_t)(now - nextBeep) >= 0) {
            beepOnce((uint32_t)freq, (uint32_t)dur);
            nextBeep = now + period;
        }

        if (trackerMode) {
            sendTrackerMeshUpdate();
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    radioStopSTA();
    scanning = false;
    trackerMode = false;
    lastScanEnd = millis();

    lastResults = String("Tracker — Mode: ") + modeStr + " Duration: " + (forever ? "∞" : String(secs)) + "s\n";
    lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    lastResults += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
    lastResults += "Target: " + macFmt6(trackerMac) + "\n";
    lastResults += "Packets from target: " + String((unsigned)trackerPackets) + "\n";
    lastResults += "Last RSSI: " + String((int)trackerRssi) + "dBm\n";

    startAPAndServer();
    extern TaskHandle_t workerTaskHandle;
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}
