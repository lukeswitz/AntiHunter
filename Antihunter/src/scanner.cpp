#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include <algorithm> 
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>


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
QueueHandle_t deauthQueue = nullptr;
QueueHandle_t beaconQueue = nullptr;
QueueHandle_t evilAPQueue = nullptr;

// Blue Tools globals
std::vector<DeauthHit> deauthLog;
std::vector<BeaconHit> beaconLog;
std::vector<EvilAPHit> evilAPLog;
static std::map<String, uint32_t> beaconCounts;
static std::map<String, uint32_t> beaconLastSeen;
static std::map<String, std::vector<uint32_t>> beaconTimings;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;
volatile uint32_t totalBeaconsSeen = 0;
volatile uint32_t suspiciousBeacons = 0;
static bool deauthDetectionEnabled = false;
static bool beaconFloodDetectionEnabled = false;
static std::map<String, std::vector<String>> ssidToBssids;
static std::map<String, EvilAPHit> knownNetworks;
static std::map<String, uint32_t> probeResponses;
volatile uint32_t evilAPCount = 0;
static bool evilAPDetectionEnabled = false;


// Beacon flood thresholds
static const uint32_t BEACON_FLOOD_THRESHOLD = 50;
static const uint32_t BEACON_TIMING_WINDOW = 10000;
static const uint32_t MIN_BEACON_INTERVAL = 50;

// EvilAP Flags
const uint8_t EVIL_AP_FLAG_TWIN = 0x01;
const uint8_t EVIL_AP_FLAG_STRONG_SIGNAL = 0x02;
const uint8_t EVIL_AP_FLAG_KARMA = 0x04;
const uint8_t EVIL_AP_FLAG_OPEN_SPOOF = 0x08;
const uint8_t EVIL_AP_FLAG_TIMING = 0x10;

// Scan state
std::set<String> uniqueMacs;
std::vector<Hit> hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;

// BLE Scanner
BLEScan *pBLEScan = nullptr;

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
extern uint32_t lastScanSecs;
extern bool lastScanForever;

// Helpers
inline uint16_t u16(const uint8_t *p) { 
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8); 
}

inline int clampi(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int getUniqueNetworkCount() {
    return ssidToBssids.size();
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

// Detection Functions
static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;

    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 26) return;

    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (ftype == 0 && (subtype == 12 || subtype == 10)) {
        DeauthHit hit;
        memcpy(hit.destMac, p + 4, 6);
        memcpy(hit.srcMac, p + 10, 6);
        memcpy(hit.bssid, p + 16, 6);
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.isDisassoc = (subtype == 10);
        hit.reasonCode = (ppkt->rx_ctrl.sig_len >= 26) ? u16(p + 24) : 0;

        if (hit.isDisassoc) {
            disassocCount = disassocCount + 1;
        } else {
            deauthCount = deauthCount + 1;
        }

        BaseType_t w = false;
        if (deauthQueue) {
            xQueueSendFromISR(deauthQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
}

static void IRAM_ATTR detectEvilAP(const wifi_promiscuous_pkt_t *ppkt) {
    if (!evilAPDetectionEnabled) return;

    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 36) return;

    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (ftype == 0 && (subtype == 8 || subtype == 5)) {
        EvilAPHit hit;
        memcpy(hit.bssid, p + 16, 6);
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.isOpen = false;
        hit.beaconInterval = 0;
        hit.detectionFlags = 0;
        hit.ssid = "";
        
        if (subtype == 8 && ppkt->rx_ctrl.sig_len >= 38) {
            hit.beaconInterval = u16(p + 32);
            
            const uint8_t *tags = p + 36;
            uint32_t remaining = ppkt->rx_ctrl.sig_len - 36;
            uint32_t offset = 0;
            
            while (offset + 1 < remaining) {
                uint8_t tagType = tags[offset];
                uint8_t tagLen = tags[offset + 1];
                
                if (offset + 2 + tagLen > remaining) break;
                
                if (tagType == 0 && tagLen > 0 && tagLen <= 32) {
                    char ssid_str[33] = {0};
                    memcpy(ssid_str, tags + offset + 2, tagLen);
                    hit.ssid = String(ssid_str);
                } else if (tagType == 48) {
                    hit.isOpen = (tagLen == 0);
                }
                
                offset += 2 + tagLen;
            }
            
            if (hit.ssid.length() == 0) {
                hit.isOpen = true;
            }
        }
        
        String bssidStr = macFmt6(hit.bssid);
        String ssidKey = hit.ssid;
        
        if (hit.rssi > -40) {
            hit.detectionFlags |= EVIL_AP_FLAG_STRONG_SIGNAL;
        }
        
        if (hit.beaconInterval > 0 && hit.beaconInterval < 50) {
            hit.detectionFlags |= EVIL_AP_FLAG_TIMING;
        }
        
        if (ssidKey.length() > 0) {
            if (ssidToBssids[ssidKey].size() == 0) {
                ssidToBssids[ssidKey].push_back(bssidStr);
                knownNetworks[bssidStr] = hit;
            } else {
                bool foundBssid = false;
                for (const String& existingBssid : ssidToBssids[ssidKey]) {
                    if (existingBssid == bssidStr) {
                        foundBssid = true;
                        break;
                    }
                }
                
                if (!foundBssid) {
                    ssidToBssids[ssidKey].push_back(bssidStr);
                    hit.detectionFlags |= EVIL_AP_FLAG_TWIN;
                    
                    if (knownNetworks.find(ssidToBssids[ssidKey][0]) != knownNetworks.end() && 
                        !knownNetworks[ssidToBssids[ssidKey][0]].isOpen && hit.isOpen) {
                        hit.detectionFlags |= EVIL_AP_FLAG_OPEN_SPOOF;
                    }
                }
            }
        }
        
        if (subtype == 5) {
            probeResponses[bssidStr]++;
            if (probeResponses[bssidStr] > 10) {
                hit.detectionFlags |= EVIL_AP_FLAG_KARMA;
            }
        }
        
        if (hit.detectionFlags > 0) {
            evilAPCount = evilAPCount + 1;
            BaseType_t w = false;
            if (evilAPQueue) {
                xQueueSendFromISR(evilAPQueue, &hit, &w);
                if (w) portYIELD_FROM_ISR();
            }
        }
    }
}

static void IRAM_ATTR detectBeaconFlood(const wifi_promiscuous_pkt_t *ppkt) {
    if (!beaconFloodDetectionEnabled) return;

    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 36) return;

    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (ftype == 0 && subtype == 8) {
        BeaconHit hit;
        memcpy(hit.srcMac, p + 10, 6);
        memcpy(hit.bssid, p + 16, 6);
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.beaconInterval = 0;
        hit.ssid = "";
        
        if (ppkt->rx_ctrl.sig_len >= 38) {
            hit.beaconInterval = u16(p + 32);
            
            const uint8_t *tags = p + 36;
            uint32_t remaining = ppkt->rx_ctrl.sig_len - 36;
            
            if (remaining >= 2 && tags[0] == 0) {
                uint8_t ssid_len = tags[1];
                if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
                    char ssid_str[33] = {0};
                    memcpy(ssid_str, tags + 2, ssid_len);
                    hit.ssid = String(ssid_str);
                }
            }
        }
        
        totalBeaconsSeen = totalBeaconsSeen + 1;
        
        String macStr = macFmt6(hit.srcMac);
        uint32_t now = millis();
        
        beaconCounts[macStr]++;
        beaconLastSeen[macStr] = now;
        
        if (beaconTimings[macStr].size() > 20) {
            beaconTimings[macStr].erase(beaconTimings[macStr].begin());
        }
        beaconTimings[macStr].push_back(now);
        
        bool suspicious = false;
        
        if (beaconTimings[macStr].size() >= 2) {
            uint32_t interval = now - beaconTimings[macStr][beaconTimings[macStr].size()-2];
            if (interval < MIN_BEACON_INTERVAL) {
                suspicious = true;
            }
        }
        
        uint32_t recentCount = 0;
        for (auto& timing : beaconTimings[macStr]) {
            if (now - timing <= BEACON_TIMING_WINDOW) {
                recentCount++;
            }
        }
        
        if (recentCount > BEACON_FLOOD_THRESHOLD) {
            suspicious = true;
        }
        
        if (hit.beaconInterval > 0 && hit.beaconInterval < 50) {
            suspicious = true;
        }
        
        if (suspicious) {
            suspiciousBeacons = suspiciousBeacons + 1;
            BaseType_t w = false;
            if (beaconQueue) {
                xQueueSendFromISR(beaconQueue, &hit, &w);
                if (w) portYIELD_FROM_ISR();
            }
        }
    }
}

// BLE Callback Class
class MyBLEAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        uint8_t mac[6];
        String macStr = advertisedDevice.getAddress().toString();
        if (!parseMac6(macStr, mac)) return;

        if (trackerMode) {
            if (isTrackerTarget(mac)) {
                trackerRssi = advertisedDevice.getRSSI();
                trackerLastSeen = millis();
                trackerPackets = trackerPackets + 1;
            }
        } else {
            if (matchesMac(mac)) {
                Hit h;
                memcpy(h.mac, mac, 6);
                h.rssi = advertisedDevice.getRSSI();
                h.ch = 0;
                h.name = advertisedDevice.getName().length() > 0 ? 
                         advertisedDevice.getName() : String("Unknown");
                h.isBLE = true;

                BaseType_t w = false;
                if (macQueue) { 
                    xQueueSendFromISR(macQueue, &h, &w);
                    if (w) portYIELD_FROM_ISR();
                }
            }
        }
    }
};


// Main WiFi Sniffer Callback
static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    
    detectDeauthFrame(ppkt);
    detectBeaconFlood(ppkt);
    detectEvilAP(ppkt);
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
            h.name = String("WiFi");
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
            h.name = String("WiFi");
            h.isBLE = false;
            
            BaseType_t w = false;
            if (macQueue) { 
                xQueueSendFromISR(macQueue, &h, &w);
                if (w) portYIELD_FROM_ISR();
            }
        }
    }
}

// Radio Control Functions
static void radioStartWiFi() {
    WiFi.mode(WIFI_MODE_STA);
    wifi_country_t ctry = {.schan = 1, .nchan = 13, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);  // Use COUNTRY instead of hardcoded "NO" - TODO
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    esp_wifi_start();

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    
    const esp_timer_create_args_t targs = {
        .callback = &hopTimerCb, 
        .arg = nullptr, 
        .dispatch_method = ESP_TIMER_TASK, 
        .name = "hop"
    };
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, 300000);
}

static void radioStartBLE() {
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyBLEAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
}

static void radioStopWiFi() {
    esp_wifi_set_promiscuous(false);
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    esp_wifi_stop();
}

static void radioStopBLE() {
    if (pBLEScan) {
        pBLEScan->stop();
        BLEDevice::deinit(false);
        pBLEScan = nullptr;
    }
}

static void radioStartSTA() {
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartWiFi();
    }
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
    }
}

static void radioStopSTA() {
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

    stopAPAndServer();

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
            if ((int32_t)(millis() - nextBLEScan) >= 0) {
                pBLEScan->start(1, false);
                nextBLEScan = millis() + 1100;
            }
        }

        if (xQueueReceive(macQueue, &h, pdMS_TO_TICKS(50)) == pdTRUE)
        {
            totalHits = totalHits + 1;
            hitsLog.push_back(h);
            uniqueMacs.insert(macFmt6(h.mac));

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macFmt6(h.mac) +
                              " RSSI=" + String(h.rssi) + "dBm";
            if (gpsValid) {
                logEntry += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }

            Serial.printf("[HIT] %s ch=%u name=%s\n", logEntry.c_str(),
                          (unsigned)h.ch, h.name.c_str());
            logToSD(logEntry);

            beepPattern(getBeepsPerHit(), getGapMs());
        }
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
        if (!e.isBLE) lastResults += "  ch=" + String((int)e.ch);
        if (e.name.length() > 0 && e.name != "WiFi") lastResults += "  name=" + e.name;
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

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            if ((int32_t)(millis() - nextBLEScan) >= 0) {
                pBLEScan->start(1, false);
                nextBLEScan = millis() + 1100;
            }
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

void deauthDetectionTask(void *pv) {
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
    deauthDetectionEnabled = true;
    uint32_t scanStart = millis();

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

    radioStopWiFi();
    scanning = false;
    deauthDetectionEnabled = false;

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
    
    extern TaskHandle_t blueTeamTaskHandle;
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
    beaconFloodDetectionEnabled = true;
    uint32_t scanStart = millis();

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
            
            if (millis() - lastAlert > 5000) {
                beepPattern(3, 100);
                lastAlert = millis();
            }
            
            if (beaconLog.size() > 200) {
                beaconLog.erase(beaconLog.begin(), beaconLog.begin() + 100);
            }
        }
    }

    radioStopWiFi();
    scanning = false;
    beaconFloodDetectionEnabled = false;

    lastResults = String("Beacon Flood Detection — Duration: ") + (forever ? "∞" : String(secs)) + "s\n";
    lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    lastResults += "Total beacons: " + String((unsigned)totalBeaconsSeen) + "\n";
    lastResults += "Suspicious beacons: " + String((unsigned)suspiciousBeacons) + "\n";
    lastResults += "Unique sources: " + String((unsigned)beaconCounts.size()) + "\n\n";
    
    lastResults += "Top Beacon Sources:\n";
    std::vector<std::pair<String, uint32_t>> sortedCounts(beaconCounts.begin(), beaconCounts.end());
    std::sort(sortedCounts.begin(), sortedCounts.end(), 
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    int show = min((int)sortedCounts.size(), 10);
    for (int i = 0; i < show; i++) {
        lastResults += sortedCounts[i].first + ": " + String(sortedCounts[i].second) + " beacons\n";
    }
    lastResults += "\n";
    
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
    
    extern TaskHandle_t blueTeamTaskHandle;
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void evilAPDetectionTask(void *pv) {
    int secs = (int)(intptr_t)pv;
    bool forever = (secs <= 0);
    
    Serial.printf("[BLUE] Evil AP detection %s...\n", 
                  forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str());

    stopAPAndServer();

    stopRequested = false;
    if (!evilAPQueue) {
        evilAPQueue = xQueueCreate(256, sizeof(EvilAPHit));
    }

    evilAPLog.clear();
    ssidToBssids.clear();
    knownNetworks.clear();
    probeResponses.clear();
    evilAPCount = 0;
    framesSeen = 0;
    scanning = true;
    evilAPDetectionEnabled = true;
    uint32_t scanStart = millis();

    radioStartWiFi();
    Serial.println("[BLUE] WiFi monitoring started for Evil AP detection");

    EvilAPHit hit;
    uint32_t lastAlert = 0;
    uint32_t nextStatus = millis() + 1000;
    uint32_t lastCleanup = millis();

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < secs * 1000 && !stopRequested)) {
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLUE] Monitoring... evil_aps=%u networks=%u frames=%u\n",
                          (unsigned)evilAPCount, (unsigned)ssidToBssids.size(), (unsigned)framesSeen);
            nextStatus += 1000;
        }

        if (millis() - lastCleanup > 60000) {
            uint32_t now = millis();
            for (auto it = knownNetworks.begin(); it != knownNetworks.end();) {
                if (now - it->second.timestamp > 300000) {
                    it = knownNetworks.erase(it);
                } else {
                    ++it;
                }
            }
            lastCleanup = now;
        }

        if (xQueueReceive(evilAPQueue, &hit, pdMS_TO_TICKS(100)) == pdTRUE) {
            evilAPLog.push_back(hit);
            
            String flags = "";
            if (hit.detectionFlags & EVIL_AP_FLAG_TWIN) flags += "TWIN ";
            if (hit.detectionFlags & EVIL_AP_FLAG_STRONG_SIGNAL) flags += "STRONG ";
            if (hit.detectionFlags & EVIL_AP_FLAG_KARMA) flags += "KARMA ";
            if (hit.detectionFlags & EVIL_AP_FLAG_OPEN_SPOOF) flags += "OPEN_SPOOF ";
            if (hit.detectionFlags & EVIL_AP_FLAG_TIMING) flags += "TIMING ";
            
            Serial.printf("[EVIL_AP] %s '%s' RSSI:%ddBm CH:%u FLAGS:%s\n",
                          macFmt6(hit.bssid).c_str(), hit.ssid.c_str(),
                          hit.rssi, hit.channel, flags.c_str());
            
            if (millis() - lastAlert > 4000) {
                beepPattern(5, 60);
                lastAlert = millis();
            }
            
            if (evilAPLog.size() > 300) {
                evilAPLog.erase(evilAPLog.begin(), evilAPLog.begin() + 150);
            }
        }
    }

    radioStopWiFi();
    scanning = false;
    evilAPDetectionEnabled = false;

    lastResults = String("Evil AP Detection — Duration: ") + (forever ? "∞" : String(secs)) + "s\n";
    lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    lastResults += "Evil APs detected: " + String((unsigned)evilAPCount) + "\n";
    lastResults += "Unique networks: " + String((unsigned)ssidToBssids.size()) + "\n\n";
    
    lastResults += "Network Analysis:\n";
    for (const auto& pair : ssidToBssids) {
        if (pair.second.size() > 1) {
            lastResults += "SSID '" + pair.first + "': " + String(pair.second.size()) + " BSSIDs\n";
        }
    }
    lastResults += "\n";
    
    int show = min((int)evilAPLog.size(), 50);
    lastResults += "Recent Evil APs:\n";
    for (int i = max(0, (int)evilAPLog.size() - show); i < evilAPLog.size(); i++) {
        const auto &e = evilAPLog[i];
        lastResults += macFmt6(e.bssid) + " '" + e.ssid + "' ";
        lastResults += "RSSI:" + String(e.rssi) + "dBm ";
        lastResults += "CH:" + String(e.channel) + " ";
        if (e.detectionFlags & EVIL_AP_FLAG_TWIN) lastResults += "[TWIN] ";
        if (e.detectionFlags & EVIL_AP_FLAG_STRONG_SIGNAL) lastResults += "[STRONG] ";
        if (e.detectionFlags & EVIL_AP_FLAG_KARMA) lastResults += "[KARMA] ";
        if (e.detectionFlags & EVIL_AP_FLAG_OPEN_SPOOF) lastResults += "[OPEN_SPOOF] ";
        if (e.detectionFlags & EVIL_AP_FLAG_TIMING) lastResults += "[TIMING] ";
        lastResults += "\n";
    }

    Serial.println("[BLUE] Evil AP detection stopped, restoring AP...");
    startAPAndServer();
    
    extern TaskHandle_t blueTeamTaskHandle;
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}
