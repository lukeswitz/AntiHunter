#include <algorithm>
#include <string>
#include <mutex>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "main.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
}

// ================================
// GLOBAL VARIABLE DEFINITIONS
// ================================

// Struct definition for Target
struct Target {
    uint8_t bytes[6];
    uint8_t len;
};

// AP handlers
static void radioStartSTA();
static void radioStopSTA();

// Scanner state variables

static std::vector<Target> targets;
QueueHandle_t macQueue = nullptr;
std::set<String> uniqueMacs;
std::set<String> seenDevices;
std::map<String, uint32_t> deviceLastSeen;
const uint32_t DEDUPE_WINDOW = 30000;
std::vector<Hit> hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;
static std::map<String, String> apCache;
static std::map<String, String> bleDeviceCache;
static unsigned long lastSnifferScan = 0;
const unsigned long SNIFFER_SCAN_INTERVAL = 10000;

NimBLEScan *pBLEScan;
static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);

// Tracker variables
volatile bool trackerMode = false;
uint8_t trackerMac[6] = {0};
volatile int8_t trackerRssi = -127;
volatile uint32_t trackerLastSeen = 0;
volatile uint32_t trackerPackets = 0;

// Scanner status variables
volatile bool scanning = false;
volatile int totalHits = 0;
volatile uint32_t framesSeen = 0;
volatile uint32_t bleFramesSeen = 0;

// Detection system variables
std::vector<DeauthHit> deauthLog;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;
bool deauthDetectionEnabled = false;
QueueHandle_t deauthQueue = nullptr;
volatile uint32_t req_frames = 0;
volatile uint32_t resp_frames = 0; 
volatile uint32_t beacon_frames = 0;
volatile uint32_t deauth_frames = 0;
volatile uint32_t num_eapol = 0;
std::vector<PwnagotchiHit> pwnagotchiLog;
std::vector<PineappleHit> pineappleLog;
std::vector<MultiSSIDTracker> multissidTrackers;
std::vector<ConfirmedMultiSSID> confirmedMultiSSID;
volatile uint32_t pwnagotchiCount = 0;
volatile uint32_t pineappleCount = 0;
volatile uint32_t multissidCount = 0;
bool pineappleDetectionEnabled = false;
bool espressifDetectionEnabled = false;
bool multissidDetectionEnabled = false;
bool pwnagotchiDetectionEnabled = false;

std::vector<BeaconHit> beaconLog;
std::map<String, uint32_t> beaconCounts;
std::map<String, uint32_t> beaconLastSeen;
std::map<String, std::vector<uint32_t>> beaconTimings;
volatile uint32_t totalBeaconsSeen = 0;
volatile uint32_t suspiciousBeacons = 0;
bool beaconFloodDetectionEnabled = false;
QueueHandle_t beaconQueue = nullptr;

// BLE Attack Detection
std::map<String, std::vector<uint32_t>> bleAdvTimings;
QueueHandle_t bleSpamQueue = nullptr;
std::vector<BLESpamHit> bleSpamLog;
volatile uint32_t bleSpamCount = 0;
std::map<String, uint32_t> bleAdvCounts;
volatile uint32_t bleAnomalyCount = 0;
bool bleSpamDetectionEnabled = false;
QueueHandle_t bleAnomalyQueue = nullptr;

// Deauth Detection
std::map<String, uint32_t> deauthSourceCounts;
std::map<String, uint32_t> deauthTargetCounts;
std::map<String, std::vector<uint32_t>> deauthTimings;

// Evil Twin Detection
std::map<String, APProfile> knownAPs;
std::vector<String> suspiciousAPs;
bool evilTwinDetectionEnabled = false;
QueueHandle_t evilTwinQueue = nullptr;

// Karma Attack Detection
bool karmaDetectionEnabled = false;
QueueHandle_t karmaQueue = nullptr;
volatile uint32_t karmaCount = 0;
volatile uint32_t probeFloodCount = 0;
std::map<String, std::vector<String>> clientProbeRequests;
std::map<String, uint32_t> karmaAPResponses;

// Probe Flood Detection
bool probeFloodDetectionEnabled = false;
QueueHandle_t probeFloodQueue = nullptr;
std::map<String, uint32_t> probeRequestCounts;
std::map<String, std::vector<uint32_t>> probeTimings;

// EAPOL Detection
bool eapolDetectionEnabled = false;
QueueHandle_t eapolQueue = nullptr;
std::map<String, uint32_t> eapolCaptureAttempts;

// External declarations
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern bool isZeroOrBroadcast(const uint8_t *mac);

inline uint16_t u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

inline int clampi(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

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
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6)
    {
        for (int i = 0; i < 3; i++)
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 3;
        return true;
    }
    return false;
}

size_t getTargetCount()
{
    return targets.size();
}

String getTargetsList()
{
    String out;
    for (auto &t : targets)
    {
        if (t.len == 6)
        {
            char b[18];
            snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                     t.bytes[0], t.bytes[1], t.bytes[2], t.bytes[3], t.bytes[4], t.bytes[5]);
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

void saveTargetsList(const String &txt)
{
    prefs.putString("maclist", txt);
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
            {
                targets.push_back(t);
            }
        }
        start = nl + 1;
    }
}

void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets)
{
    memcpy(mac, trackerMac, 6);
    rssi = trackerRssi;
    lastSeen = trackerLastSeen;
    packets = trackerPackets;
}

void setTrackerMac(const uint8_t mac[6])
{
    memcpy(trackerMac, mac, 6);
}

static inline bool matchesMac(const uint8_t *mac)
{
    for (auto &t : targets)
    {
        if (t.len == 6)
        {
            bool eq = true;
            for (int i = 0; i < 6; i++)
            {
                if (mac[i] != t.bytes[i])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
                return true;
        }
        else
        {
            if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2])
            {
                return true;
            }
        }
    }
    return false;
}

static inline bool isTrackerTarget(const uint8_t *mac)
{
    for (int i = 0; i < 6; i++)
    {
        if (mac[i] != trackerMac[i])
            return false;
    }
    return true;
}

static void hopTimerCb(void *)
{
    static size_t idx = 0;
    if (CHANNELS.empty())
        return;
    idx = (idx + 1) % CHANNELS.size();
    esp_wifi_set_channel(CHANNELS[idx], WIFI_SECOND_CHAN_NONE);
}

static int periodFromRSSI(int8_t rssi)
{
    const int rMin = -90, rMax = -30, pMin = 120, pMax = 1000;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int period = (int)(pMax - a * (pMax - pMin));
    return period;
}

static int freqFromRSSI(int8_t rssi)
{
    const int rMin = -90, rMax = -30, fMin = 2000, fMax = 4500;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int f = (int)(fMin + a * (fMax - fMin));
    return f;
}

// ============== PWNAGOTCHI DETECTION ==============
static void IRAM_ATTR detectPwnagotchi(const wifi_promiscuous_pkt_t *ppkt) {
    if (!pwnagotchiDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for beacon frame (0x80) - EXACT Marauder check
    if (payload[0] == 0x80) {
        // Check for Marauder's exact pwnagotchi MAC: de:ad:be:ef:de:ad
        uint8_t target_mac[6] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};
        bool mac_match = true;
        for (int i = 0; i < 6; i++) {
            if (payload[10 + i] != target_mac[i]) {
                mac_match = false;
                break;
            }
        }
        
        if (mac_match) {
            PwnagotchiHit hit;
            memcpy(hit.mac, payload + 10, 6);
            hit.rssi = ppkt->rx_ctrl.rssi;
            hit.channel = ppkt->rx_ctrl.channel;
            hit.timestamp = millis();
            
            // Extract JSON from SSID - EXACT Marauder method
            uint8_t ssid_len = payload[37];
            if (ssid_len > 0 && ssid_len <= 32) {
                String essid = "";
                for (int i = 0; i < ssid_len; i++) {
                    if (isAscii(payload[38 + i])) {
                        essid += (char)payload[38 + i];
                    }
                }
                
                // Parse JSON for name and pwnd_tot
                int name_start = essid.indexOf("\"name\":\"") + 8;
                int name_end = essid.indexOf("\"", name_start);
                if (name_start > 7 && name_end > name_start) {
                    hit.name = essid.substring(name_start, name_end);
                }
                
                int pwnd_start = essid.indexOf("\"pwnd_tot\":") + 11;
                int pwnd_end = essid.indexOf("}", pwnd_start);
                if (pwnd_start > 10 && pwnd_end > pwnd_start) {
                    hit.pwnd_tot = essid.substring(pwnd_start, pwnd_end).toInt();
                }
            }
            
            pwnagotchiLog.push_back(hit);
            uint32_t temp = pwnagotchiCount;
            pwnagotchiCount = temp + 1;
            
            String alert = "[PWNAGOTCHI] " + hit.name + " pwnd:" + String(hit.pwnd_tot) + 
                          " RSSI:" + String(hit.rssi) + " CH:" + String(hit.channel);
            Serial.println(alert);
            logToSD(alert);
        }
    }
}

// ============== PINEAPPLE DETECTION ==============
static int extractChannelFromBeacon(const uint8_t* payload, int len) {
    // Skip fixed parameters (36 bytes) and SSID
    uint8_t ssid_len = payload[37];
    int pos = 38 + ssid_len;
    
    while (pos < len - 2) {
        uint8_t tag_num = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        
        // DS Parameter Set (channel info)
        if (tag_num == 3 && tag_len == 1) {
            return payload[pos + 2];
        }
        
        pos += 2 + tag_len;
    }
    return -1;
}

static bool hasSuspiciousPineappleTags(const uint8_t* payload, int len) {
    uint8_t ssid_len = payload[37];
    int pos = 38 + ssid_len;
    
    // Check if next tag is DS Parameter (tag 3)
    if (pos < len - 2 && payload[pos] == 3 && payload[pos + 1] == 1) {
        // Check for end after DS Parameter (minimal tags = suspicious)
        int next_pos = pos + 2 + payload[pos + 1];
        return (next_pos >= len || next_pos + 2 > len);
    }
    return false;
}

static void IRAM_ATTR detectPineapple(const wifi_promiscuous_pkt_t *ppkt) {
    if (!pineappleDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for beacon frame (0x80) - EXACT Marauder check
    if (payload[0] == 0x80) {
        uint8_t mac_addr[6];
        memcpy(mac_addr, payload + 10, 6);
        
        // Extract capability flags - EXACT Marauder method
        uint16_t capab_info = ((uint16_t)payload[34] | ((uint16_t)payload[35] << 8));
        bool suspicious_capability = (capab_info == 0x0001);
        
        // Check for minimal tags - EXACT Marauder countPineScanTaggedParameters
        bool minimal_tags = false;
        if (ppkt->rx_ctrl.sig_len > 37) {
            uint8_t ssid_len = payload[37];
            int pos = 36 + ssid_len + 2;
            
            // Check if next tag is DS Parameter (tag 3) and then end
            if (pos < ppkt->rx_ctrl.sig_len - 2 && payload[pos] == 3 && payload[pos+1] == 1) {
                int next_pos = pos + 2 + payload[pos+1];
                minimal_tags = (next_pos >= ppkt->rx_ctrl.sig_len || next_pos + 2 > ppkt->rx_ctrl.sig_len);
            }
        }
        
        if (suspicious_capability && minimal_tags) {
            PineappleHit hit;
            memcpy(hit.mac, mac_addr, 6);
            hit.suspicious_capability = suspicious_capability;
            hit.minimal_tags = minimal_tags;
            hit.rssi = ppkt->rx_ctrl.rssi;
            hit.channel = ppkt->rx_ctrl.channel;
            hit.timestamp = millis();
            
            // Extract SSID
            if (ppkt->rx_ctrl.sig_len > 37) {
                uint8_t ssidLen = payload[37];
                if (ssidLen > 0 && ssidLen <= 32 && ppkt->rx_ctrl.sig_len >= 38 + ssidLen) {
                    char ssidBuf[33] = {0};
                    memcpy(ssidBuf, payload + 38, ssidLen);
                    hit.ssid = String(ssidBuf);
                }
            }
            
            pineappleLog.push_back(hit);
            uint32_t temp = pineappleCount;
            pineappleCount = temp + 1;
            
            String alert = "[PINEAPPLE] " + hit.ssid + " MAC:" + macFmt6(hit.mac) + 
                          " CH:" + String(hit.channel) + " RSSI:" + String(hit.rssi);
            Serial.println(alert);
            logToSD(alert);
        }
    }
}

// ============== MULTI-SSID AP DETECTION ==============
static void IRAM_ATTR detectMultiSSID(const wifi_promiscuous_pkt_t *ppkt) {
    if (!multissidDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for beacon frame (0x80) - EXACT Marauder check
    if (payload[0] == 0x80) {
        uint8_t mac_addr[6];
        memcpy(mac_addr, payload + 10, 6);
        String macStr = macFmt6(mac_addr);
        
        // Extract SSID - EXACT Marauder method
        String essid = "";
        if (ppkt->rx_ctrl.sig_len > 37) {
            uint8_t ssid_len = payload[37];
            if (ssid_len > 0 && ssid_len <= 32 && ppkt->rx_ctrl.sig_len >= 38 + ssid_len) {
                for (uint8_t i = 0; i < ssid_len; i++) {
                    essid += (char)payload[38 + i];
                }
            }
        }
        
        if (essid.length() > 0) {
            // Track SSIDs per MAC using static map (persistent across calls)
            static std::map<String, std::set<String>> mac_to_ssids;
            
            mac_to_ssids[macStr].insert(essid);
            
            if (mac_to_ssids[macStr].size() >= 3) {
                // Check if already logged this MAC
                static std::set<String> logged_macs;
                if (logged_macs.find(macStr) == logged_macs.end()) {
                    logged_macs.insert(macStr);
                    
                    ConfirmedMultiSSID confirmed;
                    memcpy(confirmed.mac, mac_addr, 6);
                    confirmed.ssid_count = mac_to_ssids[macStr].size();
                    confirmed.timestamp = millis();
                    
                    confirmedMultiSSID.push_back(confirmed);
                    uint32_t temp = multissidCount;
                    multissidCount = temp + 1;
                    
                    String alert = "[MULTI-SSID] MAC:" + macStr + 
                                  " SSIDs:" + String(confirmed.ssid_count) + 
                                  " Current:" + essid + 
                                  " RSSI:" + String(ppkt->rx_ctrl.rssi) + 
                                  " CH:" + String(ppkt->rx_ctrl.channel);
                    Serial.println(alert);
                    logToSD(alert);
                }
            }
        }
    }
}

// ============== ESPRESSIF DEVICE DETECTION ==============
static void IRAM_ATTR detectEspressif(const wifi_promiscuous_pkt_t *ppkt) {
    if (!espressifDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for beacon frame (0x80)
    if (payload[0] == 0x80) {
        uint8_t mac_addr[6];
        memcpy(mac_addr, payload + 10, 6);
        
        // Check for Espressif OUIs - EXACT Marauder method
        bool isEspressif = false;
        
        if ((mac_addr[0] == 0x24 && mac_addr[1] == 0x0A && mac_addr[2] == 0xC4) ||
            (mac_addr[0] == 0x30 && mac_addr[1] == 0xAE && mac_addr[2] == 0xA4) ||
            (mac_addr[0] == 0x8C && mac_addr[1] == 0xAA && mac_addr[2] == 0xB5) ||
            (mac_addr[0] == 0x3C && mac_addr[1] == 0x61 && mac_addr[2] == 0x05) ||
            (mac_addr[0] == 0x7C && mac_addr[1] == 0x9E && mac_addr[2] == 0xBD)) {
            isEspressif = true;
        }
        
        // Also check SSID for ESP patterns
        String essid = "";
        if (ppkt->rx_ctrl.sig_len > 37) {
            uint8_t ssidLen = payload[37];
            if (ssidLen > 0 && ssidLen <= 32 && ppkt->rx_ctrl.sig_len >= 38 + ssidLen) {
                char ssidBuf[33] = {0};
                memcpy(ssidBuf, payload + 38, ssidLen);
                essid = String(ssidBuf);
                
                if (essid.indexOf("ESP") != -1 || 
                    essid.indexOf("esp") != -1 ||
                    essid.indexOf("NodeMCU") != -1 ||
                    essid.indexOf("Wemos") != -1) {
                    isEspressif = true;
                }
            }
        }
        
        if (isEspressif) {
            // Track in static set to avoid duplicates
            static std::set<String> detected_esp;
            String macStr = macFmt6(mac_addr);
            
            if (detected_esp.find(macStr) == detected_esp.end()) {
                detected_esp.insert(macStr);
                
                String alert = "[ESPRESSIF] " + essid + " MAC:" + macStr + 
                              " CH:" + String(ppkt->rx_ctrl.channel) + 
                              " RSSI:" + String(ppkt->rx_ctrl.rssi);
                Serial.println(alert);
                logToSD(alert);
            }
        }
    }
}
static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for deauth (0xA0) or disassoc (0xC0) frames
    if (payload[0] == 0xA0 || payload[0] == 0xC0) {
        DeauthHit hit;
        memcpy(hit.srcMac, payload + 10, 6);
        memcpy(hit.destMac, payload + 4, 6);
        memcpy(hit.bssid, payload + 16, 6);
        hit.reasonCode = (payload[24] | (payload[25] << 8));
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.isDisassoc = (payload[0] == 0xA0);
        hit.isBroadcast = (memcmp(hit.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0);
        
        bool isAttack = false;
        
        // Broadcast deauth = always suspicious
        if (hit.isBroadcast) {
            isAttack = true;
        } else {
            // Track targeted attacks
            static std::map<String, uint32_t> targetedClients;
            static std::map<String, uint32_t> lastDeauthTime;
            
            String destMacStr = macFmt6(hit.destMac);
            targetedClients[destMacStr]++;
            
            if (lastDeauthTime.count(destMacStr) > 0) {
                uint32_t timeSince = millis() - lastDeauthTime[destMacStr];
                if (timeSince < 10000 && targetedClients[destMacStr] >= 2) {
                    isAttack = true;
                }
            }
            lastDeauthTime[destMacStr] = millis();
        }
        
        if (isAttack || hit.isBroadcast) {
            deauthLog.push_back(hit);
            
            if (hit.isDisassoc) {
                uint32_t temp = disassocCount;
                disassocCount = temp + 1;
            } else {
                uint32_t temp = deauthCount;
                deauthCount = temp + 1;
            }
            
            String alert = "[DEAUTH] " + String(hit.isDisassoc ? "DISASSOC" : "DEAUTH") + 
                          " " + macFmt6(hit.srcMac) + "->" + macFmt6(hit.destMac) + 
                          " Reason:" + String(hit.reasonCode);
            Serial.println(alert);
            logToSD(alert);
            
            if (meshEnabled) {
                String meshAlert = getNodeId() + ": " + alert;
                if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                    Serial1.println(meshAlert);
                }
            }
        }
    }
}

static void IRAM_ATTR detectBeaconFlood(const wifi_promiscuous_pkt_t *ppkt) {
    if (!beaconFloodDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check if it's a beacon frame (0x80)
    if (payload[0] != 0x80) return;
    
    BeaconHit hit;
    memcpy(hit.srcMac, payload + 10, 6);
    
    // Extract SSID if present
    if (ppkt->rx_ctrl.sig_len > 37) {
        uint8_t ssidLen = payload[37];
        if (ssidLen > 0 && ssidLen <= 32 && ppkt->rx_ctrl.sig_len >= 38 + ssidLen) {
            char ssidBuf[33] = {0};
            memcpy(ssidBuf, payload + 38, ssidLen);
            hit.ssid = String(ssidBuf);
        }
    }
    
    String macStr = macFmt6(hit.srcMac);
    uint32_t now = millis();
    
    // Simple flood detection: count unique MACs in time window
    static std::map<String, uint32_t> recentBeacons;
    static uint32_t lastCleanup = 0;
    
    // Cleanup old entries every 5 seconds
    if (now - lastCleanup > 5000) {
        recentBeacons.clear();
        lastCleanup = now;
    }
    
    recentBeacons[macStr]++;
    
    // If we see too many unique beacons, it's a flood
    if (recentBeacons.size() > 20) {  // 20+ unique MACs in 5 seconds
        hit.reason = "Flood: " + String(recentBeacons.size()) + " MACs";
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = now;
        
        uint32_t temp = suspiciousBeacons;
        suspiciousBeacons = temp + 1;
        
        if (beaconQueue) {
            BaseType_t w = pdFALSE;
            xQueueSendFromISR(beaconQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
    
    uint32_t temp2 = totalBeaconsSeen;
    totalBeaconsSeen = temp2 + 1;
}

static void IRAM_ATTR detectEvilTwin(const wifi_promiscuous_pkt_t *ppkt) {
    if (!evilTwinDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 36) return;
    
    if (p[0] == 0x80) {
        uint8_t bssid[6];
        memcpy(bssid, p + 10, 6);
        
        String ssid = "";
        uint8_t ssidLen = p[37];
        if (ssidLen > 0 && ssidLen <= 32 && ppkt->rx_ctrl.sig_len >= 38 + ssidLen) {
            char ssidBuf[33] = {0};
            memcpy(ssidBuf, p + 38, ssidLen);
            ssid = String(ssidBuf);
        }
        
        if (ssid.length() == 0) return;
        
        EvilTwinHit hit;
        hit.ssid = ssid;
        memcpy(hit.rogueMAC, bssid, 6);
        memset(hit.legitimateMAC, 0, 6);
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.suspicionReason = "";
        
        if (evilTwinQueue) {
            BaseType_t w = pdFALSE;
            xQueueSendFromISR(evilTwinQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
}

static void IRAM_ATTR detectKarmaAttack(const wifi_promiscuous_pkt_t *ppkt) {
    if (!karmaDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 24) return;
    
    if (p[0] == 0x40) {
        uint32_t temp = req_frames;
        req_frames = temp + 1;
    }
    else if (p[0] == 0x50) {
        uint32_t temp = resp_frames;
        resp_frames = temp + 1;
        
        uint8_t apMAC[6];
        memcpy(apMAC, p + 10, 6);
        
        KarmaHit hit;
        memcpy(hit.apMAC, apMAC, 6);
        memset(hit.clientMAC, 0, 6);
        hit.clientSSID = "";
        hit.reason = "";
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        
        temp = karmaCount;
        karmaCount = temp + 1;
        
        if (karmaQueue) {
            BaseType_t w = pdFALSE;
            xQueueSendFromISR(karmaQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
}

static void IRAM_ATTR detectProbeFlood(const wifi_promiscuous_pkt_t *ppkt) {
    if (!probeFloodDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check if it's a probe request (0x40)
    if (payload[0] != 0x40) return;
    
    uint8_t clientMAC[6];
    memcpy(clientMAC, payload + 10, 6);
    String clientMacStr = macFmt6(clientMAC);
    
    // Simple rate tracking
    static std::map<String, uint32_t> probeRates;
    static uint32_t lastReset = 0;
    uint32_t now = millis();
    
    // Reset every second
    if (now - lastReset > 1000) {
        probeRates.clear();
        lastReset = now;
    }
    
    probeRates[clientMacStr]++;
    
    // If one client sends too many probes, it's a flood
    if (probeRates[clientMacStr] > 10) {  // 10+ probes per second
        ProbeFloodHit hit;
        memcpy(hit.clientMAC, clientMAC, 6);
        hit.reason = "Rate: " + String(probeRates[clientMacStr]) + "/sec";
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = now;
        hit.probeCount = probeRates[clientMacStr];
        
        uint32_t temp = probeFloodCount;
        probeFloodCount = temp + 1;
        
        if (probeFloodQueue) {
            BaseType_t w = pdFALSE;
            xQueueSendFromISR(probeFloodQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
}

static void IRAM_ATTR detectEAPOLHarvesting(const wifi_promiscuous_pkt_t *ppkt) {
    if (!eapolDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 32) return;
    
    // Check for EAPOL packets (0x888e)
    if ((p[30] == 0x88 && p[31] == 0x8e) || (p[32] == 0x88 && p[33] == 0x8e)) {
        uint32_t temp = num_eapol;
        num_eapol = temp + 1;
        
        uint8_t clientMAC[6], apMAC[6];
        memcpy(apMAC, p + 4, 6);
        memcpy(clientMAC, p + 10, 6);
        
        EAPOLHit hit;
        memcpy(hit.clientMAC, clientMAC, 6);
        memcpy(hit.apMAC, apMAC, 6);
        hit.ssid = "";  // Can be populated if tracking SSID
        hit.messageType = 1;  // EAPOL type
        hit.hasPMKID = false;  // Can check for PMKID presence
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        
        if (eapolQueue) {
            BaseType_t w = pdFALSE;
            xQueueSendFromISR(eapolQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
        
        // Alert
        Serial.println("[EAPOL] Detected handshake from " + macFmt6(clientMAC) + 
                      " to AP " + macFmt6(apMAC));
        beepPattern(2, 100);
    }
}

// Karma Detection Task
void karmaDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[KARMA] Starting Karma attack detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());

    stopAPAndServer();

    // Isolate: Disable others, enable only Karma
    deauthDetectionEnabled = false;
    beaconFloodDetectionEnabled = false;
    probeFloodDetectionEnabled = false;
    evilTwinDetectionEnabled = false;
    eapolDetectionEnabled = false;
    karmaDetectionEnabled = true;
    stopRequested = false;

    // Reset state/maps
    clientProbeRequests.clear();
    karmaAPResponses.clear();
    uint32_t tempKarma = karmaCount;  // Volatile safe
    karmaCount = 0;

    if (karmaQueue) vQueueDelete(karmaQueue);
    karmaQueue = xQueueCreate(256, sizeof(KarmaHit));

    radioStartSTA();  // Enables WiFi sniffer; only Karma processes frames

    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    KarmaHit hit;

    const int BATCH_LIMIT = 4;  // Non-blocking batch processing

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        int processed = 0;
        while (processed++ < BATCH_LIMIT && xQueueReceive(karmaQueue, &hit, 0) == pdTRUE) {
            // Alert on hit
            String alert = "KARMA ATTACK: AP:" + macFmt6(hit.apMAC) + 
                           " Client:" + macFmt6(hit.clientMAC) + 
                           " SSID:\"" + hit.clientSSID + "\"";
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
            if (hit.reason.length() > 0) alert += " [" + hit.reason + "]";

            Serial.println("[ALERT] " + alert);
            logToSD(alert);
            beepPattern(3, 50);  // Distinct: 3 medium beeps

            if (meshEnabled) {
                String meshAlert = getNodeId() + ": KARMA: " + macFmt6(hit.apMAC) + " " + hit.clientSSID;
                if (gpsValid) meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                if (hit.reason.length() > 0) meshAlert += " " + hit.reason;
                if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                    Serial1.println(meshAlert);
                }
            }

            uint32_t temp = karmaCount;
            karmaCount = temp + 1;
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[KARMA] Detected:%u\n", karmaCount);
            nextStatus += 5000;
        }

        if (millis() - lastCleanup > 60000) {
            cleanupMaps();  // Cleans shared maps
            lastCleanup = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    karmaDetectionEnabled = false;
    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    // Store results (Karma-specific)
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Karma Attack Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Karma attacks: " + std::to_string(karmaCount) + "\n\n";
        
        // Optional: List top APs from karmaAPResponses (corrected concatenation)
        std::vector<std::pair<String, uint32_t>> topAPs(karmaAPResponses.begin(), karmaAPResponses.end());
        std::sort(topAPs.begin(), topAPs.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        for (size_t i = 0; i < std::min(topAPs.size(), size_t(10)); ++i) {
            results += topAPs[i].first.c_str();  // String to const char*
            results += ": ";
            results += std::to_string(topAPs[i].second);
            results += " SSIDs\n";
        }
        
        antihunter::lastResults = results;
    }

    startAPAndServer();
    blueTeamTaskHandle = nullptr;  // Reset shared handle
    vTaskDelete(nullptr);
}

// Probe Flood Detection Task (Corrected, symmetric)
void probeFloodDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[PROBE] Starting probe flood detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());

    stopAPAndServer();

    // Isolate: Disable others, enable only Probe Flood
    deauthDetectionEnabled = false;
    beaconFloodDetectionEnabled = false;
    karmaDetectionEnabled = false;
    evilTwinDetectionEnabled = false;
    eapolDetectionEnabled = false;
    probeFloodDetectionEnabled = true;
    stopRequested = false;

    // Reset state/maps
    probeRequestCounts.clear();
    probeTimings.clear();
    uint32_t tempProbe = probeFloodCount;  // Volatile safe
    probeFloodCount = 0;

    if (probeFloodQueue) vQueueDelete(probeFloodQueue);
    probeFloodQueue = xQueueCreate(256, sizeof(ProbeFloodHit));

    radioStartSTA();  // Enables WiFi sniffer; only Probe Flood processes

    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    ProbeFloodHit hit;

    const int BATCH_LIMIT = 4;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        int processed = 0;
        while (processed++ < BATCH_LIMIT && xQueueReceive(probeFloodQueue, &hit, 0) == pdTRUE) {
            String alert = "PROBE FLOOD: Client:" + macFmt6(hit.clientMAC) + 
                           " Count:" + String(hit.probeCount) + "/sec";
            if (hit.ssid.length() > 0) alert += " SSID:\"" + hit.ssid + "\"";
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
            if (hit.reason.length() > 0) alert += " [" + hit.reason + "]";

            Serial.println("[ALERT] " + alert);
            logToSD(alert);
            beepPattern(5, 30);  // Distinct: 5 quick beeps

            if (meshEnabled) {
                String meshAlert = getNodeId() + ": PROBE-FLOOD: " + macFmt6(hit.clientMAC) + " " + String(hit.probeCount);
                if (gpsValid) meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                if (hit.reason.length() > 0) meshAlert += " " + hit.reason;
                if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                    Serial1.println(meshAlert);
                }
            }

            uint32_t temp = probeFloodCount;
            probeFloodCount = temp + 1;
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[PROBE] Detected:%u\n", probeFloodCount);
            nextStatus += 5000;
        }

        if (millis() - lastCleanup > 60000) {
            cleanupMaps();  // Cleans probe maps
            lastCleanup = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    probeFloodDetectionEnabled = false;
    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    // Store results (Probe-specific)
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Probe Flood Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Probe floods: " + std::to_string(probeFloodCount) + "\n\n";
        
        // Optional: List top clients from probeRequestCounts (corrected concatenation)
        std::vector<std::pair<String, uint32_t>> topClients(probeRequestCounts.begin(), probeRequestCounts.end());
        std::sort(topClients.begin(), topClients.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        for (size_t i = 0; i < std::min(topClients.size(), size_t(10)); ++i) {
            results += topClients[i].first.c_str();  // String to const char*
            results += ": ";
            results += std::to_string(topClients[i].second);
            results += " probes\n";
        }
        
        antihunter::lastResults = results;
    }

    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

// Main NimBLE callback
class MyBLEAdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;

        String deviceName = "Unknown";
        if (advertisedDevice->haveName()) {
            std::string nimbleName = advertisedDevice->getName();
            if (nimbleName.length() > 0) {
                deviceName = "";
                for (size_t i = 0; i < nimbleName.length() && i < 31; i++) {
                    uint8_t c = (uint8_t)nimbleName[i];
                    if (c >= 32 && c <= 126) {
                        deviceName += (char)c;
                    }
                }
                if (deviceName.length() == 0) {
                    deviceName = "Unknown";
                }
            }
        }

        if (trackerMode) {
            if (isTrackerTarget(mac)) {
                trackerRssi = advertisedDevice->getRSSI();
                trackerLastSeen = millis();
                trackerPackets =    trackerPackets + 1;
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
                    if (xQueueSend(macQueue, &h, pdMS_TO_TICKS(10)) != pdTRUE) {
                        Serial.printf("[BLE] Queue full for %s\n", macStr.c_str());
                    }
                }
            }
        }
    }
};

// BLE Attack Callback
class BLEAttackDetector : public NimBLEAdvertisedDeviceCallbacks {
private:
    std::map<String, std::vector<uint32_t>> deviceTimings;
    std::map<String, String> lastDeviceNames;
    uint32_t lastCleanup = 0;
    
public:
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;
        
        uint32_t now = millis();
        
        // Track timing
        deviceTimings[macStr].push_back(now);
        
        // Clean old entries every 5 seconds
        if (now - lastCleanup > 5000) {
            for (auto& entry : deviceTimings) {
                entry.second.erase(
                    std::remove_if(entry.second.begin(), entry.second.end(),
                        [now](uint32_t t) { return now - t > BLE_TIMING_WINDOW; }),
                    entry.second.end()
                );
            }
            // Remove empty entries
            for (auto it = deviceTimings.begin(); it != deviceTimings.end();) {
                if (it->second.empty()) {
                    it = deviceTimings.erase(it);
                } else {
                    ++it;
                }
            }
            lastCleanup = now;
        }
        
        // Count packets in window
        uint32_t packetsInWindow = deviceTimings[macStr].size();
        
        bool isSpam = false;
        String spamType = "";
        uint16_t companyId = 0;
        
        // Check manufacturer data
        if (advertisedDevice->haveManufacturerData()) {
            std::string manData = advertisedDevice->getManufacturerData();
            if (manData.length() >= 2) {
                companyId = (manData[1] << 8) | manData[0];
                
                if (companyId == 0x004C && packetsInWindow >= 15) {  // Apple
                    isSpam = true;
                    spamType = "Apple spam";
                }
                else if ((companyId == 0x00E0 || companyId == 0xFE2C) && 
                         packetsInWindow >= 20) {  // Google Fast Pair
                    isSpam = true;
                    spamType = "Fast Pair spam";
                }
                else if (companyId == 0x0075 && packetsInWindow >= 20) {  // Samsung
                    isSpam = true;
                    spamType = "Samsung spam";
                }
            }
        }
        
        // Generic flood detection - much higher threshold
        if (!isSpam && packetsInWindow >= 50) {
            isSpam = true;
            spamType = "BLE flood";
        }
        
        // Check for name changes (spam indicator)
        if (advertisedDevice->haveName()) {
            String currentName = String(advertisedDevice->getName().c_str());
            if (lastDeviceNames.find(macStr) != lastDeviceNames.end()) {
                if (lastDeviceNames[macStr] != currentName && packetsInWindow >= 10) {
                    isSpam = true;
                    spamType = "Name-changing spam";
                }
            }
            lastDeviceNames[macStr] = currentName;
        }
        
        if (isSpam) {
            BLESpamHit hit;
            memcpy(hit.mac, mac, 6);
            hit.advType = 0;
            strncpy(hit.deviceName, advertisedDevice->haveName() ? 
                    advertisedDevice->getName().c_str() : "", sizeof(hit.deviceName) - 1);
            hit.rssi = advertisedDevice->getRSSI();
            hit.timestamp = now;
            hit.advCount = packetsInWindow;
            strncpy(hit.spamType, spamType.c_str(), sizeof(hit.spamType) - 1);
            hit.companyId = companyId;
            
            if (bleSpamQueue && bleSpamLog.size() < 500) {
                xQueueSend(bleSpamQueue, &hit, 0);
                uint32_t temp = bleSpamCount;
                bleSpamCount = temp + 1;
            }
        }
    }
};

void bleScannerTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    
    Serial.printf("[BLE-SEC] Starting BLE attack detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());
    
    stopAPAndServer();
    
    bleSpamLog.clear();
    bleAdvCounts.clear();
    bleAdvTimings.clear();
    bleSpamCount = 0;
    bleAnomalyCount = 0;
    bleSpamDetectionEnabled = true;
    stopRequested = false;
    
    if (bleSpamQueue) vQueueDelete(bleSpamQueue);
    if (bleAnomalyQueue) vQueueDelete(bleAnomalyQueue);
    
    bleSpamQueue = xQueueCreate(256, sizeof(BLESpamHit));
    bleAnomalyQueue = xQueueCreate(256, sizeof(BLEAnomalyHit));
    
    BLEDevice::init("");
    NimBLEScan* pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BLEAttackDetector());
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(50);
    pBLEScan->setWindow(30);
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    BLESpamHit spamHit;
    BLEAnomalyHit anomalyHit;
    
    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        pBLEScan->start(1, false);
        
        while (xQueueReceive(bleSpamQueue, &spamHit, 0) == pdTRUE) {
            String alert = "BLE SPAM: ";
            alert += spamHit.spamType;
            alert += " MAC:" + macFmt6(spamHit.mac);
            alert += " Count:" + String(spamHit.advCount);
            alert += " RSSI:" + String(spamHit.rssi) + "dBm";
            
            Serial.println("[ALERT] " + alert);
            logToSD(alert);
            beepPattern(4, 40);
            
            if (meshEnabled) {
                String meshAlert = getNodeId() + ": BLE-ATTACK: " + String(spamHit.spamType);
                if (Serial1.availableForWrite() >= meshAlert.length()) {
                    Serial1.println(meshAlert);
                }
            }
        }
        
        while (xQueueReceive(bleAnomalyQueue, &anomalyHit, 0) == pdTRUE) {
            String alert = "BLE ANOMALY: ";
            alert += anomalyHit.anomalyType;
            alert += " MAC:" + macFmt6(anomalyHit.mac);
            alert += " " + String(anomalyHit.details);
            
            Serial.println("[ANOMALY] " + alert);
            logToSD(alert);
            beepPattern(2, 100);
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLE-SEC] Spam:%u Anomalies:%u\n", 
                         bleSpamCount, bleAnomalyCount);
            nextStatus += 5000;
        }
        
        if (millis() - lastCleanup > 60000) {
            cleanupMaps();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    bleSpamDetectionEnabled = false;
    pBLEScan->stop();
    BLEDevice::deinit(false);
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "BLE Attack Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Spam attacks: " + std::to_string(bleSpamCount) + "\n";
        results += "Anomalies: " + std::to_string(bleAnomalyCount) + "\n\n";
        
        std::map<String, uint32_t> spamTypes;
        for (const auto& hit : bleSpamLog) {
            spamTypes[String(hit.spamType)]++;
        }
        
        for (const auto& entry : spamTypes) {
            results += std::string(entry.first.c_str()) + ": " + std::to_string(entry.second) + " attacks\n";
        }
        
        antihunter::lastResults = results;
    }
    
    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void snifferScanTask(void *pv)
{
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                 (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[SNIFFER] Starting device scan %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    stopAPAndServer();

    radioStartSTA();

    scanning = true;
    uniqueMacs.clear();
    hitsLog.clear();
    apCache.clear();
    bleDeviceCache.clear();
    totalHits = 0;
    framesSeen = 0;
    bleFramesSeen = 0;
    stopRequested = false;
    lastScanStart = millis();
    lastScanSecs = duration;
    lastScanForever = forever;

    int networksFound = 0;
    unsigned long lastBLEScan = 0;
    unsigned long lastWiFiScan = 0;
    const unsigned long BLE_SCAN_INTERVAL = 8000;
    const unsigned long WIFI_SCAN_INTERVAL = 5000;

    NimBLEScan *bleScan = nullptr;

    BLEDevice::init("");
    bleScan = BLEDevice::getScan();
    bleScan->setActiveScan(true);
    bleScan->setInterval(100);
    bleScan->setWindow(99);

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < duration * 1000 && !stopRequested))
    {
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)
        {
            lastWiFiScan = millis();

            Serial.println("[SNIFFER] Scanning WiFi networks...");
            networksFound = WiFi.scanNetworks(false, true, false, 300);

            if (networksFound > 0)
            {
                for (int i = 0; i < networksFound; i++)
                {
                    String bssid = WiFi.BSSIDstr(i);
                    String ssid = WiFi.SSID(i);
                    int32_t rssi = WiFi.RSSI(i);
                    uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0)
                    {
                        ssid = "[Hidden]";
                    }

                    if (apCache.find(bssid) == apCache.end())
                    {
                        apCache[bssid] = ssid;
                        uniqueMacs.insert(bssid);
                        totalHits = totalHits + 1;
                        framesSeen = framesSeen + 1;

                        Hit h;
                        memcpy(h.mac, bssidBytes, 6);
                        h.rssi = rssi;
                        h.ch = WiFi.channel(i);
                        strncpy(h.name, ssid.c_str(), sizeof(h.name) - 1);
                        h.name[sizeof(h.name) - 1] = '\0';
                        h.isBLE = false;

                        hitsLog.push_back(h);

                        String logEntry = "WiFi AP: " + bssid + " SSID: " + ssid +
                                          " RSSI: " + String(rssi) + "dBm CH: " + String(WiFi.channel(i));

                        if (gpsValid)
                        {
                            logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                        }

                        Serial.println("[SNIFFER] " + logEntry);
                        logToSD(logEntry);

                        uint8_t mac[6];
                        if (parseMac6(bssid, mac) && matchesMac(mac))
                        {
                            beepPattern(getBeepsPerHit(), getGapMs());
                            sendMeshNotification(h);
                        }
                    }
                }
            }

            Serial.printf("[SNIFFER] WiFi scan found %d networks\n", networksFound);
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        if (millis() - lastBLEScan >= BLE_SCAN_INTERVAL || lastBLEScan == 0)
        {
            lastBLEScan = millis();

            Serial.println("[SNIFFER] Scanning BLE devices...");

            if (bleScan)
            {
                // esp_task_wdt_reset();
                BLEScanResults scanResults = bleScan->start(1, false);

                for (int i = 0; i < scanResults.getCount(); i++)
                {
                    BLEAdvertisedDevice device = scanResults.getDevice(i);
                    String macStr = device.getAddress().toString().c_str();

                    if (bleDeviceCache.find(macStr) == bleDeviceCache.end())
                    {
                        String name = device.haveName() ? device.getName().c_str() : "Unknown";

                        String cleanName = "";
                        for (size_t j = 0; j < name.length(); j++)
                        {
                            char c = name[j];
                            if (c >= 32 && c <= 126)
                            {
                                cleanName += c;
                            }
                        }
                        if (cleanName.length() == 0)
                            cleanName = "Unknown";

                        bleDeviceCache[macStr] = cleanName;
                        uniqueMacs.insert(macStr);
                        totalHits = totalHits + 1;
                        bleFramesSeen = bleFramesSeen + 1;

                        uint8_t mac[6];
                        if (parseMac6(macStr, mac))
                        {
                            Hit h;
                            memcpy(h.mac, mac, 6);
                            h.rssi = device.getRSSI();
                            h.ch = 0;
                            strncpy(h.name, cleanName.c_str(), sizeof(h.name) - 1);
                            h.name[sizeof(h.name) - 1] = '\0';
                            h.isBLE = true;

                            hitsLog.push_back(h);

                            String logEntry = "BLE Device: " + macStr + " Name: " + cleanName +
                                              " RSSI: " + String(device.getRSSI()) + "dBm";

                            if (gpsValid)
                            {
                                logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                            }

                            Serial.println("[SNIFFER] " + logEntry);
                            logToSD(logEntry);

                            if (matchesMac(mac))
                            {
                                beepPattern(getBeepsPerHit(), getGapMs());
                                sendMeshNotification(h);
                            }
                        }
                    }
                }

                bleScan->clearResults();
                Serial.printf("[SNIFFER] BLE scan found %d devices\n", scanResults.getCount());
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }

        Serial.printf("[SNIFFER] Total: WiFi APs=%d, BLE=%d, Unique=%d, Hits=%d\n",
                      apCache.size(), bleDeviceCache.size(), uniqueMacs.size(), totalHits);

        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (bleScan)
    {
        bleScan->stop();
        delay(100);
        BLEDevice::deinit(false);
        delay(200);
    }

    stopAPAndServer();
    
    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = 
            "Sniffer scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Total hits: " + std::to_string(totalHits) + "\n" +
            "Unique devices: " + std::to_string(uniqueMacs.size()) + "\n\n";
        
        std::vector<Hit> sortedHits = hitsLog;
        std::sort(sortedHits.begin(), sortedHits.end(), 
                [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

        int shown = 0;
        for (const auto& hit : sortedHits) {
            if (shown++ >= 100) break;
            
            results += (hit.isBLE ? "BLE  " : "WiFi ");
            results += macFmt6(hit.mac).c_str();
            results += " RSSI=" + std::to_string(hit.rssi) + "dBm";
            
            if (!hit.isBLE && hit.ch > 0) {
                results += " CH=" + std::to_string(hit.ch);
            }
            
            if (strlen(hit.name) > 0 && strcmp(hit.name, "WiFi") != 0 && strcmp(hit.name, "Unknown") != 0) {
                results += " \"";
                results += hit.name;
                results += "\"";
            }
            
            results += "\n";
        }
        
        if (sortedHits.size() > 100) {
            results += "... (" + std::to_string(sortedHits.size() - 100) + " more)\n";
        }

        antihunter::lastResults = results;
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    
    startAPAndServer();
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

String getSnifferCache()
{
    String result = "=== Sniffer Cache ===\n\n";
    result += "WiFi APs: " + String(apCache.size()) + "\n";
    for (const auto &entry : apCache)
    {
        result += entry.first + " : " + entry.second + "\n";
    }
    result += "\nBLE Devices: " + String(bleDeviceCache.size()) + "\n";
    for (const auto &entry : bleDeviceCache)
    {
        result += entry.first + " : " + entry.second + "\n";
    }
    return result;
}

void blueTeamTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    String startMsg = forever ? String("[BLUE] Starting deauth detection (forever)\n")
                              : String("[BLUE] Starting deauth detection for " + String(duration) + "s\n");
    Serial.print(startMsg);

    stopAPAndServer();
    
    deauthLog.clear();
    deauthCount = 0;
    disassocCount = 0;
    deauthDetectionEnabled = true;
    stopRequested = false;
    deauthSourceCounts.clear();
    deauthTargetCounts.clear();
    deauthTimings.clear();

    if (deauthQueue) {
        vQueueDelete(deauthQueue);
    }
    
    deauthQueue = xQueueCreate(256, sizeof(DeauthHit));
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    DeauthHit hit;

    radioStartSTA();

    const int BATCH_LIMIT = 4;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
            int processed = 0;
        
            while (processed++ < BATCH_LIMIT && xQueueReceive(deauthQueue, &hit, 0) == pdTRUE) {
                

                if (deauthLog.size() < 1000) {
                    deauthLog.push_back(hit);
                }
                
                String alert = String(hit.isDisassoc ? "DISASSOC" : "DEAUTH");
                if (hit.isBroadcast) {
                    alert += " [BROADCAST]";  // Deauth flood
                } else {
                    alert += " [TARGETED]";   // Targeted attack
                }
                alert += " SRC:" + macFmt6(hit.srcMac) + " DST:" + macFmt6(hit.destMac);
                alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
                alert += " Reason:" + String(hit.reasonCode);

                Serial.println("[ALERT] " + alert);
                logToSD(alert);

                if (meshEnabled) {
                    String meshAlert = getNodeId() + ": ATTACK: " + alert;
                    if (gpsValid) {
                        meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                    }
                    if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                        Serial1.println(meshAlert);
                    }
                }
            }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLUE] Deauth:%u Disassoc:%u Total:%u\n", 
                         deauthCount, disassocCount, (unsigned)deauthLog.size());
            nextStatus += 5000;
        }
        
        if (millis() - lastCleanup > 60000) {
            if (deauthTimings.size() > 100) {
                std::map<String, std::vector<uint32_t>> newTimings;
                for (auto& entry : deauthTimings) {
                    if (entry.second.size() > 20) {
                        auto &vec = entry.second;
                        newTimings[entry.first] = std::vector<uint32_t>(vec.end() - 20, vec.end());
                    } else {
                        newTimings[entry.first] = entry.second;
                    }
                }
                deauthTimings = std::move(newTimings);
            }
            lastCleanup = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    deauthDetectionEnabled = false;
    
    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Deauth Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Deauth frames: " + std::to_string(deauthCount) + "\n";
        results += "Disassoc frames: " + std::to_string(disassocCount) + "\n";
        results += "Total attacks: " + std::to_string(deauthLog.size()) + "\n\n";

        int show = min((int)deauthLog.size(), 100);
        for (int i = 0; i < show; i++) {
            const auto &h = deauthLog[i];
            results += std::string(h.isDisassoc ? "DISASSOC" : "DEAUTH");
            
            // Add attack type indicator
            if (h.isBroadcast) {
                results += " [BROADCAST]";
            } else if (deauthTargetCounts[macFmt6(h.destMac)] >= 3) {
                results += " [TARGETED]";
            }
            
            results += " ";
            results += std::string(macFmt6(h.srcMac).c_str()) + " -> " + std::string(macFmt6(h.destMac).c_str());
            results += " BSSID:" + std::string(macFmt6(h.bssid).c_str());
            results += " RSSI:" + std::to_string(h.rssi) + "dBm";
            results += " CH:" + std::to_string(h.channel);
            results += " Reason:" + std::to_string(h.reasonCode) + "\n";
        }

        if ((int)deauthLog.size() > show) {
            results += "... (" + std::to_string((int)deauthLog.size() - show) + " more)\n";
        }
        
        antihunter::lastResults = results;
    }

    
    startAPAndServer();
    vTaskDelay(pdMS_TO_TICKS(1000));
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void beaconFloodTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[BEACON] Starting beacon flood detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());

    stopAPAndServer();

    beaconLog.clear();
    beaconCounts.clear();
    beaconLastSeen.clear();
    beaconTimings.clear();
    totalBeaconsSeen = 0;
    suspiciousBeacons = 0;
    beaconFloodDetectionEnabled = true;
    stopRequested = false;

    if (beaconQueue) {
        vQueueDelete(beaconQueue);
    }
    beaconQueue = xQueueCreate(256, sizeof(BeaconHit));

    radioStartSTA();

    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    BeaconHit hit;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {

        int processed = 0;
        while (processed++ < 10 && xQueueReceive(beaconQueue, &hit, 0) == pdTRUE) {
            beaconLog.push_back(hit);

            String alert = "BEACON FLOOD! MAC:" + macFmt6(hit.srcMac);
            alert += " SSID:" + (hit.ssid.length() > 0 ? hit.ssid : "[Hidden]");
            alert += " Count:" + String(beaconCounts[macFmt6(hit.srcMac)]);
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);

            Serial.println("[ALERT] " + alert);
            logToSD(alert);

            beepPattern(4, 40);

            if (meshEnabled) {
                String meshAlert = getNodeId() + ": FLOOD: " + alert;
                if (gpsValid) {
                    meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                }
                Serial1.println(meshAlert);
            }
        }

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BEACON] Total:%u Suspicious:%u Unique MACs:%u\n",
                          totalBeaconsSeen, suspiciousBeacons, (unsigned)beaconCounts.size());
            nextStatus += 5000;
        }
        
        if (millis() - lastCleanup > 60000) {
            cleanupMaps();
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    beaconFloodDetectionEnabled = false;
    
    radioStopSTA();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Beacon Flood Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Total beacons: " + std::to_string(totalBeaconsSeen) + "\n";
        results += "Suspicious beacons: " + std::to_string(suspiciousBeacons) + "\n";
        results += "Unique MACs: " + std::to_string(beaconCounts.size()) + "\n\n";

        std::vector<std::pair<String, uint32_t>> sorted;
        for (const auto &entry : beaconCounts) {
            sorted.push_back({entry.first, entry.second});
        }
        std::sort(sorted.begin(), sorted.end(),
                    [](const auto &a, const auto &b) { return a.second > b.second; });

        int show = min((int)sorted.size(), 50);
        for (int i = 0; i < show; i++) {
            const auto &h = beaconLog[i];
            results += "BEACON FLOOD: MAC:" + std::string(macFmt6(h.srcMac).c_str());
            results += " SSID:" + std::string(hit.ssid.length() > 0 ? hit.ssid.c_str() : "[Hidden]");
            if (h.reason.length() > 0) {
                results += " [" + std::string(h.reason.c_str()) + "]";
            }
            results += " RSSI:" + std::to_string(h.rssi) + "dBm";
            results += " CH:" + std::to_string(h.channel) + "\n";
        }

        if ((int)sorted.size() > show) {
            results += "... (" + std::to_string((int)sorted.size() - show) + " more MACs)\n";
        }
        
        antihunter::lastResults = results;
    }

    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;

    detectPwnagotchi(ppkt);
    detectPineapple(ppkt);
    detectMultiSSID(ppkt);
    detectEspressif(ppkt);
    detectDeauthFrame(ppkt);
    detectBeaconFlood(ppkt);
    detectKarmaAttack(ppkt);
    detectProbeFlood(ppkt);
    detectEvilTwin(ppkt);
    detectEAPOLHarvesting(ppkt);

    framesSeen = framesSeen + 1;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 24)
        return;

    const uint8_t *p = ppkt->payload;
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t tods = (fc >> 8) & 0x1;
    uint8_t fromds = (fc >> 9) & 0x1;

    const uint8_t *a1 = p + 4, *a2 = p + 10, *a3 = p + 16, *a4 = p + 24;
    uint8_t cand1[6], cand2[6];
    bool c1 = false, c2 = false;

    if (ftype == 0)
    {
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
    {
        if (!tods && !fromds)
        {
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
        else if (tods && !fromds)
        {
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a1))
            {
                memcpy(cand2, a1, 6);
                c2 = true;
            }
        }
        else if (!tods && fromds)
        {
            if (!isZeroOrBroadcast(a3))
            {
                memcpy(cand1, a3, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand2, a2, 6);
                c2 = true;
            }
        }
        else
        {
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
        return;
    }

    if (trackerMode && currentScanMode != SCAN_BLE)
    {
        if (c1 && isTrackerTarget(cand1))
        {
            trackerRssi = ppkt->rx_ctrl.rssi;
            trackerLastSeen = millis();
            trackerPackets = trackerPackets + 1;
        }
        if (c2 && isTrackerTarget(cand2))
        {
            trackerRssi = ppkt->rx_ctrl.rssi;
            trackerLastSeen = millis();
            trackerPackets = trackerPackets + 1;
        }
    }
    else if (!trackerMode)
    {
        if (c1 && matchesMac(cand1))
        {
            Hit h;
            memcpy(h.mac, cand1, 6);
            h.rssi = ppkt->rx_ctrl.rssi;
            h.ch = ppkt->rx_ctrl.channel;
            strncpy(h.name, "WiFi", sizeof(h.name) - 1);
            h.name[sizeof(h.name) - 1] = '\0';
            h.isBLE = false;

            BaseType_t w = false;
            if (macQueue)
            {
                xQueueSendFromISR(macQueue, &h, &w);
                if (w)
                    portYIELD_FROM_ISR();
            }
        }
        if (c2 && matchesMac(cand2))
        {
            Hit h;
            memcpy(h.mac, cand2, 6);
            h.rssi = ppkt->rx_ctrl.rssi;
            h.ch = ppkt->rx_ctrl.channel;
            strncpy(h.name, "WiFi", sizeof(h.name) - 1);
            h.name[sizeof(h.name) - 1] = '\0';
            h.isBLE = false;

            BaseType_t w = false;
            if (macQueue)
            {
                xQueueSendFromISR(macQueue, &h, &w);
                if (w)
                    portYIELD_FROM_ISR();
            }
        }
    }
}

// ---------- Radio common ----------
static void radioStartWiFi()
{
    WiFi.mode(WIFI_MODE_STA);
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    esp_wifi_start();

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    
    // Setup channel hopping
    if (hopTimer) {
        esp_timer_stop(hopTimer);
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
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (hopTimer)
    {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    esp_wifi_stop();
    esp_wifi_deinit(); // fix AP bind error
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

void initializeScanner()
{
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

    uint32_t nextStatus = millis() + 1000;
    std::map<String, uint32_t> deviceLastSeen;
    const uint32_t DEDUPE_WINDOW = 30000;
    Hit h;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("Status: Tracking %d devices... WiFi frames=%u BLE frames=%u\n",
                         (int)uniqueMacs.size(), (unsigned)framesSeen, (unsigned)bleFramesSeen);
            nextStatus += 1000;
        }

        while (xQueueReceive(macQueue, &h, 0) == pdTRUE) {
            String macStr = macFmt6(h.mac);
            uint32_t now = millis();

            if (deviceLastSeen.find(macStr) != deviceLastSeen.end()) {
                if (now - deviceLastSeen[macStr] < DEDUPE_WINDOW) continue;
            }

            deviceLastSeen[macStr] = now;
            totalHits = totalHits + 1;
            hitsLog.push_back(h);
            uniqueMacs.insert(macStr);

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macStr +
                              " RSSI=" + String(h.rssi) + "dBm";
            if (!h.isBLE && h.ch > 0) logEntry += " CH=" + String(h.ch);
            if (strlen(h.name) > 0 && strcmp(h.name, "WiFi") != 0 && strcmp(h.name, "Unknown") != 0) {
                logEntry += " Name=" + String(h.name);
            }
            if (gpsValid) {
                logEntry += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }

            Serial.printf("[HIT] %s\n", logEntry.c_str());
            logToSD(logEntry);
            beepPattern(getBeepsPerHit(), getGapMs());
            sendMeshNotification(h);
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            static uint32_t lastBLEScan = 0;
            if (millis() - lastBLEScan >= 3000) {
                pBLEScan->start(1, false);
                pBLEScan->clearResults();
                lastBLEScan = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    // BUILD AND STORE RESULTS
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = 
            "List scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(secs)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Total hits: " + std::to_string(totalHits) + "\n" +
            "Unique devices: " + std::to_string(uniqueMacs.size()) + "\n\n";
        
        // Sort hits by RSSI (strongest first)
        std::vector<Hit> sortedHits = hitsLog;
        std::sort(sortedHits.begin(), sortedHits.end(), 
                [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

        int show = sortedHits.size();
        if (show > 200) show = 200;
        for (int i = 0; i < show; i++) {
            const auto &e = sortedHits[i];
            results += std::string(e.isBLE ? "BLE " : "WiFi");
            results += " " + std::string(macFmt6(e.mac).c_str());
            results += " RSSI=" + std::to_string(e.rssi) + "dBm";
            if (!e.isBLE && e.ch > 0) results += " CH=" + std::to_string(e.ch);
            if (strlen(e.name) > 0 && strcmp(e.name, "WiFi") != 0 && strcmp(e.name, "Unknown") != 0) {
                results += " Name=" + std::string(e.name);
            }
            results += "\n";
        }
        if (static_cast<int>(sortedHits.size()) > show) {
            results += "... (" + std::to_string(sortedHits.size() - show) + " more)\n";
        }
        
        antihunter::lastResults = results;
        Serial.printf("[DEBUG] Results stored: %d chars\n", results.length());
    }

    startAPAndServer();
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr); 
}

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

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested))
    {
        if ((int32_t)(millis() - nextStatus) >= 0)
        {
            uint32_t ago = trackerLastSeen ? (millis() - trackerLastSeen) : 0;
            Serial.printf("Status: WiFi frames=%u BLE frames=%u target_rssi=%ddBm seen_ago=%ums packets=%u\n",
                          (unsigned)framesSeen, (unsigned)bleFramesSeen, (int)trackerRssi, (unsigned)ago, (unsigned)trackerPackets);
            nextStatus += 1000;
        }

        uint32_t now = millis();
        bool gotRecent = trackerLastSeen && (now - trackerLastSeen) < 2000;

        if (gotRecent)
        {
            ema = 0.75f * ema + 0.25f * (float)trackerRssi;
        }
        else
        {
            ema = 0.995f * ema - 0.05f;
        }

        int period = gotRecent ? periodFromRSSI((int8_t)ema) : 1400;
        int freq = gotRecent ? freqFromRSSI((int8_t)ema) : 2200;
        int dur = gotRecent ? 60 : 40;

        if ((int32_t)(now - nextBeep) >= 0)
        {
            beepOnce((uint32_t)freq, (uint32_t)dur);
            nextBeep = now + period;
        }

        if (trackerMode)
        {
            sendTrackerMeshUpdate();
        }

        // BLE scanning if needed
        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            if (millis() - nextBLEScan >= 1000) {
                pBLEScan->start(1, false);
                pBLEScan->clearResults();
                nextBLEScan = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    radioStopSTA();
    scanning = false;
    trackerMode = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Tracker - Mode: " + std::string(modeStr.c_str()) + 
                                " Duration: " + (forever ? "Forever" : std::to_string(secs)) + "s\n";
        results += "WiFi Frames seen: " + std::to_string(framesSeen) + "\n";
        results += "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n";
        results += "Target: " + std::string(macFmt6(trackerMac).c_str()) + "\n";
        results += "Packets from target: " + std::to_string(trackerPackets) + "\n";
        results += "Last RSSI: " + std::to_string((int)trackerRssi) + "dBm\n";
        
        antihunter::lastResults = results;
    }

    startAPAndServer();
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void cleanupMaps() {
    const size_t MAX_MAP_SIZE = 100;
    const size_t MAX_TIMING_SIZE = 50;
    const size_t MAX_LOG_SIZE = 500;
    const uint32_t EVICTION_AGE_MS = 30000;  // Remove entries older than 30s
    uint32_t now = millis();

    // Clean deauth maps (sources, targets, timings)
    if (deauthSourceCounts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : deauthSourceCounts) {
            if (entry.second < 2) {  // Low activity
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            deauthSourceCounts.erase(key);
            deauthTargetCounts.erase(key);
            deauthTimings.erase(key);
        }
        // Trim timings vectors (keep recent)
        for (auto it = deauthTimings.begin(); it != deauthTimings.end(); ) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [now](uint32_t t) { return now - t > EVICTION_AGE_MS; }), vec.end());
            if (vec.size() > MAX_TIMING_SIZE) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_TIMING_SIZE));  // Vector OK here
            }
            if (vec.empty()) {
                it = deauthTimings.erase(it);  // Safe erase with post-increment
            } else {
                ++it;
            }
        }
    }
    if (deauthQueue) xQueueReset(deauthQueue);  // Flush old hits

    // Clean deauth logs (vector - trim oldest)
    if (deauthLog.size() > MAX_LOG_SIZE) {
        deauthLog.erase(deauthLog.begin(), deauthLog.begin() + (deauthLog.size() - MAX_LOG_SIZE));
    }

    // Clean beacon maps (counts, lastSeen, timings)
    if (beaconCounts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : beaconLastSeen) {
            if (now - entry.second > EVICTION_AGE_MS) {  // Old MACs
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            beaconCounts.erase(key);
            beaconLastSeen.erase(key);
            beaconTimings.erase(key);
        }
        // Trim timings
        for (auto it = beaconTimings.begin(); it != beaconTimings.end(); ) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [now](uint32_t t) { return now - t > EVICTION_AGE_MS; }), vec.end());
            if (vec.size() > MAX_TIMING_SIZE) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_TIMING_SIZE));
            }
            if (vec.empty()) {
                it = beaconTimings.erase(it);
            } else {
                ++it;
            }
        }
        // Force clear if still too big
        if (beaconCounts.size() > MAX_MAP_SIZE * 2) {
            beaconCounts.clear();
            beaconLastSeen.clear();
            beaconTimings.clear();
        }
    }
    if (beaconQueue) xQueueReset(beaconQueue);

    // Clean beacon logs
    if (beaconLog.size() > MAX_LOG_SIZE) {
        beaconLog.erase(beaconLog.begin(), beaconLog.begin() + (beaconLog.size() - MAX_LOG_SIZE));
    }

    // Clean BLE maps (advCounts, advTimings)
    if (bleAdvCounts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : bleAdvCounts) {
            if (entry.second < 2) {  // Low activity
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            bleAdvCounts.erase(key);
            bleAdvTimings.erase(key);
        }
        // Trim timings
        for (auto it = bleAdvTimings.begin(); it != bleAdvTimings.end(); ) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [now](uint32_t t) { return now - t > EVICTION_AGE_MS; }), vec.end());
            if (vec.size() > MAX_TIMING_SIZE) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_TIMING_SIZE));
            }
            if (vec.empty()) {
                it = bleAdvTimings.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (bleSpamQueue) xQueueReset(bleSpamQueue);
    if (bleAnomalyQueue) xQueueReset(bleAnomalyQueue);

    // Clean BLE logs
    if (bleSpamLog.size() > MAX_LOG_SIZE) {
        bleSpamLog.erase(bleSpamLog.begin(), bleSpamLog.begin() + (bleSpamLog.size() - MAX_LOG_SIZE));
    }

    // Clean Karma maps (clientProbeRequests, karmaAPResponses)
    if (karmaAPResponses.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : karmaAPResponses) {
            if (entry.second < 2) {  // Low responses
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            karmaAPResponses.erase(key);
            clientProbeRequests.erase(key);  // Linked per-AP
        }
        // Trim clientProbeRequests vectors (keep last 50 SSIDs per client)
        for (auto it = clientProbeRequests.begin(); it != clientProbeRequests.end(); ) {
            auto& vec = it->second;
            if (vec.size() > 50) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - 50));
            }
            if (vec.empty()) {
                it = clientProbeRequests.erase(it);
            } else {
                ++it;
            }
        }
        if (clientProbeRequests.size() > MAX_MAP_SIZE) {
            clientProbeRequests.clear();  // Force if too many clients
        }
    }
    if (karmaQueue) xQueueReset(karmaQueue);

    // Clean Probe Flood maps (probeRequestCounts, probeTimings)
    if (probeRequestCounts.size() > MAX_MAP_SIZE) {
        probeRequestCounts.clear();  // Simple clear (counts repopulate easily)
    }
    if (probeTimings.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (auto it = probeTimings.begin(); it != probeTimings.end(); ) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [now](uint32_t t) { return now - t > EVICTION_AGE_MS; }), vec.end());
            if (vec.size() > MAX_TIMING_SIZE) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_TIMING_SIZE));
            }
            if (vec.empty()) {
                toRemove.push_back(it->first);
            }
            ++it;  // Post-increment before potential erase
        }
        for (const auto& key : toRemove) {
            probeTimings.erase(key);
        }
        if (probeTimings.size() > MAX_MAP_SIZE) {
            probeTimings.clear();
        }
    }
    if (probeFloodQueue) xQueueReset(probeFloodQueue);

    // Clean Evil Twin (knownAPs, suspiciousAPs)
    if (knownAPs.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : knownAPs) {
            if (now - entry.second.lastSeen > EVICTION_AGE_MS) {
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            knownAPs.erase(key);
        }
        // suspiciousAPs is vector<String>, trim oldest
        if (suspiciousAPs.size() > MAX_MAP_SIZE) {
            suspiciousAPs.erase(suspiciousAPs.begin(), suspiciousAPs.begin() + (suspiciousAPs.size() - MAX_MAP_SIZE));
        }
    }
    if (evilTwinQueue) xQueueReset(evilTwinQueue);

    // Clean EAPOL (eapolCaptureAttempts)
    if (eapolCaptureAttempts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : eapolCaptureAttempts) {
            if (entry.second < 2) {  // Low attempts
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            eapolCaptureAttempts.erase(key);
        }
    }
    if (eapolQueue) xQueueReset(eapolQueue);
}

// Pwnagotchi detection task
void pwnagotchiDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    
    Serial.println("[PWN] Starting Pwnagotchi detection");
    
    stopAPAndServer();
    pwnagotchiLog.clear();
    pwnagotchiCount = 0;
    stopRequested = false;
    
    radioStartSTA();
    
    uint32_t scanStart = millis();
    
    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        if (pwnagotchiLog.size() > 0) {
            for (const auto& hit : pwnagotchiLog) {
                String alert = "[PWNAGOTCHI] " + hit.name + 
                              " pwnd:" + String(hit.pwnd_tot) +
                              " RSSI:" + String(hit.rssi);
                Serial.println(alert);
                logToSD(alert);
            }
            pwnagotchiLog.clear();
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    radioStopSTA();
    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

// Multi-SSID detection task
void multissidDetectionTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);
    
    Serial.println("[MULTI] Starting Multi-SSID AP detection");
    
    stopAPAndServer();
    multissidTrackers.clear();
    confirmedMultiSSID.clear();
    multissidCount = 0;
    stopRequested = false;
    
    radioStartSTA();
    
    uint32_t scanStart = millis();
    uint32_t lastCleanup = millis();
    
    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        // Cleanup old trackers every 30 seconds
        if (millis() - lastCleanup > 30000) {
            uint32_t now = millis();
            multissidTrackers.erase(
                std::remove_if(multissidTrackers.begin(), multissidTrackers.end(),
                    [now](const MultiSSIDTracker& t) { 
                        return (now - t.last_seen) > 60000; 
                    }),
                multissidTrackers.end());
            lastCleanup = millis();
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Store results
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        std::string results = "Multi-SSID AP Detection Results\n";
        results += "Confirmed Multi-SSID APs: " + std::to_string(confirmedMultiSSID.size()) + "\n\n";
        
        for (const auto& c : confirmedMultiSSID) {
            results += "MAC: " + std::string(macFmt6(c.mac).c_str());
            results += " SSIDs: " + std::to_string(c.ssid_count) + "\n";
        }
        
        antihunter::lastResults = results;
    }
    
    radioStopSTA();
    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}