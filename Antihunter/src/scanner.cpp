#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include <algorithm>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>

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

// Scanner state 
static std::vector<Target> targets;
QueueHandle_t macQueue = nullptr;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern TaskHandle_t blueTeamTaskHandle;

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

volatile bool trackerMode = false;
uint8_t trackerMac[6] = {0};
volatile int8_t trackerRssi = -127;
volatile uint32_t trackerLastSeen = 0;
volatile uint32_t trackerPackets = 0;

volatile bool scanning = false;
volatile int totalHits = 0;
volatile uint32_t framesSeen = 0;
volatile uint32_t bleFramesSeen = 0;

// Detection system 
std::vector<DeauthHit> deauthLog;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;
bool deauthDetectionEnabled = false;
QueueHandle_t deauthQueue = nullptr;

std::vector<BeaconHit> beaconLog;
std::map<String, uint32_t> beaconCounts;
std::map<String, uint32_t> beaconLastSeen;
std::map<String, std::vector<uint32_t>> beaconTimings;
volatile uint32_t totalBeaconsSeen = 0;
volatile uint32_t suspiciousBeacons = 0;
bool beaconFloodDetectionEnabled = false;
QueueHandle_t beaconQueue = nullptr;

extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern String lastResults;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern bool isZeroOrBroadcast(const uint8_t *mac);


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

static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 26) return;
    
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    
    if (ftype != 0 || (subtype != 12 && subtype != 10)) return;
    
    DeauthHit hit;
    memcpy(hit.destMac, p + 4, 6);
    memcpy(hit.srcMac, p + 10, 6);
    memcpy(hit.bssid, p + 16, 6);
    
    hit.rssi = ppkt->rx_ctrl.rssi;
    hit.channel = ppkt->rx_ctrl.channel;
    hit.timestamp = millis();
    hit.isDisassoc = (subtype == 10);
    hit.isBroadcast = (hit.destMac[0] == 0xFF && hit.destMac[1] == 0xFF &&
                       hit.destMac[2] == 0xFF && hit.destMac[3] == 0xFF &&
                       hit.destMac[4] == 0xFF && hit.destMac[5] == 0xFF);
    hit.reasonCode = (ppkt->rx_ctrl.sig_len >= 26) ? u16(p + 24) : 0;
    
    String srcMacStr = macFmt6(hit.srcMac);
    String dstMacStr = macFmt6(hit.destMac);
    uint32_t now = millis();
    
    deauthSourceCounts[srcMacStr]++;
    deauthTargetCounts[dstMacStr]++;
    
    if (deauthTimings[srcMacStr].size() > 100) {
        deauthTimings[srcMacStr].erase(deauthTimings[srcMacStr].begin(), 
                                       deauthTimings[srcMacStr].begin() + 50);
    }
    deauthTimings[srcMacStr].push_back(now);
    
    uint32_t recentCount = 0;
    uint32_t windowStart = now > 1000 ? now - 1000 : 0;
    for (auto& timing : deauthTimings[srcMacStr]) {
        if (timing >= windowStart) {
            recentCount++;
        }
    }
    
    bool isAttack = false;
    String attackType = "";
    
    if (recentCount >= 10) {
        isAttack = true;
        attackType = "Rapid deauth flood (" + String(recentCount) + "/sec)";
    }
    
    if (hit.isBroadcast && recentCount >= 5) {
        isAttack = true;
        attackType = "Broadcast deauth attack";
    }
    
    if (hit.reasonCode >= 1 && hit.reasonCode <= 7 && recentCount >= 3) {
        isAttack = true;
        attackType = "Tool-based deauth (reason:" + String(hit.reasonCode) + ")";
    }
    
    static std::map<String, uint32_t> channelHopTracking;
    static std::map<String, uint8_t> lastChannelSeen;
    
    if (lastChannelSeen[srcMacStr] != 0 && 
        lastChannelSeen[srcMacStr] != hit.channel &&
        now - channelHopTracking[srcMacStr] < 500) {
        isAttack = true;
        attackType = "Channel-hopping deauth attack";
    }
    lastChannelSeen[srcMacStr] = hit.channel;
    channelHopTracking[srcMacStr] = now;
    
    if (isAttack) {
        hit.isDisassoc ? disassocCount++ : deauthCount++;
        
        if (deauthQueue) {
            BaseType_t xHigherPriorityTaskWoken = pdFALSE;
            xQueueSendFromISR(deauthQueue, &hit, &xHigherPriorityTaskWoken);
            if (xHigherPriorityTaskWoken) {
                portYIELD_FROM_ISR();
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
    
    if (ftype != 0 || subtype != 8) return;
    
    BeaconHit hit;
    memcpy(hit.srcMac, p + 10, 6);
    memcpy(hit.bssid, p + 16, 6);
    
    hit.rssi = ppkt->rx_ctrl.rssi;
    hit.channel = ppkt->rx_ctrl.channel;
    hit.timestamp = millis();
    hit.beaconInterval = u16(p + 32);
    
    hit.ssid = "";
    const uint8_t *tags = p + 36;
    uint32_t remaining = ppkt->rx_ctrl.sig_len - 36;
    
    if (remaining >= 2 && tags[0] == 0) {
        uint8_t ssid_len = tags[1];
        if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
            char ssid_str[33] = {0};
            memcpy(ssid_str, tags + 2, ssid_len);
            hit.ssid = String(ssid_str);
            
            for (size_t i = 0; i < hit.ssid.length(); i++) {
                if (hit.ssid[i] < 32 || hit.ssid[i] > 126) {
                    hit.ssid[i] = '?';
                }
            }
        }
    }
    
    totalBeaconsSeen++;
    
    String macStr = macFmt6(hit.srcMac);
    uint32_t now = millis();
    
    static std::map<String, std::set<String>> macToSSIDs;
    static std::map<String, uint8_t> macRandomization;
    static std::map<String, uint32_t> lastMacChange;
    
    macToSSIDs[macStr].insert(hit.ssid);
    beaconCounts[macStr]++;
    beaconLastSeen[macStr] = now;
    
    if (beaconTimings[macStr].size() > 50) {
        beaconTimings[macStr].erase(beaconTimings[macStr].begin(), 
                                   beaconTimings[macStr].begin() + 25);
    }
    beaconTimings[macStr].push_back(now);
    
    bool suspicious = false;
    String reason = "";
    
    if (macToSSIDs[macStr].size() > 5) {
        suspicious = true;
        reason = "Multiple SSIDs from same MAC (" + String(macToSSIDs[macStr].size()) + ")";
    }
    
    if (hit.beaconInterval < 100 || hit.beaconInterval > 1000) {
        suspicious = true;
        reason = "Abnormal beacon interval (" + String(hit.beaconInterval) + "ms)";
    }
    
    uint32_t recentCount = 0;
    uint32_t windowStart = now > 5000 ? now - 5000 : 0;
    for (auto& timing : beaconTimings[macStr]) {
        if (timing >= windowStart) {
            recentCount++;
        }
    }
    
    if (recentCount > 20) {
        suspicious = true;
        reason = "Beacon flood detected (" + String(recentCount) + " in 5s)";
    }
    
    bool hasEmoji = false;
    for (size_t i = 0; i < hit.ssid.length(); i++) {
        if ((uint8_t)hit.ssid[i] > 127) {
            hasEmoji = true;
            break;
        }
    }
    if (hasEmoji) {
        suspicious = true;
        reason = "Emoji/Unicode in SSID (beacon spam tool)";
    }
    
    static std::set<String> recentRandomMacs;
    if (hit.srcMac[0] & 0x02) {
        recentRandomMacs.insert(macStr);
        if (recentRandomMacs.size() > 20) {
            suspicious = true;
            reason = "MAC randomization flood";
            recentRandomMacs.clear();
        }
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

static void IRAM_ATTR detectEvilTwin(const wifi_promiscuous_pkt_t *ppkt)
{
    if (!evilTwinDetectionEnabled)
        return;

    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 36)
        return;

    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (ftype == 0 && subtype == 8)
    {
        uint8_t bssid[6];
        memcpy(bssid, p + 16, 6);
        String bssidStr = macFmt6(bssid);

        uint16_t beaconInterval = u16(p + 32);
        uint16_t capabilities = u16(p + 34);

        String ssid = "";
        const uint8_t *tags = p + 36;
        uint32_t remaining = ppkt->rx_ctrl.sig_len - 36;

        if (remaining >= 2 && tags[0] == 0)
        {
            uint8_t ssid_len = tags[1];
            if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining)
            {
                char ssid_str[33] = {0};
                memcpy(ssid_str, tags + 2, ssid_len);
                ssid = String(ssid_str);
            }
        }

        if (ssid.length() == 0)
            return;

        uint32_t now = millis();
        bool suspicious = false;
        String reason = "";

        if (knownAPs.find(ssid) != knownAPs.end())
        {
            APProfile &known = knownAPs[ssid];

            if (memcmp(known.bssid, bssid, 6) != 0)
            {
                if (abs((int)known.channel - (int)ppkt->rx_ctrl.channel) <= 2)
                {
                    suspicious = true;
                    reason = "Same SSID, different BSSID on nearby channel";
                }
            }

            if (abs((int)known.beaconInterval - (int)beaconInterval) > 50)
            {
                suspicious = true;
                reason += (reason.length() > 0 ? " + " : "") + String("Beacon interval mismatch");
            }

            known.lastSeen = now;
        }
        else
        {
            APProfile newAP;
            newAP.ssid = ssid;
            memcpy(newAP.bssid, bssid, 6);
            newAP.channel = ppkt->rx_ctrl.channel;
            newAP.rssi = ppkt->rx_ctrl.rssi;
            newAP.lastSeen = now;
            newAP.beaconInterval = beaconInterval;
            newAP.capabilities[0] = capabilities & 0xFF;
            newAP.capabilities[1] = (capabilities >> 8) & 0xFF;
            newAP.isLegitimate = true;
            knownAPs[ssid] = newAP;
        }

        if (suspicious)
        {
            EvilTwinHit hit;
            hit.ssid = ssid;
            memcpy(hit.rogueMAC, bssid, 6);
            if (knownAPs.find(ssid) != knownAPs.end())
            {
                memcpy(hit.legitimateMAC, knownAPs[ssid].bssid, 6);
            }
            hit.rssi = ppkt->rx_ctrl.rssi;
            hit.channel = ppkt->rx_ctrl.channel;
            hit.timestamp = now;
            hit.suspicionReason = reason;

            BaseType_t w = false;
            if (evilTwinQueue)
            {
                xQueueSendFromISR(evilTwinQueue, &hit, &w);
                if (w)
                    portYIELD_FROM_ISR();
            }
        }
    }
}

static void IRAM_ATTR detectKarmaAttack(const wifi_promiscuous_pkt_t *ppkt) {
    if (!karmaDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 24) return;
    
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    
    static std::map<String, uint32_t> probeRequestTimes;
    static std::map<String, std::map<String, uint32_t>> apResponsePatterns;
    
    if (ftype == 0 && subtype == 4) {
        uint8_t clientMAC[6];
        memcpy(clientMAC, p + 10, 6);
        String clientMacStr = macFmt6(clientMAC);
        
        String ssid = "";
        const uint8_t *tags = p + 24;
        uint32_t remaining = ppkt->rx_ctrl.sig_len - 24;
        
        if (remaining >= 2 && tags[0] == 0) {
            uint8_t ssid_len = tags[1];
            if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
                char ssid_str[33] = {0};
                memcpy(ssid_str, tags + 2, ssid_len);
                ssid = String(ssid_str);
            }
        }
        
        if (ssid.length() > 0) {
            probeRequestTimes[clientMacStr + ":" + ssid] = millis();
            
            if (clientProbeRequests[clientMacStr].size() > 50) {
                clientProbeRequests[clientMacStr].erase(
                    clientProbeRequests[clientMacStr].begin());
            }
            clientProbeRequests[clientMacStr].push_back(ssid);
        }
    }
    else if (ftype == 0 && subtype == 5) {
        uint8_t apMAC[6];
        memcpy(apMAC, p + 10, 6);
        String apMacStr = macFmt6(apMAC);
        
        uint8_t destMAC[6];
        memcpy(destMAC, p + 4, 6);
        String destMacStr = macFmt6(destMAC);
        
        String ssid = "";
        const uint8_t *tags = p + 24;
        uint32_t remaining = ppkt->rx_ctrl.sig_len - 24;
        
        if (remaining >= 2 && tags[0] == 0) {
            uint8_t ssid_len = tags[1];
            if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
                char ssid_str[33] = {0};
                memcpy(ssid_str, tags + 2, ssid_len);
                ssid = String(ssid_str);
            }
        }
        
        if (ssid.length() > 0) {
            uint32_t now = millis();
            String probeKey = destMacStr + ":" + ssid;
            
            if (probeRequestTimes.find(probeKey) != probeRequestTimes.end()) {
                uint32_t responseTime = now - probeRequestTimes[probeKey];
                
                if (responseTime < 50) {
                    apResponsePatterns[apMacStr][ssid]++;
                    
                    if (apResponsePatterns[apMacStr].size() > 3) {
                        KarmaHit hit;
                        memcpy(hit.apMAC, apMAC, 6);
                        hit.clientSSID = ssid;
                        memcpy(hit.clientMAC, destMAC, 6);
                        hit.rssi = ppkt->rx_ctrl.rssi;
                        hit.channel = ppkt->rx_ctrl.channel;
                        hit.timestamp = now;
                        
                        BaseType_t w = false;
                        if (karmaQueue) {
                            xQueueSendFromISR(karmaQueue, &hit, &w);
                            if (w) portYIELD_FROM_ISR();
                        }
                    }
                }
            }
        }
    }
}

static void IRAM_ATTR detectProbeFlood(const wifi_promiscuous_pkt_t *ppkt) {
    if (!probeFloodDetectionEnabled) return;
    
    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 24) return;
    
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    
    if (ftype != 0 || subtype != 4) return;
    
    uint8_t clientMAC[6];
    memcpy(clientMAC, p + 10, 6);
    String clientMacStr = macFmt6(clientMAC);
    
    uint32_t now = millis();
    probeRequestCounts[clientMacStr]++;
    
    if (probeTimings[clientMacStr].size() > 200) {
        probeTimings[clientMacStr].erase(probeTimings[clientMacStr].begin(), 
                                         probeTimings[clientMacStr].begin() + 100);
    }
    probeTimings[clientMacStr].push_back(now);
    
    uint32_t recentCount = 0;
    uint32_t windowStart = now > 1000 ? now - 1000 : 0;
    for (auto& timing : probeTimings[clientMacStr]) {
        if (timing >= windowStart) {
            recentCount++;
        }
    }
    
    static std::map<String, std::set<String>> clientSSIDRequests;
    static std::map<String, uint32_t> lastMacSeen;
    
    String ssid = "";
    const uint8_t *tags = p + 24;
    uint32_t remaining = ppkt->rx_ctrl.sig_len - 24;
    
    if (remaining >= 2 && tags[0] == 0) {
        uint8_t ssid_len = tags[1];
        if (ssid_len > 0 && ssid_len <= 32 && ssid_len + 2 <= remaining) {
            char ssid_str[33] = {0};
            memcpy(ssid_str, tags + 2, ssid_len);
            ssid = String(ssid_str);
        }
    }
    
    if (ssid.length() > 0) {
        clientSSIDRequests[clientMacStr].insert(ssid);
    }
    
    bool isFlood = false;
    String reason = "";
    
    if (recentCount >= 100) {
        isFlood = true;
        reason = "MDK4-style probe flood (" + String(recentCount) + "/sec)";
    }
    
    if (clientSSIDRequests[clientMacStr].size() > 20 && recentCount > 50) {
        isFlood = true;
        reason = "Wordlist probe attack (" + String(clientSSIDRequests[clientMacStr].size()) + " SSIDs)";
    }
    
    if (clientMAC[0] & 0x02) {
        if (lastMacSeen.find(clientMacStr) == lastMacSeen.end()) {
            lastMacSeen[clientMacStr] = now;
        }
        
        uint32_t randomMacCount = 0;
        for (auto& entry : lastMacSeen) {
            if (now - entry.second < 5000) {
                randomMacCount++;
            }
        }
        
        if (randomMacCount > 50) {
            isFlood = true;
            reason = "MAC randomization flood";
        }
    }
    
    if (isFlood) {
        ProbeFloodHit hit;
        memcpy(hit.clientMAC, clientMAC, 6);
        hit.ssid = ssid;
        hit.probeCount = recentCount;
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = now;
        
        BaseType_t w = false;
        if (probeFloodQueue) {
            xQueueSendFromISR(probeFloodQueue, &hit, &w);
            if (w) portYIELD_FROM_ISR();
        }
    }
}

static void IRAM_ATTR detectEAPOLHarvesting(const wifi_promiscuous_pkt_t *ppkt)
{
    if (!eapolDetectionEnabled)
        return;

    const uint8_t *p = ppkt->payload;
    if (ppkt->rx_ctrl.sig_len < 32)
        return;

    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;

    if (ftype == 2)
    {
        const uint8_t *llc = p + 24;
        if (ppkt->rx_ctrl.sig_len >= 32 &&
            llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
            llc[6] == 0x88 && llc[7] == 0x8E)
        {

            uint8_t clientMAC[6], apMAC[6];
            memcpy(apMAC, p + 4, 6);
            memcpy(clientMAC, p + 10, 6);

            const uint8_t *eapol = llc + 8;
            uint8_t eapolType = eapol[1];
            uint8_t keyInfo = eapol[5];

            bool hasPMKID = false;
            if (ppkt->rx_ctrl.sig_len > 95)
            {
                for (int i = 0; i < ppkt->rx_ctrl.sig_len - 95; i++)
                {
                    if (eapol[i] == 0xDD && eapol[i + 1] >= 0x14 &&
                        eapol[i + 2] == 0x00 && eapol[i + 3] == 0x0F &&
                        eapol[i + 4] == 0xAC && eapol[i + 5] == 0x04)
                    {
                        hasPMKID = true;
                        break;
                    }
                }
            }

            String apMacStr = macFmt6(apMAC);
            eapolCaptureAttempts[apMacStr]++;

            EAPOLHit hit;
            memcpy(hit.clientMAC, clientMAC, 6);
            memcpy(hit.apMAC, apMAC, 6);
            hit.ssid = "";
            hit.messageType = keyInfo;
            hit.hasPMKID = hasPMKID;
            hit.rssi = ppkt->rx_ctrl.rssi;
            hit.channel = ppkt->rx_ctrl.channel;
            hit.timestamp = millis();

            BaseType_t w = false;
            if (eapolQueue)
            {
                xQueueSendFromISR(eapolQueue, &hit, &w);
                if (w)
                    portYIELD_FROM_ISR();
            }
        }
    }
}

// Main NimBLE callback
class MyBLEAdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen++;

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
                trackerPackets++;
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

// BLE Attack callback
class BLEAttackDetector : public NimBLEAdvertisedDeviceCallbacks {
private:
    std::map<String, uint32_t> macLastSeen;
    std::map<String, uint32_t> macCounts;
    std::map<String, std::set<String>> macToNames;
    
public:
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;
        
        uint32_t now = millis();
        macCounts[macStr]++;
        
        if (bleAdvTimings[macStr].size() > 100) {
            bleAdvTimings[macStr].erase(bleAdvTimings[macStr].begin(), 
                                       bleAdvTimings[macStr].begin() + 50);
        }
        bleAdvTimings[macStr].push_back(now);
        
        String deviceName = "";
        if (advertisedDevice->haveName()) {
            deviceName = advertisedDevice->getName().c_str();
        }
        
        if (deviceName.length() > 0) {
            macToNames[macStr].insert(deviceName);
        }
        
        detectAppleSpam(advertisedDevice, macStr, mac);
        detectFastPairSpam(advertisedDevice, macStr, mac);
        detectTrackerSpam(advertisedDevice, macStr, mac);
        
        macLastSeen[macStr] = now;
    }
    
private:
    void detectAppleSpam(NimBLEAdvertisedDevice* device, const String& macStr, uint8_t* mac) {
        if (!device->haveManufacturerData()) return;
        
        std::string manData = device->getManufacturerData();
        if (manData.length() < 4) return;
        
        uint16_t companyId = (manData[1] << 8) | manData[0];
        if (companyId != 0x004C) return;
        
        uint8_t appleType = manData[2];
        uint32_t now = millis();
        
        uint32_t recentCount = 0;
        for (auto& timing : bleAdvTimings[macStr]) {
            if (now - timing < BLE_TIMING_WINDOW) recentCount++;
        }
        
        if (recentCount > BLE_SPAM_THRESHOLD) {
            BLESpamHit hit;
            memcpy(hit.mac, mac, 6);
            hit.advType = appleType;
            strncpy(hit.deviceName, "", sizeof(hit.deviceName) - 1);
            hit.rssi = device->getRSSI();
            hit.timestamp = now;
            hit.advCount = recentCount;
            
            const char* spamType = "";
            if (appleType == 0x07) spamType = "AirPods spam";
            else if (appleType == 0x09) spamType = "AppleTV spam";
            else if (appleType == 0x10) spamType = "Nearby Action spam";
            else if (appleType == 0x0F) spamType = "Continuity spam";
            else spamType = "Apple device spam";
            
            strncpy(hit.spamType, spamType, sizeof(hit.spamType) - 1);
            
            if (bleSpamQueue && bleSpamLog.size() < 1000) {
                xQueueSend(bleSpamQueue, &hit, 0);
                bleSpamLog.push_back(hit);
                bleSpamCount = bleSpamCount + 1;
            }
        }
    }
    
    void detectFastPairSpam(NimBLEAdvertisedDevice* device, const String& macStr, uint8_t* mac) {
        NimBLEUUID fastPairUUID = NimBLEUUID("0000FE2C-0000-1000-8000-00805F9B34FB");
        
        if (!device->isAdvertisingService(fastPairUUID)) return;
        
        uint32_t now = millis();
        uint32_t recentCount = 0;
        for (auto& timing : bleAdvTimings[macStr]) {
            if (now - timing < BLE_TIMING_WINDOW) recentCount++;
        }
        
        if (recentCount > BLE_SPAM_THRESHOLD) {
            BLESpamHit hit;
            memcpy(hit.mac, mac, 6);
            hit.advType = 0xFE;
            strncpy(hit.deviceName, device->haveName() ? device->getName().c_str() : "", sizeof(hit.deviceName) - 1);
            hit.rssi = device->getRSSI();
            hit.timestamp = now;
            hit.advCount = recentCount;
            strncpy(hit.spamType, "Fast Pair spam", sizeof(hit.spamType) - 1);
            
            if (bleSpamQueue && bleSpamLog.size() < 1000) {
                xQueueSend(bleSpamQueue, &hit, 0);
                bleSpamLog.push_back(hit);
                bleSpamCount = bleSpamCount + 1;
            }
        }
    }
    
    void detectTrackerSpam(NimBLEAdvertisedDevice* device, const String& macStr, uint8_t* mac) {
        bool isTracker = false;
        const char* trackerType = "";
        
        if (device->haveName()) {
            std::string name = device->getName();
            if (name.find("AirTag") != std::string::npos) {
                isTracker = true;
                trackerType = "AirTag";
            } else if (name.find("Tile") != std::string::npos) {
                isTracker = true;
                trackerType = "Tile";
            } else if (name.find("SmartTag") != std::string::npos) {
                isTracker = true;
                trackerType = "SmartTag";
            }
        }
        
        if (isTracker) {
            uint32_t now = millis();
            uint32_t recentCount = 0;
            for (auto& timing : bleAdvTimings[macStr]) {
                if (now - timing < 5000) recentCount++;
            }
            
            if (recentCount > 30) {
                BLESpamHit hit;
                memcpy(hit.mac, mac, 6);
                hit.advType = 0x12;
                strncpy(hit.deviceName, trackerType, sizeof(hit.deviceName) - 1);
                hit.rssi = device->getRSSI();
                hit.timestamp = now;
                hit.advCount = recentCount;
                
                char spamMsg[32];
                snprintf(spamMsg, sizeof(spamMsg), "%s flood", trackerType);
                strncpy(hit.spamType, spamMsg, sizeof(hit.spamType) - 1);
                
                if (bleSpamQueue && bleSpamLog.size() < 1000) {
                    xQueueSend(bleSpamQueue, &hit, 0);
                    bleSpamLog.push_back(hit);
                    bleSpamCount = bleSpamCount + 1;
                }
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
        
        delay(100);
    }
    
    bleSpamDetectionEnabled = false;
    pBLEScan->stop();
    BLEDevice::deinit(false);
    
    lastResults = "BLE Attack Detection Results\n";
    lastResults += "Duration: " + (forever ? "Forever" : String(duration)) + "s\n";
    lastResults += "Spam attacks: " + String(bleSpamCount) + "\n";
    lastResults += "Anomalies: " + String(bleAnomalyCount) + "\n\n";
    
    std::map<String, uint32_t> spamTypes;
    for (const auto& hit : bleSpamLog) {
        spamTypes[String(hit.spamType)]++;
    }
    
    for (const auto& entry : spamTypes) {
        lastResults += entry.first + ": " + String(entry.second) + " attacks\n";
    }
    
    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void snifferScanTask(void *pv)
{
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[SNIFFER] Starting device scan %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    stopAPAndServer();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

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

        // WiFi Network Scan
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
        }

        // BLE Device Scan
        if (millis() - lastBLEScan >= BLE_SCAN_INTERVAL || lastBLEScan == 0)
        {
            lastBLEScan = millis();

            Serial.println("[SNIFFER] Scanning BLE devices...");

            if (bleScan)
            {
                BLEScanResults scanResults = bleScan->start(3, false);

                for (int i = 0; i < scanResults.getCount(); i++)
                {
                    BLEAdvertisedDevice device = scanResults.getDevice(i);
                    String macStr = device.getAddress().toString().c_str();

                    if (bleDeviceCache.find(macStr) == bleDeviceCache.end())
                    {
                        String name = device.haveName() ? device.getName().c_str() : "Unknown";

                        // Clean device name
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
            }
        }

        Serial.printf("[SNIFFER] Total: WiFi APs=%d, BLE=%d, Unique=%d, Hits=%d\n",
                      apCache.size(), bleDeviceCache.size(), uniqueMacs.size(), totalHits);

        delay(200);
    }

    if (bleScan)
    {
        bleScan->stop();
        BLEDevice::deinit(false);
    }

    scanning = false;
    lastScanEnd = millis();

    lastResults = "Scan Results\n";
    lastResults += "Mode: " + String(currentScanMode == SCAN_WIFI ? "WiFi" : 
                                     currentScanMode == SCAN_BLE ? "BLE" : "WiFi+BLE") + "\n";
    lastResults += "Duration: " + String(lastScanForever ? "Forever" : String(lastScanSecs) + "s") + "\n";
    lastResults += "Unique devices: " + String(uniqueMacs.size()) + "\n";
    lastResults += "Total hits: " + String(totalHits) + "\n\n";
    
    // Sort by RSSI
    std::vector<Hit> sortedHits = hitsLog;
    std::sort(sortedHits.begin(), sortedHits.end(), 
              [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });
    
    int shown = 0;
    for (const auto& hit : sortedHits) {
        if (shown++ >= 100) break;
        
        lastResults += String(hit.isBLE ? "BLE  " : "WiFi ");
        lastResults += macFmt6(hit.mac);
        lastResults += " RSSI=" + String(hit.rssi) + "dBm";
        
        if (!hit.isBLE && hit.ch > 0) {
            lastResults += " CH=" + String(hit.ch);
        }
        
        if (strlen(hit.name) > 0 && strcmp(hit.name, "WiFi") != 0 && strcmp(hit.name, "Unknown") != 0) {
            lastResults += " \"" + String(hit.name) + "\"";
        }
        
        lastResults += "\n";
    }
    
    if (sortedHits.size() > 100) {
        lastResults += "... (" + String(sortedHits.size() - 100) + " more)\n";
    }

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

    Serial.printf("[BLUE] Starting deauth detection %s\n",
                  forever ? "(forever)" : ("for " + String(duration) + "s").c_str());

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

    WiFi.mode(WIFI_MODE_STA);
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    esp_wifi_start();

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    const esp_timer_create_args_t targs = {.callback = &hopTimerCb, .arg = nullptr, .dispatch_method = ESP_TIMER_TASK, .name = "hop"};
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, 150000);

    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    DeauthHit hit;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        if (xQueueReceive(deauthQueue, &hit, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (deauthLog.size() < 1000) {
                deauthLog.push_back(hit);
            }
            
            String alert = String(hit.isDisassoc ? "DISASSOC" : "DEAUTH") + " detected! ";
            alert += "SRC:" + macFmt6(hit.srcMac) + " DST:" + macFmt6(hit.destMac);
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
            alert += " Reason:" + String(hit.reasonCode);
            
            Serial.println("[ALERT] " + alert);
            logToSD(alert);
            
            beepPattern(3, 50);
            
            if (meshEnabled) {
                String meshAlert = getNodeId() + ": ATTACK: " + alert;
                if (gpsValid) {
                    meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                }
                if (Serial1.availableForWrite() >= meshAlert.length()) {
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
                        newTimings[entry.first] = std::vector<uint32_t>(
                            entry.second.end() - 20, entry.second.end());
                    } else {
                        newTimings[entry.first] = entry.second;
                    }
                }
                deauthTimings = newTimings;
            }
            lastCleanup = millis();
        }
        
        delay(10);
    }

    deauthDetectionEnabled = false;
    esp_wifi_set_promiscuous(false);
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    esp_wifi_stop();

    lastResults = "Deauth Detection Results\n";
    lastResults += "Duration: " + (forever ? "Forever" : String(duration)) + "s\n";
    lastResults += "Deauth frames: " + String(deauthCount) + "\n";
    lastResults += "Disassoc frames: " + String(disassocCount) + "\n";
    lastResults += "Total attacks: " + String(deauthLog.size()) + "\n\n";

    int show = min((int)deauthLog.size(), 100);
    for (int i = 0; i < show; i++) {
        const auto &h = deauthLog[i];
        lastResults += String(h.isDisassoc ? "DISASSOC" : "DEAUTH") + " ";
        lastResults += macFmt6(h.srcMac) + " -> " + macFmt6(h.destMac);
        lastResults += " BSSID:" + macFmt6(h.bssid);
        lastResults += " RSSI:" + String(h.rssi) + "dBm";
        lastResults += " CH:" + String(h.channel);
        lastResults += " Reason:" + String(h.reasonCode) + "\n";
    }

    if ((int)deauthLog.size() > show) {
        lastResults += "... (" + String((int)deauthLog.size() - show) + " more)\n";
    }

    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void beaconFloodTask(void *pv)
{
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

    if (beaconQueue)
    {
        vQueueDelete(beaconQueue);
    }
    beaconQueue = xQueueCreate(256, sizeof(BeaconHit));

    WiFi.mode(WIFI_MODE_STA);
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    esp_wifi_start();

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (hopTimer)
    {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    const esp_timer_create_args_t targs = {.callback = &hopTimerCb, .arg = nullptr, .dispatch_method = ESP_TIMER_TASK, .name = "hop"};
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, 100000);

    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    BeaconHit hit;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested))
    {

        if (xQueueReceive(beaconQueue, &hit, pdMS_TO_TICKS(100)) == pdTRUE)
        {
            beaconLog.push_back(hit);

            String alert = "BEACON FLOOD! MAC:" + macFmt6(hit.srcMac);
            alert += " SSID:" + (hit.ssid.length() > 0 ? hit.ssid : "[Hidden]");
            alert += " Count:" + String(beaconCounts[macFmt6(hit.srcMac)]);
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);

            Serial.println("[ALERT] " + alert);
            logToSD(alert);

            beepPattern(4, 40);

            if (meshEnabled)
            {
                String meshAlert = getNodeId() + ": FLOOD: " + alert;
                if (gpsValid)
                {
                    meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                }
                Serial1.println(meshAlert);
            }
        }

        if ((int32_t)(millis() - nextStatus) >= 0)
        {
            Serial.printf("[BEACON] Total:%u Suspicious:%u Unique MACs:%u\n",
                          totalBeaconsSeen, suspiciousBeacons, (unsigned)beaconCounts.size());
            nextStatus += 5000;
        }

        delay(10);
    }

    beaconFloodDetectionEnabled = false;
    esp_wifi_set_promiscuous(false);
    if (hopTimer)
    {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    esp_wifi_stop();

    lastResults = "Beacon Flood Detection Results\n";
    lastResults += "Duration: " + (forever ? "∞" : String(duration)) + "s\n";
    lastResults += "Total beacons: " + String(totalBeaconsSeen) + "\n";
    lastResults += "Suspicious beacons: " + String(suspiciousBeacons) + "\n";
    lastResults += "Unique MACs: " + String(beaconCounts.size()) + "\n\n";

    std::vector<std::pair<String, uint32_t>> sorted;
    for (const auto &entry : beaconCounts)
    {
        sorted.push_back({entry.first, entry.second});
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const auto &a, const auto &b)
              { return a.second > b.second; });

    int show = min((int)sorted.size(), 50);
    for (int i = 0; i < show; i++)
    {
        lastResults += sorted[i].first + " : " + String(sorted[i].second) + " beacons\n";
    }

    if ((int)sorted.size() > show)
    {
        lastResults += "... (" + String((int)sorted.size() - show) + " more MACs)\n";
    }

    startAPAndServer();
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;

    detectDeauthFrame(ppkt);
    detectBeaconFlood(ppkt);
    detectEvilTwin(ppkt);
    detectKarmaAttack(ppkt);
    detectProbeFlood(ppkt);
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
                if (now - deviceLastSeen[macStr] < DEDUPE_WINDOW) {
                    continue;
                }
            }
            
            deviceLastSeen[macStr] = now;
            totalHits++;
            hitsLog.push_back(h);
            uniqueMacs.insert(macStr);

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macStr +
                            " RSSI=" + String(h.rssi) + "dBm";
            if (!h.isBLE && h.ch > 0) {
                logEntry += " CH=" + String(h.ch);
            }
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

        delay(50);
    }

    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    lastResults = String("List scan - Mode: ") + modeStr + " Duration: " + (forever ? "Forever" : String(secs)) + "s\n";
    lastResults += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    lastResults += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
    lastResults += "Total hits: " + String(totalHits) + "\n";
    lastResults += "Unique devices: " + String((int)uniqueMacs.size()) + "\n\n";

    std::vector<Hit> sortedHits = hitsLog;
    std::sort(sortedHits.begin(), sortedHits.end(), 
              [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

    int show = sortedHits.size();
    if (show > 200) show = 200;
    for (int i = 0; i < show; i++) {
        const auto &e = sortedHits[i];
        lastResults += String(e.isBLE ? "BLE " : "WiFi") + " " + macFmt6(e.mac) + " RSSI=" + String((int)e.rssi) + "dBm";
        if (!e.isBLE) lastResults += " CH=" + String((int)e.ch);
        if (strlen(e.name) > 0 && strcmp(e.name, "WiFi") != 0) {
            lastResults += " Name=" + String(e.name);
        }
        lastResults += "\n";
    }
    if ((int)sortedHits.size() > show) {
        lastResults += "... (" + String((int)sortedHits.size() - show) + " more)\n";
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

void cleanupMaps() {
    const size_t MAX_MAP_SIZE = 100;
    const size_t MAX_TIMING_SIZE = 50;
    
    if (deauthTimings.size() > MAX_MAP_SIZE) {
        std::map<String, std::vector<uint32_t>> newMap;
        int count = 0;
        for (auto it = deauthTimings.rbegin(); it != deauthTimings.rend() && count < MAX_MAP_SIZE/2; ++it, ++count) {
            newMap[it->first] = it->second;
        }
        deauthTimings = newMap;
    }
    
    for (auto& entry : deauthTimings) {
        if (entry.second.size() > MAX_TIMING_SIZE) {
            entry.second.erase(entry.second.begin(), entry.second.begin() + (entry.second.size() - MAX_TIMING_SIZE));
        }
    }
    
    if (beaconTimings.size() > MAX_MAP_SIZE) {
        std::map<String, std::vector<uint32_t>> newMap;
        int count = 0;
        for (auto it = beaconTimings.rbegin(); it != beaconTimings.rend() && count < MAX_MAP_SIZE/2; ++it, ++count) {
            newMap[it->first] = it->second;
        }
        beaconTimings = newMap;
    }
    
    if (probeTimings.size() > MAX_MAP_SIZE) {
        std::map<String, std::vector<uint32_t>> newMap;
        int count = 0;
        for (auto it = probeTimings.rbegin(); it != probeTimings.rend() && count < MAX_MAP_SIZE/2; ++it, ++count) {
            newMap[it->first] = it->second;
        }
        probeTimings = newMap;
    }
    
    if (bleAdvTimings.size() > MAX_MAP_SIZE) {
        std::map<String, std::vector<uint32_t>> newMap;
        int count = 0;
        for (auto it = bleAdvTimings.rbegin(); it != bleAdvTimings.rend() && count < MAX_MAP_SIZE/2; ++it, ++count) {
            newMap[it->first] = it->second;
        }
        bleAdvTimings = newMap;
    }
    
    if (deauthLog.size() > 1000) {
        deauthLog.erase(deauthLog.begin(), deauthLog.begin() + 500);
    }
    
    if (beaconLog.size() > 1000) {
        beaconLog.erase(beaconLog.begin(), beaconLog.begin() + 500);
    }
    
    if (bleSpamLog.size() > 1000) {
        bleSpamLog.erase(bleSpamLog.begin(), bleSpamLog.begin() + 500);
    }
}