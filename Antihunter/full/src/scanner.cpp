#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include <algorithm>
#include "randomization.h"
#include <string>
#include <mutex>
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "triangulation.h"
#include "baseline.h"
#include "main.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
}

// RF handlers
void radioStartSTA();
void radioStopSTA();
void radioStartBLE();
void radioStopBLE();

// Scanner state variables
extern Preferences prefs;
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

// BLE 
NimBLEScan *pBLEScan;
static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);

// Scan intervals
uint32_t WIFI_SCAN_INTERVAL = 4000;
uint32_t BLE_SCAN_INTERVAL = 2000;

// Scanner status variables
volatile bool scanning = false;
volatile int totalHits = 0;
volatile uint32_t framesSeen = 0;
volatile uint32_t bleFramesSeen = 0;

std::map<String, DeviceHistory> deviceHistory;
uint32_t deviceAbsenceThreshold = 120000;
uint32_t reappearanceAlertWindow = 300000;
int8_t significantRssiChange = 20;

std::vector<Allowlist> allowlist;

// Scan config
RFScanConfig rfConfig = {
    .wifiChannelTime = 120,
    .wifiScanInterval = 6000,
    .bleScanInterval = 2000,
    .bleScanDuration = 3000,
    .preset = 1,
    .wifiChannels = "1..14",
    .globalRssiThreshold = -90
};

void setRFPreset(uint8_t preset) {
    switch(preset) {
        case 0:
            rfConfig.wifiChannelTime = 300;
            rfConfig.wifiScanInterval = 8000;
            rfConfig.bleScanInterval = 4000;
            rfConfig.bleScanDuration = 3000;
            rfConfig.globalRssiThreshold = -80;
            break;
        case 1:
            rfConfig.wifiChannelTime = 160;
            rfConfig.wifiScanInterval = 6000;
            rfConfig.bleScanInterval = 3000;
            rfConfig.bleScanDuration = 3000;
            rfConfig.globalRssiThreshold = -90;
            break;
        case 2:
            rfConfig.wifiChannelTime = 110;
            rfConfig.wifiScanInterval = 4000;
            rfConfig.bleScanInterval = 2000;
            rfConfig.bleScanDuration = 2000;
            rfConfig.globalRssiThreshold = -70;
            break;
        default:
            preset = 1;
            setRFPreset(1);
            return;
    }
    rfConfig.preset = preset;
    WIFI_SCAN_INTERVAL = rfConfig.wifiScanInterval;
    BLE_SCAN_INTERVAL = rfConfig.bleScanInterval;
    
    prefs.putUInt("rfPreset", preset);
    prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
    
    Serial.printf("[RF] Preset %d: WiFi chan=%dms interval=%dms, BLE interval=%dms duration=%dms, RSSI threshold=%ddBm\n",
                 preset, rfConfig.wifiChannelTime, rfConfig.wifiScanInterval, 
                 rfConfig.bleScanInterval, rfConfig.bleScanDuration, rfConfig.globalRssiThreshold);
}

void setCustomRFConfig(uint32_t wifiChanTime, uint32_t wifiInterval, uint32_t bleInterval, uint32_t bleDuration, const String &channels, int8_t rssiThreshold) {
    rfConfig.wifiChannelTime = constrain(wifiChanTime, 50, 300);
    rfConfig.wifiScanInterval = constrain(wifiInterval, 1000, 10000);
    rfConfig.bleScanInterval = constrain(bleInterval, 1000, 10000);
    rfConfig.bleScanDuration = constrain(bleDuration, 1000, 5000);
    rfConfig.globalRssiThreshold = constrain(rssiThreshold, -128, -10);
    rfConfig.preset = 3;
    
    if (channels.length() > 0) {
        rfConfig.wifiChannels = channels;
        parseChannelsCSV(channels);
        prefs.putString("channels", channels);
    }
    
    WIFI_SCAN_INTERVAL = rfConfig.wifiScanInterval;
    BLE_SCAN_INTERVAL = rfConfig.bleScanInterval;
    
    prefs.putUInt("wifiChanTime", rfConfig.wifiChannelTime);
    prefs.putUInt("wifiInterval", rfConfig.wifiScanInterval);
    prefs.putUInt("bleInterval", rfConfig.bleScanInterval);
    prefs.putUInt("bleDuration", rfConfig.bleScanDuration);
    prefs.putInt("globalRSSI", rfConfig.globalRssiThreshold);
    prefs.putUInt("rfPreset", 3);
    
    Serial.printf("[RF] Custom config: WiFi chan=%dms interval=%dms, BLE interval=%dms duration=%dms, RSSI threshold=%ddBm%s\n",
                 rfConfig.wifiChannelTime, rfConfig.wifiScanInterval, 
                 rfConfig.bleScanInterval, rfConfig.bleScanDuration,
                 rfConfig.globalRssiThreshold,
                 channels.length() > 0 ? (", channels=" + channels).c_str() : "");
}

RFScanConfig getRFConfig() {
    return rfConfig;
}

int8_t getGlobalRssiThreshold() {
    return rfConfig.globalRssiThreshold;
}

void setGlobalRssiThreshold(int8_t threshold) {
    if (threshold >= -128 && threshold <= -10) {
        rfConfig.globalRssiThreshold = threshold;
        prefs.putInt("globalRSSI", threshold);
        Serial.printf("[RF] Global RSSI threshold set to %d dBm\n", threshold);
    }
}

void loadRFConfigFromPrefs() {
    uint8_t preset = prefs.getUInt("rfPreset", 1);
    if (preset < 3) {
        setRFPreset(preset);
    } else {
        uint32_t wct = prefs.getUInt("wifiChanTime", 120);
        uint32_t wsi = prefs.getUInt("wifiInterval", 5000);
        uint32_t bsi = prefs.getUInt("bleInterval", 2000);
        uint32_t bsd = prefs.getUInt("bleDuration", 3000);
        String channels = prefs.getString("channels", "1..14");
        int8_t rssiThreshold = prefs.getInt("globalRSSI", -90);
        setCustomRFConfig(wct, wsi, bsi, bsd, channels, rssiThreshold);
    }
    
    Serial.printf("[RF] Loaded config - Preset: %d, RSSI threshold: %d dBm\n", rfConfig.preset, rfConfig.globalRssiThreshold);
}

// Detection system variables
std::vector<DeauthHit> deauthLog;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;
bool deauthDetectionEnabled = false;
QueueHandle_t deauthQueue = nullptr;
volatile uint32_t req_frames = 0;
volatile uint32_t resp_frames = 0; 
volatile uint32_t bleAnomalyCount = 0;
QueueHandle_t bleAnomalyQueue = nullptr;

// Deauth Detection
std::map<String, uint32_t> deauthSourceCounts;
std::map<String, uint32_t> deauthTargetCounts;
std::map<String, std::vector<uint32_t>> deauthTimings;

// Triangulation
TriangulationAccumulator triAccum = {0};
static const uint32_t TRI_SEND_INTERVAL = 2000;

// External declarations
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern bool isZeroOrBroadcast(const uint8_t *mac);

// Helper functions 
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
    if (ln.startsWith("T-") && ln.length() >= 6 && ln.length() <= 9) {
        // T-#### format
        bool validId = true;
        for (size_t i = 2; i < ln.length(); i++) {
            if (!isdigit(ln[i])) {
                validId = false;
                break;
            }
        }
        
        if (validId) {
            memset(&out, 0, sizeof(out));
            strncpy(out.identityId, ln.c_str(), sizeof(out.identityId) - 1);
            out.identityId[sizeof(out.identityId) - 1] = '\0';
            out.len = 0;  // 0 indicates identity ID, not MAC
            return true;
        }
    }
    
    // MAC
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

bool matchesIdentityMac(const char* identityId, const uint8_t* mac)
{
    if (!identityId || strlen(identityId) == 0 || !mac) {
        return false;
    }

    extern std::map<String, DeviceIdentity> deviceIdentities;
    extern std::mutex randMutex;
    
    std::lock_guard<std::mutex> lock(randMutex);

    String idStr(identityId);
    auto it = deviceIdentities.find(idStr);
    if (it == deviceIdentities.end()) {
        return false;
    }
    
    const DeviceIdentity& identity = it->second;
    
    for (const auto& macAddr : identity.macs) {
        if (memcmp(macAddr.bytes.data(), mac, 6) == 0) {
            return true;
        }
    }
    
    return false;
}

String getTargetsList()
{
    String out;
    for (auto &t : targets)
    {
        if (t.len == 0 && strlen(t.identityId) > 0) {
            out += String(t.identityId);
        }
        else if (t.len == 6)
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

static inline bool matchesMac(const uint8_t *mac)
{
    for (auto &t : targets)
    {
        if (t.len == 0 && strlen(t.identityId) > 0) {
            if (matchesIdentityMac(t.identityId, mac)) {
                return true;
            }
        }
        else if (t.len == 6)
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
        else if (t.len == 3)
        {
            if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2])
            {
                return true;
            }
        }
    }
    return false;
}


static void hopTimerCb(void *)
{
    if (!hopTimer || CHANNELS.empty()) return;
    static size_t idx = 0;
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

// Deauth type
String getDeauthReasonText(uint16_t reasonCode) {
    switch (reasonCode) {
        case 1: return "Unspecified reason";
        case 2: return "Previous authentication no longer valid";
        case 6: return "Class 2 frame from non-authenticated station";
        case 7: return "Class 3 frame from non-associated station";
        default: return "Reason code " + String(reasonCode);
    }
}

static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 26) return;
    
    const uint8_t *payload = ppkt->payload;
    
    uint8_t version = (payload[0] & 0x03);
    uint8_t type = (payload[0] >> 2) & 0x03;
    uint8_t subtype = (payload[0] >> 4) & 0x0F;
    
    if (type != 0 || version != 0) return;
    
    bool isDisassoc = (subtype == 0x0A);
    bool isDeauth = (subtype == 0x0C);
    
    if (!isDisassoc && !isDeauth) return;
    
    DeauthHit hit;
    memcpy(hit.destMac, payload + 4, 6);
    memcpy(hit.srcMac, payload + 10, 6);
    memcpy(hit.bssid, payload + 16, 6);
    
    hit.reasonCode = (ppkt->rx_ctrl.sig_len >= 26) 
                     ? (payload[24] | (payload[25] << 8)) 
                     : 0;
    
    hit.rssi = ppkt->rx_ctrl.rssi;
    hit.channel = ppkt->rx_ctrl.channel;
    hit.timestamp = millis();
    hit.isDisassoc = isDisassoc;
    hit.isBroadcast = (memcmp(hit.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0);
    
    bool isAttack = false;
    
    if (hit.isBroadcast) {
        isAttack = true;
    }
    
    static std::map<String, std::vector<uint32_t>> targetHistory;
    static uint32_t lastCleanupTime = 0;
    
    String destMacStr = macFmt6(hit.destMac);
    uint32_t now = millis();
    
    targetHistory[destMacStr].push_back(now);
    
    auto& times = targetHistory[destMacStr];
    times.erase(
        std::remove_if(times.begin(), times.end(),
            [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }),
        times.end()
    );
    
    if (times.size() >= DEAUTH_TARGETED_THRESHOLD) {
        isAttack = true;
    }
    
    if (hit.reasonCode == 1 || hit.reasonCode == 2 || 
        hit.reasonCode == 6 || hit.reasonCode == 7) {
        isAttack = true;
    }
    
    if ((now - lastCleanupTime) > DEAUTH_CLEANUP_INTERVAL) {
        for (auto it = targetHistory.begin(); it != targetHistory.end(); ) {
            auto& vec = it->second;
            vec.erase(
                std::remove_if(vec.begin(), vec.end(),
                    [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }),
                vec.end()
            );
            
            if (vec.empty()) {
                it = targetHistory.erase(it);
            } else {
                ++it;
            }
        }
        
        if (targetHistory.size() > DEAUTH_HISTORY_MAX_SIZE) {
            size_t toRemove = targetHistory.size() - DEAUTH_HISTORY_MAX_SIZE;
            auto it = targetHistory.begin();
            for (size_t i = 0; i < toRemove && it != targetHistory.end(); ++i) {
                it = targetHistory.erase(it);
            }
        }
        
        lastCleanupTime = now;
    }
    
    if (isAttack) {
        if (hit.isDisassoc) {
            disassocCount = disassocCount + 1;
        } else {
            deauthCount = deauthCount + 1;
        }
        
        if (deauthLog.size() < MAX_LOG_SIZE) {
            deauthLog.push_back(hit);
        }
        
        String alert = "[DEAUTH] ";
        alert += hit.isDisassoc ? "DISASSOC " : "DEAUTH ";
        alert += macFmt6(hit.srcMac) + " -> " + destMacStr;
        alert += " RSSI:" + String(hit.rssi) + " CH:" + String(hit.channel);
        alert += " | " + getDeauthReasonText(hit.reasonCode);
        
        if (hit.isBroadcast) {
            alert += " [BROADCAST ATTACK]";
        } else {
            alert += " [TARGETED x" + String(times.size()) + "]";
        }
        
        Serial.println(alert);
        logToSD(alert);
    }
}

// Main NimBLE callback
class MyBLEScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        int8_t rssi = advertisedDevice->getRSSI();
        if (!triangulationActive && rssi < rfConfig.globalRssiThreshold) {
            return;
        }

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

        bool isMatch = false;
        if (triangulationActive) {
            isMatch = (memcmp(mac, triangulationTarget, 6) == 0);
        } else {
            isMatch = matchesMac(mac);
        }
        
        if (isMatch) {
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
};

void snifferScanTask(void *pv)
{
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                 (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[SNIFFER] Starting device scan %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    } else if (currentScanMode == SCAN_BLE) {
        vTaskDelay(pdMS_TO_TICKS(100));
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

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
    unsigned long lastMeshUpdate = 0;
    const unsigned long BLE_SCAN_INTERVAL = 2000;
    const unsigned long WIFI_SCAN_INTERVAL = 4000;
    const unsigned long MESH_DEVICE_SCAN_UPDATE_INTERVAL = 3000;
    unsigned long nextResultsUpdate = millis() + 5000;
    
    std::set<String> transmittedDevices;

    NimBLEScan *bleScan = pBLEScan;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < duration * 1000 && !stopRequested))
    {
        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) &&
            (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)) {
            lastWiFiScan = millis();

            Serial.println("[SNIFFER] Scanning WiFi networks...");
            networksFound = WiFi.scanNetworks(false, true, false, rfConfig.wifiChannelTime);
            if (stopRequested) break;

            if (networksFound > 0)
            {
                for (int i = 0; i < networksFound; i++)
                {
                    String bssid = WiFi.BSSIDstr(i);
                    String ssid = WiFi.SSID(i);
                    int32_t rssi = WiFi.RSSI(i);
                    if (rssi < rfConfig.globalRssiThreshold) {
                        continue;
                    }
                    uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0)
                    {
                        ssid = "[Hidden]";
                    }

                    if (apCache.find(bssid) == apCache.end())
                    {
                        apCache[bssid] = ssid;
                        uniqueMacs.insert(bssid);

                        Hit h;
                        memcpy(h.mac, bssidBytes, 6);
                        h.rssi = rssi;
                        h.ch = WiFi.channel(i);
                        strncpy(h.name, ssid.c_str(), sizeof(h.name) - 1);
                        h.name[sizeof(h.name) - 1] = '\0';
                        h.isBLE = false;

                        hitsLog.push_back(h);

                        if (matchesMac(bssidBytes)) {
                            totalHits = totalHits + 1;
                        }

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
                            sendMeshNotification(h);
                        }
                    }
                }
            }

            Serial.printf("[SNIFFER] WiFi scan found %d networks\n", networksFound);
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        if (bleScan && (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) &&
            (millis() - lastBLEScan >= BLE_SCAN_INTERVAL || lastBLEScan == 0))
        {
            lastBLEScan = millis();

            Serial.println("[SNIFFER] Scanning BLE devices...");

            if (bleScan)
            {
                NimBLEScanResults scanResults = bleScan->getResults(2000, false);
                if (stopRequested) break;

                for (int i = 0; i < scanResults.getCount(); i++)
                {
                    const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                    String macStr = device->getAddress().toString().c_str();
                    macStr.toUpperCase();
                    int8_t rssi = device->getRSSI();    
                    if (rssi < rfConfig.globalRssiThreshold) {
                        continue;
                    }

                    if (bleDeviceCache.find(macStr) == bleDeviceCache.end())
                    {
                        String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
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
                        
                        uint8_t mac[6];
                        if (parseMac6(macStr, mac))
                        {
                            Hit h;
                            memcpy(h.mac, mac, 6);
                            h.rssi = device->getRSSI();
                            h.ch = 0;
                            strncpy(h.name, cleanName.c_str(), sizeof(h.name) - 1);
                            h.name[sizeof(h.name) - 1] = '\0';
                            h.isBLE = true;
                            hitsLog.push_back(h);
                            
                            String logEntry = "BLE Device: " + macStr + " Name: " + cleanName +
                                            " RSSI: " + String(device->getRSSI()) + "dBm";

                            if (gpsValid)
                            {
                                logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                            }

                            Serial.println("[SNIFFER] " + logEntry);
                            logToSD(logEntry);

                            if (matchesMac(mac))
                            {
                                sendMeshNotification(h);
                                totalHits = totalHits + 1;
                            }
                        }
                    }
                }

                bleScan->clearResults();
                Serial.printf("[SNIFFER] BLE scan found %d devices\n", scanResults.getCount());
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }

       if (meshEnabled && millis() - lastMeshUpdate >= MESH_DEVICE_SCAN_UPDATE_INTERVAL)
        {
            lastMeshUpdate = millis();
            uint32_t sentThisCycle = 0;
            
            for (const auto& entry : apCache)
            {
                String macStr = entry.first;
                String ssid = entry.second;
                
                if (transmittedDevices.find(macStr) == transmittedDevices.end())
                {
                    String deviceMsg = getNodeId() + ": DEVICE:" + macStr + " W ";
                    
                    int8_t bestRssi = -128;
                    uint8_t bestCh = 0;
                    for (const auto& hit : hitsLog) {
                        String hitMac = macFmt6(hit.mac);
                        if (hitMac == macStr && hit.rssi > bestRssi) {
                            bestRssi = hit.rssi;
                            bestCh = hit.ch;
                        }
                    }
                    
                    deviceMsg += String(bestRssi);
                    if (bestCh > 0) deviceMsg += " C" + String(bestCh);
                    if (ssid.length() > 0 && ssid != "[Hidden]") {
                        deviceMsg += " N:" + ssid.substring(0, 30);
                    }
                    
                    if (deviceMsg.length() < 230) {
                        if (sendToSerial1(deviceMsg, true)) {
                            transmittedDevices.insert(macStr);
                            sentThisCycle++;
                            
                            if (sentThisCycle % 2 == 0) {
                                delay(1000);
                                rateLimiter.refillTokens();
                            }
                        }
                    }
                }
            }
            
            for (const auto& entry : bleDeviceCache)
            {
                String macStr = entry.first;
                String name = entry.second;
                
                if (transmittedDevices.find(macStr) == transmittedDevices.end())
                {
                    String deviceMsg = getNodeId() + ": DEVICE:" + macStr + " B ";
                    
                    int8_t bestRssi = -128;
                    for (const auto& hit : hitsLog) {
                        String hitMac = macFmt6(hit.mac);
                        if (hitMac == macStr && hit.isBLE && hit.rssi > bestRssi) {
                            bestRssi = hit.rssi;
                        }
                    }
                    
                    deviceMsg += String(bestRssi);
                    if (name.length() > 0 && name != "Unknown") {
                        deviceMsg += " N:" + name.substring(0, 30);
                    }
                    
                    if (deviceMsg.length() < 230) {
                        if (sendToSerial1(deviceMsg, true)) {
                            transmittedDevices.insert(macStr);
                            sentThisCycle++;
                            
                            if (sentThisCycle % 2 == 0) {
                                delay(1000);
                                rateLimiter.refillTokens();
                            }
                        }
                    }
                }
            }
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            
            std::string results = "Sniffer scan - Mode: " + std::string(modeStr.c_str()) + " (IN PROGRESS)\n";
            results += "Elapsed: " + std::to_string((millis() - lastScanStart) / 1000) + "s";
            if (!forever && duration > 0) {
                results += " / " + std::to_string(duration) + "s";
            }
            results += "\nWiFi APs: " + std::to_string(apCache.size()) + 
                      "\nBLE devices: " + std::to_string(bleDeviceCache.size()) + 
                      "\nUnique devices: " + std::to_string(uniqueMacs.size()) + 
                      "\nTarget hits: " + std::to_string(totalHits) + "\n\n";
            
            std::vector<Hit> sortedHits = hitsLog;
            std::sort(sortedHits.begin(), sortedHits.end(), 
                     [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });
            
            int shown = 0;
            for (const auto& hit : sortedHits) {
                if (shown++ >= 50) break;
                results += std::string(hit.isBLE ? "BLE " : "WiFi");
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         hit.mac[0], hit.mac[1], hit.mac[2], hit.mac[3], hit.mac[4], hit.mac[5]);
                results += " " + std::string(macStr);
                results += " RSSI=" + std::to_string(hit.rssi) + "dBm";
                if (!hit.isBLE && hit.ch > 0) results += " CH=" + std::to_string(hit.ch);
                if (strlen(hit.name) > 0 && strcmp(hit.name, "Unknown") != 0 && strcmp(hit.name, "[Hidden]") != 0) {
                    results += " Name=" + std::string(hit.name);
                }
                results += "\n";
            }
            if (hitsLog.size() > 50) {
                results += "... (" + std::to_string(hitsLog.size() - 50) + " more)\n";
            }
            
            antihunter::lastResults = results;
            nextResultsUpdate = millis() + 5000;
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
    
    scanning = false;
    lastScanEnd = millis();

    if (meshEnabled)
    {
        uint32_t totalExpectedDevices = apCache.size() + bleDeviceCache.size();
        uint32_t devicesBeforeFinal = transmittedDevices.size();
        
        Serial.printf("[SNIFFER] Scan complete - transmitting final batch\n");
        Serial.printf("[SNIFFER] Already sent: %d/%d devices\n", devicesBeforeFinal, totalExpectedDevices);
        
        rateLimiter.flush();
        delay(100);
        
        for (const auto& entry : apCache)
        {
            if (transmittedDevices.find(entry.first) == transmittedDevices.end())
            {
                String deviceMsg = getNodeId() + ": DEVICE:" + entry.first + " W ";
                int8_t bestRssi = -128;
                uint8_t bestCh = 0;
                for (const auto& hit : hitsLog) {
                    String hitMac = macFmt6(hit.mac);
                    if (hitMac == entry.first && hit.rssi > bestRssi) {
                        bestRssi = hit.rssi;
                        bestCh = hit.ch;
                    }
                }
                deviceMsg += String(bestRssi);
                if (bestCh > 0) deviceMsg += " C" + String(bestCh);
                if (entry.second.length() > 0 && entry.second != "[Hidden]") {
                    deviceMsg += " N:" + entry.second.substring(0, 30);
                }
                if (deviceMsg.length() < 230) {
                    if (sendToSerial1(deviceMsg, true)) {
                        transmittedDevices.insert(entry.first);
                    }
                }
            }
        }
        
        for (const auto& entry : bleDeviceCache)
        {
            if (transmittedDevices.find(entry.first) == transmittedDevices.end())
            {
                String deviceMsg = getNodeId() + ": DEVICE:" + entry.first + " B ";
                int8_t bestRssi = -128;
                for (const auto& hit : hitsLog) {
                    String hitMac = macFmt6(hit.mac);
                    if (hitMac == entry.first && hit.isBLE && hit.rssi > bestRssi) {
                        bestRssi = hit.rssi;
                    }
                }
                deviceMsg += String(bestRssi);
                if (entry.second.length() > 0 && entry.second != "Unknown") {
                    deviceMsg += " N:" + entry.second.substring(0, 30);
                }
                if (deviceMsg.length() < 230) {
                    if (sendToSerial1(deviceMsg, true)) {
                        transmittedDevices.insert(entry.first);
                    }
                }
            }
        }
        
        Serial1.flush();
        delay(100);
        
        uint32_t finalTransmitted = transmittedDevices.size();
        uint32_t finalRemaining = totalExpectedDevices - finalTransmitted;
        
        Serial.printf("[SNIFFER] Final transmission complete: %d/%d devices sent, %d pending\n",
                     finalTransmitted, totalExpectedDevices, finalRemaining);
    }

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
    
    if (meshEnabled && !stopRequested)
    {
        uint32_t totalExpectedDevices = apCache.size() + bleDeviceCache.size();
        uint32_t finalTransmitted = transmittedDevices.size();
        uint32_t finalRemaining = totalExpectedDevices - finalTransmitted;
        
        String summary = getNodeId() + ": SCAN_DONE: W=" + String(apCache.size()) +
                        " B=" + String(bleDeviceCache.size()) + 
                        " U=" + String(uniqueMacs.size()) +
                        " H=" + String(totalHits) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        
        sendToSerial1(summary, true);
        Serial.println("[SNIFFER] Scan complete summary transmitted");
        
        if (finalRemaining > 0) {
            Serial.printf("[SNIFFER] WARNING: %d devices not transmitted\n", finalRemaining);
        }
    }

    radioStopSTA();
    delay(500);

    vTaskDelay(pdMS_TO_TICKS(100));
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

std::string buildDeauthResults(bool forever, int duration, uint32_t deauthCount, 
                                uint32_t disassocCount, const std::vector<DeauthHit>& deauthLog) {
    std::map<String, DeauthStats> statsMap;
    
    for (const auto& h : deauthLog) {
        String dstMac = macFmt6(h.destMac);
        if (dstMac == "FF:FF:FF:FF:FF:FF") dstMac = "[BROADCAST]";
        
        if (statsMap.find(dstMac) == statsMap.end()) {
            DeauthStats stats;
            stats.srcMac = dstMac;
            stats.count = 0;
            stats.broadcastCount = 0;
            stats.targetedCount = 0;
            stats.lastRssi = -128;
            stats.channel = h.channel;
            statsMap[dstMac] = stats;
        }
        
        statsMap[dstMac].count++;
        if (h.isBroadcast) {
            statsMap[dstMac].broadcastCount++;
        } else {
            statsMap[dstMac].targetedCount++;
        }
        statsMap[dstMac].lastRssi = h.rssi;
    }
    
    std::string results = "Deauth Attack Detection Results\n";
    results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
    results += "Deauth frames: " + std::to_string(deauthCount) + "\n";
    results += "Disassoc frames: " + std::to_string(disassocCount) + "\n";
    results += "Total attacks: " + std::to_string(deauthLog.size()) + "\n";
    results += "Targets attacked: " + std::to_string(statsMap.size()) + "\n\n";
    
    if (statsMap.empty()) {
        results += "No attacks detected.\n";
    } else {
        results += "Attack Targets:\n";
        results += "===============\n\n";
        
        std::vector<std::pair<String, DeauthStats>> sorted(statsMap.begin(), statsMap.end());
        std::sort(sorted.begin(), sorted.end(),
            [](const std::pair<String, DeauthStats>& a, 
            const std::pair<String, DeauthStats>& b) { 
                return a.second.count > b.second.count; 
            });
        
        for (size_t i = 0; i < sorted.size() && i < 100; i++) {
            const auto& entry = sorted[i];
            const auto& stats = entry.second;
            
            results += std::string(entry.first.c_str());
            results += " Total=" + std::to_string(stats.count);
            results += " Broadcast=" + std::to_string(stats.broadcastCount);
            results += " Targeted=" + std::to_string(stats.targetedCount);
            results += " LastRSSI=" + std::to_string(stats.lastRssi) + "dBm CH=" + std::to_string(stats.channel) + "\n";
            
            int sourcesShown = 0;
            std::map<String, int> sourceCounts;
            for (const auto& h : deauthLog) {
                String dst = macFmt6(h.destMac);
                if (dst == "FF:FF:FF:FF:FF:FF") dst = "[BROADCAST]";
                if (dst == entry.first) {
                    String src = macFmt6(h.srcMac);
                    sourceCounts[src]++;
                }
            }
            
            for (const auto& source : sourceCounts) {
                if (sourcesShown++ >= 5) {
                    if (sourceCounts.size() > 5) {
                        results += "    ... (" + std::to_string(sourceCounts.size() - 5) + " more attackers)\n";
                    }
                    break;
                }
                results += "    ← " + std::string(source.first.c_str()) + " (" + std::to_string(source.second) + "x)\n";
            }
            results += "\n";
        }
        
        if (sorted.size() > 100) {
            results += "... (" + std::to_string(sorted.size() - 100) + " more targets)\n";
        }
    }
    
    return results;
}

void blueTeamTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    String startMsg = forever ? String("[BLUE] Starting deauth detection (forever)\n")
                              : String("[BLUE] Starting deauth detection for " + String(duration) + "s\n");
    Serial.print(startMsg);
    
    deauthLog.clear();
    deauthCount = 0;
    disassocCount = 0;
    deauthDetectionEnabled = true;
    stopRequested = false;
    deauthSourceCounts.clear();
    deauthTargetCounts.clear();
    deauthTimings.clear();
    scanning = true;

    if (deauthQueue) {
        vQueueDelete(deauthQueue);
    }
    
    deauthQueue = xQueueCreate(256, sizeof(DeauthHit));
    
    std::set<String> transmittedAttacks;
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    uint32_t lastResultsUpdate = millis() + 2000;
    uint32_t lastMeshUpdate = millis();
    const unsigned long MESH_DEAUTH_UPDATE_INTERVAL = 5000;
    DeauthHit hit;

    radioStartSTA();
    vTaskDelay(pdMS_TO_TICKS(200));

    const int BATCH_LIMIT = 4;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
        int processed = 0;
        
        while (processed++ < BATCH_LIMIT && xQueueReceive(deauthQueue, &hit, 0) == pdTRUE) {
            if (deauthLog.size() < 2000) {
                deauthLog.push_back(hit);
            }
            
            String srcMac = macFmt6(hit.srcMac);
            String dstMac = macFmt6(hit.destMac);
            String attackKey = srcMac + "->" + dstMac;
            
            String alert = String(hit.isDisassoc ? "DISASSOC" : "DEAUTH");
            if (hit.isBroadcast) {
                alert += " [BROADCAST]";
            } else {
                alert += " [TARGETED]";
            }
            alert += " SRC:" + srcMac + " DST:" + dstMac;
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);

            Serial.println("[ALERT] " + alert);
            logToSD(alert);

            if (meshEnabled && transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                String meshAlert = getNodeId() + ": ATTACK: " + alert;
                if (gpsValid) {
                    meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                }
                if (sendToSerial1(meshAlert, false)) {
                    transmittedAttacks.insert(attackKey);
                }
            }
        }
        
        if (meshEnabled && (millis() - lastMeshUpdate >= MESH_DEAUTH_UPDATE_INTERVAL)) {
            lastMeshUpdate = millis();
            
            int sentThisCycle = 0;
            for (const auto& entry : deauthLog) {
                String srcMac = macFmt6(entry.srcMac);
                String dstMac = macFmt6(entry.destMac);
                String attackKey = srcMac + "->" + dstMac;
                
                if (transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                    String attackMsg = getNodeId() + ": ATTACK: ";
                    attackMsg += String(entry.isDisassoc ? "DISASSOC" : "DEAUTH");
                    attackMsg += " " + srcMac + "->" + dstMac;
                    attackMsg += " R" + String(entry.rssi) + " C" + String(entry.channel);
                    
                    if (attackMsg.length() < 230 && sendToSerial1(attackMsg, true)) {
                        transmittedAttacks.insert(attackKey);
                        sentThisCycle++;
                        
                        if (sentThisCycle % 2 == 0) {
                            delay(1000);
                            rateLimiter.refillTokens();
                        }
                    }
                }
            }
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLUE] Deauth:%u Disassoc:%u Total:%u\n", 
                         deauthCount, disassocCount, (unsigned)deauthLog.size());
            nextStatus += 5000;
        }
        
        if ((int32_t)(millis() - lastResultsUpdate) >= 0) {
            std::string results = buildDeauthResults(forever, duration, deauthCount, disassocCount, deauthLog);
            
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            
            lastResultsUpdate = millis() + 2000;
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
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    deauthDetectionEnabled = false;
    scanning = false;

    vTaskDelay(pdMS_TO_TICKS(200));

    if (deauthQueue) {
        DeauthHit dummy;
        while (xQueueReceive(deauthQueue, &dummy, 0) == pdTRUE) {
        }
        vQueueDelete(deauthQueue);
        deauthQueue = nullptr;
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    radioStopSTA();

    vTaskDelay(pdMS_TO_TICKS(500));

    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = buildDeauthResults(forever, duration, deauthCount, disassocCount, deauthLog);
    }

    if (meshEnabled && !stopRequested) {
        Serial.printf("[BLUE] Scan complete - transmitting final batch\n");
        rateLimiter.flush();
        delay(100);
        
        for (const auto& entry : deauthLog) {
            String srcMac = macFmt6(entry.srcMac);
            String dstMac = macFmt6(entry.destMac);
            String attackKey = srcMac + "->" + dstMac;
            
            if (transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                String attackMsg = getNodeId() + ": ATTACK: ";
                attackMsg += String(entry.isDisassoc ? "DISASSOC" : "DEAUTH");
                attackMsg += " " + srcMac + "->" + dstMac;
                attackMsg += " R" + String(entry.rssi) + " C" + String(entry.channel);
                
                if (attackMsg.length() < 230) {
                    if (sendToSerial1(attackMsg, true)) {
                        transmittedAttacks.insert(attackKey);
                    }
                }
            }
        }
        
        Serial1.flush();
        delay(100);
        
        uint32_t totalAttacks = deauthLog.size();
        uint32_t finalTransmitted = transmittedAttacks.size();
        uint32_t finalRemaining = totalAttacks - finalTransmitted;
        
        String summary = getNodeId() + ": DEAUTH_DONE: Total=" + String(deauthCount + disassocCount) +
                        " Deauth=" + String(deauthCount) +
                        " Disassoc=" + String(disassocCount) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        
        sendToSerial1(summary, true);
        Serial.printf("[BLUE] Detection complete: %d/%d attacks transmitted, %d pending\n",
                     finalTransmitted, totalAttacks, finalRemaining);
        
        if (finalRemaining > 0) {
            Serial.printf("[BLUE] WARNING: %d attacks not transmitted\n", finalRemaining);
        }
    }

    Serial.println("[BLUE] Deauth detection stopped cleanly");
    
    radioStopSTA();
    vTaskDelay(pdMS_TO_TICKS(200));

    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static uint8_t extractChannelFromIE(const uint8_t *payload, uint16_t length) {
    if (length < 24) return 0;
    
    const uint8_t *ie = payload + 24;
    uint16_t ieLen = length - 24;
    uint16_t offset = 0;
    
    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];
        
        if (offset + 2 + len > ieLen) break;
        
        if (tag == 3 && len == 1) {
            return ie[offset + 2];
        }
        
        offset += 2 + len;
    }
    
    return 0;
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!buf) return;
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;

    if (!triangulationActive && ppkt->rx_ctrl.rssi < rfConfig.globalRssiThreshold) {
        return;
    }

    if (droneDetectionEnabled) {
        processDronePacket(ppkt->payload, ppkt->rx_ctrl.sig_len, ppkt->rx_ctrl.rssi);
    }

    if (randomizationDetectionEnabled && ppkt->rx_ctrl.sig_len >= 24) {
        const uint8_t *payload = ppkt->payload;
        uint16_t fc = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
        uint8_t ftype = (fc >> 2) & 0x3;
        uint8_t stype = (fc >> 4) & 0xF;
        
        // Probe requests
        if (ftype == 0 && (stype == 4 || stype == 8)) {
            const uint8_t *sa = payload + 10;
            uint8_t actualChannel = extractChannelFromIE(payload, ppkt->rx_ctrl.sig_len);
            if (actualChannel == 0) {
                actualChannel = ppkt->rx_ctrl.channel;
            }
            processProbeRequest(sa, ppkt->rx_ctrl.rssi, actualChannel,
                            payload, ppkt->rx_ctrl.sig_len);
        }
        
        // Authentication frames (subtype 11 = 0xB)
        else if (ftype == 0 && stype == 11) {
            const uint8_t *srcMac = payload + 10;
            if (isGlobalMAC(srcMac)) {
                correlateAuthFrameToRandomizedSession(srcMac, ppkt->rx_ctrl.rssi, 
                                                     ppkt->rx_ctrl.channel,
                                                     payload, ppkt->rx_ctrl.sig_len);
            }
        }
        
        // Association Request frames (subtype 0)
        else if (ftype == 0 && stype == 0) {
            const uint8_t *srcMac = payload + 10;
            if (isGlobalMAC(srcMac)) {
                correlateAuthFrameToRandomizedSession(srcMac, ppkt->rx_ctrl.rssi,
                                                     ppkt->rx_ctrl.channel, 
                                                     payload, ppkt->rx_ctrl.sig_len);
            }
        }
        
        // Reassociation Request frames (subtype 2)
        else if (ftype == 0 && stype == 2) {
            const uint8_t *srcMac = payload + 10;
            if (isGlobalMAC(srcMac)) {
                correlateAuthFrameToRandomizedSession(srcMac, ppkt->rx_ctrl.rssi,
                                                     ppkt->rx_ctrl.channel,
                                                     payload, ppkt->rx_ctrl.sig_len);
            }
        }
    }

    detectDeauthFrame(ppkt);
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

    bool c1Match = false;
    if (c1) {
        if (triangulationActive) {
            c1Match = (memcmp(cand1, triangulationTarget, 6) == 0);
        } else {
            c1Match = matchesMac(cand1);
        }
    }
    if (c1Match)
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
    
    bool c2Match = false;
    if (c2) {
        if (triangulationActive) {
            c2Match = (memcmp(cand2, triangulationTarget, 6) == 0);
        } else {
            c2Match = matchesMac(cand2);
        }
    }
    if (c2Match)
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

// ---------- Radio common ----------
static void radioStartWiFi()
{
    // Clean initialization
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        Serial.printf("[RADIO] WiFi init error: %d\n", err);
        return;
    }
    
    WiFi.mode(WIFI_MODE_STA);
    delay(500);
    
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    
    err = esp_wifi_start();
    if (err != ESP_OK) {
        Serial.printf("[RADIO] WiFi start error: %d\n", err);
        return;
    }
    delay(300);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    
    // Setup channel hopping with cleanup check
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    
    const esp_timer_create_args_t targs = {
        .callback = &hopTimerCb, 
        .arg = nullptr, 
        .dispatch_method = ESP_TIMER_TASK, 
        .name = "hop"
    };
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, rfConfig.wifiChannelTime * 1000);
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
    esp_wifi_deinit();
}

void radioStopBLE()
{
    if (pBLEScan)
    {
        pBLEScan->stop();
        vTaskDelay(pdMS_TO_TICKS(200));
        pBLEScan->clearResults();
        BLEDevice::deinit(true);
        pBLEScan = nullptr;
    }
}


void radioStartBLE()
{
    if (pBLEScan) {
        radioStopBLE();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setScanCallbacks(new MyBLEScanCallbacks(), true);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(rfConfig.bleScanInterval / 10);
    pBLEScan->setWindow((rfConfig.bleScanInterval / 10) - 10);
    pBLEScan->setDuplicateFilter(false);
    pBLEScan->start(0, false);
}


void radioStopSTA() {
    Serial.println("[RADIO] Stopping STA mode");
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    delay(50);
    
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        delay(50);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
        delay(50);
    }
    
    if (pBLEScan) {
        pBLEScan->stop();
        delay(100);
        BLEDevice::deinit(false);
        pBLEScan = nullptr;
        delay(100);
    }
    

    WiFi.mode(WIFI_AP_STA);
    delay(200);
}

void radioStartSTA() {
    Serial.println("[RADIO] Starting STA mode");
    
    // Use AP_STA mode instead of just STA
    WiFi.mode(WIFI_AP_STA);
    delay(100);
    
    // Configure STA for scanning while keeping AP alive
    wifi_country_t ctry = {.schan = 1, .nchan = 12, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    
    // Start promiscuous on STA interface
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
    
    const esp_timer_create_args_t targs = {
        .callback = &hopTimerCb, 
        .arg = nullptr, 
        .dispatch_method = ESP_TIMER_TASK, 
        .name = "hop"
    };
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, rfConfig.wifiChannelTime * 1000);
    
    // Start BLE if needed from a scan call
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
    }
}

void initializeScanner()
{
    Serial.println("Loading targets...");
    String txt = prefs.getString("maclist", "");
    saveTargetsList(txt);
    Serial.printf("Loaded %d targets\n", targets.size());
    
    Serial.println("Loading allowlist...");
    String wtxt = prefs.getString("allowlist", "");
    saveAllowlist(wtxt);
    Serial.printf("Loaded %d allowlist entries\n", allowlist.size());
}

static void resetTriAccumulator(const uint8_t* mac) {
    memcpy(triAccum.targetMac, mac, 6);
    
    triAccum.wifiHitCount = 0;
    triAccum.wifiMaxRssi = -128;
    triAccum.wifiMinRssi = 0;
    triAccum.wifiRssiSum = 0.0f;
    
    triAccum.bleHitCount = 0;
    triAccum.bleMaxRssi = -128;
    triAccum.bleMinRssi = 0;
    triAccum.bleRssiSum = 0.0f;
    
    triAccum.lat = 0.0f;
    triAccum.lon = 0.0f;
    triAccum.hdop = 99.9f;
    triAccum.hasGPS = false;
    triAccum.lastSendTime = millis();
}
uint32_t hashString(const String& str) {
    uint32_t hash = 0;
    for (size_t i = 0; i < str.length(); i++) {
        hash = hash * 31 + str.charAt(i);
    }
    return hash;
}

static void sendTriAccumulatedData(const String& nodeId) {
    if (triAccum.wifiHitCount == 0 && triAccum.bleHitCount == 0) return;
    
    if (!triangulationActive) {
        triAccum.wifiHitCount = 0;
        triAccum.wifiRssiSum = 0.0f;
        triAccum.bleHitCount = 0;
        triAccum.bleRssiSum = 0.0f;
        return;
    }
    
    reportingSchedule.addNode(nodeId);
    
    if (reportingSchedule.cycleStartMs == 0) {
        reportingSchedule.initializeCycle(millis());
    }
    
    uint32_t nextSlot = 0;
    if (!reportingSchedule.isMySlotActive(nodeId, nextSlot)) {
        uint32_t now = millis();
        int32_t waitMs = (int32_t)(nextSlot - now);
        
        if (waitMs > 0 && waitMs < 60000) {
            static uint32_t lastLog = 0;
            if (millis() - lastLog > 2000) {
                Serial.printf("[TRI-WAIT] Node %s: waiting %dms for slot (next=%u, now=%u)\n", 
                            nodeId.c_str(), waitMs, nextSlot, now);
                lastLog = millis();
            }
        }
        return;
    }
    
    String macStr = macFmt6(triAccum.targetMac);
    bool sentAny = false;
    
    if (triAccum.wifiHitCount > 0) {
        int8_t wifiAvgRssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
        String wifiMsg = nodeId + ": TARGET_DATA: " + macStr + 
                         " Hits=" + String(triAccum.wifiHitCount) +
                         " RSSI:" + String(wifiAvgRssi) + " Type:WiFi";
        if (triAccum.hasGPS) {
            wifiMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                       " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(wifiMsg, false)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId);
            Serial.printf("[TRI-SLOT] %s: WiFi sent (%d hits)\n", nodeId.c_str(), triAccum.wifiHitCount);
            delay(400);
        }
    }
    
    if (triAccum.bleHitCount > 0) {
        int8_t bleAvgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
        String bleMsg = nodeId + ": TARGET_DATA: " + macStr + 
                        " Hits=" + String(triAccum.bleHitCount) +
                        " RSSI:" + String(bleAvgRssi) + " Type:BLE";
        if (triAccum.hasGPS) {
            bleMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                      " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(bleMsg, false)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId);
            Serial.printf("[TRI-SLOT] %s: BLE sent (%d hits)\n", nodeId.c_str(), triAccum.bleHitCount);
        }
    }
    
    if (sentAny) {
        triAccum.wifiHitCount = 0;
        triAccum.wifiRssiSum = 0.0f;
        triAccum.bleHitCount = 0;
        triAccum.bleRssiSum = 0.0f;
        triAccum.lastSendTime = millis();
        delay(150);
    }
}

// Scan tasks
void listScanTask(void *pv) {
    int secs = (int)(intptr_t)pv;
    bool forever = (secs <= 0);

    // Clear old results
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    Serial.printf("[SCAN] List scan %s (%s)...\n",
                  forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str(),
                  modeStr.c_str());

    stopRequested = false;
    
    if (macQueue) {
        vQueueDelete(macQueue);
        macQueue = nullptr;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    macQueue = xQueueCreate(512, sizeof(Hit));
    if (!macQueue) {
        Serial.println("[SCAN] ERROR: Failed to create macQueue");
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    uniqueMacs.clear();
    hitsLog.clear();
    totalHits = 0;
    std::set<String> seenTargets;
    std::set<String> transmittedDevices;
    framesSeen = 0;
    bleFramesSeen = 0;
    scanning = true;
    lastScanStart = millis();
    lastScanSecs = secs;
    lastScanForever = forever;

    // Register initiator at scan start
    if (triangulationInitiator) {
        String myNodeId = getNodeId();
        if (myNodeId.length() == 0) {
            myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
        }
        
        TriangulationNode selfNode;
        selfNode.nodeId = myNodeId;
        selfNode.lat = gpsValid ? gpsLat : 0.0;
        selfNode.lon = gpsValid ? gpsLon : 0.0;
        selfNode.hdop = gpsValid && gps.hdop.isValid() ? gps.hdop.hdop() : 99.9;
        selfNode.rssi = -128;
        selfNode.hitCount = 0;
        selfNode.hasGPS = gpsValid;
        selfNode.isBLE = false;
        selfNode.lastUpdate = millis();
        initNodeKalmanFilter(selfNode);
        triangulationNodes.push_back(selfNode);
        
        Serial.printf("[TRIANGULATE] Initiator registered: %s\n", myNodeId.c_str());
    }

    vTaskDelay(pdMS_TO_TICKS(200));

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    } else if (currentScanMode == SCAN_BLE) {
        vTaskDelay(pdMS_TO_TICKS(100));
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    uint32_t nextStatus = millis() + 1000;
    std::map<String, uint32_t> deviceLastSeen;
    const uint32_t DEDUPE_WINDOW = 3000;
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    Hit h;

    uint32_t nextTriResultsUpdate = millis() + 2000;


    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("Status: Tracking %d devices... WiFi frames=%u BLE frames=%u\n",
                         (int)uniqueMacs.size(), (unsigned)framesSeen, (unsigned)bleFramesSeen);
            nextStatus += 1000;
        }

        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) &&
            (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, true, false, rfConfig.wifiChannelTime);
            if (stopRequested) break;
            if (networksFound > 0) {
                for (int i = 0; i < networksFound; i++) {
                    String bssid = WiFi.BSSIDstr(i);
                    bssid.toUpperCase();
                    String ssid = WiFi.SSID(i);
                    int32_t rssi = WiFi.RSSI(i);
                    if (rssi < rfConfig.globalRssiThreshold) {
                        continue;
                    }

                    uint8_t ch = WiFi.channel(i);
                    uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0) ssid = "[Hidden]";

                    uint32_t now = millis();
                    bool shouldProcess = (deviceLastSeen.find(bssid) == deviceLastSeen.end() ||
                                          (now - deviceLastSeen[bssid] >= DEDUPE_WINDOW));

                    if (!shouldProcess) continue;

                    String origBssid = WiFi.BSSIDstr(i);
                    uint8_t mac[6];
                    bool isMatch;
                    if (triangulationActive) {
                        if (strlen(triangulationTargetIdentity) > 0) {
                            isMatch = parseMac6(origBssid, mac) && 
                                    matchesIdentityMac(triangulationTargetIdentity, mac);
                        } else {
                            isMatch = parseMac6(origBssid, mac) && 
                                    (memcmp(mac, triangulationTarget, 6) == 0);
                        }
                    } else {
                        isMatch = parseMac6(origBssid, mac) && matchesMac(mac);
                    }

                    uniqueMacs.insert(bssid);

                    Hit wh;
                    memcpy(wh.mac, bssidBytes, 6);
                    wh.rssi = rssi;
                    wh.ch = ch;
                    strncpy(wh.name, ssid.c_str(), sizeof(wh.name) - 1);
                    wh.name[sizeof(wh.name) - 1] = '\0';
                    wh.isBLE = false;

                    if (isMatch) {
                        if (macQueue) {
                            if (xQueueSend(macQueue, &wh, pdMS_TO_TICKS(10)) != pdTRUE) {
                                Serial.printf("[SCAN] Queue full for target %s\n", origBssid.c_str());
                            }
                        }
                    } else {
                        hitsLog.push_back(wh);
                        deviceLastSeen[bssid] = now;
                    }
                }
                WiFi.scanDelete();
            }
            framesSeen += networksFound;
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan &&
            (millis() - lastBLEScan >= rfConfig.bleScanInterval || lastBLEScan == 0)) {
            lastBLEScan = millis();
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            if (stopRequested) break;
            for (int i = 0; i < scanResults.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStrOrig = device->getAddress().toString().c_str();
                String macStr = macStrOrig;
                macStr.toUpperCase();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();    
                if (rssi < rfConfig.globalRssiThreshold) {
                    continue;
                }
                uint32_t now = millis();
                bool shouldProcess = (deviceLastSeen.find(macStr) == deviceLastSeen.end() ||
                                      (now - deviceLastSeen[macStr] >= DEDUPE_WINDOW));

                if (!shouldProcess) continue;

                uint8_t mac[6];
                bool isMatch;
                if (triangulationActive) {
                    if (strlen(triangulationTargetIdentity) > 0) {
                        isMatch = parseMac6(macStrOrig, mac) && 
                                matchesIdentityMac(triangulationTargetIdentity, mac);
                    } else {
                        isMatch = parseMac6(macStrOrig, mac) && 
                                (memcmp(mac, triangulationTarget, 6) == 0);
                    }
                } else {
                    isMatch = parseMac6(macStrOrig, mac) && matchesMac(mac);
                }

                uniqueMacs.insert(macStr);

                if (isMatch) {
                    Hit bh;
                    memcpy(bh.mac, mac, 6);
                    bh.rssi = rssi;
                    bh.ch = 0;
                    strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                    bh.name[sizeof(bh.name) - 1] = '\0';
                    bh.isBLE = true;
                    if (macQueue) {
                        if (xQueueSend(macQueue, &bh, pdMS_TO_TICKS(10)) != pdTRUE) {
                            Serial.printf("[SCAN] Queue full for target %s\n", macStrOrig.c_str());
                        }
                    }
                } else {
                    Hit bh;
                    if (parseMac6(macStrOrig, mac)) {
                        memcpy(bh.mac, mac, 6);
                        bh.rssi = rssi;
                        bh.ch = 0;
                        strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                        bh.name[sizeof(bh.name) - 1] = '\0';
                        bh.isBLE = true;
                        hitsLog.push_back(bh);
                        deviceLastSeen[macStr] = now;
                    }
                }
            }
            pBLEScan->clearResults();
            bleFramesSeen += scanResults.getCount();
        }

        while (xQueueReceive(macQueue, &h, 0) == pdTRUE) {
            String macStrOrig = macFmt6(h.mac);
            String macStr = macStrOrig;
            macStr.toUpperCase();
            uint32_t now = millis();

            if (isAllowlisted(h.mac)) {
                continue;
            }

            if (deviceLastSeen.find(macStr) != deviceLastSeen.end()) {
                if (now - deviceLastSeen[macStr] < DEDUPE_WINDOW) continue;
            }

            deviceLastSeen[macStr] = now;
            uniqueMacs.insert(macStr);
            hitsLog.push_back(h);

            if (seenTargets.find(macStr) == seenTargets.end()) {
                seenTargets.insert(macStr);
                totalHits = totalHits + 1;
            }

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macStrOrig +
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
            sendMeshNotification(h);

            if (triangulationActive) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) {
                    myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
                }
                
                static bool triAccumInitialized = false;
                if (!triAccumInitialized) {
                    resetTriAccumulator(triangulationTarget);
                    triAccumInitialized = true;
                }
                
                if (memcmp(triAccum.targetMac, triangulationTarget, 6) != 0) {
                    sendTriAccumulatedData(myNodeId);
                    resetTriAccumulator(triangulationTarget);
                }

                if (memcmp(h.mac, triangulationTarget, 6) == 0) {
                    // Track WiFi and BLE separately
                    if (h.isBLE) {
                        triAccum.bleHitCount++;
                        triAccum.bleRssiSum += (float)h.rssi;
                        if (h.rssi > triAccum.bleMaxRssi) triAccum.bleMaxRssi = h.rssi;
                        if (h.rssi < triAccum.bleMinRssi || triAccum.bleMinRssi == 0) triAccum.bleMinRssi = h.rssi;
                    } else {
                        triAccum.wifiHitCount++;
                        triAccum.wifiRssiSum += (float)h.rssi;
                        if (h.rssi > triAccum.wifiMaxRssi) triAccum.wifiMaxRssi = h.rssi;
                        if (h.rssi < triAccum.wifiMinRssi || triAccum.wifiMinRssi == 0) triAccum.wifiMinRssi = h.rssi;
                    }
                    
                    if (gpsValid) {
                        triAccum.lat = gpsLat;
                        triAccum.lon = gpsLon;
                        triAccum.hdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.9f;
                        triAccum.hasGPS = true;
                    }
                    
                    if (triangulationInitiator) {
                        String myNodeId = getNodeId();
                        if (myNodeId.length() == 0) {
                            myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
                        }
                        
                        // Calculate average for whichever protocol has data
                        int8_t avgRssi;
                        int totalHits;
                        bool isBLE;
                        
                        if (triAccum.wifiHitCount > 0) {
                            avgRssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
                            totalHits = triAccum.wifiHitCount;
                            isBLE = false;
                        } else if (triAccum.bleHitCount > 0) {
                            avgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
                            totalHits = triAccum.bleHitCount;
                            isBLE = true;
                        } else {
                            continue; // No data, skip
                        }
                        
                        bool selfNodeFound = false;
                        for (auto &node : triangulationNodes) {
                            if (node.nodeId == myNodeId) {
                                updateNodeRSSI(node, avgRssi);
                                node.hitCount = totalHits;
                                node.isBLE = isBLE;
                                if (triAccum.hasGPS) {
                                    node.lat = triAccum.lat;
                                    node.lon = triAccum.lon;
                                    node.hdop = triAccum.hdop;
                                    node.hasGPS = true;
                                }
                                node.distanceEstimate = rssiToDistance(node, !node.isBLE);
                                node.lastUpdate = millis();
                                selfNodeFound = true;
                                break;
                            }
                        }
                        
                        if (!selfNodeFound) {
                            TriangulationNode selfNode;
                            selfNode.nodeId = myNodeId;
                            selfNode.lat = triAccum.hasGPS ? triAccum.lat : 0.0;
                            selfNode.lon = triAccum.hasGPS ? triAccum.lon : 0.0;
                            selfNode.hdop = triAccum.hasGPS ? triAccum.hdop : 99.9;
                            selfNode.rssi = avgRssi;
                            selfNode.hitCount = totalHits;
                            selfNode.hasGPS = triAccum.hasGPS;
                            selfNode.isBLE = isBLE;
                            selfNode.lastUpdate = millis();
                            
                            initNodeKalmanFilter(selfNode);
                            updateNodeRSSI(selfNode, avgRssi);
                            selfNode.distanceEstimate = rssiToDistance(selfNode, !selfNode.isBLE);
                            
                            triangulationNodes.push_back(selfNode);
                            
                            Serial.printf("[TRIANGULATE SELF] Added: hits=%d avgRSSI=%d Type=%s dist=%.1fm GPS=%s\n",
                                        totalHits, avgRssi,
                                        selfNode.isBLE ? "BLE" : "WiFi",
                                        selfNode.distanceEstimate,
                                        triAccum.hasGPS ? "YES" : "NO");
                        }
                    }
                }
            }
        }

        // Dynamic update to results
        if (triangulationActive && (int32_t)(millis() - nextTriResultsUpdate) >= 0) {
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                
                std::string results = "\n=== Triangulation Results (IN PROGRESS) ===\n";
                results += "Target MAC: " + std::string(macFmt6(triangulationTarget).c_str()) + "\n";
                results += "Duration: " + std::to_string(triangulationDuration) + "s\n";
                results += "Elapsed: " + std::to_string((millis() - triangulationStart) / 1000) + "s\n";
                results += "Reporting Nodes: " + std::to_string(triangulationNodes.size()) + "\n\n";
                results += "--- Node Reports ---\n";
                
                for (const auto& node : triangulationNodes) {
                    results += std::string(node.nodeId.c_str()) + ": ";
                    results += "RSSI=" + std::to_string((int)node.filteredRssi) + "dBm ";
                    results += "Hits=" + std::to_string(node.hitCount) + " ";
                    results += "Signal=" + std::to_string((int)(node.signalQuality * 100.0)) + "% ";
                    results += "Type=" + std::string(node.isBLE ? "BLE" : "WiFi");
                    if (node.hasGPS) {
                        results += " GPS=" + std::to_string(node.lat) + "," + std::to_string(node.lon);
                        results += " HDOP=" + std::to_string(node.hdop);
                    } else {
                        results += " GPS=NO";
                    }
                    results += "\n";
                }
                
                results += "\n=== End Triangulation ===\n";
                antihunter::lastResults = results;
            }
            nextTriResultsUpdate = millis() + 2000;
        }

        if (triangulationActive) {
            static uint32_t nextTriReportCheck = 0;
            if ((int32_t)(millis() - nextTriReportCheck) >= 0) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) {
                    myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
                }
                sendTriAccumulatedData(myNodeId);
                nextTriReportCheck = millis() + 10000;
            }
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            static uint32_t lastBLEScan = 0;
            if (millis() - lastBLEScan >= 3000) {
                NimBLEScanResults scanResults = pBLEScan->getResults(1000, false);
                pBLEScan->clearResults();
                lastBLEScan = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (triangulationActive) {
        String myNodeId = getNodeId();
        if (myNodeId.length() == 0) {
            myNodeId = "NODE_" + String((uint32_t)ESP.getEfuseMac(), HEX);
        }
        
        // Child nodes: send final data WITHOUT slot delays, all at once
        if (!triangulationInitiator && (triAccum.wifiHitCount > 0 || triAccum.bleHitCount > 0)) {
            int8_t wifiAvgRssi = triAccum.wifiHitCount > 0 ? (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount) : -128;
            int8_t bleAvgRssi = triAccum.bleHitCount > 0 ? (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount) : -128;
            
            String macStr = macFmt6(triAccum.targetMac);
            
            if (triAccum.wifiHitCount > 0) {
                String wifiMsg = myNodeId + ": TARGET_DATA: " + macStr + 
                                " Hits=" + String(triAccum.wifiHitCount) +
                                " RSSI:" + String(wifiAvgRssi) + " Type:WiFi";
                if (triAccum.hasGPS) {
                    wifiMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                            " HDOP=" + String(triAccum.hdop, 1);
                }
                sendToSerial1(wifiMsg, false);
            }
            
            if (triAccum.bleHitCount > 0) {
                String bleMsg = myNodeId + ": TARGET_DATA: " + macStr + 
                                " Hits=" + String(triAccum.bleHitCount) +
                                " RSSI:" + String(bleAvgRssi) + " Type:BLE";
                if (triAccum.hasGPS) {
                    bleMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                            " HDOP=" + String(triAccum.hdop, 1);
                }
                sendToSerial1(bleMsg, false);
            }
            
            Serial.println("[SCAN CHILD] Final data sent (no delays)");
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        
        // Initiator: stop triangulation immediately
         if (triangulationInitiator) {
            Serial.println("[SCAN INITIATOR] Scan complete, stopping own reporting first");
            triangulationActive = false;
            stopRequested = true;
            vTaskDelay(pdMS_TO_TICKS(500));
            stopTriangulation();
        } else {
            // Tell the kids
            Serial.println("[SCAN CHILD] Scan complete, waiting for STOP command");
            uint32_t waitStart = millis();
            const uint32_t STOP_WAIT_TIMEOUT = 5000;
            
            while (!stopRequested && (millis() - waitStart < STOP_WAIT_TIMEOUT)) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            
            if (stopRequested) {
                Serial.println("[SCAN CHILD] Received STOP command, cleaning up");
            } else {
                Serial.println("[SCAN CHILD] STOP timeout, forcing cleanup");
                stopRequested = true;
            }
            
            // Clean up triangulation state for child
            triangulationActive = false;
            memset(triangulationTarget, 0, 6);
            memset(triangulationTargetIdentity, 0, sizeof(triangulationTargetIdentity));
            triAccum.wifiHitCount = 0;
            triAccum.wifiRssiSum = 0.0f;
            triAccum.bleHitCount = 0;
            triAccum.bleRssiSum = 0.0f;
            triAccum.lastSendTime = 0;
            reportingSchedule.reset();
        }
    }
    
    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        std::string results =
            "List scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(secs)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Target hits: " + std::to_string(totalHits) + "\n\n";

        std::map<String, Hit> hitsMap;
        for (const auto& targetMacStr : seenTargets) {
            Hit bestHit;
            int8_t bestRssi = -128; 
            bool found = false;

            String targetMac = targetMacStr; 
            for (const auto& hit : hitsLog) {
                String hitMacStrOrig = macFmt6(hit.mac);
                String hitMacStr = hitMacStrOrig;
                hitMacStr.toUpperCase();
                if (hitMacStr == targetMac && hit.rssi > bestRssi) {
                    bestHit = hit;
                    bestRssi = hit.rssi;
                    found = true;
                }
            }

            if (found) {
                hitsMap[targetMac] = bestHit;
            }
        }

        if (hitsMap.empty()) {
            results += "No targets detected.\n";
        } else {
            // Sort hits by RSSI
            std::vector<Hit> sortedHits;
            for (const auto& entry : hitsMap) {
                sortedHits.push_back(entry.second);
            }
            std::sort(sortedHits.begin(), sortedHits.end(),
                      [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

            int show = sortedHits.size();
            if (show > 200) show = 200;
            for (int i = 0; i < show; i++) {
                const auto &e = sortedHits[i];
                results += std::string(e.isBLE ? "BLE " : "WiFi");
                String macOut = macFmt6(e.mac);
                results += " " + std::string(macOut.c_str());
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
        }

        bool hasTriangulation = (antihunter::lastResults.find("=== Triangulation Results ===") != std::string::npos);
            
        if (hasTriangulation) {
            antihunter::lastResults = results + "\n\n" + antihunter::lastResults;
        } else if (triangulationNodes.size() > 0) {
            antihunter::lastResults = antihunter::lastResults + "\n\n=== List Scan Results ===\n" + results;
        } else {
            antihunter::lastResults = results;
        }
        
        Serial.printf("[DEBUG] Results stored: %d chars\n", results.length());
    }

    if (meshEnabled && !stopRequested) {
        uint32_t totalTargets = seenTargets.size();
        uint32_t finalTransmitted = transmittedDevices.size();
        uint32_t finalRemaining = totalTargets - finalTransmitted;
        
        String summary = getNodeId() + ": LIST_SCAN_DONE: Hits=" + String(totalHits) +
                        " Unique=" + String(uniqueMacs.size()) +
                        " Targets=" + String(totalTargets) +
                        " TX=" + String(finalTransmitted) +
                        " PEND=" + String(finalRemaining);
        
        sendToSerial1(summary, true);
        Serial.println("[SCAN] List scan summary transmitted");
        
        if (finalRemaining > 0) {
            Serial.printf("[SCAN] WARNING: %d targets not transmitted\n", finalRemaining);
        }
    }
    
    radioStopSTA();
    delay(500);

    if (pBLEScan && pBLEScan->isScanning()) {
        pBLEScan->stop();
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void cleanupMaps() {
    const size_t MAX_MAP_SIZE = 100;
    const size_t MAX_TIMING_SIZE = 50;
    const size_t MAX_LOG_SIZE = 500;
    const uint32_t EVICTION_AGE_MS = 30000;
    uint32_t now = millis();

    if (deauthSourceCounts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : deauthSourceCounts) {
            if (entry.second < 2) {
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            deauthSourceCounts.erase(key);
            deauthTargetCounts.erase(key);
            deauthTimings.erase(key);
        }
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
}


// Allowlist

static bool parseAllowlistEntry(const String &ln, Allowlist &out)
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

size_t getAllowlistCount()
{
    return allowlist.size();
}

String getAllowlistText()
{
    String out;
    for (auto &w : allowlist)
    {
        if (w.len == 6)
        {
            char b[18];
            snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                     w.bytes[0], w.bytes[1], w.bytes[2], w.bytes[3], w.bytes[4], w.bytes[5]);
            out += b;
        }
        else
        {
            char b[9];
            snprintf(b, sizeof(b), "%02X:%02X:%02X", w.bytes[0], w.bytes[1], w.bytes[2]);
            out += b;
        }
        out += "\n";
    }
    return out;
}

void saveAllowlist(const String &txt)
{
    prefs.putString("allowlist", txt);
    allowlist.clear();
    int start = 0;
    while (start < txt.length())
    {
        int nl = txt.indexOf('\n', start);
        if (nl < 0) nl = txt.length();
        String ln = txt.substring(start, nl);
        ln.trim();
        if (ln.length() > 0)
        {
            Allowlist w;
            if (parseAllowlistEntry(ln, w))
            {
                allowlist.push_back(w);
            }
        }
        start = nl + 1;
    }
}

bool isAllowlisted(const uint8_t *mac)
{
    for (auto &w : allowlist)
    {
        if (w.len == 6)
        {
            if (memcmp(w.bytes, mac, 6) == 0) return true;
        }
        else if (w.len == 3)
        {
            if (memcmp(w.bytes, mac, 3) == 0) return true;
        }
    }
    return false;
}