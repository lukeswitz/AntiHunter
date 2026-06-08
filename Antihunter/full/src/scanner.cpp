#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include <algorithm>
#include <iterator>
#include "randomization.h"
#include <string>
#include <atomic>
#include <mutex>
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "triangulation.h"
#include "baseline.h"
#include "detect.h"
#include "main.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
#include "esp_heap_caps.h"
}

// RF handlers
void radioStartSTA();
void radioStopSTA();
void radioStartBLE();
void radioStopBLE();

extern Preferences prefs;
static std::vector<Target> targets;
std::vector<String> ssidTargets;
std::atomic<bool> probeDetectionEnabled(false);
// When set, every captured probe triggers a mesh broadcast (60s dedup still applies).
// Otherwise only CONFIG_TARGETS matches are broadcast. Cleared on task exit.
std::atomic<bool> probeBroadcastAll{false};
QueueHandle_t macQueue = nullptr;
UniqueMacsSet uniqueMacs;
portMUX_TYPE uniqueMacsMux = portMUX_INITIALIZER_UNLOCKED;
DeviceLastSeenMap deviceLastSeen;
const uint32_t DEDUPE_WINDOW = 30000;
HitsVecPsram hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;
static StringStringMapPsram apCache;
static StringStringMapPsram bleDeviceCache;

static portMUX_TYPE rfConfigMux = portMUX_INITIALIZER_UNLOCKED;

const size_t MAX_AP_CACHE = 200;
const size_t MAX_BLE_CACHE = 200;

// BLE 
NimBLEScan *pBLEScan;
void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);

// Scan intervals
uint32_t WIFI_SCAN_INTERVAL = 4000;
uint32_t BLE_SCAN_INTERVAL = 2000;

// Scanner status variables
std::atomic<bool> scanning(false);
std::atomic<bool> meshTxDraining(false);
std::atomic<uint32_t> meshDrainSent(0);
std::atomic<uint32_t> meshDrainTotal(0);
std::atomic<bool> stopMeshDrain(false);
std::atomic<int> totalHits(0);
std::atomic<uint32_t> framesSeen(0);
std::atomic<uint32_t> bleFramesSeen(0);

extern TaskHandle_t blueTeamTaskHandle;

bool isRadioBusyOrDraining() {
    return scanning.load() || workerTaskHandle != nullptr ||
           blueTeamTaskHandle != nullptr || triangulationActive.load() ||
           meshTxDraining.load();
}

DeviceHistoryMapPsram deviceHistory;
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
    .globalRssiThreshold = -95
};

const uint32_t SCAN_MESH_SLOT_CYCLE_MS = 15000;
const uint32_t SCAN_MESH_NUM_SLOTS = 5;
const uint32_t SCAN_MESH_SLOT_DURATION_MS = SCAN_MESH_SLOT_CYCLE_MS / SCAN_MESH_NUM_SLOTS;
const uint32_t SLOT_GUARD_MS = 200;

const uint32_t MESH_DEDUP_TTL_MS = 300000;
const size_t MESH_DEDUP_MAX_ENTRIES = 5000;
static std::map<String, uint32_t, std::less<String>,
    PsramAllocator<std::pair<const String, uint32_t>>> g_meshSentMacs;
static std::mutex g_meshSentMacsMutex;

bool meshShouldSendMac(const String& mac) {
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    auto it = g_meshSentMacs.find(mac);
    if (it == g_meshSentMacs.end()) return true;
    return (millis() - it->second) >= MESH_DEDUP_TTL_MS;
}

void meshMarkMacSent(const String& mac) {
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    g_meshSentMacs[mac] = millis();
    if (g_meshSentMacs.size() > MESH_DEDUP_MAX_ENTRIES) {
        uint32_t now = millis();
        for (auto it = g_meshSentMacs.begin(); it != g_meshSentMacs.end();) {
            if (now - it->second >= MESH_DEDUP_TTL_MS) it = g_meshSentMacs.erase(it);
            else ++it;
        }
    }
}

void meshDedupClear() {
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    g_meshSentMacs.clear();
}

uint32_t meshDedupCount() {
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    return g_meshSentMacs.size();
}
static uint32_t scanMeshCycleStartTime = 0;

static uint8_t getScanNodeSlot() {
    String nodeId = getNodeId();
    uint32_t hash = 0;
    for (size_t i = 0; i < nodeId.length(); i++) {
        hash = hash * 31 + nodeId.charAt(i);
    }
    return hash % SCAN_MESH_NUM_SLOTS;
}

// Returns remaining milliseconds in current slot, or 0 if not in our slot
static uint32_t getTimeRemainingInSlot() {
    if (scanMeshCycleStartTime == 0) {
        scanMeshCycleStartTime = millis();
    }
    uint32_t elapsed = millis() - scanMeshCycleStartTime;
    uint32_t positionInCycle = elapsed % SCAN_MESH_SLOT_CYCLE_MS;
    uint8_t currentSlot = positionInCycle / SCAN_MESH_SLOT_DURATION_MS;

    if (currentSlot != getScanNodeSlot()) {
        return 0;  // Not our slot
    }

    uint32_t slotStart = currentSlot * SCAN_MESH_SLOT_DURATION_MS;
    uint32_t slotEnd = slotStart + SCAN_MESH_SLOT_DURATION_MS;
    uint32_t remaining = slotEnd - positionInCycle;
    return remaining;
}

static bool isMyScanMeshSlot() {
    if (scanMeshCycleStartTime == 0) {
        scanMeshCycleStartTime = millis();
    }
    uint32_t elapsed = millis() - scanMeshCycleStartTime;
    uint32_t positionInCycle = elapsed % SCAN_MESH_SLOT_CYCLE_MS;
    uint8_t currentSlot = positionInCycle / SCAN_MESH_SLOT_DURATION_MS;
    return currentSlot == getScanNodeSlot();
}

// Check if safe to send (in slot with sufficient guard time remaining)
static bool canSendInSlot() {
    uint32_t remaining = getTimeRemainingInSlot();
    return remaining > SLOT_GUARD_MS;
}

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
            rfConfig.globalRssiThreshold = -95;
            break;
        case 2:
            rfConfig.wifiChannelTime = 110;
            rfConfig.wifiScanInterval = 4000;
            rfConfig.bleScanInterval = 2000;
            rfConfig.bleScanDuration = 2000;
            rfConfig.globalRssiThreshold = -70;
            break;
        default:
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
    if (threshold <= -10) {
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
        int8_t rssiThreshold = prefs.getInt("globalRSSI", -95);
        setCustomRFConfig(wct, wsi, bsi, bsd, channels, rssiThreshold);
    }
    
    Serial.printf("[RF] Loaded config - Preset: %d, RSSI threshold: %d dBm\n", rfConfig.preset, rfConfig.globalRssiThreshold);
}

// Detection system variables
std::vector<DeauthHit> deauthLog;
std::atomic<uint32_t> deauthCount(0);
std::atomic<uint32_t> disassocCount(0);
bool deauthDetectionEnabled = false;
QueueHandle_t deauthQueue = nullptr;

// Deauth Detection

// Triangulation
TriangulationAccumulator triAccum = {0};
std::mutex triAccumMutex;
static const uint32_t TRI_SEND_INTERVAL = 2000;

// External declarations
extern Preferences prefs;
extern std::atomic<bool> stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
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

struct OuiEntry {
    uint8_t oui[3];
    char vendor[16];
};

static const OuiEntry PROGMEM ouiTable[] = {
    {{0x00, 0x17, 0xC4}, "Quanta"},
    {{0x00, 0x1A, 0x11}, "Google"},
    {{0x00, 0x25, 0x00}, "Apple"},
    {{0x00, 0x50, 0xF2}, "Microsoft"},
    {{0x04, 0xF1, 0x28}, "HTC"},
    {{0x08, 0x00, 0x27}, "Oracle VM"},
    {{0x0C, 0x77, 0x1A}, "Apple"},
    {{0x10, 0xDD, 0xB1}, "Apple"},
    {{0x14, 0x5A, 0xFC}, "Liteon"},
    {{0x18, 0xAF, 0x61}, "Samsung"},
    {{0x1C, 0x69, 0x7A}, "EliteGroup"},
    {{0x20, 0xDF, 0xB9}, "Google"},
    {{0x24, 0xB2, 0xB9}, "Liteon"},
    {{0x28, 0xCF, 0xE9}, "Apple"},
    {{0x2C, 0xF0, 0xA2}, "Xiaomi"},
    {{0x30, 0x07, 0x4D}, "Sony"},
    {{0x34, 0x14, 0x5F}, "Apple"},
    {{0x38, 0x1A, 0x52}, "Samsung"},
    {{0x3C, 0x91, 0x80}, "Liteon"},
    {{0x40, 0x4E, 0x36}, "HTC"},
    {{0x44, 0x85, 0x00}, "Intel"},
    {{0x48, 0xA4, 0x93}, "Samsung"},
    {{0x4C, 0x34, 0x88}, "Intel"},
    {{0x50, 0xDE, 0x06}, "Apple"},
    {{0x54, 0x60, 0x09}, "Google"},
    {{0x58, 0x8E, 0x81}, "Flock"},
    {{0x5C, 0x5F, 0x67}, "Huawei"},
    {{0x60, 0xF8, 0x1D}, "Apple"},
    {{0x64, 0xA2, 0xF9}, "OnePlus"},
    {{0x68, 0xDB, 0xF5}, "Amazon"},
    {{0x6C, 0x72, 0xE7}, "Apple"},
    {{0x70, 0xC9, 0x4E}, "Liteon"},
    {{0x74, 0x4C, 0xA1}, "Liteon"},
    {{0x78, 0x67, 0x0E}, "Zyxel"},
    {{0x7C, 0x04, 0xD0}, "Apple"},
    {{0x80, 0x30, 0x49}, "Liteon"},
    {{0x84, 0x38, 0x35}, "Apple"},
    {{0x88, 0xE9, 0xFE}, "Apple"},
    {{0x8C, 0x85, 0x90}, "Apple"},
    {{0x90, 0x35, 0xEA}, "Liteon"},
    {{0x94, 0x34, 0x69}, "Liteon"},
    {{0x98, 0x01, 0xA7}, "Apple"},
    {{0x9C, 0x20, 0x7B}, "Apple"},
    {{0xA0, 0x99, 0x9B}, "Apple"},
    {{0xA4, 0xB1, 0xC1}, "Intel"},
    {{0xA8, 0x51, 0xAB}, "Samsung"},
    {{0xAC, 0xBC, 0x32}, "Apple"},
    {{0xB0, 0x19, 0xC6}, "Apple"},
    {{0xB4, 0x1E, 0x52}, "Liteon"},
    {{0xB8, 0x27, 0xEB}, "Raspberry"},
    {{0xBC, 0x3A, 0xEA}, "Guangdong"},
    {{0xC0, 0xB6, 0x58}, "Apple"},
    {{0xC4, 0x2A, 0xD0}, "Intel"},
    {{0xC8, 0x69, 0xCD}, "Apple"},
    {{0xCC, 0x46, 0xD6}, "Cisco"},
    {{0xD0, 0x39, 0x57}, "Liteon"},
    {{0xD4, 0xF4, 0x6F}, "Apple"},
    {{0xD8, 0xF3, 0xBC}, "Liteon"},
    {{0xDC, 0x2C, 0x26}, "Apple"},
    {{0xE0, 0x0A, 0xF6}, "Samsung"},
    {{0xE4, 0xC6, 0x3D}, "Apple"},
    {{0xE8, 0x6F, 0x38}, "Apple"},
    {{0xEC, 0x1B, 0xBD}, "Liteon"},
    {{0xF0, 0x18, 0x98}, "Apple"},
    {{0xF0, 0x82, 0xC0}, "Liteon"},
    {{0xF4, 0x5C, 0x89}, "Apple"},
    {{0xF8, 0x95, 0xEA}, "Apple"},
    {{0xFC, 0xE9, 0x98}, "Apple"},
};

static const size_t OUI_TABLE_SIZE = sizeof(ouiTable) / sizeof(ouiTable[0]);

const char* lookupOuiVendor(const uint8_t *mac)
{
    for (size_t i = 0; i < OUI_TABLE_SIZE; i++) {
        OuiEntry entry;
        memcpy_P(&entry, &ouiTable[i], sizeof(OuiEntry));
        if (mac[0] == entry.oui[0] && mac[1] == entry.oui[1] && mac[2] == entry.oui[2]) {
            static char vendorBuf[16];
            strncpy(vendorBuf, entry.vendor, sizeof(vendorBuf) - 1);
            vendorBuf[sizeof(vendorBuf) - 1] = '\0';
            return vendorBuf;
        }
    }
    return nullptr;
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
        if (isxdigit(static_cast<int>(c)))
            t += static_cast<char>(toupper(c));
    }
    if (t.length() == 12)
    {
        for (int i = 0; i < 6; i++)
        {
            out.bytes[i] = static_cast<uint8_t>(strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16));
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6)
    {
        for (int i = 0; i < 3; i++)
        {
            out.bytes[i] = static_cast<uint8_t>(strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16));
        }
        out.len = 3;
        out.ssid[0] = '\0';
        return true;
    }

    if (ln.length() > 0 && ln.length() <= 32) {
        memset(&out, 0, sizeof(out));
        out.len = 255;
        strncpy(out.ssid, ln.c_str(), sizeof(out.ssid) - 1);
        out.ssid[sizeof(out.ssid) - 1] = '\0';
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

    // cppcheck-suppress shadowVariable
    extern DeviceIdentitiesMap deviceIdentities;
    // cppcheck-suppress shadowVariable
    extern std::mutex randMutex;

    // cppcheck-suppress localMutex
    std::lock_guard<std::mutex> lock(randMutex);

    String idStr(identityId);
    auto it = deviceIdentities.find(idStr);
    if (it == deviceIdentities.end()) {
        return false;
    }
    
    const DeviceIdentity& identity = it->second;
    
    return std::any_of(identity.macs.begin(), identity.macs.end(),
        [mac](const MacAddress& macAddr) {
            return memcmp(macAddr.bytes.data(), mac, 6) == 0;
        });
}

String getTargetsList()
{
    String out;
    for (const auto &t : targets)
    {
        if (t.len == 255) {
            out += String(t.ssid);
        }
        else if (t.len == 0 && strlen(t.identityId) > 0) {
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
    ssidTargets.clear();
    int start = 0;
    while (start < static_cast<int>(txt.length()))
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
                if (t.len == 255) {
                    String lower = String(t.ssid);
                    lower.toLowerCase();
                    ssidTargets.push_back(lower);
                }
            }
        }
        start = nl + 1;
    }
}

bool matchesSsid(const char *ssid)
{
    if (!ssid || ssid[0] == '\0') return false;
    String lower = String(ssid);
    lower.toLowerCase();
    return std::any_of(ssidTargets.begin(), ssidTargets.end(),
                       [&lower](const String &s) { return lower == s; });
}

static inline bool matchesMac(const uint8_t *mac)
{
    for (const auto &t : targets)
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
    if (!deauthQueue) return;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 28) return;

    const uint8_t *payload = ppkt->payload;
    uint8_t version = (payload[0] & 0x03);
    uint8_t type    = (payload[0] >> 2) & 0x03;
    uint8_t subtype = (payload[0] >> 4) & 0x0F;

    if (type != 0 || version != 0) return;

    bool isDisassoc = (subtype == 0x0A);
    bool isDeauth   = (subtype == 0x0C);
    if (!isDisassoc && !isDeauth) return;

    DeauthHit hit;
    memcpy(hit.destMac, payload + 4,  6);
    memcpy(hit.srcMac,  payload + 10, 6);
    memcpy(hit.bssid,   payload + 16, 6);
    hit.seqCtrl    = (uint16_t)(payload[22] | (payload[23] << 8));
    hit.reasonCode = (uint16_t)(payload[24] | (payload[25] << 8));
    hit.rssi       = ppkt->rx_ctrl.rssi;
    hit.channel    = ppkt->rx_ctrl.channel;
    hit.timestamp  = millis();
    hit.isDisassoc = isDisassoc;
    hit.isBroadcast = (memcmp(hit.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0);
    hit.companyId  = 0;
    hit.toolHint   = 0;
    // tool: FC C0 00 + reason 0x02 + seqCtrl 0xFFF0 (raw bytes 0xF0 0xFF LE).
    // seqCtrl=0xFFF0 is FIXED non-incrementing — legit STA/AP frames increment seq.
    // Combined with reason=2 = high-confidence tool fingerprint.
    if (hit.reasonCode == 0x0002 && hit.seqCtrl == 0xFFF0) hit.toolHint |= 0x01;
    // bit1 was "tool target reason in {1,4,6,7,8}" — REMOVED: these reasons are
    // commonly used by real APs (router reboot, channel switch, etc.) so flagging
    // them alone produces unacceptable false positives. The rate-based detector
    // (≥20 deauths/10s in flood logic below) catches tool floods regardless.
    // tool deauth flood: broadcast dst — informational only, not standalone alert.
    if (hit.isBroadcast) hit.toolHint |= 0x04;

    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(deauthQueue, &hit, &woken);
    if (woken) portYIELD_FROM_ISR();
}

// Main NimBLE callback
class MyBLEScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        int8_t rssi = advertisedDevice->getRSSI();
        if (rssi > -10) return;
        if (!triangulationActive && rssi < rfConfig.globalRssiThreshold) {
            return;
        }

        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;

        // Phase 1.7 / 3.1 / 3.2: feed BLE adv into detect module via queue.
        // All heavy work (tracker scoring, ODID decode, malformed check)
        // happens in detectTask context — not here in nimble_host callback.
        {
            std::vector<uint8_t> payload = advertisedDevice->getPayload();
            detect_onBleAdv(mac, rssi, payload.data(),
                            (uint16_t)payload.size(), nullptr);
        }

        String deviceName = "Unknown";
        if (advertisedDevice->haveName()) {
            std::string nimbleName = advertisedDevice->getName();
            if (nimbleName.length() > 0) {
                deviceName = "";
                for (size_t i = 0; i < nimbleName.length() && i < 31; i++) {
                    uint8_t c = static_cast<uint8_t>(nimbleName[i]);
                    if (c >= 32 && c <= 126) {
                        deviceName += static_cast<char>(c);
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
            h.rssi = rssi;
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

// Forward declarations for probe system (defined later, needed by snifferScanTask)
using ProbeDevicesMap = std::map<String, ProbeDevice, std::less<String>,
    PsramAllocator<std::pair<const String, ProbeDevice>>>;
using StringSetPsram = std::set<String, std::less<String>, PsramAllocator<String>>;
using StringU32MapPsram = std::map<String, uint32_t, std::less<String>,
    PsramAllocator<std::pair<const String, uint32_t>>>;
static ProbeDevicesMap probeDevices;
static std::mutex probeMutex;
static StringSetPsram uniqueSsids;
static StringSetPsram respondedSsids;
static void addProbeSsid(ProbeDevice &dev, const char *ssid, bool fromResponse = false);
static bool extractSsidFromIE(const uint8_t *payload, uint16_t frameLen, uint16_t ieStart, char *ssidBuf, size_t ssidBufSize);
static bool extractSsidFromProbe(const uint8_t *payload, uint16_t frameLen, char *ssidBuf, size_t ssidBufSize);

static String sanitizeAscii(const char *s, size_t maxLen) {
    String out;
    out.reserve(maxLen);
    for (size_t i = 0; i < maxLen && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c <= 0x7E && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&') {
            out += (char)c;
        }
    }
    return out;
}

static std::string sanitizeAsciiStd(const char *s, size_t maxLen) {
    std::string out;
    out.reserve(maxLen);
    for (size_t i = 0; i < maxLen && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c <= 0x7E && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&') {
            out += (char)c;
        }
    }
    return out;
}

void snifferScanTask(void *pv)
{
    sentinel_kill();
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                 (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    int duration = static_cast<int>(reinterpret_cast<intptr_t>(pv));
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
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Sniffer scan - Mode: " + std::string(modeStr.c_str()) +
                                  " (IN PROGRESS)\nTarget Hits: 0\nStarting...\n";
    }
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

    unsigned long lastBLEScan = 0;
    unsigned long lastWiFiScan = 0;
    unsigned long lastMeshUpdate = 0;
    const unsigned long MESH_DEVICE_SCAN_UPDATE_INTERVAL = 3000;
    // Fire first in-progress results write on first loop iteration so the UI
    // moves off the "Scan starting..." placeholder within ~1 tick.
    unsigned long nextResultsUpdate = millis();
    
    std::set<String> transmittedDevices;

    NimBLEScan *bleScan = pBLEScan;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < duration * 1000 && !stopRequested))
    {
        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) &&
            (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)) {
            lastWiFiScan = millis();

            Serial.println("[SNIFFER] Scanning WiFi networks...");
            int networksFound = WiFi.scanNetworks(false, true, false, rfConfig.wifiChannelTime);
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
                    const uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0)
                    {
                        ssid = "[Hidden]";
                    }

                    if (apCache.find(bssid) == apCache.end())
                    {
                        if (apCache.size() < MAX_AP_CACHE) {
                            apCache[bssid] = ssid;
                        }
                        uniqueMacs.insert(bssid);

                        Hit h;
                        memcpy(h.mac, bssidBytes, 6);
                        h.rssi = rssi;
                        h.ch = WiFi.channel(i);
                        strncpy(h.name, ssid.c_str(), sizeof(h.name) - 1);
                        h.name[sizeof(h.name) - 1] = '\0';
                        h.isBLE = false;

                        if (hitsLog.size() < MAX_LOG_SIZE) {
                            hitsLog.push_back(h);
                        }

                        if (matchesMac(bssidBytes)) {
                            totalHits = totalHits + 1;
                        }

                        String logEntry = "WiFi AP: " + bssid + " SSID: " + ssid +
                                          " RSSI: " + String(rssi) + "dBm CH: " + String(WiFi.channel(i));

                        if (gpsValid)
                        {
                            if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                                logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                                xSemaphoreGive(gpsMutex);
                            }
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
                NimBLEScanResults scanResults = bleScan->getResults(500, false);
                if (stopRequested) break;

                for (int i = 0; i < scanResults.getCount(); i++)
                {
                    const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                    String macStr = device->getAddress().toString().c_str();
                    macStr.toUpperCase();
                    int8_t rssi = device->getRSSI();
                    if (rssi > -10) continue;

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

                        if (bleDeviceCache.size() < MAX_BLE_CACHE) {
                            bleDeviceCache[macStr] = cleanName;
                        }
                        uniqueMacs.insert(macStr);
                        
                        uint8_t mac[6];
                        if (parseMac6(macStr, mac))
                        {
                            Hit h;
                            memcpy(h.mac, mac, 6);
                            h.rssi = rssi;
                            h.ch = 0;
                            strncpy(h.name, cleanName.c_str(), sizeof(h.name) - 1);
                            h.name[sizeof(h.name) - 1] = '\0';
                            h.isBLE = true;
                            if (hitsLog.size() < MAX_LOG_SIZE) {
                                hitsLog.push_back(h);
                            }

                            String logEntry = "BLE Device: " + macStr + " Name: " + cleanName +
                                            " RSSI: " + String(rssi) + "dBm";

                            if (gpsValid)
                            {
                                if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                                    logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                                    xSemaphoreGive(gpsMutex);
                                }
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

            for (const auto& entry : apCache)
            {
                String macStr = entry.first;
                String ssid = entry.second;

                if (transmittedDevices.find(macStr) == transmittedDevices.end() && meshShouldSendMac(macStr))
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

                    if (deviceMsg.length() <= MAX_MESH_SIZE) {
                        if (meshEnqueue(deviceMsg)) {
                            transmittedDevices.insert(macStr);
                            meshMarkMacSent(macStr);
                        }
                    }
                }
            }

            for (const auto& entry : bleDeviceCache)
            {
                String macStr = entry.first;
                String name = entry.second;

                if (transmittedDevices.find(macStr) == transmittedDevices.end() && meshShouldSendMac(macStr))
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

                    if (deviceMsg.length() <= MAX_MESH_SIZE) {
                        if (meshEnqueue(deviceMsg)) {
                            transmittedDevices.insert(macStr);
                            meshMarkMacSent(macStr);
                        }
                    }
                }
            }
        }

        // Drain probeRequestQueue when captureProbes is enabled during device scan
        if (probeDetectionEnabled && probeRequestQueue) {
            ProbeRequestEvent pEvt;
            int pCount = 0;
            while (xQueueReceive(probeRequestQueue, &pEvt, 0) == pdTRUE && pCount < 30) {
                pCount++;

                // Handle probe responses — map responding AP to device
                if (pEvt.isProbeResponse) {
                    char devMac[18];
                    snprintf(devMac, sizeof(devMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                             pEvt.addr1[0], pEvt.addr1[1], pEvt.addr1[2],
                             pEvt.addr1[3], pEvt.addr1[4], pEvt.addr1[5]);
                    char respSsid[33] = {0};
                    extractSsidFromIE(pEvt.payload, pEvt.payloadLen, 36, respSsid, sizeof(respSsid));
                    std::lock_guard<std::mutex> lock(probeMutex);
                    auto pit = probeDevices.find(String(devMac));
                    if (pit != probeDevices.end()) {
                        ProbeDevice &pd = pit->second;
                        char apBssid[18];
                        snprintf(apBssid, sizeof(apBssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 pEvt.addr3[0], pEvt.addr3[1], pEvt.addr3[2],
                                 pEvt.addr3[3], pEvt.addr3[4], pEvt.addr3[5]);
                        strncpy(pd.respondingAP, apBssid, 17);
                        pd.respondingAP[17] = '\0';
                        if (respSsid[0]) {
                            strncpy(pd.respondingSSID, respSsid, 32);
                            pd.respondingSSID[32] = '\0';
                            addProbeSsid(pd, respSsid);
                            respondedSsids.insert(String(respSsid));
                        }
                    }
                    continue;
                }

                if (pEvt.dstMatch) {
                    if (!matchesMac(pEvt.mac)) continue;
                }

                char pmac[18];
                snprintf(pmac, sizeof(pmac), "%02X:%02X:%02X:%02X:%02X:%02X",
                         pEvt.mac[0], pEvt.mac[1], pEvt.mac[2],
                         pEvt.mac[3], pEvt.mac[4], pEvt.mac[5]);

                char pssid[33] = {0};
                bool pHasSsid = false;
                if (!pEvt.dstMatch) {
                    pHasSsid = extractSsidFromProbe(pEvt.payload, pEvt.payloadLen, pssid, sizeof(pssid));
                }

                bool pRandomized = (pEvt.mac[0] & 0x02) && !(pEvt.mac[0] & 0x01);

                std::lock_guard<std::mutex> lock(probeMutex);
                if (pHasSsid && pssid[0]) uniqueSsids.insert(String(pssid));

                auto pit = probeDevices.find(String(pmac));
                if (pit != probeDevices.end()) {
                    ProbeDevice &pd = pit->second;
                    pd.rssi = pEvt.rssi;
                    pd.lastSeen = millis();
                    pd.probeCount++;
                    if (pHasSsid) addProbeSsid(pd, pssid);
                } else if (probeDevices.size() < 100) {
                    ProbeDevice pd = {};
                    memcpy(pd.mac, pEvt.mac, 6);
                    pd.rssi = pEvt.rssi;
                    pd.rssiMin = pEvt.rssi;
                    pd.rssiMax = pEvt.rssi;
                    pd.channel = pEvt.channel;
                    pd.firstSeen = millis();
                    pd.lastSeen = millis();
                    pd.probeCount = 1;
                    pd.isRandomized = pRandomized;
                    pd.respondingAP[0] = '\0';
                    pd.respondingSSID[0] = '\0';
                    if (!pRandomized) {
                        const char *pvLocal = lookupOuiVendor(pEvt.mac);
                        if (pvLocal) strncpy(pd.vendor, pvLocal, sizeof(pd.vendor) - 1);
                    }
                    if (pHasSsid) addProbeSsid(pd, pssid);
                    probeDevices[String(pmac)] = pd;
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
                      "\nTarget Hits: " + std::to_string(totalHits) + "\n\n";
            
            HitsVecPsram sortedHits = hitsLog;
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
                    results += " \"" + std::string(hit.name) + "\"";
                }
                results += "\n";
            }
            if (hitsLog.size() > 50) {
                results += "... (" + std::to_string(hitsLog.size() - 50) + " more)\n";
            }

            // Append probe intelligence if captureProbes enabled
            if (probeDetectionEnabled) {
                std::lock_guard<std::mutex> plock(probeMutex);
                if (!probeDevices.empty()) {
                    results += "\n--- Probe Intelligence (" + std::to_string(probeDevices.size()) + " probing devices) ---\n";
                    int pShown = 0;
                    for (auto &pp : probeDevices) {
                        if (pShown++ >= 20) break;
                        ProbeDevice &pd = pp.second;
                        results += std::string(pp.first.c_str());
                        if (pd.isRandomized) {
                            results += " Rand";
                        } else if (pd.vendor[0]) {
                            std::string v = sanitizeAsciiStd(pd.vendor, sizeof(pd.vendor));
                            if (!v.empty()) results += " " + v;
                        }
                        if (pd.ssidCount > 0) {
                            bool any = false;
                            for (uint8_t si = 0; si < pd.ssidCount; si++) {
                                std::string s = sanitizeAsciiStd(pd.ssids[si], 33);
                                if (s.empty()) continue;
                                if (!any) { results += " probes:"; any = true; }
                                else results += ",";
                                bool ghost = respondedSsids.find(String(pd.ssids[si])) == respondedSsids.end();
                                results += (ghost ? "~\"" : "\"") + s + "\"";
                            }
                        }
                        if (pd.respondingSSID[0]) {
                            std::string rs = sanitizeAsciiStd(pd.respondingSSID, sizeof(pd.respondingSSID));
                            if (!rs.empty()) {
                                results += " AP=\"" + rs + "\"";
                                if (pd.respondingAP[0]) {
                                    std::string rap = sanitizeAsciiStd(pd.respondingAP, sizeof(pd.respondingAP));
                                    if (!rap.empty()) results += " APBSSID=" + rap;
                                }
                            }
                        }
                        results += " x" + std::to_string(pd.probeCount) + "\n";
                    }
                }
            }

            antihunter::lastResults = results;
            nextResultsUpdate = millis() + 1500;
        }

        Serial.printf("[SNIFFER] Total: WiFi APs=%d, BLE=%d, Unique=%d, Hits=%d\n",
                      apCache.size(), bleDeviceCache.size(), uniqueMacs.size(), totalHits.load());

        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (bleScan && bleScan->isScanning())
    {
        bleScan->stop();
        delay(100);
        bleScan->clearResults();
    }

    // Save probe data to SD if captureProbes was enabled
    bool hadProbes = probeDetectionEnabled.load();
    if (hadProbes) {
        std::lock_guard<std::mutex> plock(probeMutex);
        for (const auto &pp : probeDevices) {
            mergeProbeDeviceToDB(pp.second);
        }
        saveProbeDB();
        Serial.printf("[SNIFFER] Saved %u probe devices to DB\n", probeDevices.size());
    }

    probeDetectionEnabled = false;
    scanning = false;
    lastScanEnd = millis();

    radioStopSTA();
    delay(500);

    // Write final results immediately so UI shows them while mesh TX runs
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        std::string results =
            "Sniffer scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Target Hits: " + std::to_string(totalHits) + "\n" +
            "Unique devices: " + std::to_string(uniqueMacs.size()) + "\n\n";

        HitsVecPsram sortedHits = hitsLog;
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

            // Add probe intelligence for target hits (what they're probing for)
            if (hadProbes) {
                char hitMacStr[18];
                snprintf(hitMacStr, sizeof(hitMacStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         hit.mac[0], hit.mac[1], hit.mac[2], hit.mac[3], hit.mac[4], hit.mac[5]);
                std::lock_guard<std::mutex> plock(probeMutex);
                auto pit = probeDevices.find(String(hitMacStr));
                if (pit != probeDevices.end() && pit->second.ssidCount > 0) {
                    bool any = false;
                    for (uint8_t si = 0; si < pit->second.ssidCount; si++) {
                        std::string s = sanitizeAsciiStd(pit->second.ssids[si], 33);
                        if (s.empty()) continue;
                        if (!any) { results += " probes:"; any = true; }
                        else results += ",";
                        bool ghost = respondedSsids.find(String(pit->second.ssids[si])) == respondedSsids.end();
                        results += (ghost ? "~\"" : "\"") + s + "\"";
                    }
                }
            }

            results += "\n";
        }

        if (sortedHits.size() > 100) {
            results += "... (" + std::to_string(sortedHits.size() - 100) + " more)\n";
        }

        // Append probe intelligence summary if captureProbes was enabled
        if (hadProbes) {
            std::lock_guard<std::mutex> plock(probeMutex);
            if (!probeDevices.empty()) {
                results += "\n--- Probe Intelligence (" + std::to_string(probeDevices.size()) + " probing devices) ---\n";
                for (auto &pp : probeDevices) {
                    ProbeDevice &pd = pp.second;
                    results += std::string(pp.first.c_str());
                    if (pd.isRandomized) results += " Rand";
                    else if (pd.vendor[0]) {
                        std::string v = sanitizeAsciiStd(pd.vendor, sizeof(pd.vendor));
                        if (!v.empty()) results += " " + v;
                    }
                    if (pd.ssidCount > 0) {
                        bool any = false;
                        for (uint8_t si = 0; si < pd.ssidCount; si++) {
                            std::string s = sanitizeAsciiStd(pd.ssids[si], 33);
                            if (s.empty()) continue;
                            if (!any) { results += " probes:"; any = true; }
                            else results += ",";
                            bool ghost = respondedSsids.find(String(pd.ssids[si])) == respondedSsids.end();
                            results += (ghost ? "~\"" : "\"") + s + "\"";
                        }
                    }
                    if (pd.respondingSSID[0]) {
                        std::string rs = sanitizeAsciiStd(pd.respondingSSID, sizeof(pd.respondingSSID));
                        if (!rs.empty()) {
                            results += " AP=\"" + rs + "\"";
                            if (pd.respondingAP[0]) {
                                std::string rap = sanitizeAsciiStd(pd.respondingAP, sizeof(pd.respondingAP));
                                if (!rap.empty()) results += " APBSSID=" + rap;
                            }
                        }
                    }
                    results += " x" + std::to_string(pd.probeCount) + "\n";
                }
            }
        }

        antihunter::lastResults = results;
    }

    uint32_t enqueuedDevices = 0;
    uint32_t skippedDevices = 0;

    if (meshEnabled) {
        for (const auto& entry : apCache) {
            if (transmittedDevices.find(entry.first) != transmittedDevices.end()) continue;
            if (!meshShouldSendMac(entry.first)) { skippedDevices++; continue; }
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
            if (deviceMsg.length() <= MAX_MESH_SIZE && meshEnqueue(deviceMsg)) {
                transmittedDevices.insert(entry.first);
                meshMarkMacSent(entry.first);
                enqueuedDevices++;
            }
        }

        for (const auto& entry : bleDeviceCache) {
            if (transmittedDevices.find(entry.first) != transmittedDevices.end()) continue;
            if (!meshShouldSendMac(entry.first)) { skippedDevices++; continue; }
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
            if (deviceMsg.length() <= MAX_MESH_SIZE && meshEnqueue(deviceMsg)) {
                transmittedDevices.insert(entry.first);
                meshMarkMacSent(entry.first);
                enqueuedDevices++;
            }
        }

        if (!stopRequested) {
            uint32_t totalDevices = apCache.size() + bleDeviceCache.size();
            uint32_t totalTx = transmittedDevices.size();
            String summary = getNodeId() + ": SCAN_DONE: W=" + String(apCache.size()) +
                            " B=" + String(bleDeviceCache.size()) +
                            " U=" + String(uniqueMacs.size()) +
                            " H=" + String(totalHits) +
                            " TX=" + String(totalTx) +
                            " DUP=" + String(skippedDevices);
            meshEnqueue(summary);
            Serial.printf("[SNIFFER] Scan complete: total %u/%u devices enqueued (%u from this final pass, %u dedup-skipped)\n",
                         totalTx, totalDevices, enqueuedDevices, skippedDevices);
        }
    }

    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

String getSnifferCache()
{
    static String cachedResult = "";
    static unsigned long lastCacheTime = 0;

    if (millis() - lastCacheTime < 5000 && cachedResult.length() > 0) {
        return cachedResult;
    }
    lastCacheTime = millis();

    String result = "=== Sniffer Cache ===\n\n";
    result += "WiFi APs: " + String(apCache.size()) + "\n";

    int apCount = 0;
    const int MAX_ENTRIES = 250;
    for (const auto &entry : apCache)
    {
        if (apCount++ >= MAX_ENTRIES) {
            result += "... (showing first " + String(MAX_ENTRIES) + " of " + String(apCache.size()) + ")\n";
            break;
        }
        result += entry.first + " : " + entry.second + "\n";
    }

    result += "\nBLE Devices: " + String(bleDeviceCache.size()) + "\n";

    int bleCount = 0;
    for (const auto &entry : bleDeviceCache)
    {
        if (bleCount++ >= MAX_ENTRIES) {
            result += "... (showing first " + String(MAX_ENTRIES) + " of " + String(bleDeviceCache.size()) + ")\n";
            break;
        }
        result += entry.first + " : " + entry.second + "\n";
    }

    cachedResult = result;
    return result;
}

static std::string buildDeauthResults(bool forever, int duration, uint32_t deauthTotal,
                                       uint32_t disassocTotal, const std::vector<DeauthHit>& deauthEntries) {
    std::map<String, DeauthStats> statsMap;
    
    for (const auto& h : deauthEntries) {
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

    // Tool-fingerprint tallies — surface known attacker frameworks
    uint32_t forgeHits = 0, bcastHits = 0;
    for (const auto &h : deauthEntries) {
        if (h.toolHint & 0x01) forgeHits++;
        if (h.toolHint & 0x04) bcastHits++;
    }

    std::string results = "Deauth Attack Detection Results\n";
    results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
    results += "Deauth frames: " + std::to_string(deauthTotal) + "\n";
    results += "Disassoc frames: " + std::to_string(disassocTotal) + "\n";
    results += "Total attacks: " + std::to_string(deauthEntries.size()) + "\n";
    results += "Targets attacked: " + std::to_string(statsMap.size()) + "\n";
    if (forgeHits) results += "tool fingerprint (reason=2 seq=FFF0): " + std::to_string(forgeHits) + "\n";
    if (bcastHits)    results += "Broadcast-dst deauths: " + std::to_string(bcastHits) + " (informational)\n";

    // EAPOL-capture-bait correlation: lone targeted deauth (src sent exactly 1
    // unicast deauth, no follow-up) is the classic "knock-the-client-off and
    // wait for re-auth" PMKID/handshake capture pattern. Count such srcs.
    {
        std::map<String, int> srcUnicastCount;
        for (const auto &h : deauthEntries) {
            if (!h.isBroadcast) {
                srcUnicastCount[macFmt6(h.srcMac)]++;
            }
        }
        uint32_t loneSrcs = static_cast<uint32_t>(std::count_if(srcUnicastCount.begin(), srcUnicastCount.end(),
            [](const auto &kv) { return kv.second == 1; }));
        if (loneSrcs > 0) {
            results += "EAPOL-capture-bait pattern (single targeted deauth, no follow-up): "
                       + std::to_string(loneSrcs) + " srcs\n";
        }
    }
    results += "\n";
    
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
            for (const auto& h : deauthEntries) {
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
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(pv));
    bool forever = (duration <= 0);

    String startMsg = forever ?
                              String("[BLUE] Starting deauth detection (forever)\n")
                              : String("[BLUE] Starting deauth detection for " + String(duration) + "s\n");
    Serial.print(startMsg);
    
    deauthLog.clear();
    deauthCount = 0;
    disassocCount = 0;
    deauthDetectionEnabled = true;
    stopRequested = false;
    scanning = true;

    if (deauthQueue) {
        vQueueDeleteWithCaps(deauthQueue);
    }

    deauthQueue = xQueueCreateWithCaps(256, sizeof(DeauthHit), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!deauthQueue) {
        Serial.println("[BLUE] FATAL: Queue creation failed");
        scanning = false;
        vTaskDelete(NULL);
        return;
    }

    std::set<String> transmittedAttacks;
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Deauth Attack Detection Results\nStarting...\n";
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
    std::map<String, std::vector<uint32_t>> targetHistory;
    uint32_t lastHistoryCleanup = millis();

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {

        int processed = 0;

        while (processed++ < BATCH_LIMIT && xQueueReceive(deauthQueue, &hit, 0) == pdTRUE) {
            uint32_t now = millis();
            String dstMac = macFmt6(hit.destMac);

            targetHistory[dstMac].push_back(now);
            auto& times = targetHistory[dstMac];
            times.erase(
                std::remove_if(times.begin(), times.end(),
                    [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }),
                times.end());

            bool isAttack = hit.isBroadcast
                || (hit.reasonCode == 1 || hit.reasonCode == 2
                    || hit.reasonCode == 6 || hit.reasonCode == 7)
                || (times.size() >= DEAUTH_TARGETED_THRESHOLD);

            if (!isAttack) continue;

            if (hit.isDisassoc) {
                disassocCount = disassocCount + 1;
            } else {
                deauthCount = deauthCount + 1;
            }

            if (deauthLog.size() < 2000) {
                deauthLog.push_back(hit);
            }

            // Feed detect.cpp for EAPOL-capture-bait correlation (unicast only).
            if (!hit.isBroadcast) {
                detect_witnessDeauth(hit.srcMac, hit.destMac, hit.rssi, hit.channel);
            }

            // High-confidence flood detector: ≥20 deauths from same src in 10s.
            // (Cisco WLC default ~30; research recommends 20.)
            static std::map<uint64_t, std::pair<uint32_t, uint16_t>> floodWin;
            {
                static std::set<uint64_t> floodAlerted;
                uint64_t k = 0;
                for (int i = 0; i < 6; ++i) k = (k << 8) | hit.srcMac[i];
                auto it = floodWin.find(k);
                if (it == floodWin.end() || (now - it->second.first) > 10000) {
                    floodWin[k] = {now, 1};
                    floodAlerted.erase(k);
                } else {
                    if (it->second.second < 65535) it->second.second++;
                    if (it->second.second >= 20 && !floodAlerted.count(k)) {
                        floodAlerted.insert(k);
                        String s = macFmt6(hit.srcMac);
                        Serial.printf("[DETECT] DEAUTH_FLOOD src=%s count=%u in 10s\n",
                                      s.c_str(), it->second.second);
                        if (meshEnabled && ah_detect::g_meshDeauth.load())
                        meshEnqueue(getNodeId() + ": DEAUTH_FLOOD:" + s + ":" +
                                    String(it->second.second) + ":" + String(hit.rssi));
                    }
                }
                // Bound map size — evict oldest if >64 srcs tracked.
                if (floodWin.size() > 64) {
                    uint32_t oldest = UINT32_MAX; uint64_t oldestK = 0;
                    for (const auto &kv : floodWin) if (kv.second.first < oldest) { oldest = kv.second.first; oldestK = kv.first; }
                    floodWin.erase(oldestK);
                }
            }

            String srcMac = macFmt6(hit.srcMac);
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

            if (meshEnabled && ah_detect::g_meshDeauth.load() && transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                String meshAlert = getNodeId() + ": ATTACK: " + alert;
                if (gpsValid) {
                    if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                        meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                        xSemaphoreGive(gpsMutex);
                    }
                }
                if (meshEnqueue(meshAlert)) {
                    transmittedAttacks.insert(attackKey);
                }
            }
        }

        if (meshEnabled && (millis() - lastMeshUpdate >= MESH_DEAUTH_UPDATE_INTERVAL)) {
            lastMeshUpdate = millis();

            for (const auto& entry : deauthLog) {
                String srcMac = macFmt6(entry.srcMac);
                String dstMac = macFmt6(entry.destMac);
                String attackKey = srcMac + "->" + dstMac;

                if (ah_detect::g_meshDeauth.load() && transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                    String attackMsg = getNodeId() + ": ATTACK: ";
                    attackMsg += String(entry.isDisassoc ? "DISASSOC" : "DEAUTH");
                    attackMsg += " " + srcMac + "->" + dstMac;
                    attackMsg += " R" + String(entry.rssi) + " C" + String(entry.channel);

                    if (attackMsg.length() <= MAX_MESH_SIZE && meshEnqueue(attackMsg)) {
                        transmittedAttacks.insert(attackKey);
                    }
                }
            }
        }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLUE] Deauth:%u Disassoc:%u Total:%u\n",
                         deauthCount.load(), disassocCount.load(), (unsigned)deauthLog.size());
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
            lastCleanup = millis();
        }

        if (millis() - lastHistoryCleanup > DEAUTH_CLEANUP_INTERVAL) {
            uint32_t now = millis();
            for (auto it = targetHistory.begin(); it != targetHistory.end(); ) {
                auto& vec = it->second;
                vec.erase(
                    std::remove_if(vec.begin(), vec.end(),
                        [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }),
                    vec.end());
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
            lastHistoryCleanup = millis();
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
        vQueueDeleteWithCaps(deauthQueue);
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

    // Log deauth events to SD
    if (SafeSD::isAvailable() && !deauthLog.empty()) {
        uint32_t now = getEventTimestamp();
        for (const auto& deauthHit : deauthLog) {
            DynamicJsonDocument doc(384);
            doc["t"] = now;
            doc["src"] = macFmt6(deauthHit.srcMac);
            doc["dst"] = macFmt6(deauthHit.destMac);
            doc["bssid"] = macFmt6(deauthHit.bssid);
            doc["rssi"] = deauthHit.rssi;
            doc["ch"] = deauthHit.channel;
            doc["reason"] = deauthHit.reasonCode;
            doc["disassoc"] = deauthHit.isDisassoc;
            doc["broadcast"] = deauthHit.isBroadcast;
            doc["seq"] = deauthHit.seqCtrl;
            doc["tool"] = deauthHit.toolHint;  // bit0=tool bit1=tool-target bit2=tool-flood
            String line;
            serializeJson(doc, line);
            logEventToSD("/deauth.jsonl", line);
        }
        Serial.printf("[BLUE] Logged %d deauth events to SD\n", (int)deauthLog.size());
    }

    if (meshEnabled && !stopRequested) {
        uint32_t enqueued = 0;
        for (const auto& entry : deauthLog) {
            String srcMac = macFmt6(entry.srcMac);
            String dstMac = macFmt6(entry.destMac);
            String attackKey = srcMac + "->" + dstMac;

            if (ah_detect::g_meshDeauth.load() && transmittedAttacks.find(attackKey) == transmittedAttacks.end()) {
                String attackMsg = getNodeId() + ": ATTACK: ";
                attackMsg += String(entry.isDisassoc ? "DISASSOC" : "DEAUTH");
                attackMsg += " " + srcMac + "->" + dstMac;
                attackMsg += " R" + String(entry.rssi) + " C" + String(entry.channel);

                if (attackMsg.length() <= MAX_MESH_SIZE && meshEnqueue(attackMsg)) {
                    transmittedAttacks.insert(attackKey);
                    enqueued++;
                }
            }
        }

        uint32_t totalAttacks = deauthLog.size();
        String summary = getNodeId() + ": DEAUTH_DONE: Total=" + String(deauthCount + disassocCount) +
                        " Deauth=" + String(deauthCount) +
                        " Disassoc=" + String(disassocCount) +
                        " TX=" + String(transmittedAttacks.size());
        meshEnqueue(summary);
        Serial.printf("[BLUE] Detection complete: enqueued %u (total %u attacks)\n",
                     enqueued, totalAttacks);
    }

    Serial.println("[BLUE] Deauth detection stopped cleanly");
    
    radioStopSTA();
    vTaskDelay(pdMS_TO_TICKS(200));

    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static uint8_t extractChannelFromIE(const uint8_t *payload, uint16_t length, uint16_t ieStart = 24) {
    if (length < ieStart) return 0;

    const uint8_t *ie = payload + ieStart;
    uint16_t ieLen = length - ieStart;
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

void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!buf) return;

    const wifi_promiscuous_pkt_t *ppkt = static_cast<wifi_promiscuous_pkt_t *>(buf);

    // Jamming PHY-stat: feed EVERY packet (incl. CRC-fail / short error frames)
    // before any length/rssi gate, so PDR-vs-error accounting sees the failures.
    detect_onPhyStat(ppkt->rx_ctrl.rx_state, ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);

    if (ppkt->rx_ctrl.sig_len < 24) {
        return;
    }

    int8_t rssiThreshold;
    portENTER_CRITICAL_ISR(&rfConfigMux);
    rssiThreshold = rfConfig.globalRssiThreshold;
    portEXIT_CRITICAL_ISR(&rfConfigMux);

    if (!triangulationActive && ppkt->rx_ctrl.rssi < rssiThreshold) {
        return;
    }

    if (droneDetectionEnabled && droneFrameQueue) {
        DroneFrameEvent droneEvt;
        uint16_t copyLen = ppkt->rx_ctrl.sig_len < sizeof(droneEvt.payload)
                           ? ppkt->rx_ctrl.sig_len
                           : static_cast<uint16_t>(sizeof(droneEvt.payload));
        memcpy(droneEvt.payload, ppkt->payload, copyLen);
        droneEvt.len  = copyLen;
        droneEvt.rssi = ppkt->rx_ctrl.rssi;
        BaseType_t woken = pdFALSE;
        xQueueSendFromISR(droneFrameQueue, &droneEvt, &woken);
        if (woken) portYIELD_FROM_ISR();
    }

    if ((randomizationDetectionEnabled || probeDetectionEnabled) && ppkt->rx_ctrl.sig_len >= 24) {
        const uint8_t *payload = ppkt->payload;
        uint16_t fc = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
        uint8_t ftype = (fc >> 2) & 0x3;
        uint8_t stype = (fc >> 4) & 0xF;

        if (ftype == 0 && (stype == 4 || stype == 8)) {
            const uint8_t *sa = payload + 10;
            // Beacons (stype 8) have 12-byte fixed body before IEs;
            // Probe requests (stype 4) have IEs right after MAC header
            uint16_t ieOffset = (stype == 8) ? 36 : 24;
            uint8_t actualChannel = extractChannelFromIE(payload, ppkt->rx_ctrl.sig_len, ieOffset);
            if (actualChannel == 0) {
                actualChannel = ppkt->rx_ctrl.channel;
            }

            if (randomizationDetectionEnabled && stype == 4) {
                processProbeRequest(sa, ppkt->rx_ctrl.rssi, actualChannel,
                                payload, ppkt->rx_ctrl.sig_len);
            }

            if (probeDetectionEnabled && probeRequestQueue && stype == 4) {
                // Only queue actual probe requests, not beacons
                ProbeRequestEvent probeEvt = {};
                memcpy(probeEvt.mac, sa, 6);
                probeEvt.rssi = ppkt->rx_ctrl.rssi;
                probeEvt.channel = actualChannel;
                probeEvt.payloadLen = ppkt->rx_ctrl.sig_len < sizeof(probeEvt.payload)
                                      ? ppkt->rx_ctrl.sig_len
                                      : static_cast<uint16_t>(sizeof(probeEvt.payload));
                memcpy(probeEvt.payload, payload, probeEvt.payloadLen);
                probeEvt.dstMatch = false;
                probeEvt.isProbeResponse = false;
                BaseType_t woken = pdFALSE;
                xQueueSendFromISR(probeRequestQueue, &probeEvt, &woken);
                if (woken) portYIELD_FROM_ISR();
            }
        }

        // Probe Response (stype 5): addr1=DA (client), addr2=SA (AP), addr3=BSSID
        // Captures which APs are responding to which devices and what SSID they serve
        // Rate-limited: only queue if queue <50% full to preserve capacity for probe requests
        else if (ftype == 0 && stype == 5 && probeDetectionEnabled && probeRequestQueue) {
            // Skip probe responses when queue is getting full — probe requests have priority
            UBaseType_t qFree = uxQueueSpacesAvailable(probeRequestQueue);
            if (qFree > 128) {
                const uint8_t *da = payload + 4;

                if (da[0] != 0xFF && !(da[0] & 0x01)) {
                    const uint8_t *sa = payload + 10;
                    const uint8_t *bssid = payload + 16;
                    ProbeRequestEvent respEvt = {};
                    memcpy(respEvt.mac, sa, 6);
                    memcpy(respEvt.addr1, da, 6);
                    memcpy(respEvt.addr3, bssid, 6);
                    respEvt.rssi = ppkt->rx_ctrl.rssi;
                    respEvt.channel = ppkt->rx_ctrl.channel;
                    respEvt.payloadLen = ppkt->rx_ctrl.sig_len < sizeof(respEvt.payload)
                                         ? ppkt->rx_ctrl.sig_len
                                         : static_cast<uint16_t>(sizeof(respEvt.payload));
                    memcpy(respEvt.payload, payload, respEvt.payloadLen);
                    respEvt.dstMatch = false;
                    respEvt.isProbeResponse = true;
                    BaseType_t woken = pdFALSE;
                    xQueueSendFromISR(probeRequestQueue, &respEvt, &woken);
                    if (woken) portYIELD_FROM_ISR();
                }
            }
        }

        else if (ftype == 0 && (stype == 11 || stype == 0 || stype == 2)) {
            const uint8_t *srcMac = payload + 10;
            if (isGlobalMAC(srcMac) && authFrameQueue) {
                AuthFrameEvent authEvt;
                memcpy(authEvt.mac, srcMac, 6);
                authEvt.rssi    = ppkt->rx_ctrl.rssi;
                authEvt.channel = ppkt->rx_ctrl.channel;
                authEvt.len = ppkt->rx_ctrl.sig_len < sizeof(authEvt.payload)
                              ? ppkt->rx_ctrl.sig_len
                              : static_cast<uint16_t>(sizeof(authEvt.payload));
                memcpy(authEvt.payload, payload, authEvt.len);
                BaseType_t woken = pdFALSE;
                xQueueSendFromISR(authFrameQueue, &authEvt, &woken);
                if (woken) portYIELD_FROM_ISR();
            }
        }

        // Queue dst events only for subtypes NOT already captured above
        // Skip stype 4 (probe req), 5 (probe resp), 8 (beacon) — already handled
        // Only queue dst events when queue has plenty of room for probe requests
        if (probeDetectionEnabled && ftype == 0 && probeRequestQueue &&
            stype != 4 && stype != 5 && stype != 8) {
            UBaseType_t qFree2 = uxQueueSpacesAvailable(probeRequestQueue);
            if (qFree2 > 192) {
                const uint8_t *da = payload + 4;
                if (da[0] != 0xFF && !(da[0] & 0x01)) {
                    ProbeRequestEvent dstEvt = {};
                    memcpy(dstEvt.mac, da, 6);
                    dstEvt.rssi = ppkt->rx_ctrl.rssi;
                    dstEvt.channel = ppkt->rx_ctrl.channel;
                    dstEvt.payloadLen = 0;
                    dstEvt.dstMatch = true;
                    dstEvt.isProbeResponse = false;
                    BaseType_t woken = pdFALSE;
                    xQueueSendFromISR(probeRequestQueue, &dstEvt, &woken);
                    if (woken) portYIELD_FROM_ISR();
                }
            }
        }
    }

    detectDeauthFrame(ppkt);

    // Phase 1: attack-signature detectors (PMKID, evil-twin, SSID confusion,
    // SAE DoS, OWE abuse, FragAttacks PN reuse). Enqueues to detect task,
    // ISR-safe (xQueueSendFromISR inside).
    detect_onWifiFrame(ppkt->payload, ppkt->rx_ctrl.sig_len,
                       ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);

    framesSeen = framesSeen + 1;

    const uint8_t *p = ppkt->payload;
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t tods = (fc >> 8) & 0x1;
    uint8_t fromds = (fc >> 9) & 0x1;

    const uint8_t *a2 = p + 10, *a3 = p + 16;
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
        // cppcheck-suppress variableScope
        const uint8_t *a1 = p + 4;
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

    WiFi.mode(WIFI_AP_STA);  // Keep AP alive during scanning - TODO investigate other ways
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
    if (pBLEScan && pBLEScan->isScanning())
    {
        pBLEScan->stop();
        vTaskDelay(pdMS_TO_TICKS(100));
        pBLEScan->clearResults();
    }
}

static volatile bool bleInitDone = false;
static volatile bool bleInitFailed = false;

static void bleInitTask(void *pv) {
    Serial.printf("[BLE_INIT] core=%d heap=%u largest=%u\n",
                  xPortGetCoreID(),
                  (unsigned)ESP.getFreeHeap(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    if (!pBLEScan) {
        Serial.println("[BLE_INIT] getScan() returned NULL");
        bleInitFailed = true;
        bleInitDone = true;
        vTaskDelete(NULL);
        return;
    }
    pBLEScan->setScanCallbacks(new MyBLEScanCallbacks(), true);
    pBLEScan->setActiveScan(true);
    pBLEScan->setDuplicateFilter(false);
    Serial.printf("[BLE_INIT] ready (heap=%u psram=%u)\n",
                  (unsigned)ESP.getFreeHeap(),
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    bleInitDone = true;
    vTaskDelete(NULL);
}

void initBLEOnce() {
    if (bleInitDone) return;
    TaskHandle_t h = nullptr;
    BaseType_t r = xTaskCreatePinnedToCore(
        bleInitTask, "ble_init", 8192, nullptr, 5, &h, 0);
    if (r != pdPASS) {
        Serial.println("[BLE_INIT] task create failed");
        bleInitFailed = true;
        bleInitDone = true;
        return;
    }
    uint32_t waitStart = millis();
    while (!bleInitDone && (millis() - waitStart) < 8000) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (!bleInitDone) {
        Serial.println("[BLE_INIT] timeout");
        bleInitFailed = true;
        bleInitDone = true;
    }
}

void radioStartBLE()
{
    (void)radioStartBLEChecked();
}

bool radioStartBLEChecked()
{
    initBLEOnce();
    if (!pBLEScan || bleInitFailed) {
        Serial.println("[RADIO] BLE not available");
        return false;
    }
    if (pBLEScan->isScanning()) {
        return true;
    }
    pBLEScan->setInterval(rfConfig.bleScanInterval / 10);
    pBLEScan->setWindow((rfConfig.bleScanInterval / 10) - 10);
    if (!pBLEScan->start(0, false)) {
        Serial.println("[RADIO] BLE scan start returned false");
        return false;
    }
    return true;
}


// Mutex for macQueue access - prevents race conditions during cleanup
static SemaphoreHandle_t macQueueMutex = nullptr;

void initMacQueueMutex() {
    if (macQueueMutex == nullptr) {
        macQueueMutex = xSemaphoreCreateMutex();
    }
}

// Safe queue send with mutex protection
bool safeMacQueueSend(const Hit* hit, TickType_t timeout) {
    if (macQueueMutex == nullptr || macQueue == nullptr) return false;
    if (xSemaphoreTake(macQueueMutex, pdMS_TO_TICKS(50)) != pdTRUE) return false;
    bool result = false;
    if (macQueue != nullptr) {
        result = (xQueueSend(macQueue, hit, timeout) == pdTRUE);
    }
    xSemaphoreGive(macQueueMutex);
    return result;
}

// Safe queue receive with mutex protection
bool safeMacQueueReceive(Hit* hit, TickType_t timeout) {
    if (macQueueMutex == nullptr || macQueue == nullptr) return false;
    if (xSemaphoreTake(macQueueMutex, pdMS_TO_TICKS(50)) != pdTRUE) return false;
    bool result = false;
    if (macQueue != nullptr) {
        result = (xQueueReceive(macQueue, hit, timeout) == pdTRUE);
    }
    xSemaphoreGive(macQueueMutex);
    return result;
}

// Safe queue delete with mutex protection
void safeMacQueueDelete() {
    if (macQueueMutex == nullptr) return;
    if (xSemaphoreTake(macQueueMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        if (macQueue != nullptr) {
            vQueueDeleteWithCaps(macQueue);
            macQueue = nullptr;
        }
        xSemaphoreGive(macQueueMutex);
    }
}

// Safe queue create with mutex protection
bool safeMacQueueCreate(size_t queueSize) {
    initMacQueueMutex();
    if (macQueueMutex == nullptr) return false;
    if (xSemaphoreTake(macQueueMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        if (macQueue != nullptr) {
            vQueueDeleteWithCaps(macQueue);
            macQueue = nullptr;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
        macQueue = xQueueCreateWithCaps(queueSize, sizeof(Hit), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        xSemaphoreGive(macQueueMutex);
        return (macQueue != nullptr);
    }
    return false;
}

void radioStopSTA() {
    Serial.println("[RADIO] Stopping STA mode");

    // Stop promiscuous mode first (if active)
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Stop channel hopping timer
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        vTaskDelay(pdMS_TO_TICKS(50));
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (pBLEScan && pBLEScan->isScanning()) {
        pBLEScan->stop();
        vTaskDelay(pdMS_TO_TICKS(100));
        pBLEScan->clearResults();
    }

    esp_wifi_set_channel(AP_CHANNEL, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));

    Serial.println("[RADIO] STA mode stopped");
}

// Start promiscuous/sniffer mode (for snifferScanTask)
void radioStartSTA() {
    Serial.println("[RADIO] Starting STA mode (promiscuous)");

    // Use AP_STA mode
    WiFi.mode(WIFI_AP_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Configure STA for scanning while keeping AP alive
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
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

// Start list scan mode - NO promiscuous mode, uses WiFi.scanNetworks()
// This avoids IPC task stack overflow by not running promiscuous + scanNetworks together
void radioStartListScan() {
    Serial.println("[RADIO] Starting list scan mode (non-promiscuous)");

    // Ensure promiscuous mode is OFF - critical to avoid IPC stack overflow
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    vTaskDelay(pdMS_TO_TICKS(50));

    // Stop any existing channel hopping
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }

    // Use AP_STA mode
    WiFi.mode(WIFI_AP_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Configure country for scanning
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);

    Serial.println("[RADIO] List scan mode ready (WiFi.scanNetworks will be used)");
}

// Stop list scan mode
void radioStopListScan() {
    Serial.println("[RADIO] Stopping list scan mode");

    // Clean up any pending scan
    WiFi.scanDelete();
    vTaskDelay(pdMS_TO_TICKS(50));

    if (pBLEScan && pBLEScan->isScanning()) {
        pBLEScan->stop();
        vTaskDelay(pdMS_TO_TICKS(100));
        pBLEScan->clearResults();
    }

    WiFi.mode(WIFI_AP_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    Serial.println("[RADIO] List scan mode stopped");
}

static std::atomic<uint32_t> totalProbeCount(0);
static std::atomic<uint32_t> probeHitCount(0);
static StringU32MapPsram probeHitCooldowns;
static const uint32_t PROBE_HIT_COOLDOWN_MS = 60000;

static void addProbeSsid(ProbeDevice &dev, const char *ssid, bool fromResponse)
{
    if (!ssid || ssid[0] == '\0') return;
    for (uint8_t i = 0; i < dev.ssidCount; i++) {
        if (strcasecmp(dev.ssids[i], ssid) == 0) return;
    }
    if (dev.ssidCount < 8) {
        strncpy(dev.ssids[dev.ssidCount], ssid, 32);
        dev.ssids[dev.ssidCount][32] = '\0';
        dev.ssidCount++;
        return;
    }
    if (fromResponse) {
        for (uint8_t i = 1; i < 8; i++) {
            memcpy(dev.ssids[i - 1], dev.ssids[i], 33);
        }
        strncpy(dev.ssids[7], ssid, 32);
        dev.ssids[7][32] = '\0';
    }
}

// Extract SSID from IE tags. ieStart=24 for probe requests, 36 for probe responses/beacons.
static bool extractSsidFromIE(const uint8_t *payload, uint16_t frameLen, uint16_t ieStart, char *ssidBuf, size_t ssidBufSize)
{
    if (frameLen < ieStart + 2) return false;
    const uint8_t *ie = payload + ieStart;
    uint16_t ieLen = frameLen - ieStart;
    uint16_t offset = 0;
    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];
        if (offset + 2 + len > ieLen) break;
        if (tag == 0) {
            if (len == 0) { ssidBuf[0] = '\0'; return false; }
            size_t copyLen = (len < ssidBufSize - 1) ? len : (ssidBufSize - 1);
            memcpy(ssidBuf, &ie[offset + 2], copyLen);
            ssidBuf[copyLen] = '\0';
            return true;
        }
        offset += 2 + len;
    }
    return false;
}

static bool extractSsidFromProbe(const uint8_t *payload, uint16_t frameLen, char *ssidBuf, size_t ssidBufSize)
{
    if (frameLen < 26) return false;
    const uint8_t *ie = payload + 24;
    uint16_t ieLen = frameLen - 24;
    uint16_t offset = 0;
    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];
        if (offset + 2 + len > ieLen) break;
        if (tag == 0) {
            if (len == 0) {
                ssidBuf[0] = '\0';
                return false;
            }
            size_t copyLen = (len < ssidBufSize - 1) ? len : (ssidBufSize - 1);
            memcpy(ssidBuf, &ie[offset + 2], copyLen);
            ssidBuf[copyLen] = '\0';
            return true;
        }
        offset += 2 + len;
    }
    return false;
}

static const size_t PROBE_HIT_COOLDOWN_MAX = 500;

static bool shouldSendProbeHit(const String &key)
{
    uint32_t now = millis();

    if (probeHitCooldowns.size() >= PROBE_HIT_COOLDOWN_MAX) {
        for (auto it = probeHitCooldowns.begin(); it != probeHitCooldowns.end(); ) {
            if ((now - it->second) >= PROBE_HIT_COOLDOWN_MS)
                it = probeHitCooldowns.erase(it);
            else
                ++it;
        }
    }

    auto it = probeHitCooldowns.find(key);
    if (it == probeHitCooldowns.end()) {
        probeHitCooldowns[key] = now;
        return true;
    }
    if ((now - it->second) >= PROBE_HIT_COOLDOWN_MS) {
        it->second = now;
        return true;
    }
    return false;
}

static void sendProbeHitMesh(const uint8_t *mac, int8_t rssi, uint8_t channel,
                              const char *ssid, const char *vendor, bool isDst,
                              bool ghostSsid)
{
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    String key = String(macStr);
    if (ssid && ssid[0]) key += String(ssid);
    if (!shouldSendProbeHit(key)) return;

    String msg = getNodeId() + ": PROBE_HIT " + String(macStr) + " ";
    bool randomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
    if (randomized) {
        msg += "Randomized";
    } else if (vendor && vendor[0]) {
        msg += String(vendor);
    } else {
        msg += "Unknown";
    }
    msg += " RSSI=" + String(rssi) + " CH=" + String(channel);
    if (ssid && ssid[0]) {
        msg += " SSID=\"" + String(ssid) + "\"";
        if (ghostSsid) msg += " GHOST";
    }
    if (isDst) {
        msg += " DST";
    }

    if (msg.length() <= static_cast<size_t>(MAX_MESH_SIZE)) {
        meshEnqueue(msg);
    }
}

void probeDetectionTask(void *pv)
{
    sentinel_kill();
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(pv));
    bool forever = (duration <= 0);

    Serial.printf("[PROBE] Starting probe detection, duration=%d forever=%d\n", duration, forever);

    // Load known device database from SD
    loadProbeDB();
    Serial.printf("[PROBE] Probe DB loaded: %u known devices\n", getProbeDBSize());

    {
        std::lock_guard<std::mutex> lock(probeMutex);
        probeDevices.clear();
        uniqueSsids.clear();
        respondedSsids.clear();
        totalProbeCount = 0;
        probeHitCount = 0;
        probeHitCooldowns.clear();
    }

    if (probeRequestQueue == nullptr) {
        probeRequestQueue = xQueueCreateWithCaps(256, sizeof(ProbeRequestEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    } else {
        xQueueReset(probeRequestQueue);
    }

    probeDetectionEnabled = true;
    scanning = true;

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Probe scan - Mode: WiFi (IN PROGRESS)\nDevices: 0 | Probes: 0 | SSIDs: 0 | Saved: 0\n\n(Starting...)\n";
    }

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    uint32_t startTime = millis();
    uint32_t nextResultsUpdate = startTime;
    uint32_t lastBLEScan = 0;
    uint32_t lastDBSave = startTime;
    uint32_t totalDrained = 0;

    while ((forever && !stopRequested) ||
           (!forever && (millis() - startTime) < (uint32_t)(duration * 1000) && !stopRequested)) {

        ProbeRequestEvent event;
        int processedCount = 0;
        // Drain aggressively each loop — queue is 256 deep, ISR fills fast.
        // Higher cap = lower latency from probe RX → UI update.
        while (xQueueReceive(probeRequestQueue, &event, 0) == pdTRUE && processedCount < 200) {
            totalDrained++;
            processedCount++;

            // --- Probe Response (stype 5) ---
            // Maps the responding AP's SSID to the device that sent the probe request
            if (event.isProbeResponse) {
                // addr1 = device that probed, extract SSID from probe response IEs (offset 36)
                char devMacStr[18];
                snprintf(devMacStr, sizeof(devMacStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         event.addr1[0], event.addr1[1], event.addr1[2],
                         event.addr1[3], event.addr1[4], event.addr1[5]);

                char apBssid[18];
                snprintf(apBssid, sizeof(apBssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                         event.addr3[0], event.addr3[1], event.addr3[2],
                         event.addr3[3], event.addr3[4], event.addr3[5]);

                char respSsid[33] = {0};
                extractSsidFromIE(event.payload, event.payloadLen, 36, respSsid, sizeof(respSsid));

                std::lock_guard<std::mutex> lock(probeMutex);
                auto it = probeDevices.find(String(devMacStr));
                if (it != probeDevices.end()) {
                    ProbeDevice &dev = it->second;
                    strncpy(dev.respondingAP, apBssid, 17);
                    dev.respondingAP[17] = '\0';
                    if (respSsid[0]) {
                        strncpy(dev.respondingSSID, respSsid, 32);
                        dev.respondingSSID[32] = '\0';
                        addProbeSsid(dev, respSsid, true);
                        uniqueSsids.insert(String(respSsid));
                        respondedSsids.insert(String(respSsid));
                    }
                }
                continue;
            }

            totalProbeCount++;

            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                     event.mac[0], event.mac[1], event.mac[2],
                     event.mac[3], event.mac[4], event.mac[5]);

            // dst events are unfiltered unicast from ISR — verify target here
            if (event.dstMatch) {
                if (!matchesMac(event.mac)) continue;
            }

            char ssidBuf[33] = {0};
            bool hasSSID = false;
            if (!event.dstMatch) {
                hasSSID = extractSsidFromProbe(event.payload, event.payloadLen, ssidBuf, sizeof(ssidBuf));
            }

            bool macHit = matchesMac(event.mac);
            bool ssidHit = hasSSID && matchesSsid(ssidBuf);
            bool dstHit = event.dstMatch;
            bool isHit = macHit || ssidHit || dstHit;

            bool randomized = (event.mac[0] & 0x02) && !(event.mac[0] & 0x01);
            const char *vendor = nullptr;
            if (!randomized) {
                vendor = lookupOuiVendor(event.mac);
            }

            {
                std::lock_guard<std::mutex> lock(probeMutex);

                if (hasSSID && ssidBuf[0]) {
                    uniqueSsids.insert(String(ssidBuf));
                }

                auto it = probeDevices.find(String(macStr));
                if (it != probeDevices.end()) {
                    ProbeDevice &dev = it->second;
                    dev.rssi = event.rssi;
                    if (event.rssi < dev.rssiMin) dev.rssiMin = event.rssi;
                    if (event.rssi > dev.rssiMax) dev.rssiMax = event.rssi;
                    dev.channel = event.channel;
                    dev.lastSeen = millis();
                    dev.probeCount++;
                    if (hasSSID) addProbeSsid(dev, ssidBuf);
                    if (isHit && !dev.isTargetHit) {
                        dev.isTargetHit = true;
                        probeHitCount++;
                    }
                    if (dstHit) dev.isDstHit = true;
                } else {
                    if (probeDevices.size() >= 100) {
                        uint32_t oldestTime = UINT32_MAX;
                        String oldestKey;
                        for (const auto &p : probeDevices) {
                            if (!p.second.isTargetHit && p.second.lastSeen < oldestTime) {
                                oldestTime = p.second.lastSeen;
                                oldestKey = p.first;
                            }
                        }
                        if (oldestKey.length() > 0) probeDevices.erase(oldestKey);
                    }

                    ProbeDevice dev = {};
                    memcpy(dev.mac, event.mac, 6);
                    dev.rssi = event.rssi;
                    dev.rssiMin = event.rssi;
                    dev.rssiMax = event.rssi;
                    dev.channel = event.channel;
                    dev.firstSeen = millis();
                    dev.lastSeen = millis();
                    dev.probeCount = 1;
                    dev.ssidCount = 0;
                    dev.isRandomized = randomized;
                    dev.isTargetHit = isHit;
                    dev.isDstHit = dstHit;
                    dev.respondingAP[0] = '\0';
                    dev.respondingSSID[0] = '\0';

                    // Annotate with SD database history
                    ProbeDBEntry hist;
                    if (lookupProbeHistory(macStr, hist)) {
                        dev.histKnown = true;
                        dev.histTotalSeen = hist.totalSeen;
                        dev.histFirstEpoch = hist.firstEpoch;
                        dev.histLastEpoch = hist.lastEpoch;
                        dev.histSessionCount = hist.sessionCount;
                    } else {
                        dev.histKnown = false;
                        dev.histTotalSeen = 0;
                        dev.histFirstEpoch = 0;
                        dev.histLastEpoch = 0;
                        dev.histSessionCount = 0;
                    }

                    if (vendor) {
                        strncpy(dev.vendor, vendor, sizeof(dev.vendor) - 1);
                        dev.vendor[sizeof(dev.vendor) - 1] = '\0';
                    } else {
                        dev.vendor[0] = '\0';
                    }

                    if (ssidHit) strncpy(dev.hitReason, "SSID", sizeof(dev.hitReason));
                    else if (dstHit) strncpy(dev.hitReason, "DST", sizeof(dev.hitReason));
                    else if (macHit) strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason));
                    else dev.hitReason[0] = '\0';

                    if (hasSSID) addProbeSsid(dev, ssidBuf);
                    probeDevices[String(macStr)] = dev;
                    if (isHit) probeHitCount++;
                }
            }

            if (isHit || probeBroadcastAll.load(std::memory_order_relaxed)) {
                bool ghostSsid = hasSSID && ssidBuf[0] &&
                                 respondedSsids.find(String(ssidBuf)) == respondedSsids.end();
                sendProbeHitMesh(event.mac, event.rssi, event.channel, ssidBuf, vendor, dstHit, ghostSsid);
            }
        }

        if ((int32_t)(millis() - nextResultsUpdate) >= 0) {
            std::string results = getProbeResults().c_str();
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            nextResultsUpdate = millis() + 2000;
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) &&
            pBLEScan && (millis() - lastBLEScan >= 3000)) {
            pBLEScan->start(2, false);
            NimBLEScanResults scanResults = pBLEScan->getResults(500, false);
            int count = scanResults.getCount();
            for (int i = 0; i < count; i++) {
                const NimBLEAdvertisedDevice *device = scanResults.getDevice(i);
                if (!device) continue;
                String macStr = device->getAddress().toString().c_str();
                macStr.toUpperCase();
                uint8_t mac[6];
                if (sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                    if (matchesMac(mac)) {
                        std::lock_guard<std::mutex> lock(probeMutex);
                        auto it = probeDevices.find(macStr);
                        if (it == probeDevices.end()) {
                            ProbeDevice dev = {};
                            memcpy(dev.mac, mac, 6);
                            dev.rssi = device->getRSSI();
                            dev.rssiMin = dev.rssi;
                            dev.rssiMax = dev.rssi;
                            dev.channel = 0;
                            dev.firstSeen = millis();
                            dev.lastSeen = millis();
                            dev.probeCount = 1;
                            dev.isRandomized = (mac[0] & 0x02) && !(mac[0] & 0x01);
                            dev.isTargetHit = true;
                            strncpy(dev.hitReason, "MAC", sizeof(dev.hitReason));
                            if (device->getName().length() > 0) {
                                strncpy(dev.vendor, device->getName().c_str(), sizeof(dev.vendor) - 1);
                            }
                            probeDevices[macStr] = dev;
                            probeHitCount++;
                        }
                    }
                }
            }
            pBLEScan->clearResults();
            lastBLEScan = millis();
        }

        // Periodic DB save every 60s (for forever mode resilience)
        if ((millis() - lastDBSave) >= 60000) {
            {
                std::lock_guard<std::mutex> lock(probeMutex);
                for (const auto &p : probeDevices) {
                    mergeProbeDeviceToDB(p.second);
                }
            }
            saveProbeDB();
            lastDBSave = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    probeDetectionEnabled = false;
    probeBroadcastAll.store(false, std::memory_order_relaxed);

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStopSTA();
    }

    // Merge all devices into SD database and save
    {
        std::lock_guard<std::mutex> lock(probeMutex);
        for (const auto &p : probeDevices) {
            mergeProbeDeviceToDB(p.second);
        }
    }
    saveProbeDB();
    Serial.printf("[PROBE] Merged %u devices into probe database\n", probeDevices.size());

    // Log probe events to /probes.jsonl on SD
    {
        File logFile = SD.open("/probes.jsonl", FILE_APPEND);
        if (logFile) {
            uint32_t now = getEventTimestamp();
            std::lock_guard<std::mutex> lock(probeMutex);
            for (auto &p : probeDevices) {
                ProbeDevice &dev = p.second;
                DynamicJsonDocument doc(512);
                doc["t"] = now;
                doc["mac"] = p.first;
                doc["rssi"] = dev.rssi;
                doc["ch"] = dev.channel;
                doc["cnt"] = dev.probeCount;
                doc["rand"] = dev.isRandomized;
                if (dev.vendor[0]) doc["v"] = dev.vendor;
                if (dev.isTargetHit) doc["hit"] = true;
                if (dev.isDstHit) doc["dst"] = true;
                JsonArray ss = doc.createNestedArray("ss");
                for (uint8_t i = 0; i < dev.ssidCount; i++) {
                    ss.add(dev.ssids[i]);
                }
                if (dev.respondingAP[0]) doc["ap"] = dev.respondingAP;
                if (dev.respondingSSID[0]) doc["apssid"] = dev.respondingSSID;
                serializeJson(doc, logFile);
                logFile.println();
            }
            logFile.close();

            // Rotate if over 1MB
            File check = SD.open("/probes.jsonl", FILE_READ);
            if (check && check.size() > 1048576) {
                check.close();
                SD.remove("/probes_old.jsonl");
                SD.rename("/probes.jsonl", "/probes_old.jsonl");
                Serial.println("[PROBE] Rotated probes.jsonl");
            } else if (check) {
                check.close();
            }
        }
    }

    scanning = false;

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = getProbeResults().c_str();
    }
    workerTaskHandle = nullptr;
    Serial.println("[PROBE] Probe detection stopped");
    vTaskDelete(nullptr);
}

static String formatAge(uint32_t epochNow, uint32_t epochThen)
{
    if (epochThen == 0 || epochNow <= epochThen) return "now";
    uint32_t diff = epochNow - epochThen;
    if (diff < 60) return String(diff) + "s ago";
    if (diff < 3600) return String(diff / 60) + "m ago";
    if (diff < 86400) return String(diff / 3600) + "h ago";
    return String(diff / 86400) + "d ago";
}

String getProbeResults()
{
    std::lock_guard<std::mutex> lock(probeMutex);

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    String results = "Probe scan - Mode: " + modeStr;
    if (scanning) results += " (IN PROGRESS)";
    results += "\nDevices: " + String(probeDevices.size()) +
               " | Probes: " + String((uint32_t)totalProbeCount) +
               " | SSIDs: " + String(uniqueSsids.size()) +
               " | Saved: " + String(getProbeDBSize()) + "\n\n";

    std::vector<std::pair<String, ProbeDevice*>> sorted;
    sorted.reserve(probeDevices.size());
    std::transform(probeDevices.begin(), probeDevices.end(), std::back_inserter(sorted),
        [](std::pair<const String, ProbeDevice> &p) -> std::pair<String, ProbeDevice*> {
            return {p.first, &p.second};
        });
    // Sort: known devices first, then by signal strength
    std::sort(sorted.begin(), sorted.end(),
        [](const std::pair<String, ProbeDevice*> &a, const std::pair<String, ProbeDevice*> &b) {
        if (a.second->histKnown != b.second->histKnown) return a.second->histKnown;
        return a.second->rssi > b.second->rssi;
    });

    uint32_t nowEpoch = millis() / 1000;

    for (auto &p : sorted) {
        ProbeDevice &dev = *p.second;
        results += "WiFi " + p.first + " RSSI=" + String(dev.rssi) + "dBm CH=" + String(dev.channel) + " ";

        if (dev.isRandomized) {
            results += "Randomized";
        } else if (dev.vendor[0]) {
            String v = sanitizeAscii(dev.vendor, sizeof(dev.vendor));
            if (v.length() > 0) results += v;
        }

        if (dev.ssidCount > 0) {
            bool any = false;
            for (uint8_t i = 0; i < dev.ssidCount; i++) {
                String s = sanitizeAscii(dev.ssids[i], 33);
                if (s.length() == 0) continue;
                if (!any) { results += " probes:"; any = true; }
                else results += ",";
                bool ghost = respondedSsids.find(String(dev.ssids[i])) == respondedSsids.end();
                results += (ghost ? "~\"" : "\"") + s + "\"";
            }
            if (!any) results += " (wildcard)";
        } else {
            results += " (wildcard)";
        }

        if (dev.respondingSSID[0]) {
            String rs = sanitizeAscii(dev.respondingSSID, sizeof(dev.respondingSSID));
            if (rs.length() > 0) {
                results += " AP=\"" + rs + "\"";
                if (dev.respondingAP[0]) {
                    String rap = sanitizeAscii(dev.respondingAP, sizeof(dev.respondingAP));
                    if (rap.length() > 0) results += " APBSSID=" + rap;
                }
            }
        }

        // Probe count this session
        if (dev.probeCount > 1) {
            results += " x" + String(dev.probeCount);
        }

        // Historical intelligence from SD database
        if (dev.histKnown) {
            results += " [KNOWN:seen=" + String(dev.histTotalSeen) +
                       " sessions=" + String(dev.histSessionCount) +
                       " last=" + formatAge(nowEpoch, dev.histLastEpoch) + "]";
        }

        results += "\n";
    }

    // SSID summary with device mapping
    if (uniqueSsids.size() > 0) {
        results += "\nSSIDs seen (" + String(uniqueSsids.size()) + "):\n";

        // Build SSID→devices map
        std::map<String, std::vector<String>> ssidToDevices;
        for (const auto &p : probeDevices) {
            for (uint8_t i = 0; i < p.second.ssidCount; i++) {
                ssidToDevices[String(p.second.ssids[i])].push_back(p.first);
            }
        }

        // Sort by device count descending
        std::vector<std::pair<String, std::vector<String>>> ssidSorted(ssidToDevices.begin(), ssidToDevices.end());
        std::sort(ssidSorted.begin(), ssidSorted.end(),
            [](const std::pair<String, std::vector<String>> &a,
               const std::pair<String, std::vector<String>> &b) { return a.second.size() > b.second.size(); });

        for (const auto &s : ssidSorted) {
            bool ghost = respondedSsids.find(s.first) == respondedSsids.end();
            results += "  " + String(ghost ? "~" : "") + "\"" + s.first + "\" (" + String(s.second.size()) +
                       (s.second.size() == 1 ? " device" : " devices") + ")";
            // Show the first 3 MAC addresses probing for this SSID
            if (s.second.size() <= 3) {
                results += " [";
                for (size_t i = 0; i < s.second.size(); i++) {
                    if (i > 0) results += ", ";
                    results += s.second[i].substring(9); // last 3 octets for brevity
                }
                results += "]";
            }
            results += "\n";
        }
    }

    return results;
}

void resetProbeDetection()
{
    std::lock_guard<std::mutex> lock(probeMutex);
    probeDevices.clear();
    uniqueSsids.clear();
    respondedSsids.clear();
    totalProbeCount = 0;
    probeHitCount = 0;
    probeHitCooldowns.clear();
}

// --- SD Probe Device Database ---
// Stores known devices as JSONL on SD: /probedb.jsonl
// Each line: {"m":"AA:BB:CC:DD:EE:FF","t":1234,"f":100,"l":200,"s":3,"r":-42,"v":"Apple","rd":0,"ss":["Net1","Net2"]}

static std::map<String, ProbeDBEntry> probeDB;
static std::mutex probeDBMutex;
static const char *PROBE_DB_PATH = "/probedb.jsonl";
static const size_t PROBE_DB_MAX_ENTRIES = 500;

void loadProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDB.clear();

    if (!SD.exists(PROBE_DB_PATH)) {
        Serial.println("[PROBEDB] No database file on SD");
        return;
    }

    File f = SD.open(PROBE_DB_PATH, FILE_READ);
    if (!f) {
        Serial.println("[PROBEDB] Failed to open database");
        return;
    }

    uint32_t count = 0;
    while (f.available() && count < PROBE_DB_MAX_ENTRIES) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 10) continue;

        DynamicJsonDocument doc(512);
        if (deserializeJson(doc, line) != DeserializationError::Ok) continue;

        const char *mac = doc["m"] | "";
        if (strlen(mac) < 17) continue;

        ProbeDBEntry entry = {};
        strncpy(entry.mac, mac, 17);
        entry.mac[17] = '\0';
        entry.totalSeen = doc["t"].as<uint32_t>();
        entry.firstEpoch = doc["f"].as<uint32_t>();
        entry.lastEpoch = doc["l"].as<uint32_t>();
        entry.sessionCount = doc["s"].as<uint16_t>();
        entry.bestRssi = doc["r"] | -128;
        entry.isRandomized = doc["rd"].as<bool>();

        const char *vendor = doc["v"] | "";
        strncpy(entry.vendor, vendor, sizeof(entry.vendor) - 1);

        JsonArray ssArr = doc["ss"];
        entry.ssidCount = 0;
        if (ssArr) {
            for (JsonVariant s : ssArr) {
                if (entry.ssidCount >= 4) break;
                const char *ss = s.as<const char*>();
                if (ss && ss[0]) {
                    strncpy(entry.ssids[entry.ssidCount], ss, 32);
                    entry.ssids[entry.ssidCount][32] = '\0';
                    entry.ssidCount++;
                }
            }
        }

        probeDB[String(mac)] = entry;
        count++;
    }
    f.close();
    Serial.printf("[PROBEDB] Loaded %u devices from SD\n", count);
}

void saveProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);

    File f = SD.open(PROBE_DB_PATH, FILE_WRITE);
    if (!f) {
        Serial.println("[PROBEDB] Failed to write database");
        return;
    }

    uint32_t written = 0;
    for (const auto &p : probeDB) {
        DynamicJsonDocument doc(512);
        doc["m"] = p.second.mac;
        doc["t"] = p.second.totalSeen;
        doc["f"] = p.second.firstEpoch;
        doc["l"] = p.second.lastEpoch;
        doc["s"] = p.second.sessionCount;
        doc["r"] = p.second.bestRssi;
        doc["v"] = p.second.vendor;
        doc["rd"] = p.second.isRandomized ? 1 : 0;

        JsonArray ss = doc.createNestedArray("ss");
        for (uint8_t i = 0; i < p.second.ssidCount; i++) {
            ss.add(p.second.ssids[i]);
        }

        serializeJson(doc, f);
        f.println();
        written++;
    }
    f.close();
    Serial.printf("[PROBEDB] Saved %u devices to SD\n", written);
}

void mergeProbeDeviceToDB(const ProbeDevice &dev)
{
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);

    std::lock_guard<std::mutex> lock(probeDBMutex);
    uint32_t now = getEventTimestamp();

    auto it = probeDB.find(String(macStr));
    if (it != probeDB.end()) {
        ProbeDBEntry &e = it->second;
        e.totalSeen += dev.probeCount;
        e.lastEpoch = now;
        e.sessionCount++;
        if (dev.rssi > e.bestRssi) e.bestRssi = dev.rssi;
        if (dev.vendor[0] && !e.vendor[0]) {
            strncpy(e.vendor, dev.vendor, sizeof(e.vendor) - 1);
        }
        for (uint8_t i = 0; i < dev.ssidCount; i++) {
            bool found = false;
            for (uint8_t j = 0; j < e.ssidCount; j++) {
                if (strcasecmp(e.ssids[j], dev.ssids[i]) == 0) { found = true; break; }
            }
            if (!found && e.ssidCount < 8) {
                strncpy(e.ssids[e.ssidCount], dev.ssids[i], 32);
                e.ssids[e.ssidCount][32] = '\0';
                e.ssidCount++;
            }
        }
    } else {
        if (probeDB.size() >= PROBE_DB_MAX_ENTRIES) {
            uint32_t oldestEpoch = UINT32_MAX;
            String oldestKey;
            for (const auto &p : probeDB) {
                if (p.second.lastEpoch < oldestEpoch) {
                    oldestEpoch = p.second.lastEpoch;
                    oldestKey = p.first;
                }
            }
            if (oldestKey.length() > 0) probeDB.erase(oldestKey);
        }

        ProbeDBEntry e = {};
        strncpy(e.mac, macStr, 17);
        e.mac[17] = '\0';
        e.totalSeen = dev.probeCount;
        e.firstEpoch = now;
        e.lastEpoch = now;
        e.sessionCount = 1;
        e.bestRssi = dev.rssi;
        e.isRandomized = dev.isRandomized;
        strncpy(e.vendor, dev.vendor, sizeof(e.vendor) - 1);
        e.ssidCount = 0;
        for (uint8_t i = 0; i < dev.ssidCount && e.ssidCount < 8; i++) {
            strncpy(e.ssids[e.ssidCount], dev.ssids[i], 32);
            e.ssids[e.ssidCount][32] = '\0';
            e.ssidCount++;
        }
        probeDB[String(macStr)] = e;
    }
}

bool lookupProbeHistory(const char *macStr, ProbeDBEntry &out)
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    auto it = probeDB.find(String(macStr));
    if (it != probeDB.end()) {
        out = it->second;
        return true;
    }
    return false;
}

uint32_t getProbeDBSize()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    return probeDB.size();
}

String getProbeDBJson()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    String out = "[";
    bool first = true;
    for (const auto &p : probeDB) {
        if (!first) out += ",";
        first = false;
        DynamicJsonDocument doc(512);
        doc["mac"] = p.second.mac;
        doc["seen"] = p.second.totalSeen;
        doc["sessions"] = p.second.sessionCount;
        doc["first"] = p.second.firstEpoch;
        doc["last"] = p.second.lastEpoch;
        doc["rssi"] = p.second.bestRssi;
        doc["vendor"] = p.second.vendor;
        doc["rand"] = p.second.isRandomized;
        JsonArray ss = doc.createNestedArray("ssids");
        for (uint8_t i = 0; i < p.second.ssidCount; i++) {
            ss.add(p.second.ssids[i]);
        }
        String tmp;
        serializeJson(doc, tmp);
        out += tmp;
    }
    out += "]";
    return out;
}

void clearProbeDB()
{
    std::lock_guard<std::mutex> lock(probeDBMutex);
    probeDB.clear();
    SD.remove(PROBE_DB_PATH);
    Serial.println("[PROBEDB] Database cleared");
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

    loadProbeDB();
    Serial.printf("Loaded %u probe devices from DB\n", getProbeDBSize());

    if (!probeRequestQueue) {
        probeRequestQueue = xQueueCreateWithCaps(256, sizeof(ProbeRequestEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (probeRequestQueue) {
            Serial.printf("[INIT] probeRequestQueue PSRAM (256 entries, internal:%u psram:%u)\n",
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        } else {
            Serial.println("[INIT] probeRequestQueue alloc failed at boot");
        }
    }
    if (!authFrameQueue) {
        authFrameQueue = xQueueCreateWithCaps(64, sizeof(AuthFrameEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (authFrameQueue) {
            Serial.printf("[INIT] authFrameQueue PSRAM (64 entries, internal:%u psram:%u)\n",
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        } else {
            Serial.println("[INIT] authFrameQueue alloc failed at boot");
        }
    }
}

static void resetTriAccumulator(const uint8_t* mac) {
    std::lock_guard<std::mutex> lock(triAccumMutex);
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
static uint32_t hashString(const String& str) {
    uint32_t hash = 0;
    for (size_t i = 0; i < str.length(); i++) {
        hash = hash * 31 + str.charAt(i);
    }
    return hash;
}

static void sendTriAccumulatedData(const String& nodeId) {
    std::lock_guard<std::mutex> lock(triAccumMutex);

    if (triAccum.wifiHitCount == 0 && triAccum.bleHitCount == 0) return;

    if (!triangulationActive) {
        triAccum.wifiHitCount = 0;
        triAccum.wifiRssiSum = 0.0f;
        triAccum.bleHitCount = 0;
        triAccum.bleRssiSum = 0.0f;
        return;
    }

    // Fix for dual-radio devices showing as two types
    if (triAccum.wifiHitCount > 0 && triAccum.bleHitCount > 0) {
        String macStr = macFmt6(triAccum.targetMac);
        Serial.printf("[TRI-MIXED] WARNING: Device %s has BOTH WiFi (%d) and BLE (%d) hits!\n",
                     macStr.c_str(), triAccum.wifiHitCount, triAccum.bleHitCount);

        if (triAccum.wifiHitCount >= triAccum.bleHitCount) {
            Serial.printf("[TRI-MIXED] Keeping WiFi, clearing BLE hits\n");
            triAccum.bleHitCount = 0;
            triAccum.bleRssiSum = 0.0f;
            triAccum.bleMaxRssi = -128;
            triAccum.bleMinRssi = 0;
        } else {
            Serial.printf("[TRI-MIXED] Keeping BLE, clearing WiFi hits\n");
            triAccum.wifiHitCount = 0;
            triAccum.wifiRssiSum = 0.0f;
            triAccum.wifiMaxRssi = -128;
            triAccum.wifiMinRssi = 0;
        }
    }

    reportingSchedule.addNode(nodeId);

    if (reportingSchedule.cycleStartMs == 0) {
        // Use GPS-synchronized time instead of local millis() to ensure all nodes agree on slot boundaries
        int64_t syncedUs = getCorrectedMicroseconds();
        uint32_t syncedMs = (uint32_t)(syncedUs / 1000LL);
        reportingSchedule.initializeCycle(syncedMs);
        Serial.printf("[TRI-SLOT] Initialized cycle start at syncedMs=%u (from GPS-corrected time)\n", syncedMs);
    }

    // Use GPS-synchronized time for consistent slot checking across all nodes
    int64_t syncedUs = getCorrectedMicroseconds();
    uint32_t now = (uint32_t)(syncedUs / 1000LL);

    uint32_t nextSlot = 0;
    if (!reportingSchedule.isMySlotActive(nodeId, nextSlot, now)) {
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
        String wifiMsg = nodeId + ": T_D: " + macStr +
                         " RSSI:" + String(wifiAvgRssi) +
                         " Hits=" + String(triAccum.wifiHitCount) +
                         " Type:WiFi";
        if (triAccum.hasGPS) {
            wifiMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                       " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(wifiMsg, true)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId);
            Serial.printf("[TRI-SLOT] %s: WiFi sent (%d hits)\n", nodeId.c_str(), triAccum.wifiHitCount);
            delay(600);
        } else {
            Serial.printf("[TRI-SLOT] %s: WiFi DROPPED by rate limiter\n", nodeId.c_str());
        }
    }

    if (triAccum.bleHitCount > 0) {
        int8_t bleAvgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
        String bleMsg = nodeId + ": T_D: " + macStr +
                        " RSSI:" + String(bleAvgRssi) +
                        " Hits=" + String(triAccum.bleHitCount) +
                        " Type:BLE";
        if (triAccum.hasGPS) {
            bleMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                      " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(bleMsg, true)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId);
            Serial.printf("[TRI-SLOT] %s: BLE sent (%d hits)\n", nodeId.c_str(), triAccum.bleHitCount);
            delay(600);
        } else {
            Serial.printf("[TRI-SLOT] %s: BLE DROPPED by rate limiter\n", nodeId.c_str());
        }
    }

    if (sentAny) {
        triAccum.lastSendTime = millis();
        delay(150);
    }
}

// Scan tasks
void listScanTask(void *pv) {
    sentinel_kill();
    int secs = static_cast<int>(reinterpret_cast<intptr_t>(pv));
    bool forever = (secs <= 0);

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "Target scan starting...\nMode: " + std::string(modeStr.c_str()) + "\n";
    }

    Serial.printf("[SCAN] List scan %s (%s)...\n",
                  forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str(),
                  modeStr.c_str());

    stopRequested = false;

    // Use safe queue creation with mutex protection
    if (!safeMacQueueCreate(512)) {
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
    sentinel_yieldAndWait(1500);
    // Note: lastResults already set to "Target scan starting..." above (line ~2197)
    // Do NOT clear it here — that creates a race where tick() sees "None yet."
    lastScanStart = millis();
    lastScanSecs = secs;
    lastScanForever = forever;

    // Register initiator at scan start
    if (triangulationInitiator) {
        String myNodeId = getNodeId();
        if (myNodeId.length() == 0) {
            myNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
        }

        {
            std::lock_guard<std::mutex> lock(triangulationMutex);
            bool selfNodeExists = false;
            for (const auto& node : triangulationNodes) {
                // cppcheck-suppress useStlAlgorithm
                if (node.nodeId == myNodeId) {
                    selfNodeExists = true;
                    Serial.printf("[TRIANGULATE] Initiator already registered: %s\n", myNodeId.c_str());
                    break;
                }
            }

            if (!selfNodeExists) {
                TriangulationNode selfNode;
                selfNode.nodeId = myNodeId;
                if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                    selfNode.lat = gpsValid ? gpsLat : 0.0;
                    selfNode.lon = gpsValid ? gpsLon : 0.0;
                    xSemaphoreGive(gpsMutex);
                } else {
                    selfNode.lat = 0.0;
                    selfNode.lon = 0.0;
                }
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
        }
    }

    vTaskDelay(pdMS_TO_TICKS(200));

    // Use list scan mode (non-promiscuous) to avoid IPC stack overflow
    // WiFi.scanNetworks() and promiscuous mode cannot run together safely
    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        radioStartListScan();  // Non-promiscuous mode for WiFi.scanNetworks()
        vTaskDelay(pdMS_TO_TICKS(200));

        // Start BLE separately if needed (SCAN_BOTH mode)
        if (currentScanMode == SCAN_BOTH) {
            radioStartBLE();
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    } else if (currentScanMode == SCAN_BLE) {
        vTaskDelay(pdMS_TO_TICKS(100));
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    std::map<String, uint32_t> localDeviceLastSeen;
    const uint32_t LOCAL_DEDUPE_WINDOW = 3000;
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    Hit h;

    uint32_t nextTriResultsUpdate = millis() + 2000;
    uint32_t lastListProgressUpdate = millis() + 1000;
    uint32_t lastTimeSyncBroadcast = 0;
    uint32_t lastBLEScanTri = 0;
    uint32_t nextTriReportCheck = 0;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {
        if (triangulationActive && triangulationInitiator &&
            (millis() - lastTimeSyncBroadcast) > 30000) {
            broadcastTimeSyncRequest();
            lastTimeSyncBroadcast = millis();
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
                    // Skip RSSI threshold during triangulation - we want ALL measurements
                    if (!triangulationActive && rssi < rfConfig.globalRssiThreshold) {
                        continue;
                    }

                    uint8_t ch = WiFi.channel(i);
                    const uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0) ssid = "[Hidden]";

                    uint32_t now = millis();
                    bool shouldProcess = (localDeviceLastSeen.find(bssid) == localDeviceLastSeen.end() ||
                                          (now - localDeviceLastSeen[bssid] >= LOCAL_DEDUPE_WINDOW));

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
                        if (!isMatch && ssid.length() > 0) {
                            isMatch = matchesSsid(ssid.c_str());
                        }
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
                        if (!safeMacQueueSend(&wh, pdMS_TO_TICKS(10))) {
                            Serial.printf("[SCAN] Queue full/unavailable for target %s\n", origBssid.c_str());
                        }
                    } else {
                        if (hitsLog.size() < MAX_LOG_SIZE) {
                            hitsLog.push_back(wh);
                        }
                        localDeviceLastSeen[bssid] = now;
                    }
                }
                WiFi.scanDelete();
            }
            framesSeen += networksFound;
        }

        extern void processUSBToMesh();
        processUSBToMesh();

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan &&
            (millis() - lastBLEScan >= rfConfig.bleScanInterval || lastBLEScan == 0)) {
            lastBLEScan = millis();
            NimBLEScanResults scanResults = pBLEScan->getResults(500, false);
            if (stopRequested) break;
            for (int i = 0; i < scanResults.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStrOrig = device->getAddress().toString().c_str();
                String macStr = macStrOrig;
                macStr.toUpperCase();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();
                if (rssi > -10) continue;
                // Skip RSSI threshold during triangulation - we want ALL measurements
                if (!triangulationActive && rssi < rfConfig.globalRssiThreshold) {
                    continue;
                }
                uint32_t now = millis();
                bool shouldProcess = (localDeviceLastSeen.find(macStr) == localDeviceLastSeen.end() ||
                                      (now - localDeviceLastSeen[macStr] >= LOCAL_DEDUPE_WINDOW));

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
                    if (!isMatch && name.length() > 0 && name != "Unknown") {
                        isMatch = matchesSsid(name.c_str());
                    }
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
                    if (!safeMacQueueSend(&bh, pdMS_TO_TICKS(10))) {
                        Serial.printf("[SCAN] Queue full/unavailable for target %s\n", macStrOrig.c_str());
                    }
                } else {
                    if (parseMac6(macStrOrig, mac)) {
                        Hit bh;
                        memcpy(bh.mac, mac, 6);
                        bh.rssi = rssi;
                        bh.ch = 0;
                        strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                        bh.name[sizeof(bh.name) - 1] = '\0';
                        bh.isBLE = true;
                        if (hitsLog.size() < MAX_LOG_SIZE) {
                            hitsLog.push_back(bh);
                        }
                        localDeviceLastSeen[macStr] = now;
                    }
                }
            }
            pBLEScan->clearResults();
            bleFramesSeen += scanResults.getCount();
        }

        while (safeMacQueueReceive(&h, 0)) {
            String macStrOrig = macFmt6(h.mac);
            String macStr = macStrOrig;
            macStr.toUpperCase();
            uint32_t now = millis();

            if (isAllowlisted(h.mac)) {
                continue;
            }

            if (localDeviceLastSeen.find(macStr) != localDeviceLastSeen.end()) {
                if (now - localDeviceLastSeen[macStr] < LOCAL_DEDUPE_WINDOW) continue;
            }

            localDeviceLastSeen[macStr] = now;
            uniqueMacs.insert(macStr);
            if (hitsLog.size() < MAX_LOG_SIZE) {
                hitsLog.push_back(h);
            }

            bool inserted = seenTargets.insert(macStr).second;
            if (inserted) {
                totalHits = totalHits + 1;
            }

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macStrOrig +
                              " RSSI=" + String(h.rssi) + "dBm";
            if (!h.isBLE && h.ch > 0) logEntry += " CH=" + String(h.ch);
            if (strlen(h.name) > 0 && strcmp(h.name, "WiFi") != 0 && strcmp(h.name, "Unknown") != 0) {
                logEntry += " Name=" + String(h.name);
            }
            if (gpsValid) {
                if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                    logEntry += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                    xSemaphoreGive(gpsMutex);
                }
            }

            Serial.printf("[HIT] %s\n", logEntry.c_str());
            logToSD(logEntry);
            sendMeshNotification(h);

            if (triangulationActive) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) {
                    myNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
                }

                bool needsReset = false;
                {
                    std::lock_guard<std::mutex> lock(triAccumMutex);
                    needsReset = (memcmp(triAccum.targetMac, triangulationTarget, 6) != 0);
                }

                if (needsReset) {
                    sendTriAccumulatedData(myNodeId);
                    resetTriAccumulator(triangulationTarget);
                }

                if (memcmp(h.mac, triangulationTarget, 6) == 0) {
                    {
                        std::lock_guard<std::mutex> lock(triAccumMutex);

                        String macStrTri = macFmt6(h.mac);
                        Serial.printf("[TRI-HIT] MAC=%s Type=%s RSSI=%d CH=%d Name=%s\n",
                                     macStrTri.c_str(), h.isBLE ? "BLE" : "WiFi",
                                     h.rssi, h.ch, h.name);

                        if (h.isBLE && triAccum.wifiHitCount > 0 && triAccum.bleHitCount == 0) {
                            Serial.printf("[TRI-CONFLICT] WARNING: Device %s switching from WiFi to BLE! Ignoring BLE detection.\n",
                                         macStrTri.c_str());
                            goto skip_accumulation;
                        }
                        if (!h.isBLE && triAccum.bleHitCount > 0 && triAccum.wifiHitCount == 0) {
                            Serial.printf("[TRI-CONFLICT] WARNING: Device %s switching from BLE to WiFi! Ignoring WiFi detection.\n",
                                         macStrTri.c_str());
                            goto skip_accumulation;
                        }

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
                            if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                                triAccum.lat = gpsLat;
                                triAccum.lon = gpsLon;
                                xSemaphoreGive(gpsMutex);
                            } else {
                                triAccum.lat = 0.0;
                                triAccum.lon = 0.0;
                            }
                            triAccum.hdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.9f;
                            triAccum.hasGPS = true;
                        }

                        skip_accumulation:
                        (void)0;
                    }

                    if (triangulationInitiator) {
                        String myNodeIdLocal = getNodeId();
                        if (myNodeIdLocal.length() == 0) {
                            myNodeIdLocal = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
                        }

                        int8_t avgRssi;
                        int triHitCount;
                        bool isBLE;
                        float triLat, triLon, triHdop;
                        bool hasGPS;

                        {
                            std::lock_guard<std::mutex> lock(triAccumMutex);
                            if (triAccum.wifiHitCount > 0) {
                                avgRssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
                                triHitCount = triAccum.wifiHitCount;
                                isBLE = false;
                            } else if (triAccum.bleHitCount > 0) {
                                avgRssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
                                triHitCount = triAccum.bleHitCount;
                                isBLE = true;
                            } else {
                                continue;
                            }

                            triLat = triAccum.lat;
                            triLon = triAccum.lon;
                            triHdop = triAccum.hdop;
                            hasGPS = triAccum.hasGPS;
                        }

                        {
                            std::lock_guard<std::mutex> lock(triangulationMutex);
                            bool selfNodeFound = false;
                            for (auto &node : triangulationNodes) {
                                // cppcheck-suppress useStlAlgorithm
                                if (node.nodeId == myNodeIdLocal) {
                                    updateNodeRSSI(node, avgRssi);
                                    node.hitCount = triHitCount;
                                    node.isBLE = isBLE;
                                    if (hasGPS) {
                                        node.lat = triLat;
                                        node.lon = triLon;
                                        node.hdop = triHdop;
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
                                selfNode.nodeId = myNodeIdLocal;
                                selfNode.lat = hasGPS ? triLat : 0.0f;
                                selfNode.lon = hasGPS ? triLon : 0.0f;
                                selfNode.hdop = hasGPS ? triHdop : 99.9f;
                                selfNode.rssi = avgRssi;
                                selfNode.hitCount = triHitCount;
                                selfNode.hasGPS = hasGPS;
                                selfNode.isBLE = isBLE;
                                selfNode.lastUpdate = millis();

                                initNodeKalmanFilter(selfNode);
                                updateNodeRSSI(selfNode, avgRssi);
                                selfNode.distanceEstimate = rssiToDistance(selfNode, !selfNode.isBLE);

                                triangulationNodes.push_back(selfNode);

                                Serial.printf("[TRIANGULATE SELF] Added: hits=%d avgRSSI=%d Type=%s dist=%.1fm GPS=%s\n",
                                            triHitCount, avgRssi,
                                            selfNode.isBLE ? "BLE" : "WiFi",
                                            selfNode.distanceEstimate,
                                            hasGPS ? "YES" : "NO");
                            }
                        }
                    }
                }
            }
        }

        // Dynamic update to results (only while running, stop when stopRequested is set)
        if (triangulationActive && !stopRequested && (int32_t)(millis() - nextTriResultsUpdate) >= 0) {
            Serial.println("[SCAN] Updating IN PROGRESS triangulation results");
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                std::lock_guard<std::mutex> triLock(triangulationMutex);  // Lock order: lastResultsMutex first

                uint32_t elapsedSec = (millis() - triangulationStart) / 1000;
                uint32_t remainingSec = (elapsedSec < triangulationDuration) ? (triangulationDuration - elapsedSec) : 0;

                std::string results = "TRIANGULATING: Scanning... " + std::to_string(elapsedSec) + "s elapsed, " +
                                      std::to_string(remainingSec) + "s remaining\n\n";
                results += "=== Triangulation Results (IN PROGRESS) ===\n";
                results += "Target MAC: " + std::string(macFmt6(triangulationTarget).c_str()) + "\n";
                results += "Duration: " + std::to_string(triangulationDuration) + "s\n";
                results += "Elapsed: " + std::to_string(elapsedSec) + "s\n";
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
                Serial.printf("[SCAN] IN PROGRESS results stored (%d chars)\n", results.length());
            }
            nextTriResultsUpdate = millis() + 2000;
        }

        if (triangulationActive && !stopRequested) {
            // Check periodically - sendTriAccumulatedData has built-in 3s rate limiting
            if ((int32_t)(millis() - nextTriReportCheck) >= 0) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) {
                    myNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
                }
                sendTriAccumulatedData(myNodeId);
                nextTriReportCheck = millis() + 1000;  // Check every second
            }
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            if (millis() - lastBLEScanTri >= 3000) {
                NimBLEScanResults scanResults = pBLEScan->getResults(1000, false);
                pBLEScan->clearResults();
                lastBLEScanTri = millis();
            }
        }

        if (!triangulationActive && (int32_t)(millis() - lastListProgressUpdate) >= 0) {
            std::string pr = "Target scan (IN PROGRESS)\nElapsed: ";
            pr += std::to_string((millis() - lastScanStart) / 1000) + "s";
            if (!forever && secs > 0) {
                int32_t rem = secs - (int32_t)((millis() - lastScanStart) / 1000);
                if (rem > 0) pr += " / " + std::to_string(secs) + "s (" + std::to_string(rem) + "s left)";
            }
            pr += "\nTarget Hits: " + std::to_string(totalHits.load());
            pr += "\nWiFi frames: " + std::to_string(framesSeen.load());
            pr += "\nBLE frames: " + std::to_string(bleFramesSeen.load()) + "\n\n";

            // Dedupe hitsLog by MAC, keeping best RSSI per device
            std::map<std::string, Hit> bestByMac;
            for (const auto& sh : hitsLog) {
                char mb[18];
                snprintf(mb, sizeof(mb), "%02X:%02X:%02X:%02X:%02X:%02X",
                         sh.mac[0], sh.mac[1], sh.mac[2], sh.mac[3], sh.mac[4], sh.mac[5]);
                std::string key(mb);
                auto it = bestByMac.find(key);
                if (it == bestByMac.end() || sh.rssi > it->second.rssi) {
                    bestByMac[key] = sh;
                }
            }
            std::vector<Hit> deduped;
            deduped.reserve(bestByMac.size());
            std::transform(bestByMac.begin(), bestByMac.end(), std::back_inserter(deduped),
                [](const std::pair<const std::string, Hit>& p) { return p.second; });
            std::sort(deduped.begin(), deduped.end(), [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });
            int shown = 0;
            for (const auto& sh : deduped) {
                if (shown++ >= 50) break;
                char mb[18];
                snprintf(mb, sizeof(mb), "%02X:%02X:%02X:%02X:%02X:%02X",
                         sh.mac[0], sh.mac[1], sh.mac[2], sh.mac[3], sh.mac[4], sh.mac[5]);
                pr += std::string(sh.isBLE ? "BLE " : "WiFi") + " " + mb;
                pr += " RSSI=" + std::to_string(sh.rssi) + "dBm";
                if (!sh.isBLE && sh.ch > 0) pr += " CH=" + std::to_string(sh.ch);
                if (strlen(sh.name) > 0 && strcmp(sh.name, "Unknown") != 0 && strcmp(sh.name, "WiFi") != 0)
                    pr += " \"" + std::string(sh.name) + "\"";
                pr += "\n";
            }
            if (deduped.size() > 50) pr += "... (" + std::to_string(deduped.size() - 50) + " more)\n";

            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = pr;
            }
            lastListProgressUpdate = millis() + 2000;
        }

        vTaskDelay(pdMS_TO_TICKS(150));
    }
    // Build final results BEFORE setting scanning=false to prevent race
    // where tick() sees scanning=false but final results aren't written yet
    std::string results =
        "List scan - Mode: " + std::string(modeStr.c_str()) +
        " Duration: " + (forever ? "Forever" : std::to_string(secs)) + "s\n" +
        "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
        "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
        "Target Hits: " + std::to_string(totalHits) + "\n\n";

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
        std::vector<Hit> sortedHits;
        sortedHits.reserve(hitsMap.size());
        std::transform(hitsMap.begin(), hitsMap.end(), std::back_inserter(sortedHits),
            [](const std::pair<const String, Hit>& entry) { return entry.second; });
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
                results += " \"" + std::string(e.name) + "\"";
            }
            results += "\n";
        }
        if (static_cast<int>(sortedHits.size()) > show) {
            results += "... (" + std::to_string(sortedHits.size() - show) + " more)\n";
        }
    }

    // Write final results while still scanning so tick() picks them up
    if (!stopRequested) {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        bool hasTriangulation = (antihunter::lastResults.find("=== Triangulation Results ===") != std::string::npos);

        if (hasTriangulation) {
            antihunter::lastResults = results + "\n\n" + antihunter::lastResults;
        } else if (triangulationNodes.size() > 0) {
            antihunter::lastResults = antihunter::lastResults + "\n\n=== List Scan Results ===\n" + results;
        } else {
            antihunter::lastResults = results;
        }

        Serial.printf("[SCAN] List results stored: %d chars\n", results.length());
    } else {
        Serial.println("[SCAN] Skipping list results - stopRequested (letting stopTriangulation() handle it)");
    }

    // NOW set scanning=false after results are written
    if (triangulationActive) {
        if (triangulationInitiator) {
            Serial.println("[SCAN INITIATOR] Scan complete, calling stopTriangulation()");
            stopRequested = true;
            vTaskDelay(pdMS_TO_TICKS(500));
            stopTriangulation();
            scanning = false;
            lastScanEnd = millis();
        } else {
            Serial.println("[SCAN CHILD] Scan complete, waiting for STOP command");
            uint32_t waitStart = millis();
            uint32_t STOP_WAIT_TIMEOUT = 30000;
            auto maxIt = std::max_element(nodePropagationDelays.begin(), nodePropagationDelays.end(),
                [](const std::pair<const String, uint32_t>& a, const std::pair<const String, uint32_t>& b) {
                    uint32_t va = (a.second < 1000000) ? a.second : 0;
                    uint32_t vb = (b.second < 1000000) ? b.second : 0;
                    return va < vb;
                });
            uint32_t maxPropDelay = (maxIt != nodePropagationDelays.end() && maxIt->second < 1000000)
                                    ? maxIt->second : 0;
            if (maxPropDelay > 0) {
                uint32_t latencyMargin = (maxPropDelay / 1000) * 5;
                STOP_WAIT_TIMEOUT += latencyMargin;
                Serial.printf("[SCAN CHILD] Timeout: %ums (+ %ums mesh latency)\n",
                             STOP_WAIT_TIMEOUT, latencyMargin);
            }

            while (!stopRequested && (millis() - waitStart < STOP_WAIT_TIMEOUT)) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }

            if (stopRequested) {
                Serial.println("[SCAN CHILD] Received STOP command, exiting scan task");
            } else {
                Serial.println("[SCAN CHILD] STOP timeout, exiting anyway");
                stopRequested = true;
                triangulationActive = false;
            }
            scanning = false;
            lastScanEnd = millis();
        }
    } else {
        scanning = false;
        lastScanEnd = millis();
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
        
        meshEnqueue(summary);
        Serial.println("[SCAN] List scan summary enqueued");

        if (finalRemaining > 0) {
            Serial.printf("[SCAN] WARNING: %d targets not transmitted\n", finalRemaining);
        }
    }
    
    radioStopListScan();
    vTaskDelay(pdMS_TO_TICKS(500));

    safeMacQueueDelete();

    seenTargets.clear();
    transmittedDevices.clear();
    localDeviceLastSeen.clear();

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void cleanupMaps() {
    const size_t DEAUTH_LOG_MAX = 500;

    if (deauthQueue) xQueueReset(deauthQueue);

    // Clean deauth logs (vector - trim oldest)
    if (deauthLog.size() > DEAUTH_LOG_MAX) {
        deauthLog.erase(deauthLog.begin(), deauthLog.begin() + (deauthLog.size() - DEAUTH_LOG_MAX));
    }
}


// Allowlist

static bool parseAllowlistEntry(const String &ln, Allowlist &out)
{
    String t;
    for (size_t i = 0; i < ln.length(); ++i)
    {
        char c = ln[i];
        if (isxdigit(static_cast<int>(c)))
            t += static_cast<char>(toupper(c));
    }
    if (t.length() == 12)
    {
        for (int i = 0; i < 6; i++)
        {
            out.bytes[i] = static_cast<uint8_t>(strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16));
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6)
    {
        for (int i = 0; i < 3; i++)
        {
            out.bytes[i] = static_cast<uint8_t>(strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16));
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
    for (const auto &w : allowlist)
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
    return std::any_of(allowlist.begin(), allowlist.end(),
        [mac](const Allowlist &w) {
            if (w.len == 6) return memcmp(w.bytes, mac, 6) == 0;
            if (w.len == 3) return memcmp(w.bytes, mac, 3) == 0;
            return false;
        });
}