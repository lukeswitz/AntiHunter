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
#include "scanner_internal.h"

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

extern Preferences prefs;
static std::vector<Target> targets;
std::vector<String> ssidTargets;

static const size_t IDENTITY_MAC_SNAPSHOT_CAP = 64;
static uint8_t identityMacSnapshot[IDENTITY_MAC_SNAPSHOT_CAP][6];
static std::atomic<uint16_t> identityMacSnapshotCount{0};

struct MacTargetSnap { uint8_t bytes[6]; uint8_t len; };
static const size_t MAC_TARGET_SNAPSHOT_CAP = 256;
static MacTargetSnap macTargetSnapshot[MAC_TARGET_SNAPSHOT_CAP];
static std::atomic<uint16_t> macTargetSnapshotCount{0};
static std::atomic<bool> identityTargetPresentSnap{false};

std::atomic<bool> probeDetectionEnabled(false);
std::atomic<bool> apCaptureEnabled(false);
QueueHandle_t apInfoQueue = nullptr;
std::atomic<bool> listScanTriMode(false);
// When set, every captured probe triggers a mesh broadcast (60s dedup still applies).
// Otherwise only CONFIG_TARGETS matches are broadcast. Cleared on task exit.
std::atomic<bool> probeBroadcastAll{false};
QueueHandle_t macQueue = nullptr;
UniqueMacsSet uniqueMacs;
DeviceLastSeenMap deviceLastSeen;
const uint32_t DEDUPE_WINDOW = 30000;
HitsVecPsram hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;
uint32_t g_curScanEndMs = 0;
bool g_curScanForever = false;
std::atomic<bool> scanStopPending{false};

void scanSetCountdown(int secs, bool forever) {
    g_curScanForever = forever;
    g_curScanEndMs = (forever || secs <= 0) ? 0 : (millis() + (uint32_t)secs * 1000);
    if (forever || secs > 0) scanStopPending.store(false);
}

void stopAllScans(bool cancelMeshDrain) {
    stopRequested = true;
    scanStopPending.store(true);
    scanSetCountdown(0, false);

    esp_wifi_scan_stop();
    WiFi.scanDelete();
    if (pBLEScan) pBLEScan->stop();

    if (cancelMeshDrain && (meshTxDraining.load() || meshTxQueueDepth() > 0)) {
        stopMeshDrain.store(true);
    }

    if (!workerTaskHandle && !blueTeamTaskHandle && !triangulationActive) {
        scanning = false;
        scanStopPending.store(false);
    }
}
static StringStringMapPsram apCache;
static StringStringMapPsram bleDeviceCache;
static std::mutex snifferCacheMutex;

static portMUX_TYPE rfConfigMux = portMUX_INITIALIZER_UNLOCKED;

const size_t MAX_AP_CACHE = 200;
const size_t MAX_BLE_CACHE = 200;
const size_t MAX_UNIQUE_MACS = 5000;

// BLE 
NimBLEScan *pBLEScan;
void sniffer_cb(const void *buf, wifi_promiscuous_pkt_type_t type);

// Scan intervals
uint32_t WIFI_SCAN_INTERVAL = 3000;
uint32_t BLE_SCAN_INTERVAL = 4000;

// Scanner status variables
std::atomic<bool> scanning(false);
std::atomic<bool> meshTxDraining(false);
std::atomic<uint32_t> meshDrainSent(0);
std::atomic<uint32_t> meshDrainTotal(0);
std::atomic<bool> stopMeshDrain(false);
std::atomic<uint32_t> meshTxDroppedRateLimit(0);
std::atomic<uint32_t> meshTxDroppedBufFull(0);
std::atomic<uint32_t> meshTxDroppedTriGate(0);
std::atomic<uint32_t> meshTxDroppedEvicted(0);
std::atomic<int> totalHits(0);
std::atomic<uint32_t> framesSeen(0);
std::atomic<uint32_t> bleFramesSeen(0);

extern TaskHandle_t blueTeamTaskHandle;

DeviceHistoryMapPsram deviceHistory;
uint32_t deviceAbsenceThreshold = 120000;
uint32_t reappearanceAlertWindow = 300000;
int8_t significantRssiChange = 20;

std::vector<Allowlist> allowlist;
static std::mutex allowlistMutex;

// Scan config
RFScanConfig rfConfig = {
    .wifiChannelTime = 160,
    .wifiScanInterval = 3000,
    .bleScanInterval = 4000,
    .bleScanDuration = 2000,
    .preset = 1,
    .wifiChannels = "1..11",
    .globalRssiThreshold = -95,
    .bandMode = DEFAULT_BAND_MODE
};

extern std::vector<uint8_t> CHANNELS;

// Band-filtered hop list (subset of CHANNELS for the active band); rebuilt at radioStart/setBandMode.
#ifndef AH_BLE_MIN_INTERNAL
#define AH_BLE_MIN_INTERNAL 45000
#endif
#ifndef AH_BLE_MIN_BLOCK
#define AH_BLE_MIN_BLOCK 20000
#endif
std::vector<uint8_t> g_activeChannels;

static inline bool channelIs2G(uint8_t ch) { return ch >= 1 && ch <= 14; }

void rebuildActiveChannels() {
    g_activeChannels.clear();
    for (uint8_t ch : CHANNELS) {
        if (rfConfig.bandMode == 0 && !channelIs2G(ch)) continue;  // 2.4GHz only
        if (rfConfig.bandMode == 1 &&  channelIs2G(ch)) continue;  // 5GHz only
        g_activeChannels.push_back(ch);
    }
#ifdef ARDUINO_XIAO_ESP32C5
    // bandMode 1/2 need 5GHz in the rotation; a 2.4-only saved list would otherwise never scan 5GHz.
    if (rfConfig.bandMode != 0) {
        static const uint8_t k5g[9] = {36, 40, 44, 48, 149, 153, 157, 161, 165};
        bool have5g = false;
        for (uint8_t ch : g_activeChannels) if (!channelIs2G(ch)) { have5g = true; break; }
        if (!have5g) {
            for (uint8_t ch : k5g) g_activeChannels.push_back(ch);
            Serial.println("[RF] no 5GHz channel saved; adding 36/40/44/48/149/153/157/161/165");
        }
    }
    if (rfConfig.bandMode == 2) {
        bool have2g = false;
        for (uint8_t ch : g_activeChannels) if (channelIs2G(ch)) { have2g = true; break; }
        if (!have2g) { const uint8_t k2g[3] = {1, 6, 11}; for (uint8_t ch : k2g) g_activeChannels.push_back(ch); }
    }
#endif
    if (g_activeChannels.empty()) g_activeChannels = CHANNELS;
}

// Apply the selected band to the radio. C5-only; compiled out on 2.4GHz-only parts.
void applyBandMode() {
#ifdef ARDUINO_XIAO_ESP32C5
    // esp_wifi.h:824/826 - changing country rewrites the soft-AP beacon IE and switches PHY
    // init data, which drops associated clients. Apply once; skip when the band is unchanged.
    static uint8_t appliedBand = 0xFF;
    if (appliedBand == rfConfig.bandMode) return;
    // UNII-1/UNII-3 only stay reachable under a manual regdomain spanning to ch165;
    // set_country_code alone leaves the 5GHz channels barred.
    if (rfConfig.bandMode != 0) {
        wifi_country_t c = { .cc = "US", .schan = 1, .nchan = 165,
                             .max_tx_power = 20, .policy = WIFI_COUNTRY_POLICY_MANUAL };
        esp_wifi_set_country(&c);
    } else {
        esp_wifi_set_country_code(COUNTRY, true);
    }
    appliedBand = rfConfig.bandMode;
    // Band follows esp_wifi_set_channel; esp_wifi_set_band_mode is not called because a band
    // change through it re-homes the radio to ch1/ch36 (esp_wifi.h:1711) and drops AP clients.
    Serial.printf("[RF] Band=%u (0=2.4GHz 1=5GHz 2=both) regdomain applied\n", rfConfig.bandMode);
#endif
}

void setBandMode(uint8_t mode) {
#ifdef ARDUINO_XIAO_ESP32C5
    if (mode > 2) mode = 2;
#else
    mode = 0;  // 2.4GHz-only hardware
#endif
    rfConfig.bandMode = mode;
    prefs.putUInt("bandMode", mode);
    rebuildActiveChannels();
    Serial.printf("[RF] Band mode set to %u\n", mode);
}

const uint32_t SCAN_MESH_SLOT_CYCLE_MS = 15000;
const uint32_t SCAN_MESH_NUM_SLOTS = 5;
const uint32_t SCAN_MESH_SLOT_DURATION_MS = SCAN_MESH_SLOT_CYCLE_MS / SCAN_MESH_NUM_SLOTS;
const uint32_t SLOT_GUARD_MS = 200;

const uint32_t MESH_DEDUP_TTL_MIN_S = 0;
const uint32_t MESH_DEDUP_TTL_MAX_S = 3600;
const uint32_t MESH_DEDUP_TTL_DEFAULT_S = 300;
const size_t MESH_DEDUP_MAX_ENTRIES = 5000;
std::atomic<uint32_t> g_meshDedupTtlMs(MESH_DEDUP_TTL_DEFAULT_S * 1000);
std::atomic<bool> g_meshSessionDedup(false);
static std::map<String, uint32_t, std::less<String>,
    PsramAllocator<std::pair<const String, uint32_t>>> g_meshSentMacs;
static std::mutex g_meshSentMacsMutex;

void setMeshSessionDedup(bool on) { g_meshSessionDedup.store(on); }
bool getMeshSessionDedup() { return g_meshSessionDedup.load(); }

void setMeshDedupTtlSec(uint32_t sec) {
    if (sec > MESH_DEDUP_TTL_MAX_S) sec = MESH_DEDUP_TTL_MAX_S;
    g_meshDedupTtlMs.store(sec * 1000UL);
}

uint32_t getMeshDedupTtlSec() {
    return g_meshDedupTtlMs.load() / 1000UL;
}

bool meshShouldSendMac(const String& mac) {
    bool session = g_meshSessionDedup.load();
    uint32_t ttl = g_meshDedupTtlMs.load();
    if (!session && ttl == 0) return true;
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    auto it = g_meshSentMacs.find(mac);
    if (it == g_meshSentMacs.end()) return true;
    if (session) return false;
    return (millis() - it->second) >= ttl;
}

void meshMarkMacSent(const String& mac) {
    uint32_t ttl = g_meshDedupTtlMs.load();
    if (ttl == 0) return;
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    g_meshSentMacs[mac] = millis();
    if (g_meshSentMacs.size() > MESH_DEDUP_MAX_ENTRIES) {
        uint32_t now = millis();
        for (auto it = g_meshSentMacs.begin(); it != g_meshSentMacs.end();) {
            if (now - it->second >= ttl) it = g_meshSentMacs.erase(it);
            else ++it;
        }
    }
}

void meshDedupClear() {
    std::lock_guard<std::mutex> lk(g_meshSentMacsMutex);
    g_meshSentMacs.clear();
}

void setRFPreset(uint8_t preset) {
    switch(preset) {
        case 0:
            rfConfig.wifiChannelTime = 300;
            rfConfig.wifiScanInterval = 5000;
            rfConfig.bleScanInterval = 6000;
            rfConfig.bleScanDuration = 3000;
            rfConfig.globalRssiThreshold = -80;
            break;
        case 1:
            rfConfig.wifiChannelTime = 160;
            rfConfig.wifiScanInterval = 3000;
            rfConfig.bleScanInterval = 4000;
            rfConfig.bleScanDuration = 2000;
            rfConfig.globalRssiThreshold = -95;
            break;
        case 2:
            rfConfig.wifiChannelTime = 110;
            rfConfig.wifiScanInterval = 1500;
            rfConfig.bleScanInterval = 2000;
            rfConfig.bleScanDuration = 1000;
            rfConfig.globalRssiThreshold = -100;
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
        uint32_t wct = prefs.getUInt("wifiChanTime", 160);
        uint32_t wsi = prefs.getUInt("wifiInterval", 3000);
        uint32_t bsi = prefs.getUInt("bleInterval", 4000);
        uint32_t bsd = prefs.getUInt("bleDuration", 2000);
        String channels = prefs.getString("channels", "1..11");
        int8_t rssiThreshold = prefs.getInt("globalRSSI", -95);
        setCustomRFConfig(wct, wsi, bsi, bsd, channels, rssiThreshold);
    }

#ifdef ARDUINO_XIAO_ESP32C5
    uint8_t bm = prefs.getUInt("bandMode", DEFAULT_BAND_MODE);
    rfConfig.bandMode = (bm > 2) ? DEFAULT_BAND_MODE : bm;
#else
    rfConfig.bandMode = 0;  // 2.4GHz-only hardware
#endif
    rebuildActiveChannels();

    Serial.printf("[RF] Loaded config - Preset: %d, RSSI threshold: %d dBm, band: %u\n", rfConfig.preset, rfConfig.globalRssiThreshold, rfConfig.bandMode);
}

// Detection system variables
std::vector<DeauthHit> deauthLog;
std::mutex deauthLogMutex;
std::atomic<uint32_t> deauthCount(0);
std::atomic<uint32_t> disassocCount(0);
std::atomic<bool> deauthDetectionEnabled{false};
QueueHandle_t deauthQueue = nullptr;

// Triangulation
TriangulationAccumulator triAccum = {0};
std::atomic<uint8_t> triTargetChannel(0);
std::atomic<uint8_t> triTargetRadio(0);
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
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
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
        if (mac[0] == ouiTable[i].oui[0] && mac[1] == ouiTable[i].oui[1] && mac[2] == ouiTable[i].oui[2]) {
            return ouiTable[i].vendor;
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

static bool matchesIdentityMacLocked(const char* identityId, const uint8_t* mac)
{
    if (!identityId || strlen(identityId) == 0 || !mac) {
        return false;
    }

    String idStr(identityId);
    auto it = deviceIdentities.find(idStr);
    if (it == deviceIdentities.end()) {
        return false;
    }

    const DeviceIdentity& identity = it->second;

    return std::any_of(identity.macs.begin(), identity.macs.end(),
        [&](const auto& m) { return memcmp(m.bytes.data(), mac, 6) == 0; });
}

bool matchesIdentityMac(const char* identityId, const uint8_t* mac)
{
    std::lock_guard<std::mutex> lock(randMutex);
    return matchesIdentityMacLocked(identityId, mac);
}

void rebuildIdentityMacSnapshot()
{
    uint8_t staging[IDENTITY_MAC_SNAPSHOT_CAP][6];
    uint16_t n = 0;
    MacTargetSnap macStaging[MAC_TARGET_SNAPSHOT_CAP];
    uint16_t mn = 0;
    bool idPresent = false;

    {
        std::lock_guard<std::mutex> lock(randMutex);
        for (const auto &t : targets)
        {
            if (t.len == 0 && strlen(t.identityId) > 0) {
                idPresent = true;
                auto it = deviceIdentities.find(String(t.identityId));
                if (it == deviceIdentities.end()) continue;
                for (const auto &macAddr : it->second.macs)
                {
                    if (n >= IDENTITY_MAC_SNAPSHOT_CAP) break;
                    bool dup = false;
                    for (uint16_t j = 0; j < n; j++)
                    {
                        if (memcmp(staging[j], macAddr.bytes.data(), 6) == 0) { dup = true; break; }
                    }
                    if (dup) continue;
                    memcpy(staging[n], macAddr.bytes.data(), 6);
                    n++;
                }
                if (n >= IDENTITY_MAC_SNAPSHOT_CAP) break;
            }
            else if ((t.len == 6 || t.len == 3) && mn < MAC_TARGET_SNAPSHOT_CAP)
            {
                memcpy(macStaging[mn].bytes, t.bytes, 6);
                macStaging[mn].len = t.len;
                mn++;
            }
        }
    }

    identityMacSnapshotCount.store(0, std::memory_order_release);
    for (uint16_t i = 0; i < n; i++)
    {
        memcpy(identityMacSnapshot[i], staging[i], 6);
    }
    identityMacSnapshotCount.store(n, std::memory_order_release);

    macTargetSnapshotCount.store(0, std::memory_order_release);
    for (uint16_t i = 0; i < mn; i++)
    {
        macTargetSnapshot[i] = macStaging[i];
    }
    macTargetSnapshotCount.store(mn, std::memory_order_release);
    identityTargetPresentSnap.store(idPresent, std::memory_order_release);
}

static inline bool matchesIdentityMacSnapshot(const uint8_t *mac)
{
    uint16_t n = identityMacSnapshotCount.load(std::memory_order_acquire);
    if (n > IDENTITY_MAC_SNAPSHOT_CAP) n = IDENTITY_MAC_SNAPSHOT_CAP;
    for (uint16_t i = 0; i < n; i++)
    {
        if (memcmp(identityMacSnapshot[i], mac, 6) == 0) return true;
    }
    return false;
}

void saveTargetsList(const String &txt)
{
    prefs.putString("maclist", txt);
    {
    std::lock_guard<std::mutex> lock(randMutex);
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
    rebuildIdentityMacSnapshot();
}

bool matchesSsid(const char *ssid)
{
    if (!ssid || ssid[0] == '\0') return false;
    String lower = String(ssid);
    lower.toLowerCase();
    std::lock_guard<std::mutex> lock(randMutex);
    return std::any_of(ssidTargets.begin(), ssidTargets.end(),
        [&](const auto& s) { return lower == s; });
}

bool matchesMac(const uint8_t *mac)
{
    bool allFF = true, allZero = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) allFF = false;
        if (mac[i] != 0x00) allZero = false;
    }
    if (allFF || allZero) return false;

    std::lock_guard<std::mutex> lock(randMutex);
    for (const auto &t : targets)
    {
        if (t.len == 0 && strlen(t.identityId) > 0) {
            if (matchesIdentityMacLocked(t.identityId, mac)) {
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

static inline bool IRAM_ATTR matchesMacISR(const uint8_t *mac)
{
    uint16_t mn = macTargetSnapshotCount.load(std::memory_order_acquire);
    for (uint16_t i = 0; i < mn; i++)
    {
        const MacTargetSnap &t = macTargetSnapshot[i];
        if (t.len == 6)
        {
            bool eq = true;
            for (int k = 0; k < 6; k++)
            {
                if (mac[k] != t.bytes[k]) { eq = false; break; }
            }
            if (eq) return true;
        }
        else if (t.len == 3)
        {
            if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2])
                return true;
        }
    }
    if (identityTargetPresentSnap.load(std::memory_order_acquire) && matchesIdentityMacSnapshot(mac)) {
        return true;
    }
    return false;
}

#ifndef AH_C5_RF_TRACE
#ifdef ARDUINO_XIAO_ESP32C5
#define AH_C5_RF_TRACE 1
#else
#define AH_C5_RF_TRACE 0
#endif
#endif

#if AH_C5_RF_TRACE
// cppcheck-suppress unusedFunction
static void rfTrace(const char *tag, uint8_t reqCh, int rc, uint32_t ms)
{
    uint8_t prim = 0;
    wifi_second_chan_t sec;
    esp_wifi_get_channel(&prim, &sec);
    Serial.printf("[RF] %s req=%u rc=%d %ums radio=%u sta=%u\n", tag, (unsigned)reqCh, rc,
                  (unsigned)ms, (unsigned)prim, (unsigned)WiFi.softAPgetStationNum());
}
#else
// cppcheck-suppress unusedFunction
static void rfTrace(const char *, uint8_t, int, uint32_t) {}
#endif

// A station drops the SoftAP after AH_AP_BEACON_TIMEOUT_MS without a beacon (ESP-IDF default 6s),
// so every off-channel excursion is charged against that budget and the AP is serviced before it.
static volatile uint32_t g_apLastServedMs = 0;
static volatile uint8_t g_apHomeCh = AP_CHANNEL;

uint8_t apHomeChannel()
{
    wifi_config_t cfg;
    if (esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK && cfg.ap.channel)
        g_apHomeCh = cfg.ap.channel;
    return g_apHomeCh;
}

bool apHasClients() { return WiFi.softAPgetStationNum() > 0; }

uint32_t apServiceGapMs()
{
    uint32_t last = g_apLastServedMs;
    return last ? (millis() - last) : 0;
}

void apMarkServed() { g_apLastServedMs = millis(); }

void apServiceNow(const char *why)
{
    uint8_t home = apHomeChannel();
    uint32_t gap = apServiceGapMs();
    esp_wifi_set_channel(home, WIFI_SECOND_CHAN_NONE);
    apMarkServed();
#if AH_C5_RF_TRACE
    if (gap > AH_AP_SERVICE_WARN_MS)
        Serial.printf("[AP_SVC] %s home=%u gap=%ums sta=%u\n", why, (unsigned)home,
                      (unsigned)gap, (unsigned)WiFi.softAPgetStationNum());
#else
    (void)why; (void)gap;
#endif
}

static void hopTimerCb(void *)
{
    if (!hopTimer || g_activeChannels.empty()) return;
    static size_t idx = 0;
    static bool serveAp = false;

    if (apHasClients()) {
        serveAp = !serveAp;
        if (serveAp) {
            esp_wifi_set_channel(apHomeChannel(), WIFI_SECOND_CHAN_NONE);
            apMarkServed();
            return;
        }
        if (apServiceGapMs() >= AH_AP_SERVICE_MAX_MS) {
            esp_wifi_set_channel(apHomeChannel(), WIFI_SECOND_CHAN_NONE);
            apMarkServed();
            return;
        }
    }

    if (triangulationActive.load()) {
        uint8_t tch = triTargetChannel.load();
        if (tch >= 1 && tch <= 14) {
            esp_wifi_set_channel(tch, WIFI_SECOND_CHAN_NONE);
            return;
        }
    }

    idx = (idx + 1) % g_activeChannels.size();
    uint8_t ch = g_activeChannels[idx];
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (ch == apHomeChannel()) apMarkServed();
}

uint8_t nextActiveScanChannel()
{
    const std::vector<uint8_t> &pool = g_activeChannels.empty() ? CHANNELS : g_activeChannels;
    if (pool.empty()) return (uint8_t)AP_CHANNEL;
    static size_t i = 0;
    i = (i + 1) % pool.size();
    return pool[i];
}


// Deauth type
static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 28) return;
    if (!deauthQueue) return;

    const uint8_t *payload = ppkt->payload;
    uint8_t version = (payload[0] & 0x03);
    uint8_t type    = (payload[0] >> 2) & 0x03;
    uint8_t subtype = (payload[0] >> 4) & 0x0F;

    if (type != 0 || version != 0) return;

    bool isDisassoc = (subtype == 0x0A);
    bool isDeauth   = (subtype == 0x0C);
    if (!isDisassoc && !isDeauth) return;
    if (payload[1] & 0x08) return;   // retransmit — exact dup, drop (parity with Sentinel)

    DeauthHit hit;
    memcpy(hit.destMac, payload + 4,  6);
    memcpy(hit.srcMac,  payload + 10, 6);
    memcpy(hit.bssid,   payload + 16, 6);
    hit.seqCtrl     = static_cast<uint16_t>(payload[22] | (payload[23] << 8));
    hit.reasonCode  = static_cast<uint16_t>(payload[24] | (payload[25] << 8));
    hit.rssi        = ppkt->rx_ctrl.rssi;
    hit.channel     = ppkt->rx_ctrl.channel;
    hit.timestamp   = millis();
    hit.isDisassoc  = isDisassoc;
    hit.isBroadcast = (memcmp(hit.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0);
    hit.companyId   = 0;
    hit.toolHint    = 0;
    if (hit.reasonCode == 0x0002 && hit.seqCtrl == 0xFFF0) hit.toolHint |= 0x01;  // tool
    // bit1 (tool reason in {1,4,6,7,8}) removed — too FP-heavy on real APs.
    if (hit.isBroadcast) hit.toolHint |= 0x04;  // broadcast-dst (informational)

    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(deauthQueue, &hit, &woken);
    if (woken) portYIELD_FROM_ISR();
}

// Main NimBLE callback
class MyBLEScanCallbacks : public NimBLEScanCallbacks {
    // cppcheck-suppress unusedFunction // NimBLEScanCallbacks override, invoked by NimBLE per advertisement
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        int8_t rssi = advertisedDevice->getRSSI();
        if (rssi > -10) return;

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

        if (randomizationDetectionEnabled && bleAdvQueue) {
            BleAdvEvent evt = {};
            memcpy(evt.mac, mac, 6);
            evt.rssi = rssi;
            strncpy(evt.name, deviceName.c_str(), sizeof(evt.name) - 1);
            evt.name[sizeof(evt.name) - 1] = '\0';
            std::string mfr = advertisedDevice->getManufacturerData();
            evt.mfrDataLen = static_cast<uint8_t>(std::min<size_t>(mfr.size(), sizeof(evt.mfrData)));
            if (evt.mfrDataLen > 0) memcpy(evt.mfrData, mfr.data(), evt.mfrDataLen);
            std::vector<uint8_t> pl = advertisedDevice->getPayload();
            evt.payloadLen = static_cast<uint8_t>(std::min<size_t>(pl.size(), sizeof(evt.payload)));
            if (evt.payloadLen > 0) memcpy(evt.payload, pl.data(), evt.payloadLen);
            xQueueSend(bleAdvQueue, &evt, 0);
        }

        if (droneDetectionEnabled) {
            std::vector<uint8_t> dpl = advertisedDevice->getPayload();
            const uint8_t *dp = dpl.data();
            size_t dlen = dpl.size();
            size_t doff = 0;
            while (doff + 2 <= dlen) {
                uint8_t dl = dp[doff];
                if (dl == 0) { doff += 1; continue; }
                if (doff + 1 + dl > dlen) break;
                if (dp[doff + 1] == 0x16 && dl >= 4 && dp[doff + 2] == 0xFA && dp[doff + 3] == 0xFF) {
                    processDroneOdidBle(mac, rssi, dp + doff + 4, (int)(dlen - (doff + 4)));
                    break;
                }
                doff += 1 + dl;
            }
        }

        if (!triangulationActive && rssi < rfConfig.globalRssiThreshold) {
            return;
        }

        {
            std::vector<uint8_t> payload = advertisedDevice->getPayload();
            detect_onBleAdv(mac, rssi, payload.data(),
                            (uint16_t)payload.size(), nullptr);
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

ProbeDevicesMap probeDevices;
std::mutex probeMutex;
StringSetPsram uniqueSsids;
StringSetPsram respondedSsids;

bool ssidLooksRandom(const char *s, size_t len) {
    if (!s || len < 20) return false;
    bool up = false, lo = false, di = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 'A' && c <= 'Z') up = true;
        else if (c >= 'a' && c <= 'z') lo = true;
        else if (c >= '0' && c <= '9') di = true;
        else return false;
    }
    if (!(up && lo && di)) return false;
    size_t sw = 0;
    for (size_t i = 1; i < len; i++) {
        char a = s[i - 1], b = s[i];
        int ca = (a >= 'A' && a <= 'Z') ? 0 : (a >= 'a' && a <= 'z') ? 1 : 2;
        int cb = (b >= 'A' && b <= 'Z') ? 0 : (b >= 'a' && b <= 'z') ? 1 : 2;
        if (ca != cb) sw++;
    }
    return (sw * 100) / (len - 1) >= 55;
}

bool ssidIsValid(const char *s, size_t len) {
    if (!s || len == 0 || len > 32) return false;
    size_t i = 0;
    while (i < len) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F) return false;
        if (c < 0x80) { i++; continue; }
        int n;
        if (c >= 0xC2 && c <= 0xDF) n = 1;
        else if (c >= 0xE0 && c <= 0xEF) n = 2;
        else if (c >= 0xF0 && c <= 0xF4) n = 3;
        else return false;
        if (i + (size_t)n >= len) return false;
        for (int k = 1; k <= n; k++) {
            unsigned char cc = (unsigned char)s[i + k];
            if (cc < 0x80 || cc > 0xBF) return false;
        }
        i += (size_t)n + 1;
    }
    return true;
}

String sanitizeAscii(const char *s, size_t maxLen) {
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

    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);

    Serial.printf("[SNIFFER] Starting device scan %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    if (currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) {
        if (apInfoQueue == nullptr) {
            apInfoQueue = xQueueCreateWithCaps(128, sizeof(ApInfoEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        }
        if (apInfoQueue) xQueueReset(apInfoQueue);
        apCaptureEnabled = true;
        radioStartSTA();
        vTaskDelay(pdMS_TO_TICKS(200));
    } else if (currentScanMode == SCAN_BLE) {
        vTaskDelay(pdMS_TO_TICKS(100));
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    uint32_t bleInterval = BLE_SCAN_INTERVAL;

    scanning = true;
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }
    uniqueMacs.clear();
    hitsLog.clear();
    { std::lock_guard<std::mutex> lock(snifferCacheMutex); apCache.clear(); bleDeviceCache.clear(); }
    totalHits = 0;
    framesSeen = 0;
    bleFramesSeen = 0;
    stopRequested = false;
    lastScanStart = millis();
    lastScanSecs = duration;
    lastScanForever = forever;
    scanSetCountdown(duration, forever);

    unsigned long lastBLEScan = 0;
    unsigned long lastMeshUpdate = 0;
    const unsigned long MESH_DEVICE_SCAN_UPDATE_INTERVAL = 3000;
    unsigned long lastTotalPrint = 0;
    size_t lastTotalAp = SIZE_MAX, lastTotalBle = SIZE_MAX, lastTotalUniq = SIZE_MAX;
    int lastTotalHits = -1;
    unsigned long nextResultsUpdate = millis();
    size_t lastWrittenHitCount = SIZE_MAX;

    std::set<String> transmittedDevices;
    if (!getMeshSessionDedup()) meshDedupClear();

    String meshBatch;
    std::vector<String> meshBatchMacs;
    auto flushMeshBatch = [&]() {
        if (meshBatch.length() == 0) return;
        if (meshEnqueue(meshBatch)) {
            for (const auto &m : meshBatchMacs) {
                transmittedDevices.insert(m);
                meshMarkMacSent(m);
            }
        }
        meshBatch = "";
        meshBatchMacs.clear();
    };
    auto addMeshDeviceRow = [&](const String &row, const String &mac) {
        String firstFrame = getNodeId() + ": " + row;
        if (firstFrame.length() > (size_t)MAX_MESH_SIZE) return;
        String candidate = (meshBatch.length() == 0) ? firstFrame : (meshBatch + "\n" + row);
        if (candidate.length() > (size_t)MAX_MESH_SIZE) {
            flushMeshBatch();
            meshBatch = firstFrame;
        } else {
            meshBatch = candidate;
        }
        meshBatchMacs.push_back(mac);
    };

    NimBLEScan *bleScan = pBLEScan;

    while ((forever && !stopRequested) ||
           (!forever && static_cast<int>(millis() - lastScanStart) < duration * 1000 && !stopRequested))
    {
        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) && apInfoQueue) {
            ApInfoEvent ae;
            int apDrained = 0;
            while (xQueueReceive(apInfoQueue, &ae, 0) == pdTRUE && apDrained < 50) {
                apDrained++;
                if (!triangulationActive && ae.rssi < rfConfig.globalRssiThreshold) continue;

                char bstr[18];
                snprintf(bstr, sizeof(bstr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         ae.bssid[0], ae.bssid[1], ae.bssid[2], ae.bssid[3], ae.bssid[4], ae.bssid[5]);
                String bssid = bstr;
                String ssid = (ae.ssid[0] && ssidIsValid(ae.ssid, strlen(ae.ssid))) ? String(ae.ssid) : String("[Hidden]");

                if (apCache.find(bssid) == apCache.end())
                {
                    std::lock_guard<std::mutex> lock(snifferCacheMutex);
                    if (apCache.size() < MAX_AP_CACHE) {
                        apCache[bssid] = ssid;
                    }
                    if (uniqueMacs.size() < MAX_UNIQUE_MACS) uniqueMacs.insert(bssid);

                    Hit h;
                    memcpy(h.mac, ae.bssid, 6);
                    h.rssi = ae.rssi;
                    h.ch = ae.channel;
                    strncpy(h.name, ssid.c_str(), sizeof(h.name) - 1);
                    h.name[sizeof(h.name) - 1] = '\0';
                    h.isBLE = false;

                    if (hitsLog.size() < MAX_LOG_SIZE) {
                        hitsLog.push_back(h);
                    }

                    if (matchesMac(ae.bssid)) {
                        totalHits = totalHits + 1;
                    }

                    String logEntry = "WiFi AP: " + bssid + " SSID: " + ssid +
                                      " RSSI: " + String(ae.rssi) + "dBm CH: " + String(ae.channel);

                    if (gpsValid)
                    {
                        if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                            logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                            xSemaphoreGive(gpsMutex);
                        }
                    }

                    Serial.println("[SNIFFER] " + logEntry);
                    logToSD(logEntry);

                    if (matchesMac(ae.bssid)) {
                        sendMeshNotification(h);
                    }
                }
            }
        }

        if (bleScan && (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) &&
            (millis() - lastBLEScan >= bleInterval || lastBLEScan == 0))
        {
            lastBLEScan = millis();

            Serial.println("[SNIFFER] Scanning BLE devices...");

                NimBLEScanResults scanResults = bleScan->getResults(rfConfig.bleScanDuration, false);
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

                        {
                            std::lock_guard<std::mutex> lock(snifferCacheMutex);
                            if (bleDeviceCache.size() < MAX_BLE_CACHE) {
                                bleDeviceCache[macStr] = cleanName;
                            }
                        }
                        if (uniqueMacs.size() < MAX_UNIQUE_MACS) uniqueMacs.insert(macStr);

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

        if (meshEnabled && millis() - lastMeshUpdate >= MESH_DEVICE_SCAN_UPDATE_INTERVAL)
        {
            lastMeshUpdate = millis();

            for (const auto& entry : apCache)
            {
                String macStr = entry.first;
                String ssid = entry.second;

                if (transmittedDevices.find(macStr) == transmittedDevices.end() && meshShouldSendMac(macStr))
                {
                    String row = "DEVICE:" + macStr + " W ";

                    int8_t bestRssi = -128;
                    uint8_t bestCh = 0;
                    for (const auto& hit : hitsLog) {
                        String hitMac = macFmt6(hit.mac);
                        if (hitMac == macStr && hit.rssi > bestRssi) {
                            bestRssi = hit.rssi;
                            bestCh = hit.ch;
                        }
                    }

                    row += String(bestRssi);
                    if (bestCh > 0) row += " C" + String(bestCh);
                    if (ssid.length() > 0 && ssid != "[Hidden]") {
                        row += " N:" + ssid.substring(0, 30);
                    }

                    addMeshDeviceRow(row, macStr);
                }
            }

            for (const auto& entry : bleDeviceCache)
            {
                String macStr = entry.first;
                String name = entry.second;

                if (transmittedDevices.find(macStr) == transmittedDevices.end() && meshShouldSendMac(macStr))
                {
                    String row = "DEVICE:" + macStr + " B ";

                    int8_t bestRssi = -128;
                    for (const auto& hit : hitsLog) {
                        String hitMac = macFmt6(hit.mac);
                        if (hitMac == macStr && hit.isBLE && hit.rssi > bestRssi) {
                            bestRssi = hit.rssi;
                        }
                    }

                    row += String(bestRssi);
                    if (name.length() > 0 && name != "Unknown") {
                        row += " N:" + name.substring(0, 30);
                    }

                    addMeshDeviceRow(row, macStr);
                }
            }

            flushMeshBatch();
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
                bool pWildcard = false;
                if (!pEvt.dstMatch) {
                    pHasSsid = extractSsidFromProbe(pEvt.payload, pEvt.payloadLen, pssid, sizeof(pssid), &pWildcard);
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
                    if (pWildcard) pd.wildcardCount++;
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
                        const char *ouiVendor = lookupOuiVendor(pEvt.mac);
                        if (ouiVendor) strncpy(pd.vendor, ouiVendor, sizeof(pd.vendor) - 1);
                    }
                    if (pHasSsid) addProbeSsid(pd, pssid);
                    if (pWildcard) pd.wildcardCount++;
                    probeDevices[String(pmac)] = pd;
                }
            }
        }

        if (static_cast<int32_t>(millis() - nextResultsUpdate) >= 0 || hitsLog.size() != lastWrittenHitCount) {
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
                { const char *hv = lookupOuiVendor(hit.mac); if (hv) results += std::string(" V=") + hv; }
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
                            if (!rs.empty()) results += " AP=\"" + rs + "\"";
                        }
                        results += " x" + std::to_string(pd.probeCount) + "\n";
                    }
                }
            }

            antihunter::lastResults = results;
            nextResultsUpdate = millis() + 1000;
            lastWrittenHitCount = hitsLog.size();
        }

        {
            size_t nAp = apCache.size(), nBle = bleDeviceCache.size(), nUniq = uniqueMacs.size();
            int nHits = totalHits.load();
            bool changed = (nAp != lastTotalAp || nBle != lastTotalBle ||
                            nUniq != lastTotalUniq || nHits != lastTotalHits);
            if (changed || (millis() - lastTotalPrint) >= 5000) {
                Serial.printf("[SNIFFER] Total: WiFi APs=%d, BLE=%d, Unique=%d, Hits=%d\n",
                              nAp, nBle, nUniq, nHits);
                lastTotalPrint = millis();
                lastTotalAp = nAp; lastTotalBle = nBle; lastTotalUniq = nUniq; lastTotalHits = nHits;
            }
        }

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

    apCaptureEnabled = false;
    probeDetectionEnabled = false;
    scanning = false;
    lastScanEnd = millis();

    radioStopSTA();
    releaseProbeQueue();
    delay(500);

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        std::string results =
            "Sniffer scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? std::string("Forever\n") : (std::to_string(duration) + "s\n")) +
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

            { const char *hv = lookupOuiVendor(hit.mac); if (hv) results += std::string(" V=") + hv; }
            results += "\n";
        }

        if (sortedHits.size() > 100) {
            results += "... (" + std::to_string(sortedHits.size() - 100) + " more)\n";
        }

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

    if (meshEnabled) {
        const size_t txBefore = transmittedDevices.size();
        uint32_t skippedDevices = 0;
        for (const auto& entry : apCache) {
            if (transmittedDevices.find(entry.first) != transmittedDevices.end()) continue;
            if (!meshShouldSendMac(entry.first)) { skippedDevices++; continue; }
            String row = "DEVICE:" + entry.first + " W ";
            int8_t bestRssi = -128;
            uint8_t bestCh = 0;
            for (const auto& hit : hitsLog) {
                String hitMac = macFmt6(hit.mac);
                if (hitMac == entry.first && hit.rssi > bestRssi) {
                    bestRssi = hit.rssi;
                    bestCh = hit.ch;
                }
            }
            row += String(bestRssi);
            if (bestCh > 0) row += " C" + String(bestCh);
            if (entry.second.length() > 0 && entry.second != "[Hidden]") {
                row += " N:" + entry.second.substring(0, 30);
            }
            addMeshDeviceRow(row, entry.first);
        }

        for (const auto& entry : bleDeviceCache) {
            if (transmittedDevices.find(entry.first) != transmittedDevices.end()) continue;
            if (!meshShouldSendMac(entry.first)) { skippedDevices++; continue; }
            String row = "DEVICE:" + entry.first + " B ";
            int8_t bestRssi = -128;
            for (const auto& hit : hitsLog) {
                String hitMac = macFmt6(hit.mac);
                if (hitMac == entry.first && hit.isBLE && hit.rssi > bestRssi) {
                    bestRssi = hit.rssi;
                }
            }
            row += String(bestRssi);
            if (entry.second.length() > 0 && entry.second != "Unknown") {
                row += " N:" + entry.second.substring(0, 30);
            }
            addMeshDeviceRow(row, entry.first);
        }
        flushMeshBatch();

        if (!stopRequested) {
            const uint32_t totalTx = transmittedDevices.size();
            const uint32_t enqueuedDevices = totalTx - static_cast<uint32_t>(txBefore);
            const uint32_t totalDevices = apCache.size() + bleDeviceCache.size();
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

static std::string buildDeauthResults(bool forever, int duration, uint32_t deauthFrames,
                                      uint32_t disassocFrames, const std::vector<DeauthHit>& deauthHits) {
    std::map<String, DeauthStats> statsMap;
    
    for (const auto& h : deauthHits) {
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
    
    uint32_t forgeHits = 0, bcastHits = 0;
    for (const auto &h : deauthHits) {
        if (h.toolHint & 0x01) forgeHits++;
        if (h.toolHint & 0x04) bcastHits++;
    }

    std::string results = "Deauth Attack Detection Results\n";
    results += "Duration: " + (forever ? std::string("Forever\n") : (std::to_string(duration) + "s\n"));
    results += "Deauth frames: " + std::to_string(deauthFrames) + "\n";
    results += "Disassoc frames: " + std::to_string(disassocFrames) + "\n";
    results += "Total attacks: " + std::to_string(deauthHits.size()) + "\n";
    results += "Targets attacked: " + std::to_string(statsMap.size()) + "\n";
    if (forgeHits) results += "tool fingerprint (reason=2 seq=FFF0): " + std::to_string(forgeHits) + "\n";
    if (bcastHits)    results += "Broadcast-dst deauths: " + std::to_string(bcastHits) + " (informational)\n";
    {
        std::map<String, int> srcUnicastCount;
        for (const auto &h : deauthHits) {
            if (!h.isBroadcast) srcUnicastCount[macFmt6(h.srcMac)]++;
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
            for (const auto& h : deauthHits) {
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
    sentinel_yieldAndWait(1000);   // hand off radio; detect engine keeps ingesting our frames
    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
    bool forever = (duration <= 0);

    String startMsg = forever ?
                              String("[BLUE] Starting deauth detection (forever)\n")
                              : String("[BLUE] Starting deauth detection for " + String(duration) + "s\n");
    Serial.print(startMsg);
    
    { std::lock_guard<std::mutex> lock(deauthLogMutex); deauthLog.clear(); }
    deauthCount = 0;
    disassocCount = 0;
    deauthDetectionEnabled = false;
    stopRequested = false;
    scanning = true;
    scanSetCountdown(duration, forever);

    std::map<uint64_t, std::pair<uint32_t, uint16_t>> floodWin;
    std::set<uint64_t> floodAlerted;

    if (deauthQueue) {
        QueueHandle_t oldQueue = deauthQueue;
        deauthQueue = nullptr;
        vQueueDeleteWithCaps(oldQueue);
    }

    deauthQueue = xQueueCreateWithCaps(256, sizeof(DeauthHit), AH_ISR_QUEUE_CAPS);
    if (!deauthQueue) {
        Serial.printf("[BLUE] FATAL: Queue creation failed (need=%u internal=%u largest=%u)\n",
                      (unsigned)(256 * sizeof(DeauthHit)),
                      (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                      (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        scanning = false;
        blueTeamTaskHandle = nullptr;
        scanSetCountdown(0, false);
        vTaskDelete(NULL);
        return;
    }
    deauthDetectionEnabled = true;

    std::set<String> transmittedAttacks;
    
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    uint32_t lastResultsUpdate = millis() + 1000;
    uint32_t lastWrittenDeauthTotal = UINT32_MAX;
    uint32_t lastMeshUpdate = millis();
    const unsigned long MESH_DEAUTH_UPDATE_INTERVAL = 5000;
    DeauthHit hit;

    radioStartSTA();
    vTaskDelay(pdMS_TO_TICKS(200));

    const int BATCH_LIMIT = 4;
    std::map<String, std::vector<uint32_t>> targetHistory;
    uint32_t lastTargetCleanup = millis();

    while ((forever && !stopRequested) ||
           (!forever && static_cast<int>(millis() - scanStart) < duration * 1000 && !stopRequested)) {

        int processed = 0;

        while (processed++ < BATCH_LIMIT && xQueueReceive(deauthQueue, &hit, 0) == pdTRUE) {
            // our own SoftAP dropping clients (channel hop / idle) is not an attack
            if (detect_isSelfApMac(hit.srcMac)) continue;
            uint32_t now = millis();
            String destMacStr = macFmt6(hit.destMac);

            // Reason-code arm dropped (1/2/6/7 are legit deauth causes; Sentinel does attribution).
            bool isAttack = hit.isBroadcast;

            targetHistory[destMacStr].push_back(now);
            auto& times = targetHistory[destMacStr];
            times.erase(std::remove_if(times.begin(), times.end(),
                [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }), times.end());
            if (times.size() >= ah_detect::g_deauthTargetedThresh.load()) isAttack = true;

            if ((now - lastTargetCleanup) > DEAUTH_CLEANUP_INTERVAL) {
                for (auto it = targetHistory.begin(); it != targetHistory.end(); ) {
                    auto& vec = it->second;
                    vec.erase(std::remove_if(vec.begin(), vec.end(),
                        [now](uint32_t t) { return (now - t) > DEAUTH_TARGETED_WINDOW; }), vec.end());
                    if (vec.empty()) it = targetHistory.erase(it); else ++it;
                }
                if (targetHistory.size() > DEAUTH_HISTORY_MAX_SIZE) {
                    size_t toRemove = targetHistory.size() - DEAUTH_HISTORY_MAX_SIZE;
                    auto it = targetHistory.begin();
                    for (size_t i = 0; i < toRemove && it != targetHistory.end(); ++i)
                        it = targetHistory.erase(it);
                }
                lastTargetCleanup = now;
            }

            if (!isAttack) continue;

            if (hit.isDisassoc) disassocCount = disassocCount + 1;
            else                deauthCount   = deauthCount + 1;

            {
                std::lock_guard<std::mutex> lock(deauthLogMutex);
                if (deauthLog.size() < 2000) {
                    deauthLog.push_back(hit);
                }
            }

            if (!hit.isBroadcast) {
                detect_witnessDeauth(hit.srcMac, hit.destMac, hit.rssi, hit.channel);
            }

            // High-confidence flood detector — same as full firmware.
            {
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
                if (floodWin.size() > 64) {
                    uint32_t oldest = UINT32_MAX; uint64_t oldestK = 0;
                    for (const auto &kv : floodWin) if (kv.second.first < oldest) { oldest = kv.second.first; oldestK = kv.first; }
                    floodWin.erase(oldestK);
                    floodAlerted.erase(oldestK);
                }
            }

            String srcMac = macFmt6(hit.srcMac);
            String dstMac = destMacStr;
            String attackKey = srcMac + "->" + dstMac;

            String alert = String(hit.isDisassoc ? "DISASSOC" : "DEAUTH");
            if (hit.isBroadcast) {
                alert += " [BROADCAST]";
            } else {
                alert += " [TARGETED]";
            }
            alert += " SRC:" + srcMac + " DST:" + dstMac;
            alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
            alert += " R:" + String(hit.reasonCode);

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

            std::lock_guard<std::mutex> lock(deauthLogMutex);
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
        
        if (static_cast<int32_t>(millis() - nextStatus) >= 0) {
            size_t n;
            { std::lock_guard<std::mutex> lock(deauthLogMutex); n = deauthLog.size(); }
            Serial.printf("[BLUE] Deauth:%u Disassoc:%u Total:%u\n",
                         deauthCount.load(), disassocCount.load(), static_cast<unsigned>(n));
            nextStatus += 5000;
        }

        uint32_t curDeauthTotal = deauthCount.load() + disassocCount.load();
        if (static_cast<int32_t>(millis() - lastResultsUpdate) >= 0 || curDeauthTotal != lastWrittenDeauthTotal) {
            std::string results;
            {
                std::lock_guard<std::mutex> lock(deauthLogMutex);
                results = buildDeauthResults(forever, duration, deauthCount.load(), disassocCount.load(), deauthLog);
            }

            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = results;
            }
            
            lastResultsUpdate = millis() + 1000;
            lastWrittenDeauthTotal = curDeauthTotal;
        }
        
        if (millis() - lastCleanup > 60000) {
            lastCleanup = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    deauthDetectionEnabled = false;

    std::vector<DeauthHit> deauthSnapshot;
    {
        std::lock_guard<std::mutex> lock(deauthLogMutex);
        deauthSnapshot = deauthLog;
    }

    {
        std::string deauthRes = buildDeauthResults(forever, duration, deauthCount.load(), disassocCount.load(), deauthSnapshot);
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = deauthRes;
    }

    scanSetCountdown(0, false);
    scanning = false;

    vTaskDelay(pdMS_TO_TICKS(200));

    radioStopSTA();

    vTaskDelay(pdMS_TO_TICKS(100));

    if (deauthQueue) {
        DeauthHit dummy;
        while (xQueueReceive(deauthQueue, &dummy, 0) == pdTRUE) {
        }
        vQueueDeleteWithCaps(deauthQueue);
        deauthQueue = nullptr;
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    lastScanEnd = millis();

    // Log deauth events to SD
    if (SafeSD::isAvailable() && !deauthSnapshot.empty()) {
        uint32_t now = getEventTimestamp();
        for (const auto& logHit : deauthSnapshot) {
            DynamicJsonDocument doc(384);
            doc["t"] = now;
            doc["src"] = macFmt6(logHit.srcMac);
            doc["dst"] = macFmt6(logHit.destMac);
            doc["bssid"] = macFmt6(logHit.bssid);
            doc["rssi"] = logHit.rssi;
            doc["ch"] = logHit.channel;
            doc["reason"] = logHit.reasonCode;
            doc["disassoc"] = logHit.isDisassoc;
            doc["broadcast"] = logHit.isBroadcast;
            doc["seq"] = logHit.seqCtrl;
            doc["tool"] = logHit.toolHint;
            String line;
            serializeJson(doc, line);
            logEventToSD("/deauth.jsonl", line);
        }
        Serial.printf("[BLUE] Logged %d deauth events to SD\n", static_cast<int>(deauthSnapshot.size()));
    }

    if (meshEnabled && !stopRequested) {
        uint32_t enqueued = 0;
        for (const auto& entry : deauthSnapshot) {
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

        uint32_t totalAttacks = deauthSnapshot.size();
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
    uint8_t dsChan = 0;
    uint8_t htChan = 0;

    while (offset + 2 <= ieLen) {
        uint8_t tag = ie[offset];
        uint8_t len = ie[offset + 1];

        if (offset + 2 + len > ieLen) break;

        // Tag 3 = DS Parameter Set (2.4 GHz only) — 1 byte primary channel
        if (tag == 3 && len == 1) {
            dsChan = ie[offset + 2];
        }
        // Tag 61 = HT Operation IE (2.4/5 GHz) — byte 0 = primary channel
        else if (tag == 61 && len >= 1) {
            htChan = ie[offset + 2];
        }

        offset += 2 + len;
    }

    if (dsChan) return dsChan;
    if (htChan) return htChan;
    return 0;
}

void IRAM_ATTR sniffer_cb(const void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!buf) return;

    const wifi_promiscuous_pkt_t *ppkt = static_cast<const wifi_promiscuous_pkt_t *>(buf);

    // Jamming PHY-stat: feed EVERY packet (incl. CRC-fail / short error frames)
    // before any length/rssi gate, so PDR-vs-error accounting sees the failures.
    detect_onPhyStat(ppkt->rx_ctrl.rx_state, ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);

    if (ppkt->rx_ctrl.sig_len < 24) {
        return;
    }

    framesSeen = framesSeen + 1;

    if (ppkt->rx_ctrl.rx_state != 0) return;

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
        if (copyLen < sizeof(droneEvt.payload))
            memset(droneEvt.payload + copyLen, 0, sizeof(droneEvt.payload) - copyLen);
        droneEvt.len  = copyLen;
        droneEvt.rssi = ppkt->rx_ctrl.rssi;
        BaseType_t woken = pdFALSE;
        xQueueSendFromISR(droneFrameQueue, &droneEvt, &woken);
        if (woken) portYIELD_FROM_ISR();
    }

    if (apCaptureEnabled && apInfoQueue && ppkt->rx_ctrl.sig_len >= 36) {
        const uint8_t *p = ppkt->payload;
        uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        uint8_t ftype = (fc >> 2) & 0x3;
        uint8_t stype = (fc >> 4) & 0xF;
        if (ftype == 0 && (stype == 8 || stype == 5)) {
            ApInfoEvent ae = {};
            memcpy(ae.bssid, p + 16, 6);
            ae.rssi = ppkt->rx_ctrl.rssi;
            uint8_t chIe = extractChannelFromIE(p, ppkt->rx_ctrl.sig_len, 36);
            ae.channel = (chIe >= 1 && chIe <= 14) ? chIe : ppkt->rx_ctrl.channel;
            extractSsidFromIE(p, ppkt->rx_ctrl.sig_len, 36, ae.ssid, sizeof(ae.ssid));
            BaseType_t woken = pdFALSE;
            xQueueSendFromISR(apInfoQueue, &ae, &woken);
            if (woken) portYIELD_FROM_ISR();
        }
    }

    if ((randomizationDetectionEnabled || probeDetectionEnabled) && ppkt->rx_ctrl.sig_len >= 24) {
        const uint8_t *payload = ppkt->payload;
        uint16_t fc = static_cast<uint16_t>(payload[0]) | (static_cast<uint16_t>(payload[1]) << 8);
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
        // Rate-limited: only queue if queue <50% full to preserve capacity for probe requests
        else if (ftype == 0 && stype == 5 && probeDetectionEnabled && probeRequestQueue) {
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

        if (probeDetectionEnabled && ftype == 0 && probeRequestQueue
            && stype != 4 && stype != 5 && stype != 8) {
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
                    BaseType_t woken = pdFALSE;
                    xQueueSendFromISR(probeRequestQueue, &dstEvt, &woken);
                    if (woken) portYIELD_FROM_ISR();
                }
            }
        }
    }

    detectDeauthFrame(ppkt);

    // Phase 1: attack-signature detectors (PMKID, evil-twin, SSID confusion,
    // SAE DoS, OWE abuse, FragAttacks PN reuse).
    detect_onWifiFrame(ppkt->payload, ppkt->rx_ctrl.sig_len,
                       ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);

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
            const uint8_t *a1 = p + 4;
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
            c1Match = matchesMacISR(cand1);
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
            c2Match = matchesMacISR(cand2);
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

static volatile bool bleInitDone = false;
static volatile bool bleInitFailed = false;

static void bleInitTask(void *pv) {
    Serial.printf("[BLE_INIT] core=%d heap=%u largest=%u\n",
                  xPortGetCoreID(),
                  (unsigned)ESP.getFreeHeap(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    // NimBLE aborts (npl_freertos_funcs_init assert) instead of returning when internal RAM is short
    {
        size_t freeInt = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (freeInt < AH_BLE_MIN_INTERNAL || largest < AH_BLE_MIN_BLOCK) {
            Serial.printf("[BLE_INIT] refusing: internal=%u largest=%u (need >=%u/%u) - BLE unavailable\n",
                          (unsigned)freeInt, (unsigned)largest,
                          (unsigned)AH_BLE_MIN_INTERNAL, (unsigned)AH_BLE_MIN_BLOCK);
            bleInitFailed = true;
            bleInitDone = true;
            vTaskDelete(NULL);
            return;
        }
    }
    if (!BLEDevice::init("")) {
        Serial.println("[BLE_INIT] BLEDevice::init failed (controller alloc) - BLE unavailable");
        bleInitFailed = true;
        bleInitDone = true;
        vTaskDelete(NULL);
        return;
    }
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
    static std::atomic<bool> bleInitStarted{false};
    if (!bleInitStarted.exchange(true)) {
        TaskHandle_t h = nullptr;
        BaseType_t r = xTaskCreatePinnedToCore(
            bleInitTask, "ble_init", 8192, nullptr, 5, &h, 0);
        if (r != pdPASS) {
            Serial.println("[BLE_INIT] task create failed");
            bleInitFailed = true;
            bleInitDone = true;
            return;
        }
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
        macQueue = xQueueCreateWithCaps(queueSize, sizeof(Hit), AH_ISR_QUEUE_CAPS);
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

    // Stop BLE if active - do this BEFORE WiFi mode change
    if (pBLEScan && pBLEScan->isScanning()) {
        pBLEScan->stop();
        vTaskDelay(pdMS_TO_TICKS(100));
        pBLEScan->clearResults();
    }

    WiFi.mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(200));

    Serial.println("[RADIO] STA mode stopped");
}

// Start promiscuous/sniffer mode (for snifferScanTask)
void radioStartSTA() {
    Serial.println("[RADIO] Starting STA mode (promiscuous)");

    // Headless uses STA-only mode (no AP)
    WiFi.mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Configure STA for scanning
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    applyBandMode();

    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
    }

    // Start promiscuous on STA interface
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(reinterpret_cast<wifi_promiscuous_cb_t>(&sniffer_cb));
    esp_wifi_set_promiscuous(true);

    if (CHANNELS.empty()) CHANNELS = DEFAULT_CHANNELS;
    rebuildActiveChannels();
    esp_wifi_set_channel(g_activeChannels[0], WIFI_SECOND_CHAN_NONE);

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

    // Use STA mode (headless has no AP)
    WiFi.mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Configure country for scanning
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    applyBandMode();

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

    WiFi.mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    Serial.println("[RADIO] List scan mode stopped");
}


void releaseProbeQueue() {
    QueueHandle_t q = probeRequestQueue;
    if (q) { probeRequestQueue = nullptr; vQueueDeleteWithCaps(q); }
}

void releaseAuthFrameQueue() {
    QueueHandle_t q = authFrameQueue;
    if (q) { authFrameQueue = nullptr; vQueueDeleteWithCaps(q); }
}

void initializeScanner()
{
    WiFi.setScanTimeout(5000);

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

    // probe/auth queues (~32KB ISR-internal on C5) now lazy: allocated at scan start, freed at stop.
    if (!bleAdvQueue) {
        bleAdvQueue = xQueueCreateWithCaps(128, sizeof(BleAdvEvent), AH_ALLOC_CAPS);
        if (bleAdvQueue) {
            Serial.printf("[INIT] bleAdvQueue PSRAM (128 entries, internal:%u psram:%u)\n",
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        } else {
            Serial.println("[INIT] bleAdvQueue alloc failed at boot");
        }
    }
}

static void resetTriAccumulator(const uint8_t* mac) {
    triTargetChannel.store(0);
    triTargetRadio.store(0);
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
    triAccum.gpsSamples = 0;
    triAccum.bestHdop = 99.9f;
    triAccum.gpsRejects = 0;
    triAccum.hasGPS = false;
    triAccum.lastSendTime = 0;
    triAccum.lastSendSeq = 0;
}
static std::atomic<bool> triSelfDirty(false);

static void triUpsertSelfNode(const String& nodeId) {
    if (!triangulationActive.load() || nodeId.length() == 0) return;
    if (!triSelfDirty.exchange(false)) return;
    int hits = 0; int8_t rssi = 0; bool isBle = false;
    float lat = 0, lon = 0, hdop = 99.9f; bool hasGps = false;
    {
        std::lock_guard<std::mutex> lock(triAccumMutex);
        if (triAccum.wifiHitCount == 0 && triAccum.bleHitCount == 0) return;
        if (triAccum.wifiHitCount >= triAccum.bleHitCount) {
            hits = triAccum.wifiHitCount;
            rssi = (int8_t)(triAccum.wifiRssiSum / triAccum.wifiHitCount);
            isBle = false;
        } else {
            hits = triAccum.bleHitCount;
            rssi = (int8_t)(triAccum.bleRssiSum / triAccum.bleHitCount);
            isBle = true;
        }
        lat = triAccum.lat; lon = triAccum.lon; hdop = triAccum.hdop; hasGps = triAccum.hasGPS;
    }
    std::lock_guard<std::mutex> lock(triangulationMutex);
    auto it = std::find_if(triangulationNodes.begin(), triangulationNodes.end(),
        [&](const TriangulationNode& n) { return n.nodeId == nodeId; });
    if (it == triangulationNodes.end()) {
        if (triangulationNodes.size() >= MAX_TRIANGULATION_NODES) return;
        TriangulationNode n;
        n.nodeId = nodeId;
        initNodeKalmanFilter(n);
        triangulationNodes.push_back(n);
        it = triangulationNodes.end() - 1;
    }
    it->hitCount = hits;
    it->isBLE = isBle;
    updateNodeRSSI(*it, rssi);
    if (hasGps) { it->lat = lat; it->lon = lon; it->hdop = hdop; it->hasGPS = true; }
    it->lastUpdate = millis();
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

    // Fix dual-radio devices showing as both types in triangulation
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
        int64_t syncedUs = getCorrectedMicroseconds();
        uint32_t syncedMs = static_cast<uint32_t>(syncedUs / 1000LL);
        reportingSchedule.initializeCycle(syncedMs);
    }

    uint32_t now = millis();
    uint32_t minGap = reportingSchedule.selfGapMs();
    if (triAccum.lastSendTime != 0 && static_cast<uint32_t>(now - triAccum.lastSendTime) < minGap) return;

    if (triAccum.lastSendTime != 0 && reportingSchedule.nodeCount() > 1 &&
        reportingSchedule.peerSeq() == triAccum.lastSendSeq) {
        if (!reportingSchedule.lapElapsed(now)) {
            static uint32_t lastHoldLog = 0;
            if (now - lastHoldLog > 5000) {
                Serial.printf("[TRI-TURN] %s holding - no peer report received since my last send\n", nodeId.c_str());
                lastHoldLog = now;
            }
            return;
        }
        Serial.printf("[TRI-TURN] %s re-seeding ring - full lap with no peer report\n", nodeId.c_str());
    }

    String waitingOn;
    if (!reportingSchedule.isMyTurn(nodeId, now, waitingOn)) {
        static uint32_t lastLog = 0;
        if (waitingOn.length() && now - lastLog > 2000) {
            Serial.printf("[TRI-TURN] %s waiting for %s\n", nodeId.c_str(), waitingOn.c_str());
            lastLog = now;
        }
        return;
    }

    String macStr = macFmt6(triAccum.targetMac);
    bool sentAny = false;

    if (triAccum.wifiHitCount > 0) {
        int8_t wifiAvgRssi = static_cast<int8_t>(triAccum.wifiRssiSum / triAccum.wifiHitCount);
        String wifiMsg = nodeId + ": T_D: " + macStr +
                         " Hits=" + String(triAccum.wifiHitCount) +
                         " RSSI:" + String(wifiAvgRssi) + " Type:WiFi";
        if (triAccum.hasGPS) {
            wifiMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                       " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(wifiMsg, true)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId, false);
            Serial.printf("[TRI-SLOT] %s: WiFi sent (%d hits)\n", nodeId.c_str(), triAccum.wifiHitCount);
            delay(150);
        } else {
            Serial.printf("[TRI-SLOT] %s: WiFi DROPPED by rate limiter\n", nodeId.c_str());
        }
    }

    if (triAccum.bleHitCount > 0) {
        int8_t bleAvgRssi = static_cast<int8_t>(triAccum.bleRssiSum / triAccum.bleHitCount);
        String bleMsg = nodeId + ": T_D: " + macStr +
                        " Hits=" + String(triAccum.bleHitCount) +
                        " RSSI:" + String(bleAvgRssi) + " Type:BLE";
        if (triAccum.hasGPS) {
            bleMsg += " GPS=" + String(triAccum.lat, 6) + "," + String(triAccum.lon, 6) +
                      " HDOP=" + String(triAccum.hdop, 1);
        }
        if (sendToSerial1(bleMsg, true)) {
            sentAny = true;
            reportingSchedule.markReportReceived(nodeId, false);
            Serial.printf("[TRI-SLOT] %s: BLE sent (%d hits)\n", nodeId.c_str(), triAccum.bleHitCount);
            delay(150);
        } else {
            Serial.printf("[TRI-SLOT] %s: BLE DROPPED by rate limiter\n", nodeId.c_str());
        }
    }

    if (sentAny) {
        triAccum.lastSendTime = millis();
        triAccum.lastSendSeq = reportingSchedule.peerSeq();
        triSelfDirty.store(true);
        delay(150);
    }
}


// Scan tasks
void listScanTask(void *pv) {
    sentinel_kill();
    bool triMode = listScanTriMode.load();
    int secs = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int*>(pv)));
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
    // Do NOT clear lastResults here — that creates a race where tick() sees "None yet."
    lastScanStart = millis();
    lastScanSecs = secs;
    lastScanForever = forever;
    scanSetCountdown(secs, forever);

    if (triangulationInitiator) {
        String myNodeId = getNodeId();
        if (myNodeId.length() == 0) {
            myNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
        }

        // Check if initiator already exists (mutex protected)
        {
            std::lock_guard<std::mutex> lock(triangulationMutex);
            const bool selfNodeExists = std::any_of(triangulationNodes.begin(), triangulationNodes.end(),
                [&](const auto& n) { return n.nodeId == myNodeId; });
            if (selfNodeExists) {
                Serial.printf("[TRIANGULATE] Initiator already registered: %s\n", myNodeId.c_str());
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
        if (currentScanMode == SCAN_BOTH) {
            radioStartBLE();
            vTaskDelay(pdMS_TO_TICKS(300));
        }
        if (apInfoQueue == nullptr) {
            apInfoQueue = xQueueCreateWithCaps(128, sizeof(ApInfoEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        }
        if (apInfoQueue) xQueueReset(apInfoQueue);
        apCaptureEnabled = true;
        ScanMode savedMode = currentScanMode;
        currentScanMode = SCAN_WIFI;
        radioStartSTA();
        currentScanMode = savedMode;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (currentScanMode == SCAN_BLE) {
        radioStartBLE();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    std::map<String, uint32_t> localDeviceLastSeen;
    const uint32_t LOCAL_DEDUPE_WINDOW = 3000;
    uint32_t lastBLEScan = 0;
    uint32_t lastBLEScanTri = 0;
    Hit h;

    uint32_t nextTriResultsUpdate = millis() + 2000;
    size_t lastWrittenHitCount = SIZE_MAX;
    uint32_t lastTimeSyncBroadcast = 0;

    while ((forever && !stopRequested) ||
           (!forever && static_cast<int>(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {

        if (triangulationActive && triangulationInitiator &&
            (millis() - lastTimeSyncBroadcast) > 30000) {
            broadcastTimeSyncRequest();
            lastTimeSyncBroadcast = millis();
        }

        if (localDeviceLastSeen.size() > 512) {
            uint32_t nowSweep = millis();
            for (auto it = localDeviceLastSeen.begin(); it != localDeviceLastSeen.end(); ) {
                if (nowSweep - it->second >= LOCAL_DEDUPE_WINDOW) it = localDeviceLastSeen.erase(it);
                else ++it;
            }
        }

        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) && apInfoQueue) {
            ApInfoEvent ae;
            int apDrained = 0;
            while (xQueueReceive(apInfoQueue, &ae, 0) == pdTRUE && apDrained < 50) {
                apDrained++;
                bool isMatch;
                if (triMode) {
                    uint8_t tmac[6];
                    memcpy(tmac, ae.bssid, 6);
                    if (strlen(triangulationTargetIdentity) > 0)
                        isMatch = matchesIdentityMac(triangulationTargetIdentity, tmac);
                    else
                        isMatch = (memcmp(tmac, triangulationTarget, 6) == 0);
                } else {
                    isMatch = matchesMac(ae.bssid);
                    if (!isMatch && ae.ssid[0]) isMatch = matchesSsid(ae.ssid);
                }
                if (!isMatch) continue;
                Hit wh;
                memcpy(wh.mac, ae.bssid, 6);
                wh.rssi = ae.rssi;
                wh.ch = ae.channel;
                String ssid = ae.ssid[0] ? String(ae.ssid) : String("[Hidden]");
                strncpy(wh.name, ssid.c_str(), sizeof(wh.name) - 1);
                wh.name[sizeof(wh.name) - 1] = '\0';
                wh.isBLE = false;
                safeMacQueueSend(&wh, pdMS_TO_TICKS(10));
            }
        }

        extern void processUSBToMesh();
        processUSBToMesh();

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan &&
            !(triangulationActive.load() && triTargetRadio.load() == 2) &&
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

                if (uniqueMacs.size() < MAX_UNIQUE_MACS) uniqueMacs.insert(macStr);

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
                    localDeviceLastSeen[macStr] = now;
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

            if (seenTargets.insert(macStr).second) {
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
                    triUpsertSelfNode(myNodeId);
                    resetTriAccumulator(triangulationTarget);
                }

                if (memcmp(h.mac, triangulationTarget, 6) == 0) {
                    {
                        std::lock_guard<std::mutex> lock(triAccumMutex);

                        // Debug logging to track type mismatches
                        String triMacStr = macFmt6(h.mac);
                        Serial.printf("[TRI-HIT] MAC=%s Type=%s RSSI=%d CH=%d Name=%s\n",
                                     triMacStr.c_str(), h.isBLE ? "BLE" : "WiFi",
                                     h.rssi, h.ch, h.name);

                        if (h.isBLE && triAccum.wifiHitCount > 0 && triAccum.bleHitCount == 0) {
                            Serial.printf("[TRI-CONFLICT] WARNING: Device %s switching from WiFi to BLE! Ignoring BLE detection.\n",
                                         macStr.c_str());
                            goto skip_accumulation_headless;
                        }
                        if (!h.isBLE && triAccum.bleHitCount > 0 && triAccum.wifiHitCount == 0) {
                            Serial.printf("[TRI-CONFLICT] WARNING: Device %s switching from BLE to WiFi! Ignoring WiFi detection.\n",
                                         macStr.c_str());
                            goto skip_accumulation_headless;
                        }

                        if (!h.isBLE && h.ch >= 1 && h.ch <= 14 && triTargetChannel.load() != h.ch) {
                            triTargetChannel.store(h.ch);
                            Serial.printf("[TRI-CH] Target on channel %u - locking scan to it\n", h.ch);
                        }
                        if (triTargetRadio.load() == 0) {
                            triTargetRadio.store(h.isBLE ? 1 : 2);
                            Serial.printf("[TRI-RADIO] Target is %s - narrowing scan\n", h.isBLE ? "BLE" : "WiFi");
                        }

                        if (h.isBLE) {
                            triAccum.bleHitCount++;
                            triAccum.bleRssiSum += static_cast<float>(h.rssi);
                            if (h.rssi > triAccum.bleMaxRssi) triAccum.bleMaxRssi = h.rssi;
                            if (h.rssi < triAccum.bleMinRssi || triAccum.bleMinRssi == 0) triAccum.bleMinRssi = h.rssi;
                        } else {
                            triAccum.wifiHitCount++;
                            triAccum.wifiRssiSum += static_cast<float>(h.rssi);
                            if (h.rssi > triAccum.wifiMaxRssi) triAccum.wifiMaxRssi = h.rssi;
                            if (h.rssi < triAccum.wifiMinRssi || triAccum.wifiMinRssi == 0) triAccum.wifiMinRssi = h.rssi;
                        }

                        if (gpsValid) {
                            float sLat = 0.0f, sLon = 0.0f; bool got = false;
                            if (gpsMutex != nullptr && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                                sLat = gpsLat; sLon = gpsLon; got = true;
                                xSemaphoreGive(gpsMutex);
                            }
                            float sHdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.9f;
                            if (got && sHdop > 0.0f) {
                                if (!triAccum.hasGPS || triAccum.gpsSamples == 0) {
                                    triAccum.lat = sLat; triAccum.lon = sLon;
                                    triAccum.gpsSamples = 1;
                                    triAccum.bestHdop = sHdop;
                                    triAccum.gpsRejects = 0;
                                    triAccum.hdop = sHdop;
                                } else {
                                    bool bad = false;
                                    if (triAccum.gpsSamples >= GPS_MIN_SAMPLES_TO_JUDGE) {
                                        if (sHdop > triAccum.bestHdop * GPS_HDOP_REJECT_RATIO) bad = true;
                                        float dm = haversineDistance(triAccum.lat, triAccum.lon, sLat, sLon);
                                        if (dm > GPS_JUMP_REJECT_M) bad = true;
                                    }
                                    if (bad) {
                                        if (++triAccum.gpsRejects >= GPS_REJECT_RESET_COUNT) {
                                            triAccum.lat = sLat; triAccum.lon = sLon;
                                            triAccum.gpsSamples = 1;
                                            triAccum.bestHdop = sHdop;
                                            triAccum.gpsRejects = 0;
                                            triAccum.hdop = sHdop;
                                        }
                                    } else {
                                        triAccum.gpsRejects = 0;
                                        if (triAccum.gpsSamples < 65535) triAccum.gpsSamples++;
                                        float k = 1.0f / (float)triAccum.gpsSamples;
                                        triAccum.lat += (sLat - triAccum.lat) * k;
                                        triAccum.lon += (sLon - triAccum.lon) * k;
                                        if (sHdop < triAccum.bestHdop) triAccum.bestHdop = sHdop;
                                        triAccum.hdop = triAccum.bestHdop;
                                    }
                                }
                                triAccum.hasGPS = true;
                            }
                        }

                        skip_accumulation_headless:
                        (void)0;
                    }

                    if (triangulationInitiator) {
                        String triNodeId = getNodeId();
                        if (triNodeId.length() == 0) {
                            triNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
                        }

                        int8_t avgRssi;
                        int triTotalHits;
                        bool isBLE;
                        float lat, lon, hdop;
                        bool hasGPS;

                        {
                            std::lock_guard<std::mutex> lock(triAccumMutex);
                            if (triAccum.wifiHitCount > 0) {
                                avgRssi = static_cast<int8_t>(triAccum.wifiRssiSum / triAccum.wifiHitCount);
                                triTotalHits = triAccum.wifiHitCount;
                                isBLE = false;
                            } else if (triAccum.bleHitCount > 0) {
                                avgRssi = static_cast<int8_t>(triAccum.bleRssiSum / triAccum.bleHitCount);
                                triTotalHits = triAccum.bleHitCount;
                                isBLE = true;
                            } else {
                                continue;
                            }

                            lat = triAccum.lat;
                            lon = triAccum.lon;
                            hdop = triAccum.hdop;
                            hasGPS = triAccum.hasGPS;
                        }

                        {
                            std::lock_guard<std::mutex> lock(triangulationMutex);
                            auto selfNodeIt = std::find_if(triangulationNodes.begin(), triangulationNodes.end(),
                                [&](const auto& n) { return n.nodeId == triNodeId; });
                            const bool selfNodeFound = (selfNodeIt != triangulationNodes.end());
                            if (selfNodeFound) {
                                auto &node = *selfNodeIt;
                                updateNodeRSSI(node, avgRssi);
                                node.hitCount = triTotalHits;
                                node.isBLE = isBLE;
                                if (hasGPS) {
                                    node.lat = lat;
                                    node.lon = lon;
                                    node.hdop = hdop;
                                    node.hasGPS = true;
                                }
                                node.distanceEstimate = rssiToDistance(node, !node.isBLE);
                                node.lastUpdate = millis();
                            }

                            if (!selfNodeFound) {
                                TriangulationNode selfNode;
                                selfNode.nodeId = triNodeId;
                                selfNode.lat = hasGPS ? lat : 0.0;
                                selfNode.lon = hasGPS ? lon : 0.0;
                                selfNode.hdop = hasGPS ? hdop : 99.9;
                                selfNode.rssi = avgRssi;
                                selfNode.hitCount = triTotalHits;
                                selfNode.hasGPS = hasGPS;
                                selfNode.isBLE = isBLE;
                                selfNode.lastUpdate = millis();

                                initNodeKalmanFilter(selfNode);
                                updateNodeRSSI(selfNode, avgRssi);
                                selfNode.distanceEstimate = rssiToDistance(selfNode, !selfNode.isBLE);

                                triangulationNodes.push_back(selfNode);

                                Serial.printf("[TRIANGULATE SELF] Added: hits=%d avgRSSI=%d Type=%s dist=%.1fm GPS=%s\n",
                                            triTotalHits, avgRssi,
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
        if (triangulationActive && !stopRequested && (static_cast<int32_t>(millis() - nextTriResultsUpdate) >= 0 || hitsLog.size() != lastWrittenHitCount)) {
            Serial.println("[SCAN] Updating IN PROGRESS triangulation results");
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

                std::string results = "\n=== Triangulation Results (IN PROGRESS) ===\n";
                results += "Target MAC: " + std::string(macFmt6(triangulationTarget).c_str()) + "\n";
                results += "Duration: " + std::to_string(triangulationDuration) + "s\n";
                results += "Elapsed: " + std::to_string((millis() - triangulationStart) / 1000) + "s\n";
                results += "Reporting Nodes: " + std::to_string(triangulationNodes.size()) + "\n";

                std::vector<TriangulationNode> liveGps;
                for (const auto& n : triangulationNodes) if (n.hasGPS) liveGps.push_back(n);
                if (liveGps.size() >= 3) {
                    float lat = 0, lon = 0, conf = 0;
                    if (performWeightedTrilateration(liveGps, lat, lon, conf) && conf > 0.0f) {
                        char buf[128];
                        snprintf(buf, sizeof(buf), "Estimate: %.6f,%.6f CONF=%.1f%%\n",
                                 lat, lon, conf * 100.0f);
                        results += buf;
                    }
                }
                results += "\n--- Node Reports ---\n";

                for (const auto& node : triangulationNodes) {
                    results += std::string(node.nodeId.c_str()) + ": ";
                    results += "RSSI=" + std::to_string(static_cast<int>(node.filteredRssi)) + "dBm ";
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
            lastWrittenHitCount = hitsLog.size();
        }

        if (triangulationActive && !stopRequested) {
            static uint32_t nextTriReportCheck = 0;
            if (static_cast<int32_t>(millis() - nextTriReportCheck) >= 0) {
                String myNodeId = getNodeId();
                if (myNodeId.length() == 0) {
                    myNodeId = "NODE_" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
                }
                sendTriAccumulatedData(myNodeId);
                triUpsertSelfNode(myNodeId);
                nextTriReportCheck = millis() + 250;
            }
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            if (millis() - lastBLEScanTri >= 3000) {
                NimBLEScanResults scanResults = pBLEScan->getResults(1000, false);
                pBLEScan->clearResults();
                lastBLEScanTri = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(150));
    }

    // Build final results BEFORE setting scanning=false to prevent race
    // where tick() sees scanning=false but final results aren't written yet
    std::string results =
        "List scan - Mode: " + std::string(modeStr.c_str()) +
        " Duration: " + (forever ? std::string("Forever\n") : (std::to_string(secs) + "s\n")) +
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
            { const char *hv = lookupOuiVendor(e.mac); if (hv) results += std::string(" V=") + hv; }
            results += "\n";
        }
        if (static_cast<int>(sortedHits.size()) > show) {
            results += "... (" + std::to_string(sortedHits.size() - show) + " more)\n";
        }
    }

    // Write final results while still scanning so tick() picks them up
    if (!triangulationActive) {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        bool hasTriangulation = (antihunter::lastResults.find("=== Triangulation Results ===") != std::string::npos);

        size_t triNodeCount;
        { std::lock_guard<std::mutex> tl(triangulationMutex); triNodeCount = triangulationNodes.size(); }

        if (hasTriangulation) {
            antihunter::lastResults = results + "\n\n" + antihunter::lastResults;
        } else if (triNodeCount > 0) {
            antihunter::lastResults = antihunter::lastResults + "\n\n=== List Scan Results ===\n" + results;
        } else {
            antihunter::lastResults = results;
        }

        Serial.printf("[SCAN] List results stored: %d chars\n", results.length());
    } else {
        Serial.println("[SCAN] Skipping list results - triangulation active (stopTriangulation() owns final results)");
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
            uint32_t maxPropDelay = 0;
            {
                std::lock_guard<std::mutex> tl(triangulationMutex);
                auto maxIt = std::max_element(nodePropagationDelays.begin(), nodePropagationDelays.end(),
                    [](const std::pair<const String, uint32_t>& a, const std::pair<const String, uint32_t>& b) {
                        uint32_t va = (a.second < 1000000) ? a.second : 0;
                        uint32_t vb = (b.second < 1000000) ? b.second : 0;
                        return va < vb;
                    });
                maxPropDelay = (maxIt != nodePropagationDelays.end() && maxIt->second < 1000000)
                                        ? maxIt->second : 0;
            }
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
    
    apCaptureEnabled = false;
    radioStopSTA();
    vTaskDelay(pdMS_TO_TICKS(500));

    safeMacQueueDelete();

    seenTargets.clear();
    transmittedDevices.clear();
    localDeviceLastSeen.clear();

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
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

void saveAllowlist(const String &txt)
{
    prefs.putString("allowlist", txt);
    std::lock_guard<std::mutex> lock(allowlistMutex);
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
    std::lock_guard<std::mutex> lock(allowlistMutex);
    return std::any_of(allowlist.begin(), allowlist.end(),
        [&](const auto& w) {
            if (w.len == 6) return memcmp(w.bytes, mac, 6) == 0;
            if (w.len == 3) return memcmp(w.bytes, mac, 3) == 0;
            return false;
        });
}
