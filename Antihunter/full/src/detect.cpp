#include "detect.h"
#include "hardware.h"
#include "network.h"
#include "scanner.h"
#include "baseline.h"
#include "drone_detector.h"
#include "main.h"
#include "triangulation.h"
#include <SD.h>
#include <LittleFS.h>
#include <esp_timer.h>
#include <esp_attr.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <driver/gpio.h>
#include <math.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <algorithm>
#include <deque>

extern std::atomic<bool> g_detectVerbose;

namespace ah_detect {

static uint8_t g_selfApMac[6] = {0};
static bool g_selfApMacValid = false;
static char g_selfApSsid[33] = {0};

static inline bool isSelfMac(const uint8_t *m) {
    if (!g_selfApMacValid || !m) return false;
    return memcmp(m, g_selfApMac, 6) == 0;
}

static inline bool isSelfSsid(const char *ssid) {
    if (!g_selfApSsid[0] || !ssid) return false;
    return strncmp(ssid, g_selfApSsid, sizeof(g_selfApSsid)) == 0;
}

void detect_setSelfApIdentity(const uint8_t mac[6], const char *ssid) {
    if (mac) {
        memcpy(g_selfApMac, mac, 6);
        g_selfApMacValid = true;
    }
    if (ssid) {
        strncpy(g_selfApSsid, ssid, sizeof(g_selfApSsid) - 1);
        g_selfApSsid[sizeof(g_selfApSsid) - 1] = 0;
    }
}

static uint32_t trackerTryLinkRotation(const uint8_t *addr, const char *vendor, int8_t rssi, uint32_t now);
static void trackerSweepVanished(uint32_t now);
static void airtagProcess(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len);
static uint8_t classifyEapolMsg(uint16_t keyInfo);
static void hshkRecord(const uint8_t *bssid, const uint8_t *sta, uint8_t msgNum,
                       uint64_t replayCtr, int8_t rssi, const char *nodeId, uint32_t now);
static void persistSnapshot();
static void loadSnapshot();
static bool meshRateGate(const String &type, uint32_t minIntervalMs);
void attacker_kick(const uint8_t *mac, const char *attackType);
static bool isPwnagotchiBeacon(const uint8_t *frame, uint16_t len);
static void pwnagotchiObserve(const uint8_t *bssid, int8_t rssi,
                              const uint8_t *ie, uint16_t ieLen);
void karma_observeProbeResp(const uint8_t *bssid, const char *ssid, int8_t rssi);
bool karma_checkBaitMatch(const char *ssid, const uint8_t *bssid, int8_t rssi);
static void tsfObserve(const uint8_t *bssid, uint64_t tsf, uint16_t beaconInterval,
                       const char *ssid, uint32_t now);

// =============================================================================
// State
// =============================================================================

std::atomic<bool> g_detectEnabled{true};

// Tunables
std::atomic<uint16_t> g_pmkidWindow{10000};
std::atomic<uint8_t>  g_pmkidMinBssids{3};
std::atomic<uint16_t> g_saeWindow{5000};
std::atomic<uint8_t>  g_saeUnmatchedThresh{10};
std::atomic<uint16_t> g_beaconDriftPermil{50};
std::atomic<uint32_t> g_trackerWindowMs{4UL * 3600UL * 1000UL};
std::atomic<uint32_t> g_trackerGapMs{30UL * 60UL * 1000UL};
std::atomic<uint8_t>  g_trackerMinSightings{3};

// Frame queue (from sniffer_cb)
QueueHandle_t g_detectFrameQueue = nullptr;

// Mutex
std::recursive_mutex g_mtx;

// PMKID burst tracking — per src MAC, list of (bssid, ts)
struct PmkidBurst {
    std::map<uint64_t, uint32_t> bssidTs; // packed bssid -> ts
    uint32_t lastSeen;
};
std::map<uint64_t, PmkidBurst> g_pmkidBursts;
std::vector<PmkidHarvestEvent> g_pmkidLog;

// Evil-twin baseline (per BSSID)
struct ApBaseline {
    uint64_t lastTSF;
    uint32_t lastTSFSampleMs;
    uint16_t beaconInterval;
    uint32_t ieHash;
    char ssid[33];
    uint8_t channel;
    int8_t rssi;
    bool hasOweTransition;
    uint8_t oweTransitionBssid[6];
    bool isOpen;
    uint32_t lastSeen;
    char respSsid[33];
    uint32_t lastEvilEmitMs;
    uint8_t tsfViolStreak;
    uint32_t tsfViolWindowMs;
};
std::map<uint64_t, ApBaseline> g_apBaseline;
std::vector<EvilTwinEvent> g_evilTwinLog;
std::vector<SsidConfusionEvent> g_ssidConfusionLog;
std::vector<OweAbuseEvent> g_oweAbuseLog;

// SAE tracking
struct SaeCounter {
    uint16_t commits;
    uint16_t confirms;
    uint32_t windowStart;
    bool alerted;
};
std::map<uint64_t, SaeCounter> g_saeCounters;
std::vector<SaeDosEvent> g_saeDosLog;

// Auth-frame flood (mdk4 mode a / Auth-DoS): open-system Auth (algo=0) flooded
// to one BSSID from many spoofed src MACs, none completing association.
// docs/detector-verification.md section 1. Always-on (like deauth), no toggle.
struct AuthFloodWindow {
    uint32_t windowStartMs;
    uint16_t frames;
    std::set<uint64_t> distinctSrc;
    int8_t   bestRssi;
    uint8_t  channel;
    bool     alerted;
};
std::map<uint64_t, AuthFloodWindow> g_authFlood;
static constexpr size_t   MAX_AUTH_FLOOD_MAP = 32;
static constexpr uint32_t AUTH_FLOOD_WIN_MS  = 5000;
static constexpr uint16_t AUTH_FLOOD_DISTINCT_SRC = 16;  // spoofed-MAC fan-out
static constexpr uint16_t AUTH_FLOOD_FRAMES  = 60;        // raw rate floor in window

// FragAttacks PN tracking — key = (srcMac<<8 | tid)
struct PnState {
    uint32_t lastPN;
    uint32_t lastSeen;
    uint8_t  reuseCount;
};
std::map<uint64_t, PnState> g_pnState;
std::vector<FragAttackEvent> g_fragLog;
std::atomic<bool>    g_fragEnabled{false};
std::atomic<uint8_t> g_fragReuseThresh{8};

// Per-feature enable (local detection on/off)
std::atomic<bool> g_karmaEnabled{false};
std::atomic<bool> g_pmkidEnabled{true};
std::atomic<bool> g_eviltwinEnabled{true};
std::atomic<bool> g_ssidConfusionEnabled{false};
std::atomic<bool> g_saeEnabled{false};
std::atomic<bool> g_sentinelScanMode{false};
std::atomic<bool> g_oweEnabled{false};
std::atomic<bool> g_bleMalformedEnabled{false};
std::atomic<bool> g_hshkEnabled{false};
std::atomic<bool> g_pwnaEnabled{false};
std::atomic<bool> g_trackerEnabled{false};
std::atomic<bool> g_airtagEnabled{false};
std::atomic<bool> g_tsfEnabled{false};
std::atomic<bool> g_ridSpoofEnabled{false};
std::atomic<bool> g_bloomGossipEnabled{false};
std::atomic<bool> g_attackerTrilatEnabled{false};

// Per-feature mesh broadcast (separate from local detection)
std::atomic<bool> g_meshPmkid{true};
std::atomic<bool> g_meshEviltwin{true};
std::atomic<bool> g_meshSsidConf{true};
std::atomic<bool> g_meshSae{true};
std::atomic<bool> g_meshFrag{false};
std::atomic<bool> g_meshBleMalformed{false};
std::atomic<bool> g_meshHshk{false};
std::atomic<bool> g_meshKrack{true};
std::atomic<bool> g_meshTracker{true};
std::atomic<bool> g_meshPwna{true};
std::atomic<bool> g_meshKarma{true};
std::atomic<bool> g_meshRecon{true};
std::atomic<bool> g_meshCsiMotion{false};
std::atomic<bool> g_meshAttackerHunt{true};

// BLE malformed
std::vector<BleMalformedEvent> g_bleMalformedLog;

// BLE tracker
std::map<uint64_t, BleTrackerSighting> g_bleTrackers;

// Recon
std::map<String, ReconAlert> g_recon;

// RID claims (mesh-cooperative validation)
std::map<String, RidClaim> g_ridClaims;  // key = uavId

// Quorum
std::map<String, AlertCandidate> g_alerts;  // key = type+":"+key
std::map<String, uint8_t> g_quorumRequired;

// Bloom — local + neighbor union
BloomFilter g_localBloom;
BloomFilter g_neighborBloom;
uint32_t g_lastBloomGossip = 0;

// PPS
volatile uint64_t g_ppsAnchorMicros = 0;
volatile uint32_t g_ppsAnchorEpoch = 0;
volatile uint32_t g_ppsLastEdge = 0;
std::atomic<bool> g_ppsLocked{false};

// Channel partition (per-node assigned set; coordinator drives via mesh)
std::vector<uint8_t> g_myChannels;
std::map<String, std::vector<uint8_t>> g_chanAssignments;

// OUI category table
struct OuiTableEntry {
    uint8_t oui[3];
    uint8_t cat;
} __attribute__((packed));
std::vector<OuiTableEntry> g_ouiTable;

// Log caps
static constexpr size_t MAX_PMKID_LOG = 100;
static constexpr size_t MAX_ET_LOG = 100;
static constexpr size_t MAX_SC_LOG = 100;
static constexpr size_t MAX_SAE_LOG = 100;
static constexpr size_t MAX_OWE_LOG = 50;
static constexpr size_t MAX_FRAG_LOG = 100;
static constexpr size_t MAX_BLEM_LOG = 100;
static constexpr size_t MAX_TRACKER_MAP = 200;

// =============================================================================
// Helpers
// =============================================================================

static inline uint64_t packMac(const uint8_t *m) {
    return ((uint64_t)m[0]<<40) | ((uint64_t)m[1]<<32) | ((uint64_t)m[2]<<24) |
           ((uint64_t)m[3]<<16) | ((uint64_t)m[4]<<8)  |  (uint64_t)m[5];
}
static inline void unpackMac(uint64_t v, uint8_t *m) {
    m[0]=(v>>40)&0xFF; m[1]=(v>>32)&0xFF; m[2]=(v>>24)&0xFF;
    m[3]=(v>>16)&0xFF; m[4]=(v>>8)&0xFF;  m[5]= v      &0xFF;
}
static inline String macStr(const uint8_t *m) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0],m[1],m[2],m[3],m[4],m[5]);
    return String(buf);
}

static std::map<String, uint32_t> g_meshRateMap;
static std::atomic<uint32_t> g_droppedWifi{0};
static std::atomic<uint32_t> g_droppedBle{0};
static std::atomic<uint32_t> g_droppedCsi{0};
static std::atomic<uint32_t> g_meshGated{0};
static bool meshRateGate(const String &type, uint32_t minIntervalMs) {
    uint32_t now = millis();
    auto it = g_meshRateMap.find(type);
    if (it != g_meshRateMap.end() && (now - it->second) < minIntervalMs) {
        g_meshGated.fetch_add(1);
        return false;
    }
    g_meshRateMap[type] = now;
    if (g_meshRateMap.size() > 256) {
        String oldestK;
        uint32_t oldestT = UINT32_MAX;
        for (auto &kv : g_meshRateMap) if (kv.second < oldestT) { oldestT = kv.second; oldestK = kv.first; }
        g_meshRateMap.erase(oldestK);
    }
    return true;
}

static String tsHuman(uint32_t ms) {
    if (rtcAvailable) {
        time_t e = getRTCEpoch();
        return String((unsigned long)e);
    }
    return String(ms);
}

// FNV-1a 32-bit
static uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) { h ^= data[i]; h *= 16777619u; }
    return h;
}

// IE hash — concatenate (tag, len) pairs (skip value where length variable like SSID/TIM)
// Captures IE order + presence; tolerates value churn that doesn't indicate spoof.
static uint32_t hashIeSet(const uint8_t *ie, uint16_t ieLen) {
    uint32_t h = 0x811C9DC5;
    uint16_t off = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ie[off];
        uint8_t len = ie[off+1];
        if (off + 2 + len > ieLen) break;
        h ^= tag; h *= 16777619u;
        // For stable IEs (RSN, HT cap, VHT cap, Ext cap, Vendor) include value too
        if (tag == 48 || tag == 45 || tag == 191 || tag == 127 || tag == 221) {
            for (uint8_t i = 0; i < len; ++i) { h ^= ie[off+2+i]; h *= 16777619u; }
        }
        off += 2 + len;
    }
    return h;
}

static bool extractSSID(const uint8_t *ie, uint16_t ieLen, char *out, size_t outSz) {
    uint16_t off = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ie[off];
        uint8_t len = ie[off+1];
        if (off + 2 + len > ieLen) break;
        if (tag == 0) {
            size_t n = std::min<size_t>(len, outSz - 1);
            memcpy(out, ie + off + 2, n);
            out[n] = 0;
            for (size_t i = 0; i < n; ++i) {
                if ((uint8_t)out[i] < 32 || (uint8_t)out[i] > 126) out[i] = '?';
            }
            return true;
        }
        off += 2 + len;
    }
    out[0] = 0;
    return false;
}

static bool hasOpenAuth(const uint8_t *ie, uint16_t ieLen) {
    // Open if no RSN (48) and no WPA vendor IE (221 with WPA OUI 00:50:F2 type 1)
    uint16_t off = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ie[off];
        uint8_t len = ie[off+1];
        if (off + 2 + len > ieLen) break;
        if (tag == 48) return false;
        if (tag == 221 && len >= 4 &&
            ie[off+2] == 0x00 && ie[off+3] == 0x50 && ie[off+4] == 0xF2 && ie[off+5] == 0x01) {
            return false;
        }
        off += 2 + len;
    }
    return true;
}

// OWE Transition Mode element: vendor IE OUI 50:6F:9A type 0x1C
static bool extractOweTransition(const uint8_t *ie, uint16_t ieLen, uint8_t *outBssid) {
    uint16_t off = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ie[off];
        uint8_t len = ie[off+1];
        if (off + 2 + len > ieLen) break;
        if (tag == 221 && len >= 10 &&
            ie[off+2] == 0x50 && ie[off+3] == 0x6F && ie[off+4] == 0x9A &&
            ie[off+5] == 0x1C) {
            memcpy(outBssid, ie + off + 6, 6);
            return true;
        }
        off += 2 + len;
    }
    return false;
}

// BloomFilter impl moved outside ah_detect namespace (defined below namespace block)

// =============================================================================
// PPS — GPS pulse-per-second time discipline
// =============================================================================
static int g_ppsGpio = -1;

static void IRAM_ATTR pps_isr(void *) {
    uint64_t now = esp_timer_get_time();  // µs since boot
    g_ppsAnchorMicros = now;
    g_ppsLastEdge = (uint32_t)now;
    // Epoch update happens in detectTask polling getRTCEpoch (avoid I2C from ISR)
}

void initGpsPps(int gpio) {
    if (gpio < 0) return;
    g_ppsGpio = gpio;
    gpio_config_t cfg = {};
    cfg.pin_bit_mask = (1ULL << gpio);
    cfg.mode = GPIO_MODE_INPUT;
    cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_ENABLE;
    cfg.intr_type = GPIO_INTR_POSEDGE;
    gpio_config(&cfg);
    // ISR service is installed earlier by the SD SPI driver and/or Arduino attachInterrupt.
    // Try adding the handler directly; only install if not yet installed (ESP_ERR_INVALID_STATE).
    esp_err_t err = gpio_isr_handler_add((gpio_num_t)gpio, pps_isr, nullptr);
    if (err == ESP_ERR_INVALID_STATE) {
        if (gpio_install_isr_service(0) == ESP_OK) {
            err = gpio_isr_handler_add((gpio_num_t)gpio, pps_isr, nullptr);
        }
    }
    if (err != ESP_OK) {
        Serial.printf("[PPS] handler_add failed: %s\n", esp_err_to_name(err));
        return;
    }
    Serial.printf("[PPS] Armed on GPIO %d\n", gpio);
}

uint64_t getDisciplinedMicros() {
    uint64_t bootMicros = esp_timer_get_time();
    static portMUX_TYPE ppsMux = portMUX_INITIALIZER_UNLOCKED;
    uint32_t epoch;
    uint64_t anchor;
    portENTER_CRITICAL(&ppsMux);
    epoch = g_ppsAnchorEpoch;
    anchor = g_ppsAnchorMicros;
    portEXIT_CRITICAL(&ppsMux);
    if (epoch == 0 || anchor == 0) {
        time_t e = getRTCEpoch();
        return (uint64_t)e * 1000000ULL;
    }
    return ((uint64_t)epoch * 1000000ULL) + (bootMicros - anchor);
}

// =============================================================================
// EAPOL capture-bait witness store
// =============================================================================
// Tracks recent unicast deauths (src, dst, ts). When EAPOL traffic from dst
// appears within EAPOL_BAIT_WINDOW_MS, the src is flagged as a capture-bait
// attacker. tool capture_handshake() emits one targeted deauth to force a
// re-association so it can sniff EAPOL.
struct DeauthWitness {
    uint8_t src[6];
    uint8_t dst[6];
    uint32_t ts;
    int8_t rssi;
    uint8_t channel;
    uint8_t deauthCount;  // increments on repeat from same src
    bool alerted;
};
static std::vector<DeauthWitness> g_deauthWitness;
static constexpr size_t MAX_DEAUTH_WITNESS = 32;
static constexpr uint32_t EAPOL_BAIT_WINDOW_MS = 30000;

void detect_correlateEapolBait(const uint8_t *sta, int8_t rssi, uint8_t channel);

void detect_witnessDeauth(const uint8_t *src, const uint8_t *dst, int8_t rssi, uint8_t channel) {
    if (!src || !dst) return;
    if (dst[0] & 0x01) return;  // broadcast/multicast — not bait
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    // Age out + look for existing entry from same src
    for (auto it = g_deauthWitness.begin(); it != g_deauthWitness.end(); ) {
        if (now - it->ts > EAPOL_BAIT_WINDOW_MS) { it = g_deauthWitness.erase(it); continue; }
        if (memcmp(it->src, src, 6) == 0 && memcmp(it->dst, dst, 6) == 0) {
            it->ts = now;
            if (it->deauthCount < 255) it->deauthCount++;
            return;
        }
        ++it;
    }
    if (g_deauthWitness.size() >= MAX_DEAUTH_WITNESS) {
        // evict oldest
        size_t oldestIdx = 0; uint32_t oldestTs = UINT32_MAX;
        for (size_t i = 0; i < g_deauthWitness.size(); ++i) {
            if (g_deauthWitness[i].ts < oldestTs) { oldestTs = g_deauthWitness[i].ts; oldestIdx = i; }
        }
        g_deauthWitness.erase(g_deauthWitness.begin() + oldestIdx);
    }
    DeauthWitness w{};
    memcpy(w.src, src, 6);
    memcpy(w.dst, dst, 6);
    w.ts = now;
    w.rssi = rssi;
    w.channel = channel;
    w.deauthCount = 1;
    w.alerted = false;
    g_deauthWitness.push_back(w);
}

void detect_correlateEapolBait(const uint8_t *sta, int8_t rssi, uint8_t channel) {
    if (!sta) return;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (auto &w : g_deauthWitness) {
        if (now - w.ts > EAPOL_BAIT_WINDOW_MS) continue;
        if (memcmp(w.dst, sta, 6) != 0) continue;
        // Bait pattern: 1-3 deauths total from src X to STA Y, then EAPOL from Y.
        // >3 deauths = ongoing DoS attack, not bait sniff.
        if (w.deauthCount > 3) continue;
        if (w.alerted) continue;
        w.alerted = true;
        uint32_t latencyMs = now - w.ts;
        // Confidence tier (research-based):
        //   ≤5s deauth→EAPOL = HIGH confidence (legit re-association takes 1-6s
        //     usually preceded by AP beacon traffic; attacker bait <1s typical)
        //   ≤30s = MEDIUM confidence (could be slow roam or genuine bait)
        const char *confidence = (latencyMs <= 2000) ? "high" : "medium";
        char srcBuf[18], dstBuf[18];
        snprintf(srcBuf, sizeof(srcBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 w.src[0],w.src[1],w.src[2],w.src[3],w.src[4],w.src[5]);
        snprintf(dstBuf, sizeof(dstBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 w.dst[0],w.dst[1],w.dst[2],w.dst[3],w.dst[4],w.dst[5]);
        String srcS(srcBuf);
        String dstS(dstBuf);
        char lineBuf[320];
        snprintf(lineBuf, sizeof(lineBuf),
                 "{\"src\":\"%s\",\"sta\":\"%s\",\"deauth_count\":%u,\"latency_ms\":%u,\"confidence\":\"%s\",\"rssi\":%d,\"ch\":%u,\"reason\":\"EAPOL_CAPTURE_BAIT\",\"ts\":%u}",
                 srcBuf, dstBuf, (unsigned)w.deauthCount, (unsigned)latencyMs,
                 confidence, (int)rssi, (unsigned)channel, (unsigned)now);
        String line(lineBuf);
        logEventToSD("/eapol_bait.jsonl", line);
        if (meshEnabled && meshRateGate("EAPOL_BAIT_" + srcS + "_" + dstS, 60000)) {
            sendToSerial1(getNodeId() + ": EAPOL_BAIT:" + srcS + ":" + dstS +
                          ":" + String(w.deauthCount) + ":" + String(rssi) +
                          ":" + confidence, true);
        }
        quorum_addReport("EAPOL_BAIT", srcS, getNodeId(), rssi);
        // Only fire attacker-trilateration on HIGH confidence to avoid kicking
        // legit gear that did a normal deauth+reconnect.
        if (latencyMs <= 2000) attacker_kick(w.src, "EAPOL_BAIT");
        return;
    }
}

// PMKID detection
// =============================================================================
// EAPOL-Key in 802.11: data frame ftype=2, LLC/SNAP DSAP=0xAA SSAP=0xAA ctrl=0x03,
// OUI 00:00:00, Ethertype 0x88 0x8E. Key descriptor starts after.
// PMKID-request M1 has: key_info: pairwise=1, ack=1, install=0, mic=0; key_data has
// PMKID KDE (00:0F:AC, type 4) or is broadcast-induced.
// We detect: EAPOL-Key from src targeting >=N distinct BSSIDs within window.

static void handleEAPOL(const DetectFrameEvent &e) {
    if (!g_hshkEnabled.load() && !g_pmkidEnabled.load()) return;
    if (e.len < 34) return;
    int eapolOff = -1;
    int searchEnd = (int)e.len - 8;
    for (int i = 24; i < searchEnd; ++i) {
        if (e.payload[i] == 0xAA && e.payload[i+1] == 0xAA && e.payload[i+2] == 0x03 &&
            e.payload[i+3] == 0x00 && e.payload[i+4] == 0x00 && e.payload[i+5] == 0x00 &&
            e.payload[i+6] == 0x88 && e.payload[i+7] == 0x8E) {
            eapolOff = i + 8;
            break;
        }
    }
    if (eapolOff < 0 || eapolOff + 16 >= (int)e.len) return;
    if (e.payload[eapolOff + 1] != 0x03) return;
    uint16_t keyInfo = ((uint16_t)e.payload[eapolOff + 5] << 8) | e.payload[eapolOff + 6];
    uint8_t msgNum = classifyEapolMsg(keyInfo);

    // EAPOL capture-bait correlation: if an EAPOL handshake frame is observed
    // from a STA that was recently (≤30s) the unicast target of a deauth from
    // some src X, and X has stayed silent (no follow-up frames), that's the
    // classic "knock-the-client-off and sniff re-association" pattern tool
    // uses in its handshake/PMKID capture mode.
    {
        const uint8_t *sta = e.payload + 10;  // tentative — refined below by FC
        // Re-compute correct STA addr from FC ToDS/FromDS (matches earlier logic).
        uint16_t fcCheck = (uint16_t)e.payload[0] | ((uint16_t)e.payload[1] << 8);
        uint8_t toDsX   = (fcCheck >> 8) & 1;
        uint8_t fromDsX = (fcCheck >> 9) & 1;
        const uint8_t *a1X = e.payload + 4;
        const uint8_t *a2X = e.payload + 10;
        if (toDsX == 1 && fromDsX == 0) sta = a2X;       // STA → AP: STA is src
        else if (toDsX == 0 && fromDsX == 1) sta = a1X;  // AP → STA: STA is dst
        // else use default a2X
        detect_correlateEapolBait(sta, e.rssi, e.channel);
    }

    // tool EAPOL bad-msg1 / forged PMKID — WiFiScan.cpp lines 7889-7939.
    // Body uses a FIXED 16-byte PMKID: 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 11
    // preceded by PMKID KDE: DD 14 00 0F AC 04. Combined with Key Info 0x00CA (WPA2)
    // or 0x00CB (WPA3), this is unambiguous.
    if (g_pmkidEnabled.load() && (keyInfo == 0x00CA || keyInfo == 0x00CB)) {
        static const uint8_t FORGE_PMKID_TEMPLATE[16] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11
        };
        static const uint8_t PMKID_KDE_HDR[6] = {0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04};
        const uint8_t *body = e.payload + eapolOff;
        int bodyLen = (int)e.len - eapolOff;
        bool sigHit = false;
        // Scan for `DD 14 00 0F AC 04` + 16 bytes matching FORGE_PMKID_TEMPLATE
        for (int i = 0; i + (int)sizeof(PMKID_KDE_HDR) + 16 <= bodyLen; ++i) {
            if (memcmp(body + i, PMKID_KDE_HDR, sizeof(PMKID_KDE_HDR)) != 0) continue;
            if (memcmp(body + i + sizeof(PMKID_KDE_HDR), FORGE_PMKID_TEMPLATE, 16) == 0) {
                sigHit = true;
                break;
            }
        }
        if (sigHit) {
            const uint8_t *src = e.payload + 10;
            const uint8_t *bss = e.payload + 4;  // dst in M1-from-AP path is STA, BSSID = src
            char srBuf[18], bsBuf[18];
            snprintf(srBuf, sizeof(srBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     src[0],src[1],src[2],src[3],src[4],src[5]);
            snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     bss[0],bss[1],bss[2],bss[3],bss[4],bss[5]);
            String sr(srBuf);
            String bs(bsBuf);
            char lineBuf[260];
            snprintf(lineBuf, sizeof(lineBuf),
                     "{\"src\":\"%s\",\"sta\":\"%s\",\"keyinfo\":\"0x%04X\",\"reason\":\"FORGE_PMKID\",\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                     srBuf, bsBuf, (unsigned)keyInfo, (int)e.rssi, (unsigned)e.channel, (unsigned)millis());
            logEventToSD("/pmkid_forge.jsonl", String(lineBuf));
            if (meshEnabled && meshRateGate(String("PMKID_FORGE_") + sr, 30000)) {
                char meshBuf[80];
                snprintf(meshBuf, sizeof(meshBuf), "%s: PMKID_FORGE:%s:%s:%d",
                         getNodeId().c_str(), srBuf, bsBuf, (int)e.rssi);
                sendToSerial1(String(meshBuf), true);
            }
            quorum_addReport("PMKID_FORGE", sr, getNodeId(), e.rssi);
            attacker_kick(src, "PMKID_FORGE");
        }
    }

    uint16_t fc = (uint16_t)e.payload[0] | ((uint16_t)e.payload[1] << 8);
    uint8_t toDs   = (fc >> 8) & 1;
    uint8_t fromDs = (fc >> 9) & 1;
    const uint8_t *a1 = e.payload + 4;
    const uint8_t *a2 = e.payload + 10;
    const uint8_t *a3 = e.payload + 16;
    const uint8_t *bssid;
    const uint8_t *sta;
    if (toDs == 0 && fromDs == 1) { bssid = a2; sta = a1; }
    else if (toDs == 1 && fromDs == 0) { bssid = a1; sta = a2; }
    else if (toDs == 0 && fromDs == 0) { bssid = a3; sta = a2; }
    else return;

    uint64_t replayCtr = 0;
    for (int i = 0; i < 8; ++i) replayCtr = (replayCtr << 8) | e.payload[eapolOff + 9 + i];

    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);

    if (g_hshkEnabled.load() && msgNum >= 1 && msgNum <= 4) {
        hshkRecord(bssid, sta, msgNum, replayCtr, e.rssi, getNodeId().c_str(), now);
        if (meshEnabled && g_meshHshk.load() && meshRateGate("HSHK", 1000)) {
            sendToSerial1(getNodeId() + ": HSHK:" + macStr(bssid) + ":" + macStr(sta) +
                          ":" + String(msgNum) + ":" + String((unsigned long)replayCtr) +
                          ":" + String(e.rssi), true);
        }
    }

    if (msgNum != 1 || !g_pmkidEnabled.load()) return;
    const uint8_t *src = sta;
    bool broadcastDest = (a1[0] & 0x01) != 0;
    uint64_t srcK = packMac(src);
    PmkidBurst &b = g_pmkidBursts[srcK];
    b.lastSeen = now;
    uint64_t bssK = packMac(bssid);
    b.bssidTs[bssK] = now;
    uint16_t win = g_pmkidWindow.load();
    for (auto it = b.bssidTs.begin(); it != b.bssidTs.end(); ) {
        if (now - it->second > win) it = b.bssidTs.erase(it);
        else ++it;
    }
    bool fire = (b.bssidTs.size() >= g_pmkidMinBssids.load()) || broadcastDest;
    if (fire) {
        PmkidHarvestEvent ev{};
        memcpy(ev.srcMac, src, 6);
        memcpy(ev.bssid, bssid, 6);
        ev.rssi = e.rssi;
        ev.channel = e.channel;
        ev.ts = now;
        g_pmkidLog.push_back(ev);
        if (g_pmkidLog.size() > MAX_PMKID_LOG) g_pmkidLog.erase(g_pmkidLog.begin());

        char bsBuf[18], srBuf[18];
        snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
        snprintf(srBuf, sizeof(srBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 src[0],src[1],src[2],src[3],src[4],src[5]);
        String bs(bsBuf);
        String sr(srBuf);
        char lineBuf[280];
        snprintf(lineBuf, sizeof(lineBuf),
                 "{\"src\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"ch\":%u,\"ts\":%u,\"distinct_peers\":%u,\"bcast\":%s}",
                 srBuf, bsBuf, (int)ev.rssi, (unsigned)ev.channel, (unsigned)now,
                 (unsigned)b.bssidTs.size(), broadcastDest ? "true" : "false");
        logEventToSD("/pmkid.jsonl", String(lineBuf));
        if (meshEnabled && g_meshPmkid.load() && meshRateGate("PMKID_HARVEST", 5000)) {
            char meshBuf[80];
            snprintf(meshBuf, sizeof(meshBuf), "%s: PMKID_HARVEST:%s:%s:%d",
                     getNodeId().c_str(), srBuf, bsBuf, (int)ev.rssi);
            sendToSerial1(String(meshBuf), true);
        }
        quorum_addReport("PMKID", sr, getNodeId(), ev.rssi);
        attacker_kick(src, "PMKID");
        b.bssidTs.clear();
    }
}

// =============================================================================
// Beacon / Evil-Twin / SSID Confusion / OWE
// =============================================================================
// tool + tool static beacon-spam template fingerprint at TSF bytes 24-31.
// Both tools ship with this exact constant burned into their beacon template.
static const uint8_t BEACON_FORGERY_TSF[8] = {0x83, 0x51, 0xF7, 0x8F, 0x0F, 0x00, 0x00, 0x00};
static std::map<uint64_t, uint32_t> g_beaconForgeFired;  // bssid -> reason mask seen
static constexpr size_t MAX_BEACON_FORGE_MAP = 64;

// Beacon-flood detector: counts DISTINCT BSSIDs seen in a rolling window.
// Real environments have a handful of APs; spam tools spew dozens of new
// BSSIDs/sec. This catches ALL beacon-flood tools (template-independent) and,
// while active, suppresses evil-twin/SSID-collision emits (those collisions are
// spam artifacts, not a real twin) -> fixes beacon-spam-as-EVILTWIN misclassify.
static std::set<uint64_t> g_beaconFloodBssids;
static uint32_t g_beaconFloodWinStart = 0;
static uint32_t g_beaconFloodLastEmit = 0;
static bool     g_beaconFloodActive = false;
static constexpr uint32_t BEACON_FLOOD_WIN_MS    = 10000;
static constexpr size_t   BEACON_FLOOD_DISTINCT  = 40;     // distinct NEAR BSSIDs/10s
static constexpr size_t   BEACON_FLOOD_MAP_CAP   = 256;
static constexpr uint32_t BEACON_FLOOD_COOLDOWN  = 10000;
// Only count beacons stronger than this. A beacon-spam attacker is in the room
// (-10..-40 dBm in tests); ambient/neighbor APs at -70..-90 are NOT spam. Without
// this gate a dense RF area trivially shows 25+ distinct BSSIDs -> false positive
// (observed firing at rssi=-82/-86). Gating to near beacons kills that FP.
static constexpr int8_t   BEACON_FLOOD_RSSI_MIN  = -65;

// Common Espressif OUI prefixes — found in nearly every tool/tool build
// because they run on ESP32-S3/C3. Used as confidence bump for Evil-Portal.
static const uint8_t ESP_OUIS[][3] = {
    {0x24,0x0A,0xC4}, {0x24,0x6F,0x28}, {0x30,0xAE,0xA4}, {0x3C,0x71,0xBF},
    {0x7C,0x9E,0xBD}, {0x84,0xF3,0xEB}, {0xAC,0x67,0xB2}, {0x84,0xCC,0xA8},
    {0xC8,0x2B,0x96}, {0xCC,0x50,0xE3}, {0xDC,0x54,0x75}, {0x30,0xC6,0xF7},
    {0x80,0x7D,0x3A}, {0x90,0x38,0x0C}, {0x8C,0xCE,0x4E}, {0x78,0xE3,0x6D},
    {0x78,0x21,0x84}, {0x7C,0xDF,0xA1}, {0x94,0xB9,0x7E}, {0x98,0xCD,0xAC},
    {0xA0,0xDD,0x6C}, {0xAC,0x0B,0xFB}, {0xB4,0x8A,0x0A}, {0xB8,0xD6,0x1A},
    {0xBC,0xDD,0xC2}, {0xC4,0xDD,0x57}, {0xD8,0xBC,0x38}, {0xE0,0x98,0x06},
    {0xE8,0x9F,0x6D}, {0xEC,0xDA,0x3B}, {0xF0,0x08,0xD1}, {0xF4,0xCF,0xA2},
    {0xF8,0xB7,0x62}, {0xFC,0xF5,0xC4},
};
static constexpr size_t ESP_OUI_COUNT = sizeof(ESP_OUIS) / sizeof(ESP_OUIS[0]);
static bool isEspOui(const uint8_t *mac) {
    for (size_t i = 0; i < ESP_OUI_COUNT; ++i) {
        if (memcmp(mac, ESP_OUIS[i], 3) == 0) return true;
    }
    return false;
}

// Captive-portal lure SSID substrings (lowercase).
// Hit any of these on an open AP and there is a strong chance of Evil-Portal.
static const char *LURE_SSIDS[] = {
    "free wifi", "free_wifi", "freewifi", "free internet",
    "guest", "public wifi", "public_wifi",
    "starbucks", "mcdonald", "airport", "hotel",
    "captive", "portal", "login", "wifi-auth", "wifi_auth", "wifi auth",
    "evil_portal", "evilportal", "phish",
    "xfinity", "attwifi", "att wi-fi", "spectrum",
};
static constexpr size_t LURE_SSID_COUNT = sizeof(LURE_SSIDS) / sizeof(LURE_SSIDS[0]);

static bool containsLureSsid(const char *ssid) {
    if (!ssid || !ssid[0]) return false;
    char lower[34] = {0};
    size_t n = strnlen(ssid, 32);
    for (size_t i = 0; i < n; ++i) {
        char c = ssid[i];
        lower[i] = (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
    }
    for (size_t i = 0; i < LURE_SSID_COUNT; ++i) {
        if (strstr(lower, LURE_SSIDS[i])) return true;
    }
    return false;
}

static const char *classifyBeaconForgery(const uint8_t *p, uint16_t len) {
    if (len < 36) return nullptr;
    if (memcmp(p + 24, BEACON_FORGERY_TSF, 8) == 0) return "FORGE_TSF_STATIC";
    uint16_t bi = (uint16_t)p[32] | ((uint16_t)p[33] << 8);
    if (bi == 1000 && (p[10] & 0x02)) return "FORGE_BI_1000";
    if (len > 36) {
        uint16_t off = 36;
        while (off + 2 <= len) {
            uint8_t tag = p[off];
            uint8_t l   = p[off + 1];
            if ((size_t)off + 2 + l > (size_t)len) break;
            if (tag == 0x25 && l >= 1 && p[off + 2] == 0xFF) return "FORGE_CSA_FF";
            off += 2 + l;
        }
    }
    return nullptr;
}

static void emitBeaconForgery(const uint8_t *bssid, const char *ssid, uint16_t bi,
                              uint32_t ieHash, int8_t rssi, uint8_t channel,
                              const char *reason);

static void handleBeacon(const DetectFrameEvent &e) {
    if (::g_detectVerbose.load() && e.len >= 38) {
        const uint8_t *src = e.payload + 10;
        Serial.printf("[VERIFY-BEACON] bssid=%02X:%02X:%02X:%02X:%02X:%02X len=%u ch=%u rssi=%d\n",
                      src[0],src[1],src[2],src[3],src[4],src[5], (unsigned)e.len, (unsigned)e.channel, (int)e.rssi);
    }
    if (e.len < 36) return;
    if (isSelfMac(e.payload + 10)) return;
    const uint8_t *bssid_early = e.payload + 16;
    bool isLaaBssid = (bssid_early[0] & 0x02) != 0;

    // --- Beacon-flood detection (distinct-BSSID churn). Runs before per-detector
    // gates so it catches spam regardless of which detectors are on.
    // CRITICAL: once a flood is active, do NOT keep logging/processing each spam
    // beacon — that per-frame String/SD/map work is what exhausts heap and crashes.
    // Detect once, alert (rate-gated), then bail out of the whole handler. ---
    {
        uint64_t bk = packMac(bssid_early);
        uint32_t tnow = millis();
        std::lock_guard<std::recursive_mutex> lkF(g_mtx);
        if (g_beaconFloodWinStart == 0 || (tnow - g_beaconFloodWinStart) > BEACON_FLOOD_WIN_MS) {
            g_beaconFloodWinStart = tnow;
            g_beaconFloodBssids.clear();
            g_beaconFloodActive = false;
        }
        if (!g_beaconFloodActive) {
            // Only count NEAR beacons. Ambient/neighbor APs (weak RSSI) are not spam.
            if (e.rssi >= BEACON_FLOOD_RSSI_MIN) {
                g_beaconFloodBssids.insert(bk);
                if (g_beaconFloodBssids.size() >= BEACON_FLOOD_DISTINCT) {
                    g_beaconFloodActive = true;
                    g_beaconFloodBssids.clear();   // free the set; flag carries state
                }
            }
        }
        if (g_beaconFloodActive) {
            // Rate-gated alert; everything else about this beacon is skipped.
            if (g_beaconFloodLastEmit == 0 || (tnow - g_beaconFloodLastEmit) > BEACON_FLOOD_COOLDOWN) {
                g_beaconFloodLastEmit = tnow;
                Serial.printf("[DETECT] BEACON_FLOOD active ch=%u rssi=%d\n",
                              (unsigned)e.channel, (int)e.rssi);
                ::detect_logIncident(String("BEACON_FLOOD:ch") + String(e.channel) + ":" + String((int)e.rssi) + "dBm", nullptr);
                char lb[160];
                snprintf(lb, sizeof(lb),
                         "{\"distinct_bssid\":%u,\"win_ms\":%u,\"ch\":%u,\"rssi\":%d,\"reason\":\"BEACON_FLOOD\",\"ts\":%u}",
                         (unsigned)BEACON_FLOOD_DISTINCT, (unsigned)BEACON_FLOOD_WIN_MS,
                         (unsigned)e.channel, (int)e.rssi, (unsigned)tnow);
                logEventToSD("/eviltwin.jsonl", String(lb));
                if (meshEnabled && g_meshEviltwin.load() && meshRateGate(String("BEACON_FLOOD"), 30000)) {
                    char mb[64];
                    snprintf(mb, sizeof(mb), "%s: BEACON_FLOOD:%d",
                             getNodeId().c_str(), (int)e.rssi);
                    sendToSerial1(String(mb), true);
                }
            }
            return;   // skip ALL per-frame work during flood -> no heap storm
        }
    }

    bool wantPwna = g_pwnaEnabled.load();
    bool wantEvil = g_eviltwinEnabled.load();
    bool wantTsf  = g_tsfEnabled.load();
    bool wantOwe  = g_oweEnabled.load();
    if (!wantPwna && !wantEvil && !wantTsf && !wantOwe) return;
    const uint8_t *p = e.payload;
    const uint8_t *bssid = p + 16;
    uint64_t tsf = 0;
    for (int i = 0; i < 8; ++i) tsf |= ((uint64_t)p[24 + i]) << (8 * i);
    uint16_t beaconInt = (uint16_t)p[32] | ((uint16_t)p[33] << 8);
    const uint8_t *ie = p + 36;
    uint16_t ieLen = e.len - 36;

    // Evil-twin-of-us: any non-self BSSID beaconing OUR SSID is a clone of our AP.
    if (wantEvil) {
        char ssidSelf[33] = {0};
        extractSSID(ie, ieLen, ssidSelf, sizeof(ssidSelf));
        if (ssidSelf[0] && isSelfSsid(ssidSelf) && !isSelfMac(bssid) && !isSelfMac(p + 10)) {
            static std::map<uint64_t, uint32_t> s_selfCloneSeen;
            uint64_t ck = packMac(bssid);
            uint32_t nowc = millis();
            auto sit = s_selfCloneSeen.find(ck);
            if (sit == s_selfCloneSeen.end() || (nowc - sit->second) > 30000) {
                if (s_selfCloneSeen.size() >= 32) s_selfCloneSeen.erase(s_selfCloneSeen.begin());
                s_selfCloneSeen[ck] = nowc;
                const char *rsn = hasOpenAuth(ie, ieLen) ? "SELF_CLONE_OPEN" : "SELF_CLONE";
                char bb[18];
                snprintf(bb, sizeof(bb), "%02X:%02X:%02X:%02X:%02X:%02X",
                         bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
                Serial.printf("[DETECT] EVILTWIN src=%s reason=%s (clone of our AP)\n", bb, rsn);
                char lb[220];
                snprintf(lb, sizeof(lb),
                         "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"reason\":\"%s\",\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                         bb, ssidSelf, rsn, (int)e.rssi, (unsigned)e.channel, (unsigned)nowc);
                logEventToSD("/eviltwin.jsonl", String(lb));
                ::detect_logIncident(String("EVILTWIN:") + bb + ":" + rsn, bb);
                quorum_addReport("EVILTWIN", String(bb), getNodeId(), e.rssi);
                attacker_kick(bssid, "EVILTWIN");
                if (meshEnabled && g_meshEviltwin.load() && meshRateGate(String("ETW_SELF_") + bb, 30000))
                    sendToSerial1(getNodeId() + ": EVILTWIN:" + bb + ":" + rsn + ":" + String((int)e.rssi), true);
            }
        }
    }
    if (wantEvil) {
        const char *forgeReason = classifyBeaconForgery(p, e.len);
        if (forgeReason) {
            char ssidLocal[33] = {0};
            extractSSID(ie, ieLen, ssidLocal, sizeof(ssidLocal));
            uint32_t ieH = hashIeSet(ie, ieLen);
            emitBeaconForgery(bssid, ssidLocal, beaconInt, ieH, e.rssi, e.channel, forgeReason);
        }

        // Evil-Portal heuristic — STRICT to avoid FP on legit captive portals
        // (hotels, airports, Starbucks). Require ALL THREE:
        //   1. open auth (no Privacy bit)
        //   2. lure-style SSID (Free WiFi, captive, portal, etc.)
        //   3. Espressif OUI source MAC
        // ESP32 doesn't run consumer/enterprise APs. ESP32 + open + lure SSID =
        // high-confidence Evil-Portal. Generic open+lure (no ESP) is too FP-heavy.
        {
            uint8_t capInfo0 = p[34];
            bool privacy = (capInfo0 & 0x10) != 0;
            if (!privacy && isEspOui(p + 10)) {
                char ssidEvp[33] = {0};
                extractSSID(ie, ieLen, ssidEvp, sizeof(ssidEvp));
                if (containsLureSsid(ssidEvp)) {
                    uint32_t ieH = hashIeSet(ie, ieLen);
                    emitBeaconForgery(bssid, ssidEvp, beaconInt, ieH, e.rssi, e.channel,
                                      "FORGE_EVIL_PORTAL_ESP");
                }
            }
        }

        // Behavioral fallback: per-src-MAC SSID rotation. Real APs broadcast ONE
        // SSID per BSSID. >=3 distinct SSIDs from same src MAC in 30s = bait,
        // catches tool/tool even if they evolve their template.
        //
        // Skip if Multi-BSSID IE (tag 71) is present — 802.11v/ax feature lets
        // one AP advertise multiple SSIDs from one BSSID legitimately.
        static std::map<uint64_t, std::pair<uint32_t, std::set<String>>> g_beaconSsidRotate;
        static constexpr size_t MAX_BEACON_ROTATE_MAP = 64;
        static constexpr uint32_t BEACON_ROTATE_WIN_MS = 5000;
        static constexpr uint8_t  BEACON_ROTATE_THRESH = 12;
        bool hasMBSSID = false;
        {
            uint16_t mo = 0;
            while (mo + 2 <= ieLen) {
                uint8_t t = ie[mo];
                uint8_t l = ie[mo + 1];
                if ((size_t)mo + 2 + l > (size_t)ieLen) break;
                if (t == 71) { hasMBSSID = true; break; }  // Multi-BSSID element
                mo += 2 + l;
            }
        }
        char ssidLocal2[33] = {0};
        extractSSID(ie, ieLen, ssidLocal2, sizeof(ssidLocal2));
        if (!hasMBSSID && ssidLocal2[0]) {
            uint64_t srcK = packMac(p + 10);
            uint32_t now2 = millis();
            std::lock_guard<std::recursive_mutex> lkR(g_mtx);
            auto rit = g_beaconSsidRotate.find(srcK);
            if (rit == g_beaconSsidRotate.end() || (now2 - rit->second.first) > BEACON_ROTATE_WIN_MS) {
                if (g_beaconSsidRotate.size() >= MAX_BEACON_ROTATE_MAP) {
                    g_beaconSsidRotate.erase(g_beaconSsidRotate.begin());
                }
                g_beaconSsidRotate[srcK] = {now2, std::set<String>{String(ssidLocal2)}};
            } else {
                rit->second.second.insert(String(ssidLocal2));
                if (rit->second.second.size() == BEACON_ROTATE_THRESH) {
                    uint32_t ieH = hashIeSet(ie, ieLen);
                    emitBeaconForgery(p + 10, ssidLocal2, beaconInt, ieH, e.rssi, e.channel,
                                      "FORGE_SSID_ROTATE");
                }
            }
        }
    }

    if (isPwnagotchiBeacon(p, e.len)) {
        if (!wantPwna) return;
        std::lock_guard<std::recursive_mutex> lkP(g_mtx);
        pwnagotchiObserve(bssid, e.rssi, ie, ieLen);
        return;
    }

    if (wantTsf && !isLaaBssid) {
        char ssidLocal[33] = {0};
        extractSSID(ie, ieLen, ssidLocal, sizeof(ssidLocal));
        std::lock_guard<std::recursive_mutex> lkT(g_mtx);
        tsfObserve(bssid, tsf, beaconInt, ssidLocal, millis());
    }
    if (!wantEvil && !wantOwe) return;

    char ssid[33] = {0};
    extractSSID(ie, ieLen, ssid, sizeof(ssid));
    uint32_t ieHash = hashIeSet(ie, ieLen);
    bool isOpen = hasOpenAuth(ie, ieLen);
    uint8_t oweTransBssid[6] = {0};
    bool hasOweTrans = extractOweTransition(ie, ieLen, oweTransBssid);

    if (isLaaBssid) return;

    uint64_t k = packMac(bssid);
    uint32_t now = millis();

    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    static constexpr size_t MAX_AP_BASELINE = 96;
    if (g_apBaseline.size() >= MAX_AP_BASELINE && g_apBaseline.find(k) == g_apBaseline.end()) {
        uint32_t oldestTs = UINT32_MAX;
        uint64_t oldestK = 0;
        for (auto &kv : g_apBaseline) {
            if (kv.second.lastSeen < oldestTs) {
                oldestTs = kv.second.lastSeen;
                oldestK = kv.first;
            }
        }
        if (oldestK) g_apBaseline.erase(oldestK);
    }
    auto it = g_apBaseline.find(k);
    if (it == g_apBaseline.end()) {
        ApBaseline b{};
        b.lastTSF = tsf;
        b.lastTSFSampleMs = now;
        b.beaconInterval = beaconInt;
        b.ieHash = ieHash;
        strncpy(b.ssid, ssid, sizeof(b.ssid) - 1);
        b.channel = e.channel;
        b.rssi = e.rssi;
        b.isOpen = isOpen;
        b.hasOweTransition = hasOweTrans;
        if (hasOweTrans) memcpy(b.oweTransitionBssid, oweTransBssid, 6);
        b.lastSeen = now;
        g_apBaseline[k] = b;

        uint8_t hbuf[10];
        memcpy(hbuf, bssid, 6);
        memcpy(hbuf + 6, &ieHash, 4);
        g_localBloom.add(fnv1a(hbuf, 10));
        return;
    }

    ApBaseline &b = it->second;

    // Freshness gate: if baseline sample is stale (>30s old) we cannot trust
    // a TSF compare — channel-hop gap, AP rekey, or buffer-reorder dominates.
    // Update baseline and skip anomaly detection for this beacon.
    bool baselineStale = (b.lastTSFSampleMs == 0) || ((now - b.lastTSFSampleMs) > 30000UL);

    // TSF anomaly: TSF should monotonically increase; or restart (cloned AP reboot)
    bool tsfRestart = !baselineStale && (tsf < b.lastTSF) && ((b.lastTSF - tsf) > 1000000000ULL); // >1000s jump back
    bool tsfNonMonoRaw = !baselineStale && (tsf < b.lastTSF) && !tsfRestart && ((b.lastTSF - tsf) > 5000000ULL);

    // Streak gate: require 2+ TSF-nonmono observations within 30s before emitting.
    // Single-shot rejected — most are buggy LAA APs, reorder, or transient.
    bool tsfNonMono = false;
    if (tsfNonMonoRaw) {
        if (b.tsfViolWindowMs == 0 || (now - b.tsfViolWindowMs) > 30000UL) {
            b.tsfViolStreak = 1;
            b.tsfViolWindowMs = now;
        } else {
            if (b.tsfViolStreak < 255) b.tsfViolStreak++;
            if (b.tsfViolStreak >= 2) tsfNonMono = true;
        }
    } else if (!baselineStale) {
        // monotonic beacon resets streak
        b.tsfViolStreak = 0;
        b.tsfViolWindowMs = 0;
    }

    // Beacon-interval drift permil
    uint16_t driftPermil = 0;
    if (!baselineStale && b.beaconInterval > 0 && beaconInt > 0) {
        int32_t d = (int32_t)beaconInt - (int32_t)b.beaconInterval;
        if (d < 0) d = -d;
        driftPermil = (uint16_t)((1000UL * d) / b.beaconInterval);
    }
    bool intervalDrift = false;
    bool ieDrift = false;
    tsfRestart = false;

    struct SsidWatch {
        uint32_t winStartMs;
        uint8_t streak;
        std::set<uint32_t> ouis;
        std::set<uint64_t> bssids;
        uint32_t lastFiredMs;
    };
    static std::map<uint64_t, SsidWatch> g_ssidWatch;
    static constexpr size_t MAX_SSID_TRACK = 48;
    static constexpr uint32_t SSID_COLLISION_WIN_MS = 60000;
    static constexpr uint32_t SSID_FIRE_COOLDOWN_MS = 600000;
    static constexpr uint8_t  SSID_PERSIST_STREAK = 2;

    bool ssidCollision = false;
    uint32_t collisionOuiCount = 0;
    uint32_t bssidOui = ((uint32_t)bssid[0] << 16) | ((uint32_t)bssid[1] << 8) | (uint32_t)bssid[2];

    if (ssid[0] != 0 && !isSelfSsid(ssid)) {
        uint64_t ssidHash = fnv1a((const uint8_t*)ssid, strlen(ssid));
        auto sit = g_ssidWatch.find(ssidHash);
        if (sit == g_ssidWatch.end()) {
            if (g_ssidWatch.size() >= MAX_SSID_TRACK) {
                uint32_t oldestTs = UINT32_MAX;
                uint64_t oldestK = 0;
                for (auto &kv : g_ssidWatch) {
                    if (kv.second.winStartMs < oldestTs) { oldestTs = kv.second.winStartMs; oldestK = kv.first; }
                }
                if (oldestK) g_ssidWatch.erase(oldestK);
            }
            SsidWatch sw{};
            sw.winStartMs = now;
            sw.streak = 0;
            sw.lastFiredMs = 0;
            sw.ouis.insert(bssidOui);
            sw.bssids.insert(k);
            g_ssidWatch[ssidHash] = sw;
        } else {
            SsidWatch &sw = sit->second;
            if ((now - sw.winStartMs) > SSID_COLLISION_WIN_MS) {
                sw.winStartMs = now;
                sw.ouis.clear();
                sw.bssids.clear();
            }
            sw.ouis.insert(bssidOui);
            sw.bssids.insert(k);
            collisionOuiCount = sw.ouis.size();
            bool ouiMismatch = collisionOuiCount >= 2;
            bool cooldownPassed = (sw.lastFiredMs == 0) || ((now - sw.lastFiredMs) >= SSID_FIRE_COOLDOWN_MS);
            if (ouiMismatch && cooldownPassed) {
                if (sw.streak < 255) sw.streak++;
                if (sw.streak >= SSID_PERSIST_STREAK) {
                    ssidCollision = true;
                    sw.lastFiredMs = now;
                    sw.streak = 0;
                }
            } else if (!ouiMismatch) {
                sw.streak = 0;
            }
        }
    }

    uint32_t cooldownMs = (tsfNonMono || ssidCollision) ? 300000UL : 60000UL;
    bool cooldownOk = (b.lastEvilEmitMs == 0) || ((now - b.lastEvilEmitMs) >= cooldownMs);

    // Suppress evil-twin emit during an active beacon flood: SSID collisions and
    // TSF anomalies under flood are spam artifacts (random BSSIDs reusing SSIDs),
    // not a real twin. BEACON_FLOOD already reported the attack.
    if ((tsfNonMono || ssidCollision) && cooldownOk && !g_beaconFloodActive) {
        EvilTwinEvent ev{};
        memcpy(ev.bssid, bssid, 6);
        strncpy(ev.ssid, ssid, sizeof(ev.ssid) - 1);
        ev.oldTSF = b.lastTSF;
        ev.newTSF = tsf;
        ev.oldIeHash = b.ieHash;
        ev.newIeHash = ieHash;
        ev.oldBeaconInt = b.beaconInterval;
        ev.newBeaconInt = beaconInt;
        ev.rssi = e.rssi;
        ev.channel = e.channel;
        ev.ts = now;
        if (ssidCollision) strncpy(ev.reason, "SSID_COLLISION", sizeof(ev.reason) - 1);
        else strncpy(ev.reason, "TSF_NONMONO", sizeof(ev.reason) - 1);

        g_evilTwinLog.push_back(ev);
        if (g_evilTwinLog.size() > MAX_ET_LOG) g_evilTwinLog.erase(g_evilTwinLog.begin());

        char bs[18];
        snprintf(bs, sizeof(bs), "%02X:%02X:%02X:%02X:%02X:%02X",
                 bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
        char jsonLine[320];
        snprintf(jsonLine, sizeof(jsonLine),
                 "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"reason\":\"%s\",\"ouis\":%u,\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                 bs, ev.ssid, ev.reason, (unsigned)collisionOuiCount,
                 (int)ev.rssi, (unsigned)ev.channel, (unsigned)now);
        logEventToSD("/eviltwin.jsonl", String(jsonLine));
        String bsStr(bs);
        if (meshEnabled && g_meshEviltwin.load() && meshRateGate(String("EVILTWIN_") + bsStr, 10000)) {
            char meshMsg[80];
            snprintf(meshMsg, sizeof(meshMsg), "%s: EVILTWIN:%s:%s:%d",
                     getNodeId().c_str(), bs, ev.reason, (int)ev.rssi);
            sendToSerial1(String(meshMsg), true);
        }
        ::detect_logIncident(String("EVILTWIN:") + bsStr + ":" + ev.reason, bs);
        quorum_addReport("EVILTWIN", bsStr, getNodeId(), ev.rssi);
        b.lastEvilEmitMs = now;
        b.tsfViolStreak = 0;
        b.tsfViolWindowMs = 0;
    }

    // OWE transition abuse: open beacon on SSID that matches an OWE-tagged BSSID without
    // being its declared transition partner.
    if (isOpen && !hasOweTrans) {
        for (auto &kv : g_apBaseline) {
            ApBaseline &other = kv.second;
            if (other.hasOweTransition && strcmp(other.ssid, ssid) == 0) {
                if (memcmp(other.oweTransitionBssid, bssid, 6) != 0) {
                    OweAbuseEvent ev{};
                    memcpy(ev.openBssid, bssid, 6);
                    unpackMac(kv.first, ev.oweBssid);
                    strncpy(ev.ssid, ssid, sizeof(ev.ssid) - 1);
                    ev.rssi = e.rssi;
                    ev.channel = e.channel;
                    ev.ts = now;
                    g_oweAbuseLog.push_back(ev);
                    if (g_oweAbuseLog.size() > MAX_OWE_LOG) g_oweAbuseLog.erase(g_oweAbuseLog.begin());
                    char obBuf[18], owbBuf[18];
                    snprintf(obBuf, sizeof(obBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                             bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
                    snprintf(owbBuf, sizeof(owbBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                             ev.oweBssid[0],ev.oweBssid[1],ev.oweBssid[2],ev.oweBssid[3],ev.oweBssid[4],ev.oweBssid[5]);
                    char lineBuf[260];
                    snprintf(lineBuf, sizeof(lineBuf),
                             "{\"open_bssid\":\"%s\",\"owe_bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                             obBuf, owbBuf, ssid, (int)e.rssi, (unsigned)e.channel, (unsigned)now);
                    logEventToSD("/owe_abuse.jsonl", String(lineBuf));
                    ::detect_logIncident(String("OWE_ABUSE:") + obBuf + ":" + ssid, obBuf);
                    break;
                }
            }
        }
    }

    // Update baseline state
    b.lastTSF = tsf;
    b.lastTSFSampleMs = now;
    b.beaconInterval = beaconInt;
    b.ieHash = ieHash;
    strncpy(b.ssid, ssid, sizeof(b.ssid) - 1);
    b.channel = e.channel;
    b.rssi = e.rssi;
    b.isOpen = isOpen;
    b.hasOweTransition = hasOweTrans;
    if (hasOweTrans) memcpy(b.oweTransitionBssid, oweTransBssid, 6);
    b.lastSeen = now;
}

// Beacon-forgery emitter — fires once per (BSSID, reason) per session to avoid spam.
static void emitBeaconForgery(const uint8_t *bssid, const char *ssid, uint16_t bi,
                              uint32_t ieHash, int8_t rssi, uint8_t channel,
                              const char *reason) {
    uint64_t k = packMac(bssid);
    uint32_t reasonBit = 0;
    uint8_t reasonIdx = 0;
    if      (strcmp(reason, "FORGE_TSF_STATIC") == 0) { reasonBit = 0x01; reasonIdx = 0; }
    else if (strcmp(reason, "FORGE_BI_1000")    == 0) { reasonBit = 0x02; reasonIdx = 1; }
    else if (strcmp(reason, "FORGE_SRC_MCAST")  == 0) { reasonBit = 0x04; reasonIdx = 2; }
    else if (strcmp(reason, "FORGE_CSA_FF")     == 0) { reasonBit = 0x08; reasonIdx = 3; }
    else if (strcmp(reason, "FORGE_QUIET_ELEM") == 0) { reasonBit = 0x10; reasonIdx = 4; }
    else if (strcmp(reason, "FORGE_SSID_ROTATE") == 0) { reasonBit = 0x20; reasonIdx = 5; }
    else if (strcmp(reason, "FORGE_EVIL_PORTAL")  == 0) { reasonBit = 0x40; reasonIdx = 6; }
    else if (strcmp(reason, "FORGE_EVIL_PORTAL_ESP") == 0) { reasonBit = 0x80; reasonIdx = 7; }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);

    // GLOBAL per-reason rate gate. Beacon spam randomizes BSSID every frame, so the
    // per-BSSID dedup below never triggers -> without this, a flood causes one
    // SD-write + String-alloc PER beacon (hundreds/sec) -> heap exhaustion -> crash.
    // Collapse a flood to one emit per cooldown while still flagging the attack.
    static uint32_t s_lastEmitMs[8] = {0};
    uint32_t nowMs = millis();
    if (s_lastEmitMs[reasonIdx] != 0 && (nowMs - s_lastEmitMs[reasonIdx]) < 5000) return;

    auto it = g_beaconForgeFired.find(k);
    if (it != g_beaconForgeFired.end() && (it->second & reasonBit)) return;  // already reported
    if (g_beaconForgeFired.size() >= MAX_BEACON_FORGE_MAP) {
        // Evict an arbitrary entry; this set is bounded for memory safety only.
        g_beaconForgeFired.erase(g_beaconForgeFired.begin());
    }
    g_beaconForgeFired[k] |= reasonBit;
    s_lastEmitMs[reasonIdx] = nowMs;

    EvilTwinEvent ev{};
    memcpy(ev.bssid, bssid, 6);
    strncpy(ev.ssid, ssid, sizeof(ev.ssid) - 1);
    ev.oldBeaconInt = 0;
    ev.newBeaconInt = bi;
    ev.oldIeHash = 0;
    ev.newIeHash = ieHash;
    ev.rssi = rssi;
    ev.channel = channel;
    ev.ts = millis();
    strncpy(ev.reason, reason, sizeof(ev.reason) - 1);
    g_evilTwinLog.push_back(ev);
    if (g_evilTwinLog.size() > MAX_ET_LOG) g_evilTwinLog.erase(g_evilTwinLog.begin());

    char bs[18];
    snprintf(bs, sizeof(bs), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    char jsonLine[280];
    snprintf(jsonLine, sizeof(jsonLine),
             "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"reason\":\"%s\",\"bi\":%u,\"ie\":%u,\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
             bs, ev.ssid, ev.reason, (unsigned)bi, (unsigned)ieHash,
             (int)rssi, (unsigned)channel, (unsigned)ev.ts);
    logEventToSD("/eviltwin.jsonl", String(jsonLine));
    String bsStr(bs);
    if (meshEnabled && g_meshEviltwin.load() && meshRateGate(String("BEACON_FORGE_REASON_") + reason, 30000)) {
        char meshMsg[80];
        snprintf(meshMsg, sizeof(meshMsg), "%s: BEACON_FORGE:%s:%s:%d",
                 getNodeId().c_str(), bs, reason, (int)rssi);
        sendToSerial1(String(meshMsg), true);
    }
    quorum_addReport("BEACON_FORGE", bsStr, getNodeId(), rssi);
}

// =============================================================================
// Assoc-Sleep / tool assoc attack — sends assoc-request frames with the
// PM (power-management) bit set in frame-control byte 1, from random STA MACs
// to a target AP, every 200ms (WiFiScan.cpp:7987-8112). Distinguishes from
// legit clients because real STAs negotiate sleep AFTER association.
// Detection: per-BSSID, count distinct src MACs sending assoc-req with PM bit
// in a 5s window. >=4 distinct = alert.
// =============================================================================
struct AssocSleepWindow {
    uint32_t windowStartMs;
    std::set<uint64_t> distinctSrc;
    uint16_t frames;
    int8_t bestRssi;
    uint8_t channel;
    bool alerted;
};
static std::map<uint64_t, AssocSleepWindow> g_assocSleep;
static constexpr size_t MAX_ASSOC_SLEEP_MAP = 32;
static constexpr uint16_t ASSOC_SLEEP_WIN_MS = 5000;
static constexpr uint8_t  ASSOC_SLEEP_THRESH = 4;   // distinct spoofed src (multi-client)
static constexpr uint16_t ASSOC_SLEEP_FRAMES = 8;   // PM-bit assoc-req rate (catches 1-MAC flood)
static std::atomic<bool> g_assocSleepEnabled{true};

struct DeauthRateEntry {
    uint32_t winStartMs;
    uint16_t count;
    bool alerted;
    // Per-tool behavioral trackers (see docs/detector-verification.md §1)
    uint16_t lastSeqNum;     // last sequence number (seqCtrl>>4)
    uint8_t  sawtoothHits;   // consecutive 0..63 incrementing seqs (bettercap)
    uint8_t  lastSubtype;    // 0x0C deauth / 0x0A disassoc
    uint8_t  altHits;        // consecutive deauth<->disassoc alternations (mdk4)
    uint8_t  reason7Hits;    // reason=7 + dur=0x013A frames (aireplay/bettercap class)
    bool     toolAlerted;    // emitted a per-tool forge alert this window
};
static std::map<uint64_t, DeauthRateEntry> g_deauthRate;
static constexpr size_t MAX_DEAUTH_RATE_MAP = 64;
static constexpr uint32_t DEAUTH_FLOOD_WIN_MS = 10000;
static constexpr uint16_t DEAUTH_FLOOD_THRESH = 20;
static std::atomic<uint32_t> g_lastRealDeauthMs{0};

// Classify a deauth/disassoc frame against verified per-tool source fingerprints.
// Returns a static tool tag or nullptr. Single-frame static checks only.
//   reason: frame reason code   seqCtrl: raw seq-control field
//   durLE: duration field (bytes 2-3, little-endian)   subtype: 0x0C or 0x0A
static const char *classifyDeauthTool(uint16_t reason, uint16_t seqCtrl, uint16_t durLE) {
    // ESP32Marauder WiFiScan.h:491 — reason=2, seqCtrl=0xFFF0 (fixed)
    if (reason == 0x0002 && seqCtrl == 0xFFF0) return "MARAUDER";
    if (reason == 0x000E) return "MICHAEL_TKIP";
    // reason=7+dur=0x013A is shared by aireplay AND bettercap — resolved behaviorally
    // (sawtooth->BETTERCAP, sustained-no-sawtooth->AIREPLAY), not statically.
    return nullptr;
}

static void handleDeauthFrame(const DetectFrameEvent &e) {
    if (e.len < 26) return;
    const uint8_t *p = e.payload;
    const uint8_t *dst = p + 4;
    const uint8_t *src = p + 10;
    bool selfSrc = isSelfMac(src);
    bool sentinelHop = ::sentinel_isRunning();
    if (!selfSrc) g_lastRealDeauthMs.store(millis());
    uint16_t durLE   = (uint16_t)p[2]  | ((uint16_t)p[3]  << 8);
    uint16_t seqCtrl = (uint16_t)p[22] | ((uint16_t)p[23] << 8);
    uint16_t seqNum  = seqCtrl >> 4;
    uint8_t  subtype = (p[0] >> 4) & 0x0F;   // 0x0C deauth, 0x0A disassoc
    uint16_t reason  = (uint16_t)p[24] | ((uint16_t)p[25] << 8);
    bool isBroadcast = (dst[0] == 0xFF && dst[1] == 0xFF && dst[2] == 0xFF &&
                        dst[3] == 0xFF && dst[4] == 0xFF && dst[5] == 0xFF);
    const char *toolTag = classifyDeauthTool(reason, seqCtrl, durLE);
    bool forgeFingerprint = (toolTag != nullptr);
    if (::g_detectVerbose.load()) {
        Serial.printf("[VERIFY-DEAUTH] src=%02X:%02X:%02X:%02X:%02X:%02X subtype=0x%02X reason=%u seq=0x%04X dur=0x%04X bcast=%d tool=%s selfSrc=%d\n",
                      src[0],src[1],src[2],src[3],src[4],src[5], subtype, reason, seqCtrl, durLE,
                      isBroadcast?1:0, toolTag?toolTag:"-", selfSrc?1:0);
    }
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    uint64_t k = packMac(src);
    auto it = g_deauthRate.find(k);
    if (it == g_deauthRate.end() || (now - it->second.winStartMs) > DEAUTH_FLOOD_WIN_MS) {
        if (g_deauthRate.size() >= MAX_DEAUTH_RATE_MAP) {
            uint32_t oldest = UINT32_MAX; uint64_t oldestK = 0;
            for (auto &kv : g_deauthRate) if (kv.second.winStartMs < oldest) { oldest = kv.second.winStartMs; oldestK = kv.first; }
            g_deauthRate.erase(oldestK);
        }
        DeauthRateEntry ne{};
        ne.winStartMs = now;
        ne.count = 1;
        ne.alerted = false;
        ne.lastSeqNum = seqNum;
        ne.lastSubtype = subtype;
        g_deauthRate[k] = ne;
    } else {
        DeauthRateEntry &r = it->second;
        if (r.count < 65535) r.count++;
        // bettercap: seq walks 0..63 then resets (wifi_deauth.go:14). Count monotonic increments.
        if (seqNum == (uint16_t)(r.lastSeqNum + 1) && seqNum <= 0x003F) {
            if (r.sawtoothHits < 255) r.sawtoothHits++;
        } else if (seqNum != r.lastSeqNum) {
            r.sawtoothHits = 0;
        }
        r.lastSeqNum = seqNum;
        // mdk4 mode d: alternating deauth(0x0C) <-> disassoc(0x0A) pairs (deauth.c:443-466).
        if ((subtype == 0x0C || subtype == 0x0A) && subtype != r.lastSubtype) {
            if (r.altHits < 255) r.altHits++;
        }
        r.lastSubtype = subtype;
        if (reason == 0x0007 && durLE == 0x013A) {
            if (r.reason7Hits < 255) r.reason7Hits++;
        }
        if (!r.toolAlerted && !(selfSrc && sentinelHop)) {
            const char *behavTool = nullptr;
            if (r.altHits >= 6) behavTool = "MDK4";                 // deauth/disassoc alt
            // aireplay & bettercap both emit reason=7+dur=0x013A; sawtooth is lost to
            // frame-drop/hopping so they're not reliably distinguishable -> shared tag.
            else if (r.reason7Hits >= 12 || r.sawtoothHits >= 8) behavTool = "AIREPLAY/BETTERCAP";
            if (behavTool) {
                r.toolAlerted = true;
                char sb[18];
                snprintf(sb, sizeof(sb), "%02X:%02X:%02X:%02X:%02X:%02X",
                         src[0],src[1],src[2],src[3],src[4],src[5]);
                Serial.printf("[DETECT] DEAUTH_FORGE tool=%s src=%s (behavioral)\n", behavTool, sb);
                char lb[200];
                snprintf(lb, sizeof(lb),
                         "{\"src\":\"%s\",\"tool\":\"%s\",\"class\":\"behavioral\",\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                         sb, behavTool, (int)e.rssi, (unsigned)e.channel, (unsigned)now);
                logEventToSD("/deauth_flood.jsonl", String(lb));
                if (meshEnabled && meshRateGate(String("DEAUTH_TOOL_") + sb, 30000)) {
                    char mb[80];
                    snprintf(mb, sizeof(mb), "%s: DEAUTH_FORGE:%s:%s:%d",
                             getNodeId().c_str(), sb, behavTool, (int)e.rssi);
                    sendToSerial1(String(mb), true);
                }
                ::detect_logIncident(String("DEAUTH_FORGE:") + sb + ":" + behavTool, sb);
                quorum_addReport("DEAUTH_FORGE", String(sb), getNodeId(), e.rssi);
                attacker_kick(src, "DEAUTH_FORGE");
            }
        }
        bool suppressSelfBurst = selfSrc && sentinelHop && (r.count < (DEAUTH_FLOOD_THRESH * 2));
        if (!r.alerted && r.count >= DEAUTH_FLOOD_THRESH && !suppressSelfBurst) {
            r.alerted = true;
            char srcBuf[18];
            snprintf(srcBuf, sizeof(srcBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     src[0],src[1],src[2],src[3],src[4],src[5]);
            String srcS(srcBuf);
            Serial.printf("[DETECT] DEAUTH_FLOOD src=%s count=%u in %ums (reason=%u seq=0x%04X bcast=%d%s)\n",
                          srcBuf, r.count, (unsigned)(now - r.winStartMs),
                          (unsigned)reason, seqCtrl, (int)isBroadcast,
                          selfSrc ? " IMPERSONATION" : "");
            char lineBuf[320];
            snprintf(lineBuf, sizeof(lineBuf),
                     "{\"src\":\"%s\",\"count\":%u,\"win_ms\":%u,\"reason\":%u,\"seq\":%u,\"bcast\":%s,\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                     srcBuf, (unsigned)r.count, (unsigned)(now - r.winStartMs),
                     (unsigned)reason, (unsigned)seqCtrl, isBroadcast ? "true" : "false",
                     (int)e.rssi, (unsigned)e.channel, (unsigned)now);
            logEventToSD("/deauth_flood.jsonl", String(lineBuf));
            if (meshEnabled && meshRateGate(String("DEAUTH_FLOOD_") + srcS, 30000)) {
                char meshBuf[80];
                snprintf(meshBuf, sizeof(meshBuf), "%s: DEAUTH_FLOOD:%s:%u:%d",
                         getNodeId().c_str(), srcBuf, (unsigned)r.count, (int)e.rssi);
                sendToSerial1(String(meshBuf), true);
            }
            ::detect_logIncident(String("DEAUTH_FLOOD:") + srcS + ":" + String(r.count), srcBuf);
            quorum_addReport("DEAUTH_FLOOD", srcS, getNodeId(), e.rssi);
            attacker_kick(src, "DEAUTH_FLOOD");
        }
    }
    if (forgeFingerprint && !(selfSrc && sentinelHop)) {
        // Detection emit is INDEPENDENT of mesh. A targeted/low-rate deauth never
        // trips the flood counter, so the static tool fingerprint is the only
        // signal — it must alert even with mesh off. Own per-src cooldown (10s).
        static std::map<uint64_t, uint32_t> g_forgeLastEmit;
        static constexpr size_t MAX_FORGE_EMIT_MAP = 64;
        uint64_t fk = packMac(src);
        auto fit = g_forgeLastEmit.find(fk);
        bool emitOk = (fit == g_forgeLastEmit.end()) || ((now - fit->second) > 10000);
        if (emitOk) {
            if (g_forgeLastEmit.size() >= MAX_FORGE_EMIT_MAP) g_forgeLastEmit.erase(g_forgeLastEmit.begin());
            g_forgeLastEmit[fk] = now;
            char srcBuf[18];
            snprintf(srcBuf, sizeof(srcBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     src[0],src[1],src[2],src[3],src[4],src[5]);
            String srcS(srcBuf);
            Serial.printf("[DETECT] DEAUTH_FORGE tool=%s src=%s (reason=%u seq=0x%04X dur=0x%04X%s)\n",
                          toolTag, srcBuf, (unsigned)reason, seqCtrl, durLE,
                          selfSrc ? " IMPERSONATION" : "");
            char lineBuf[260];
            snprintf(lineBuf, sizeof(lineBuf),
                     "{\"src\":\"%s\",\"tool\":\"%s\",\"class\":\"static\",\"reason\":%u,\"seq\":%u,\"dur\":%u,\"self_impersonation\":%s,\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                     srcBuf, toolTag, (unsigned)reason, (unsigned)seqCtrl, (unsigned)durLE,
                     selfSrc ? "true" : "false", (int)e.rssi, (unsigned)e.channel, (unsigned)now);
            logEventToSD("/deauth_flood.jsonl", String(lineBuf));
            ::detect_logIncident(String("DEAUTH_FORGE:") + srcS + ":" + toolTag, srcBuf);
            quorum_addReport("DEAUTH_FORGE", srcS, getNodeId(), e.rssi);
            attacker_kick(src, "DEAUTH_FORGE");
            // Mesh forwarding is separate/additional.
            if (meshEnabled && meshRateGate(String("DEAUTH_FORGE_") + srcS, 30000)) {
                char meshBuf[96];
                snprintf(meshBuf, sizeof(meshBuf), "%s: DEAUTH_FORGE:%s:%s:%d",
                         getNodeId().c_str(), srcBuf, toolTag, (int)e.rssi);
                sendToSerial1(String(meshBuf), true);
            }
        }
    }
}

static void handleAssocReq(const DetectFrameEvent &e) {
    if (!g_assocSleepEnabled.load()) return;
    if (e.len < 28) return;
    // Frame Control byte 1 bit 4 = PM (power management). For assoc-request the
    // PM bit being set is unusual since the client hasn't completed association.
    uint8_t fc1 = e.payload[1];
    bool pmBit = (fc1 & 0x10) != 0;
    if (!pmBit) return;
    const uint8_t *src   = e.payload + 10;
    const uint8_t *bssid = e.payload + 16;
    uint64_t bssK = packMac(bssid);
    uint64_t srcK = packMac(src);
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_assocSleep.find(bssK);
    if (it == g_assocSleep.end() || (now - it->second.windowStartMs) > ASSOC_SLEEP_WIN_MS) {
        if (g_assocSleep.size() >= MAX_ASSOC_SLEEP_MAP) g_assocSleep.erase(g_assocSleep.begin());
        AssocSleepWindow w{};
        w.windowStartMs = now;
        w.bestRssi = e.rssi;
        w.channel = e.channel;
        w.alerted = false;
        w.frames = 1;
        w.distinctSrc.insert(srcK);
        g_assocSleep[bssK] = w;
        return;
    }
    AssocSleepWindow &w = it->second;
    w.distinctSrc.insert(srcK);
    if (w.frames < 65535) w.frames++;
    if (e.rssi > w.bestRssi) w.bestRssi = e.rssi;
    // Fire on PM-bit assoc-req RATE (1-MAC flood) OR distinct-src fan-out (multi-client).
    if (w.alerted || (w.frames < ASSOC_SLEEP_FRAMES && w.distinctSrc.size() < ASSOC_SLEEP_THRESH)) return;
    w.alerted = true;
    char bsBuf[18];
    snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    String bs(bsBuf);
    char lineBuf[260];
    snprintf(lineBuf, sizeof(lineBuf),
             "{\"bssid\":\"%s\",\"distinct_src\":%u,\"win_ms\":%u,\"rssi\":%d,\"ch\":%u,\"reason\":\"FORGE_ASSOC_SLEEP\",\"ts\":%u}",
             bsBuf, (unsigned)w.distinctSrc.size(), (unsigned)ASSOC_SLEEP_WIN_MS,
             (int)w.bestRssi, (unsigned)w.channel, (unsigned)now);
    logEventToSD("/assoc_sleep.jsonl", String(lineBuf));
    if (meshEnabled && meshRateGate(String("ASSOC_SLEEP_") + bs, 30000)) {
        char meshBuf[80];
        snprintf(meshBuf, sizeof(meshBuf), "%s: ASSOC_SLEEP:%s:%u:%d",
                 getNodeId().c_str(), bsBuf, (unsigned)w.distinctSrc.size(), (int)w.bestRssi);
        sendToSerial1(String(meshBuf), true);
    }
    ::detect_logIncident(String("ASSOC_SLEEP:") + bs + ":" + String((unsigned)w.distinctSrc.size()), bsBuf);
    quorum_addReport("ASSOC_SLEEP", bs, getNodeId(), w.bestRssi);
}

// =============================================================================
// Probe-flood / tool probe attack fingerprint
// tool probe-attack template (esp32_tool/WiFiScan.cpp:7763-7823):
//   - Seq ctrl = 0x01 0x00 (raw byte 22=0x01, byte 23=0x00) FIXED, never increments
//   - Post-SSID IE: HT Capabilities (tag 0x2D, len 0x1A) — unusual in probe-req
//   - 165 frames per tick from rotating random src MACs
// tool probe-flood does not use this signature (lower rate, varies).
// Detection here: per-BSSID running rate of seq=0x0001 probe-reqs containing 0x2D.
// =============================================================================
struct ProbeFloodWindow {
    uint32_t windowStartMs;
    uint16_t hits;         // probe-req frames matching tool fingerprint
    int8_t   bestRssi;
    uint8_t  channel;
    bool     alerted;
    char     ssid[33];
};
static std::map<uint64_t, ProbeFloodWindow> g_probeFlood;  // key = packMac(srcMac & 0xFEFFFFFFFFFF) — collapse LAA
static constexpr size_t MAX_PROBE_FLOOD_MAP = 64;
static constexpr uint16_t PROBE_FLOOD_WIN_MS = 5000;
static constexpr uint16_t PROBE_FLOOD_THRESH = 10;
static std::atomic<bool> g_probeFloodEnabled{true};

static bool probeReqHasHT(const uint8_t *ies, uint16_t ieLen) {
    uint16_t off = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ies[off];
        uint8_t l   = ies[off + 1];
        if ((size_t)off + 2 + l > (size_t)ieLen) break;
        if (tag == 0x2D) return true;  // HT Capabilities — tool fingerprint
        off += 2 + l;
    }
    return false;
}

// Behavioral fallback: distinct src MACs probing identical SSID in 5s window.
// Catches probe-flood variants that don't use the fixed seq=0x0001 fingerprint.
struct ProbeBehaveWindow {
    uint32_t windowStartMs;
    std::set<uint64_t> distinctSrc;
    int8_t bestRssi;
    uint8_t channel;
    bool alerted;
    char ssid[33];
};
static std::map<uint64_t, ProbeBehaveWindow> g_probeBehave;
static constexpr size_t MAX_PROBE_BEHAVE_MAP = 64;
static constexpr uint16_t PROBE_BEHAVE_WIN_MS = 5000;
// Threshold from academic IDS research: >40 distinct MACs probing same SSID in 5s
// is the suspicious-scanner-sweep range. Below that = busy-venue normal.
static constexpr uint8_t  PROBE_BEHAVE_THRESH = 40;

static void probeBehaveCheck(const uint8_t *src, const char *ssid, int8_t rssi,
                             uint8_t channel, uint32_t now) {
    if (!ssid || !ssid[0]) return;
    if (isSelfSsid(ssid)) return;
    uint64_t key = 0;
    for (int i = 0; i < 32 && ssid[i]; ++i) key = key * 131 + (uint8_t)ssid[i];
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_probeBehave.find(key);
    if (it == g_probeBehave.end() || (now - it->second.windowStartMs) > PROBE_BEHAVE_WIN_MS) {
        if (g_probeBehave.size() >= MAX_PROBE_BEHAVE_MAP) g_probeBehave.erase(g_probeBehave.begin());
        ProbeBehaveWindow w{};
        w.windowStartMs = now; w.bestRssi = rssi; w.channel = channel; w.alerted = false;
        strncpy(w.ssid, ssid, sizeof(w.ssid) - 1);
        w.distinctSrc.insert(packMac(src));
        g_probeBehave[key] = w;
        return;
    }
    ProbeBehaveWindow &w = it->second;
    w.distinctSrc.insert(packMac(src));
    if (rssi > w.bestRssi) w.bestRssi = rssi;
    if (w.alerted || w.distinctSrc.size() < PROBE_BEHAVE_THRESH) return;
    w.alerted = true;
    char lineBuf[260];
    snprintf(lineBuf, sizeof(lineBuf),
             "{\"ssid\":\"%s\",\"distinct_src\":%u,\"win_ms\":%u,\"rssi\":%d,\"ch\":%u,\"reason\":\"PROBE_FLOOD_BEHAVIORAL\",\"ts\":%u}",
             w.ssid, (unsigned)w.distinctSrc.size(), (unsigned)PROBE_BEHAVE_WIN_MS,
             (int)w.bestRssi, (unsigned)w.channel, (unsigned)now);
    logEventToSD("/probe_flood.jsonl", String(lineBuf));
    char rateKeyBuf[40];
    snprintf(rateKeyBuf, sizeof(rateKeyBuf), "PROBE_BEHAVE_%08X", (uint32_t)key);
    if (meshEnabled && meshRateGate(String(rateKeyBuf), 30000)) {
        char meshBuf[120];
        snprintf(meshBuf, sizeof(meshBuf), "%s: PROBE_FLOOD_BEHAVE:%s:src=%u:%d",
                 getNodeId().c_str(), w.ssid, (unsigned)w.distinctSrc.size(), (int)w.bestRssi);
        sendToSerial1(String(meshBuf), true);
    }
    quorum_addReport("PROBE_FLOOD", String(w.ssid), getNodeId(), w.bestRssi);
}

static void handleProbeReq(const DetectFrameEvent &e) {
    if (!g_probeFloodEnabled.load()) return;
    if (e.len < 26) return;
    const uint8_t *p = e.payload;
    if (isSelfMac(p + 10)) return;
    // Extract SSID for behavioral check (runs regardless of fingerprint match).
    const uint8_t *ieB = p + 24;
    uint16_t ieLenB = e.len - 24;
    char ssidB[33] = {0};
    if (ieLenB >= 2 && ieB[0] == 0) {
        uint8_t l = ieB[1];
        if (l <= 32 && (size_t)2 + l <= (size_t)ieLenB) {
            memcpy(ssidB, ieB + 2, l);
            ssidB[l] = 0;
        }
    }
    if (ssidB[0]) probeBehaveCheck(p + 10, ssidB, e.rssi, e.channel, millis());

    // tool template: seq ctrl bytes 22-23 = 0x01 0x00 (= seqCtrl LE 0x0001).
    uint16_t seqCtrl = (uint16_t)p[22] | ((uint16_t)p[23] << 8);
    if (seqCtrl != 0x0001) return;

    // Probe-request IE start = 24
    const uint8_t *ie = p + 24;
    uint16_t ieLen = e.len - 24;
    if (!probeReqHasHT(ie, ieLen)) return;

    const uint8_t *src = p + 10;
    char ssid[33] = {0};
    if (ieLen >= 2 && ie[0] == 0) {
        uint8_t l = ie[1];
        if (l <= 32 && (size_t)2 + l <= (size_t)ieLen) {
            memcpy(ssid, ie + 2, l);
            ssid[l] = 0;
        }
    }
    if (isSelfSsid(ssid)) return;

    uint64_t key = 0;
    for (int i = 0; i < 32 && ssid[i]; ++i) key = key * 131 + (uint8_t)ssid[i];
    if (key == 0) key = 0xDEADBEEFUL;  // anonymous bucket for empty SSID

    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_probeFlood.find(key);
    if (it == g_probeFlood.end() || (now - it->second.windowStartMs) > PROBE_FLOOD_WIN_MS) {
        if (g_probeFlood.size() >= MAX_PROBE_FLOOD_MAP) g_probeFlood.erase(g_probeFlood.begin());
        ProbeFloodWindow w{};
        w.windowStartMs = now;
        w.hits = 1;
        w.bestRssi = e.rssi;
        w.channel = e.channel;
        w.alerted = false;
        strncpy(w.ssid, ssid, sizeof(w.ssid) - 1);
        g_probeFlood[key] = w;
        return;
    }
    ProbeFloodWindow &w = it->second;
    if (w.hits < 65535) w.hits++;
    if (e.rssi > w.bestRssi) w.bestRssi = e.rssi;
    if (w.alerted || w.hits < PROBE_FLOOD_THRESH) return;
    w.alerted = true;
    String msg = String("{\"ssid\":\"") + w.ssid +
                 "\",\"hits\":" + String(w.hits) +
                 ",\"win_ms\":" + String(PROBE_FLOOD_WIN_MS) +
                 ",\"src_sample\":\"" + macStr(src) +
                 "\",\"rssi\":" + String(w.bestRssi) +
                 ",\"ch\":" + String(w.channel) +
                 ",\"reason\":\"FORGE_PROBE_FLOOD\"" +
                 ",\"ts\":" + String(now) + "}";
    logEventToSD("/probe_flood.jsonl", msg);
    if (meshEnabled && meshRateGate("PROBE_FLOOD_" + String((uint32_t)key, HEX), 30000)) {
        sendToSerial1(getNodeId() + ": PROBE_FLOOD:" + w.ssid + ":" + String(w.hits) + ":" + String(w.bestRssi), true);
    }
    quorum_addReport("PROBE_FLOOD", String(w.ssid), getNodeId(), w.bestRssi);
}

// =============================================================================
// SSID Confusion (CVE-2023-52424)
// =============================================================================
static void handleProbeResp(const DetectFrameEvent &e) {
    if (!g_ssidConfusionEnabled.load() && !g_karmaEnabled.load()) return;
    if (e.len < 36) return;
    const uint8_t *p = e.payload;
    const uint8_t *bssid = p + 16;
    const uint8_t *ie = p + 36;
    uint16_t ieLen = e.len - 36;
    char ssid[33] = {0};
    if (!extractSSID(ie, ieLen, ssid, sizeof(ssid))) return;
    if (ssid[0] == 0) return;

    if (g_karmaEnabled.load()) {
        karma_observeProbeResp(bssid, ssid, e.rssi);
        karma_checkBaitMatch(ssid, bssid, e.rssi);
    }
    if (!g_ssidConfusionEnabled.load()) return;

    uint64_t k = packMac(bssid);
    uint32_t now = millis();

    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_apBaseline.find(k);
    if (it == g_apBaseline.end()) return;  // need a beacon baseline first
    ApBaseline &b = it->second;
    if (b.ssid[0] == 0) return;
    if (strcmp(b.ssid, ssid) == 0) {
        strncpy(b.respSsid, ssid, sizeof(b.respSsid) - 1);
        return;
    }
    // Mismatch: probe-response SSID differs from beacon SSID for same BSSID
    SsidConfusionEvent ev{};
    memcpy(ev.bssid, bssid, 6);
    strncpy(ev.beaconSsid, b.ssid, sizeof(ev.beaconSsid) - 1);
    strncpy(ev.respSsid, ssid, sizeof(ev.respSsid) - 1);
    ev.rssi = e.rssi;
    ev.channel = e.channel;
    ev.ts = now;
    g_ssidConfusionLog.push_back(ev);
    if (g_ssidConfusionLog.size() > MAX_SC_LOG) g_ssidConfusionLog.erase(g_ssidConfusionLog.begin());

    char bsBuf[18];
    snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    String bs(bsBuf);
    char lineBuf[280];
    snprintf(lineBuf, sizeof(lineBuf),
             "{\"bssid\":\"%s\",\"beacon_ssid\":\"%s\",\"resp_ssid\":\"%s\",\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
             bsBuf, b.ssid, ssid, (int)e.rssi, (unsigned)e.channel, (unsigned)now);
    logEventToSD("/ssid_confusion.jsonl", String(lineBuf));
    if (meshEnabled) {
        if (g_meshSsidConf.load() && meshRateGate(String("SSIDCONF_") + bs, 30000)) {
            char meshBuf[80];
            snprintf(meshBuf, sizeof(meshBuf), "%s: SSID_CONFUSION:%s:%d",
                     getNodeId().c_str(), bsBuf, (int)e.rssi);
            sendToSerial1(String(meshBuf), true);
        }
    }
    quorum_addReport("SSIDCONF", bs, getNodeId(), e.rssi);
    strncpy(b.respSsid, ssid, sizeof(b.respSsid) - 1);
}

// =============================================================================
// SAE / Dragonblood DoS
// =============================================================================
static void handleAuthSae(const DetectFrameEvent &e) {
    // 802.11 auth: fixed body at +24 = algo(2) seq(2) status(2)
    if (e.len < 30) return;
    const uint8_t *p = e.payload;
    uint16_t algo = (uint16_t)p[24] | ((uint16_t)p[25] << 8);
    if (::g_detectVerbose.load()) {
        uint16_t vseq = (uint16_t)p[26] | ((uint16_t)p[27] << 8);
        Serial.printf("[VERIFY-AUTH] algo=%u seq=%u ch=%u rssi=%d saeOn=%d\n",
                      algo, vseq, (unsigned)e.channel, (int)e.rssi, (int)g_saeEnabled.load());
    }

    if (algo == 0) {
        const uint8_t *src   = p + 10;
        const uint8_t *bss   = p + 16;
        if (isSelfMac(src)) return;
        uint64_t bk = packMac(bss);
        uint64_t sk = packMac(src);
        uint32_t tnow = millis();
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        auto ai = g_authFlood.find(bk);
        if (ai == g_authFlood.end() || (tnow - ai->second.windowStartMs) > AUTH_FLOOD_WIN_MS) {
            if (g_authFlood.size() >= MAX_AUTH_FLOOD_MAP) g_authFlood.erase(g_authFlood.begin());
            AuthFloodWindow w{};
            w.windowStartMs = tnow; w.frames = 1; w.bestRssi = e.rssi;
            w.channel = e.channel; w.alerted = false; w.distinctSrc.insert(sk);
            g_authFlood[bk] = w;
            return;
        }
        AuthFloodWindow &w = ai->second;
        if (w.frames < 65535) w.frames++;
        w.distinctSrc.insert(sk);
        if (e.rssi > w.bestRssi) w.bestRssi = e.rssi;
        if (!w.alerted && w.distinctSrc.size() >= AUTH_FLOOD_DISTINCT_SRC &&
            w.frames >= AUTH_FLOOD_FRAMES) {
            w.alerted = true;
            char bsBuf[18];
            snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     bss[0],bss[1],bss[2],bss[3],bss[4],bss[5]);
            String bs(bsBuf);
            Serial.printf("[DETECT] AUTH_FLOOD bssid=%s distinct_src=%u frames=%u in %ums\n",
                          bsBuf, (unsigned)w.distinctSrc.size(), (unsigned)w.frames,
                          (unsigned)(tnow - w.windowStartMs));
            ::detect_logIncident(String("AUTH_FLOOD:") + bs + ":" + String((unsigned)w.distinctSrc.size()) + ":" + String((int)w.bestRssi), bsBuf);
            char lb[260];
            snprintf(lb, sizeof(lb),
                     "{\"bssid\":\"%s\",\"distinct_src\":%u,\"frames\":%u,\"win_ms\":%u,\"rssi\":%d,\"ch\":%u,\"reason\":\"AUTH_DOS\",\"ts\":%u}",
                     bsBuf, (unsigned)w.distinctSrc.size(), (unsigned)w.frames,
                     (unsigned)AUTH_FLOOD_WIN_MS, (int)w.bestRssi, (unsigned)w.channel, (unsigned)tnow);
            logEventToSD("/sae_dos.jsonl", String(lb));
            if (meshEnabled && g_meshSae.load() && meshRateGate(String("AUTH_FLOOD_") + bs, 30000)) {
                char mb[80];
                snprintf(mb, sizeof(mb), "%s: AUTH_FLOOD:%s:%u:%d",
                         getNodeId().c_str(), bsBuf, (unsigned)w.distinctSrc.size(), (int)w.bestRssi);
                sendToSerial1(String(mb), true);
            }
            quorum_addReport("AUTH_FLOOD", bs, getNodeId(), w.bestRssi);
            attacker_kick(bss, "AUTH_FLOOD");
        }
        return;
    }

    if (!g_saeEnabled.load()) return;
    if (algo != 3) return;
    uint16_t seq = (uint16_t)p[26] | ((uint16_t)p[27] << 8);
    const uint8_t *bssid = p + 16;
    uint64_t k = packMac(bssid);
    uint32_t now = millis();
    uint16_t win = g_saeWindow.load();

    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    SaeCounter &c = g_saeCounters[k];
    if (c.windowStart == 0 || now - c.windowStart > win) {
        c.windowStart = now;
        c.commits = 0;
        c.confirms = 0;
        c.alerted = false;
    }
    if (seq == 1) c.commits++;
    else if (seq == 2) c.confirms++;
    uint16_t unmatched = (c.commits > c.confirms) ? (c.commits - c.confirms) : 0;
    if (!c.alerted && unmatched >= g_saeUnmatchedThresh.load()) {
        c.alerted = true;
        SaeDosEvent ev{};
        memcpy(ev.bssid, bssid, 6);
        ev.unmatchedCommits = unmatched;
        ev.rssi = e.rssi;
        ev.channel = e.channel;
        ev.windowStart = c.windowStart;
        ev.ts = now;
        g_saeDosLog.push_back(ev);
        if (g_saeDosLog.size() > MAX_SAE_LOG) g_saeDosLog.erase(g_saeDosLog.begin());

        char bsBuf[18];
        snprintf(bsBuf, sizeof(bsBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
        String bs(bsBuf);
        char lineBuf[260];
        snprintf(lineBuf, sizeof(lineBuf),
                 "{\"bssid\":\"%s\",\"unmatched_commits\":%u,\"rssi\":%d,\"ch\":%u,\"window_start\":%u,\"ts\":%u}",
                 bsBuf, (unsigned)unmatched, (int)e.rssi, (unsigned)e.channel,
                 (unsigned)c.windowStart, (unsigned)now);
        logEventToSD("/sae_dos.jsonl", String(lineBuf));
        ::detect_logIncident(String("SAE_DOS:") + bs + ":" + String((unsigned)unmatched), bsBuf);
        if (meshEnabled && g_meshSae.load() && meshRateGate(String("SAE_DOS_") + bs, 10000)) {
            char meshBuf[80];
            snprintf(meshBuf, sizeof(meshBuf), "%s: SAE_DOS:%s:%u",
                     getNodeId().c_str(), bsBuf, (unsigned)unmatched);
            sendToSerial1(String(meshBuf), true);
        }
        quorum_addReport("SAE_DOS", bs, getNodeId(), e.rssi);
        attacker_kick(bssid, "SAE_DOS");
    }
}

// =============================================================================
// FragAttacks A-MSDU + PN reuse
// =============================================================================
static void handleQosData(const DetectFrameEvent &e) {
    if (e.len < 38) return;
    const uint8_t *p = e.payload;
    uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint8_t stype = (fc >> 4) & 0xF;
    uint8_t ftype = (fc >> 2) & 0x3;
    if (ftype != 2 || stype != 8) return;
    uint8_t toDs   = (fc >> 8) & 1;
    uint8_t fromDs = (fc >> 9) & 1;
    uint8_t protectedBit = (fc >> 14) & 1;
    if (!protectedBit) return;
    const uint8_t *a1 = p + 4;
    if (a1[0] & 0x01) return;
    const uint8_t *a2 = p + 10;
    uint8_t hdrLen = 24 + 2;
    bool fourAddr = (toDs == 1 && fromDs == 1);
    if (fourAddr) hdrLen += 6;
    if ((int)e.len < hdrLen + 8) return;
    uint8_t qos0 = p[hdrLen - 2];
    uint8_t tid = qos0 & 0x0F;
    uint8_t aMsdu = (qos0 >> 7) & 1;

    const uint8_t *cc = p + hdrLen;
    if (!(cc[3] & 0x20)) return;
    uint32_t pn32 = ((uint32_t)cc[5] << 24) | ((uint32_t)cc[4] << 16) |
                    ((uint32_t)cc[1] << 8)  |  cc[0];

    if (!g_fragEnabled.load()) return;
    uint64_t key = (packMac(a2) << 4) | tid;
    uint32_t now = millis();

    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_pnState.find(key);
    if (it == g_pnState.end()) {
        if (g_pnState.size() >= 64) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_pnState) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_pnState.erase(oldestK);
        }
        g_pnState[key] = {pn32, now, 0};
        return;
    }
    uint32_t lastPN = it->second.lastPN;
    bool exactReuse = (pn32 == lastPN);
    if (exactReuse) {
        if (it->second.reuseCount < 255) it->second.reuseCount++;
    } else {
        it->second.reuseCount = 0;
    }
    bool sustainedReuse = it->second.reuseCount >= g_fragReuseThresh.load();
    bool fired = false;
    FragAttackEvent ev{};
    memcpy(ev.srcMac, a2, 6);
    ev.tid = tid;
    ev.lastPN = lastPN;
    ev.observedPN = pn32;
    ev.rssi = e.rssi;
    ev.channel = e.channel;
    ev.ts = now;
    if (sustainedReuse) { strncpy(ev.reason, "PN_REUSE", sizeof(ev.reason) - 1); fired = true; it->second.reuseCount = 0; }
    if (aMsdu && sustainedReuse) {
        strncpy(ev.reason, "AMSDU_BAD", sizeof(ev.reason) - 1);
    }
    if (fired) {
        g_fragLog.push_back(ev);
        if (g_fragLog.size() > MAX_FRAG_LOG) g_fragLog.erase(g_fragLog.begin());
        char srcBuf[18];
        snprintf(srcBuf, sizeof(srcBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 a2[0],a2[1],a2[2],a2[3],a2[4],a2[5]);
        String src(srcBuf);
        char lineBuf[260];
        snprintf(lineBuf, sizeof(lineBuf),
                 "{\"src\":\"%s\",\"tid\":%u,\"reason\":\"%s\",\"last_pn\":%u,\"obs_pn\":%u,\"rssi\":%d,\"ch\":%u,\"ts\":%u}",
                 srcBuf, (unsigned)tid, ev.reason, (unsigned)ev.lastPN,
                 (unsigned)ev.observedPN, (int)e.rssi, (unsigned)e.channel, (unsigned)now);
        logEventToSD("/fragattack.jsonl", String(lineBuf));
        if (meshEnabled && g_meshFrag.load() && meshRateGate(String("FRAG_") + src, 30000)) {
            char meshBuf[80];
            snprintf(meshBuf, sizeof(meshBuf), "%s: FRAG:%s:%s",
                     getNodeId().c_str(), srcBuf, ev.reason);
            sendToSerial1(String(meshBuf), true);
        }
    }
    it->second.lastPN = pn32;
    it->second.lastSeen = now;
}

// =============================================================================
// BLE tracker watchlist + BLE malformed PDU
// =============================================================================
struct WatchEntry {
    uint16_t serviceUuid;   // 0 means use mfgId check
    uint16_t mfgId;         // 0xFFFF if N/A
    uint8_t mfgPrefixLen;
    uint8_t mfgPrefix[4];
    const char *vendor;
};
static const WatchEntry kWatch[] = {
    {0xFEEC, 0xFFFF, 0, {0,0,0,0}, "TileUnreg"},
    {0xFEED, 0xFFFF, 0, {0,0,0,0}, "Tile"},
    {0xFD59, 0xFFFF, 0, {0,0,0,0}, "SmartTagUnreg"},
    {0xFD5A, 0xFFFF, 0, {0,0,0,0}, "SamsungSmartTag"},
    {0xFEAA, 0xFFFF, 1, {0x40,0,0,0}, "GoogleFMDN"},
    {0xFFFA, 0xFFFF, 1, {0x0D,0,0,0}, "OpenDroneID"},
    {0,       0x004C, 2, {0x12,0x19,0,0}, "AirTag_or_FindMy"},
    {0,       0x004C, 1, {0x07,0,0,0}, "AppleProxPair"},
    {0,       0x004C, 1, {0x10,0,0,0}, "AppleNearby"},
    {0,       0x004C, 0, {0,0,0,0}, "Apple"},
    {0,       0x0075, 0, {0,0,0,0}, "Samsung"},
};

static bool parseAdvForWatch(const uint8_t *p, uint16_t len, WatchEntry &outMatch) {
    uint16_t off = 0;
    while (off + 2 <= len) {
        uint8_t l = p[off];
        if (l == 0) { off += 1; continue; }
        if (off + 1 + l > len) return false;
        uint8_t adType = p[off + 1];
        if (adType == 0x16 && l >= 3) {
            uint16_t uuid = (uint16_t)p[off + 2] | ((uint16_t)p[off + 3] << 8);
            for (const auto &w : kWatch) {
                if (w.serviceUuid != uuid) continue;
                if (w.mfgPrefixLen == 0) { outMatch = w; return true; }
                if (l >= 3 + w.mfgPrefixLen &&
                    memcmp(&p[off + 4], w.mfgPrefix, w.mfgPrefixLen) == 0) {
                    outMatch = w; return true;
                }
            }
        }
        if (adType == 0xFF && l >= 3) {
            uint16_t mfg = (uint16_t)p[off + 2] | ((uint16_t)p[off + 3] << 8);
            for (const auto &w : kWatch) {
                if (w.serviceUuid != 0) continue;
                if (w.mfgId != mfg) continue;
                if (w.mfgPrefixLen == 0) { outMatch = w; return true; }
                if (l >= 3 + w.mfgPrefixLen &&
                    memcmp(&p[off + 4], w.mfgPrefix, w.mfgPrefixLen) == 0) {
                    outMatch = w; return true;
                }
            }
        }
        off += 1 + l;
    }
    return false;
}

static bool validateBleAdvStructure(const uint8_t *p, uint16_t len, const char **reason) {
    if (len > 254) { *reason = "PAYLOAD_OVERLEN"; return false; }
    uint16_t off = 0;
    while (off < len) {
        uint8_t l = p[off];
        if (l == 0) { off += 1; continue; }
        if (off + 1 + l > len) { *reason = "BAD_LEN_FIELD"; return false; }
        off += 1 + l;
    }
    return true;
}

// BLE attack-tool fingerprint table — byte matches from tool/tool audit.
struct BleAttackSig {
    uint8_t pattern[10];
    uint8_t patLen;
    const char *tool;
    const char *family;
};
static const BleAttackSig BLE_ATTACK_SIGS[] = {
    // Sour Apple / Apple Actions — `FF 4C 00 0F 05 C0` (tool) or `FF 4C 00 0F 05 C1` (tool)
    {{0xFF, 0x4C, 0x00, 0x0F, 0x05, 0xC0}, 6, "SourApple_TypeA",   "apple_action"},
    {{0xFF, 0x4C, 0x00, 0x0F, 0x05, 0xC1}, 6, "SourApple_TypeB",      "apple_action"},
    // Apple Juice / HomePod Continuity bait — `4C 00 04 04 2A 00 00 00 0F 05`
    {{0x4C, 0x00, 0x04, 0x04, 0x2A, 0x00, 0x00, 0x00, 0x0F, 0x05}, 10, "AppleJuice_Continuity", "apple_continuity"},
    // Samsung BLE Spam — `FF 75 00 01 00 02 00 01 01 FF`
    {{0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF}, 10, "Samsung_Spam",         "samsung"},
    // Microsoft Swift Pair — `FF 06 00 03 00 80`
    {{0xFF, 0x06, 0x00, 0x03, 0x00, 0x80}, 6, "Microsoft_SwiftPair",  "swiftpair"},
    // Flipper Zero spoof — `FF BA 0F 4C 75 67 26 E1 80` (mfg ID 0x0FBA + payload prefix)
    {{0xFF, 0xBA, 0x0F, 0x4C, 0x75, 0x67, 0x26, 0xE1, 0x80}, 9, "Flipper_Spoof",        "flipper"},
    // Google Fast Pair — tool hardcoded model ID 0x00B727: `16 2C FE 00 B7 27`
    {{0x16, 0x2C, 0xFE, 0x00, 0xB7, 0x27}, 6, "FastPair_TypeA",    "fastpair"},
};
static constexpr size_t BLE_ATTACK_SIG_COUNT = sizeof(BLE_ATTACK_SIGS) / sizeof(BLE_ATTACK_SIGS[0]);

struct BleAttackEvent {
    uint8_t addr[6];
    int8_t rssi;
    uint32_t ts;
    char tool[32];
    char family[24];
};
static std::vector<BleAttackEvent> g_bleAttackLog;
static constexpr size_t MAX_BLE_ATTACK_LOG = 100;
static std::map<uint64_t, uint32_t> g_bleAttackSeen;  // suppress duplicate (addr,tool) within 30s
static std::atomic<bool> g_bleAttackEnabled{true};

static bool bleScanForSig(const uint8_t *payload, uint16_t len, const BleAttackSig &sig) {
    if (len < sig.patLen) return false;
    for (uint16_t i = 0; i + sig.patLen <= len; ++i) {
        if (memcmp(payload + i, sig.pattern, sig.patLen) == 0) return true;
    }
    return false;
}

static void emitBleAttack(const uint8_t *addr, int8_t rssi, const BleAttackSig &sig) {
    uint64_t k = packMac(addr);
    uint32_t now = millis();
    auto it = g_bleAttackSeen.find(k);
    if (it != g_bleAttackSeen.end() && (now - it->second) < 30000) return;  // dedup
    g_bleAttackSeen[k] = now;
    if (g_bleAttackSeen.size() > 128) {
        // GC: drop ones older than 60s
        for (auto i = g_bleAttackSeen.begin(); i != g_bleAttackSeen.end(); ) {
            if (now - i->second > 60000) i = g_bleAttackSeen.erase(i); else ++i;
        }
    }
    BleAttackEvent ev{};
    memcpy(ev.addr, addr, 6);
    ev.rssi = rssi;
    ev.ts = now;
    strncpy(ev.tool,   sig.tool,   sizeof(ev.tool)   - 1);
    strncpy(ev.family, sig.family, sizeof(ev.family) - 1);
    g_bleAttackLog.push_back(ev);
    if (g_bleAttackLog.size() > MAX_BLE_ATTACK_LOG) g_bleAttackLog.erase(g_bleAttackLog.begin());

    String a = macStr(addr);
    String line = String("{\"addr\":\"") + a +
                  "\",\"tool\":\"" + ev.tool +
                  "\",\"family\":\"" + ev.family +
                  "\",\"rssi\":" + String(rssi) +
                  ",\"ts\":" + String(now) + "}";
    logEventToSD("/ble_attack.jsonl", line);
    if (meshEnabled && meshRateGate(String("BLEATK_") + ev.tool + "_" + a, 30000)) {
        sendToSerial1(getNodeId() + ": BLE_ATTACK:" + ev.tool + ":" + a + ":" + String(rssi), true);
    }
    quorum_addReport("BLE_ATTACK", a, getNodeId(), rssi);
}

void onBleAdv(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len, const char *name) {
    (void)name;
    if (!g_detectEnabled.load()) return;
    uint32_t now = millis();

    // tool/tool BLE attack-tool fingerprint scan — strong byte matches.
    if (g_bleAttackEnabled.load() && payload && len >= 6) {
        std::lock_guard<std::recursive_mutex> lkA(g_mtx);
        for (size_t i = 0; i < BLE_ATTACK_SIG_COUNT; ++i) {
            if (bleScanForSig(payload, len, BLE_ATTACK_SIGS[i])) {
                emitBleAttack(addr, rssi, BLE_ATTACK_SIGS[i]);
                break;  // one match per adv frame is enough
            }
        }

        // tool Google Fast Pair rate anomaly:
        // tool rotates through 60+ model IDs. Real Fast Pair beacons repeat one
        // model ID. Look for service-data IE `16 2C FE <m1> <m2> <m3>` and track
        // distinct (m1,m2,m3) tuples from same source addr in a 5s window.
        // >=3 distinct model IDs from one addr → bait.
        static uint32_t fpWinStart = 0;
        static std::set<uint32_t> fpModels;
        static uint64_t fpAddr = 0;
        static bool fpAlerted = false;
        static const uint8_t FP_HDR[3] = {0x16, 0x2C, 0xFE};
        for (uint16_t i = 0; i + 5 < len; ++i) {
            if (memcmp(payload + i, FP_HDR, 3) != 0) continue;
            uint32_t model = ((uint32_t)payload[i+3] << 16) | ((uint32_t)payload[i+4] << 8) | payload[i+5];
            uint32_t nowM = millis();
            uint64_t addrK = packMac(addr);
            if (fpWinStart == 0 || (nowM - fpWinStart) > 5000 || fpAddr != addrK) {
                fpWinStart = nowM; fpAddr = addrK; fpModels.clear(); fpAlerted = false;
            }
            fpModels.insert(model);
            if (!fpAlerted && fpModels.size() >= 3) {
                fpAlerted = true;
                String a = macStr(addr);
                String line = String("{\"addr\":\"") + a +
                              "\",\"distinct_models\":" + String((unsigned)fpModels.size()) +
                              ",\"win_ms\":5000,\"rssi\":" + String(rssi) +
                              ",\"reason\":\"FASTPAIR_ROTATE\"" +
                              ",\"ts\":" + String(nowM) + "}";
                logEventToSD("/ble_attack.jsonl", line);
                if (meshEnabled && meshRateGate("FP_ROTATE_" + a, 30000)) {
                    sendToSerial1(getNodeId() + ": BLE_ATTACK:FastPair_Rotate:" + a +
                                  ":models=" + String(fpModels.size()), true);
                }
                quorum_addReport("BLE_ATTACK", String("FastPair_Rotate"), getNodeId(), rssi);
            }
            break;
        }

        // tool AirPods iOS-spam rate anomaly:
        // tool/tool cycle ALL Apple proximity-pair types (10+) at 100ms intervals
        // from rotating MACs. Research: real Apple devices never cycle types — one
        // device, one type, stable. 3+ distinct types from different MACs in 1s = impossible legit.
        static uint32_t iosWinStart = 0;
        static std::set<uint8_t>  iosTypes;
        static std::set<uint64_t> iosAddrs;
        static bool iosAlerted = false;
        static const uint8_t IOS_HDR[6] = {0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07};
        for (uint16_t i = 0; i + 6 < len; ++i) {
            if (memcmp(payload + i, IOS_HDR, 6) != 0) continue;
            uint8_t typeByte = payload[i + 6];
            uint32_t nowM = millis();
            // 1s window — research-cited "impossible legit" interval.
            if (iosWinStart == 0 || (nowM - iosWinStart) > 1000) {
                iosWinStart = nowM; iosTypes.clear(); iosAddrs.clear(); iosAlerted = false;
            }
            iosTypes.insert(typeByte);
            iosAddrs.insert(packMac(addr));
            if (!iosAlerted && iosTypes.size() >= 3 && iosAddrs.size() >= 3) {
                iosAlerted = true;
                String a = macStr(addr);
                String line = String("{\"addr\":\"") + a +
                              "\",\"distinct_types\":" + String((unsigned)iosTypes.size()) +
                              ",\"distinct_addrs\":" + String((unsigned)iosAddrs.size()) +
                              ",\"win_ms\":1000" +
                              ",\"rssi\":" + String(rssi) +
                              ",\"reason\":\"IOS_PAIR_SPAM\"" +
                              ",\"ts\":" + String(nowM) + "}";
                logEventToSD("/ble_attack.jsonl", line);
                if (meshEnabled && meshRateGate("IOS_SPAM", 30000)) {
                    sendToSerial1(getNodeId() + ": BLE_ATTACK:iOS_Pair_Spam:" + a +
                                  ":types=" + String(iosTypes.size()) +
                                  ":addrs=" + String(iosAddrs.size()), true);
                }
                quorum_addReport("BLE_ATTACK", String("iOS_Pair_Spam"), getNodeId(), rssi);
            }
            break;
        }
    }

    // Phase 3.2 BLE ODID Remote ID — Service Data 16-bit UUID 0xFFFA
    // (AD type 0x16, UUID bytes FA FF little-endian). Done here in task
    // context, not in nimble_host callback.
    if (len >= 8 && payload) {
        size_t off = 0;
        while (off + 2 <= len) {
            uint8_t l = payload[off];
            if (l == 0) { off += 1; continue; }
            if (off + 1 + l > len) break;
            uint8_t adType = payload[off + 1];
            if (adType == 0x16 && l >= 4 &&
                payload[off + 2] == 0xFA && payload[off + 3] == 0xFF) {
                size_t odidLen = len - (off + 4);
                processDroneOdidBle(addr, rssi, payload + off + 4, (int)odidLen);
                break;
            }
            off += 1 + l;
        }
    }
    const char *malformedReason = nullptr;
    if (g_bleMalformedEnabled.load() && !validateBleAdvStructure(payload, len, &malformedReason) && malformedReason) {
        BleMalformedEvent ev{};
        memcpy(ev.addr, addr, 6);
        ev.rssi = rssi;
        strncpy(ev.reason, malformedReason, sizeof(ev.reason) - 1);
        ev.payloadLen = len;
        ev.ts = now;
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        g_bleMalformedLog.push_back(ev);
        if (g_bleMalformedLog.size() > MAX_BLEM_LOG) g_bleMalformedLog.erase(g_bleMalformedLog.begin());
        String addr_s = macStr(addr);
        String line = String("{\"addr\":\"") + addr_s +
                      "\",\"rssi\":" + String(rssi) +
                      ",\"reason\":\"" + malformedReason +
                      "\",\"len\":" + String(len) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/ble_malformed.jsonl", line);
        return;
    }
    if (!g_trackerEnabled.load() && !g_airtagEnabled.load()) return;
    WatchEntry match{};
    if (!parseAdvForWatch(payload, len, match)) return;

    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (g_airtagEnabled.load()) airtagProcess(addr, rssi, payload, len);
    if (!g_trackerEnabled.load()) return;
    uint64_t k = packMac(addr);
    auto it = g_bleTrackers.find(k);
    if (it == g_bleTrackers.end()) {
        if (g_bleTrackers.size() >= MAX_TRACKER_MAP) {
            // evict oldest
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_bleTrackers) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_bleTrackers.erase(oldestK);
        }
        BleTrackerSighting s{};
        memcpy(s.addr, addr, 6);
        s.serviceUuid = match.serviceUuid;
        s.mfgId = match.mfgId;
        strncpy(s.vendor, match.vendor, sizeof(s.vendor) - 1);
        s.firstSeen = now;
        s.lastSeen = now;
        s.sightingCount = 1;
        s.avgRssi = rssi;
        s.rssiVarN = 0;
        s.persistenceScore = 10;
        s.followAlerted = false;
        g_bleTrackers[k] = s;
        trackerSweepVanished(now);
        trackerTryLinkRotation(addr, match.vendor, rssi, now);
        return;
    }
    BleTrackerSighting &s = it->second;
    uint32_t gap = now - s.lastSeen;
    if (gap >= g_trackerGapMs.load()) {
        s.sightingCount++;
    }
    s.lastSeen = now;
    // Update avg/var
    s.avgRssi = (int8_t)(((int)s.avgRssi * 7 + rssi) / 8);
    int diff = rssi - s.avgRssi;
    if (diff < 0) diff = -diff;
    if (diff > 4) s.rssiVarN = (s.rssiVarN < 250) ? s.rssiVarN + 1 : s.rssiVarN;

    // Persistence score: time-window-based
    uint32_t windowDur = now - s.firstSeen;
    uint8_t score = 0;
    if (windowDur > 15UL * 60UL * 1000UL) score += 20;
    if (windowDur > 60UL * 60UL * 1000UL) score += 20;
    if (windowDur > g_trackerWindowMs.load()) score += 30;
    if (s.sightingCount >= g_trackerMinSightings.load()) score += 20;
    if (s.rssiVarN < 10) score += 10;   // low variance = stationary follower
    s.persistenceScore = (score > 100) ? 100 : score;

    bool followCriteria = (s.sightingCount >= g_trackerMinSightings.load()) &&
                          (windowDur >= g_trackerWindowMs.load());
    if (followCriteria && !s.followAlerted) {
        s.followAlerted = true;
        String a_s = macStr(addr);
        String line = String("{\"addr\":\"") + a_s +
                      "\",\"vendor\":\"" + match.vendor +
                      "\",\"sightings\":" + String(s.sightingCount) +
                      ",\"window_ms\":" + String(windowDur) +
                      ",\"score\":" + String(s.persistenceScore) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/ble_follow.jsonl", line);
        if (meshEnabled && g_meshTracker.load() && meshRateGate("BLETRACK_" + a_s, 60000)) {
            sendToSerial1(getNodeId() + ": BLETRACK:" + a_s + ":" + match.vendor + ":" + String(s.persistenceScore), true);
        }
        quorum_addReport("BLETRACK", a_s, getNodeId(), rssi);
    }
}

// =============================================================================
// RID claim validation
// =============================================================================
static float haversineMeters(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371000.0;
    double dLat = (lat2 - lat1) * 0.0174532925;
    double dLon = (lon2 - lon1) * 0.0174532925;
    double a = sin(dLat/2)*sin(dLat/2) +
               cos(lat1*0.0174532925)*cos(lat2*0.0174532925)*sin(dLon/2)*sin(dLon/2);
    double c = 2 * atan2(sqrt(a), sqrt(1-a));
    return (float)(R * c);
}

// RSSI → distance via free-space + path-loss model (n=2.5 default outdoor)
static float rssiToMeters(int8_t rssi) {
    const float rssi0 = -45.0f;  // RSSI at 1m
    const float n = 2.5f;
    return powf(10.0f, (rssi0 - rssi) / (10.0f * n));
}

void recordRidClaim(const char *uavId, double lat, double lon, float alt, int8_t rssi) {
    if (!uavId || uavId[0] == 0) return;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto &c = g_ridClaims[uavId];
    strncpy(c.uavId, uavId, sizeof(c.uavId) - 1);
    c.lat = lat;
    c.lon = lon;
    c.alt = alt;
    c.ts = now;
    RidClaim::Rx rx;
    rx.nodeId = getNodeId();
    rx.rssi = rssi;
    rx.hasGps = gpsValid;
    rx.nodeLat = gpsLat;
    rx.nodeLon = gpsLon;
    rx.ts = now;
    c.rxs.push_back(rx);
    if (c.rxs.size() > 16) c.rxs.erase(c.rxs.begin());

    if (meshEnabled) {
        char buf[160];
        snprintf(buf, sizeof(buf), "%s: RID_RX:%s:%d:%.6f:%.6f:%d",
                 getNodeId().c_str(), uavId, (int)rssi,
                 (double)gpsLat, (double)gpsLon, gpsValid ? 1 : 0);
        sendToSerial1(String(buf), true);
        snprintf(buf, sizeof(buf), "%s: RID_CLAIM:%s:%.6f:%.6f:%.1f",
                 getNodeId().c_str(), uavId, lat, lon, alt);
        sendToSerial1(String(buf), true);
    }

    int gpsCount = 0;
    bool geomViolation = false;
    bool anyClose = false;
    for (auto &rx2 : c.rxs) if (rx2.hasGps) gpsCount++;
    if (gpsCount >= 2) {
        for (auto &rx2 : c.rxs) {
            if (!rx2.hasGps) continue;
            float claimedDist = haversineMeters(rx2.nodeLat, rx2.nodeLon, lat, lon);
            float rssiDist = rssiToMeters(rx2.rssi);
            float ratio = (claimedDist > 1.0f) ? (rssiDist / claimedDist) : 0.0f;
            if (claimedDist > 2000.0f && rssiDist < 200.0f) anyClose = true;
            if (ratio > 5.0f || ratio < 0.05f) geomViolation = true;
        }
        c.verified = !geomViolation && !anyClose;
        c.insufficient = false;
    } else {
        c.insufficient = true;
        c.verified = false;
    }
}
// =============================================================================
// Feature 12: Inter-node ToF / link-quality via mesh ping
// =============================================================================
struct TofPendingPing {
    uint32_t seqId;
    uint64_t txUs;
    char target[16];
};
static std::map<String, TofPeer> g_tofPeers;
static std::vector<TofPendingPing> g_tofPending;
static std::atomic<uint32_t> g_tofSeq{1};
static constexpr size_t MAX_TOF_PENDING = 16;
static constexpr size_t MAX_TOF_PEERS   = 32;

void tof_ping(const char *targetNode) {
    if (!targetNode || !meshEnabled) return;
    uint32_t seq = g_tofSeq.fetch_add(1);
    uint64_t txUs = getDisciplinedMicros();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (g_tofPending.size() >= MAX_TOF_PENDING) g_tofPending.erase(g_tofPending.begin());
    TofPendingPing p{};
    p.seqId = seq;
    p.txUs = txUs;
    strncpy(p.target, targetNode, sizeof(p.target) - 1);
    g_tofPending.push_back(p);
    char buf[96];
    snprintf(buf, sizeof(buf), "%s: TOF_PING:%s:%u:%llu",
             getNodeId().c_str(), targetNode, (unsigned)seq, (unsigned long long)txUs);
    sendToSerial1(String(buf), true);
}

void tof_broadcastPing() { tof_ping("*"); }

void tof_processPing(const String &fromNode, uint32_t seq, uint64_t theirTxUs) {
    if (!meshEnabled) return;
    uint64_t rxUs = getDisciplinedMicros();
    char buf[176];
    snprintf(buf, sizeof(buf), "%s: TOF_PONG:%s:%u:%llu:%llu",
             getNodeId().c_str(), fromNode.c_str(), (unsigned)seq,
             (unsigned long long)theirTxUs,
             (unsigned long long)rxUs);
    sendToSerial1(String(buf), true);
}

void tof_processPong(const String &fromNode, uint32_t seqHint, uint64_t origTxEcho, uint64_t theirRxUs) {
    uint64_t rxUs = getDisciplinedMicros();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    uint64_t origTxUs = 0;
    bool matched = false;
    for (auto it = g_tofPending.begin(); it != g_tofPending.end(); ) {
        if (rxUs - it->txUs > 5000000ULL) { it = g_tofPending.erase(it); continue; }
        if (it->seqId == seqHint &&
            (String(it->target) == fromNode || String(it->target) == "*")) {
            origTxUs = it->txUs;
            it = g_tofPending.erase(it);
            matched = true;
            break;
        }
        ++it;
    }
    if (!matched) return;
    if (origTxEcho != 0 && origTxEcho != origTxUs) return;
    uint64_t totalRtt = rxUs - origTxUs;
    uint64_t netRtt = totalRtt;
    if (theirRxUs > origTxEcho && origTxEcho > 0) {
        uint64_t remoteProc = (theirRxUs > origTxEcho) ? (theirRxUs - origTxEcho) : 0;
        if (remoteProc < totalRtt) netRtt = totalRtt - remoteProc;
    }

    auto pit = g_tofPeers.find(fromNode);
    if (pit == g_tofPeers.end()) {
        if (g_tofPeers.size() >= MAX_TOF_PEERS) {
            String oldestKey;
            uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_tofPeers) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestKey = kv.first; }
            if (oldestKey.length()) g_tofPeers.erase(oldestKey);
        }
        TofPeer np{};
        strncpy(np.nodeId, fromNode.c_str(), sizeof(np.nodeId) - 1);
        np.bestRttUs = netRtt;
        np.avgRttUs = netRtt;
        np.lastRttUs = netRtt;
        np.samples = 1;
        np.lastSeen = millis();
        np.estDistanceM = -1;
        g_tofPeers[fromNode] = np;
        return;
    }
    TofPeer &peer = pit->second;
    if (netRtt < peer.bestRttUs) peer.bestRttUs = netRtt;
    peer.avgRttUs = (peer.avgRttUs * 7 + netRtt) / 8;
    peer.lastRttUs = netRtt;
    peer.samples++;
    peer.lastSeen = millis();
    peer.estDistanceM = -1;
}

String tof_getPeersJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_tofPeers) {
        if (!first) out += ",";
        first = false;
        out += "{\"node\":\"" + String(kv.second.nodeId) + "\"" +
               ",\"last_rtt_us\":" + String((unsigned long)kv.second.lastRttUs) +
               ",\"best_rtt_us\":" + String((unsigned long)kv.second.bestRttUs) +
               ",\"avg_rtt_us\":" + String((unsigned long)kv.second.avgRttUs) +
               ",\"samples\":" + String(kv.second.samples) +
               ",\"est_dist_m\":" + String(kv.second.estDistanceM) +
               ",\"last\":" + String(kv.second.lastSeen) + "}";
    }
    out += "]";
    return out;
}
void tof_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_tofPeers.clear();
    g_tofPending.clear();
}
size_t tof_peerCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_tofPeers.size();
}

// =============================================================================
// Feature 10/11: TSF clock-skew fingerprint
// =============================================================================
struct TsfTrack {
    uint64_t prevTsf;
    uint64_t prevRxUs;
    uint16_t beaconInterval;
    float ppmEstimate;
    int32_t lastSkewUs;
    uint32_t samples;
    uint32_t firstSeen;
    uint32_t lastSeen;
    char ssid[33];
};
static std::map<uint64_t, TsfTrack> g_tsfTrack;
static constexpr size_t MAX_TSF_TRACK = 200;

static void tsfObserve(const uint8_t *bssid, uint64_t tsf, uint16_t beaconInterval,
                       const char *ssid, uint32_t nowMs) {
    uint64_t nowUs = esp_timer_get_time();
    uint64_t k = packMac(bssid);
    auto tit = g_tsfTrack.find(k);
    if (tit == g_tsfTrack.end()) {
        if (g_tsfTrack.size() >= MAX_TSF_TRACK) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_tsfTrack) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_tsfTrack.erase(oldestK);
        }
        TsfTrack nt{};
        nt.prevTsf = tsf;
        nt.prevRxUs = nowUs;
        nt.beaconInterval = beaconInterval;
        nt.firstSeen = nowMs;
        strncpy(nt.ssid, ssid ? ssid : "", sizeof(nt.ssid) - 1);
        nt.samples = 1;
        nt.lastSeen = nowMs;
        g_tsfTrack[k] = nt;
        return;
    }
    TsfTrack &t = tit->second;
    if (tsf <= t.prevTsf) {
        t.prevTsf = tsf;
        t.prevRxUs = nowUs;
        t.lastSeen = nowMs;
        return;
    }
    uint64_t actualDelta = tsf - t.prevTsf;
    uint64_t rxDeltaUs = nowUs - t.prevRxUs;
    if (rxDeltaUs < 50000ULL || rxDeltaUs > 60000000ULL) {
        t.prevTsf = tsf;
        t.prevRxUs = nowUs;
        t.lastSeen = nowMs;
        return;
    }
    int64_t skew = (int64_t)actualDelta - (int64_t)rxDeltaUs;
    if (skew > 200000 || skew < -200000) {
        t.prevTsf = tsf;
        t.prevRxUs = nowUs;
        t.lastSeen = nowMs;
        return;
    }
    float ppm = ((float)skew / (float)rxDeltaUs) * 1e6f;
    if (ppm > 500.0f || ppm < -500.0f) {
        t.prevTsf = tsf;
        t.prevRxUs = nowUs;
        t.lastSeen = nowMs;
        return;
    }
    t.ppmEstimate = (t.ppmEstimate * (float)(t.samples - 1) + ppm) / (float)t.samples;
    t.lastSkewUs = (int32_t)skew;
    if (t.samples < UINT32_MAX) t.samples++;
    t.prevTsf = tsf;
    t.prevRxUs = nowUs;
    t.beaconInterval = beaconInterval;
    strncpy(t.ssid, ssid ? ssid : "", sizeof(t.ssid) - 1);
    t.lastSeen = nowMs;
}

String tsf_getSkewJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_tsfTrack) {
        if (kv.second.samples < 3) continue;
        if (!first) out += ",";
        first = false;
        uint8_t bssid[6];
        unpackMac(kv.first, bssid);
        out += "{\"bssid\":\"" + macStr(bssid) + "\"" +
               ",\"ssid\":\"" + String(kv.second.ssid) + "\"" +
               ",\"ppm\":" + String(kv.second.ppmEstimate, 2) +
               ",\"last_skew_us\":" + String(kv.second.lastSkewUs) +
               ",\"samples\":" + String(kv.second.samples) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) + "}";
    }
    out += "]";
    return out;
}
void tsf_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_tsfTrack.clear();
}
size_t tsf_count() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_tsfTrack.size();
}

// =============================================================================
// Feature 9: Reactive KARMA probe-bait
// =============================================================================
static std::map<uint64_t, KarmaCandidate> g_karma;
static std::map<uint64_t, std::set<String>> g_karmaSsids;
static std::vector<String> g_baitSsids;
// g_karmaEnabled declared earlier
static constexpr uint8_t  KARMA_DISTINCT_THRESHOLD = 2;
static constexpr uint32_t KARMA_WINDOW_MS = 60000;
static constexpr size_t   MAX_KARMA = 64;
static constexpr size_t   MAX_BAIT  = 8;

static const uint8_t kProbeReqHeader[24] = {
    0x40, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00
};
static const uint8_t kSupportedRates[10] = {
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24
};

static void karmaEmitBait(const uint8_t *targetBssid) {
    uint32_t seq = (uint32_t)esp_timer_get_time() & 0xFFFFFF;
    char ssid[33];
    snprintf(ssid, sizeof(ssid), "H%s_%06X", getNodeId().c_str(), (unsigned)seq);
    size_t ssidLen = strlen(ssid);
    if (ssidLen > 32) ssidLen = 32;

    uint8_t frame[24 + 2 + 32 + sizeof(kSupportedRates)];
    memcpy(frame, kProbeReqHeader, 24);
    frame[24] = 0x00;
    frame[25] = (uint8_t)ssidLen;
    memcpy(frame + 26, ssid, ssidLen);
    memcpy(frame + 26 + ssidLen, kSupportedRates, sizeof(kSupportedRates));
    size_t total = 26 + ssidLen + sizeof(kSupportedRates);

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, total, false);
    (void)err;

    if (g_baitSsids.size() >= MAX_BAIT) g_baitSsids.erase(g_baitSsids.begin());
    g_baitSsids.push_back(String(ssid));
    (void)targetBssid;
}

void karma_setEnabled(bool on) { g_karmaEnabled.store(on); }
bool karma_isEnabled() { return g_karmaEnabled.load(); }
void karma_init() {}

void karma_observeProbeResp(const uint8_t *bssid, const char *ssid, int8_t rssi) {
    if (!g_karmaEnabled.load() || !bssid || !ssid || ssid[0] == 0) return;
    if (::g_detectVerbose.load()) {
        Serial.printf("[VERIFY-KARMA] probe-resp bssid=%02X:%02X:%02X:%02X:%02X:%02X ssid=\"%s\" rssi=%d\n",
                      bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5], ssid, (int)rssi);
    }
    uint64_t k = packMac(bssid);
    uint32_t now = millis();
    std::unique_lock<std::recursive_mutex> lk(g_mtx);
    auto kit = g_karma.find(k);
    if (kit == g_karma.end()) {
        if (g_karma.size() >= MAX_KARMA) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_karma) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_karma.erase(oldestK);
            g_karmaSsids.erase(oldestK);
        }
        KarmaCandidate nc{};
        memcpy(nc.bssid, bssid, 6);
        nc.firstSseen = now;
        nc.lastSeen = now;
        nc.distinctSsids = 0;
        nc.baitEmitted = false;
        nc.confirmed = false;
        g_karma[k] = nc;
        kit = g_karma.find(k);
    }
    KarmaCandidate &candidate = kit->second;
    auto &ssidSet = g_karmaSsids[k];
    if (now - candidate.firstSseen > KARMA_WINDOW_MS) {
        ssidSet.clear();
        candidate.firstSseen = now;
        candidate.distinctSsids = 0;
        candidate.baitEmitted = false;
    }
    candidate.lastSeen = now;
    strncpy(candidate.lastSsid, ssid, sizeof(candidate.lastSsid) - 1);
    if (ssidSet.insert(String(ssid)).second) {
        candidate.distinctSsids = (uint8_t)std::min<size_t>(255, ssidSet.size());
    }

    bool shouldEmitBait = false;
    uint8_t emitDistinctSsids = 0;
    uint8_t emitBssid[6];
    if (!candidate.baitEmitted && candidate.distinctSsids >= KARMA_DISTINCT_THRESHOLD) {
        candidate.baitEmitted = true;
        shouldEmitBait = true;
        emitDistinctSsids = candidate.distinctSsids;
        memcpy(emitBssid, bssid, 6);
    }
    (void)rssi;
    if (shouldEmitBait) {
        lk.unlock();
        karmaEmitBait(emitBssid);
        Serial.printf("[DETECT] KARMA_CAND bssid=%s distinct_ssids=%u\n", macStr(emitBssid).c_str(), (unsigned)emitDistinctSsids);
        ::detect_logIncident(String("KARMA_CAND:") + macStr(emitBssid) + ":" + String(emitDistinctSsids), macStr(emitBssid).c_str());
        if (meshEnabled && g_meshKarma.load() && meshRateGate("KARMA_CAND_" + macStr(emitBssid), 60000)) {
            sendToSerial1(getNodeId() + ": KARMA_CAND:" + macStr(emitBssid) +
                          ":" + String(emitDistinctSsids), true);
        }
    }
}

bool karma_checkBaitMatch(const char *ssid, const uint8_t *bssid, int8_t rssi) {
    if (!ssid || !bssid) return false;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (auto &s : g_baitSsids) {
        if (s == ssid) {
            uint64_t k = packMac(bssid);
            auto &cand = g_karma[k];
            if (cand.firstSseen == 0) {
                memcpy(cand.bssid, bssid, 6);
                cand.firstSseen = millis();
            }
            bool wasConfirmed = cand.confirmed;
            cand.confirmed = true;
            cand.lastSeen = millis();
            strncpy(cand.lastSsid, ssid, sizeof(cand.lastSsid) - 1);
            if (!wasConfirmed) {   // emit once per BSSID — karma answers every bait, would storm otherwise
                Serial.printf("[DETECT] KARMA_CONFIRMED bssid=%s ssid=%s rssi=%d\n", macStr(bssid).c_str(), ssid, (int)rssi);
                ::detect_logIncident(String("KARMA_CONFIRMED:") + macStr(bssid) + ":" + String(rssi), macStr(bssid).c_str());
                if (meshEnabled && g_meshKarma.load() && meshRateGate("KARMA_CONF_" + macStr(bssid), 30000)) {
                    sendToSerial1(getNodeId() + ": KARMA_CONFIRMED:" + macStr(bssid) + ":" + String(rssi), true);
                }
                quorum_addReport("KARMA", macStr(bssid), getNodeId(), rssi);
                attacker_kick(bssid, "KARMA");
            }
            return true;
        }
    }
    return false;
}

String karma_getJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_karma) {
        if (!first) out += ",";
        first = false;
        out += "{\"bssid\":\"" + macStr(kv.second.bssid) + "\"" +
               ",\"distinct_ssids\":" + String((unsigned)kv.second.distinctSsids) +
               ",\"bait_emitted\":" + String(kv.second.baitEmitted ? "true" : "false") +
               ",\"confirmed\":" + String(kv.second.confirmed ? "true" : "false") +
               ",\"last_ssid\":\"" + String(kv.second.lastSsid) + "\"" +
               ",\"first\":" + String(kv.second.firstSseen) +
               ",\"last\":" + String(kv.second.lastSeen) + "}";
    }
    out += "]";
    return out;
}
void karma_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_karma.clear();
    g_karmaSsids.clear();
    g_baitSsids.clear();
}
size_t karma_candidateCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_karma.size();
}
size_t karma_confirmedCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    size_t n = 0;
    for (auto &kv : g_karma) if (kv.second.confirmed) n++;
    return n;
}

// =============================================================================
// Feature 7: Pwnagotchi swarm detect
// =============================================================================
static const uint8_t PWNAGOTCHI_ADDR2[6] = {0xDE,0xAD,0xBE,0xEF,0xDE,0xAD};
static std::map<uint64_t, PwnagotchiSighting> g_pwna;
static constexpr size_t MAX_PWNA = 32;

static bool isPwnagotchiBeacon(const uint8_t *frame, uint16_t len) {
    if (len < 36) return false;
    return memcmp(frame + 10, PWNAGOTCHI_ADDR2, 6) == 0;
}

static void pwnagotchiExtractSnippet(const uint8_t *ie, uint16_t ieLen, char *out, size_t outSz) {
    uint16_t off = 0;
    out[0] = 0;
    while (off + 2 <= ieLen) {
        uint8_t tag = ie[off];
        uint8_t len = ie[off + 1];
        if (off + 2 + len > ieLen) break;
        if (tag == 222 && len > 0) {
            size_t n = std::min<size_t>(len, outSz - 1);
            for (size_t i = 0; i < n; ++i) {
                uint8_t c = ie[off + 2 + i];
                out[i] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            out[n] = 0;
            return;
        }
        off += 2 + len;
    }
}

static void pwnagotchiObserve(const uint8_t *bssid, int8_t rssi,
                              const uint8_t *ie, uint16_t ieLen) {
    uint32_t now = millis();
    uint64_t k = packMac(bssid);
    auto sit = g_pwna.find(k);
    if (sit == g_pwna.end()) {
        if (g_pwna.size() >= MAX_PWNA) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_pwna) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_pwna.erase(oldestK);
        }
        PwnagotchiSighting ns{};
        memcpy(ns.bssid, bssid, 6);
        ns.firstSeen = now;
        ns.bestRssi = rssi;
        g_pwna[k] = ns;
        sit = g_pwna.find(k);
    }
    PwnagotchiSighting &s = sit->second;
    if (rssi > s.bestRssi) s.bestRssi = rssi;
    s.lastRssi = rssi;
    if (s.observations < 65535) s.observations++;
    s.lastSeen = now;
    pwnagotchiExtractSnippet(ie, ieLen, s.snippet, sizeof(s.snippet));

    if (meshEnabled) {
        if (g_meshPwna.load() && meshRateGate("PWNAGOTCHI_" + macStr(bssid), 30000))
            sendToSerial1(getNodeId() + ": PWNAGOTCHI:" + macStr(bssid) + ":" + String(rssi), true);
    }
    quorum_addReport("PWNAGOTCHI", macStr(bssid), getNodeId(), rssi);
    attacker_kick(bssid, "PWNAGOTCHI");
}

String pwnagotchi_getJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_pwna) {
        if (!first) out += ",";
        first = false;
        out += "{\"bssid\":\"" + macStr(kv.second.bssid) + "\"" +
               ",\"observations\":" + String(kv.second.observations) +
               ",\"last_rssi\":" + String(kv.second.lastRssi) +
               ",\"best_rssi\":" + String(kv.second.bestRssi) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) +
               ",\"snippet\":\"" + String(kv.second.snippet) + "\"}";
    }
    out += "]";
    return out;
}
void pwnagotchi_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_pwna.clear();
}
size_t pwnagotchi_count() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_pwna.size();
}

// =============================================================================
// Feature 6: Attacker reverse-trilateration
// =============================================================================
struct AttackerHunt {
    uint8_t mac[6];
    char attackType[16];
    uint32_t startedAt;
    uint32_t lastKick;
};
static std::map<uint64_t, AttackerHunt> g_hunts;
static std::atomic<uint32_t> g_huntCooldown{60000};
static constexpr size_t MAX_HUNTS = 32;

void attacker_kick(const uint8_t *mac, const char *attackType) {
    if (!mac) return;
    if (!g_attackerTrilatEnabled.load()) return;
    uint64_t k = packMac(mac);
    uint32_t now = millis();
    bool startTrilat = false;
    String macS;
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        auto it = g_hunts.find(k);
        uint32_t cool = g_huntCooldown.load();
        if (it != g_hunts.end() && (now - it->second.lastKick) < cool) return;
        uint32_t priorStartedAt = (it != g_hunts.end()) ? it->second.startedAt : now;
        if (it == g_hunts.end() && g_hunts.size() >= MAX_HUNTS) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_hunts) if (kv.second.lastKick < oldestT) { oldestT = kv.second.lastKick; oldestK = kv.first; }
            g_hunts.erase(oldestK);
        }
        AttackerHunt h{};
        memcpy(h.mac, mac, 6);
        strncpy(h.attackType, attackType ? attackType : "?", sizeof(h.attackType) - 1);
        h.startedAt = priorStartedAt;
        h.lastKick = now;
        g_hunts[k] = h;
        if (!::triangulationActive.load()) {
            startTrilat = true;
            macS = macStr(mac);
        }
    }
    if (startTrilat) ::startTriangulation(macS, 60);
    if (meshEnabled && g_meshAttackerHunt.load() && meshRateGate("HUNT_" + macStr(mac), 60000)) {
        sendToSerial1(getNodeId() + ": ATTACKER_HUNT:" + macStr(mac) + ":" + String(attackType ? attackType : "?"), true);
    }
}
String attacker_getActiveHuntsJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_hunts) {
        if (!first) out += ",";
        first = false;
        out += "{\"mac\":\"" + macStr(kv.second.mac) +
               "\",\"type\":\"" + String(kv.second.attackType) +
               "\",\"started\":" + String(kv.second.startedAt) +
               ",\"last_kick\":" + String(kv.second.lastKick) + "}";
    }
    out += "]";
    return out;
}
void attacker_clearHunts() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_hunts.clear();
}
size_t attacker_huntCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_hunts.size();
}
void attacker_setCooldown(uint32_t ms) { g_huntCooldown.store(ms); }

// =============================================================================
// Feature 5: Distributed 4-way handshake reconstruction + KRACK
// =============================================================================
static std::map<uint64_t, HandshakeReconstruction> g_hshk;
static std::atomic<uint32_t> g_krackEvents{0};
static constexpr size_t MAX_HSHK = 48;
static constexpr size_t MAX_HSHK_FRAGS = 16;

static uint64_t hshkKey(const uint8_t *bssid, const uint8_t *sta) {
    uint64_t kb = 0, ks = 0;
    for (int i = 0; i < 6; ++i) kb = (kb << 8) | bssid[i];
    for (int i = 0; i < 6; ++i) ks = (ks << 8) | sta[i];
    return kb ^ (ks * 0x9E3779B97F4A7C15ULL);
}

static uint8_t classifyEapolMsg(uint16_t keyInfo) {
    bool pairwise = (keyInfo >> 3) & 1;
    bool install  = (keyInfo >> 6) & 1;
    bool ack      = (keyInfo >> 7) & 1;
    bool mic      = (keyInfo >> 8) & 1;
    bool secure   = (keyInfo >> 9) & 1;
    if (!pairwise) return 0;
    if (!install && ack && !mic) return 1;
    if (!install && !ack && mic && !secure) return 2;
    if (install && ack && mic) return 3;
    if (!install && !ack && mic && secure) return 4;
    return 0;
}

static void hshkRecord(const uint8_t *bssid, const uint8_t *sta, uint8_t msgNum,
                       uint64_t replayCtr, int8_t rssi, const char *nodeId, uint32_t now) {
    if (msgNum < 1 || msgNum > 4) return;
    uint64_t k = hshkKey(bssid, sta);
    auto it = g_hshk.find(k);
    if (it == g_hshk.end()) {
        if (g_hshk.size() >= MAX_HSHK) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_hshk) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_hshk.erase(oldestK);
        }
        HandshakeReconstruction r{};
        memcpy(r.bssid, bssid, 6);
        memcpy(r.sta, sta, 6);
        r.seenMask = 0;
        r.firstSeen = now;
        r.lastSeen = now;
        r.krackEvents = 0;
        g_hshk[k] = r;
        it = g_hshk.find(k);
    }
    HandshakeReconstruction &r = it->second;
    if (msgNum == 3) {
        for (auto &f : r.fragments) {
            if (f.msgNum == 3 && f.replayCtr == replayCtr) {
                if (r.krackEvents < 255) r.krackEvents++;
                g_krackEvents.fetch_add(1);
                if (meshEnabled && g_meshKrack.load() && meshRateGate("KRACK_" + macStr(bssid), 30000)) {
                    sendToSerial1(getNodeId() + ": KRACK:" + macStr(bssid) + ":" + macStr(sta) +
                                  ":" + String((unsigned long)replayCtr), true);
                }
                quorum_addReport("KRACK", macStr(bssid) + "/" + macStr(sta), getNodeId(), rssi);
                attacker_kick(bssid, "KRACK");
                break;
            }
        }
    }
    HandshakeFragment f{};
    memcpy(f.bssid, bssid, 6);
    memcpy(f.sta, sta, 6);
    f.msgNum = msgNum;
    f.replayCtr = replayCtr;
    f.rssi = rssi;
    f.ts = now;
    strncpy(f.nodeId, nodeId, sizeof(f.nodeId) - 1);
    r.fragments.push_back(f);
    if (r.fragments.size() > MAX_HSHK_FRAGS) r.fragments.erase(r.fragments.begin());
    r.seenMask |= (1 << (msgNum - 1));
    r.lastSeen = now;
}

String hshk_getReconJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_hshk) {
        if (!first) out += ",";
        first = false;
        out += "{\"bssid\":\"" + macStr(kv.second.bssid) +
               "\",\"sta\":\"" + macStr(kv.second.sta) +
               "\",\"seen_mask\":" + String((unsigned)kv.second.seenMask) +
               ",\"complete\":" + String(kv.second.seenMask == 0x0F ? "true" : "false") +
               ",\"krack_events\":" + String((unsigned)kv.second.krackEvents) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) +
               ",\"frags\":[";
        bool ff = true;
        for (auto &f : kv.second.fragments) {
            if (!ff) out += ",";
            ff = false;
            out += "{\"msg\":" + String(f.msgNum) +
                   ",\"rc\":" + String((unsigned long)f.replayCtr) +
                   ",\"rssi\":" + String(f.rssi) +
                   ",\"node\":\"" + String(f.nodeId) + "\"" +
                   ",\"ts\":" + String(f.ts) + "}";
        }
        out += "]}";
    }
    out += "]";
    return out;
}
void hshk_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_hshk.clear();
    g_krackEvents.store(0);
}
size_t hshk_count() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_hshk.size();
}
uint32_t hshk_krackEvents() { return g_krackEvents.load(); }

// =============================================================================
// Feature 4: AirTag owner-presence inference + battery
// =============================================================================
static std::map<uint64_t, AirTagPresence> g_airtag;
static constexpr size_t MAX_AIRTAG = 120;

static bool airtagDecode(const uint8_t *adv, uint16_t len, uint8_t &statusOut) {
    uint16_t off = 0;
    while (off + 2 <= len) {
        uint8_t l = adv[off];
        if (l == 0) { off++; continue; }
        if (off + 1 + l > len) return false;
        uint8_t adType = adv[off + 1];
        if (adType == 0xFF && l >= 5) {
            uint16_t mfg = (uint16_t)adv[off + 2] | ((uint16_t)adv[off + 3] << 8);
            if (mfg == 0x004C && adv[off + 4] == 0x12 && adv[off + 5] == 0x19) {
                if (l < 7) return false;
                statusOut = adv[off + 6];
                return true;
            }
        }
        off += 1 + l;
    }
    return false;
}

// Replay-detection state: payload-hash → first addr seen + first ts.
// Real AirTag rotates payload+MAC together. Replay attack reuses same payload
// from a DIFFERENT MAC. Same payload from >=2 distinct MACs = AIRTAG_REPLAY.
//
// Memory/SD strategy:
//   RAM (g_airtagReplay): active tracking, 128 entries, ~12KB. O(log N) lookup.
//   SD (/airtag_replay.bin): audit log of CONFIRMED replays only. 20 bytes/record,
//     append-only, capped at 256 records ~5KB. Loaded on boot so reboot doesn't
//     re-alert on the same replay. Real-world: rare enough event to never bloat.
struct AirTagReplayEntry {
    uint64_t firstAddr;
    uint32_t firstSeenMs;
    std::set<uint64_t> seenAddrs;
    bool alerted;
    bool persisted;  // already on SD — skip re-write
};
static std::map<uint32_t, AirTagReplayEntry> g_airtagReplay;
static constexpr size_t MAX_AIRTAG_REPLAY_MAP = 128;
static constexpr const char *AIRTAG_REPLAY_SD_PATH = "/airtag_replay.bin";
static constexpr size_t MAX_AIRTAG_REPLAY_SD_RECORDS = 256;

// SD record format (20 bytes, little-endian):
//   [0..3]   pHash (uint32)
//   [4..9]   firstAddr (6 bytes mac)
//   [10..15] altAddr   (6 bytes — the MAC that triggered replay alert)
//   [16..19] firstSeenMs (uint32 — millis at first sighting, ignored across boots)
struct AirTagReplaySdRec {
    uint32_t pHash;
    uint8_t  firstAddr[6];
    uint8_t  altAddr[6];
    uint32_t firstSeenMs;
} __attribute__((packed));

static void airtagReplayPersist(uint32_t pHash, const uint8_t *firstMac, const uint8_t *altMac, uint32_t firstSeenMs) {
    if (!SafeSD::isAvailable()) return;
    // Cap file size: if at limit, rotate (rename → .old, start fresh).
    File f = SafeSD::open(AIRTAG_REPLAY_SD_PATH, FILE_APPEND);
    if (!f) {
        f = SafeSD::open(AIRTAG_REPLAY_SD_PATH, FILE_WRITE);
        if (!f) return;
    }
    if (f.size() >= (uint32_t)(sizeof(AirTagReplaySdRec) * MAX_AIRTAG_REPLAY_SD_RECORDS)) {
        f.close();
        SafeSD::remove("/airtag_replay_old.bin");
        // Best-effort rename via copy-then-delete is complex; just truncate.
        SafeSD::remove(AIRTAG_REPLAY_SD_PATH);
        f = SafeSD::open(AIRTAG_REPLAY_SD_PATH, FILE_WRITE);
        if (!f) return;
    }
    AirTagReplaySdRec rec{};
    rec.pHash = pHash;
    memcpy(rec.firstAddr, firstMac, 6);
    if (altMac) memcpy(rec.altAddr, altMac, 6);
    rec.firstSeenMs = firstSeenMs;
    f.write((const uint8_t *)&rec, sizeof(rec));
    f.close();
}

static void airtagReplayLoadFromSD() {
    if (!SafeSD::isAvailable()) return;
    if (!SD.exists(AIRTAG_REPLAY_SD_PATH)) return;
    File f = SafeSD::open(AIRTAG_REPLAY_SD_PATH, FILE_READ);
    if (!f) return;
    size_t recCount = f.size() / sizeof(AirTagReplaySdRec);
    if (recCount == 0) { f.close(); return; }
    // Read most recent 64 records into RAM as already-alerted entries.
    size_t toRead = recCount > 64 ? 64 : recCount;
    size_t skip = (recCount - toRead) * sizeof(AirTagReplaySdRec);
    if (skip) f.seek(skip, SeekSet);
    AirTagReplaySdRec rec;
    while (toRead-- && f.read((uint8_t *)&rec, sizeof(rec)) == sizeof(rec)) {
        if (g_airtagReplay.size() >= MAX_AIRTAG_REPLAY_MAP) break;
        AirTagReplayEntry ne{};
        ne.firstAddr = packMac(rec.firstAddr);
        ne.firstSeenMs = 0;  // millis from prior boot meaningless
        ne.alerted = true;
        ne.persisted = true;
        ne.seenAddrs.insert(ne.firstAddr);
        if (memcmp(rec.altAddr, "\x00\x00\x00\x00\x00\x00", 6) != 0) {
            ne.seenAddrs.insert(packMac(rec.altAddr));
        }
        g_airtagReplay[rec.pHash] = ne;
    }
    f.close();
    Serial.printf("[DETECT] AirTag replay: loaded %u prior records from SD\n",
                  (unsigned)g_airtagReplay.size());
}

static uint32_t airtagPayloadHash(const uint8_t *payload, uint16_t len) {
    // 32-bit FNV-1a hash of the FindMy advertisement payload (post `4C 00`).
    uint32_t h = 2166136261u;
    for (uint16_t i = 0; i < len; ++i) {
        h ^= payload[i];
        h *= 16777619u;
    }
    return h;
}

static void airtagProcess(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len) {
    uint8_t status = 0;
    if (!airtagDecode(payload, len, status)) return;

    // Replay check: same payload bytes under multiple MACs.
    uint32_t pHash = airtagPayloadHash(payload, len);
    uint64_t addrK = packMac(addr);
    uint32_t nowMs = millis();
    {
        auto rit = g_airtagReplay.find(pHash);
        if (rit == g_airtagReplay.end()) {
            if (g_airtagReplay.size() >= MAX_AIRTAG_REPLAY_MAP) {
                // Evict oldest entry by firstSeenMs.
                uint32_t oldest = UINT32_MAX; uint32_t oldestKey = 0;
                for (auto &kv : g_airtagReplay) if (kv.second.firstSeenMs < oldest) { oldest = kv.second.firstSeenMs; oldestKey = kv.first; }
                g_airtagReplay.erase(oldestKey);
            }
            AirTagReplayEntry ne{};
            ne.firstAddr = addrK;
            ne.firstSeenMs = nowMs;
            ne.alerted = false;
            ne.persisted = false;
            ne.seenAddrs.insert(addrK);
            g_airtagReplay[pHash] = ne;
        } else {
            AirTagReplayEntry &e = rit->second;
            e.seenAddrs.insert(addrK);
            if (!e.alerted && e.seenAddrs.size() >= 2) {
                e.alerted = true;
                String a1 = macStr(addr);
                String line = String("{\"addr\":\"") + a1 +
                              "\",\"payload_hash\":\"" + String(pHash, HEX) +
                              "\",\"distinct_macs\":" + String((unsigned)e.seenAddrs.size()) +
                              ",\"rssi\":" + String(rssi) +
                              ",\"reason\":\"AIRTAG_REPLAY\"" +
                              ",\"ts\":" + String(nowMs) + "}";
                logEventToSD("/ble_attack.jsonl", line);
                // Persist to dedicated AirTag-replay SD audit log (binary, 20B/rec).
                if (!e.persisted) {
                    uint64_t fa = e.firstAddr;
                    uint8_t fab[6];
                    for (int i = 5; i >= 0; --i) { fab[i] = (uint8_t)(fa & 0xFF); fa >>= 8; }
                    airtagReplayPersist(pHash, fab, addr, e.firstSeenMs);
                    e.persisted = true;
                }
                if (meshEnabled && meshRateGate("AIRTAG_REPLAY_" + String(pHash, HEX), 60000)) {
                    sendToSerial1(getNodeId() + ": BLE_ATTACK:AirTag_Replay:" + a1 +
                                  ":payload=" + String(pHash, HEX) +
                                  ":macs=" + String(e.seenAddrs.size()), true);
                }
                quorum_addReport("BLE_ATTACK", String("AirTag_Replay"), getNodeId(), rssi);
            }
        }
    }

    uint64_t k = packMac(addr);
    uint32_t now = millis();
    auto ait = g_airtag.find(k);
    if (ait == g_airtag.end()) {
        if (g_airtag.size() >= MAX_AIRTAG) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_airtag) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_airtag.erase(oldestK);
        }
        AirTagPresence np{};
        memcpy(np.addr, addr, 6);
        np.firstSeen = now;
        np.isFindMy = true;
        g_airtag[k] = np;
        ait = g_airtag.find(k);
    }
    AirTagPresence &p = ait->second;
    p.lastStatusByte = status;
    p.observations++;
    bool maintained = (status & 0x04) != 0;
    if (maintained) {
        p.maintainedCount++;
        p.batteryLastSeen = (status >> 6) & 0x03;
    }
    p.lastRssi = rssi;
    p.lastSeen = now;
}

String airtag_getPresenceJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_airtag) {
        if (!first) out += ",";
        first = false;
        bool ownerNearby = (kv.second.lastStatusByte & 0x04) != 0;
        const char *bat = "unknown";
        if (ownerNearby) {
            switch (kv.second.batteryLastSeen) {
                case 0: bat = "full"; break;
                case 1: bat = "medium"; break;
                case 2: bat = "low"; break;
                case 3: bat = "critical"; break;
            }
        }
        float ownerRate = (kv.second.observations > 0)
                          ? (float)kv.second.maintainedCount / (float)kv.second.observations : 0.0f;
        out += "{\"addr\":\"" + macStr(kv.second.addr) + "\"" +
               ",\"status\":" + String(kv.second.lastStatusByte) +
               ",\"owner_nearby\":" + String(ownerNearby ? "true" : "false") +
               ",\"owner_seen_rate\":" + String(ownerRate, 2) +
               ",\"battery\":\"" + bat + "\"" +
               ",\"observations\":" + String(kv.second.observations) +
               ",\"last_rssi\":" + String(kv.second.lastRssi) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) + "}";
    }
    out += "]";
    return out;
}
void airtag_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_airtag.clear();
}
size_t airtag_count() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_airtag.size();
}

// =============================================================================
// Feature 3: BLE tracker rotation un-linking
// =============================================================================
struct VanishedTracker {
    uint8_t addr[6];
    char vendor[16];
    int8_t lastRssi;
    uint32_t vanishedAt;
    uint32_t chainId;
};
static std::vector<VanishedTracker> g_vanished;
static std::map<uint32_t, TrackerChain> g_chains;
static uint32_t g_chainSeq = 1;
static constexpr uint32_t TRACKER_VANISH_MS    = 60000;
static constexpr uint32_t TRACKER_LINK_WINDOW  = 90000;
static constexpr int8_t   TRACKER_RSSI_TOL_DB  = 6;
static constexpr size_t   MAX_CHAINS           = 80;
static constexpr size_t   MAX_VANISHED         = 60;

static uint32_t trackerTryLinkRotation(const uint8_t *addr, const char *vendor, int8_t rssi, uint32_t now) {
    if (!vendor || vendor[0] == 0) return 0;
    for (auto it = g_vanished.begin(); it != g_vanished.end(); ) {
        if (now - it->vanishedAt > TRACKER_LINK_WINDOW) {
            it = g_vanished.erase(it);
            continue;
        }
        if (strcmp(it->vendor, vendor) == 0 &&
            abs((int)it->lastRssi - (int)rssi) <= TRACKER_RSSI_TOL_DB &&
            memcmp(it->addr, addr, 6) != 0) {
            uint32_t cid = it->chainId;
            VanishedTracker v = *it;
            g_vanished.erase(it);
            if (cid == 0) {
                if (g_chains.size() >= MAX_CHAINS) {
                    uint32_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
                    for (auto &kv : g_chains) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
                    g_chains.erase(oldestK);
                }
                cid = g_chainSeq++;
                TrackerChain c{};
                c.chainId = cid;
                strncpy(c.vendor, vendor, sizeof(c.vendor) - 1);
                c.avgRssi = rssi;
                c.firstSeen = v.vanishedAt;
                c.lastSeen = now;
                TrackerChain::Link l1{};
                memcpy(l1.addr, v.addr, 6);
                l1.rssi = v.lastRssi;
                l1.startTs = v.vanishedAt;
                l1.endTs = v.vanishedAt;
                c.links.push_back(l1);
                c.linkCount = 1;
                g_chains[cid] = c;
            }
            TrackerChain &chain = g_chains[cid];
            TrackerChain::Link l{};
            memcpy(l.addr, addr, 6);
            l.rssi = rssi;
            l.startTs = now;
            l.endTs = now;
            chain.links.push_back(l);
            if (chain.linkCount < 255) chain.linkCount++;
            chain.avgRssi = (int8_t)(((int32_t)chain.avgRssi + rssi) / 2);
            chain.lastSeen = now;
            if (meshEnabled && g_meshTracker.load() && meshRateGate("TRKLINK_" + String(cid), 30000)) {
                sendToSerial1(getNodeId() + ": TRK_LINK:" + String(cid) + ":" +
                              vendor + ":" + macStr(addr) + ":" + String(rssi), true);
            }
            return cid;
        }
        ++it;
    }
    return 0;
}

static void trackerSweepVanished(uint32_t now) {
    for (auto it = g_bleTrackers.begin(); it != g_bleTrackers.end(); ) {
        if (now - it->second.lastSeen > TRACKER_VANISH_MS && it->second.vendor[0]) {
            if (g_vanished.size() >= MAX_VANISHED) g_vanished.erase(g_vanished.begin());
            VanishedTracker v{};
            memcpy(v.addr, it->second.addr, 6);
            strncpy(v.vendor, it->second.vendor, sizeof(v.vendor) - 1);
            v.lastRssi = it->second.avgRssi;
            v.vanishedAt = it->second.lastSeen;
            v.chainId = 0;
            g_vanished.push_back(v);
            it = g_bleTrackers.erase(it);
        } else {
            ++it;
        }
    }
}

String tracker_getChainsJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    trackerSweepVanished(millis());
    String out = "[";
    bool first = true;
    for (auto &kv : g_chains) {
        if (!first) out += ",";
        first = false;
        out += "{\"chain\":" + String(kv.second.chainId) +
               ",\"vendor\":\"" + String(kv.second.vendor) + "\"" +
               ",\"links\":" + String((unsigned)kv.second.linkCount) +
               ",\"avg_rssi\":" + String(kv.second.avgRssi) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) +
               ",\"history\":[";
        bool fl = true;
        for (auto &l : kv.second.links) {
            if (!fl) out += ",";
            fl = false;
            out += "{\"addr\":\"" + macStr(l.addr) +
                   "\",\"rssi\":" + String(l.rssi) +
                   ",\"first\":" + String(l.startTs) +
                   ",\"last\":" + String(l.endTs) + "}";
        }
        out += "]}";
    }
    out += "]";
    return out;
}
void tracker_clearChains() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_chains.clear();
    g_vanished.clear();
}
size_t tracker_chainCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_chains.size();
}

// =============================================================================
// Feature 2: Probe-graph identity correlator
// =============================================================================
static std::map<uint32_t, ProbeGraphIdentity> g_pgGraph;

uint32_t pg_computeHashFromBytes(const uint8_t *ieFp12, const uint8_t *ieOrderBytes,
                                 uint8_t ieOrderLen, const uint8_t *chanSeq, uint8_t chanSeqLen) {
    uint32_t h = 0x811C9DC5;
    if (ieFp12) for (uint8_t i = 0; i < 12; ++i) { h ^= ieFp12[i]; h *= 16777619u; }
    if (ieOrderBytes && ieOrderLen) for (uint8_t i = 0; i < ieOrderLen; ++i) { h ^= ieOrderBytes[i]; h *= 16777619u; }
    if (chanSeq && chanSeqLen) for (uint8_t i = 0; i < chanSeqLen; ++i) { h ^= chanSeq[i]; h *= 16777619u; }
    return h;
}

void pg_announceLocalIdentity(uint32_t hash, const char *localTrackId, int8_t rssi) {
    if (!localTrackId) return;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto &id = g_pgGraph[hash];
    if (id.hash == 0) {
        id.hash = hash;
        id.firstSeen = now;
        id.bestRssi = rssi;
        id.sightingCount = 1;
        strncpy(id.localTrackId, localTrackId, sizeof(id.localTrackId) - 1);
    } else {
        if (rssi > id.bestRssi) id.bestRssi = rssi;
        if (id.sightingCount < 255) id.sightingCount++;
    }
    id.lastSeen = now;
    bool selfPresent = false;
    String me = getNodeId();
    for (auto &n : id.nodes) if (n.nodeId == me) { n.rssi = rssi; n.ts = now; selfPresent = true; break; }
    if (!selfPresent) {
        ProbeGraphIdentity::NodeSeen ns;
        ns.nodeId = me; ns.rssi = rssi; ns.ts = now;
        id.nodes.push_back(ns);
    }
    if (meshEnabled) {
        sendToSerial1(me + ": IDHASH:" + String(hash) + ":" +
                      String(localTrackId) + ":" + String(rssi), true);
    }
}

void pg_init() {}
void pg_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_pgGraph.clear();
}
size_t pg_size() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_pgGraph.size();
}
String pg_getGraphJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_pgGraph) {
        if (!first) out += ",";
        first = false;
        out += "{\"hash\":" + String(kv.second.hash) +
               ",\"local\":\"" + String(kv.second.localTrackId) + "\"" +
               ",\"best_rssi\":" + String(kv.second.bestRssi) +
               ",\"sightings\":" + String((unsigned)kv.second.sightingCount) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) +
               ",\"nodes\":[";
        bool fn = true;
        for (auto &n : kv.second.nodes) {
            if (!fn) out += ",";
            fn = false;
            out += "{\"node\":\"" + n.nodeId + "\",\"rssi\":" + String(n.rssi) +
                   ",\"ts\":" + String(n.ts) + "}";
        }
        out += "]}";
    }
    out += "]";
    return out;
}

// =============================================================================
// Feature 1+8: CSI Presence / Motion / RF Fingerprint
// =============================================================================
static QueueHandle_t g_csiQueue = nullptr;
static std::atomic<bool> g_csiEnabled{false};
static std::atomic<uint32_t> g_csiPkts{0};
static std::atomic<uint32_t> g_csiMotion{0};
static std::atomic<uint16_t> g_csiThreshQ8{1500};
static std::vector<CsiMotionEvent> g_csiMotionLog;
static std::map<uint64_t, CsiFingerprint> g_csiFp;

struct CsiHistory {
    int16_t prevAmp[64];
    uint16_t varQ8;
    uint8_t valid;
    uint32_t lastTs;
};
static std::map<uint64_t, CsiHistory> g_csiHist;
static constexpr size_t MAX_CSI_MOTION_LOG = 80;
static constexpr size_t MAX_CSI_FP = 200;

static void IRAM_ATTR csi_rx_cb(void *ctx, wifi_csi_info_t *info) {
    (void)ctx;
    if (!info || !info->buf || info->len < 8) return;
    if (!g_csiQueue) return;
    CsiSnapshot snap{};
    memcpy(snap.srcMac, info->mac, 6);
    snap.rssi = info->rx_ctrl.rssi;
    snap.channel = info->rx_ctrl.channel;
    snap.bandwidth = info->rx_ctrl.cwb;
    snap.ts = info->rx_ctrl.timestamp;
    int8_t *src = info->buf;
    int n = info->len / 2;
    if (n > 64) n = 64;
    snap.numSubcarriers = (uint8_t)n;
    for (int i = 0; i < n; ++i) {
        int8_t I = src[i * 2];
        int8_t Q = src[i * 2 + 1];
        int32_t mag2 = (int32_t)I * I + (int32_t)Q * Q;
        int32_t m = mag2;
        int32_t r = 0;
        for (int b = 14; b >= 0; --b) {
            int32_t t = r + (1 << b);
            if (t * t <= m) r = t;
        }
        snap.amp[i] = (int16_t)r;
    }
    if (uxQueueSpacesAvailable(g_csiQueue) < 1) { g_droppedCsi.fetch_add(1); return; }
    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(g_csiQueue, &snap, &woken);
    if (woken) portYIELD_FROM_ISR();
}

static void csiProcess(const CsiSnapshot &s) {
    g_csiPkts.fetch_add(1);
    uint64_t k = packMac(s.srcMac);
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    CsiHistory &h = g_csiHist[k];
    if (h.valid) {
        int32_t accum = 0;
        uint8_t cnt = s.numSubcarriers < 52 ? s.numSubcarriers : 52;
        for (uint8_t i = 0; i < cnt; ++i) {
            int32_t d = (int32_t)s.amp[i] - (int32_t)h.prevAmp[i];
            accum += d * d;
        }
        uint32_t mean = (cnt > 0) ? (uint32_t)(accum / cnt) : 0;
        uint16_t varQ8 = (mean > 0xFFFF) ? 0xFFFF : (uint16_t)mean;
        h.varQ8 = (uint16_t)(((uint32_t)h.varQ8 * 7 + varQ8) / 8);
        uint16_t thresh = g_csiThreshQ8.load();
        if (h.varQ8 > thresh && (now - h.lastTs) > 500) {
            CsiMotionEvent ev{};
            memcpy(ev.srcMac, s.srcMac, 6);
            ev.varianceQ8 = h.varQ8;
            ev.rssi = s.rssi;
            ev.channel = s.channel;
            ev.ts = now;
            if (s.rssi > -55) strncpy(ev.zone, "near", sizeof(ev.zone) - 1);
            else if (s.rssi > -75) strncpy(ev.zone, "mid", sizeof(ev.zone) - 1);
            else strncpy(ev.zone, "far", sizeof(ev.zone) - 1);
            g_csiMotionLog.push_back(ev);
            if (g_csiMotionLog.size() > MAX_CSI_MOTION_LOG) g_csiMotionLog.erase(g_csiMotionLog.begin());
            g_csiMotion.fetch_add(1);
            h.lastTs = now;
            if (meshEnabled) {
                if (g_meshCsiMotion.load() && meshRateGate("CSI_MOTION_" + macStr(s.srcMac), 5000))
                    sendToSerial1(getNodeId() + ": CSI_MOTION:" + macStr(s.srcMac) +
                                  ":" + String(h.varQ8) + ":" + String(s.rssi) + ":" + ev.zone, true);
            }
        }
    }
    uint8_t cap = s.numSubcarriers < 64 ? s.numSubcarriers : 64;
    memcpy(h.prevAmp, s.amp, cap * sizeof(int16_t));
    h.valid = 1;

    if (g_csiFp.size() < MAX_CSI_FP) {
        CsiFingerprint &fp = g_csiFp[k];
        if (fp.observations == 0) {
            memcpy(fp.srcMac, s.srcMac, 6);
            fp.firstSeen = now;
        }
        uint32_t fh = 0x811C9DC5;
        for (uint8_t i = 0; i < cap; ++i) {
            uint8_t q = (uint8_t)(s.amp[i] >> 2);
            fh ^= q; fh *= 16777619u;
        }
        fp.profileHash = (uint16_t)(fh ^ (fh >> 16));
        uint32_t n = fp.observations;
        fp.avgRssi = (int8_t)(((int32_t)fp.avgRssi * (int32_t)n + s.rssi) / (int32_t)(n + 1));
        fp.observations = n + 1;
        fp.lastSeen = now;
    }
}

void csi_init() {
    if (!g_csiQueue) g_csiQueue = xQueueCreate(48, sizeof(CsiSnapshot));
    wifi_csi_config_t cfg = {
        .lltf_en = true,
        .htltf_en = true,
        .stbc_htltf2_en = true,
        .ltf_merge_en = true,
        .channel_filter_en = true,
        .manu_scale = false,
        .shift = 0,
    };
    esp_wifi_set_csi_config(&cfg);
    esp_wifi_set_csi_rx_cb(csi_rx_cb, nullptr);
}
void csi_enable(bool on) {
    esp_wifi_set_csi(on);
    g_csiEnabled.store(on);
}
bool csi_isEnabled() { return g_csiEnabled.load(); }
void csi_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_csiMotionLog.clear();
    g_csiFp.clear();
    g_csiHist.clear();
    g_csiPkts.store(0);
    g_csiMotion.store(0);
}
void csi_setMotionThreshold(uint16_t v) { g_csiThreshQ8.store(v); }
uint16_t csi_getMotionThreshold() { return g_csiThreshQ8.load(); }
uint32_t csi_packetsObserved() { return g_csiPkts.load(); }
uint32_t csi_motionEvents() { return g_csiMotion.load(); }
String csi_getMotionJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out;
    for (auto &e : g_csiMotionLog) {
        out += String("{\"src\":\"") + macStr(e.srcMac) +
               "\",\"var\":" + String(e.varianceQ8) +
               ",\"rssi\":" + String(e.rssi) +
               ",\"ch\":" + String(e.channel) +
               ",\"zone\":\"" + e.zone +
               "\",\"ts\":" + String(e.ts) + "}\n";
    }
    return out;
}
String csi_getFingerprintJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_csiFp) {
        if (!first) out += ",";
        first = false;
        out += "{\"src\":\"" + macStr(kv.second.srcMac) +
               "\",\"hash\":" + String(kv.second.profileHash) +
               ",\"obs\":" + String((unsigned)kv.second.observations) +
               ",\"avg_rssi\":" + String(kv.second.avgRssi) +
               ",\"first\":" + String(kv.second.firstSeen) +
               ",\"last\":" + String(kv.second.lastSeen) + "}";
    }
    out += "]";
    return out;
}

void csiDrainTask(void *pv) {
    CsiSnapshot s;
    while (true) {
        if (g_csiQueue && xQueueReceive(g_csiQueue, &s, pdMS_TO_TICKS(200)) == pdTRUE) {
            csiProcess(s);
        }
    }
}

// =============================================================================
// Persistence (SD snapshot of mid-term state across reboot)
// =============================================================================
static constexpr const char *SNAP_PATH = "/detect_state.bin";
static constexpr uint32_t SNAP_MAGIC = 0xA111EDD1;
static constexpr uint16_t SNAP_VER   = 2;

struct SnapHeader {
    uint32_t magic;
    uint16_t ver;
    uint16_t reserved;
    uint32_t chains;
    uint32_t airtag;
    uint32_t recon;
    uint32_t tsf;
    uint32_t pwna;
};

static void persistSnapshot() {
    if (!SafeSD::isAvailable()) return;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    const char *tmpPath = "/detect_state.tmp";
    File f = SD.open(tmpPath, FILE_WRITE);
    if (!f) return;
    SnapHeader h{};
    h.magic = SNAP_MAGIC;
    h.ver = SNAP_VER;
    h.chains = g_chains.size();
    h.airtag = g_airtag.size();
    h.recon  = g_recon.size();
    h.tsf    = g_tsfTrack.size();
    h.pwna   = g_pwna.size();
    f.write((const uint8_t*)&h, sizeof(h));
    for (auto &kv : g_chains) {
        uint32_t cid = kv.second.chainId;
        f.write((const uint8_t*)&cid, 4);
        f.write((const uint8_t*)kv.second.vendor, 16);
        int8_t avg = kv.second.avgRssi;
        f.write((const uint8_t*)&avg, 1);
        uint8_t lc = (kv.second.links.size() > 8) ? 8 : (uint8_t)kv.second.links.size();
        f.write(&lc, 1);
        f.write((const uint8_t*)&kv.second.firstSeen, 4);
        f.write((const uint8_t*)&kv.second.lastSeen, 4);
        size_t writtenLinks = 0;
        for (auto &lnk : kv.second.links) {
            if (writtenLinks >= 8) break;
            f.write(lnk.addr, 6);
            int8_t lr = lnk.rssi;
            f.write((const uint8_t*)&lr, 1);
            f.write((const uint8_t*)&lnk.startTs, 4);
            f.write((const uint8_t*)&lnk.endTs, 4);
            writtenLinks++;
        }
    }
    for (auto &kv : g_airtag) {
        f.write(kv.second.addr, 6);
        f.write(&kv.second.lastStatusByte, 1);
        uint16_t obs = kv.second.observations;
        f.write((const uint8_t*)&obs, 2);
        uint16_t mc = kv.second.maintainedCount;
        f.write((const uint8_t*)&mc, 2);
        f.write(&kv.second.batteryLastSeen, 1);
        int8_t rs = kv.second.lastRssi;
        f.write((const uint8_t*)&rs, 1);
        f.write((const uint8_t*)&kv.second.firstSeen, 4);
        f.write((const uint8_t*)&kv.second.lastSeen, 4);
    }
    for (auto &kv : g_recon) {
        char id[10] = {0};
        strncpy(id, kv.second.identityId, 9);
        f.write((const uint8_t*)id, 10);
        f.write(&kv.second.score, 1);
        f.write((const uint8_t*)kv.second.reasons, 96);
        f.write((const uint8_t*)&kv.second.ts, 4);
    }
    for (auto &kv : g_tsfTrack) {
        uint64_t mac = kv.first;
        f.write((const uint8_t*)&mac, 8);
        float ppm = kv.second.ppmEstimate;
        f.write((const uint8_t*)&ppm, 4);
        uint32_t n = kv.second.samples;
        f.write((const uint8_t*)&n, 4);
        f.write((const uint8_t*)kv.second.ssid, 33);
        f.write((const uint8_t*)&kv.second.firstSeen, 4);
        f.write((const uint8_t*)&kv.second.lastSeen, 4);
    }
    for (auto &kv : g_pwna) {
        f.write(kv.second.bssid, 6);
        f.write((const uint8_t*)&kv.second.observations, 2);
        int8_t br = kv.second.bestRssi;
        f.write((const uint8_t*)&br, 1);
        int8_t lr = kv.second.lastRssi;
        f.write((const uint8_t*)&lr, 1);
        f.write((const uint8_t*)&kv.second.firstSeen, 4);
        f.write((const uint8_t*)&kv.second.lastSeen, 4);
        f.write((const uint8_t*)kv.second.snippet, sizeof(kv.second.snippet));
    }
    f.close();
    if (SD.exists(SNAP_PATH)) SD.remove(SNAP_PATH);
    SD.rename(tmpPath, SNAP_PATH);
}

static void loadSnapshot() {
    if (!SafeSD::isAvailable()) return;
    if (!SD.exists(SNAP_PATH)) return;
    File f = SD.open(SNAP_PATH, FILE_READ);
    if (!f) return;
    SnapHeader h{};
    if (f.read((uint8_t*)&h, sizeof(h)) != sizeof(h)) { f.close(); return; }
    if (h.magic != SNAP_MAGIC || h.ver != SNAP_VER) { f.close(); return; }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (uint32_t i = 0; i < h.chains; ++i) {
        uint32_t cid; char vendor[16]; int8_t avg; uint8_t lc;
        uint32_t first, last;
        if (f.read((uint8_t*)&cid, 4) != 4) break;
        if (f.read((uint8_t*)vendor, 16) != 16) break;
        if (f.read((uint8_t*)&avg, 1) != 1) break;
        if (f.read(&lc, 1) != 1) break;
        if (f.read((uint8_t*)&first, 4) != 4) break;
        if (f.read((uint8_t*)&last, 4) != 4) break;
        TrackerChain c{};
        c.chainId = cid;
        memcpy(c.vendor, vendor, 16);
        c.avgRssi = avg;
        c.linkCount = lc;
        c.firstSeen = first;
        c.lastSeen = last;
        for (uint8_t lidx = 0; lidx < lc && lidx < 8; ++lidx) {
            TrackerChain::Link lnk{};
            if (f.read(lnk.addr, 6) != 6) { c.linkCount = lidx; break; }
            int8_t lr;
            if (f.read((uint8_t*)&lr, 1) != 1) { c.linkCount = lidx; break; }
            lnk.rssi = lr;
            if (f.read((uint8_t*)&lnk.startTs, 4) != 4) { c.linkCount = lidx; break; }
            if (f.read((uint8_t*)&lnk.endTs, 4) != 4) { c.linkCount = lidx; break; }
            c.links.push_back(lnk);
        }
        g_chains[cid] = c;
        if (cid >= g_chainSeq) g_chainSeq = cid + 1;
    }
    for (uint32_t i = 0; i < h.airtag; ++i) {
        AirTagPresence p{};
        if (f.read(p.addr, 6) != 6) break;
        if (f.read(&p.lastStatusByte, 1) != 1) break;
        uint16_t obs, mc;
        if (f.read((uint8_t*)&obs, 2) != 2) break;
        if (f.read((uint8_t*)&mc, 2) != 2) break;
        if (f.read(&p.batteryLastSeen, 1) != 1) break;
        int8_t rs;
        if (f.read((uint8_t*)&rs, 1) != 1) break;
        p.observations = obs;
        p.maintainedCount = mc;
        p.lastRssi = rs;
        if (f.read((uint8_t*)&p.firstSeen, 4) != 4) break;
        if (f.read((uint8_t*)&p.lastSeen, 4) != 4) break;
        p.isFindMy = true;
        g_airtag[packMac(p.addr)] = p;
    }
    for (uint32_t i = 0; i < h.recon; ++i) {
        char id[10] = {0};
        ReconAlert r{};
        if (f.read((uint8_t*)id, 10) != 10) break;
        if (f.read(&r.score, 1) != 1) break;
        if (f.read((uint8_t*)r.reasons, 96) != 96) break;
        if (f.read((uint8_t*)&r.ts, 4) != 4) break;
        strncpy(r.identityId, id, 9);
        g_recon[String(id)] = r;
    }
    for (uint32_t i = 0; i < h.tsf; ++i) {
        uint64_t mac;
        if (f.read((uint8_t*)&mac, 8) != 8) break;
        TsfTrack t{};
        if (f.read((uint8_t*)&t.ppmEstimate, 4) != 4) break;
        if (f.read((uint8_t*)&t.samples, 4) != 4) break;
        if (f.read((uint8_t*)t.ssid, 33) != 33) break;
        if (f.read((uint8_t*)&t.firstSeen, 4) != 4) break;
        if (f.read((uint8_t*)&t.lastSeen, 4) != 4) break;
        if (t.samples > 0) g_tsfTrack[mac] = t;
    }
    for (uint32_t i = 0; i < h.pwna; ++i) {
        PwnagotchiSighting p{};
        if (f.read(p.bssid, 6) != 6) break;
        if (f.read((uint8_t*)&p.observations, 2) != 2) break;
        int8_t br;
        if (f.read((uint8_t*)&br, 1) != 1) break;
        p.bestRssi = br;
        int8_t lr;
        if (f.read((uint8_t*)&lr, 1) != 1) break;
        p.lastRssi = lr;
        if (f.read((uint8_t*)&p.firstSeen, 4) != 4) break;
        if (f.read((uint8_t*)&p.lastSeen, 4) != 4) break;
        if (f.read((uint8_t*)p.snippet, sizeof(p.snippet)) != sizeof(p.snippet)) break;
        g_pwna[packMac(p.bssid)] = p;
    }
    f.close();
}

// =============================================================================
// Unified incidents log — captures every detector mesh line (local TX + peer RX)
// to /incidents.jsonl on SD + small in-RAM ring for fast UI render.
// =============================================================================
static std::deque<String> g_incidentRing;
static std::recursive_mutex g_incidentMtx;
static constexpr size_t MAX_INCIDENT_RING = 200;

static bool isDetectorPrefix(const String &type) {
    static const char *kPrefixes[] = {
        "DEAUTH_FORGE","DEAUTH_FLOOD","EVILTWIN","KARMA_CAND","KARMA_CONFIRMED",
        "BEACON_FORGE","PMKID_HARVEST","PMKID_FORGE","EAPOL_BAIT","PROBE_FLOOD",
        "PROBE_FLOOD_BEHAVE","ASSOC_SLEEP","BLE_ATTACK","BLETRACK","SAE_DOS",
        "OWE_ABUSE","SSID_CONFUSION","FRAG","CSI_MOTION","KRACK","PWNAGOTCHI",
        "ATTACKER_HUNT","RECON","TRK_LINK","HSHK","DEAUTH_AP_TARGETED",
        "PROBE_FLOOD_AP","BEACON_FLOOD","AUTH_FLOOD",
        nullptr
    };
    for (const char **p = kPrefixes; *p; ++p) {
        if (type == *p) return true;
    }
    return false;
}

void detect_logIncident(const String &raw, const char *src) {
    if (raw.length() == 0) return;
    const char *rc = raw.c_str();
    const char *colon = strchr(rc, ':');
    if (!colon || colon == rc) return;
    size_t typeLen = (size_t)(colon - rc);
    static const char *kPrefixesFast[] = {
        "DEAUTH_FORGE","DEAUTH_FLOOD","EVILTWIN","KARMA_CAND","KARMA_CONFIRMED",
        "BEACON_FORGE","PMKID_HARVEST","PMKID_FORGE","EAPOL_BAIT","PROBE_FLOOD",
        "PROBE_FLOOD_BEHAVE","ASSOC_SLEEP","BLE_ATTACK","BLETRACK","SAE_DOS",
        "OWE_ABUSE","SSID_CONFUSION","FRAG","CSI_MOTION","KRACK","PWNAGOTCHI",
        "ATTACKER_HUNT","RECON","TRK_LINK","HSHK","DEAUTH_AP_TARGETED",
        "PROBE_FLOOD_AP","BEACON_FLOOD","AUTH_FLOOD", nullptr
    };
    bool matched = false;
    for (const char **p = kPrefixesFast; *p; ++p) {
        if (strlen(*p) == typeLen && memcmp(rc, *p, typeLen) == 0) {
            matched = true;
            break;
        }
    }
    if (!matched) return;
    String type = raw.substring(0, (int)typeLen);
    if (!isDetectorPrefix(type)) return;

    uint32_t now = millis();
    String node = getNodeId();
    String escRaw = raw;
    escRaw.replace("\\", "\\\\");
    escRaw.replace("\"", "\\\"");
    String line = String("{\"ts\":") + String(now) +
                  ",\"node\":\"" + node +
                  "\",\"src\":\"" + (src ? src : "local") +
                  "\",\"type\":\"" + type +
                  "\",\"raw\":\"" + escRaw + "\"}";

    {
        std::lock_guard<std::recursive_mutex> lk(g_incidentMtx);
        g_incidentRing.push_back(line);
        while (g_incidentRing.size() > MAX_INCIDENT_RING) g_incidentRing.pop_front();
    }
    logEventToSD("/incidents.jsonl", line);
}

String detect_getIncidentsJson(size_t maxEntries) {
    std::lock_guard<std::recursive_mutex> lk(g_incidentMtx);
    String out = "[";
    size_t total = g_incidentRing.size();
    size_t start = (maxEntries > 0 && maxEntries < total) ? (total - maxEntries) : 0;
    bool first = true;
    for (size_t i = start; i < total; ++i) {
        if (!first) out += ",";
        first = false;
        out += g_incidentRing[i];
    }
    out += "]";
    return out;
}

void detect_clearIncidents() {
    {
        std::lock_guard<std::recursive_mutex> lk(g_incidentMtx);
        g_incidentRing.clear();
    }
    if (SD.exists("/incidents.jsonl")) {
        SD.remove("/incidents.jsonl");
    }
    if (SD.exists("/incidents.jsonl_old")) {
        SD.remove("/incidents.jsonl_old");
    }
}

} // namespace ah_detect

void detect_persistTunables();

void tof_ping(const char *n)                 { ah_detect::tof_ping(n); }
void tof_broadcastPing()                     { ah_detect::tof_broadcastPing(); }
void tof_processPing(const String &f, uint32_t s, uint64_t t) { ah_detect::tof_processPing(f, s, t); }
void tof_processPong(const String &f, uint32_t s, uint64_t a, uint64_t b) { ah_detect::tof_processPong(f, s, a, b); }
String tof_getPeersJson()                    { return ah_detect::tof_getPeersJson(); }
void tof_clear()                             { ah_detect::tof_clear(); }
size_t tof_peerCount()                       { return ah_detect::tof_peerCount(); }
String tsf_getSkewJson()                     { return ah_detect::tsf_getSkewJson(); }
void tsf_clear()                             { ah_detect::tsf_clear(); }
size_t tsf_count()                           { return ah_detect::tsf_count(); }
void karma_setEnabled(bool on)               { ah_detect::karma_setEnabled(on); detect_persistTunables(); }
bool karma_isEnabled()                       { return ah_detect::karma_isEnabled(); }
void karma_init()                            { ah_detect::karma_init(); }
String karma_getJson()                       { return ah_detect::karma_getJson(); }
void karma_clear()                           { ah_detect::karma_clear(); }
size_t karma_candidateCount()                { return ah_detect::karma_candidateCount(); }
size_t karma_confirmedCount()                { return ah_detect::karma_confirmedCount(); }
String pwnagotchi_getJson()                  { return ah_detect::pwnagotchi_getJson(); }
void pwnagotchi_clear()                      { ah_detect::pwnagotchi_clear(); }
size_t pwnagotchi_count()                    { return ah_detect::pwnagotchi_count(); }
void attacker_kick(const uint8_t *mac, const char *t) { ah_detect::attacker_kick(mac, t); }
void detect_witnessDeauth(const uint8_t *src, const uint8_t *dst, int8_t rssi, uint8_t channel) { ah_detect::detect_witnessDeauth(src, dst, rssi, channel); }
void detect_setSelfApIdentity(const uint8_t mac[6], const char *ssid) { ah_detect::detect_setSelfApIdentity(mac, ssid); }
String attacker_getActiveHuntsJson()         { return ah_detect::attacker_getActiveHuntsJson(); }
void attacker_clearHunts()                   { ah_detect::attacker_clearHunts(); }
size_t attacker_huntCount()                  { return ah_detect::attacker_huntCount(); }
void attacker_setCooldown(uint32_t ms)       { ah_detect::attacker_setCooldown(ms); detect_persistTunables(); }
String hshk_getReconJson()                   { return ah_detect::hshk_getReconJson(); }
void hshk_clear()                            { ah_detect::hshk_clear(); }
size_t hshk_count()                          { return ah_detect::hshk_count(); }
uint32_t hshk_krackEvents()                  { return ah_detect::hshk_krackEvents(); }
String airtag_getPresenceJson()              { return ah_detect::airtag_getPresenceJson(); }
void airtag_clear()                          { ah_detect::airtag_clear(); }
size_t airtag_count()                        { return ah_detect::airtag_count(); }
String tracker_getChainsJson()               { return ah_detect::tracker_getChainsJson(); }
void tracker_clearChains()                   { ah_detect::tracker_clearChains(); }
size_t tracker_chainCount()                  { return ah_detect::tracker_chainCount(); }
void pg_init()                                                 { ah_detect::pg_init(); }
uint32_t pg_computeHashFromBytes(const uint8_t *a, const uint8_t *b, uint8_t bl, const uint8_t *c, uint8_t cl) {
    return ah_detect::pg_computeHashFromBytes(a, b, bl, c, cl);
}
void pg_announceLocalIdentity(uint32_t h, const char *t, int8_t r) {
    ah_detect::pg_announceLocalIdentity(h, t, r);
}
String pg_getGraphJson()                     { return ah_detect::pg_getGraphJson(); }
void pg_clear()                              { ah_detect::pg_clear(); }
size_t pg_size()                             { return ah_detect::pg_size(); }
void csi_init()                              { ah_detect::csi_init(); }
void csi_enable(bool on)                     { ah_detect::csi_enable(on); detect_persistTunables(); }
bool csi_isEnabled()                         { return ah_detect::csi_isEnabled(); }
void csi_clear()                             { ah_detect::csi_clear(); }
void csi_setMotionThreshold(uint16_t v)      { ah_detect::csi_setMotionThreshold(v); detect_persistTunables(); }
uint16_t csi_getMotionThreshold()            { return ah_detect::csi_getMotionThreshold(); }
uint32_t csi_packetsObserved()               { return ah_detect::csi_packetsObserved(); }
uint32_t csi_motionEvents()                  { return ah_detect::csi_motionEvents(); }
String csi_getMotionJsonl()                  { return ah_detect::csi_getMotionJsonl(); }
String csi_getFingerprintJson()              { return ah_detect::csi_getFingerprintJson(); }

// =============================================================================
// BloomFilter impl (class declared in global scope in detect.h)
// =============================================================================
uint32_t BloomFilter::h1(uint32_t x) { x ^= x >> 16; x *= 0x7feb352d; x ^= x >> 15; x *= 0x846ca68b; x ^= x >> 16; return x; }
uint32_t BloomFilter::h2(uint32_t x) { x *= 0xcc9e2d51; x = (x<<15)|(x>>17); x *= 0x1b873593; return x ^ 0xa3b195f5; }
uint32_t BloomFilter::h3(uint32_t x) { x ^= 0xdeadbeef; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; }

void BloomFilter::add(uint32_t hash) {
    uint32_t a = h1(hash) % BITS;
    uint32_t b = h2(hash) % BITS;
    uint32_t c = h3(hash) % BITS;
    bits[a >> 3] |= (1 << (a & 7));
    bits[b >> 3] |= (1 << (b & 7));
    bits[c >> 3] |= (1 << (c & 7));
}
bool BloomFilter::maybeContains(uint32_t hash) const {
    uint32_t a = h1(hash) % BITS;
    uint32_t b = h2(hash) % BITS;
    uint32_t c = h3(hash) % BITS;
    return (bits[a >> 3] & (1 << (a & 7))) &&
           (bits[b >> 3] & (1 << (b & 7))) &&
           (bits[c >> 3] & (1 << (c & 7)));
}
void BloomFilter::orFrom(const BloomFilter& o) {
    for (size_t i = 0; i < BYTES; ++i) bits[i] |= o.bits[i];
}

// =============================================================================
// Public C++ API (out of namespace, matches detect.h declarations)
// =============================================================================
using namespace ah_detect;

std::atomic<bool> detectEnabled{true};
QueueHandle_t detectFrameQueue = nullptr;
std::atomic<uint16_t> pmkid_burst_window_ms{10000};
std::atomic<uint8_t>  pmkid_burst_min_bssids{3};
std::atomic<uint16_t> sae_window_ms{5000};
std::atomic<uint8_t>  sae_unmatched_threshold{10};
std::atomic<uint16_t> beacon_int_drift_permil{50};
std::atomic<uint32_t> tracker_follow_window_ms{4UL * 3600UL * 1000UL};
std::atomic<uint32_t> tracker_follow_gap_ms{30UL * 60UL * 1000UL};
std::atomic<uint8_t>  tracker_follow_min_sightings{3};

void initializeDetect() {
    // 24 deep (was 64). Each entry is sizeof(DetectFrameEvent) (~266B with the
    // 256B payload), so 64 cost ~17KB internal SRAM on a board that idles ~33KB
    // free. 24 (~6.4KB) frees ~10KB headroom; the consumer task drains fast and
    // backpressure drops cleanly under flood (detect-once logic already gates).
    detectFrameQueue = xQueueCreate(24, sizeof(DetectFrameEvent));
    g_detectFrameQueue = detectFrameQueue;
    g_quorumRequired["PMKID"] = 2;
    g_quorumRequired["EVILTWIN"] = 2;
    g_quorumRequired["SSIDCONF"] = 2;
    g_quorumRequired["SAE_DOS"] = 1;
    g_quorumRequired["BLETRACK"] = 2;
    g_quorumRequired["RECON"] = 2;
    // loadOuiTable() removed — unused, triggered vfs_api error on missing file
    {
        Preferences p;
        if (p.begin("ahdetect", false)) {
            {
                bool detMig = p.getBool("detMig5", false);
                if (!detMig) {
                    p.putBool("pmkidOn", true);
                    p.putBool("etwOn", true);
                    p.putBool("pflOn", true);
                    p.putBool("aslOn", true);
                    p.putBool("blatkOn", true);
                    p.putBool("scnOn", false);
                    p.putBool("saeOn", false);
                    p.putBool("oweOn", false);
                    p.putBool("fragOn", false);
                    p.putBool("blemOn", false);
                    p.putBool("hshkOn", false);
                    p.putBool("pwnaOn", false);
                    p.putBool("trkOn", false);
                    p.putBool("atgOn", false);
                    p.putBool("tsfOn", false);
                    p.putBool("ridOn", false);
                    p.putBool("blmgOn", false);
                    p.putBool("karmaOn", false);
                    p.putBool("csiOn", false);
                    p.putBool("detMig5", true);
                    Serial.println("[NVS] Migration v5: tool-fingerprint detectors ON (pmkid,etw,probe-flood,assoc-sleep,ble-attack)");
                }
            }
            uint16_t v;
            if ((v = p.getUShort("csiThr", 0))) ah_detect::g_csiThreshQ8.store(v);
            if ((v = p.getUShort("pmkidWin", 0))) ah_detect::g_pmkidWindow.store(v);
            uint8_t u;
            if ((u = p.getUChar("pmkidN", 0))) ah_detect::g_pmkidMinBssids.store(u);
            if ((u = p.getUChar("saeN", 0))) ah_detect::g_saeUnmatchedThresh.store(u);
            if ((v = p.getUShort("saeWin", 0))) ah_detect::g_saeWindow.store(v);
            ah_detect::g_karmaEnabled.store(p.getBool("karmaOn", false));
            ah_detect::g_csiEnabled.store(p.getBool("csiOn", false));
            uint32_t w;
            if ((w = p.getULong("trkWin", 0))) ah_detect::g_trackerWindowMs.store(w);
            if ((w = p.getULong("huntCool", 0))) ah_detect::g_huntCooldown.store(w);
            if ((u = p.getUChar("fragN", 0))) ah_detect::g_fragReuseThresh.store(u);
            ah_detect::g_pmkidEnabled.store(p.getBool("pmkidOn", true));
            ah_detect::g_eviltwinEnabled.store(p.getBool("etwOn", true));
            ah_detect::g_ssidConfusionEnabled.store(p.getBool("scnOn", false));
            ah_detect::g_saeEnabled.store(p.getBool("saeOn", false));
            ah_detect::g_sentinelScanMode.store(p.getBool("sclScan", false));
            ah_detect::g_oweEnabled.store(p.getBool("oweOn", false));
            ah_detect::g_fragEnabled.store(p.getBool("fragOn", false));
            ah_detect::g_bleMalformedEnabled.store(p.getBool("blemOn", false));
            ah_detect::g_hshkEnabled.store(p.getBool("hshkOn", false));
            ah_detect::g_pwnaEnabled.store(p.getBool("pwnaOn", false));
            ah_detect::g_trackerEnabled.store(p.getBool("trkOn", false));
            ah_detect::g_airtagEnabled.store(p.getBool("atgOn", false));
            ah_detect::g_tsfEnabled.store(p.getBool("tsfOn", false));
            ah_detect::g_ridSpoofEnabled.store(p.getBool("ridOn", false));
            ah_detect::g_bloomGossipEnabled.store(p.getBool("blmgOn", false));
            {
                bool migrated = p.getBool("trlMig2", false);
                if (!migrated) {
                    p.putBool("trlOn", false);
                    p.putBool("trlMig2", true);
                    ah_detect::g_attackerTrilatEnabled.store(false);
                    Serial.println("[NVS] Migration: forced attacker_trilat=false (one-shot)");
                } else {
                    ah_detect::g_attackerTrilatEnabled.store(p.getBool("trlOn", false));
                }
            }
            ah_detect::g_meshPmkid.store(p.getBool("mPmkid", true));
            ah_detect::g_meshEviltwin.store(p.getBool("mEtw", true));
            ah_detect::g_meshSsidConf.store(p.getBool("mScn", true));
            ah_detect::g_meshSae.store(p.getBool("mSae", true));
            ah_detect::g_meshFrag.store(p.getBool("mFrag", false));
            ah_detect::g_meshBleMalformed.store(p.getBool("mBlem", false));
            ah_detect::g_meshHshk.store(p.getBool("mHshk", false));
            ah_detect::g_meshKrack.store(p.getBool("mKrack", true));
            ah_detect::g_meshTracker.store(p.getBool("mTrk", true));
            ah_detect::g_meshPwna.store(p.getBool("mPwna", true));
            ah_detect::g_meshKarma.store(p.getBool("mKarma", true));
            ah_detect::g_meshRecon.store(p.getBool("mRecon", true));
            ah_detect::g_meshCsiMotion.store(p.getBool("mCsim", false));
            ah_detect::g_meshAttackerHunt.store(p.getBool("mHunt", true));
            ah_detect::g_probeFloodEnabled.store(p.getBool("pflOn", true));
            ah_detect::g_assocSleepEnabled.store(p.getBool("aslOn", true));
            ah_detect::g_bleAttackEnabled.store(p.getBool("blatkOn", true));
            p.end();
        }
    }
    ah_detect::csi_init();
    xTaskCreatePinnedToCore(ah_detect::csiDrainTask, "CsiDrain", 4096, NULL, 2, NULL, 1);
    {
        static const char *kBootClear[] = {
            "/deauth_flood.jsonl", "/deauth_ap.jsonl", "/assoc_sleep.jsonl",
            "/sae_dos.jsonl", "/pmkid.jsonl", "/pmkid_forge.jsonl", "/eviltwin.jsonl",
            "/ssid_confusion.jsonl", "/owe_abuse.jsonl", "/fragattack.jsonl",
            "/ble_malformed.jsonl", "/ble_attack.jsonl", "/probe_flood.jsonl"
        };
        for (const char *pth : kBootClear) {
            if (SafeSD::exists(pth)) SafeSD::remove(pth);
        }
    }
    Serial.println("[DETECT] Initialized");
}

extern std::atomic<bool> scanning;
extern void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
extern std::vector<uint8_t> CHANNELS;   // user-configured scan channel list

static std::atomic<bool> g_sentinelAlwaysOnActive{false};
static std::atomic<bool> g_sentinelUserEnabled{false};
static TaskHandle_t g_sentinelTaskHandle = nullptr;

static void sentinelAlwaysOnTask(void *pv) {
    (void)pv;
    uint8_t apChan = AP_CHANNEL;
    { uint8_t prim = 0; wifi_second_chan_t sec; if (esp_wifi_get_channel(&prim, &sec) == ESP_OK && prim) apChan = prim; }
    Serial.printf("[SENTINEL] task started ap_ch=%u mode=%s\n", (unsigned)apChan,
                  g_sentinelScanMode.load() ? "scan" : "pin");
    bool weOwn = false;
    while (g_sentinelUserEnabled.load() && !scanning.load()) {
        if (!weOwn) {
            bool wantData = g_pmkidEnabled.load() || g_hshkEnabled.load() || g_fragEnabled.load();
            wifi_promiscuous_filter_t filter = {};
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
            if (wantData) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
            esp_err_t r1 = esp_wifi_set_promiscuous_filter(&filter);
            esp_err_t r2 = esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
            esp_err_t r3 = esp_wifi_set_promiscuous(true);
            weOwn = true;
            Serial.printf("[SENTINEL] Took radio: filter=%s r1=%d r2=%d r3=%d\n",
                          wantData ? "MGMT+DATA" : "MGMT", (int)r1, (int)r2, (int)r3);
        }
        // Proactive KARMA bait: fake-SSID probe; any AP that answers = karma.
        static uint32_t s_lastBait = 0;
        if (g_karmaEnabled.load() && (millis() - s_lastBait > 8000)) {
            s_lastBait = millis();
            karmaEmitBait(nullptr);
        }
        if (!g_sentinelScanMode.load()) {
            // PIN: stay on the AP channel. Catches attacks against us, keeps AP clients
            // associated (no hop -> no false DEAUTH_AP_TARGETED from churn).
            esp_wifi_set_channel(apChan, WIFI_SECOND_CHAN_NONE);
            uint32_t waited = 0;
            while (waited < 1000 && g_sentinelUserEnabled.load() && !scanning.load()
                   && !g_sentinelScanMode.load()) {
                vTaskDelay(pdMS_TO_TICKS(20));
                waited += 20;
            }
        } else {
            // SCAN: hop the configured channel list (AP channel weighted).
            std::vector<uint8_t> chans;
            {
                std::lock_guard<std::recursive_mutex> lk(g_mtx);
                chans = CHANNELS;
            }
            if (chans.empty()) chans.push_back(apChan);
            for (uint8_t ch : chans) {
                if (!g_sentinelUserEnabled.load() || scanning.load() || !g_sentinelScanMode.load()) break;
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                uint32_t dwellMs = (ch == apChan) ? 400 : 120;
                uint32_t waited = 0;
                while (waited < dwellMs && g_sentinelUserEnabled.load() && !scanning.load()) {
                    vTaskDelay(pdMS_TO_TICKS(20));
                    waited += 20;
                }
            }
        }
    }
    if (weOwn) {
        esp_wifi_set_channel(apChan, WIFI_SECOND_CHAN_NONE);
        esp_wifi_set_promiscuous(false);
    }
    Serial.println("[SENTINEL] Task exiting (disabled or scan started)");
    g_sentinelTaskHandle = nullptr;
    g_sentinelAlwaysOnActive.store(false);
    vTaskDelete(NULL);
}

void sentinel_startAlwaysOn() {
    if (!g_sentinelUserEnabled.load()) return;
    if (scanning.load()) return;
    if (g_sentinelAlwaysOnActive.exchange(true)) return;
    xTaskCreatePinnedToCore(sentinelAlwaysOnTask, "Sentinel", 4096, NULL, 2,
                            &g_sentinelTaskHandle, 1);
}

void sentinel_kill() {
    g_sentinelUserEnabled.store(false);
}

void sentinel_setUserEnabled(bool on) {
    bool prev = g_sentinelUserEnabled.exchange(on);
    if (!on && prev) {
        esp_wifi_set_promiscuous(false);
        Serial.println("[SENTINEL] Stop requested — promiscuous released immediately");
    }
    if (on && !prev && !scanning.load()) {
        sentinel_startAlwaysOn();
    }
}

bool sentinel_isUserEnabled() { return g_sentinelUserEnabled.load(); }
bool sentinel_isRunning() { return g_sentinelAlwaysOnActive.load(); }

void sentinel_loadUserPref() {
    // Sentinel OFF at boot. (Auto-enabling here started promiscuous during setup,
    // before radioStartBLE() -> NimBLE esp_timer_create OOM'd -> boot crash loop.
    // Enable via UI after boot, or wire a deferred start AFTER BLE init if needed.)
    g_sentinelUserEnabled.store(false);
}

void detect_persistTunables() {
    Preferences p;
    if (!p.begin("ahdetect", false)) return;
    p.putUShort("csiThr", ah_detect::g_csiThreshQ8.load());
    p.putUShort("pmkidWin", ah_detect::g_pmkidWindow.load());
    p.putUChar("pmkidN", ah_detect::g_pmkidMinBssids.load());
    p.putUChar("saeN", ah_detect::g_saeUnmatchedThresh.load());
    p.putUShort("saeWin", ah_detect::g_saeWindow.load());
    p.putUChar("fragN", ah_detect::g_fragReuseThresh.load());
    p.putBool("karmaOn", ah_detect::g_karmaEnabled.load());
    p.putBool("csiOn", ah_detect::g_csiEnabled.load());
    p.putULong("trkWin", ah_detect::g_trackerWindowMs.load());
    p.putULong("huntCool", ah_detect::g_huntCooldown.load());
    p.putBool("pmkidOn", ah_detect::g_pmkidEnabled.load());
    p.putBool("etwOn", ah_detect::g_eviltwinEnabled.load());
    p.putBool("scnOn", ah_detect::g_ssidConfusionEnabled.load());
    p.putBool("saeOn", ah_detect::g_saeEnabled.load());
    p.putBool("sclScan", ah_detect::g_sentinelScanMode.load());
    p.putBool("oweOn", ah_detect::g_oweEnabled.load());
    p.putBool("fragOn", ah_detect::g_fragEnabled.load());
    p.putBool("blemOn", ah_detect::g_bleMalformedEnabled.load());
    p.putBool("hshkOn", ah_detect::g_hshkEnabled.load());
    p.putBool("pwnaOn", ah_detect::g_pwnaEnabled.load());
    p.putBool("trkOn", ah_detect::g_trackerEnabled.load());
    p.putBool("atgOn", ah_detect::g_airtagEnabled.load());
    p.putBool("tsfOn", ah_detect::g_tsfEnabled.load());
    p.putBool("ridOn", ah_detect::g_ridSpoofEnabled.load());
    p.putBool("blmgOn", ah_detect::g_bloomGossipEnabled.load());
    p.putBool("trlOn", ah_detect::g_attackerTrilatEnabled.load());
    p.putBool("mPmkid", ah_detect::g_meshPmkid.load());
    p.putBool("mEtw", ah_detect::g_meshEviltwin.load());
    p.putBool("mScn", ah_detect::g_meshSsidConf.load());
    p.putBool("mSae", ah_detect::g_meshSae.load());
    p.putBool("mFrag", ah_detect::g_meshFrag.load());
    p.putBool("mBlem", ah_detect::g_meshBleMalformed.load());
    p.putBool("mHshk", ah_detect::g_meshHshk.load());
    p.putBool("mKrack", ah_detect::g_meshKrack.load());
    p.putBool("pflOn",   ah_detect::g_probeFloodEnabled.load());
    p.putBool("aslOn",   ah_detect::g_assocSleepEnabled.load());
    p.putBool("blatkOn", ah_detect::g_bleAttackEnabled.load());
    p.putBool("mTrk", ah_detect::g_meshTracker.load());
    p.putBool("mPwna", ah_detect::g_meshPwna.load());
    p.putBool("mKarma", ah_detect::g_meshKarma.load());
    p.putBool("mRecon", ah_detect::g_meshRecon.load());
    p.putBool("mCsim", ah_detect::g_meshCsiMotion.load());
    p.putBool("mHunt", ah_detect::g_meshAttackerHunt.load());
    p.end();
}

void IRAM_ATTR detect_onWifiFrame(const uint8_t *payload, uint16_t len, int8_t rssi, uint8_t channel) {
    if (!detectEnabled.load() || !detectFrameQueue) return;
    if (len < 24) return;
    uint16_t fc = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t stype = (fc >> 4) & 0xF;
    uint8_t kind = 0;
    bool eapolHit = false;
    if (ftype == 2 && len >= 32) {
        int searchEnd = (int)len - 8;
        for (int i = 24; i < searchEnd && i < 40; ++i) {
            if (payload[i] == 0xAA && payload[i+1] == 0xAA && payload[i+2] == 0x03 &&
                payload[i+6] == 0x88 && payload[i+7] == 0x8E) {
                eapolHit = true;
                break;
            }
        }
    }
    if (ftype == 0 && stype == 8)        kind = DetectFrameEvent::BEACON_DEEP;
    else if (ftype == 0 && stype == 5)   kind = DetectFrameEvent::PROBE_RESP;
    else if (ftype == 0 && stype == 4)   kind = DetectFrameEvent::PROBE_REQ;
    else if (ftype == 0 && (stype == 0 || stype == 2)) kind = DetectFrameEvent::ASSOC_REQ;
    else if (ftype == 0 && (stype == 10 || stype == 12)) kind = DetectFrameEvent::DEAUTH;
    else if (ftype == 0 && stype == 11)  kind = DetectFrameEvent::AUTH_SAE;
    else if (eapolHit)                   kind = DetectFrameEvent::EAPOL;   // PMKID/handshake — keep
    // QoS data only when frag detection is on; otherwise normal data traffic
    // floods the queue. All other data frames are dropped here at the ISR — the
    // old catch-all (enqueue every data frame as EAPOL) is what hung DATA capture.
    else if (ftype == 2 && stype == 8 && g_fragEnabled.load()) kind = DetectFrameEvent::QOS_DATA;
    else return;
    // Backpressure: drop if queue full rather than spinning the ISR.
    // Note: uxQueueSpacesAvailable is also safe-from-ISR on ESP-IDF FreeRTOS port.
    if (uxQueueSpacesAvailable(detectFrameQueue) < 2) { g_droppedWifi.fetch_add(1); return; }
    DetectFrameEvent ev;
    ev.kind = kind;
    ev.channel = channel;
    ev.rssi = rssi;
    ev.rxMicrosLo = 0;
    uint16_t cap = (len < sizeof(ev.payload)) ? len : (uint16_t)sizeof(ev.payload);
    memcpy(ev.payload, payload, cap);
    ev.len = cap;
    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(detectFrameQueue, &ev, &woken);
    if (woken) portYIELD_FROM_ISR();
}

// BLE callback runs on nimble_host task — must not do heavy work here.
// Defer to detectTask via queue. Drop on backpressure.
void detect_onBleAdv(const uint8_t *addr, int8_t rssi,
                     const uint8_t *payload, uint16_t payloadLen,
                     const char *name) {
    if (!detectEnabled.load() || !detectFrameQueue || !addr || !payload) return;
    if (uxQueueSpacesAvailable(detectFrameQueue) < 4) { g_droppedBle.fetch_add(1); return; }
    DetectFrameEvent ev;
    ev.kind = DetectFrameEvent::BLE_ADV;
    ev.channel = 0;
    ev.rssi = rssi;
    ev.rxMicrosLo = 0;
    // Layout: [0..5]=BLE addr, [6..]=adv payload. BLE adv max 31, fits.
    memcpy(ev.payload, addr, 6);
    uint16_t cap = (payloadLen < (sizeof(ev.payload) - 6))
                   ? payloadLen : (uint16_t)(sizeof(ev.payload) - 6);
    memcpy(ev.payload + 6, payload, cap);
    ev.len = (uint16_t)(6 + cap);
    (void)name;
    xQueueSend(detectFrameQueue, &ev, 0);
}

void detectTask(void *pv) {
    Serial.println("[DETECT] Task started");
    loadSnapshot();
    DetectFrameEvent ev;
    uint32_t lastGossip = millis();
    uint32_t lastPpsEpochUpdate = 0;
    uint32_t lastAgeSweep = millis();
    uint32_t lastPersist = millis();
    while (true) {
        if (xQueueReceive(detectFrameQueue, &ev, pdMS_TO_TICKS(100)) == pdTRUE) {
            switch (ev.kind) {
                case DetectFrameEvent::EAPOL:       handleEAPOL(ev); break;
                case DetectFrameEvent::AUTH_SAE:    handleAuthSae(ev); break;
                case DetectFrameEvent::DEAUTH:      handleDeauthFrame(ev); break;
                case DetectFrameEvent::BEACON_DEEP: handleBeacon(ev); break;
                case DetectFrameEvent::PROBE_RESP:  handleProbeResp(ev); break;
                case DetectFrameEvent::PROBE_REQ:   handleProbeReq(ev); break;
                case DetectFrameEvent::ASSOC_REQ:   handleAssocReq(ev); break;
                case DetectFrameEvent::QOS_DATA:    handleQosData(ev); break;
                case DetectFrameEvent::BLE_ADV: {
                    // [0..5]=addr, [6..]=payload
                    if (ev.len >= 6) {
                        onBleAdv(ev.payload, ev.rssi, ev.payload + 6,
                                 (uint16_t)(ev.len - 6), nullptr);
                    }
                    break;
                }
                default: break;
            }
        }
        uint32_t now = millis();
        // PPS epoch slow-update (avoid I2C in ISR)
        if (now - lastPpsEpochUpdate > 1000) {
            lastPpsEpochUpdate = now;
            if (g_ppsAnchorMicros != 0 && rtcAvailable) {
                time_t e = getRTCEpoch();
                g_ppsAnchorEpoch = (uint32_t)e;
                if (gpsValid) g_ppsLocked.store(true);
            }
        }
        // Periodic mesh gossip — Bloom filter
        if (meshEnabled && g_bloomGossipEnabled.load() && now - lastGossip > 300000) {
            lastGossip = now;
            detect_periodicMeshGossip();
        }
        if (now - lastPersist > 300000) {
            lastPersist = now;
            persistSnapshot();
        }
        if (now - lastAgeSweep > 30000) {
            lastAgeSweep = now;
            std::lock_guard<std::recursive_mutex> lk(g_mtx);
            for (auto it = g_alerts.begin(); it != g_alerts.end(); ) {
                if (now - it->second.firstSeen > 120000) it = g_alerts.erase(it);
                else ++it;
            }
            for (auto it = g_pmkidBursts.begin(); it != g_pmkidBursts.end(); ) {
                if (now - it->second.lastSeen > 300000) it = g_pmkidBursts.erase(it);
                else ++it;
            }
            for (auto it = g_saeCounters.begin(); it != g_saeCounters.end(); ) {
                if (now - it->second.windowStart > 60000) it = g_saeCounters.erase(it);
                else ++it;
            }
            for (auto it = g_pnState.begin(); it != g_pnState.end(); ) {
                if (now - it->second.lastSeen > 600000) it = g_pnState.erase(it);
                else ++it;
            }
            for (auto it = g_apBaseline.begin(); it != g_apBaseline.end(); ) {
                if (now - it->second.lastSeen > 3600000UL) it = g_apBaseline.erase(it);
                else ++it;
            }
            for (auto it = g_tsfTrack.begin(); it != g_tsfTrack.end(); ) {
                if (now - it->second.lastSeen > 3600000UL) it = g_tsfTrack.erase(it);
                else ++it;
            }
            for (auto it = g_bleTrackers.begin(); it != g_bleTrackers.end(); ) {
                if (now - it->second.lastSeen > 1800000UL) it = g_bleTrackers.erase(it);
                else ++it;
            }
            for (auto it = g_airtag.begin(); it != g_airtag.end(); ) {
                if (now - it->second.lastSeen > 1800000UL) it = g_airtag.erase(it);
                else ++it;
            }
            for (auto it = g_chains.begin(); it != g_chains.end(); ) {
                if (now - it->second.lastSeen > 7200000UL) it = g_chains.erase(it);
                else ++it;
            }
            for (auto it = g_hunts.begin(); it != g_hunts.end(); ) {
                if (now - it->second.lastKick > 600000UL) it = g_hunts.erase(it);
                else ++it;
            }
            for (auto it = g_recon.begin(); it != g_recon.end(); ) {
                if (now - it->second.ts > 1800000UL) it = g_recon.erase(it);
                else ++it;
            }
            for (auto it = g_pwna.begin(); it != g_pwna.end(); ) {
                if (now - it->second.lastSeen > 1800000UL) it = g_pwna.erase(it);
                else ++it;
            }
            for (auto it = g_karma.begin(); it != g_karma.end(); ) {
                if (now - it->second.lastSeen > 600000UL) { g_karmaSsids.erase(it->first); it = g_karma.erase(it); }
                else ++it;
            }
            for (auto it = g_tofPeers.begin(); it != g_tofPeers.end(); ) {
                if (now - it->second.lastSeen > 1800000UL) it = g_tofPeers.erase(it);
                else ++it;
            }
            for (auto it = g_csiFp.begin(); it != g_csiFp.end(); ) {
                if (now - it->second.lastSeen > 600000UL) it = g_csiFp.erase(it);
                else ++it;
            }
            for (auto it = g_csiHist.begin(); it != g_csiHist.end(); ) {
                if (now - it->second.lastTs > 300000UL) it = g_csiHist.erase(it);
                else ++it;
            }
            for (auto it = g_pgGraph.begin(); it != g_pgGraph.end(); ) {
                if (now - it->second.lastSeen > 3600000UL) it = g_pgGraph.erase(it);
                else ++it;
            }
            for (auto it = g_hshk.begin(); it != g_hshk.end(); ) {
                if (now - it->second.lastSeen > 1800000UL) it = g_hshk.erase(it);
                else ++it;
            }
        }
    }
}

// =============================================================================
// Quorum
// =============================================================================
void quorum_addReport(const String &type, const String &key,
                      const String &fromNode, int8_t rssi) {
    String k = type + ":" + key;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto &c = g_alerts[k];
    if (c.firstSeen == 0) {
        c.type = type; c.key = key; c.firstSeen = now; c.fired = false;
    }
    bool seen = false;
    for (auto &r : c.reports) if (r.nodeId == fromNode) { seen = true; r.rssi = rssi; r.ts = now; break; }
    if (!seen) {
        AlertCandidate::Report r;
        r.nodeId = fromNode; r.rssi = rssi; r.ts = now;
        c.reports.push_back(r);
    }
    uint8_t need = g_quorumRequired.count(type) ? g_quorumRequired[type] : 2;
    if (!c.fired && c.reports.size() >= need) {
        // Krum-lite: drop most-divergent when N>=5
        std::vector<int> rssis;
        for (auto &r : c.reports) rssis.push_back(r.rssi);
        if (rssis.size() >= 5) {
            int sum = 0; for (int v : rssis) sum += v;
            int mean = sum / (int)rssis.size();
            int worstIdx = 0; int worstD = -1;
            for (size_t i = 0; i < rssis.size(); ++i) {
                int d = std::abs(rssis[i] - mean);
                if (d > worstD) { worstD = d; worstIdx = (int)i; }
            }
            rssis.erase(rssis.begin() + worstIdx);
        }
        std::sort(rssis.begin(), rssis.end());
        int median = rssis[rssis.size() / 2];
        if (median > -85) {
            c.fired = true;
            String line = String("{\"type\":\"") + type +
                          "\",\"key\":\"" + key +
                          "\",\"nodes\":" + String((unsigned)c.reports.size()) +
                          ",\"median_rssi\":" + String(median) +
                          ",\"ts\":" + String(now) + "}";
            logEventToSD("/quorum.jsonl", line);
            Serial.printf("[QUORUM] %s fired key=%s nodes=%u\n",
                          type.c_str(), key.c_str(), (unsigned)c.reports.size());
        }
    }
}

size_t quorum_currentConfirmingNodes(const String &type, const String &key) {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_alerts.find(type + ":" + key);
    if (it == g_alerts.end()) return 0;
    return it->second.reports.size();
}
void quorum_setRequired(const String &type, uint8_t n) {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_quorumRequired[type] = n;
}
uint8_t quorum_getRequired(const String &type) {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_quorumRequired.find(type);
    return it == g_quorumRequired.end() ? 2 : it->second;
}

// =============================================================================
// Mesh handling for new prefixes
// =============================================================================
// Global wrappers for unified incident log
void detect_logIncident(const String &raw, const char *src) {
    ah_detect::detect_logIncident(raw, src);
}
String detect_getIncidentsJson(size_t maxEntries) {
    return ah_detect::detect_getIncidentsJson(maxEntries);
}
void detect_clearIncidents() {
    ah_detect::detect_clearIncidents();
}

namespace {
    struct SoftApDeauthState {
        uint32_t winStartMs;
        uint16_t count;
        bool alerted;
    } g_softApDeauth = {0, 0, false};
    static std::recursive_mutex g_softApMtx;
    static constexpr uint32_t SOFTAP_DEAUTH_WIN_MS = 10000;
    static constexpr uint16_t SOFTAP_DEAUTH_THRESH = 3;
    struct SoftApProbeState {
        std::map<uint64_t, uint16_t> srcCounts;
        uint32_t winStartMs;
        bool alerted;
    } g_softApProbe;
    static constexpr uint32_t SOFTAP_PROBE_WIN_MS = 10000;
    static constexpr uint16_t SOFTAP_PROBE_DISTINCT = 20;
}

void detect_onSoftApDisconnect(const uint8_t *clientMac, uint8_t reasonCode) {
    if (!clientMac) return;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_softApMtx);
    if ((now - g_softApDeauth.winStartMs) > SOFTAP_DEAUTH_WIN_MS) {
        g_softApDeauth.winStartMs = now;
        g_softApDeauth.count = 0;
        g_softApDeauth.alerted = false;
    }
    g_softApDeauth.count++;
    Serial.printf("[AP] STA disconnect mac=%02X:%02X:%02X:%02X:%02X:%02X reason=%u count=%u/%ums\n",
                  clientMac[0],clientMac[1],clientMac[2],clientMac[3],clientMac[4],clientMac[5],
                  reasonCode, g_softApDeauth.count, (unsigned)(now - g_softApDeauth.winStartMs));
    bool deauthFrameSeen = (now - g_lastRealDeauthMs.load()) < 3000;
    if (!g_softApDeauth.alerted && g_softApDeauth.count >= SOFTAP_DEAUTH_THRESH && deauthFrameSeen) {
        g_softApDeauth.alerted = true;
        char mc[18];
        snprintf(mc, sizeof(mc), "%02X:%02X:%02X:%02X:%02X:%02X",
                 clientMac[0],clientMac[1],clientMac[2],clientMac[3],clientMac[4],clientMac[5]);
        String body = String("DEAUTH_AP_TARGETED:") + mc + ":" + String(reasonCode) + ":" + String(g_softApDeauth.count);
        Serial.printf("[DETECT] %s (AP under deauth - %u disconnects in %ums)\n",
                      body.c_str(), g_softApDeauth.count, (unsigned)(now - g_softApDeauth.winStartMs));
        ::detect_logIncident(body, mc);
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": " + body, true);
        }
        String line = String("{\"client\":\"") + mc +
                      "\",\"reason\":" + String(reasonCode) +
                      ",\"count\":" + String(g_softApDeauth.count) +
                      ",\"win_ms\":" + String(now - g_softApDeauth.winStartMs) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/deauth_ap.jsonl", line);
    }
}

void detect_onSoftApProbeReq(const uint8_t *srcMac, int8_t rssi) {
    if (!srcMac) return;
    uint32_t now = millis();
    std::lock_guard<std::recursive_mutex> lk(g_softApMtx);
    if ((now - g_softApProbe.winStartMs) > SOFTAP_PROBE_WIN_MS) {
        g_softApProbe.srcCounts.clear();
        g_softApProbe.winStartMs = now;
        g_softApProbe.alerted = false;
    }
    uint64_t k = ((uint64_t)srcMac[0]<<40)|((uint64_t)srcMac[1]<<32)|
                 ((uint64_t)srcMac[2]<<24)|((uint64_t)srcMac[3]<<16)|
                 ((uint64_t)srcMac[4]<<8)|(uint64_t)srcMac[5];
    g_softApProbe.srcCounts[k]++;
    if (!g_softApProbe.alerted && g_softApProbe.srcCounts.size() >= SOFTAP_PROBE_DISTINCT) {
        g_softApProbe.alerted = true;
        Serial.printf("[DETECT] PROBE_FLOOD_AP distinct=%u in %ums rssi=%d\n",
                      (unsigned)g_softApProbe.srcCounts.size(),
                      (unsigned)(now - g_softApProbe.winStartMs), (int)rssi);
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": PROBE_FLOOD_AP:" + String((unsigned)g_softApProbe.srcCounts.size()) +
                          ":" + String((int)rssi), true);
        }
        String line = String("{\"distinct\":") + String((unsigned)g_softApProbe.srcCounts.size()) +
                      ",\"win_ms\":" + String(now - g_softApProbe.winStartMs) +
                      ",\"rssi\":" + String((int)rssi) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/probe_ap.jsonl", line);
    }
}

extern void _detect_recordMeshPeer(const String &fromNode);
void detect_processMesh(const String &fromNode, const String &msg) {
    _detect_recordMeshPeer(fromNode);
    ah_detect::detect_logIncident(msg, fromNode.c_str());

    // === New tool-fingerprint quorum aggregators ===
    if (msg.startsWith("BEACON_FORGE:")) {
        // BEACON_FORGE:<bssid>:<reason>:<rssi>
        int p1 = msg.indexOf(':', 13);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String bssid = msg.substring(13, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("BEACON_FORGE", bssid, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("BLE_ATTACK:")) {
        // BLE_ATTACK:<tool>:<addr>:<rssi>
        int p1 = msg.indexOf(':', 11);
        int p2 = msg.indexOf(':', p1 + 1);
        int p3 = msg.indexOf(':', p2 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0) return;
        String addr = msg.substring(p1 + 1, p2);
        int rssi = msg.substring(p3 + 1).toInt();
        quorum_addReport("BLE_ATTACK", addr, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("PMKID_FORGE:")) {
        // PMKID_FORGE:<src>:<sta>:<rssi>
        int p1 = msg.indexOf(':', 12);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String src = msg.substring(12, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("PMKID_FORGE", src, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("EAPOL_BAIT:")) {
        // EAPOL_BAIT:<src>:<sta>:<count>:<rssi>[:<confidence>]
        int p1 = msg.indexOf(':', 11);
        int p2 = msg.indexOf(':', p1 + 1);
        int p3 = msg.indexOf(':', p2 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0) return;
        String src = msg.substring(11, p1);
        int rssi = msg.substring(p3 + 1).toInt();
        quorum_addReport("EAPOL_BAIT", src, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("PROBE_FLOOD:") || msg.startsWith("PROBE_FLOOD_BEHAVE:")) {
        // PROBE_FLOOD[_BEHAVE]:<ssid>:<count>:<rssi> — key on SSID
        size_t prefixLen = msg.startsWith("PROBE_FLOOD_BEHAVE:") ? 19 : 12;
        int p1 = msg.indexOf(':', prefixLen);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String ssid = msg.substring(prefixLen, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("PROBE_FLOOD", ssid, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("ASSOC_SLEEP:")) {
        // ASSOC_SLEEP:<bssid>:<distinct_src>:<rssi>
        int p1 = msg.indexOf(':', 12);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String bssid = msg.substring(12, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("ASSOC_SLEEP", bssid, fromNode, (int8_t)rssi);
        return;
    }
    if (msg.startsWith("DEAUTH_FLOOD:")) {
        // DEAUTH_FLOOD:<src>:<count>:<rssi>
        int p1 = msg.indexOf(':', 13);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String src = msg.substring(13, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("DEAUTH_FLOOD", src, fromNode, (int8_t)rssi);
        return;
    }
    // === Existing handlers ===
    if (msg.startsWith("PMKID_HARVEST:")) {
        int p1 = msg.indexOf(':', 14);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String src = msg.substring(14, p1);
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("PMKID", src, fromNode, (int8_t)rssi);
    } else if (msg.startsWith("EVILTWIN:")) {
        int p1 = msg.indexOf(':', 9);
        if (p1 < 0) return;
        String bssid = msg.substring(9, p1);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p2 < 0) return;
        int rssi = msg.substring(p2 + 1).toInt();
        quorum_addReport("EVILTWIN", bssid, fromNode, (int8_t)rssi);
    } else if (msg.startsWith("SSID_CONFUSION:")) {
        int p1 = msg.indexOf(':', 15);
        if (p1 < 0) return;
        String bssid = msg.substring(15, p1);
        int rssi = msg.substring(p1 + 1).toInt();
        quorum_addReport("SSIDCONF", bssid, fromNode, (int8_t)rssi);
    } else if (msg.startsWith("SAE_DOS:")) {
        int p1 = msg.indexOf(':', 8);
        if (p1 < 0) return;
        String bssid = msg.substring(8, p1);
        quorum_addReport("SAE_DOS", bssid, fromNode, -50);
    } else if (msg.startsWith("BLETRACK:")) {
        int p1 = msg.indexOf(':', 9);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String addr = msg.substring(9, p1);
        quorum_addReport("BLETRACK", addr, fromNode, -60);
    } else if (msg.startsWith("RID_CLAIM:")) {
        // uavId:lat:lon:alt
        String rest = msg.substring(10);
        int p1 = rest.indexOf(':');
        int p2 = rest.indexOf(':', p1 + 1);
        int p3 = rest.indexOf(':', p2 + 1);
        if (p1 < 0 || p2 < 0) return;
        String uavId = rest.substring(0, p1);
        double lat = rest.substring(p1 + 1, p2).toDouble();
        double lon = rest.substring(p2 + 1, p3 > 0 ? p3 : rest.length()).toDouble();
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        auto &c = g_ridClaims[uavId];
        strncpy(c.uavId, uavId.c_str(), sizeof(c.uavId) - 1);
        c.lat = lat;
        c.lon = lon;
        c.ts = millis();
    } else if (msg.startsWith("RID_RX:")) {
        // uavId:rssi:lat:lon:gpsValid
        String rest = msg.substring(7);
        int p1 = rest.indexOf(':');
        int p2 = rest.indexOf(':', p1 + 1);
        int p3 = rest.indexOf(':', p2 + 1);
        int p4 = rest.indexOf(':', p3 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0) return;
        String uavId = rest.substring(0, p1);
        int rssi = rest.substring(p1 + 1, p2).toInt();
        double lat = rest.substring(p2 + 1, p3).toDouble();
        double lon = rest.substring(p3 + 1, p4).toDouble();
        int valid = rest.substring(p4 + 1).toInt();
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        auto &c = g_ridClaims[uavId];
        strncpy(c.uavId, uavId.c_str(), sizeof(c.uavId) - 1);
        RidClaim::Rx rx;
        rx.nodeId = fromNode; rx.rssi = (int8_t)rssi;
        rx.nodeLat = lat; rx.nodeLon = lon; rx.hasGps = (valid != 0);
        rx.ts = millis();
        c.rxs.push_back(rx);
        if (c.rxs.size() > 16) c.rxs.erase(c.rxs.begin());
    } else if (msg.startsWith("HSHK:")) {
        int p1 = msg.indexOf(':', 5);
        int p2 = msg.indexOf(':', p1 + 1);
        int p3 = msg.indexOf(':', p2 + 1);
        int p4 = msg.indexOf(':', p3 + 1);
        int p5 = msg.indexOf(':', p4 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0 || p5 < 0) return;
        String bssidS = msg.substring(5, p1);
        String staS   = msg.substring(p1 + 1, p2);
        int mn        = msg.substring(p2 + 1, p3).toInt();
        uint64_t rc   = (uint64_t)strtoull(msg.substring(p3 + 1, p4).c_str(), nullptr, 10);
        int rssi      = msg.substring(p4 + 1, p5).toInt();
        uint8_t bssid[6], sta[6];
        auto parse = [](const String &s, uint8_t out[6]) -> bool {
            String t;
            for (size_t i = 0; i < s.length(); ++i) { char c = s[i]; if (isxdigit((int)c)) t += (char)toupper(c); }
            if (t.length() != 12) return false;
            for (int i = 0; i < 6; i++) out[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
            return true;
        };
        if (!parse(bssidS, bssid) || !parse(staS, sta)) return;
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        hshkRecord(bssid, sta, (uint8_t)mn, rc, (int8_t)rssi, fromNode.c_str(), millis());
    } else if (msg.startsWith("KRACK:")) {
        g_krackEvents.fetch_add(1);
    } else if (msg.startsWith("TOF_PING:")) {
        int p1 = msg.indexOf(':', 9);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        String target = msg.substring(9, p1);
        if (target != getNodeId() && target != "*") return;
        uint32_t seq = (uint32_t)strtoul(msg.substring(p1 + 1, p2).c_str(), nullptr, 10);
        uint64_t theirTxUs = strtoull(msg.substring(p2 + 1).c_str(), nullptr, 10);
        ah_detect::tof_processPing(fromNode, seq, theirTxUs);
    } else if (msg.startsWith("TOF_PONG:")) {
        int p1 = msg.indexOf(':', 9);
        int p2 = msg.indexOf(':', p1 + 1);
        int p3 = msg.indexOf(':', p2 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0) return;
        String forNode = msg.substring(9, p1);
        if (forNode != getNodeId()) return;
        uint32_t seq = (uint32_t)strtoul(msg.substring(p1 + 1, p2).c_str(), nullptr, 10);
        uint64_t origTx = strtoull(msg.substring(p2 + 1, p3).c_str(), nullptr, 10);
        uint64_t theirRx = strtoull(msg.substring(p3 + 1).c_str(), nullptr, 10);
        ah_detect::tof_processPong(fromNode, seq, origTx, theirRx);
    } else if (msg.startsWith("ATTACKER_HUNT:")) {
        int p1 = msg.indexOf(':', 14);
        if (p1 < 0) return;
        String macS = msg.substring(14, p1);
        String type = msg.substring(p1 + 1);
        uint8_t mac[6];
        String t;
        for (size_t i = 0; i < macS.length(); ++i) { char c = macS[i]; if (isxdigit((int)c)) t += (char)toupper(c); }
        if (t.length() != 12) return;
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        ah_detect::attacker_kick(mac, type.c_str());
    } else if (msg.startsWith("RECON:")) {
        int p1 = msg.indexOf(':', 6);
        if (p1 < 0) return;
        String idStr = msg.substring(6, p1);
        int score = msg.substring(p1 + 1).toInt();
        quorum_addReport("RECON", idStr, fromNode, -50);
        if (score >= 70) {
            std::lock_guard<std::recursive_mutex> lk(g_mtx);
            auto &r = g_recon[idStr];
            strncpy(r.identityId, idStr.c_str(), sizeof(r.identityId) - 1);
            if ((int)r.score < score) r.score = (uint8_t)score;
            r.ts = millis();
        }
    } else if (msg.startsWith("FRAG:")) {
        int p1 = msg.indexOf(':', 5);
        if (p1 < 0) return;
        String src = msg.substring(5, p1);
        quorum_addReport("FRAG", src, fromNode, -60);
    } else if (msg.startsWith("CSI_MOTION:")) {
        int p1 = msg.indexOf(':', 11);
        if (p1 < 0) return;
        String src = msg.substring(11, p1);
        quorum_addReport("CSI_MOTION", src, fromNode, -60);
    } else if (msg.startsWith("PWNAGOTCHI:")) {
        int p1 = msg.indexOf(':', 11);
        if (p1 < 0) return;
        String bssid = msg.substring(11, p1);
        int rssi = msg.substring(p1 + 1).toInt();
        quorum_addReport("PWNAGOTCHI", bssid, fromNode, (int8_t)rssi);
    } else if (msg.startsWith("KARMA_CAND:") || msg.startsWith("KARMA_CONFIRMED:")) {
        int offs = msg.startsWith("KARMA_CONFIRMED:") ? 16 : 11;
        int p1 = msg.indexOf(':', offs);
        if (p1 < 0) return;
        String bssid = msg.substring(offs, p1);
        int sec = msg.substring(p1 + 1).toInt();
        quorum_addReport("KARMA", bssid, fromNode, (int8_t)sec);
    } else if (msg.startsWith("TRK_LINK:")) {
        int p1 = msg.indexOf(':', 9);
        int p2 = msg.indexOf(':', p1 + 1);
        int p3 = msg.indexOf(':', p2 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0) return;
        uint32_t cid = (uint32_t)msg.substring(9, p1).toInt();
        String vendor = msg.substring(p1 + 1, p2);
        String addrS  = msg.substring(p2 + 1, p3);
        int rssi      = msg.substring(p3 + 1).toInt();
        uint8_t addr[6];
        {
            String t;
            for (size_t i = 0; i < addrS.length(); ++i) { char c = addrS[i]; if (isxdigit((int)c)) t += (char)toupper(c); }
            if (t.length() != 12) return;
            for (int i = 0; i < 6; i++) addr[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        uint32_t now = millis();
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        TrackerChain &c = g_chains[cid];
        if (c.chainId == 0) {
            c.chainId = cid;
            strncpy(c.vendor, vendor.c_str(), sizeof(c.vendor) - 1);
            c.firstSeen = now;
            c.avgRssi = (int8_t)rssi;
        }
        TrackerChain::Link l{};
        memcpy(l.addr, addr, 6);
        l.rssi = (int8_t)rssi;
        l.startTs = now;
        l.endTs = now;
        c.links.push_back(l);
        if (c.linkCount < 255) c.linkCount++;
        c.lastSeen = now;
    } else if (msg.startsWith("IDHASH:")) {
        int p1 = msg.indexOf(':', 7);
        int p2 = msg.indexOf(':', p1 + 1);
        if (p1 < 0 || p2 < 0) return;
        uint32_t hash = (uint32_t)msg.substring(7, p1).toInt();
        String trackId = msg.substring(p1 + 1, p2);
        int rssi = msg.substring(p2 + 1).toInt();
        uint32_t now = millis();
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        auto &id = g_pgGraph[hash];
        if (id.hash == 0) {
            id.hash = hash;
            id.firstSeen = now;
            id.bestRssi = (int8_t)rssi;
            strncpy(id.localTrackId, trackId.c_str(), sizeof(id.localTrackId) - 1);
        } else if (rssi > id.bestRssi) id.bestRssi = (int8_t)rssi;
        if (id.sightingCount < 255) id.sightingCount++;
        id.lastSeen = now;
        bool found = false;
        for (auto &n : id.nodes) if (n.nodeId == fromNode) { n.rssi = (int8_t)rssi; n.ts = now; found = true; break; }
        if (!found) {
            ProbeGraphIdentity::NodeSeen ns;
            ns.nodeId = fromNode; ns.rssi = (int8_t)rssi; ns.ts = now;
            id.nodes.push_back(ns);
        }
    } else if (msg.startsWith("BLOOM:")) {
        // Two formats supported:
        //   Dense: BLOOM:<idx>:<256-hex-chars>           (full 128-byte chunk)
        //   Sparse: BLOOM:<idx>:S:<off>=<val>,<off>=<val>... (only non-zero bytes, off/val hex)
        int p1 = msg.indexOf(':', 6);
        if (p1 < 0) return;
        int idx = msg.substring(6, p1).toInt();
        if (idx < 0 || idx >= (int)(BloomFilter::BYTES / 128)) return;
        String body = msg.substring(p1 + 1);
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        uint8_t *dst = g_neighborBloom.mutableData() + idx * 128;
        if (body.startsWith("S:")) {
            int s = 2;
            while (s < (int)body.length()) {
                int e = body.indexOf(',', s);
                String tok = (e < 0) ? body.substring(s) : body.substring(s, e);
                int eq = tok.indexOf('=');
                if (eq > 0) {
                    int off = (int)strtol(tok.substring(0, eq).c_str(), nullptr, 16);
                    int val = (int)strtol(tok.substring(eq + 1).c_str(), nullptr, 16);
                    if (off >= 0 && off < 128 && val >= 0 && val <= 0xFF) {
                        dst[off] |= (uint8_t)val;
                    }
                }
                if (e < 0) break;
                s = e + 1;
            }
        } else {
            for (size_t i = 0; i < 128 && i * 2 + 1 < body.length(); ++i) {
                uint8_t b = 0;
                for (int n = 0; n < 2; ++n) {
                    char c = body[i * 2 + n];
                    b <<= 4;
                    if (c >= '0' && c <= '9') b |= c - '0';
                    else if (c >= 'A' && c <= 'F') b |= c - 'A' + 10;
                    else if (c >= 'a' && c <= 'f') b |= c - 'a' + 10;
                }
                dst[i] |= b;
            }
        }
    } else if (msg.startsWith("CHAN_ASSIGN:")) {
        // CHAN_ASSIGN:nodeId:1,2,3
        int p1 = msg.indexOf(':', 12);
        if (p1 < 0) return;
        String tgt = msg.substring(12, p1);
        String csv = msg.substring(p1 + 1);
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        std::vector<uint8_t> chans;
        int s = 0;
        while (s < (int)csv.length()) {
            int e = csv.indexOf(',', s);
            String tok = (e < 0) ? csv.substring(s) : csv.substring(s, e);
            int v = tok.toInt();
            if (v > 0 && v < 256) chans.push_back((uint8_t)v);
            if (e < 0) break;
            s = e + 1;
        }
        g_chanAssignments[tgt] = chans;
        if (tgt == getNodeId()) g_myChannels = chans;
    }
}

static uint8_t g_lastBloomTxHash[BloomFilter::BYTES / 128] = {0};
static std::map<String, uint32_t> g_meshPeerLastSeen;
static constexpr uint32_t MESH_PEER_TIMEOUT_MS = 120000;
void _detect_recordMeshPeer(const String &fromNode) {
    if (fromNode.length() == 0 || fromNode == getNodeId()) return;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_meshPeerLastSeen[fromNode] = millis();
}
static bool hasMeshPeer() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    uint32_t now = millis();
    for (auto &kv : g_meshPeerLastSeen) {
        if ((now - kv.second) < MESH_PEER_TIMEOUT_MS) return true;
    }
    return false;
}
size_t detect_meshPeerCount() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    uint32_t now = millis();
    size_t n = 0;
    for (auto &kv : g_meshPeerLastSeen) {
        if ((now - kv.second) < MESH_PEER_TIMEOUT_MS) n++;
    }
    return n;
}

std::atomic<bool> g_detectVerbose{false};
void detect_setVerbose(bool on) { g_detectVerbose.store(on); }
bool detect_isVerbose() { return g_detectVerbose.load(); }

void detect_periodicMeshGossip() {
    if (!g_bloomGossipEnabled.load()) return;
    if (!hasMeshPeer()) {
        if (g_detectVerbose.load()) Serial.println("[VERIFY-BLOOM] skip: no mesh peer seen in 120s");
        return;
    }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    const uint8_t *src = g_localBloom.data();
    size_t sent = 0;
    for (size_t idx = 0; idx < BloomFilter::BYTES / 128; ++idx) {
        uint16_t nonzero = 0;
        uint8_t chunkHash = 0;
        for (size_t i = 0; i < 128; ++i) {
            uint8_t b = src[idx * 128 + i];
            if (b) nonzero++;
            chunkHash ^= b;
            chunkHash = (chunkHash << 1) | (chunkHash >> 7);
        }
        if (nonzero == 0) continue;
        if (chunkHash == g_lastBloomTxHash[idx]) continue;
        g_lastBloomTxHash[idx] = chunkHash;
        // Sparse fmt break-even ~50 nonzero bytes (50*5=250 vs 256 dense).
        // Use sparse when noticeably smaller — most chunks are heavily sparse.
        String body;
        if (nonzero <= 48) {
            body = "S:";
            char tmp[8];
            bool first = true;
            for (size_t i = 0; i < 128; ++i) {
                uint8_t b = src[idx * 128 + i];
                if (!b) continue;
                if (!first) body += ',';
                first = false;
                snprintf(tmp, sizeof(tmp), "%X=%X", (unsigned)i, b);
                body += tmp;
            }
        } else {
            char tmp[3];
            for (size_t i = 0; i < 128; ++i) {
                snprintf(tmp, sizeof(tmp), "%02X", src[idx * 128 + i]);
                body += tmp;
            }
        }
        sendToSerial1(getNodeId() + ": BLOOM:" + String((unsigned)idx) + ":" + body, true);
        vTaskDelay(pdMS_TO_TICKS(50));
        if (++sent >= 1) break;
    }
}

// =============================================================================
// Bloom API
// =============================================================================
void detect_addLocalBaseline(const uint8_t *mac, uint32_t ieHash) {
    uint8_t buf[10]; memcpy(buf, mac, 6); memcpy(buf + 6, &ieHash, 4);
    uint32_t h = fnv1a(buf, 10);
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_localBloom.add(h);
}
bool detect_neighborKnows(const uint8_t *mac, uint32_t ieHash) {
    uint8_t buf[10]; memcpy(buf, mac, 6); memcpy(buf + 6, &ieHash, 4);
    uint32_t h = fnv1a(buf, 10);
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_neighborBloom.maybeContains(h);
}
String detect_getBloomStatsJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    size_t localPop = 0, nbrPop = 0;
    for (size_t i = 0; i < BloomFilter::BYTES; ++i) {
        for (int b = 0; b < 8; ++b) {
            if (g_localBloom.data()[i] & (1 << b)) localPop++;
            if (g_neighborBloom.data()[i] & (1 << b)) nbrPop++;
        }
    }
    return String("{\"local_bits_set\":") + String((unsigned)localPop) +
           ",\"neighbor_bits_set\":" + String((unsigned)nbrPop) +
           ",\"capacity_bits\":" + String((unsigned)BloomFilter::BITS) + "}";
}

// =============================================================================
// RID public + JSON
// =============================================================================
void detect_recordRidClaim(const char *uavId, double lat, double lon, float alt, int8_t rssi) {
    recordRidClaim(uavId, lat, lon, alt, rssi);
}
String detect_getRidClaimsJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_ridClaims) {
        if (!first) out += ",";
        first = false;
        out += "{\"uav_id\":\"" + String(kv.second.uavId) + "\"";
        out += ",\"claim_lat\":" + String(kv.second.lat, 6);
        out += ",\"claim_lon\":" + String(kv.second.lon, 6);
        out += ",\"alt\":" + String(kv.second.alt, 1);
        out += ",\"verified\":" + String(kv.second.verified ? "true" : "false");
        out += ",\"insufficient\":" + String(kv.second.insufficient ? "true" : "false");
        out += ",\"rxs\":[";
        bool firstRx = true;
        for (auto &rx : kv.second.rxs) {
            if (!firstRx) out += ",";
            firstRx = false;
            out += "{\"node\":\"" + rx.nodeId + "\",\"rssi\":" + String(rx.rssi) +
                   ",\"lat\":" + String(rx.nodeLat, 6) +
                   ",\"lon\":" + String(rx.nodeLon, 6) +
                   ",\"gps\":" + String(rx.hasGps ? "true" : "false") + "}";
        }
        out += "]}";
    }
    out += "]";
    return out;
}

// =============================================================================
// OUI table
// =============================================================================
bool loadOuiTable() {
    if (!LittleFS.begin(true)) return false;
    if (!LittleFS.exists("/oui_cat.bin")) return false;
    File f = LittleFS.open("/oui_cat.bin", "r");
    if (!f) return false;
    size_t sz = f.size();
    size_t n = sz / sizeof(OuiTableEntry);
    g_ouiTable.clear();
    g_ouiTable.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        OuiTableEntry e;
        if (f.read((uint8_t*)&e, sizeof(e)) != sizeof(e)) break;
        g_ouiTable.push_back(e);
    }
    f.close();
    Serial.printf("[DETECT] Loaded %u OUI entries\n", (unsigned)g_ouiTable.size());
    return true;
}
OuiCategory ouiLookup(const uint8_t *mac) {
    if (g_ouiTable.empty()) return OUI_UNKNOWN;
    int lo = 0, hi = (int)g_ouiTable.size() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = memcmp(g_ouiTable[mid].oui, mac, 3);
        if (cmp == 0) return (OuiCategory)g_ouiTable[mid].cat;
        if (cmp < 0) lo = mid + 1; else hi = mid - 1;
    }
    return OUI_UNKNOWN;
}
const char* ouiCategoryName(OuiCategory c) {
    switch (c) {
        case OUI_KNOWN_GOOD:   return "known_good";
        case OUI_IOT_BASELINE: return "iot";
        case OUI_PENTEST_TOOL: return "pentest_tool";
        case OUI_SURVEILLANCE: return "surveillance";
        case OUI_SKIMMER:      return "skimmer";
        default:               return "unknown";
    }
}

// =============================================================================
// Recon scoring
// =============================================================================
void recon_updateFromProbeSession(const char *identityId, uint8_t addToScore, const char *reason) {
    if (!identityId || identityId[0] == 0) return;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto &r = g_recon[String(identityId)];
    strncpy(r.identityId, identityId, sizeof(r.identityId) - 1);
    int s = r.score + addToScore;
    r.score = (uint8_t)(s > 100 ? 100 : s);
    if (reason && reason[0]) {
        size_t avail = sizeof(r.reasons) - strlen(r.reasons) - 2;
        if (avail > 0) {
            if (r.reasons[0]) strncat(r.reasons, ",", avail);
            strncat(r.reasons, reason, avail - 1);
        }
    }
    r.ts = millis();
    if (r.score >= 70 && meshEnabled) {
        if (g_meshRecon.load() && meshRateGate("RECON_" + String(identityId), 30000))
            sendToSerial1(getNodeId() + ": RECON:" + identityId + ":" + String(r.score), true);
        quorum_addReport("RECON", String(identityId), getNodeId(), -50);
    }
}
String detect_getReconJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_recon) {
        if (!first) out += ",";
        first = false;
        out += "{\"id\":\"" + String(kv.second.identityId) + "\"";
        out += ",\"score\":" + String(kv.second.score);
        out += ",\"reasons\":\"" + String(kv.second.reasons) + "\"";
        out += ",\"ts\":" + String(kv.second.ts) + "}";
    }
    out += "]";
    return out;
}
void detect_clearRecon() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_recon.clear();
}

// =============================================================================
// PPS
// =============================================================================
void initializeGpsPps(int gpio) { initGpsPps(gpio); }
bool ppsLocked() { return g_ppsLocked.load(); }
uint32_t ppsLastEdgeMicros() { return g_ppsLastEdge; }
uint64_t getDisciplinedMicros() { return ah_detect::getDisciplinedMicros(); }

// =============================================================================
// Channel partition
// =============================================================================
void detect_assignChannelPartition() {
    // Coordinator: split 1..14 (2.4 GHz) across confirmed mesh nodes inc. self.
    // Discovery of mesh peers piggybacks on triangulateAcks/heartbeat; we use a
    // simple fallback: any nodeId we've seen recently via quorum.
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    std::set<String> peers;
    peers.insert(getNodeId());
    for (auto &kv : g_alerts) for (auto &r : kv.second.reports) peers.insert(r.nodeId);
    if (peers.empty()) return;
    std::vector<String> peerList(peers.begin(), peers.end());
    g_chanAssignments.clear();
    const uint8_t allCh[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};
    size_t per = (sizeof(allCh) / peerList.size());
    if (per == 0) per = 1;
    size_t k = 0;
    for (size_t i = 0; i < peerList.size(); ++i) {
        std::vector<uint8_t> mine;
        size_t end = (i + 1 == peerList.size()) ? sizeof(allCh) : k + per;
        if (end > sizeof(allCh)) end = sizeof(allCh);
        for (; k < end; ++k) mine.push_back(allCh[k]);
        g_chanAssignments[peerList[i]] = mine;
        if (peerList[i] == getNodeId()) g_myChannels = mine;
        if (meshEnabled && peerList[i] != getNodeId()) {
            String csv;
            for (size_t j = 0; j < mine.size(); ++j) {
                if (j) csv += ",";
                csv += String(mine[j]);
            }
            sendToSerial1(getNodeId() + ": CHAN_ASSIGN:" + peerList[i] + ":" + csv, true);
        }
    }
}
String detect_getChannelAssignmentJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "{";
    bool first = true;
    for (auto &kv : g_chanAssignments) {
        if (!first) out += ",";
        first = false;
        out += "\"" + kv.first + "\":[";
        for (size_t i = 0; i < kv.second.size(); ++i) {
            if (i) out += ",";
            out += String(kv.second[i]);
        }
        out += "]";
    }
    out += "}";
    return out;
}
std::vector<uint8_t> detect_getMyAssignedChannels() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return g_myChannels;
}
void detect_setMyAssignedChannels(const String &csv) {
    std::vector<uint8_t> v;
    int s = 0;
    while (s < (int)csv.length()) {
        int e = csv.indexOf(',', s);
        String tok = (e < 0) ? csv.substring(s) : csv.substring(s, e);
        int x = tok.toInt();
        if (x > 0 && x < 256) v.push_back((uint8_t)x);
        if (e < 0) break;
        s = e + 1;
    }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_myChannels = v;
}

// =============================================================================
// JSON getters
// =============================================================================
template<class V, class Fmt>
static String jsonlOf(const std::vector<V> &v, Fmt fmt) {
    String out;
    for (auto &x : v) { out += fmt(x); out += "\n"; }
    return out;
}

String detect_getPmkidJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_pmkidLog, [](const PmkidHarvestEvent &e){
        return String("{\"src\":\"") + macStr(e.srcMac) + "\",\"bssid\":\"" + macStr(e.bssid) +
               "\",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getEvilTwinJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_evilTwinLog, [](const EvilTwinEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) + "\",\"ssid\":\"" + e.ssid +
               "\",\"reason\":\"" + e.reason +
               "\",\"new_bi\":" + String(e.newBeaconInt) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getSsidConfusionJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_ssidConfusionLog, [](const SsidConfusionEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) + "\",\"beacon\":\"" + e.beaconSsid +
               "\",\"resp\":\"" + e.respSsid + "\",\"rssi\":" + String(e.rssi) +
               ",\"ch\":" + String(e.channel) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getSaeDosJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_saeDosLog, [](const SaeDosEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) +
               "\",\"unmatched\":" + String(e.unmatchedCommits) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getOweAbuseJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_oweAbuseLog, [](const OweAbuseEvent &e){
        return String("{\"open\":\"") + macStr(e.openBssid) + "\",\"owe\":\"" + macStr(e.oweBssid) +
               "\",\"ssid\":\"" + e.ssid + "\",\"rssi\":" + String(e.rssi) +
               ",\"ch\":" + String(e.channel) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getFragAttackJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_fragLog, [](const FragAttackEvent &e){
        return String("{\"src\":\"") + macStr(e.srcMac) + "\",\"tid\":" + String(e.tid) +
               ",\"reason\":\"" + e.reason +
               "\",\"last_pn\":" + String(e.lastPN) + ",\"obs_pn\":" + String(e.observedPN) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getBleMalformedJsonl() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return jsonlOf(g_bleMalformedLog, [](const BleMalformedEvent &e){
        return String("{\"addr\":\"") + macStr(e.addr) +
               "\",\"reason\":\"" + e.reason + "\",\"len\":" + String(e.payloadLen) +
               ",\"rssi\":" + String(e.rssi) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getQuorumStatusJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "{\"required\":{";
    bool first = true;
    for (auto &kv : g_quorumRequired) {
        if (!first) out += ",";
        first = false;
        out += "\"" + kv.first + "\":" + String((unsigned)kv.second);
    }
    out += "},\"candidates\":[";
    first = true;
    for (auto &kv : g_alerts) {
        if (!first) out += ",";
        first = false;
        out += "{\"type\":\"" + kv.second.type +
               "\",\"key\":\"" + kv.second.key +
               "\",\"nodes\":" + String((unsigned)kv.second.reports.size()) +
               ",\"fired\":" + String(kv.second.fired ? "true" : "false") + "}";
    }
    out += "]}";
    return out;
}
String detect_getBleTrackerJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (auto &kv : g_bleTrackers) {
        if (!first) out += ",";
        first = false;
        out += "{\"addr\":\"" + macStr(kv.second.addr) +
               "\",\"vendor\":\"" + String(kv.second.vendor) +
               "\",\"sightings\":" + String(kv.second.sightingCount) +
               ",\"first_seen\":" + String(kv.second.firstSeen) +
               ",\"last_seen\":" + String(kv.second.lastSeen) +
               ",\"avg_rssi\":" + String(kv.second.avgRssi) +
               ",\"score\":" + String(kv.second.persistenceScore) +
               ",\"followed\":" + String(kv.second.followAlerted ? "true" : "false") + "}";
    }
    out += "]";
    return out;
}
void detect_clearBleTracker() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_bleTrackers.clear();
}
static inline String _bjson(const char *k, bool v, bool first=false) {
    return String(first ? "\"" : ",\"") + k + "\":" + (v ? "true" : "false");
}
static inline String _ijson(const char *k, uint32_t v) {
    return String(",\"") + k + "\":" + String(v);
}
String detect_getConfigJson() {
    String j = "{";
    j += _bjson("pmkid", g_pmkidEnabled.load(), true);
    j += _bjson("sentinel_scan", g_sentinelScanMode.load());
    j += _bjson("eviltwin", g_eviltwinEnabled.load());
    j += _bjson("ssid_confusion", g_ssidConfusionEnabled.load());
    j += _bjson("sae", g_saeEnabled.load());
    j += _bjson("owe", g_oweEnabled.load());
    j += _bjson("frag", g_fragEnabled.load());
    j += _bjson("ble_malformed", g_bleMalformedEnabled.load());
    j += _bjson("hshk", g_hshkEnabled.load());
    j += _bjson("pwna", g_pwnaEnabled.load());
    j += _bjson("tracker", g_trackerEnabled.load());
    j += _bjson("airtag", g_airtagEnabled.load());
    j += _bjson("tsf", g_tsfEnabled.load());
    j += _bjson("rid_spoof", g_ridSpoofEnabled.load());
    j += _bjson("bloom_gossip", g_bloomGossipEnabled.load());
    j += _bjson("attacker_trilat", g_attackerTrilatEnabled.load());
    j += _bjson("karma", g_karmaEnabled.load());
    j += _bjson("csi", g_csiEnabled.load());
    j += _bjson("mesh_pmkid", g_meshPmkid.load());
    j += _bjson("mesh_eviltwin", g_meshEviltwin.load());
    j += _bjson("mesh_ssid_confusion", g_meshSsidConf.load());
    j += _bjson("mesh_sae", g_meshSae.load());
    j += _bjson("mesh_frag", g_meshFrag.load());
    j += _bjson("mesh_ble_malformed", g_meshBleMalformed.load());
    j += _bjson("mesh_hshk", g_meshHshk.load());
    j += _bjson("mesh_krack", g_meshKrack.load());
    j += _bjson("mesh_tracker", g_meshTracker.load());
    j += _bjson("mesh_pwna", g_meshPwna.load());
    j += _bjson("mesh_karma", g_meshKarma.load());
    j += _bjson("mesh_recon", g_meshRecon.load());
    j += _bjson("mesh_csi_motion", g_meshCsiMotion.load());
    j += _bjson("mesh_attacker_hunt", g_meshAttackerHunt.load());
    // New tool-fingerprint detector toggles (tool/tool signatures)
    j += _bjson("probe_flood", g_probeFloodEnabled.load());
    j += _bjson("assoc_sleep", g_assocSleepEnabled.load());
    j += _bjson("ble_attack",  g_bleAttackEnabled.load());
    j += _ijson("csi_thresh", g_csiThreshQ8.load());
    j += _ijson("pmkid_window", g_pmkidWindow.load());
    j += _ijson("pmkid_min_bssids", g_pmkidMinBssids.load());
    j += _ijson("sae_window", g_saeWindow.load());
    j += _ijson("sae_unmatched_thresh", g_saeUnmatchedThresh.load());
    j += _ijson("frag_reuse_thresh", g_fragReuseThresh.load());
    j += _ijson("hunt_cooldown_ms", g_huntCooldown.load());
    j += _ijson("tracker_window_ms", g_trackerWindowMs.load());
    j += "}";
    return j;
}
static void _setb(const String &b, const char *k, std::atomic<bool> &a) {
    int p = b.indexOf(String("\"") + k + "\"");
    if (p < 0) return;
    int colon = b.indexOf(':', p);
    if (colon < 0) return;
    String v = b.substring(colon + 1, colon + 8);
    v.trim();
    a.store(v.startsWith("true") || v.startsWith("1"));
}
static void _seti(const String &b, const char *k, std::atomic<uint16_t> &a) {
    int p = b.indexOf(String("\"") + k + "\"");
    if (p < 0) return;
    int colon = b.indexOf(':', p);
    if (colon < 0) return;
    int v = b.substring(colon + 1, colon + 12).toInt();
    if (v > 0 && v <= 65535) a.store((uint16_t)v);
}
static void _setu8(const String &b, const char *k, std::atomic<uint8_t> &a) {
    int p = b.indexOf(String("\"") + k + "\"");
    if (p < 0) return;
    int colon = b.indexOf(':', p);
    if (colon < 0) return;
    int v = b.substring(colon + 1, colon + 8).toInt();
    if (v > 0 && v <= 255) a.store((uint8_t)v);
}
static void _setu32(const String &b, const char *k, std::atomic<uint32_t> &a) {
    int p = b.indexOf(String("\"") + k + "\"");
    if (p < 0) return;
    int colon = b.indexOf(':', p);
    if (colon < 0) return;
    long long v = atoll(b.substring(colon + 1, colon + 16).c_str());
    if (v > 0) a.store((uint32_t)v);
}
bool detect_setConfigFromJson(const String &b) {
    _setb(b, "pmkid", g_pmkidEnabled);
    _setb(b, "sentinel_scan", g_sentinelScanMode);
    _setb(b, "eviltwin", g_eviltwinEnabled);
    _setb(b, "ssid_confusion", g_ssidConfusionEnabled);
    _setb(b, "sae", g_saeEnabled);
    _setb(b, "owe", g_oweEnabled);
    _setb(b, "frag", g_fragEnabled);
    _setb(b, "ble_malformed", g_bleMalformedEnabled);
    _setb(b, "hshk", g_hshkEnabled);
    _setb(b, "pwna", g_pwnaEnabled);
    _setb(b, "tracker", g_trackerEnabled);
    _setb(b, "airtag", g_airtagEnabled);
    _setb(b, "tsf", g_tsfEnabled);
    _setb(b, "rid_spoof", g_ridSpoofEnabled);
    _setb(b, "bloom_gossip", g_bloomGossipEnabled);
    _setb(b, "attacker_trilat", g_attackerTrilatEnabled);
    _setb(b, "karma", g_karmaEnabled);
    _setb(b, "csi", g_csiEnabled);
    _setb(b, "mesh_pmkid", g_meshPmkid);
    _setb(b, "mesh_eviltwin", g_meshEviltwin);
    _setb(b, "mesh_ssid_confusion", g_meshSsidConf);
    _setb(b, "mesh_sae", g_meshSae);
    _setb(b, "mesh_frag", g_meshFrag);
    _setb(b, "mesh_ble_malformed", g_meshBleMalformed);
    _setb(b, "mesh_hshk", g_meshHshk);
    _setb(b, "mesh_krack", g_meshKrack);
    _setb(b, "mesh_tracker", g_meshTracker);
    _setb(b, "mesh_pwna", g_meshPwna);
    _setb(b, "mesh_karma", g_meshKarma);
    _setb(b, "mesh_recon", g_meshRecon);
    _setb(b, "mesh_csi_motion", g_meshCsiMotion);
    _setb(b, "mesh_attacker_hunt", g_meshAttackerHunt);
    _setb(b, "probe_flood", g_probeFloodEnabled);
    _setb(b, "assoc_sleep", g_assocSleepEnabled);
    _setb(b, "ble_attack",  g_bleAttackEnabled);
    _seti(b, "csi_thresh", g_csiThreshQ8);
    _seti(b, "pmkid_window", g_pmkidWindow);
    _setu8(b, "pmkid_min_bssids", g_pmkidMinBssids);
    _seti(b, "sae_window", g_saeWindow);
    _setu8(b, "sae_unmatched_thresh", g_saeUnmatchedThresh);
    _setu8(b, "frag_reuse_thresh", g_fragReuseThresh);
    _setu32(b, "hunt_cooldown_ms", g_huntCooldown);
    return true;
}
uint32_t detect_droppedWifi() { return g_droppedWifi.load(); }
uint32_t detect_droppedBle() { return g_droppedBle.load(); }
uint32_t detect_droppedCsi() { return g_droppedCsi.load(); }
uint32_t detect_meshRateGated() { return g_meshGated.load(); }
String detect_getHealthJson() {
    UBaseType_t framesQ = detectFrameQueue ? uxQueueMessagesWaiting(detectFrameQueue) : 0;
    UBaseType_t csiQ = g_csiQueue ? uxQueueMessagesWaiting(g_csiQueue) : 0;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String j = "{";
    j += "\"uptime_ms\":" + String(millis());
    j += ",\"heap_free\":" + String((unsigned long)ESP.getFreeHeap());
    j += ",\"heap_min\":" + String((unsigned long)ESP.getMinFreeHeap());
    j += ",\"psram_free\":" + String((unsigned long)ESP.getFreePsram());
    j += ",\"queues\":{\"frame\":" + String((unsigned)framesQ) +
         ",\"csi\":" + String((unsigned)csiQ) + "}";
    j += ",\"drops\":{\"wifi\":" + String(g_droppedWifi.load()) +
         ",\"ble\":" + String(g_droppedBle.load()) +
         ",\"csi\":" + String(g_droppedCsi.load()) +
         ",\"mesh_gated\":" + String(g_meshGated.load()) + "}";
    j += ",\"state\":{\"ap_baseline\":" + String((unsigned)g_apBaseline.size()) +
         ",\"pmkid_bursts\":" + String((unsigned)g_pmkidBursts.size()) +
         ",\"sae_counters\":" + String((unsigned)g_saeCounters.size()) +
         ",\"pn_state\":" + String((unsigned)g_pnState.size()) +
         ",\"tsf_track\":" + String((unsigned)g_tsfTrack.size()) +
         ",\"ble_trackers\":" + String((unsigned)g_bleTrackers.size()) +
         ",\"airtag\":" + String((unsigned)g_airtag.size()) +
         ",\"chains\":" + String((unsigned)g_chains.size()) +
         ",\"hshk\":" + String((unsigned)g_hshk.size()) +
         ",\"hunts\":" + String((unsigned)g_hunts.size()) +
         ",\"pwna\":" + String((unsigned)g_pwna.size()) +
         ",\"karma\":" + String((unsigned)g_karma.size()) +
         ",\"recon\":" + String((unsigned)g_recon.size()) +
         ",\"alerts\":" + String((unsigned)g_alerts.size()) +
         ",\"tof_peers\":" + String((unsigned)g_tofPeers.size()) +
         ",\"csi_fp\":" + String((unsigned)g_csiFp.size()) +
         ",\"pg_graph\":" + String((unsigned)g_pgGraph.size()) +
         ",\"rid_claims\":" + String((unsigned)g_ridClaims.size()) +
         ",\"probe_flood\":" + String((unsigned)g_probeFlood.size()) +
         ",\"probe_behave\":" + String((unsigned)g_probeBehave.size()) +
         ",\"assoc_sleep\":" + String((unsigned)g_assocSleep.size()) +
         ",\"beacon_forge\":" + String((unsigned)g_beaconForgeFired.size()) +
         ",\"ble_attack\":" + String((unsigned)g_bleAttackLog.size()) +
         ",\"airtag_replay\":" + String((unsigned)g_airtagReplay.size()) + "}";
    j += ",\"counters\":{\"csi_pkts\":" + String(g_csiPkts.load()) +
         ",\"csi_motion\":" + String(g_csiMotion.load()) +
         ",\"krack_events\":" + String(g_krackEvents.load()) + "}";
    j += ",\"pps_locked\":" + String(g_ppsLocked.load() ? "true" : "false");
    j += ",\"csi_enabled\":" + String(g_csiEnabled.load() ? "true" : "false");
    j += ",\"karma_enabled\":" + String(g_karmaEnabled.load() ? "true" : "false");
    j += "}";
    return j;
}
void detect_clearAll() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    g_pmkidLog.clear();
    g_pmkidBursts.clear();
    g_evilTwinLog.clear();
    g_ssidConfusionLog.clear();
    g_saeDosLog.clear();
    g_saeCounters.clear();
    g_oweAbuseLog.clear();
    g_fragLog.clear();
    g_pnState.clear();
    g_bleMalformedLog.clear();
    g_ridClaims.clear();
    g_alerts.clear();
    g_bleTrackers.clear();
    g_recon.clear();
    g_apBaseline.clear();
    g_csiMotionLog.clear();
    g_csiFp.clear();
    g_csiHist.clear();
    g_pgGraph.clear();
    g_chains.clear();
    g_vanished.clear();
    g_airtag.clear();
    g_hshk.clear();
    g_krackEvents.store(0);
    g_hunts.clear();
    g_pwna.clear();
    g_karma.clear();
    g_karmaSsids.clear();
    g_baitSsids.clear();
    g_tsfTrack.clear();
    g_tofPeers.clear();
    g_tofPending.clear();
    g_localBloom.clear();
    g_neighborBloom.clear();
    g_meshRateMap.clear();
    // DoS-group RAM windows (were not cleared before -> stale counts persisted)
    g_deauthRate.clear();
    g_assocSleep.clear();
    g_authFlood.clear();
    // Truncate persisted detection logs so Overview line-counts reset too.
    // (Overview reads counts from these SD files; clearing RAM alone left stale totals.)
    static const char *kDetectLogs[] = {
        "/deauth_flood.jsonl", "/deauth_ap.jsonl", "/assoc_sleep.jsonl", "/sae_dos.jsonl",
        "/pmkid.jsonl", "/pmkid_forge.jsonl", "/eviltwin.jsonl", "/ssid_confusion.jsonl",
        "/owe_abuse.jsonl", "/fragattack.jsonl", "/ble_malformed.jsonl", "/ble_attack.jsonl",
        "/ble_follow.jsonl", "/eapol_bait.jsonl", "/probe_flood.jsonl", "/probe_ap.jsonl",
        "/incidents.jsonl"
    };
    for (const char *path : kDetectLogs) {
        if (SafeSD::exists(path)) SafeSD::remove(path);  // skip absent files (no error spam)
    }
}
