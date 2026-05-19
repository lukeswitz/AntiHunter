#include "detect.h"
#include "hardware.h"
#include "network.h"
#include "scanner.h"
#include "baseline.h"
#include <SD.h>
#include <LittleFS.h>
#include <esp_timer.h>
#include <esp_attr.h>
#include <driver/gpio.h>
#include <ArduinoJson.h>
#include <algorithm>

namespace ah_detect {

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
std::mutex g_mtx;

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

// FragAttacks PN tracking — key = (srcMac<<8 | tid)
struct PnState {
    uint32_t lastPN;
    uint32_t lastSeen;
};
std::map<uint64_t, PnState> g_pnState;
std::vector<FragAttackEvent> g_fragLog;

// BLE malformed
std::vector<BleMalformedEvent> g_bleMalformedLog;

// BLE tracker
std::map<uint64_t, BleTrackerSighting> g_bleTrackers;

// Recon
std::map<String, ReconAlert> g_recon;

// RID claims (mesh-cooperative validation)
std::map<String, RidClaim> g_ridClaims;  // key = uavId
std::vector<RidClaim> g_ridHistory;       // archived

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
    static bool isrInstalled = false;
    if (!isrInstalled) {
        gpio_install_isr_service(0);
        isrInstalled = true;
    }
    gpio_isr_handler_add((gpio_num_t)gpio, pps_isr, nullptr);
    Serial.printf("[PPS] Armed on GPIO %d\n", gpio);
}

uint64_t getDisciplinedMicros() {
    uint64_t bootMicros = esp_timer_get_time();
    uint32_t epoch = g_ppsAnchorEpoch;
    uint64_t anchor = g_ppsAnchorMicros;
    if (epoch == 0 || anchor == 0) {
        // Fallback: RTC seconds + boot µs delta (low precision)
        time_t e = getRTCEpoch();
        return (uint64_t)e * 1000000ULL;
    }
    return ((uint64_t)epoch * 1000000ULL) + (bootMicros - anchor);
}

// =============================================================================
// PMKID detection
// =============================================================================
// EAPOL-Key in 802.11: data frame ftype=2, LLC/SNAP DSAP=0xAA SSAP=0xAA ctrl=0x03,
// OUI 00:00:00, Ethertype 0x88 0x8E. Key descriptor starts after.
// PMKID-request M1 has: key_info: pairwise=1, ack=1, install=0, mic=0; key_data has
// PMKID KDE (00:0F:AC, type 4) or is broadcast-induced.
// We detect: EAPOL-Key from src targeting >=N distinct BSSIDs within window.

static void handleEAPOL(const DetectFrameEvent &e) {
    if (e.len < 32) return;
    // Identify EAPOL: scan for 0x88 0x8E ethertype after LLC SNAP
    // QoS-Data has 26-byte header (+2 QoS); Data has 24-byte.
    // Quick approach: locate 0xAA 0xAA 0x03 then check ethertype.
    int eapolOff = -1;
    for (int i = 24; i < (int)e.len - 8; ++i) {
        if (e.payload[i] == 0xAA && e.payload[i+1] == 0xAA && e.payload[i+2] == 0x03 &&
            e.payload[i+6] == 0x88 && e.payload[i+7] == 0x8E) {
            eapolOff = i + 8;
            break;
        }
    }
    if (eapolOff < 0 || eapolOff + 4 >= (int)e.len) return;
    // EAPOL header: version(1) type(1) length(2). type==3 => EAPOL-Key
    if (e.payload[eapolOff + 1] != 0x03) return;
    // KeyDescriptor type at +4 (RSN/WPA=2)
    // Key Information at +5..+6 (big-endian per 802.11)
    if (eapolOff + 6 >= (int)e.len) return;
    uint16_t keyInfo = ((uint16_t)e.payload[eapolOff + 5] << 8) | e.payload[eapolOff + 6];
    bool pairwise = (keyInfo >> 3) & 1;
    bool install  = (keyInfo >> 6) & 1;
    bool ack      = (keyInfo >> 7) & 1;
    bool mic      = (keyInfo >> 8) & 1;
    // M1 / PMKID-request: pairwise=1, install=0, ack=1, mic=0
    if (!(pairwise && !install && ack && !mic)) return;

    // src=addr2, bssid=addr3 for ToDS=0,FromDS=1 (AP->STA); for STA->AP swap.
    const uint8_t *a2 = e.payload + 10;
    const uint8_t *a3 = e.payload + 16;

    uint64_t srcK = packMac(a2);
    uint64_t bssK = packMac(a3);
    uint32_t now = millis();

    std::lock_guard<std::mutex> lk(g_mtx);
    PmkidBurst &b = g_pmkidBursts[srcK];
    b.lastSeen = now;
    b.bssidTs[bssK] = now;
    // Prune old
    uint16_t win = g_pmkidWindow.load();
    for (auto it = b.bssidTs.begin(); it != b.bssidTs.end(); ) {
        if (now - it->second > win) it = b.bssidTs.erase(it);
        else ++it;
    }
    if (b.bssidTs.size() >= g_pmkidMinBssids.load()) {
        PmkidHarvestEvent ev{};
        memcpy(ev.srcMac, a2, 6);
        memcpy(ev.bssid, a3, 6);
        ev.rssi = e.rssi;
        ev.channel = e.channel;
        ev.ts = now;
        g_pmkidLog.push_back(ev);
        if (g_pmkidLog.size() > MAX_PMKID_LOG) g_pmkidLog.erase(g_pmkidLog.begin());

        String src = macStr(a2);
        String line = String("{\"src\":\"") + src + "\",\"bssid\":\"" + macStr(a3) +
                      "\",\"rssi\":" + String(ev.rssi) +
                      ",\"ch\":" + String(ev.channel) +
                      ",\"ts\":" + String(now) +
                      ",\"burst_bssids\":" + String((unsigned)b.bssidTs.size()) + "}";
        logEventToSD("/pmkid.jsonl", line);

        // Mesh announce
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": PMKID_HARVEST:" + src + ":" + macStr(a3) +
                          ":" + String(ev.rssi), true);
        }
        // Local quorum
        quorum_addReport("PMKID", src, getNodeId(), ev.rssi);
        // Throttle: clear burst after firing
        b.bssidTs.clear();
    }
}

// =============================================================================
// Beacon / Evil-Twin / SSID Confusion / OWE
// =============================================================================
static void handleBeacon(const DetectFrameEvent &e) {
    // Mgmt frame: ftype=0 stype=8. fixed body 12 bytes: timestamp(8) interval(2) caps(2)
    if (e.len < 36) return;
    const uint8_t *p = e.payload;
    const uint8_t *bssid = p + 16; // addr3
    uint64_t tsf = 0;
    for (int i = 0; i < 8; ++i) tsf |= ((uint64_t)p[24 + i]) << (8 * i);
    uint16_t beaconInt = (uint16_t)p[32] | ((uint16_t)p[33] << 8);
    const uint8_t *ie = p + 36;
    uint16_t ieLen = e.len - 36;

    char ssid[33] = {0};
    extractSSID(ie, ieLen, ssid, sizeof(ssid));
    uint32_t ieHash = hashIeSet(ie, ieLen);
    bool isOpen = hasOpenAuth(ie, ieLen);
    uint8_t oweTransBssid[6] = {0};
    bool hasOweTrans = extractOweTransition(ie, ieLen, oweTransBssid);

    uint64_t k = packMac(bssid);
    uint32_t now = millis();

    std::lock_guard<std::mutex> lk(g_mtx);
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

        // Feed local Bloom (BSSID+ieHash) for gossip
        uint8_t hbuf[10];
        memcpy(hbuf, bssid, 6);
        memcpy(hbuf + 6, &ieHash, 4);
        g_localBloom.add(fnv1a(hbuf, 10));
        return;
    }

    ApBaseline &b = it->second;

    // TSF anomaly: TSF should monotonically increase; or restart (cloned AP reboot)
    bool tsfRestart = (tsf < b.lastTSF && (b.lastTSF - tsf) > 1000000000ULL); // >1000s jump back
    bool tsfNonMono = (tsf < b.lastTSF) && !tsfRestart && ((b.lastTSF - tsf) > 5000000ULL);
    // Beacon-interval drift permil
    uint16_t driftPermil = 0;
    if (b.beaconInterval > 0 && beaconInt > 0) {
        int32_t d = (int32_t)beaconInt - (int32_t)b.beaconInterval;
        if (d < 0) d = -d;
        driftPermil = (uint16_t)((1000UL * d) / b.beaconInterval);
    }
    bool intervalDrift = driftPermil > g_beaconDriftPermil.load();
    bool ieDrift = (ieHash != b.ieHash);

    if (tsfRestart || tsfNonMono || intervalDrift || ieDrift) {
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
        if (tsfRestart) strncpy(ev.reason, "TSF_RESTART", sizeof(ev.reason) - 1);
        else if (tsfNonMono) strncpy(ev.reason, "TSF_NONMONO", sizeof(ev.reason) - 1);
        else if (ieDrift) strncpy(ev.reason, "IE_DRIFT", sizeof(ev.reason) - 1);
        else strncpy(ev.reason, "BEACON_INTERVAL", sizeof(ev.reason) - 1);

        g_evilTwinLog.push_back(ev);
        if (g_evilTwinLog.size() > MAX_ET_LOG) g_evilTwinLog.erase(g_evilTwinLog.begin());

        String bs = macStr(bssid);
        String line = String("{\"bssid\":\"") + bs + "\",\"ssid\":\"" + ev.ssid +
                      "\",\"reason\":\"" + ev.reason +
                      "\",\"old_ie\":" + String(ev.oldIeHash) +
                      ",\"new_ie\":" + String(ev.newIeHash) +
                      ",\"old_bi\":" + String(ev.oldBeaconInt) +
                      ",\"new_bi\":" + String(ev.newBeaconInt) +
                      ",\"rssi\":" + String(ev.rssi) +
                      ",\"ch\":" + String(ev.channel) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/eviltwin.jsonl", line);
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": EVILTWIN:" + bs + ":" + ev.reason + ":" + String(ev.rssi), true);
        }
        quorum_addReport("EVILTWIN", bs, getNodeId(), ev.rssi);
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
                    String line = String("{\"open_bssid\":\"") + macStr(bssid) +
                                  "\",\"owe_bssid\":\"" + macStr(ev.oweBssid) +
                                  "\",\"ssid\":\"" + ssid +
                                  "\",\"rssi\":" + String(e.rssi) +
                                  ",\"ch\":" + String(e.channel) +
                                  ",\"ts\":" + String(now) + "}";
                    logEventToSD("/owe_abuse.jsonl", line);
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

// =============================================================================
// SSID Confusion (CVE-2023-52424)
// =============================================================================
static void handleProbeResp(const DetectFrameEvent &e) {
    if (e.len < 36) return;
    const uint8_t *p = e.payload;
    const uint8_t *bssid = p + 16;
    const uint8_t *ie = p + 36;
    uint16_t ieLen = e.len - 36;
    char ssid[33] = {0};
    if (!extractSSID(ie, ieLen, ssid, sizeof(ssid))) return;
    if (ssid[0] == 0) return;

    uint64_t k = packMac(bssid);
    uint32_t now = millis();

    std::lock_guard<std::mutex> lk(g_mtx);
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

    String bs = macStr(bssid);
    String line = String("{\"bssid\":\"") + bs + "\",\"beacon_ssid\":\"" + b.ssid +
                  "\",\"resp_ssid\":\"" + ssid +
                  "\",\"rssi\":" + String(e.rssi) +
                  ",\"ch\":" + String(e.channel) +
                  ",\"ts\":" + String(now) + "}";
    logEventToSD("/ssid_confusion.jsonl", line);
    if (meshEnabled) {
        sendToSerial1(getNodeId() + ": SSID_CONFUSION:" + bs + ":" + String(e.rssi), true);
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
    if (algo != 3) return;
    uint16_t seq = (uint16_t)p[26] | ((uint16_t)p[27] << 8);
    const uint8_t *bssid = p + 16;
    uint64_t k = packMac(bssid);
    uint32_t now = millis();
    uint16_t win = g_saeWindow.load();

    std::lock_guard<std::mutex> lk(g_mtx);
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

        String bs = macStr(bssid);
        String line = String("{\"bssid\":\"") + bs +
                      "\",\"unmatched_commits\":" + String(unmatched) +
                      ",\"rssi\":" + String(e.rssi) +
                      ",\"ch\":" + String(e.channel) +
                      ",\"window_start\":" + String(c.windowStart) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/sae_dos.jsonl", line);
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": SAE_DOS:" + bs + ":" + String(unmatched), true);
        }
        quorum_addReport("SAE_DOS", bs, getNodeId(), e.rssi);
    }
}

// =============================================================================
// FragAttacks A-MSDU + PN reuse
// =============================================================================
static void handleQosData(const DetectFrameEvent &e) {
    // QoS Data: ftype=2 stype=8. Header 26 bytes. QoS Ctrl at +24..+25.
    if (e.len < 32) return;
    const uint8_t *p = e.payload;
    uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint8_t stype = (fc >> 4) & 0xF;
    uint8_t ftype = (fc >> 2) & 0x3;
    if (ftype != 2 || stype != 8) return;
    uint8_t protectedBit = (fc >> 14) & 1;
    if (!protectedBit) return;  // PN only meaningful on protected frames
    const uint8_t *a2 = p + 10;
    uint8_t qos0 = p[24];
    uint8_t tid = qos0 & 0x0F;
    uint8_t aMsdu = (qos0 >> 7) & 1;

    // CCMP/GCMP header is at +26 for QoS Data. PN field: PN0(1) PN1(1) rsvd(1) keyid(1) PN2..PN5(4)
    // Reconstructed PN: PN5 PN4 PN3 PN2 PN1 PN0  (48-bit). We use low 32 bits for tracking.
    uint8_t pn0 = p[26], pn1 = p[27], pn2 = p[30], pn3 = p[31];
    // Validate keyid byte (offset 27 layout) — bit 5 (ExtIV) must be set
    if (!(p[27] & 0x20)) {
        // Not standard CCMP/GCMP — skip
        (void)pn0; (void)pn1; (void)pn2; (void)pn3;
        return;
    }
    pn1 = p[26];
    pn0 = p[27];
    // Actually CCMP header layout: byte0=PN0, byte1=PN1, byte2=Rsvd, byte3=KeyId, byte4=PN2, byte5=PN3, byte6=PN4, byte7=PN5
    uint8_t b0 = p[26], b1 = p[27], b2 = p[28], b3 = p[29], b4 = p[30], b5 = p[31];
    (void)b2;
    if (!(b3 & 0x20)) return;
    uint32_t pnLow = ((uint32_t)b5 << 24) | ((uint32_t)b4 << 16) | ((uint32_t)b1 << 8) | b0;
    (void)pnLow;
    uint32_t pn32 = ((uint32_t)b5 << 24) | ((uint32_t)b4 << 16) | ((uint32_t)b1 << 8) | b0;

    uint64_t key = (packMac(a2) << 4) | tid;
    uint32_t now = millis();

    std::lock_guard<std::mutex> lk(g_mtx);
    auto it = g_pnState.find(key);
    if (it == g_pnState.end()) {
        g_pnState[key] = {pn32, now};
        if (g_pnState.size() > 64) {
            // evict oldest
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (auto &kv : g_pnState) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
            g_pnState.erase(oldestK);
        }
        return;
    }
    bool reuse = (pn32 == it->second.lastPN);
    bool rewind = (pn32 < it->second.lastPN) && !reuse;
    bool fired = false;
    FragAttackEvent ev{};
    memcpy(ev.srcMac, a2, 6);
    ev.tid = tid;
    ev.lastPN = it->second.lastPN;
    ev.observedPN = pn32;
    ev.rssi = e.rssi;
    ev.channel = e.channel;
    ev.ts = now;
    if (reuse) { strncpy(ev.reason, "PN_REUSE", sizeof(ev.reason) - 1); fired = true; }
    else if (rewind) { strncpy(ev.reason, "PN_REWIND", sizeof(ev.reason) - 1); fired = true; }
    if (aMsdu) {
        // A-MSDU bit set: spec-compliant frames must use LLC/SNAP A-MSDU header.
        // Without decryption we can't fully validate; flag if PN rewind co-occurs.
        if (rewind || reuse) {
            strncpy(ev.reason, "AMSDU_BAD", sizeof(ev.reason) - 1);
            fired = true;
        }
    }
    if (fired) {
        g_fragLog.push_back(ev);
        if (g_fragLog.size() > MAX_FRAG_LOG) g_fragLog.erase(g_fragLog.begin());
        String src = macStr(a2);
        String line = String("{\"src\":\"") + src +
                      "\",\"tid\":" + String(tid) +
                      ",\"reason\":\"" + ev.reason +
                      "\",\"last_pn\":" + String(ev.lastPN) +
                      ",\"obs_pn\":" + String(ev.observedPN) +
                      ",\"rssi\":" + String(e.rssi) +
                      ",\"ch\":" + String(e.channel) +
                      ",\"ts\":" + String(now) + "}";
        logEventToSD("/fragattack.jsonl", line);
        if (meshEnabled) {
            sendToSerial1(getNodeId() + ": FRAG:" + src + ":" + ev.reason, true);
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
    {0xFF4F, 0xFFFF, 0, {0,0,0,0}, "AirTag"},
    {0xFD6F, 0xFFFF, 0, {0,0,0,0}, "AppleFindMy"},
    {0xFD5A, 0xFFFF, 0, {0,0,0,0}, "SamsungSmartTag"},
    {0xFEED, 0xFFFF, 0, {0,0,0,0}, "Tile"},
    {0xFD6C, 0xFFFF, 0, {0,0,0,0}, "Skydio"},
    {0xFFE0, 0xFFFF, 0, {0,0,0,0}, "DJI"},
    {0xFFFA, 0xFFFF, 0, {0,0,0,0}, "OpenDroneID"},
    {0,       0x004C, 0, {0,0,0,0}, "Apple"},          // generic Apple mfg
    {0,       0x0075, 0, {0,0,0,0}, "Samsung"},
    {0,       0x009C, 0, {0,0,0,0}, "Chipolo"},
    {0,       0x0500, 0, {0,0,0,0}, "PebbleBee"},
    {0,       0x015F, 0, {0,0,0,0}, "Eufy"},
    {0,       0x05E6, 0, {0,0,0,0}, "RollingSquare"},
    {0,       0x5941, 0, {0,0,0,0}, "Autel"},
};

static bool parseAdvForWatch(const uint8_t *p, uint16_t len, WatchEntry &outMatch) {
    uint16_t off = 0;
    while (off + 2 <= len) {
        uint8_t l = p[off];
        if (l == 0) { off += 1; continue; }
        if (off + 1 + l > len) return false;
        uint8_t adType = p[off + 1];
        // 0x16 Service Data 16-bit UUID
        if (adType == 0x16 && l >= 3) {
            uint16_t uuid = (uint16_t)p[off + 2] | ((uint16_t)p[off + 3] << 8);
            for (const auto &w : kWatch) {
                if (w.serviceUuid == uuid) { outMatch = w; return true; }
            }
        }
        // 0xFF Manufacturer Specific Data
        if (adType == 0xFF && l >= 3) {
            uint16_t mfg = (uint16_t)p[off + 2] | ((uint16_t)p[off + 3] << 8);
            for (const auto &w : kWatch) {
                if (w.serviceUuid == 0 && w.mfgId == mfg) { outMatch = w; return true; }
            }
        }
        off += 1 + l;
    }
    return false;
}

static bool validateBleAdvStructure(const uint8_t *p, uint16_t len, const char **reason) {
    if (len > 31) { *reason = "PAYLOAD_OVERLEN"; return false; }
    uint16_t off = 0;
    while (off < len) {
        uint8_t l = p[off];
        if (l == 0) { off += 1; continue; }
        if (off + 1 + l > len) { *reason = "BAD_LEN_FIELD"; return false; }
        off += 1 + l;
    }
    return true;
}

void onBleAdv(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len, const char *name) {
    if (!g_detectEnabled.load()) return;
    uint32_t now = millis();
    const char *malformedReason = nullptr;
    if (!validateBleAdvStructure(payload, len, &malformedReason) && malformedReason) {
        BleMalformedEvent ev{};
        memcpy(ev.addr, addr, 6);
        ev.rssi = rssi;
        strncpy(ev.reason, malformedReason, sizeof(ev.reason) - 1);
        ev.payloadLen = len;
        ev.ts = now;
        std::lock_guard<std::mutex> lk(g_mtx);
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
    WatchEntry match{};
    if (!parseAdvForWatch(payload, len, match)) return;

    std::lock_guard<std::mutex> lk(g_mtx);
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
        if (meshEnabled) {
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
    std::lock_guard<std::mutex> lk(g_mtx);
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

    // Local validation if we have 2+ GPS reports
    int gpsCount = 0;
    bool geomViolation = false;
    for (auto &rx2 : c.rxs) if (rx2.hasGps) gpsCount++;
    if (gpsCount >= 2) {
        bool anyClose = false;
        bool anyFar = false;
        for (auto &rx2 : c.rxs) {
            if (!rx2.hasGps) continue;
            float claimedDist = haversineMeters(rx2.nodeLat, rx2.nodeLon, lat, lon);
            float rssiDist = rssiToMeters(rx2.rssi);
            float ratio = (claimedDist > 1.0f) ? (rssiDist / claimedDist) : 0.0f;
            if (claimedDist > 2000.0f && rssiDist < 200.0f) anyClose = true;
            if (ratio > 5.0f || ratio < 0.05f) geomViolation = true;
            (void)anyFar;
        }
        c.verified = !geomViolation && !anyClose;
        c.insufficient = false;
    } else {
        c.insufficient = true;
        c.verified = false;
    }
}
} // namespace ah_detect

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
    detectFrameQueue = xQueueCreate(64, sizeof(DetectFrameEvent));
    g_detectFrameQueue = detectFrameQueue;
    g_quorumRequired["PMKID"] = 2;
    g_quorumRequired["EVILTWIN"] = 2;
    g_quorumRequired["SSIDCONF"] = 2;
    g_quorumRequired["SAE_DOS"] = 1;
    g_quorumRequired["BLETRACK"] = 2;
    g_quorumRequired["RECON"] = 2;
    loadOuiTable();
    Serial.println("[DETECT] Initialized");
}

void detect_onWifiFrame(const uint8_t *payload, uint16_t len, int8_t rssi, uint8_t channel) {
    if (!detectEnabled.load() || !detectFrameQueue) return;
    if (len < 24) return;
    uint16_t fc = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t stype = (fc >> 4) & 0xF;
    DetectFrameEvent ev{};
    ev.channel = channel;
    ev.rssi = rssi;
    uint16_t cap = (len < sizeof(ev.payload)) ? len : (uint16_t)sizeof(ev.payload);
    memcpy(ev.payload, payload, cap);
    ev.len = cap;

    if (ftype == 0 && stype == 8)        ev.kind = DetectFrameEvent::BEACON_DEEP;
    else if (ftype == 0 && stype == 5)   ev.kind = DetectFrameEvent::PROBE_RESP;
    else if (ftype == 0 && stype == 11)  ev.kind = DetectFrameEvent::AUTH_SAE;
    else if (ftype == 2 && stype == 8)   ev.kind = DetectFrameEvent::QOS_DATA;
    else if (ftype == 2)                 ev.kind = DetectFrameEvent::EAPOL;
    else return;

    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(detectFrameQueue, &ev, &woken);
    if (woken) portYIELD_FROM_ISR();
}

void detect_onBleAdv(const uint8_t *addr, int8_t rssi,
                     const uint8_t *payload, uint16_t payloadLen,
                     const char *name) {
    onBleAdv(addr, rssi, payload, payloadLen, name);
}

void detectTask(void *pv) {
    Serial.println("[DETECT] Task started");
    DetectFrameEvent ev;
    // Skip first gossip cycle so Bloom has chance to populate during boot
    uint32_t lastGossip = millis();
    uint32_t lastPpsEpochUpdate = 0;
    while (true) {
        if (xQueueReceive(detectFrameQueue, &ev, pdMS_TO_TICKS(100)) == pdTRUE) {
            switch (ev.kind) {
                case DetectFrameEvent::EAPOL:       handleEAPOL(ev); break;
                case DetectFrameEvent::AUTH_SAE:    handleAuthSae(ev); break;
                case DetectFrameEvent::BEACON_DEEP: handleBeacon(ev); break;
                case DetectFrameEvent::PROBE_RESP:  handleProbeResp(ev); break;
                case DetectFrameEvent::QOS_DATA:    handleQosData(ev); break;
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
        if (meshEnabled && now - lastGossip > 60000) {
            lastGossip = now;
            detect_periodicMeshGossip();
        }
        // Quorum aging
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            for (auto it = g_alerts.begin(); it != g_alerts.end(); ) {
                if (now - it->second.firstSeen > 120000) it = g_alerts.erase(it);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
    auto it = g_alerts.find(type + ":" + key);
    if (it == g_alerts.end()) return 0;
    return it->second.reports.size();
}
void quorum_setRequired(const String &type, uint8_t n) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_quorumRequired[type] = n;
}
uint8_t quorum_getRequired(const String &type) {
    std::lock_guard<std::mutex> lk(g_mtx);
    auto it = g_quorumRequired.find(type);
    return it == g_quorumRequired.end() ? 2 : it->second;
}

// =============================================================================
// Mesh handling for new prefixes
// =============================================================================
void detect_processMesh(const String &fromNode, const String &msg) {
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
        std::lock_guard<std::mutex> lk(g_mtx);
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
        std::lock_guard<std::mutex> lk(g_mtx);
        auto &c = g_ridClaims[uavId];
        strncpy(c.uavId, uavId.c_str(), sizeof(c.uavId) - 1);
        RidClaim::Rx rx;
        rx.nodeId = fromNode; rx.rssi = (int8_t)rssi;
        rx.nodeLat = lat; rx.nodeLon = lon; rx.hasGps = (valid != 0);
        rx.ts = millis();
        c.rxs.push_back(rx);
        if (c.rxs.size() > 16) c.rxs.erase(c.rxs.begin());
    } else if (msg.startsWith("BLOOM:")) {
        // Base64-like raw 2KB filter would exceed mesh frame. We use packed-hex chunks
        // by index: BLOOM:<idx>:<128hex bytes>
        int p1 = msg.indexOf(':', 6);
        if (p1 < 0) return;
        int idx = msg.substring(6, p1).toInt();
        String hex = msg.substring(p1 + 1);
        if (idx < 0 || idx >= (int)(BloomFilter::BYTES / 128)) return;
        std::lock_guard<std::mutex> lk(g_mtx);
        uint8_t *dst = g_neighborBloom.mutableData() + idx * 128;
        for (size_t i = 0; i < 128 && i * 2 + 1 < hex.length(); ++i) {
            uint8_t b = 0;
            for (int n = 0; n < 2; ++n) {
                char c = hex[i * 2 + n];
                b <<= 4;
                if (c >= '0' && c <= '9') b |= c - '0';
                else if (c >= 'A' && c <= 'F') b |= c - 'A' + 10;
                else if (c >= 'a' && c <= 'f') b |= c - 'a' + 10;
            }
            dst[i] |= b;  // OR-merge
        }
    } else if (msg.startsWith("CHAN_ASSIGN:")) {
        // CHAN_ASSIGN:nodeId:1,2,3
        int p1 = msg.indexOf(':', 12);
        if (p1 < 0) return;
        String tgt = msg.substring(12, p1);
        String csv = msg.substring(p1 + 1);
        std::lock_guard<std::mutex> lk(g_mtx);
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

void detect_periodicMeshGossip() {
    // Send only non-zero Bloom chunks. Empty filter = no broadcast.
    std::lock_guard<std::mutex> lk(g_mtx);
    const uint8_t *src = g_localBloom.data();
    size_t sent = 0;
    for (size_t idx = 0; idx < BloomFilter::BYTES / 128; ++idx) {
        bool anySet = false;
        for (size_t i = 0; i < 128; ++i) {
            if (src[idx * 128 + i]) { anySet = true; break; }
        }
        if (!anySet) continue;
        String hex = String("BLOOM:") + String((unsigned)idx) + ":";
        char tmp[3];
        for (size_t i = 0; i < 128; ++i) {
            snprintf(tmp, sizeof(tmp), "%02X", src[idx * 128 + i]);
            hex += tmp;
        }
        sendToSerial1(getNodeId() + ": " + hex, true);
        vTaskDelay(pdMS_TO_TICKS(20));
        if (++sent >= 4) break;  // cap per gossip cycle to limit mesh load
    }
}

// =============================================================================
// Bloom API
// =============================================================================
void detect_addLocalBaseline(const uint8_t *mac, uint32_t ieHash) {
    uint8_t buf[10]; memcpy(buf, mac, 6); memcpy(buf + 6, &ieHash, 4);
    uint32_t h = fnv1a(buf, 10);
    std::lock_guard<std::mutex> lk(g_mtx);
    g_localBloom.add(h);
}
bool detect_neighborKnows(const uint8_t *mac, uint32_t ieHash) {
    uint8_t buf[10]; memcpy(buf, mac, 6); memcpy(buf + 6, &ieHash, 4);
    uint32_t h = fnv1a(buf, 10);
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_neighborBloom.maybeContains(h);
}
String detect_getBloomStatsJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    if (!LittleFS.begin(false)) return false;
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
        sendToSerial1(getNodeId() + ": RECON:" + identityId + ":" + String(r.score), true);
        quorum_addReport("RECON", String(identityId), getNodeId(), -50);
    }
}
String detect_getReconJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_pmkidLog, [](const PmkidHarvestEvent &e){
        return String("{\"src\":\"") + macStr(e.srcMac) + "\",\"bssid\":\"" + macStr(e.bssid) +
               "\",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getEvilTwinJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_evilTwinLog, [](const EvilTwinEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) + "\",\"ssid\":\"" + e.ssid +
               "\",\"reason\":\"" + e.reason +
               "\",\"new_bi\":" + String(e.newBeaconInt) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getSsidConfusionJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_ssidConfusionLog, [](const SsidConfusionEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) + "\",\"beacon\":\"" + e.beaconSsid +
               "\",\"resp\":\"" + e.respSsid + "\",\"rssi\":" + String(e.rssi) +
               ",\"ch\":" + String(e.channel) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getSaeDosJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_saeDosLog, [](const SaeDosEvent &e){
        return String("{\"bssid\":\"") + macStr(e.bssid) +
               "\",\"unmatched\":" + String(e.unmatchedCommits) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getOweAbuseJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_oweAbuseLog, [](const OweAbuseEvent &e){
        return String("{\"open\":\"") + macStr(e.openBssid) + "\",\"owe\":\"" + macStr(e.oweBssid) +
               "\",\"ssid\":\"" + e.ssid + "\",\"rssi\":" + String(e.rssi) +
               ",\"ch\":" + String(e.channel) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getFragAttackJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_fragLog, [](const FragAttackEvent &e){
        return String("{\"src\":\"") + macStr(e.srcMac) + "\",\"tid\":" + String(e.tid) +
               ",\"reason\":\"" + e.reason +
               "\",\"last_pn\":" + String(e.lastPN) + ",\"obs_pn\":" + String(e.observedPN) +
               ",\"rssi\":" + String(e.rssi) + ",\"ch\":" + String(e.channel) +
               ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getBleMalformedJsonl() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return jsonlOf(g_bleMalformedLog, [](const BleMalformedEvent &e){
        return String("{\"addr\":\"") + macStr(e.addr) +
               "\",\"reason\":\"" + e.reason + "\",\"len\":" + String(e.payloadLen) +
               ",\"rssi\":" + String(e.rssi) + ",\"ts\":" + String(e.ts) + "}";
    });
}
String detect_getQuorumStatusJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
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
    std::lock_guard<std::mutex> lk(g_mtx);
    g_bleTrackers.clear();
}
void detect_clearAll() {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_pmkidLog.clear();
    g_evilTwinLog.clear();
    g_ssidConfusionLog.clear();
    g_saeDosLog.clear();
    g_oweAbuseLog.clear();
    g_fragLog.clear();
    g_bleMalformedLog.clear();
    g_ridClaims.clear();
    g_alerts.clear();
    g_bleTrackers.clear();
    g_recon.clear();
}
