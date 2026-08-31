// detect_features.cpp - feature detectors (ToF/TSF/KARMA/Pwnagotchi/trilat/handshake/AirTag/BLE-rotation/probe-graph/persistence/incidents)
// extracted from detect.cpp; part of namespace ah_detect.
#include "detect.h"
#include "hardware.h"
#include "network.h"
#include "scanner.h"
#include "baseline.h"
#include "drone_detector.h"
#include "main.h"
#include "triangulation.h"
#include "pcap.h"
#include <SD.h>
#include <LittleFS.h>
#include <esp_timer.h>
#include <esp_attr.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <driver/gpio.h>
#include <math.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <algorithm>
#include <numeric>
#include <deque>
#include "detect_internal.h"

extern std::atomic<bool> g_detectVerbose;

extern std::atomic<bool> scanning;
extern std::atomic<bool> stopRequested;
extern ScanMode currentScanMode;

namespace ah_detect {

// =============================================================================
// Feature 12: Inter-node ToF / link-quality via mesh ping
// =============================================================================
// struct TofPendingPing now in detect_internal.h
PsramMap<String, TofPeer> g_tofPeers;
PsramVec<TofPendingPing> g_tofPending;
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
            g_tofPending.erase(it);
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
        uint64_t remoteProc = theirRxUs - origTxEcho;
        if (remoteProc < totalRtt) netRtt = totalRtt - remoteProc;
    }

    auto pit = g_tofPeers.find(fromNode);
    if (pit == g_tofPeers.end()) {
        if (g_tofPeers.size() >= MAX_TOF_PEERS) {
            String oldestKey;
            uint32_t oldestT = UINT32_MAX;
            for (const auto &kv : g_tofPeers) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestKey = kv.first; }
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
// Evil-twin via channel multiplicity: same BSSID on >=2 channels (scan mode) =
// two radios. Tracked inline in g_apBaseline (chanA/chanB). Replaced the
// unreliable, attacker-spoofable clock-skew approach. JSON reports per-BSSID
// channel observations.
String tsf_getSkewJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "[";
    bool first = true;
    for (const auto &kv : g_apBaseline) {
        const ApBaseline &b = kv.second;
        if (b.chanA == 0) continue;
        if (!first) out += ",";
        first = false;
        uint8_t bssid[6];
        unpackMac(kv.first, bssid);
        out += "{\"bssid\":\"" + macStr(bssid) + "\"" +
               ",\"ssid\":\"" + String(b.ssid) + "\"" +
               ",\"chan_a\":" + String((unsigned)b.chanA) +
               ",\"chan_b\":" + String((unsigned)b.chanB) +
               ",\"chan_a_ms\":" + String(b.chanAMs) +
               ",\"chan_b_ms\":" + String(b.chanBMs) +
               ",\"last\":" + String(b.lastSeen) + "}";
    }
    out += "]";
    return out;
}
void tsf_clear() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (auto &kv : g_apBaseline) {
        kv.second.chanA = kv.second.chanB = 0;
        kv.second.chanAMs = kv.second.chanBMs = 0;
        kv.second.lastMultichEmitMs = 0;
    }
}
size_t tsf_count() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    return std::count_if(g_apBaseline.begin(), g_apBaseline.end(),
        [](const auto &kv) { return kv.second.chanA != 0; });
}

// =============================================================================
// Feature 9: Reactive KARMA probe-bait
// =============================================================================
PsramMap<uint64_t, KarmaCandidate> g_karma;
PsramMap<uint64_t, PsramSet<String>> g_karmaSsids;
PsramVec<String> g_baitSsids;
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

void karmaEmitBait(const uint8_t *targetBssid) {
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

    wifi_mode_t wmode = WIFI_MODE_NULL;
    wifi_interface_t txif = (esp_wifi_get_mode(&wmode) == ESP_OK && wmode == WIFI_MODE_STA) ? WIFI_IF_STA : WIFI_IF_AP;
    esp_err_t err = esp_wifi_80211_tx(txif, frame, total, false);
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
            for (const auto &kv : g_karma) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
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
        ::detect_logIncident(String("KARMA_CAND:") + macStr(emitBssid) + ":" + String(emitDistinctSsids), nullptr);
        if (meshEnabled && sentinel_isRunning() && g_meshKarma.load() && meshRateGate("KARMA_CAND_" + macStr(emitBssid), 60000)) {
            sendToSerial1(getNodeId() + ": KARMA_CAND:" + macStr(emitBssid) +
                          ":" + String(emitDistinctSsids), true);
        }
    }
}

bool karma_checkBaitMatch(const char *ssid, const uint8_t *bssid, int8_t rssi) {
    if (!ssid || !bssid) return false;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (std::find(g_baitSsids.begin(), g_baitSsids.end(), String(ssid)) == g_baitSsids.end())
        return false;
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
        ::detect_logIncident(String("KARMA_CONFIRMED:") + macStr(bssid) + ":" + String(rssi), nullptr);
        if (meshEnabled && sentinel_isRunning() && g_meshKarma.load() && meshRateGate("KARMA_CONF_" + macStr(bssid), 30000)) {
            sendToSerial1(getNodeId() + ": KARMA_CONFIRMED:" + macStr(bssid) + ":" + String(rssi), true);
        }
        quorum_addReport("KARMA", macStr(bssid), getNodeId(), rssi);
        attacker_kick(bssid, "KARMA");
    }
    return true;
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
    return std::count_if(g_karma.begin(), g_karma.end(),
        [](const auto &kv) { return kv.second.confirmed; });
}

// =============================================================================
// Feature 7: Pwnagotchi swarm detect
// =============================================================================
static const uint8_t PWNAGOTCHI_ADDR2[6] = {0xDE,0xAD,0xBE,0xEF,0xDE,0xAD};
PsramMap<uint64_t, PwnagotchiSighting> g_pwna;
static constexpr size_t MAX_PWNA = 32;

bool isPwnagotchiBeacon(const uint8_t *frame, uint16_t len) {
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

void pwnagotchiObserve(const uint8_t *bssid, int8_t rssi,
                              const uint8_t *ie, uint16_t ieLen) {
    uint32_t now = millis();
    uint64_t k = packMac(bssid);
    auto sit = g_pwna.find(k);
    if (sit == g_pwna.end()) {
        if (g_pwna.size() >= MAX_PWNA) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (const auto &kv : g_pwna) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
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

    static PsramMap<uint64_t, uint32_t> s_pwnaEmit;
    auto eit = s_pwnaEmit.find(k);
    if (eit != s_pwnaEmit.end() && (now - eit->second) < 30000) return;
    if (eit == s_pwnaEmit.end() && s_pwnaEmit.size() >= MAX_PWNA) {
        uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
        for (const auto &kv : s_pwnaEmit) if (kv.second < oldestT) { oldestT = kv.second; oldestK = kv.first; }
        s_pwnaEmit.erase(oldestK);
    }
    s_pwnaEmit[k] = now;

    Serial.printf("[DETECT] PWNAGOTCHI src=%s rssi=%d obs=%u name=%s\n",
                  macStr(bssid).c_str(), (int)rssi, (unsigned)s.observations, s.snippet);
    ::detect_logIncident(String("PWNAGOTCHI:") + macStr(bssid) + ":" + String(rssi), nullptr);
    if (meshEnabled && sentinel_isRunning() && g_meshPwna.load() && meshRateGate("PWNAGOTCHI_" + macStr(bssid), 30000))
        sendToSerial1(getNodeId() + ": PWNAGOTCHI:" + macStr(bssid) + ":" + String(rssi), true);
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
// struct AttackerHunt now in detect_internal.h
PsramMap<uint64_t, AttackerHunt> g_hunts;
std::atomic<uint32_t> g_huntCooldown{60000};
static constexpr size_t MAX_HUNTS = 32;

static std::atomic<uint8_t> g_arPending{0};
static std::atomic<uint32_t> g_arArmedAt{0};
static uint8_t g_arMac[6] = {0};
static char g_arType[24] = {0};
static constexpr uint32_t AR_STALE_MS = 900000;

void attack_responseArm(const uint8_t *mac, const char *attackType) {
    const uint8_t mask = g_attackRespMask.load();
    if (mask == 0) return;
    if (mac) memcpy(g_arMac, mac, 6);
    strncpy(g_arType, attackType ? attackType : "?", sizeof(g_arType) - 1);
    g_arType[sizeof(g_arType) - 1] = '\0';
    g_arPending.store(mask);
    g_arArmedAt.store(millis());
    Serial.printf("[SENTINEL] Attack response armed for %s (mask 0x%02X)\n",
                  macStr(g_arMac).c_str(), mask);
}

void attack_responseCancel() {
    if (g_arPending.exchange(0)) Serial.println("[SENTINEL] Attack response cancelled");
}

uint8_t attack_responsePending() { return g_arPending.load(); }

void attack_responsePump() {
    uint8_t pending = g_arPending.load();
    if (!pending) return;

    if (millis() - g_arArmedAt.load() > AR_STALE_MS) {
        g_arPending.store(0);
        Serial.println("[SENTINEL] Attack response expired before the radio freed up");
        return;
    }
    if (::scanning.load() || ::workerTaskHandle || ::blueTeamTaskHandle || ::triangulationActive.load()) return;

    const uint8_t bit = (uint8_t)(pending & (uint8_t)(-(int8_t)pending));
    g_arPending.store((uint8_t)(pending & ~bit));

    const char *label = "?";
    uint16_t secs = 60;
    TaskFunction_t fn = nullptr;
    const char *taskName = "arespond";
    uint32_t stack = 12288;

    switch (bit) {
        case AR_PCAP:
            label = "packet capture";
            secs = g_arSecsPcap.load();
            setPcapConfig(PCAP_RADIO_WIFI, PCAP_BAND_24, String(""), 250, false);
            setPcapAutoTriggered(true);
            fn = pcapCaptureTask;
            taskName = "pcap";
            stack = 8192;
            break;
        case AR_DEVICE:
            label = "device discovery";
            secs = g_arSecsDevice.load();
            ::currentScanMode = SCAN_BOTH;
            fn = snifferScanTask;
            taskName = "sniffer";
            break;
        case AR_PROBE:
            label = "probe scan";
            secs = g_arSecsProbe.load();
            ::currentScanMode = SCAN_BOTH;
            fn = probeDetectionTask;
            taskName = "probedet";
            stack = 8192;
            break;
        case AR_DRONE:
            label = "drone RID";
            secs = g_arSecsDrone.load();
            ::currentScanMode = SCAN_BOTH;
            fn = droneDetectorTask;
            taskName = "drone";
            break;
        default:
            return;
    }

    ::stopRequested = false;
    ::scanning = true;
    if (ahCreateTask(fn, taskName, stack,
                     reinterpret_cast<void *>(static_cast<intptr_t>(secs)),
                     1, &::workerTaskHandle, 1) != pdPASS) {
        ::scanning = false;
        ::workerTaskHandle = nullptr;
        scanSetCountdown(0, false);
        Serial.printf("[SENTINEL] Attack response %s failed to start\n", label);
        return;
    }
    Serial.printf("[SENTINEL] Attack response: %s for %us on %s (%s)\n",
                  label, (unsigned)secs, macStr(g_arMac).c_str(), g_arType);
    ::detect_logIncident(String("ATTACK_RESPONSE:") + macStr(g_arMac) + ":" + String(label), nullptr);
}

void attacker_kick(const uint8_t *mac, const char *attackType) {
    if (!mac) return;
    const bool trilatOn = g_attackerTrilatEnabled.load();
    if (!trilatOn && g_attackRespMask.load() == 0) return;
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
            for (const auto &kv : g_hunts) if (kv.second.lastKick < oldestT) { oldestT = kv.second.lastKick; oldestK = kv.first; }
            g_hunts.erase(oldestK);
        }
        AttackerHunt h{};
        memcpy(h.mac, mac, 6);
        strncpy(h.attackType, attackType ? attackType : "?", sizeof(h.attackType) - 1);
        h.startedAt = priorStartedAt;
        h.lastKick = now;
        g_hunts[k] = h;
        if (trilatOn && !::triangulationActive.load()) {
            startTrilat = true;
            macS = macStr(mac);
        }
    }
    if (startTrilat) ::startTriangulation(macS, g_arSecsTrilat.load());
    attack_responseArm(mac, attackType);
    ::detect_logIncident(String("ATTACKER_HUNT:") + macStr(mac) + ":" + String(attackType ? attackType : "?"), nullptr);
    if (meshEnabled && sentinel_isRunning() && g_meshAttackerHunt.load() && meshRateGate("HUNT_" + macStr(mac), 60000)) {
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
// Feature 5: Distributed 4-way handshake reconstruction
// =============================================================================
PsramMap<uint64_t, HandshakeReconstruction> g_hshk;
std::atomic<uint32_t> g_krackEvents{0};
static constexpr size_t MAX_HSHK = 48;
static constexpr size_t MAX_HSHK_FRAGS = 16;

static uint64_t hshkKey(const uint8_t *bssid, const uint8_t *sta) {
    uint64_t kb = 0, ks = 0;
    for (int i = 0; i < 6; ++i) kb = (kb << 8) | bssid[i];
    for (int i = 0; i < 6; ++i) ks = (ks << 8) | sta[i];
    return kb ^ (ks * 0x9E3779B97F4A7C15ULL);
}

uint8_t classifyEapolMsg(uint16_t keyInfo) {
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

void hshkRecord(const uint8_t *bssid, const uint8_t *sta, uint8_t msgNum,
                       uint64_t replayCtr, int8_t rssi, const char *nodeId, uint32_t now) {
    if (msgNum < 1 || msgNum > 4) return;
    if (bssid[0] & 0x02) return;
    uint64_t k = hshkKey(bssid, sta);
    auto it = g_hshk.find(k);
    if (it == g_hshk.end()) {
        if (g_hshk.size() >= MAX_HSHK) {
            uint64_t oldestK = 0; uint32_t oldestT = UINT32_MAX;
            for (const auto &kv : g_hshk) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
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
// Feature 2: Probe-graph identity correlator
// =============================================================================
PsramMap<uint32_t, ProbeGraphIdentity> g_pgGraph;

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
    String me = getNodeId();
    auto selfIt = std::find_if(id.nodes.begin(), id.nodes.end(),
        [&me](const ProbeGraphIdentity::NodeSeen &n) { return n.nodeId == me; });
    if (selfIt != id.nodes.end()) {
        selfIt->rssi = rssi; selfIt->ts = now;
    } else {
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
// Persistence (SD snapshot of mid-term state across reboot)
// =============================================================================
static constexpr const char *SNAP_PATH = "/detect_state.bin";
static constexpr uint32_t SNAP_MAGIC = 0xA111EDD1;
static constexpr uint16_t SNAP_VER   = 4;

struct SnapHeader {
    uint32_t magic;
    uint16_t ver;
    uint16_t _pad;
    uint32_t chains;
    uint32_t airtag;
    uint32_t recon;
    uint32_t tsf;
    uint32_t pwna;
};

void persistSnapshot() {
    if (!SafeSD::isAvailable()) return;
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    const char *tmpPath = "/detect_state.tmp";
    File f = SafeSD::open(tmpPath, FILE_WRITE);
    if (!f) return;
    SnapHeader h{};
    h.magic = SNAP_MAGIC;
    h.ver = SNAP_VER;
    h._pad = 0;
    h.chains = 0;
    h.airtag = 0;
    h.recon  = g_recon.size();
    h.tsf    = 0;
    h.pwna   = g_pwna.size();
    f.write(reinterpret_cast<const uint8_t*>(&h), sizeof(h));
    for (auto &kv : g_recon) {
        char id[10] = {0};
        strncpy(id, kv.second.identityId, 9);
        f.write(reinterpret_cast<const uint8_t*>(id), 10);
        f.write(&kv.second.score, 1);
        f.write(reinterpret_cast<const uint8_t*>(kv.second.reasons), 96);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.ts), 4);
    }
    for (auto &kv : g_pwna) {
        f.write(kv.second.bssid, 6);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.observations), 2);
        int8_t br = kv.second.bestRssi;
        f.write(reinterpret_cast<const uint8_t*>(&br), 1);
        int8_t lr = kv.second.lastRssi;
        f.write(reinterpret_cast<const uint8_t*>(&lr), 1);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.firstSeen), 4);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.lastSeen), 4);
        f.write(reinterpret_cast<const uint8_t*>(kv.second.snippet), sizeof(kv.second.snippet));
    }
    f.close();
    if (SD.exists(SNAP_PATH)) SD.remove(SNAP_PATH);
    SD.rename(tmpPath, SNAP_PATH);
}

void loadSnapshot() {
    if (!SafeSD::isAvailable()) return;
    if (!SD.exists(SNAP_PATH)) return;
    File f = SafeSD::open(SNAP_PATH, FILE_READ);
    if (!f) return;
    SnapHeader h{};
    if (f.read(reinterpret_cast<uint8_t*>(&h), sizeof(h)) != sizeof(h)) { f.close(); return; }
    if (h.magic != SNAP_MAGIC || h.ver != SNAP_VER) { f.close(); return; }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (uint32_t i = 0; i < h.recon; ++i) {
        char id[10] = {0};
        ReconAlert r{};
        if (f.read(reinterpret_cast<uint8_t*>(id), 10) != 10) break;
        if (f.read(&r.score, 1) != 1) break;
        if (f.read(reinterpret_cast<uint8_t*>(r.reasons), 96) != 96) break;
        if (f.read(reinterpret_cast<uint8_t*>(&r.ts), 4) != 4) break;
        strncpy(r.identityId, id, 9);
        g_recon[String(id)] = r;
    }
    for (uint32_t i = 0; i < h.pwna; ++i) {
        PwnagotchiSighting p{};
        if (f.read(p.bssid, 6) != 6) break;
        if (f.read(reinterpret_cast<uint8_t*>(&p.observations), 2) != 2) break;
        int8_t br;
        if (f.read(reinterpret_cast<uint8_t*>(&br), 1) != 1) break;
        p.bestRssi = br;
        int8_t lr;
        if (f.read(reinterpret_cast<uint8_t*>(&lr), 1) != 1) break;
        p.lastRssi = lr;
        if (f.read(reinterpret_cast<uint8_t*>(&p.firstSeen), 4) != 4) break;
        if (f.read(reinterpret_cast<uint8_t*>(&p.lastSeen), 4) != 4) break;
        if (f.read(reinterpret_cast<uint8_t*>(p.snippet), sizeof(p.snippet)) != sizeof(p.snippet)) break;
        g_pwna[packMac(p.bssid)] = p;
    }
    f.close();
}

// =============================================================================
// Unified incidents log — captures every detector mesh line (local TX + peer RX)
// to /incidents.jsonl on SD + small in-RAM ring for fast UI render.
// =============================================================================
static PsramDeque<String> g_incidentRing;
static std::recursive_mutex g_incidentMtx;
static constexpr size_t MAX_INCIDENT_RING = 200;

static bool isDetectorPrefix(const String &type) {
    static const char *kPrefixes[] = {
        "DEAUTH_FORGE","DEAUTH_FLOOD","EVILTWIN","KARMA_CAND","KARMA_CONFIRMED",
        "BEACON_FORGE","PMKID_HARVEST","PMKID_FORGE","EAPOL_BAIT","PROBE_FLOOD",
        "CSA_SPOOF","QUIET_ABUSE",
        "PROBE_FLOOD_BEHAVE","ASSOC_SLEEP","SAE_DOS",
        "OWE_ABUSE","SSID_CONFUSION","FRAG","KRACK","PWNAGOTCHI",
        "ATTACKER_HUNT","RECON","HSHK","DEAUTH_AP_TARGETED",
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
        "CSA_SPOOF","QUIET_ABUSE",
        "PROBE_FLOOD_BEHAVE","ASSOC_SLEEP","SAE_DOS",
        "OWE_ABUSE","SSID_CONFUSION","FRAG","KRACK","PWNAGOTCHI",
        "ATTACKER_HUNT","RECON","HSHK","DEAUTH_AP_TARGETED",
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
    time_t ep = getRTCEpoch();
    String node = getNodeId();
    String escRaw = raw;
    escRaw.replace("\\", "\\\\");
    escRaw.replace("\"", "\\\"");
    String line = String("{\"ts\":") + String(now) +
                  ",\"epoch\":" + String((uint32_t)ep) +
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
