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
            for (const auto &kv : g_hunts) if (kv.second.lastKick < oldestT) { oldestT = kv.second.lastKick; oldestK = kv.first; }
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
// Feature 5: Distributed 4-way handshake reconstruction + KRACK
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
    if (msgNum == 3) {
        auto kfit = std::find_if(r.fragments.begin(), r.fragments.end(),
            [replayCtr](const HandshakeFragment &frag) { return frag.msgNum == 3 && frag.replayCtr == replayCtr; });
        if (kfit != r.fragments.end()) {
            if (r.krackEvents < 255) r.krackEvents++;
            g_krackEvents.fetch_add(1);
            ::detect_logIncident(String("KRACK:") + macStr(bssid) + ":" + macStr(sta) +
                                 ":" + String((unsigned long)replayCtr), nullptr);
            if (meshEnabled && sentinel_isRunning() && g_meshHshk.load() && meshRateGate("KRACK_" + macStr(bssid), 30000)) {
                sendToSerial1(getNodeId() + ": KRACK:" + macStr(bssid) + ":" + macStr(sta) +
                              ":" + String((unsigned long)replayCtr), true);
            }
            quorum_addReport("KRACK", macStr(bssid) + "/" + macStr(sta), getNodeId(), rssi);
            attacker_kick(bssid, "KRACK");
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
PsramMap<uint64_t, AirTagPresence> g_airtag;
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
// struct AirTagReplayEntry now in detect_internal.h
PsramMap<uint32_t, AirTagReplayEntry> g_airtagReplay;
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
    f.write(reinterpret_cast<const uint8_t*>(&rec), sizeof(rec));
    f.close();
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

// Marauder WiFiScan.cpp:334/338 sliding-window fallback for shifted/malformed
// frames the structured AD-walk (airtagDecode) can't parse.
static bool airtagDecodeSliding(const uint8_t *adv, uint16_t len, uint8_t &statusOut) {
    if (len < 4) return false;
    for (uint16_t i = 0; i + 4 <= len; i++) {
        if (adv[i] == 0x1E && adv[i+1] == 0xFF && adv[i+2] == 0x4C && adv[i+3] == 0x00) {
            if (i + 6 < len && adv[i+4] == 0x12 && adv[i+5] == 0x19) { statusOut = adv[i+6]; return true; }
            statusOut = 0; return true;
        }
        if (adv[i] == 0x4C && adv[i+1] == 0x00 && adv[i+2] == 0x12 && adv[i+3] == 0x19) {
            if (i + 4 < len) { statusOut = adv[i+4]; return true; }
            statusOut = 0; return true;
        }
    }
    return false;
}

static uint32_t fnvStr(const String &s) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < s.length(); ++i) { h ^= (uint8_t)s[i]; h *= 16777619u; }
    return h;
}

// Follower/stalk scoring: co-present + owner-absent + (mesh clusters OR single-node persist).
// identityHash = on-air payload hash (cross-node stable within rotation window).
void followerProcess(uint32_t identityHash, const String &nodeId, int8_t rssi, bool ownerNearby, uint32_t now) {
    auto it = g_followers.find(identityHash);
    if (it == g_followers.end()) {
        if (g_followers.size() >= MAX_FOLLOWERS) {
            uint32_t oldK = 0, oldT = UINT32_MAX;
            for (const auto &kv : g_followers) if (kv.second.lastSeen < oldT) { oldT = kv.second.lastSeen; oldK = kv.first; }
            g_followers.erase(oldK);
        }
        FollowerTrack nf{};
        nf.identityHash = identityHash;
        nf.firstSeen = now;
        g_followers[identityHash] = nf;
        it = g_followers.find(identityHash);
    }
    FollowerTrack &f = it->second;
    f.lastSeen = now;
    f.observations++;
    if (!ownerNearby) f.ownerAbsentCount++;
    f.clusters.insert(fnvStr(nodeId));
    if (meshEnabled && meshRateGate("CSS_" + String(identityHash, HEX), 30000))
        sendToSerial1(getNodeId() + ": FOLLOWER:" + String(identityHash, HEX) +
                      " seen=" + String(f.observations) + "x owner-absent=" +
                      String(f.observations ? (int)((100u * f.ownerAbsentCount) / f.observations) : 0) +
                      "% rssi=" + String(rssi) + (f.alerted ? " [ALERTED]" : ""), true);

    uint32_t co = now - f.firstSeen;
    int absentPct = f.observations ? (int)((100u * f.ownerAbsentCount) / f.observations) : 0;
    bool clusterOk = f.clusters.size() >= cs_min_clusters.load();
    bool persistOk = co >= cs_persist_ms.load();
    if (!f.alerted && co >= cs_copresent_ms.load() && (clusterOk || persistOk) &&
        absentPct >= (int)cs_owner_absent_pct_x100.load()) {
        f.alerted = true;
        String line = String("{\"identity\":\"") + String(identityHash, HEX) +
                      "\",\"clusters\":" + String((unsigned)f.clusters.size()) +
                      ",\"owner_absent_pct\":" + String(absentPct) +
                      ",\"copresent_ms\":" + String(co) +
                      ",\"rssi\":" + String(rssi) +
                      ",\"reason\":\"FOLLOWER\",\"ts\":" + String(now) + "}";
        logEventToSD("/ble_attack.jsonl", line);
        if (meshEnabled && meshRateGate("FOLLOWER_" + String(identityHash, HEX), 60000))
            sendToSerial1(getNodeId() + ": BLE_ATTACK:Follower:" + String(identityHash, HEX) +
                          ":clusters=" + String((unsigned)f.clusters.size()) + ":absent=" + String(absentPct), true);
        quorum_addReport("BLE_ATTACK", String("Follower"), getNodeId(), rssi);
    }
}

void followerAddCluster(uint32_t identityHash, const String &nodeId, uint32_t now) {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    auto it = g_followers.find(identityHash);
    if (it == g_followers.end()) return;   // only enrich locally-seen tracks
    it->second.clusters.insert(fnvStr(nodeId));
    it->second.lastSeen = now;
    // ponytail: peer sighting enriches cluster set; alert re-scored on next local adv (trackers beacon ~1-2s)
}

// Apple continuity message type = byte after mfg 4C 00.
static bool appleContinuitySubtype(const uint8_t *adv, uint16_t len, uint8_t &out) {
    uint16_t off = 0;
    while (off + 2 <= len) {
        uint8_t l = adv[off];
        if (l == 0) { off++; continue; }
        if (off + 1 + l > len) return false;
        if (adv[off+1] == 0xFF && l >= 4 && adv[off+2] == 0x4C && adv[off+3] == 0x00) { out = adv[off+4]; return true; }
        off += 1 + l;
    }
    return false;
}

// Impossible-rotation: real Apple holds a continuity identity ~15 min; a spam tool
// (Flipper/nRF) cycles the same subtype across many MACs/sec. Closes the 2026-05-22
// rate-gate caveat on BLE_ATTACK_SIGS.
struct CsRotWindow { uint32_t start{}; PsramSet<uint64_t> macs; bool alerted{}; };
static PsramMap<uint8_t, CsRotWindow> g_csRot;

void rotationAnomaly(const uint8_t *payload, uint16_t len, uint64_t mac, int8_t rssi, uint32_t now) {
    uint8_t subtype;
    if (!appleContinuitySubtype(payload, len, subtype)) return;
    CsRotWindow &w = g_csRot[subtype];
    if (now - w.start > 1000) { w.start = now; w.macs.clear(); w.alerted = false; }
    w.macs.insert(mac);
    if (!w.alerted && w.macs.size() > cs_rotation_rate.load()) {
        w.alerted = true;
        String line = String("{\"subtype\":") + String(subtype) +
                      ",\"distinct_macs\":" + String((unsigned)w.macs.size()) +
                      ",\"rssi\":" + String(rssi) +
                      ",\"reason\":\"BLE_SPAM\",\"ts\":" + String(now) + "}";
        logEventToSD("/ble_attack.jsonl", line);
        if (meshEnabled && meshRateGate("BLESPAM_" + String(subtype), 30000))
            sendToSerial1(getNodeId() + ": BLE_ATTACK:BLE_Spam:subtype=" + String(subtype) +
                          ":macs=" + String((unsigned)w.macs.size()), true);
        quorum_addReport("BLE_ATTACK", String("BLE_Spam"), getNodeId(), rssi);
        g_csSpamAlerts.fetch_add(1);
    }
}

// Find-My exfil (Send My / OpenHaystack modem): a real tag holds one key ~15 min,
// so its payload hash recurs, not "new". A modem streams NEW keys to push payload
// bits. Flag on new-key rate; static ambient tags don't recur as new -> low FP.
// ponytail: threshold = 4x rotation_rate (~20 new keys/10s); one knob, defensible default.
static PsramMap<uint32_t, uint32_t> g_csKeySeen;   // pHash -> firstSeen
static uint32_t g_csExfilWinStart = 0, g_csExfilNewKeys = 0;
static bool g_csExfilAlerted = false;

void exfilCadence(uint32_t pHash, int8_t rssi, uint32_t now) {
    if (now - g_csExfilWinStart > 10000) { g_csExfilWinStart = now; g_csExfilNewKeys = 0; g_csExfilAlerted = false; }
    if (g_csKeySeen.find(pHash) == g_csKeySeen.end()) {
        if (g_csKeySeen.size() >= 256) {
            uint32_t oldK = 0, oldT = UINT32_MAX;
            for (const auto &kv : g_csKeySeen) if (kv.second < oldT) { oldT = kv.second; oldK = kv.first; }
            g_csKeySeen.erase(oldK);
        }
        g_csKeySeen[pHash] = now;
        g_csExfilNewKeys++;
    }
    if (!g_csExfilAlerted && g_csExfilNewKeys > cs_rotation_rate.load() * 4) {
        g_csExfilAlerted = true;
        String line = String("{\"new_keys_10s\":") + String(g_csExfilNewKeys) +
                      ",\"rssi\":" + String(rssi) +
                      ",\"reason\":\"FINDMY_EXFIL\",\"ts\":" + String(now) + "}";
        logEventToSD("/ble_attack.jsonl", line);
        if (meshEnabled && meshRateGate("FMEXFIL", 30000))
            sendToSerial1(getNodeId() + ": BLE_ATTACK:FindMy_Exfil:newkeys=" + String(g_csExfilNewKeys), true);
        quorum_addReport("BLE_ATTACK", String("FindMy_Exfil"), getNodeId(), rssi);
        g_csExfilAlerts.fetch_add(1);
    }
}

void airtagProcess(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len) {
    uint8_t status = 0;
    if (!airtagDecode(payload, len, status) &&
        !airtagDecodeSliding(payload, len, status)) return;

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
                for (const auto &kv : g_airtagReplay) if (kv.second.firstSeenMs < oldest) { oldest = kv.second.firstSeenMs; oldestKey = kv.first; }
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
            for (const auto &kv : g_airtag) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
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

    followerProcess(pHash, getNodeId(), rssi, maintained, now);
    if (g_csEnabled.load()) exfilCadence(pHash, rssi, now);
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

String cs_getResultsJson() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "{\"present\":" + airtag_getPresenceJson() + ",\"followers\":[";
    bool first = true;
    for (auto &kv : g_followers) {
        FollowerTrack &f = kv.second;
        if (!first) out += ",";
        first = false;
        int absentPct = f.observations ? (int)((100u * f.ownerAbsentCount) / f.observations) : 0;
        out += "{\"identity\":\"" + String(f.identityHash, HEX) + "\"" +
               ",\"clusters\":" + String((unsigned)f.clusters.size()) +
               ",\"observations\":" + String(f.observations) +
               ",\"owner_absent_pct\":" + String(absentPct) +
               ",\"alerted\":" + String(f.alerted ? "true" : "false") +
               ",\"first\":" + String(f.firstSeen) +
               ",\"last\":" + String(f.lastSeen) + "}";
    }
    out += "]}";
    return out;
}

String cs_getResultsText() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    String out = "Counter-Surveillance / Find My\n";
    out += "AirTags / Find My present: " + String((unsigned)g_airtag.size()) + "\n";
    for (auto &kv : g_airtag) {
        AirTagPresence &p = kv.second;
        bool ownerNearby = (p.lastStatusByte & 0x04) != 0;
        out += "  " + macStr(p.addr) + "  RSSI " + String(p.lastRssi) + "dBm  " +
               (ownerNearby ? "owner-nearby" : "separated") +
               "  seen " + String(p.observations) + "x\n";
    }
    out += "Potential followers: " + String((unsigned)g_followers.size()) + "\n";
    for (auto &kv : g_followers) {
        FollowerTrack &f = kv.second;
        int absentPct = f.observations ? (int)((100u * f.ownerAbsentCount) / f.observations) : 0;
        out += "  id " + String(f.identityHash, HEX) + "  seen " + String(f.observations) +
               "x  owner-absent " + String(absentPct) + "%  clusters " + String((unsigned)f.clusters.size()) +
               (f.alerted ? "  [ALERTED - possible follower]" : "") + "\n";
    }
    out += "BLE trackers: " + String((unsigned)g_bleTrackers.size()) + "\n";
    for (auto &kv : g_bleTrackers) {
        BleTrackerSighting &s = kv.second;
        out += "  " + macStr(s.addr) + "  " + String(s.vendor) + "  RSSI " + String(s.avgRssi) +
               "dBm  seen " + String(s.sightingCount) + "x  persist " + String(s.persistenceScore) +
               (s.followAlerted ? "  [FOLLOWING]" : "") + "\n";
    }
    if (g_airtag.empty() && g_followers.empty() && g_bleTrackers.empty())
        out += "\nNo AirTags / Find My devices, trackers, or followers detected yet.\n";
    return out;
}

// =============================================================================
// Feature 3: BLE tracker rotation un-linking
// =============================================================================
// struct VanishedTracker now in detect_internal.h
PsramVec<VanishedTracker> g_vanished;
PsramMap<uint32_t, TrackerChain> g_chains;
PsramMap<uint32_t, FollowerTrack> g_followers;
std::atomic<uint32_t> cs_copresent_ms{600000};
std::atomic<uint32_t> cs_persist_ms{900000};
std::atomic<uint32_t> cs_min_clusters{2};
std::atomic<uint32_t> cs_rotation_rate{5};
std::atomic<uint32_t> cs_owner_absent_pct_x100{80};
std::atomic<bool> g_csEnabled{false};
std::atomic<uint32_t> g_csSpamAlerts{0};   // session count of BLE_SPAM alerts (telemetry)
std::atomic<uint32_t> g_csExfilAlerts{0};  // session count of FINDMY_EXFIL alerts
static uint32_t g_chainSeq = 1;
static constexpr uint32_t TRACKER_VANISH_MS    = 60000;
static constexpr uint32_t TRACKER_LINK_WINDOW  = 90000;
static constexpr int8_t   TRACKER_RSSI_TOL_DB  = 6;
static constexpr size_t   MAX_CHAINS           = 80;
static constexpr size_t   MAX_VANISHED         = 60;

uint32_t trackerTryLinkRotation(const uint8_t *addr, const char *vendor, int8_t rssi, uint32_t now) {
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
                    for (const auto &kv : g_chains) if (kv.second.lastSeen < oldestT) { oldestT = kv.second.lastSeen; oldestK = kv.first; }
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
            if (meshEnabled && sentinel_isRunning() && g_meshTracker.load() && meshRateGate("TRKLINK_" + String(cid), 30000)) {
                sendToSerial1(getNodeId() + ": TRK_LINK:" + String(cid) + ":" +
                              vendor + ":" + macStr(addr) + ":" + String(rssi), true);
            }
            return cid;
        }
        ++it;
    }
    return 0;
}

void trackerSweepVanished(uint32_t now) {
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
static constexpr uint16_t SNAP_VER   = 3;

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
    File f = SD.open(tmpPath, FILE_WRITE);
    if (!f) return;
    SnapHeader h{};
    h.magic = SNAP_MAGIC;
    h.ver = SNAP_VER;
    h._pad = 0;
    h.chains = g_chains.size();
    h.airtag = g_airtag.size();
    h.recon  = g_recon.size();
    h.tsf    = 0;
    h.pwna   = g_pwna.size();
    f.write(reinterpret_cast<const uint8_t*>(&h), sizeof(h));
    for (auto &kv : g_chains) {
        uint32_t cid = kv.second.chainId;
        f.write(reinterpret_cast<const uint8_t*>(&cid), 4);
        f.write(reinterpret_cast<const uint8_t*>(kv.second.vendor), 16);
        int8_t avg = kv.second.avgRssi;
        f.write(reinterpret_cast<const uint8_t*>(&avg), 1);
        uint8_t lc = (kv.second.links.size() > 8) ? 8 : static_cast<uint8_t>(kv.second.links.size());
        f.write(&lc, 1);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.firstSeen), 4);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.lastSeen), 4);
        size_t writtenLinks = 0;
        for (auto &lnk : kv.second.links) {
            if (writtenLinks >= 8) break;
            f.write(lnk.addr, 6);
            int8_t lr = lnk.rssi;
            f.write(reinterpret_cast<const uint8_t*>(&lr), 1);
            f.write(reinterpret_cast<const uint8_t*>(&lnk.startTs), 4);
            f.write(reinterpret_cast<const uint8_t*>(&lnk.endTs), 4);
            writtenLinks++;
        }
    }
    for (auto &kv : g_airtag) {
        f.write(kv.second.addr, 6);
        f.write(&kv.second.lastStatusByte, 1);
        uint16_t obs = kv.second.observations;
        f.write(reinterpret_cast<const uint8_t*>(&obs), 2);
        uint16_t mc = kv.second.maintainedCount;
        f.write(reinterpret_cast<const uint8_t*>(&mc), 2);
        f.write(&kv.second.batteryLastSeen, 1);
        int8_t rs = kv.second.lastRssi;
        f.write(reinterpret_cast<const uint8_t*>(&rs), 1);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.firstSeen), 4);
        f.write(reinterpret_cast<const uint8_t*>(&kv.second.lastSeen), 4);
    }
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
    File f = SD.open(SNAP_PATH, FILE_READ);
    if (!f) return;
    SnapHeader h{};
    if (f.read(reinterpret_cast<uint8_t*>(&h), sizeof(h)) != sizeof(h)) { f.close(); return; }
    if (h.magic != SNAP_MAGIC || h.ver != SNAP_VER) { f.close(); return; }
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    for (uint32_t i = 0; i < h.chains; ++i) {
        uint32_t cid; char vendor[16]; int8_t avg; uint8_t lc;
        uint32_t first, last;
        if (f.read(reinterpret_cast<uint8_t*>(&cid), 4) != 4) break;
        if (f.read(reinterpret_cast<uint8_t*>(vendor), 16) != 16) break;
        if (f.read(reinterpret_cast<uint8_t*>(&avg), 1) != 1) break;
        if (f.read(&lc, 1) != 1) break;
        if (f.read(reinterpret_cast<uint8_t*>(&first), 4) != 4) break;
        if (f.read(reinterpret_cast<uint8_t*>(&last), 4) != 4) break;
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
            if (f.read(reinterpret_cast<uint8_t*>(&lr), 1) != 1) { c.linkCount = lidx; break; }
            lnk.rssi = lr;
            if (f.read(reinterpret_cast<uint8_t*>(&lnk.startTs), 4) != 4) { c.linkCount = lidx; break; }
            if (f.read(reinterpret_cast<uint8_t*>(&lnk.endTs), 4) != 4) { c.linkCount = lidx; break; }
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
        if (f.read(reinterpret_cast<uint8_t*>(&obs), 2) != 2) break;
        if (f.read(reinterpret_cast<uint8_t*>(&mc), 2) != 2) break;
        if (f.read(&p.batteryLastSeen, 1) != 1) break;
        int8_t rs;
        if (f.read(reinterpret_cast<uint8_t*>(&rs), 1) != 1) break;
        p.observations = obs;
        p.maintainedCount = mc;
        p.lastRssi = rs;
        if (f.read(reinterpret_cast<uint8_t*>(&p.firstSeen), 4) != 4) break;
        if (f.read(reinterpret_cast<uint8_t*>(&p.lastSeen), 4) != 4) break;
        p.isFindMy = true;
        g_airtag[packMac(p.addr)] = p;
    }
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
