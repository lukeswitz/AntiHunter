#pragma once
// AntiHunter detection-engineering module
// Phase 1: WiFi/BLE attack-signature detectors (PMKID, evil-twin, SSID confusion,
//          SAE DoS, OWE abuse, FragAttacks A-MSDU PN reuse, BLE malformed adv)
// Phase 2: Mesh coordination (RID spoof validate, Bloom gossip, Byzantine quorum,
//          GPS-PPS time discipline, coordinated channel partition)
// Phase 3: BLE perimeter (tracker persistence/watchlist, BLE ODID, OUI category,
//          CYT recon score, StateFi chipset fingerprint)

#include <Arduino.h>
#include <atomic>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// =============================================================================
// Phase 1 — Attack-signature event types
// =============================================================================

struct PmkidHarvestEvent {
    uint8_t srcMac[6];
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
};

struct EvilTwinEvent {
    uint8_t bssid[6];
    char ssid[33];
    char reason[24];  // "TSF_RESTART" | "TSF_NONMONO" | "IE_DRIFT" | "BEACON_INTERVAL"
    uint64_t oldTSF;
    uint64_t newTSF;
    uint32_t oldIeHash;
    uint32_t newIeHash;
    uint16_t oldBeaconInt;
    uint16_t newBeaconInt;
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
};

struct SsidConfusionEvent {
    uint8_t bssid[6];
    char beaconSsid[33];
    char respSsid[33];
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
};

struct SaeDosEvent {
    uint8_t bssid[6];
    uint16_t unmatchedCommits;
    int8_t rssi;
    uint8_t channel;
    uint32_t windowStart;
    uint32_t ts;
};

struct OweAbuseEvent {
    uint8_t openBssid[6];
    uint8_t oweBssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
};

struct FragAttackEvent {
    uint8_t srcMac[6];
    uint8_t tid;
    uint32_t lastPN;
    uint32_t observedPN;
    char reason[16];  // "PN_REUSE" | "PN_REWIND" | "AMSDU_BAD"
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
};

struct BleMalformedEvent {
    uint8_t addr[6];
    int8_t rssi;
    char reason[24];  // "ADVA_INVALID" | "PAYLOAD_OVERLEN" | "BAD_LEN_FIELD"
    uint16_t payloadLen;
    uint32_t ts;
};

// Raw frame-fragment events from sniffer_cb (ISR-safe)
struct DetectFrameEvent {
    enum Kind : uint8_t {
        EAPOL = 1,        // EAPOL-Key M1 candidate
        AUTH_SAE = 2,     // 802.11 auth, algo=3 SAE
        BEACON_DEEP = 3,  // beacon for evil-twin/OWE analysis
        QOS_DATA = 4,     // QoS data frame for A-MSDU PN check
        PROBE_RESP = 5,   // probe response for SSID confusion
        BLE_ADV = 6,      // BLE adv (deferred from NimBLE callback)
        PROBE_REQ = 7,    // probe request — tool probe-flood fingerprint
        DEAUTH = 8,       // deauth/disassoc — tool/tool tool fingerprint
        ASSOC_REQ = 9     // association request — tool assoc-sleep fingerprint
    };
    uint8_t kind;
    uint8_t channel;
    int8_t rssi;
    uint16_t len;
    uint32_t rxMicrosLo;  // low 32b of disciplined micros (full via lookup if needed)
    uint8_t payload[256]; // truncated; enough for headers + first IE block
};

// =============================================================================
// Phase 2 — Mesh coordination
// =============================================================================

struct AlertCandidate {
    String type;     // "PMKID", "EVILTWIN", "DEAUTH", "RECON", "BLETRACK"
    String key;      // e.g. BSSID or src MAC
    struct Report {
        String nodeId;
        int8_t rssi;
        uint32_t ts;
    };
    std::vector<Report> reports;
    uint32_t firstSeen;
    bool fired;
};

struct RidClaim {
    char uavId[24];
    double lat;
    double lon;
    float alt;
    uint32_t ts;
    struct Rx {
        String nodeId;
        int8_t rssi;
        float nodeLat;
        float nodeLon;
        bool hasGps;
        uint32_t ts;
    };
    std::vector<Rx> rxs;
    bool verified;
    bool insufficient;
};

// Bloom filter — 2KB, k=3 hashes
class BloomFilter {
public:
    static constexpr size_t BITS = 16384;
    static constexpr size_t BYTES = BITS / 8;
    BloomFilter() { memset(bits, 0, BYTES); }
    void add(uint32_t hash);
    bool maybeContains(uint32_t hash) const;
    void clear() { memset(bits, 0, BYTES); }
    const uint8_t* data() const { return bits; }
    uint8_t* mutableData() { return bits; }
    void orFrom(const BloomFilter& other);
private:
    uint8_t bits[BYTES];
    static inline uint32_t h1(uint32_t x);
    static inline uint32_t h2(uint32_t x);
    static inline uint32_t h3(uint32_t x);
};

// =============================================================================
// Phase 3 — BLE perimeter / OUI / recon
// =============================================================================

struct BleTrackerSighting {
    uint8_t addr[6];
    uint16_t serviceUuid;   // 0xFF4F AirTag, 0xFD6F FindMy, 0xFD5A SmartTag, etc.
    uint16_t mfgId;
    uint8_t mfgPrefix[4];
    char vendor[16];        // "AirTag", "SmartTag", "Tile", "Chipolo", ...
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint32_t sightingCount;
    int8_t avgRssi;
    int8_t rssiVarN;        // simple count-based variance proxy
    uint8_t persistenceScore; // 0..100
    bool followAlerted;
};

struct ReconAlert {
    char identityId[10];
    uint8_t score;
    char reasons[96];
    uint32_t ts;
};

enum OuiCategory : uint8_t {
    OUI_UNKNOWN        = 0,
    OUI_KNOWN_GOOD     = 1,
    OUI_IOT_BASELINE   = 2,
    OUI_PENTEST_TOOL   = 3,
    OUI_SURVEILLANCE   = 4,
    OUI_SKIMMER        = 5,
};

// =============================================================================
// Public API
// =============================================================================

extern std::atomic<bool> detectEnabled;

// Lifecycle
void initializeDetect();
void detectTask(void *pv);

// Sniffer hook — called from sniffer_cb (IRAM, must be brief / ISR-safe)
void IRAM_ATTR detect_onWifiFrame(const uint8_t *payload, uint16_t len, int8_t rssi, uint8_t channel);

void detect_witnessDeauth(const uint8_t *src, const uint8_t *dst, int8_t rssi, uint8_t channel);

void detect_onSoftApDisconnect(const uint8_t *clientMac, uint8_t reasonCode);
void detect_onSoftApProbeReq(const uint8_t *srcMac, int8_t rssi);

void sentinel_startAlwaysOn();
void sentinel_kill();
void sentinel_setUserEnabled(bool on);
bool sentinel_isUserEnabled();
bool sentinel_isRunning();
void sentinel_loadUserPref();
void detect_setSelfApIdentity(const uint8_t mac[6], const char *ssid);

// BLE hook — called from BLE scan onResult
void detect_onBleAdv(const uint8_t *addr, int8_t rssi,
                     const uint8_t *payload, uint16_t payloadLen,
                     const char *name);

// Mesh
void detect_processMesh(const String &fromNode, const String &msg);
void detect_periodicMeshGossip();

// Unified incidents log — all detector mesh msgs from local TX + peer RX.
// Persisted to /incidents.jsonl on SD + small in-RAM ring (200 entries).
void detect_logIncident(const String &raw, const char *src);
String detect_getIncidentsJson(size_t maxEntries);
void detect_clearIncidents();

// Quorum
void quorum_addReport(const String &type, const String &key,
                      const String &fromNode, int8_t rssi);
size_t quorum_currentConfirmingNodes(const String &type, const String &key);
void quorum_setRequired(const String &type, uint8_t n);
uint8_t quorum_getRequired(const String &type);

// RID claim validator (called by drone_detector when ODID location received)
void detect_recordRidClaim(const char *uavId, double lat, double lon, float alt, int8_t rssi);
String detect_getRidClaimsJson();

// Bloom gossip
void detect_addLocalBaseline(const uint8_t *mac, uint32_t ieHash);
bool detect_neighborKnows(const uint8_t *mac, uint32_t ieHash);
String detect_getBloomStatsJson();

// OUI category
OuiCategory ouiLookup(const uint8_t *mac);
const char* ouiCategoryName(OuiCategory c);
bool loadOuiTable();  // from LittleFS /oui_cat.bin if present

// BLE tracker watchlist
String detect_getBleTrackerJson();
void detect_clearBleTracker();

// Recon score
String detect_getReconJson();
void detect_clearRecon();
void recon_updateFromProbeSession(const char *identityId, uint8_t addToScore, const char *reason);

// =============================================================================
// Feature 12: Inter-node mesh ping (PPS-disciplined link-quality)
// =============================================================================
// NOTE: transport is mesh-Serial1 (Meshtastic), not direct ESP-NOW. RTT is
// dominated by transport latency, not RF time-of-flight. est_dist_m is NOT
// a real distance; kept as -1 sentinel. Use for link health + jitter only.
struct TofPeer {
    char nodeId[16];
    uint64_t lastRttUs;
    uint64_t bestRttUs;
    uint64_t avgRttUs;
    uint32_t samples;
    uint32_t lastSeen;
    int8_t estDistanceM;
};

void   tof_ping(const char *targetNode);
void   tof_broadcastPing();
void   tof_processPing(const String &fromNode, uint32_t seq, uint64_t theirTxUs);
void   tof_processPong(const String &fromNode, uint32_t seqId, uint64_t origTxEcho, uint64_t theirRxUs);
String tof_getPeersJson();
void   tof_clear();
size_t tof_peerCount();

// =============================================================================
// Feature 10/11: TSF clock-skew physical-layer AP fingerprint
// =============================================================================
// Every AP's beacon TSF advances at crystal-PPM-offset rate. Track per-BSSID
// skew: expected_delta = beacon_interval * 1024 us; actual_delta = tsf - prev.
// PPM = (actual - expected) / expected * 1e6. Running average = hw fingerprint.
// Spoofed evil-twin has different PPM than legit AP even if all IEs/SSID match.

struct TsfSkewEntry {
    uint8_t bssid[6];
    char ssid[33];
    float ppmEstimate;
    int32_t lastSkewUs;
    uint32_t samples;
    uint32_t firstSeen;
    uint32_t lastSeen;
};

String tsf_getSkewJson();
void   tsf_clear();
size_t tsf_count();

// =============================================================================
// Feature 9: Reactive KARMA probe-bait
// =============================================================================
// Track APs emitting probe-responses for >N distinct SSIDs in a window (KARMA
// candidate). Then emit honey probe-requests with deterministic markers; any
// probe-response echoing the marker confirms KARMA + identifies the rogue AP.

struct KarmaCandidate {
    uint8_t bssid[6];
    uint8_t distinctSsids;
    uint32_t firstSseen;
    uint32_t lastSeen;
    char lastSsid[33];
    bool baitEmitted;
    bool confirmed;
};

void   karma_init();
void   karma_setEnabled(bool on);
bool   karma_isEnabled();
void   karma_observeProbeResp(const uint8_t *bssid, const char *ssid, int8_t rssi);
bool   karma_checkBaitMatch(const char *ssid, const uint8_t *bssid, int8_t rssi);
String karma_getJson();
void   karma_clear();
size_t karma_candidateCount();
size_t karma_confirmedCount();

// =============================================================================
// Feature 7: Pwnagotchi swarm detection (verified addr2 = DE:AD:BE:EF:DE:AD)
// =============================================================================
struct PwnagotchiSighting {
    uint8_t bssid[6];
    int8_t lastRssi;
    int8_t bestRssi;
    uint16_t observations;
    uint32_t firstSeen;
    uint32_t lastSeen;
    char snippet[64];
};

String pwnagotchi_getJson();
void   pwnagotchi_clear();
size_t pwnagotchi_count();

// =============================================================================
// Feature 6: Attacker reverse-trilateration
// =============================================================================
// On confirmed attack signature (PMKID burst, SAE DoS, deauth flood, KRACK)
// auto-kick existing triangulation infra against the offender's MAC.
// Cooldown per source MAC. Mesh-broadcast hunt request so all nodes participate.

void attacker_kick(const uint8_t *mac, const char *attackType);
String attacker_getActiveHuntsJson();
void   attacker_clearHunts();
size_t attacker_huntCount();
void   attacker_setCooldown(uint32_t ms);

// =============================================================================
// Feature 5: Distributed 4-way handshake reconstruction + KRACK detect
// =============================================================================
// Each node captures M1/M2/M3/M4 from EAPOL-Key frames. Mesh broadcasts each
// (BSSID, STA, msg_num, replay_counter, rssi, node). Coordinator stitches into
// per-(BSSID,STA) reconstruction. Repeated M3 with same replay-counter from one
// BSSID/STA pair = KRACK CVE-2017-13077 PTK reinstallation signature.

struct HandshakeFragment {
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t msgNum;        // 1, 2, 3, 4
    uint64_t replayCtr;
    int8_t rssi;
    uint32_t ts;
    char nodeId[16];
};

struct HandshakeReconstruction {
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t seenMask;      // bit 0..3 = M1..M4 seen
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint8_t krackEvents;
    std::vector<HandshakeFragment> fragments;
};

String hshk_getReconJson();
void   hshk_clear();
size_t hshk_count();
uint32_t hshk_krackEvents();

// =============================================================================
// Feature 4: AirTag owner-presence inference + battery decode
// =============================================================================
// Apple Find My adv: FF 4C 00 12 19 [status] ...
// status bit 2 = Maintained (owner connected within last ~15 min)
// status bits 6-7 = battery level (00 full, 01 medium, 10 low, 11 critical)
//                   only meaningful when Maintained set
//
// We decode per-adv and aggregate: owner-present rate + battery + chain to
// tracker rotation chain id from Feature 3.

struct AirTagPresence {
    uint8_t addr[6];
    uint8_t lastStatusByte;
    uint16_t observations;
    uint16_t maintainedCount;
    uint8_t batteryLastSeen;
    int8_t lastRssi;
    uint32_t firstSeen;
    uint32_t lastSeen;
    bool isFindMy;
};

String airtag_getPresenceJson();
void   airtag_clear();
size_t airtag_count();

// =============================================================================
// Feature 3: BLE tracker rotation un-linking
// =============================================================================
// Trackers rotate identifiers: Tile/SmartTag every ~15 min, AirTag every ~24h.
// When one disappears and a new tracker of same vendor class appears at similar
// RSSI within a rotation window, stitch them into a persistent chain.

struct TrackerChain {
    uint32_t chainId;
    char vendor[16];
    int8_t avgRssi;
    uint8_t linkCount;
    uint32_t firstSeen;
    uint32_t lastSeen;
    struct Link {
        uint8_t addr[6];
        int8_t rssi;
        uint32_t startTs;
        uint32_t endTs;
    };
    std::vector<Link> links;
};

String tracker_getChainsJson();
void tracker_clearChains();
size_t tracker_chainCount();

// =============================================================================
// Feature 2: Probe-graph identity correlator (mesh-wide)
// =============================================================================
// Each node already de-randomizes via IE fingerprint + IE order + chan-sequence
// (randomization.cpp). New: broadcast a deterministic hash of those over mesh.
// Other nodes that derive the SAME hash for any of their tracked identities
// link the two — same device seen by N nodes => meta-identity with motion path.

struct ProbeGraphIdentity {
    uint32_t hash;
    char localTrackId[10];
    int8_t bestRssi;
    uint8_t sightingCount;
    uint32_t firstSeen;
    uint32_t lastSeen;
    struct NodeSeen {
        String nodeId;
        int8_t rssi;
        uint32_t ts;
    };
    std::vector<NodeSeen> nodes;
};

void pg_init();
uint32_t pg_computeHashFromBytes(const uint8_t *ieFp12, const uint8_t *ieOrderBytes,
                                 uint8_t ieOrderLen, const uint8_t *chanSeq, uint8_t chanSeqLen);
void pg_announceLocalIdentity(uint32_t hash, const char *localTrackId, int8_t rssi);
String pg_getGraphJson();
void pg_clear();
size_t pg_size();

// =============================================================================
// Feature 1+8: CSI Presence / Motion / RF Fingerprint
// =============================================================================
// ESP32-S3 exposes per-packet Channel State Information via esp_wifi_set_csi_rx_cb.
// We capture amplitude per subcarrier, compute rolling variance, detect motion
// when variance crosses threshold. Per-source-MAC amplitude profile = radio
// physical-layer fingerprint surviving MAC randomization.

struct CsiSnapshot {
    uint8_t srcMac[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t bandwidth;       // 0=20MHz, 1=40MHz
    uint8_t firstWord;       // L-LTF / HT-LTF marker
    uint8_t numSubcarriers;  // typically 52 (20MHz) or 114 (40MHz)
    int16_t amp[64];         // amplitude proxy (sqrt(I^2+Q^2)) — clipped to 64 subcarriers
    uint32_t ts;
};

struct CsiMotionEvent {
    uint8_t srcMac[6];
    uint16_t varianceQ8;     // running variance in Q8 fixed-point
    int8_t rssi;
    uint8_t channel;
    uint32_t ts;
    char zone[8];            // "near" / "mid" / "far" by RSSI bucket
};

struct CsiFingerprint {
    uint8_t srcMac[6];
    uint16_t profileHash;
    uint32_t observations;
    int8_t avgRssi;
    uint32_t firstSeen;
    uint32_t lastSeen;
};

void csi_init();
void csi_enable(bool on);
bool csi_isEnabled();
String csi_getMotionJsonl();
String csi_getFingerprintJson();
void csi_clear();
String detect_getHealthJson();
String detect_getConfigJson();
bool   detect_setConfigFromJson(const String &body);
void   detect_persistTunables();
uint32_t detect_droppedWifi();
uint32_t detect_droppedBle();
uint32_t detect_droppedCsi();
uint32_t detect_meshRateGated();
void csi_setMotionThreshold(uint16_t varQ8);
uint16_t csi_getMotionThreshold();
uint32_t csi_packetsObserved();
uint32_t csi_motionEvents();

// PPS (GPS pulse-per-second) time discipline
void initializeGpsPps(int gpio);
uint64_t getDisciplinedMicros();   // sub-µs epoch if PPS locked; else esp_timer_get_time + boot offset
bool ppsLocked();
uint32_t ppsLastEdgeMicros();

// Channel partition (coordinator-side)
void detect_assignChannelPartition();
String detect_getChannelAssignmentJson();
std::vector<uint8_t> detect_getMyAssignedChannels();
void detect_setMyAssignedChannels(const String &csv);

// API JSON getters for /api/* endpoints
String detect_getPmkidJsonl();
String detect_getEvilTwinJsonl();
String detect_getSsidConfusionJsonl();
String detect_getSaeDosJsonl();
String detect_getOweAbuseJsonl();
String detect_getFragAttackJsonl();
String detect_getBleMalformedJsonl();
String detect_getQuorumStatusJson();
void   detect_clearAll();

// External queues (filled from ISR)
extern QueueHandle_t detectFrameQueue;

// Tunables (config-exposed)
extern std::atomic<uint16_t> pmkid_burst_window_ms;
extern std::atomic<uint8_t>  pmkid_burst_min_bssids;
extern std::atomic<uint16_t> sae_window_ms;
extern std::atomic<uint8_t>  sae_unmatched_threshold;
extern std::atomic<uint16_t> beacon_int_drift_permil; // permil drift before alert (default 50 = 5%)
extern std::atomic<uint32_t> tracker_follow_window_ms;
extern std::atomic<uint32_t> tracker_follow_gap_ms;
extern std::atomic<uint8_t>  tracker_follow_min_sightings;
