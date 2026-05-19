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
        PROBE_RESP = 5    // probe response for SSID confusion
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
void detect_onWifiFrame(const uint8_t *payload, uint16_t len, int8_t rssi, uint8_t channel);

// BLE hook — called from BLE scan onResult
void detect_onBleAdv(const uint8_t *addr, int8_t rssi,
                     const uint8_t *payload, uint16_t payloadLen,
                     const char *name);

// Mesh
void detect_processMesh(const String &fromNode, const String &msg);
void detect_periodicMeshGossip();

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
