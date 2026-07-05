#pragma once
// Shared internals for the ah_detect translation units (detect.cpp + detect_*.cpp).
// Small MAC helpers are inline here; stateful helpers are declared and defined once
// in detect.cpp.
#include "detect.h"

namespace ah_detect {

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

// Defined once in detect.cpp; shared across detect_*.cpp.
bool meshRateGate(const String &type, uint32_t minIntervalMs);

// ---- Types shared across the ah_detect TUs ----
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
    uint8_t  chanA;            // two most-recent distinct channels this BSSID
    uint8_t  chanB;            // beaconed on — both live => evil twin (2 radios)
    uint32_t chanAMs;
    uint32_t chanBMs;
    uint32_t lastMultichEmitMs;
};

struct TofPendingPing {
    uint32_t seqId;
    uint64_t txUs;
    char target[16];
};

struct AttackerHunt {
    uint8_t mac[6];
    char attackType[16];
    uint32_t startedAt;
    uint32_t lastKick;
};

struct AirTagReplayEntry {
    uint64_t firstAddr{};
    uint32_t firstSeenMs{};
    PsramSet<uint64_t> seenAddrs;
    bool alerted{};
    bool persisted{};  // already on SD — skip re-write
};

struct FollowerTrack {
    uint32_t identityHash{};
    uint32_t firstSeen{};
    uint32_t lastSeen{};
    uint16_t observations{};
    uint16_t ownerAbsentCount{};
    PsramSet<uint32_t> clusters;   // FNV(nodeId) set — local + mesh peers
    bool alerted{};
};
constexpr size_t MAX_FOLLOWERS = 64;

struct VanishedTracker {
    uint8_t addr[6];
    char vendor[16];
    int8_t lastRssi;
    uint32_t vanishedAt;
    uint32_t chainId;
};

// ---- Core globals defined in detect.cpp ----
extern std::recursive_mutex g_mtx;
extern PsramMap<uint64_t, ApBaseline> g_apBaseline;
extern std::atomic<bool> g_karmaEnabled;
extern std::atomic<bool> g_meshPwna;
extern std::atomic<bool> g_attackerTrilatEnabled;
extern std::atomic<bool> g_meshAttackerHunt;
extern std::atomic<bool> g_meshTracker;
extern PsramMap<uint64_t, BleTrackerSighting> g_bleTrackers;
extern PsramMap<String, ReconAlert> g_recon;

// ---- Feature globals defined in detect_features.cpp ----
extern std::atomic<uint32_t> g_huntCooldown;
extern std::atomic<uint32_t> g_krackEvents;
extern PsramMap<uint64_t, AirTagPresence> g_airtag;
extern PsramMap<uint32_t, AirTagReplayEntry> g_airtagReplay;
extern PsramMap<uint32_t, FollowerTrack> g_followers;
extern std::atomic<uint32_t> cs_copresent_ms;
extern std::atomic<uint32_t> cs_persist_ms;
extern std::atomic<uint32_t> cs_min_clusters;
extern std::atomic<uint32_t> cs_rotation_rate;
extern std::atomic<uint32_t> cs_owner_absent_pct_x100;
void followerAddCluster(uint32_t identityHash, const String &nodeId, uint32_t now);
extern std::atomic<bool> g_csEnabled;
extern std::atomic<uint32_t> g_csSpamAlerts;
extern std::atomic<uint32_t> g_csExfilAlerts;
void rotationAnomaly(const uint8_t *payload, uint16_t len, uint64_t mac, int8_t rssi, uint32_t now);
String cs_getResultsJson();
extern PsramVec<String> g_baitSsids;
extern PsramMap<uint32_t, TrackerChain> g_chains;
extern PsramMap<uint64_t, HandshakeReconstruction> g_hshk;
extern PsramMap<uint64_t, AttackerHunt> g_hunts;
extern PsramMap<uint64_t, KarmaCandidate> g_karma;
extern PsramMap<uint64_t, PsramSet<String>> g_karmaSsids;
extern PsramMap<uint32_t, ProbeGraphIdentity> g_pgGraph;
extern PsramMap<uint64_t, PwnagotchiSighting> g_pwna;
extern PsramMap<String, TofPeer> g_tofPeers;
extern PsramVec<TofPendingPing> g_tofPending;
extern PsramVec<VanishedTracker> g_vanished;

// Internal feature helpers also called from detect.cpp.
void karmaEmitBait(const uint8_t *targetBssid);
uint8_t classifyEapolMsg(uint16_t keyInfo);
void hshkRecord(const uint8_t *bssid, const uint8_t *sta, uint8_t msgNum,
                uint64_t replayCtr, int8_t rssi, const char *nodeId, uint32_t now);
void airtagProcess(const uint8_t *addr, int8_t rssi, const uint8_t *payload, uint16_t len);
void pwnagotchiObserve(const uint8_t *bssid, int8_t rssi, const uint8_t *ie, uint16_t ieLen);
bool isPwnagotchiBeacon(const uint8_t *frame, uint16_t len);
void trackerSweepVanished(uint32_t now);
uint32_t trackerTryLinkRotation(const uint8_t *addr, const char *vendor, int8_t rssi, uint32_t now);
void persistSnapshot();
void loadSnapshot();

// ---- Feature functions defined in detect_features.cpp ----
void tof_ping(const char *targetNode);
void tof_broadcastPing();
void tof_processPing(const String &fromNode, uint32_t seq, uint64_t theirTxUs);
void tof_processPong(const String &fromNode, uint32_t seqHint, uint64_t origTxEcho, uint64_t theirRxUs);
String tof_getPeersJson();
void tof_clear();
size_t tof_peerCount();
String tsf_getSkewJson();
void tsf_clear();
size_t tsf_count();
void karma_setEnabled(bool on);
bool karma_isEnabled();
void karma_init();
String karma_getJson();
void karma_clear();
size_t karma_candidateCount();
size_t karma_confirmedCount();
String pwnagotchi_getJson();
void pwnagotchi_clear();
size_t pwnagotchi_count();
void attacker_setCooldown(uint32_t ms);
String attacker_getActiveHuntsJson();
void attacker_clearHunts();
size_t attacker_huntCount();
String hshk_getReconJson();
void hshk_clear();
size_t hshk_count();
uint32_t hshk_krackEvents();
String airtag_getPresenceJson();
void airtag_clear();
size_t airtag_count();
String tracker_getChainsJson();
void tracker_clearChains();
size_t tracker_chainCount();
void pg_announceLocalIdentity(uint32_t hash, const char *localTrackId, int8_t rssi);
void pg_clear();
size_t pg_size();
String pg_getGraphJson();
void pg_init();
uint32_t pg_computeHashFromBytes(const uint8_t *ieFp12, const uint8_t *ieOrderBytes,
                                 uint8_t ieOrderLen, const uint8_t *chanSeq, uint8_t chanSeqLen);
void detect_logIncident(const String &raw, const char *src);
String detect_getIncidentsJson(size_t maxEntries);
void detect_clearIncidents();

} // namespace ah_detect
