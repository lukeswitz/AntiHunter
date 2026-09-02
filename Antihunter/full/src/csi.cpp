#include "csi.h"
#include "network.h"
#include "scanner.h"
#include "hardware.h"
#include "detect.h"
#include "main.h"

extern "C" {
extern volatile uint32_t g_memcpyBadLenRejects;
extern volatile uint32_t g_memcpyBadLenLast;
}

#include <WiFi.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <math.h>
#include <string.h>
#include <mutex>

extern Preferences prefs;
extern String macFmt6(const uint8_t *m);
extern std::atomic<bool> scanning;
extern std::atomic<bool> stopRequested;
extern TaskHandle_t workerTaskHandle;
extern std::vector<uint8_t> CHANNELS;

std::atomic<bool> csiRawDump{false};
std::atomic<bool> csiTelemetry{false};
std::atomic<bool> csiAutoTrigger{false};
std::atomic<uint8_t> csiPinnedChannel{0};
std::atomic<uint32_t> csiThresholdMilli{100};
std::atomic<uint64_t> csiExcludeMac{0};
std::atomic<uint32_t> csiHoldMs{5000};
std::atomic<uint32_t> csiConsecNeeded{3};

static const uint32_t CSI_LINK_STALE_MS = 20000;
static const uint32_t CSI_SURVEY_DWELL_MS = 2500;
static const uint32_t CSI_BLIND_REHOP_MS = 180000;
static const uint32_t CSI_REHOP_COOLDOWN_MS = 600000;
static const uint32_t CSI_REHOP_DWELL_MS = 150;
static const uint32_t CSI_SOLICIT_FLOOR = 15;
static const uint32_t CSI_CAL_MS = 20000;
static const float CSI_CAL_MARGIN = 1.50f;
static const float CSI_TRIG_MIN = 1.15f;
static const float CSI_TRIG_MAX = 6.0f;

static std::atomic<bool> g_surveyMode{false};
static std::atomic<uint32_t> g_surveyHits{0};
static std::atomic<uint32_t> g_surveyStrong{0};
static std::atomic<uint32_t> g_surveyTx{0};
static uint8_t g_surveyMacs[16][6];
static uint8_t g_surveyMacCount = 0;

static const uint8_t CSI_HEAT_CELLS = 120;
static const uint16_t CSI_HEAT_STEPS[] = {60, 300, 900, 1800, 3600, 7200, 21600, 43200};
static const uint8_t CSI_HEAT_NSTEPS = sizeof(CSI_HEAT_STEPS) / sizeof(CSI_HEAT_STEPS[0]);
static uint8_t g_heatStep = 0;
static uint8_t g_heat[CSI_HEAT_CELLS];
static uint8_t g_heatHot[CSI_HEAT_CELLS];
static uint8_t g_heatHotCur = 0;
static uint8_t g_heatLen = 0;
static uint16_t g_heatSec = 60;
static uint32_t g_heatSum = 0;
static uint16_t g_heatCurSec = 0;

static void csiHeatPush(float act, bool alerting) {
    uint16_t q = (act > 0.0f) ? (uint16_t)(act * 25.0f) : 0;
    if (q > 255) q = 255;
    if (q > g_heatSum) g_heatSum = q;
    if (alerting) g_heatHotCur = 1;
    g_heatCurSec++;
    if (g_heatCurSec < g_heatSec) return;

    const uint8_t cell = (uint8_t)g_heatSum;
    const uint8_t hot = g_heatHotCur;
    g_heatSum = 0;
    g_heatHotCur = 0;
    g_heatCurSec = 0;

    if (g_heatLen < CSI_HEAT_CELLS) {
        g_heatHot[g_heatLen] = hot;
        g_heat[g_heatLen++] = cell;
    } else {
        uint16_t factor = 2;
        if (g_heatStep + 1 < CSI_HEAT_NSTEPS) {
            factor = CSI_HEAT_STEPS[g_heatStep + 1] / CSI_HEAT_STEPS[g_heatStep];
            g_heatStep++;
            g_heatSec = CSI_HEAT_STEPS[g_heatStep];
        } else {
            g_heatSec *= 2;
        }
        uint8_t out = 0;
        for (uint8_t i = 0; i < CSI_HEAT_CELLS; i += factor) {
            uint8_t mx = 0, mhot = 0;
            for (uint8_t k = i; k < i + factor && k < CSI_HEAT_CELLS; k++) {
                if (g_heat[k] > mx) mx = g_heat[k];
                mhot |= g_heatHot[k];
            }
            g_heat[out] = mx;
            g_heatHot[out] = mhot;
            out++;
        }
        g_heatLen = out;
        g_heatHot[g_heatLen] = hot;
        g_heat[g_heatLen++] = cell;
    }
}

static const uint16_t CSI_DRAIN_BURST = 64;
static const uint32_t CSI_MOTION_MIN_MS = 300;
static const uint8_t CSI_RADIO_KEY_LEN = 5;
static const uint32_t CSI_ELEV_CAP_MS = 6000;
static const uint32_t CSI_ELEV_DECAY = 2;
static const uint32_t CSI_AREA_DEBOUNCE_MS = 15000;
static bool g_areaMotion = false;
static bool g_areaCand = false;
static uint32_t g_areaCandSince = 0;
static uint32_t g_areaSinceMs = 0;
static uint32_t g_areaLastMotionMs = 0;

static const uint8_t CSI_EPISODES = 24;
struct CsiEpisode {
    char at[24];
    uint32_t dwellSec;
    float peak;
    bool open;
};
static CsiEpisode g_eps[CSI_EPISODES];
static uint8_t g_epCount = 0;
static uint8_t g_epHead = 0;
static uint32_t g_epTotal = 0;
static float g_epPeak = 0.0f;

static void csiEpisodesReset() {
    for (uint8_t i = 0; i < CSI_EPISODES; i++) g_eps[i] = CsiEpisode{};
    g_epCount = 0;
    g_epHead = 0;
    g_epTotal = 0;
    g_epPeak = 0.0f;
}

static void csiEpisodeOpen(const String &at) {
    CsiEpisode &e = g_eps[g_epHead];
    strncpy(e.at, at.c_str(), sizeof(e.at) - 1);
    e.at[sizeof(e.at) - 1] = '\0';
    e.dwellSec = 0;
    e.peak = 0.0f;
    e.open = true;
    g_epHead = (uint8_t)((g_epHead + 1) % CSI_EPISODES);
    if (g_epCount < CSI_EPISODES) g_epCount++;
    g_epTotal++;
    g_epPeak = 0.0f;
}

static void csiEpisodeClose(uint32_t dwellSec) {
    if (g_epCount == 0) return;
    CsiEpisode &e = g_eps[(uint8_t)((g_epHead + CSI_EPISODES - 1) % CSI_EPISODES)];
    e.dwellSec = dwellSec;
    e.peak = g_epPeak;
    e.open = false;
}

static bool g_calActive = false;
static float g_calSum = 0.0f;
static uint32_t g_calSamples = 0;
static float g_calTrigger = 0.0f;

struct CsiEvent {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t ch;
    uint32_t ts;
    int8_t buf[CSI_BUF_BYTES];
};

struct CsiLink {
    uint8_t mac[6];
    bool used;
    uint32_t packets;
    uint32_t firstMs;
    uint32_t lastMs;
    int8_t rssi;
    CsiScorer sc;
    float peakScore;
    uint8_t consec;
    bool motion;
    uint32_t lastAboveMs;
    uint32_t lastTickMs;
    uint32_t elevMs;
    uint32_t motionStartMs;
    uint32_t events;
};

static CsiLink g_links[CSI_MAX_LINKS];
static std::mutex g_csiMutex;
static QueueHandle_t csiQueue = nullptr;

static std::atomic<uint32_t> g_csiSeen{0};
static std::atomic<uint32_t> g_csiDropped{0};
static std::atomic<uint32_t> g_csiRejected{0};
static std::atomic<uint32_t> g_rejFcs{0};
static std::atomic<uint32_t> g_rejWidth{0};
static std::atomic<uint32_t> g_rejShort{0};
static std::atomic<uint32_t> g_rejMac{0};
static std::atomic<uint32_t> g_csiMotionEvents{0};
static uint32_t g_csiStartMs = 0;
static uint32_t g_csiEndMs = 0;
static uint8_t g_csiActiveChannel = 0;

static std::atomic<uint32_t> g_promFrames{0};

extern std::atomic<uint32_t> framesSeen;

static void csi_prom_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    g_promFrames.fetch_add(1);
    const wifi_promiscuous_pkt_t *ppkt = static_cast<wifi_promiscuous_pkt_t *>(buf);
    if (ppkt && ppkt->rx_ctrl.sig_len >= 24) framesSeen.fetch_add(1, std::memory_order_relaxed);
}

// cppcheck-suppress constParameterCallback // wifi_csi_cb_t signature is fixed by esp_wifi_set_csi_rx_cb
static void csi_rx_cb(void *ctx, wifi_csi_info_t *info) {
    if (!info || !info->buf || !csiQueue) return;

    const wifi_pkt_rx_ctrl_t &rx = info->rx_ctrl;
    if (rx.rx_state != 0) {
        g_csiRejected.fetch_add(1);
        g_rejFcs.fetch_add(1);
        return;
    }
#if CONFIG_SOC_WIFI_HE_SUPPORT
    if (rx.second != 0 ||
        (rx.cur_bb_format != RX_BB_FORMAT_11G && rx.cur_bb_format != RX_BB_FORMAT_HT)) {
        g_csiRejected.fetch_add(1);
        g_rejWidth.fetch_add(1);
        return;
    }
#else
    if (rx.cwb != 0 || rx.secondary_channel != 0) {
        g_csiRejected.fetch_add(1);
        g_rejWidth.fetch_add(1);
        return;
    }
#endif
    if (info->len < CSI_BUF_BYTES) {
        g_csiRejected.fetch_add(1);
        g_rejShort.fetch_add(1);
        return;
    }

    const uint8_t *m = info->mac;
    if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0) {
        g_csiRejected.fetch_add(1);
        g_rejMac.fetch_add(1);
        return;
    }

    if (g_surveyMode.load()) {
        g_surveyHits.fetch_add(1);
        if (rx.rssi >= CSI_SURVEY_MIN_RSSI) g_surveyStrong.fetch_add(1);
        bool known = false;
        for (uint8_t i = 0; i < g_surveyMacCount; i++) {
            if (memcmp(g_surveyMacs[i], m, 6) == 0) { known = true; break; }
        }
        if (!known && g_surveyMacCount < 16) {
            memcpy(g_surveyMacs[g_surveyMacCount], m, 6);
            g_surveyMacCount++;
            g_surveyTx.fetch_add(1);
        }
        return;
    }

    CsiEvent ev;
    memcpy(ev.mac, m, 6);
    ev.rssi = rx.rssi;
    ev.ch = rx.channel;
    ev.ts = rx.timestamp;
    memcpy(ev.buf, info->buf, CSI_BUF_BYTES);

    g_csiSeen.fetch_add(1);
    if (xQueueSend(csiQueue, &ev, 0) != pdTRUE) g_csiDropped.fetch_add(1);
}

static uint8_t csiSurveyPickChannel(uint32_t dwellMs) {
    if (WiFi.softAPgetStationNum() > 0) {
        const uint8_t home = apHomeChannel();
        Serial.printf("[CSI] a client is on the AP - skipping the survey, staying on ch%u\n", home);
        return home;
    }

    std::vector<uint8_t> chans;
    for (uint8_t c : CHANNELS) {
        if (c >= 1 && c <= 14) chans.push_back(c);
    }
    if (chans.empty()) chans = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    Serial.printf("[CSI] Surveying %u channels for traffic (%ums each)...\n",
                  (unsigned)chans.size(), dwellMs);

    uint8_t bestTotalCh = chans[0], bestStrongCh = chans[0];
    uint32_t bestTotal = 0, bestStrong = 0, bestStrongTx = 0, bestStrongHits = 0, bestChScore = 0;

    for (uint8_t ch : chans) {
        if (stopRequested) break;

        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(30));

        g_surveyHits.store(0);
        g_surveyStrong.store(0);
        g_surveyTx.store(0);
        g_surveyMacCount = 0;
        g_surveyMode.store(true);
        vTaskDelay(pdMS_TO_TICKS(dwellMs));
        g_surveyMode.store(false);

        const uint32_t hits = g_surveyHits.load();
        const uint32_t strong = g_surveyStrong.load();
        const uint32_t tx = g_surveyTx.load();
        const float rate = (float)hits * 1000.0f / (float)dwellMs;
        Serial.printf("[CSI]   ch%-3u %5u records  %5.1f/s  %u transmitters  %u strong\n",
                      ch, hits, rate, tx, strong);

        if (hits > bestTotal) { bestTotal = hits; bestTotalCh = ch; }
        const uint32_t chScore = hits * strong;
        if (chScore > bestChScore) {
            bestChScore = chScore; bestStrongHits = hits; bestStrong = strong;
            bestStrongTx = tx; bestStrongCh = ch;
        }
    }

    if (bestTotal == 0) {
        Serial.println("[CSI] No CSI-eligible traffic on any surveyed channel");
        return 0;
    }

    if (bestStrong == 0) {
        Serial.printf("[CSI] WARNING: no transmitter stronger than %ddBm on any channel - "
                      "falling back to ch%u (%u records). Detection will report BLIND.\n",
                      (int)CSI_SURVEY_MIN_RSSI, bestTotalCh, bestTotal);
        return bestTotalCh;
    }

    Serial.printf("[CSI] Selected ch%u (%.1f/s, %u strong, %u transmitters)\n",
                  bestStrongCh,
                  (float)bestStrongHits * 1000.0f / (float)dwellMs, bestStrong, bestStrongTx);
    return bestStrongCh;
}

static bool csiChannelAllowed(uint8_t ch) {
    if (ch < 1 || ch > 14) return false;
    if (CHANNELS.empty()) return true;
    for (uint8_t c : CHANNELS) {
        if (c == ch) return true;
    }
    return false;
}

static uint8_t csiRehopPickChannel() {
    wifi_scan_config_t sc = {};
    sc.show_hidden = true;
    sc.scan_type = WIFI_SCAN_TYPE_PASSIVE;
    sc.scan_time.passive = CSI_REHOP_DWELL_MS;
    sc.home_chan_dwell_time = 30;

    g_surveyMode.store(true);
    const esp_err_t r = esp_wifi_scan_start(&sc, true);
    g_surveyMode.store(false);
    if (r != ESP_OK) {
        Serial.printf("[CSI] rehop scan failed: %s\n", esp_err_to_name(r));
        return 0;
    }

    wifi_ap_record_t rec;
    uint8_t bestCh = 0;
    int bestRssi = -127;
    uint16_t seen = 0;
    while (esp_wifi_scan_get_ap_record(&rec) == ESP_OK) {
        seen++;
        if (!csiChannelAllowed(rec.primary)) continue;
        if (rec.rssi > bestRssi) {
            bestRssi = rec.rssi;
            bestCh = rec.primary;
        }
    }
    esp_wifi_clear_ap_list();

    if (bestCh == 0 || bestRssi < CSI_SURVEY_MIN_RSSI) {
        Serial.printf("[CSI] rehop: %u APs seen, none stronger than %ddBm - staying on ch%u\n",
                      seen, (int)CSI_SURVEY_MIN_RSSI, g_csiActiveChannel);
        return 0;
    }
    Serial.printf("[CSI] rehop: best ch%u at %ddBm (%u APs seen)\n", bestCh, bestRssi, seen);
    return bestCh;
}

static const uint8_t kCsiProbeHdr[24] = {
    0x40, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00
};
static const uint8_t kCsiProbeRates[10] = {
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24
};

static void csiSolicit() {
    uint8_t frame[24 + 2 + sizeof(kCsiProbeRates)];
    memcpy(frame, kCsiProbeHdr, 24);
    frame[24] = 0x00;
    frame[25] = 0x00;
    memcpy(frame + 26, kCsiProbeRates, sizeof(kCsiProbeRates));
    const size_t total = 26 + sizeof(kCsiProbeRates);

    wifi_mode_t wmode = WIFI_MODE_NULL;
    wifi_interface_t txif =
        (esp_wifi_get_mode(&wmode) == ESP_OK && wmode == WIFI_MODE_STA) ? WIFI_IF_STA : WIFI_IF_AP;
    esp_wifi_80211_tx(txif, frame, total, true);
}

static void csiLinkReset(CsiLink &l) {
    memset(l.mac, 0, sizeof(l.mac));
    l.used = false;
    l.packets = 0;
    l.firstMs = 0;
    l.lastMs = 0;
    l.rssi = 0;
    l.sc.reset();
    l.peakScore = 0.0f;
    l.consec = 0;
    l.motion = false;
    l.lastAboveMs = 0;
    l.lastTickMs = 0;
    l.elevMs = 0;
    l.motionStartMs = 0;
    l.events = 0;
}

bool csiClearResults() {
    const bool wasActive = (csiQueue != nullptr);
    {
        std::lock_guard<std::mutex> lock(g_csiMutex);
        for (int i = 0; i < CSI_MAX_LINKS; i++) csiLinkReset(g_links[i]);
        g_heatLen = 0;
        g_heatSec = 60;
        g_heatStep = 0;
        g_heatSum = 0;
        g_heatHotCur = 0;
        g_heatCurSec = 0;
        g_areaMotion = false;
        g_areaCand = false;
        g_areaCandSince = 0;
        g_areaLastMotionMs = 0;
        csiEpisodesReset();
    }
    g_csiMotionEvents.store(0);
    g_csiSeen.store(0);
    g_csiRejected.store(0);
    g_csiDropped.store(0);
    g_rejFcs.store(0);
    g_rejWidth.store(0);
    g_rejShort.store(0);
    g_rejMac.store(0);
    g_csiStartMs = millis();
    Serial.println("[CSI] Results cleared - links, heat and counters reset");
    return wasActive;
}

static bool csiLinkUsable(const CsiLink &l) {
    if (!l.used || l.packets < CSI_LINK_MIN_PKTS) return false;
    const uint64_t ex = csiExcludeMac.load();
    if (ex != 0) {
        uint64_t m = 0;
        for (int i = 0; i < 6; i++) m = (m << 8) | l.mac[i];
        if ((m >> 8) == (ex >> 8)) return false;
    }
    return l.rssi >= CSI_LINK_MIN_RSSI;
}

static float csiTriggerRatio(float acf, float vote, float eta) {
    if (vote < CSI_VOTE_FRAC) return 0.0f;
    return (eta > 0.0f) ? (acf / eta) : 0.0f;
}

static uint8_t csiUsableCount() {
    uint8_t n = 0;
    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        if (csiLinkUsable(g_links[i])) n++;
    }
    return n;
}

static CsiLink *csiFindLink(const uint8_t *mac) {
    CsiLink *freeSlot = nullptr;
    CsiLink *oldest = nullptr;

    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        CsiLink &l = g_links[i];
        if (l.used && memcmp(l.mac, mac, CSI_RADIO_KEY_LEN) == 0) return &l;
        if (!l.used) {
            if (!freeSlot) freeSlot = &l;
            continue;
        }
        if (!oldest || (int32_t)(l.lastMs - oldest->lastMs) < 0) oldest = &l;
    }

    CsiLink *slot = freeSlot;
    if (!slot) {
        if (!oldest) return nullptr;
        if (oldest->motion) return nullptr;
        if (oldest->packets >= CSI_LINK_MIN_PKTS) return nullptr;
        slot = oldest;
    }

    csiLinkReset(*slot);
    memcpy(slot->mac, mac, 6);
    slot->used = true;
    slot->firstMs = millis();
    slot->lastMs = slot->firstMs;
    return slot;
}

struct CsiAlert {
    bool valid;
    bool rising;
    uint8_t mac[6];
    int8_t rssi;
    uint32_t packets;
    uint32_t dwell;
    float score;
    float mad;
    float floorMad;
};

static void csiStageAlert(CsiAlert &al, const CsiLink &l, bool rising) {
    al.valid = true;
    al.rising = rising;
    memcpy(al.mac, l.mac, 6);
    al.rssi = l.rssi;
    al.packets = l.packets;
    al.dwell = rising ? 0 : ((millis() - l.motionStartMs) / 1000);
    al.score = l.sc.score;
    al.mad = l.sc.mad;
    al.floorMad = l.sc.floorMad;
}

static void csiEmitAlert(const CsiAlert &al) {
    if (!al.valid) return;

    String mac = macFmt6(al.mac);
    String line;

    if (al.rising) {
        char scoreStr[16];
        snprintf(scoreStr, sizeof(scoreStr), "%.2f", al.score);
        line = getNodeId() + ": CSI_MOTION: " + mac +
               " S=" + String(scoreStr) +
               " R=" + String(al.rssi) +
               " CH=" + String(g_csiActiveChannel) +
               " P=" + String(al.packets);
        Serial.printf("[CSI] MOTION %s score=%.2f mad=%.4f floor=%.4f rssi=%d\n",
                      mac.c_str(), al.score, al.mad, al.floorMad, al.rssi);
    } else {
        line = getNodeId() + ": CSI_CLEAR: " + mac +
               " D=" + String(al.dwell) + "s" +
               " CH=" + String(g_csiActiveChannel);
        Serial.printf("[CSI] CLEAR %s dwell=%us\n", mac.c_str(), al.dwell);
    }

}

static void csiProcess(const CsiEvent &ev) {
    float a[CSI_NSUB];
    if (!csiAmplitudes(ev.buf, a)) return;

    if (csiRawDump.load()) {
        String row = "CSIR," + String(ev.ts) + "," + macFmt6(ev.mac) + "," +
                     String(ev.rssi) + "," + String(ev.ch) + "," + String((int)sizeof(ev.buf));
        for (int i = 0; i < (int)sizeof(ev.buf); i++) {
            row += "," + String((int)ev.buf[i]);
        }
        Serial.println(row);
    }

    CsiAlert alert = {};

    {
        std::lock_guard<std::mutex> lock(g_csiMutex);

        CsiLink *lp = csiFindLink(ev.mac);
        if (!lp) return;
        CsiLink &l = *lp;

        const uint32_t now = millis();
        l.lastMs = now;
        l.rssi = ev.rssi;
        l.packets++;

        if (!l.sc.update(a, l.motion)) return;
        if (l.sc.score > l.peakScore) l.peakScore = l.sc.score;

        if (csiTelemetry.load()) {
            Serial.printf("CSIT,%lu,%s,%.3f,%.5f,%.5f,%d\n",
                          (unsigned long)now, macFmt6(l.mac).c_str(),
                          l.sc.score, l.sc.mad, l.sc.floorMad, l.rssi);
        }

        if (g_calActive) {
            g_calSum += l.sc.score;
            g_calSamples++;
        }

        const uint32_t consecNeeded = csiConsecNeeded.load();
        const uint32_t hold = csiHoldMs.load();

        const uint32_t dt = (l.lastTickMs && now > l.lastTickMs) ? (now - l.lastTickMs) : 0;
        l.lastTickMs = now;

        const float eta = (float)csiThresholdMilli.load() / 1000.0f;
        if (l.sc.acf >= eta && l.sc.vote >= CSI_VOTE_FRAC) {
            l.lastAboveMs = now;
            if (l.consec < 255) l.consec++;
            l.elevMs += dt;
            if (l.elevMs > CSI_ELEV_CAP_MS) l.elevMs = CSI_ELEV_CAP_MS;
        } else {
            l.consec = 0;
            const uint32_t decay = dt * CSI_ELEV_DECAY;
            l.elevMs = (l.elevMs > decay) ? (l.elevMs - decay) : 0;
        }

        if (g_calActive || !l.sc.settled()) return;

        if (!csiLinkUsable(l)) return;

        const bool heldLongEnough = l.elevMs >= CSI_MOTION_MIN_MS;

        if (!l.motion && heldLongEnough && l.consec >= consecNeeded) {
            l.motion = true;
            l.motionStartMs = now;
            l.events++;
            g_csiMotionEvents.fetch_add(1);
            csiStageAlert(alert, l, true);
        } else if (l.motion && (l.sc.acf < eta || l.sc.vote < CSI_VOTE_FRAC) &&
                   (now - l.lastAboveMs) >= hold) {
            l.motion = false;
            l.consec = 0;
            l.elevMs = 0;
            csiStageAlert(alert, l, false);
        }
    }

    csiEmitAlert(alert);
}

static void csiExpireLinks() {
    const uint32_t now = millis();
    CsiAlert alerts[CSI_MAX_LINKS] = {};

    {
        std::lock_guard<std::mutex> lock(g_csiMutex);

        for (int i = 0; i < CSI_MAX_LINKS; i++) {
            CsiLink &l = g_links[i];
            if (!l.used) continue;

            const bool stale = (now - l.lastMs) >= CSI_LINK_STALE_MS;
            const bool flat = l.sc.settled() && l.sc.spread() < CSI_LINK_MIN_SPREAD;
            if (!stale && !flat) continue;

            if (flat && !stale) {
                Serial.printf("[CSI] DROP %s flat (spread %.3f over %u pkts)\n",
                              macFmt6(l.mac).c_str(), l.sc.spread(), l.packets);
            }
            if (l.motion) {
                l.motion = false;
                csiStageAlert(alerts[i], l, false);
            }
            l.used = false;
        }
    }

    for (int i = 0; i < CSI_MAX_LINKS; i++) csiEmitAlert(alerts[i]);
}

static void csiSnapshot(CsiLinkView *out, int &count) {
    const uint32_t now = millis();
    count = 0;
    std::lock_guard<std::mutex> lock(g_csiMutex);

    for (int i = 0; i < CSI_MAX_LINKS && count < CSI_MAX_LINKS; i++) {
        const CsiLink &l = g_links[i];
        if (!l.used) continue;

        CsiLinkView &v = out[count++];
        String mac = macFmt6(l.mac);
        strncpy(v.mac, mac.c_str(), sizeof(v.mac) - 1);
        v.mac[sizeof(v.mac) - 1] = '\0';
        v.packets = l.packets;
        v.ageMs = now - l.lastMs;
        v.events = l.events;
        v.rssi = l.rssi;

        const uint32_t span = (now > l.firstMs) ? (now - l.firstMs) : 1;
        v.rate = (float)l.packets * 1000.0f / (float)span;
        v.mad = l.sc.mad;
        v.floorMad = l.sc.floorMad;
        v.spread = l.sc.spread();
        v.acf = l.sc.acf;
        v.vote = l.sc.vote;
        v.score = l.sc.score;
        v.peakScore = l.peakScore;
        v.motion = l.motion;
    }
}

String getCsiResults() {
    CsiLinkView views[CSI_MAX_LINKS];
    int n = 0;
    csiSnapshot(views, n);

    const uint32_t span = (g_csiStartMs && millis() > g_csiStartMs) ? (millis() - g_csiStartMs) : 1;
    const float rate = (float)g_csiSeen.load() * 1000.0f / (float)span;

    String r = "CSI Motion Detection\n\n";
    r += "Channel: " + String(g_csiActiveChannel) + " (pinned)\n";
    {
        uint8_t usable;
        {
            std::lock_guard<std::mutex> lock(g_csiMutex);
            usable = csiUsableCount();
        }
        r += "Usable links: " + String(usable) + "\n";
        if (usable == 0) {
            r += "BLIND - no link reaches " + String((int)CSI_LINK_MIN_RSSI) + "dBm.\n"
                 "Motion cannot be detected. Move the node nearer an active AP or pick a busier channel.\n";
        }
    }
    if (g_calActive) {
        r += "Calibrating still-state trigger - alerts held until this completes\n";
    } else if (g_calTrigger > 0.0f) {
        r += "Trigger calibrated from this room: " + String(g_calTrigger, 2) + "x\n";
    }
    r += "CSI records: " + String(g_csiSeen.load()) +
         "  rate: " + String(rate, 1) + "/s\n";
    r += "Rejected (FCS/40MHz/short): " + String(g_csiRejected.load()) + "\n";
    r += "Queue drops: " + String(g_csiDropped.load()) + "\n";
    r += "Motion events: " + String(g_csiMotionEvents.load()) + "\n";
    r += "Threshold: " + String((float)csiThresholdMilli.load() / 1000.0f, 2) +
         "x  Hold: " + String(csiHoldMs.load()) + "ms\n\n";

    if (n == 0) {
        r += "No transmitters tracked yet on this channel.\n";
        r += "CSI arrives only when a frame is decoded here - pick a channel with traffic.\n";
        return r;
    }

    r += "Tracked links (one channel response per transmitter):\n";
    r += "====================================================\n\n";

    for (int i = 0; i < n; i++) {
        const CsiLinkView &v = views[i];
        r += String(v.motion ? "[MOTION] " : "[ still] ");
        r += String(v.mac);
        r += "  " + String(v.rssi) + " dBm";
        r += "  " + String(v.rate, 1) + " pkt/s";
        r += "  n=" + String(v.packets) + "\n";
        r += "          score " + String(v.score, 2) + "x";
        r += "  peak " + String(v.peakScore, 2) + "x";
        r += "  mad " + String(v.mad, 4);
        r += "  floor " + String(v.floorMad, 4);
        r += "  events " + String(v.events);
        r += "  age " + String(v.ageMs / 1000) + "s\n\n";
    }

    return r;
}

String getCsiJson() {
    CsiLinkView views[CSI_MAX_LINKS];
    int n = 0;
    csiSnapshot(views, n);

    const uint32_t span = (g_csiStartMs && millis() > g_csiStartMs) ? (millis() - g_csiStartMs) : 1;
    const float rate = (float)g_csiSeen.load() * 1000.0f / (float)span;

    String j = "{\"channel\":" + String(g_csiActiveChannel);
    uint8_t usableNow;
    {
        std::lock_guard<std::mutex> lock(g_csiMutex);
        usableNow = csiUsableCount();
    }
    j += ",\"usable\":" + String(usableNow);
    j += ",\"records\":" + String(g_csiSeen.load());
    j += ",\"rejFcs\":" + String(g_rejFcs.load());
    j += ",\"rejWidth\":" + String(g_rejWidth.load());
    j += ",\"rejShort\":" + String(g_rejShort.load());
    j += ",\"rejMac\":" + String(g_rejMac.load());
    j += ",\"rate\":" + String(rate, 2);
    j += ",\"rejected\":" + String(g_csiRejected.load());
    j += ",\"drops\":" + String(g_csiDropped.load());
    j += ",\"events\":" + String(g_csiMotionEvents.load());
    j += ",\"motion\":" + String(g_areaMotion ? "true" : "false");
    j += ",\"threshold\":" + String((float)csiThresholdMilli.load() / 1000.0f, 2);
    j += ",\"voteFrac\":" + String(CSI_VOTE_FRAC, 2);
    j += ",\"calibrated\":" + String(prefs.getBool("csiCalDone", false) ? "true" : "false");
    j += ",\"uptime\":" + String(g_csiStartMs ? ((g_csiEndMs ? g_csiEndMs : millis()) - g_csiStartMs) / 1000 : 0);
    j += ",\"sinceMotion\":" + String(g_areaLastMotionMs ? (int32_t)((millis() - g_areaLastMotionMs) / 1000) : -1);
    j += ",\"areaEvents\":" + String(g_epTotal);
    j += ",\"episodes\":[";
    for (uint8_t i = 0; i < g_epCount; i++) {
        const CsiEpisode &e = g_eps[(uint8_t)((g_epHead + CSI_EPISODES - 1 - i) % CSI_EPISODES)];
        if (i) j += ",";
        j += "{\"at\":\"" + String(e.at) + "\",\"dwell\":" + String(e.dwellSec) +
             ",\"peak\":" + String(e.peak, 2) +
             ",\"open\":" + String(e.open ? "true" : "false") + "}";
    }
    j += "]";
    j += ",\"heatSec\":" + String(g_heatSec);
    j += ",\"heat\":[";
    for (uint8_t i = 0; i < g_heatLen; i++) {
        if (i) j += ",";
        j += String(g_heat[i]);
    }
    if (g_heatCurSec > 0) {
        if (g_heatLen) j += ",";
        j += String((uint8_t)g_heatSum);
    }
    j += "]";
    j += ",\"hot\":[";
    for (uint8_t i = 0; i < g_heatLen; i++) {
        if (i) j += ",";
        j += String(g_heatHot[i]);
    }
    if (g_heatCurSec > 0) {
        if (g_heatLen) j += ",";
        j += String(g_heatHotCur);
    }
    j += "]";
    j += ",\"links\":[";

    for (int i = 0; i < n; i++) {
        const CsiLinkView &v = views[i];
        if (i) j += ",";
        j += "{\"mac\":\"" + String(v.mac) + "\"";
        j += ",\"rssi\":" + String(v.rssi);
        j += ",\"rate\":" + String(v.rate, 2);
        j += ",\"packets\":" + String(v.packets);
        j += ",\"score\":" + String(v.score, 3);
        j += ",\"peak\":" + String(v.peakScore, 3);
        j += ",\"mad\":" + String(v.mad, 5);
        j += ",\"floor\":" + String(v.floorMad, 5);
        j += ",\"spread\":" + String(v.spread, 3);
        j += ",\"acf\":" + String(v.acf, 4);
        j += ",\"vote\":" + String(v.vote, 3);
        j += ",\"events\":" + String(v.events);
        j += ",\"age\":" + String(v.ageMs / 1000);
        j += ",\"motion\":" + String(v.motion ? "true" : "false") + "}";
    }

    j += "]}";
    return j;
}

void csiClearCalibration() {
    prefs.putBool("csiCalDone", false);
    Serial.println("[CSI] Saved baseline cleared - next start will re-learn the trigger");
}

void setCsiConfig(uint8_t channel, float threshold, uint32_t holdMs, uint32_t consec,
                  bool rawDump, bool telemetry, bool autoTrigger) {
    if (channel <= 14) csiPinnedChannel.store(channel);
    if (threshold >= 0.02f && threshold <= 0.60f) csiThresholdMilli.store((uint32_t)(threshold * 1000.0f));
    if (holdMs >= 500 && holdMs <= 120000) csiHoldMs.store(holdMs);
    if (consec >= 1 && consec <= 50) csiConsecNeeded.store(consec);
    csiRawDump.store(rawDump);
    csiTelemetry.store(telemetry);
    csiAutoTrigger.store(autoTrigger);

    prefs.putUChar("csiCh", csiPinnedChannel.load());
    prefs.putUInt("csiThr", csiThresholdMilli.load());
    prefs.putUInt("csiHold", csiHoldMs.load());
    prefs.putUInt("csiCons", csiConsecNeeded.load());
}

void loadCsiConfigFromPrefs() {
    csiPinnedChannel.store(prefs.getUChar("csiCh", 0));
    uint32_t thrStored = prefs.getUInt("csiThr", 100);
    if (thrStored < 20 || thrStored > 600) thrStored = 100;
    csiThresholdMilli.store(thrStored);
    csiHoldMs.store(prefs.getUInt("csiHold", 5000));
    csiConsecNeeded.store(prefs.getUInt("csiCons", 3));
}

static bool csiArmCsi(uint8_t ch) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

    wifi_csi_config_t cfg = {};
#if CONFIG_SOC_WIFI_HE_SUPPORT
    cfg.enable = 1;
    cfg.acquire_csi_legacy = 1;
    cfg.acquire_csi_force_lltf = 1;
    cfg.acquire_csi_ht20 = 0;
    cfg.acquire_csi_ht40 = 0;
    cfg.acquire_csi_vht = 0;
    cfg.acquire_csi_su = 0;
    cfg.acquire_csi_mu = 0;
    cfg.acquire_csi_dcm = 0;
    cfg.acquire_csi_beamformed = 0;
    cfg.acquire_csi_he_stbc_mode = 0;
    cfg.val_scale_cfg = 0;
    cfg.lltf_bit_mode = 0;
    cfg.dump_ack_en = 0;
#else
    cfg.lltf_en = true;
    cfg.htltf_en = true;
    cfg.stbc_htltf2_en = true;
    cfg.ltf_merge_en = false;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = false;
#endif

    if (esp_wifi_set_csi_rx_cb(&csi_rx_cb, nullptr) != ESP_OK) return false;
    if (esp_wifi_set_csi_config(&cfg) != ESP_OK) {
        esp_wifi_set_csi_rx_cb(NULL, nullptr);
        return false;
    }
    return esp_wifi_set_csi(true) == ESP_OK;
}

static bool csiRadioStart(uint8_t ch) {
    WiFi.mode(WIFI_AP_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&csi_prom_cb);

    esp_err_t rp = esp_wifi_set_promiscuous(true);
    if (rp != ESP_OK) {
        Serial.printf("[CSI] promiscuous enable failed: %s\n", esp_err_to_name(rp));
        return false;
    }

    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));

    wifi_csi_config_t cfg = {};
#if CONFIG_SOC_WIFI_HE_SUPPORT
    cfg.enable = 1;
    cfg.acquire_csi_legacy = 1;
    cfg.acquire_csi_force_lltf = 1;
    cfg.acquire_csi_ht20 = 0;
    cfg.acquire_csi_ht40 = 0;
    cfg.acquire_csi_vht = 0;
    cfg.acquire_csi_su = 0;
    cfg.acquire_csi_mu = 0;
    cfg.acquire_csi_dcm = 0;
    cfg.acquire_csi_beamformed = 0;
    cfg.acquire_csi_he_stbc_mode = 0;
    cfg.val_scale_cfg = 0;
    cfg.lltf_bit_mode = 0;
    cfg.dump_ack_en = 0;
#else
    cfg.lltf_en = true;
    cfg.htltf_en = true;
    cfg.stbc_htltf2_en = true;
    cfg.ltf_merge_en = false;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = false;
#endif

    esp_err_t rb = esp_wifi_set_csi_rx_cb(&csi_rx_cb, nullptr);
    if (rb != ESP_OK) {
        Serial.printf("[CSI] set_csi_rx_cb failed: %s\n", esp_err_to_name(rb));
        esp_wifi_set_promiscuous(false);
        return false;
    }

    esp_err_t rc = esp_wifi_set_csi_config(&cfg);
    if (rc != ESP_OK) {
        Serial.printf("[CSI] set_csi_config failed: %s\n", esp_err_to_name(rc));
        esp_wifi_set_csi_rx_cb(NULL, nullptr);
        esp_wifi_set_promiscuous(false);
        return false;
    }

    esp_err_t re = esp_wifi_set_csi(true);
    if (re != ESP_OK) {
        Serial.printf("[CSI] set_csi failed: %s\n", esp_err_to_name(re));
        esp_wifi_set_csi_rx_cb(NULL, nullptr);
        esp_wifi_set_promiscuous(false);
        return false;
    }

    return true;
}

static void csiRadioStop() {
    esp_wifi_set_csi(false);
    esp_wifi_set_csi_rx_cb(NULL, nullptr);
    vTaskDelay(pdMS_TO_TICKS(50));
    radioStopSTA();
}

void csiMotionTask(void *pv) {
    sentinel_yieldAndWait(1500);

    int duration = static_cast<int>(reinterpret_cast<intptr_t>(static_cast<int *>(pv)));
    bool forever = (duration <= 0);
    uint8_t ch = csiPinnedChannel.load();
    const bool autoChannel = (ch == 0);

    Serial.printf("[CSI] Starting motion detection %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    {
        std::lock_guard<std::mutex> lock(g_csiMutex);
        for (int i = 0; i < CSI_MAX_LINKS; i++) csiLinkReset(g_links[i]);
    }

    g_csiSeen.store(0);
    g_csiDropped.store(0);
    g_csiRejected.store(0);
    g_csiMotionEvents.store(0);
    g_promFrames.store(0);
    g_calActive = false;
    g_calSum = 0.0f;
    g_calSamples = 0;
    g_calTrigger = 0.0f;
    g_areaMotion = false;
    g_areaCand = false;
    g_areaCandSince = 0;
    g_areaSinceMs = 0;
    g_areaLastMotionMs = 0;
    csiEpisodesReset();
    g_heatLen = 0;
    g_heatSec = 60;
    g_heatStep = 0;
    g_heatSum = 0;
    g_heatHotCur = 0;
    g_heatCurSec = 0;
    g_csiStartMs = millis();
    g_csiEndMs = 0;

    if (csiQueue == nullptr) {
        csiQueue = xQueueCreateWithCaps(48, sizeof(CsiEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    } else {
        xQueueReset(csiQueue);
    }

    if (csiQueue == nullptr) {
        Serial.println("[CSI] queue alloc failed");
        scanning = false;
        scanSetCountdown(0, false);
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    if (!csiRadioStart(ch ? ch : 1)) {
        vQueueDeleteWithCaps(csiQueue);
        csiQueue = nullptr;
        scanning = false;
        scanSetCountdown(0, false);
        {
            std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
            antihunter::lastResults = "CSI Motion Detection\n\nRadio failed to enter CSI mode - see serial log.\n";
        }
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    scanning = true;
    stopRequested = false;
    scanStopPending.store(false);
    scanSetCountdown(duration, forever);

    if (autoChannel) {
        uint8_t picked = csiSurveyPickChannel(CSI_SURVEY_DWELL_MS);
        if (picked == 0) {
            Serial.println("[CSI] Aborting: no channel carries CSI-eligible traffic");
            {
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults =
                    "CSI Motion Detection\n\nNo CSI-eligible traffic found on any surveyed channel.\n"
                    "CSI only exists when a frame is decoded - nothing was transmitting.\n";
            }
            scanning = false;
            csiRadioStop();
            vQueueDeleteWithCaps(csiQueue);
            csiQueue = nullptr;
            scanSetCountdown(0, false);
            workerTaskHandle = nullptr;
            vTaskDelete(nullptr);
            return;
        }
        ch = picked;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(50));
        xQueueReset(csiQueue);
    }

    g_csiActiveChannel = ch;
    g_csiSeen.store(0);
    g_csiRejected.store(0);
    g_csiDropped.store(0);
    g_csiStartMs = millis();
    g_csiEndMs = 0;

    Serial.printf("[CSI] Radio locked to ch%u for the run - SoftAP moves to ch%u with it, rejoin there; returns to ch%u when the scan ends\n",
                  ch, ch, (unsigned)AP_CHANNEL);

    {
        uint8_t priCh = 0;
        wifi_second_chan_t secCh = WIFI_SECOND_CHAN_NONE;
        if (esp_wifi_get_channel(&priCh, &secCh) == ESP_OK && priCh != ch) {
            Serial.printf("[CSI] WARNING: radio reports ch%u, not the selected ch%u - "
                          "re-applying\n", priCh, ch);
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(30));
            if (esp_wifi_get_channel(&priCh, &secCh) == ESP_OK) {
                Serial.printf("[CSI] radio channel after re-apply: ch%u\n", priCh);
            }
        }
    }

    if (csiAutoTrigger.load()) {
        g_calActive = true;
        Serial.printf("[CSI] Learning trigger from this area for %us - keep it empty\n", CSI_CAL_MS / 1000);
    } else {
        Serial.printf("[CSI] Trigger %.2fx (self-normalizing, no setup needed)\n",
                      (float)csiThresholdMilli.load() / 1000.0f);
    }

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = "CSI Motion Detection - ch" + std::to_string(ch) +
                                  " (IN PROGRESS)\nLearning still-state baseline...\n";
    }

    const uint32_t startMs = millis();
    uint32_t lastResultsMs = 0;
    uint32_t lastExpireMs = millis();
    uint32_t lastStatMs = millis();
    uint32_t lastRollMs = millis();
    uint32_t lastStallMs = millis();
    uint32_t lastSeenSnap = 0;
    uint32_t lastRejSnap = 0;
    uint32_t blindSinceMs = 0;
    uint32_t lastRehopMs = 0;
    uint32_t lastSolicitMs = millis();
    uint32_t lastSolicitSeen = 0;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - startMs) < duration * 1000 && !stopRequested)) {

        CsiEvent ev;
        if (xQueueReceive(csiQueue, &ev, pdMS_TO_TICKS(100)) == pdTRUE) {
            csiProcess(ev);
            for (uint16_t burst = 0; burst < CSI_DRAIN_BURST; burst++) {
                if (xQueueReceive(csiQueue, &ev, 0) != pdTRUE) break;
                csiProcess(ev);
            }
        }

        const uint32_t now = millis();

        if (g_calActive) {
            std::lock_guard<std::mutex> lock(g_csiMutex);
            g_calActive = false;
            Serial.println("[CSI] Calibration ignored: the ACF trigger is derived, not learned");
        }

        if (now - lastExpireMs >= 2000) {
            lastExpireMs = now;
            csiExpireLinks();

            int movingLinks = 0;
            float peak = 0.0f;
            uint8_t usableLinks = 0;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                usableLinks = csiUsableCount();
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].motion) continue;
                    movingLinks++;
                    if (g_links[i].sc.score > peak) peak = g_links[i].sc.score;
                }
            }

            const int needLinks = (usableLinks >= 2) ? 2 : 1;
            const bool areaNow = (movingLinks >= needLinks);
            if (areaNow) g_areaLastMotionMs = now;

            if (areaNow != g_areaCand) {
                g_areaCand = areaNow;
                g_areaCandSince = now;
            }

            if (g_areaCand != g_areaMotion && (now - g_areaCandSince) >= CSI_AREA_DEBOUNCE_MS) {
                g_areaMotion = g_areaCand;
                if (g_areaMotion) {
                    g_areaSinceMs = g_areaCandSince;
                    csiEpisodeOpen(getFormattedTimestamp());
                    if (meshEnabled) {
                        meshEnqueuePrio(getNodeId() + ": CSI_MOTION: CH=" + String(g_csiActiveChannel) +
                                        " N=" + String(movingLinks) +
                                        " S=" + String(peak, 2), PRIO_EVENT);
                    }
                    Serial.printf("[CSI] AREA MOTION (held %us)\n", CSI_AREA_DEBOUNCE_MS / 1000);
                } else {
                    const uint32_t dwell = (g_areaCandSince - g_areaSinceMs) / 1000;
                    csiEpisodeClose(dwell);
                    if (meshEnabled) {
                        meshEnqueuePrio(getNodeId() + ": CSI_CLEAR: CH=" + String(g_csiActiveChannel) +
                                        " D=" + String(dwell) + "s", PRIO_EVENT);
                    }
                    Serial.printf("[CSI] AREA CLEAR (moved %us)\n", dwell);
                }
            }
        }

        if (now - lastResultsMs >= 1000) {
            lastResultsMs = now;
            if (!g_calActive) {
                float peakNow = 0.0f;
                {
                    const float eta = (float)csiThresholdMilli.load() / 1000.0f;
                    std::lock_guard<std::mutex> lock(g_csiMutex);
                    float r1 = 0.0f, r2 = 0.0f;
                    for (int i = 0; i < CSI_MAX_LINKS; i++) {
                        const CsiLink &l = g_links[i];
                        if (!l.used || !l.sc.settled() || l.packets < CSI_LINK_MIN_PKTS) continue;
                        if (!csiLinkUsable(l)) continue;
                        const float r = csiTriggerRatio(l.sc.acf, l.sc.vote, eta);
                        if (r > r1) { r2 = r1; r1 = r; }
                        else if (r > r2) { r2 = r; }
                    }
                    peakNow = (csiUsableCount() >= 2) ? r2 : r1;
                }
                if (g_areaMotion && peakNow > g_epPeak) g_epPeak = peakNow;
                csiHeatPush(peakNow, g_areaMotion);
            }
            if (uxQueueMessagesWaiting(csiQueue) == 0) {
                String snap = getCsiResults();
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = std::string(snap.c_str());
            }
        }

        if (now - lastSolicitMs >= 1000) {
            const uint32_t seenNow = g_csiSeen.load();
            if ((seenNow - lastSolicitSeen) < CSI_SOLICIT_FLOOR) {
                csiSolicit();
            }
            lastSolicitSeen = seenNow;
            lastSolicitMs = now;
        }

        if (now - lastStallMs >= 5000) {
            lastStallMs = now;
            const uint32_t seenNow = g_csiSeen.load();
            const uint32_t rejNow = g_csiRejected.load();
            if (seenNow == lastSeenSnap && rejNow > lastRejSnap) {
                Serial.printf("[CSI] STALL: 0 accepted, +%u rejected (fcs=%u width=%u short=%u mac=%u) - re-arming ch%u\n",
                              rejNow - lastRejSnap, g_rejFcs.load(), g_rejWidth.load(),
                              g_rejShort.load(), g_rejMac.load(), g_csiActiveChannel);
                if (!csiArmCsi(g_csiActiveChannel)) Serial.println("[CSI] re-arm failed");
            }
            lastSeenSnap = seenNow;
            lastRejSnap = rejNow;
        }

        if (now - lastRollMs >= 60000) {
            lastRollMs = now;
            float peakRoll = 0.0f;
            int movingRoll = 0;
            uint8_t usableRoll = 0;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                usableRoll = csiUsableCount();
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].sc.settled()) continue;
                    if (g_links[i].motion) movingRoll++;
                    if (g_links[i].sc.score > peakRoll) peakRoll = g_links[i].sc.score;
                }
            }
            Serial.printf("[CSI] STATE %s peak=%.2f links=%d usable=%u events=%u up=%us\n",
                          usableRoll == 0 ? "BLIND" : (g_areaMotion ? "MOVE" : "quiet"),
                          peakRoll, movingRoll, usableRoll,
                          g_csiMotionEvents.load(), (now - g_csiStartMs) / 1000);
            if (g_memcpyBadLenRejects) {
                Serial.printf("[WIFI] blob bad-length memcpy rejected: n=%u count=%u\n",
                              (unsigned)g_memcpyBadLenLast, (unsigned)g_memcpyBadLenRejects);
            }
            if (usableRoll == 0) {
                Serial.printf("[CSI] BLIND: no link reaches %ddBm - cannot detect motion on ch%u\n",
                              (int)CSI_LINK_MIN_RSSI, g_csiActiveChannel);
                if (blindSinceMs == 0) blindSinceMs = now;
                if (autoChannel && (now - blindSinceMs) >= CSI_BLIND_REHOP_MS &&
                    (lastRehopMs == 0 || (now - lastRehopMs) >= CSI_REHOP_COOLDOWN_MS)) {
                    if (WiFi.softAPgetStationNum() > 0) {
                        Serial.println("[CSI] blind but a client is on the AP - holding this channel");
                        blindSinceMs = now;
                        continue;
                    }
                    const uint32_t blindFor = (now - blindSinceMs) / 1000;
                    lastRehopMs = now;
                    blindSinceMs = 0;
                    const uint8_t next = csiRehopPickChannel();
                    if (next != 0 && next != g_csiActiveChannel) {
                        Serial.printf("[CSI] blind %us on ch%u - moving to ch%u, SoftAP moves with it\n",
                                      blindFor, g_csiActiveChannel, next);
                        {
                            std::lock_guard<std::mutex> lock(g_csiMutex);
                            for (int i = 0; i < CSI_MAX_LINKS; i++) csiLinkReset(g_links[i]);
                        }
                        g_csiActiveChannel = next;
                        xQueueReset(csiQueue);
                        if (!csiArmCsi(next)) Serial.println("[CSI] re-arm after channel move failed");
                    }
                    const uint32_t after = millis();
                    lastExpireMs = lastResultsMs = lastStallMs = lastStatMs = lastRollMs = after;
                    lastSeenSnap = g_csiSeen.load();
                    lastRejSnap = g_csiRejected.load();
                    continue;
                }
            } else {
                blindSinceMs = 0;
            }
        }

        if (now - lastStatMs >= 15000) {
            lastStatMs = now;
            const uint32_t span = now - startMs;
            float statAcfMax = 0.0f, statAcfMin = 1.0f, statVoteMax = 0.0f;
            uint8_t statLinks = 0, statPassEta = 0, statPassVote = 0;
            {
                const float eta = (float)csiThresholdMilli.load() / 1000.0f;
                std::lock_guard<std::mutex> lock(g_csiMutex);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    const CsiLink &l = g_links[i];
                    if (!l.used || !l.sc.settled() || !csiLinkUsable(l)) continue;
                    statLinks++;
                    if (l.sc.acf > statAcfMax) statAcfMax = l.sc.acf;
                    if (l.sc.acf < statAcfMin) statAcfMin = l.sc.acf;
                    if (l.sc.vote > statVoteMax) statVoteMax = l.sc.vote;
                    if (l.sc.acf >= eta) statPassEta++;
                    if (l.sc.vote >= CSI_VOTE_FRAC) statPassVote++;
                }
            }
            Serial.printf("[CSI] ch%u records=%u rate=%.1f/s rejected=%u drops=%u events=%u | "
                          "links=%u acf=%.3f..%.3f vote=%.2f pass-eta=%u pass-vote=%u frames=%u\n",
                          g_csiActiveChannel, g_csiSeen.load(),
                          (float)g_csiSeen.load() * 1000.0f / (float)(span ? span : 1),
                          g_csiRejected.load(), g_csiDropped.load(), g_csiMotionEvents.load(),
                          statLinks, statLinks ? statAcfMin : 0.0f, statAcfMax, statVoteMax,
                          statPassEta, statPassVote, g_promFrames.load());
        }
    }

    {
        CsiAlert finalAlerts[CSI_MAX_LINKS] = {};
        {
            std::lock_guard<std::mutex> lock(g_csiMutex);
            g_areaMotion = false;
            g_areaCand = false;
            for (int i = 0; i < CSI_MAX_LINKS; i++) {
                if (g_links[i].used && g_links[i].motion) {
                    g_links[i].motion = false;
                    csiStageAlert(finalAlerts[i], g_links[i], false);
                }
            }
        }
        for (int i = 0; i < CSI_MAX_LINKS; i++) csiEmitAlert(finalAlerts[i]);
    }

    String finalResults = getCsiResults();
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults = std::string(finalResults.c_str());
    }

    {
        const uint32_t span = millis() - startMs;
        Serial.printf("[CSI] Done: CH=%u N=%u R=%.1f/s E=%u\n",
                      g_csiActiveChannel, g_csiSeen.load(),
                      (float)g_csiSeen.load() * 1000.0f / (float)(span ? span : 1),
                      g_csiMotionEvents.load());
    }

    scanning = false;
    g_csiEndMs = millis();
    csiRadioStop();

    if (csiQueue) {
        vQueueDeleteWithCaps(csiQueue);
        csiQueue = nullptr;
    }

    Serial.printf("[CSI] Stopped: %u records, %u motion events\n",
                  g_csiSeen.load(), g_csiMotionEvents.load());

    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}
