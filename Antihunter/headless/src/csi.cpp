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
std::atomic<uint8_t> csiPinnedChannel{0};
std::atomic<uint32_t> csiThresholdMilli{0};
std::atomic<uint32_t> csiHoldMs{5000};
std::atomic<uint32_t> csiConsecNeeded{3};
std::atomic<uint32_t> csiSolicitMs{0};
std::atomic<uint8_t> csiNoTx{0};
std::atomic<uint8_t> csiAllowRandom{0};
std::atomic<uint32_t> csiAreaDutyMinS{8};
std::atomic<uint32_t> csiAreaRadiosNeeded{1};
std::atomic<uint64_t> csiExcludeMac{0};
std::atomic<uint8_t> csiMgmtOnly{0};

static const uint32_t CSI_LINK_STALE_MS = 20000;
static const uint32_t CSI_LINK_FORGET_MS = 600000;
static const uint32_t CSI_SURVEY_DWELL_MS = 2500;
static const uint32_t CSI_BLIND_REHOP_MS = 180000;
static const uint32_t CSI_REHOP_COOLDOWN_MS = 600000;
static const uint32_t CSI_SOLICIT_FLOOR = 15;

static std::atomic<bool> g_surveyMode{false};
static std::atomic<uint32_t> g_surveyHits{0};
static std::atomic<uint32_t> g_surveyStrong{0};
static std::atomic<uint32_t> g_surveyHt{0};
static std::atomic<int> g_surveyPeak{-128};
static std::atomic<uint32_t> g_surveyTx{0};
static uint8_t g_surveyMacs[16][6];
static uint32_t g_surveyMacHits[16];
static uint8_t g_surveyMacCount = 0;

static const uint8_t CSI_HEAT_CELLS = 120;
static const float CSI_HEAT_FULL_RATIO = 2.0f;
static uint32_t g_epTotal = 0;
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
static uint32_t g_heatEvSnap = 0;

static void csiHeatPush(bool alerting, float peakRatio) {
    if (alerting) {
        g_heatHotCur = 1;
        float s = (peakRatio - 1.0f) / 2.0f;
        if (s < 0.0f) s = 0.0f;
        if (s > 1.0f) s = 1.0f;
        g_heatSum += (uint32_t)(s * 255.0f + 0.5f);
    }
    g_heatCurSec++;
    if (g_heatCurSec < g_heatSec) return;

    const uint32_t evNow = g_epTotal;
    const uint8_t hot = (g_heatHotCur || evNow != g_heatEvSnap) ? 1 : 0;
    g_heatEvSnap = evNow;

    float lvl = (float)g_heatSum / (255.0f * (float)(g_heatSec ? g_heatSec : 1));
    if (lvl > 1.0f) lvl = 1.0f;
    const uint8_t cell = (uint8_t)(lvl * 255.0f + 0.5f);
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
            uint16_t acc = 0;
            uint8_t n = 0, mhot = 0;
            for (uint8_t k = i; k < i + factor && k < CSI_HEAT_CELLS; k++) {
                acc = (uint16_t)(acc + g_heat[k]);
                n++;
                mhot |= g_heatHot[k];
            }
            g_heat[out] = (uint8_t)(acc / (n ? n : 1));
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
static const uint8_t CSI_RADIO_KEY_LEN = 6;
static const uint32_t CSI_ELEV_CAP_MS = 6000;
static const uint32_t CSI_ELEV_DECAY = 2;
static const uint32_t CSI_AREA_DEBOUNCE_MS = 6000;
static const uint8_t CSI_AREA_DUTY_SLOTS = 30;
static const uint16_t CSI_AREA_DUTY_MIN_S = 4;
static uint8_t g_areaDuty[CSI_AREA_DUTY_SLOTS];
static uint8_t g_areaDutyPos = 0;
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


struct CsiEvent {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t ch;
    uint32_t ts;
    uint16_t len;
    bool fwInvalid;
    int8_t buf[CSI_BUF_BYTES];
    bool usable;
};

static inline bool csiFromAp(const uint8_t *h) {
    if (!h) return false;
    const uint8_t type = (h[0] >> 2) & 0x03;
    const uint8_t sub = (h[0] >> 4) & 0x0F;
    if (type == 0) return sub == 8 || sub == 5;
    if (type == 2) return (h[1] & 0x03) == 0x02;
    return false;
}

struct CsiLink {
    uint8_t mac[6] = {};
    bool used = false;
    uint32_t packets = 0;
    uint32_t firstMs = 0;
    uint32_t lastMs = 0;
    uint32_t lastTs = 0;
    int8_t rssi = 0;
    CsiScorer sc;
    float peakScore = 0.0f;
    uint8_t consec = 0;
    bool motion = false;
    uint32_t lastAboveMs = 0;
    uint32_t lastTickMs = 0;
    uint32_t elevMs = 0;
    uint32_t motionStartMs = 0;
    uint32_t events = 0;
    uint16_t fmtLen = 0;
    uint8_t liveBins = 0;
    uint32_t pairsSnap = 0;
    float pairRate = 0.0f;
};

static CsiLink g_links[CSI_MAX_LINKS];
static float *g_gring = nullptr;
static std::mutex g_csiMutex;
static QueueHandle_t csiQueue = nullptr;

static std::atomic<uint32_t> g_csiSeen{0};
static std::atomic<uint32_t> g_csiUsedSeen{0};
static std::atomic<uint32_t> g_csiDropped{0};
static std::atomic<uint32_t> g_csiRejected{0};
static std::atomic<uint32_t> g_rejFcs{0};
static std::atomic<uint32_t> g_rejWidth{0};
static std::atomic<uint32_t> g_rejShort{0};
static std::atomic<uint32_t> g_rejMac{0};
static std::atomic<uint32_t> g_csiMotionEvents{0};
static uint32_t g_csiStartMs = 0;
static uint32_t g_csiRunStartMs = 0;
static uint32_t g_csiEndMs = 0;
static uint8_t g_csiActiveChannel = 0;

static std::atomic<uint32_t> g_promFrames{0};
static std::atomic<uint32_t> g_rejFmt{0};
static std::atomic<uint32_t> g_fwSkip{0};
static std::atomic<uint32_t> g_solicitOk{0};
static std::atomic<uint32_t> g_solicitErr{0};
static std::atomic<int32_t> g_solicitLastErr{0};
static std::atomic<uint32_t> g_pollOk{0};
static std::atomic<uint32_t> g_pollErr{0};
static std::atomic<int32_t> g_pollLastErr{0};

extern std::atomic<uint32_t> framesSeen;

static std::atomic<uint32_t> g_ceVld{0};
static std::atomic<uint32_t> g_ceInvld{0};
static std::atomic<uint32_t> g_ceLen{0};
static std::atomic<uint32_t> g_rejStale{0};
std::atomic<bool> csiRequireCeVld{false};

static const uint8_t CSI_LEN_SLOTS = 6;
static volatile uint16_t g_lenVal[CSI_LEN_SLOTS];
static volatile uint32_t g_lenCnt[CSI_LEN_SLOTS];
static volatile uint8_t g_lenFmt[CSI_LEN_SLOTS];

static void csiLenSeen(uint16_t len, uint8_t fmt) {
    for (uint8_t i = 0; i < CSI_LEN_SLOTS; i++) {
        if (g_lenCnt[i] && g_lenVal[i] == len && g_lenFmt[i] == fmt) { g_lenCnt[i]++; return; }
    }
    for (uint8_t i = 0; i < CSI_LEN_SLOTS; i++) {
        if (!g_lenCnt[i]) { g_lenVal[i] = len; g_lenFmt[i] = fmt; g_lenCnt[i] = 1; return; }
    }
}

static std::atomic<uint32_t> g_phyDsss{0};
static std::atomic<uint32_t> g_phyOfdm{0};
static std::atomic<uint32_t> g_phyHt{0};
static std::atomic<uint32_t> g_phyOther{0};

static void csi_prom_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    g_promFrames.fetch_add(1);
    const wifi_promiscuous_pkt_t *ppkt = static_cast<wifi_promiscuous_pkt_t *>(buf);
    if (ppkt && ppkt->rx_ctrl.sig_len >= 24) framesSeen.fetch_add(1, std::memory_order_relaxed);
    if (!ppkt) return;
#if CONFIG_SOC_WIFI_HE_SUPPORT
    switch (ppkt->rx_ctrl.cur_bb_format) {
        case RX_BB_FORMAT_11B: g_phyDsss.fetch_add(1, std::memory_order_relaxed); break;
        case RX_BB_FORMAT_11G: g_phyOfdm.fetch_add(1, std::memory_order_relaxed); break;
        case RX_BB_FORMAT_HT:  g_phyHt.fetch_add(1, std::memory_order_relaxed); break;
        default:               g_phyOther.fetch_add(1, std::memory_order_relaxed); break;
    }
#else
    const unsigned sm = ppkt->rx_ctrl.sig_mode;
    const unsigned rt = ppkt->rx_ctrl.rate;
    if (sm == 1) g_phyHt.fetch_add(1, std::memory_order_relaxed);
    else if (sm == 0 && rt <= WIFI_PHY_RATE_11M_S) g_phyDsss.fetch_add(1, std::memory_order_relaxed);
    else if (sm == 0 && rt <= WIFI_PHY_RATE_9M) g_phyOfdm.fetch_add(1, std::memory_order_relaxed);
    else g_phyOther.fetch_add(1, std::memory_order_relaxed);
#endif
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
    if (rx.rx_channel_estimate_info_vld) g_ceVld.fetch_add(1);
    else g_ceInvld.fetch_add(1);
    g_ceLen.store(rx.rx_channel_estimate_len);
    if (csiRequireCeVld.load() && !rx.rx_channel_estimate_info_vld) {
        g_csiRejected.fetch_add(1);
        g_rejStale.fetch_add(1);
        return;
    }
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
    csiLenSeen(info->len, rx.cur_bb_format);
    if (info->len != CSI_LEN_LLTF && info->len != CSI_LEN_HTLTF) {
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
    const uint64_t ex = csiExcludeMac.load();
    const bool excluded = ex != 0 &&
        ((((uint64_t)m[0] << 32) | ((uint64_t)m[1] << 24) | ((uint64_t)m[2] << 16) |
          ((uint64_t)m[3] << 8) | (uint64_t)m[4]) == (ex >> 8));
    const bool usable = !excluded &&
        (csiAllowRandom.load() || !(m[0] & 0x02));

    if (g_surveyMode.load()) {
        if (!usable) return;
        g_surveyHits.fetch_add(1);
        if (rx.rssi >= CSI_SURVEY_MIN_RSSI) g_surveyStrong.fetch_add(1);
#if CONFIG_SOC_WIFI_HE_SUPPORT
        if (rx.cur_bb_format == RX_BB_FORMAT_HT) g_surveyHt.fetch_add(1);
#endif
        {
            int pk = g_surveyPeak.load();
            while ((int)rx.rssi > pk && !g_surveyPeak.compare_exchange_weak(pk, (int)rx.rssi)) {}
        }
        bool known = false;
        for (uint8_t i = 0; i < g_surveyMacCount; i++) {
            if (memcmp(g_surveyMacs[i], m, 6) == 0) { g_surveyMacHits[i]++; known = true; break; }
        }
        if (!known && g_surveyMacCount < 16) {
            memcpy(g_surveyMacs[g_surveyMacCount], m, 6);
            g_surveyMacHits[g_surveyMacCount] = 1;
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
    ev.len = info->len;
    ev.fwInvalid = info->first_word_invalid;
    memcpy(ev.buf, info->buf, info->len);
    ev.usable = usable;

    g_csiSeen.fetch_add(1);
    if (usable) g_csiUsedSeen.fetch_add(1);
    if (xQueueSend(csiQueue, &ev, 0) != pdTRUE) g_csiDropped.fetch_add(1);
}

static void csiSolicit();

static bool csiMoveRadio(uint8_t ch);
static uint8_t g_probeTarget[6];
static bool g_probeTargetSet = false;

static uint8_t csiSurveyPickChannel(uint32_t dwellMs, uint16_t avoidMask = 0) {
    uint16_t allowed = 0;
    for (uint8_t c : CHANNELS) {
        if (c >= 1 && c <= 14) allowed |= (uint16_t)(1u << c);
    }
    if (!allowed) allowed = 0x0FFE;
    allowed &= (uint16_t)~avoidMask;

    wifi_scan_config_t sc = {};
    sc.show_hidden = true;
    sc.scan_type = csiNoTx.load() ? WIFI_SCAN_TYPE_PASSIVE : WIFI_SCAN_TYPE_ACTIVE;
    const esp_err_t sr = esp_wifi_scan_start(&sc, true);
    uint16_t n = 0;
    if (sr == ESP_OK) esp_wifi_scan_get_ap_num(&n);
    std::vector<wifi_ap_record_t> recs(n);
    if (n && esp_wifi_scan_get_ap_records(&n, recs.data()) != ESP_OK) n = 0;
    esp_wifi_clear_ap_list();

    int8_t best[15];
    uint8_t bestMac[15][6] = {};
    for (int c = 0; c < 15; c++) best[c] = -128;
    const uint64_t ex = csiExcludeMac.load();
    uint16_t aps = 0;
    for (uint16_t i = 0; i < n; i++) {
        const uint8_t *b = recs[i].bssid;
        const uint8_t c = recs[i].primary;
        if (c < 1 || c > 14 || !((allowed >> c) & 1)) continue;
        if (!csiAllowRandom.load() && (b[0] & 0x02)) continue;
        if (ex && ((((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) | ((uint64_t)b[2] << 16) |
                    ((uint64_t)b[3] << 8) | (uint64_t)b[4]) == (ex >> 8))) continue;
        aps++;
        if (recs[i].rssi > best[c]) { best[c] = recs[i].rssi; memcpy(bestMac[c], b, 6); }
    }
    Serial.printf("[CSI] Survey: %u access points on allowed channels (scan %s)\n",
                  aps, esp_err_to_name(sr));

    uint8_t cand[3] = {0, 0, 0};
    for (int k = 0; k < 3; k++) {
        int top = CSI_LINK_MIN_RSSI - 1;
        for (uint8_t c = 1; c <= 14; c++) {
            if (best[c] > top && c != cand[0] && c != cand[1]) { top = best[c]; cand[k] = c; }
        }
    }
    if (!cand[0]) {
        Serial.println("[CSI] No access point in range on any allowed channel");
        return 0;
    }

    const uint32_t trialMs = dwellMs * 2;
    uint8_t pick = cand[0];
    uint32_t pickHits = 0;
    for (uint8_t c : cand) {
        if (!c || stopRequested) continue;
        csiMoveRadio(c);
        memcpy(g_probeTarget, bestMac[c], 6);
        g_probeTargetSet = true;
        g_surveyHits.store(0);
        g_surveyStrong.store(0);
        g_surveyHt.store(0);
        g_surveyPeak.store(-128);
        g_surveyTx.store(0);
        g_surveyMacCount = 0;
        g_surveyMode.store(true);
        const uint32_t t0 = millis();
        while (millis() - t0 < trialMs && !stopRequested) {
            csiSolicit();
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        g_surveyMode.store(false);
        uint32_t top = 0;
        uint8_t topIdx = 0;
        for (uint8_t i = 0; i < g_surveyMacCount; i++) {
            if (g_surveyMacHits[i] > top) { top = g_surveyMacHits[i]; topIdx = i; }
        }
        Serial.printf("[CSI]   ch%-3u strongest AP %ddBm  %u APs answered  %u ht  best AP %.1f/s %s\n",
                      c, best[c], g_surveyTx.load(), g_surveyHt.load(),
                      (float)top * 1000.0f / (float)trialMs,
                      top ? macFmt6(g_surveyMacs[topIdx]).c_str() : "-");
        if (top > pickHits) { pickHits = top; pick = c; }
    }

    Serial.printf("[CSI] Selected ch%u (%.1f/s from its best access point)\n",
                  pick, (float)pickHits * 1000.0f / (float)trialMs);
    return pick;
}

static const uint8_t kCsiProbeHdr[24] = {
    0x40, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00
};
static const uint8_t kCsiProbeRates[10] = {
    0x01, 0x08, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C
};



static void csiSolicit() {
    if (csiNoTx.load()) return;
    uint8_t frame[24 + 2 + sizeof(kCsiProbeRates)];
    memcpy(frame, kCsiProbeHdr, 24);
    if (g_probeTargetSet) {
        memcpy(frame + 4, g_probeTarget, 6);
        memcpy(frame + 16, g_probeTarget, 6);
    }
    frame[24] = 0x00;
    frame[25] = 0x00;
    memcpy(frame + 26, kCsiProbeRates, sizeof(kCsiProbeRates));
    const size_t total = 26 + sizeof(kCsiProbeRates);

    wifi_mode_t wmode = WIFI_MODE_NULL;
    wifi_interface_t txif =
        (esp_wifi_get_mode(&wmode) == ESP_OK && wmode == WIFI_MODE_STA) ? WIFI_IF_STA : WIFI_IF_AP;
    esp_wifi_config_80211_tx_rate(txif, WIFI_PHY_RATE_6M);
    const esp_err_t err = esp_wifi_80211_tx(txif, frame, total, true);
    if (err == ESP_OK) g_solicitOk.fetch_add(1);
    else { g_solicitErr.fetch_add(1); g_solicitLastErr.store((int32_t)err); }
}

static wifi_sta_list_t g_apStas;
static uint32_t g_apStaMs = 0;

static void csiPollClients() {
    if (csiNoTx.load()) return;
    const uint32_t now = millis();
    if (g_apStaMs == 0 || (now - g_apStaMs) >= 5000) {
        g_apStaMs = now;
        if (esp_wifi_ap_get_sta_list(&g_apStas) != ESP_OK) g_apStas.num = 0;
    }
    uint8_t frame[24];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x48;

    if (g_apStas.num > 0) {
        uint8_t ap[6] = {0};
        if (esp_wifi_get_mac(WIFI_IF_AP, ap) != ESP_OK) return;
        frame[1] = 0x02;
        for (int i = 0; i < g_apStas.num && i < ESP_WIFI_MAX_CONN_NUM; i++) {
            memcpy(frame + 4, g_apStas.sta[i].mac, 6);
            memcpy(frame + 10, ap, 6);
            memcpy(frame + 16, ap, 6);
            const esp_err_t e = esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true);
            if (e == ESP_OK) g_pollOk.fetch_add(1);
            else { g_pollErr.fetch_add(1); g_pollLastErr.store((int32_t)e); }
        }
        return;
    }

    uint8_t sta[6] = {0};
    if (esp_wifi_get_mac(WIFI_IF_STA, sta) != ESP_OK) return;
    frame[1] = 0x01;
    memcpy(frame + 10, sta, 6);

    uint8_t targets[CSI_MAX_LINKS][6];
    uint8_t n = 0;
    {
        std::lock_guard<std::mutex> lock(g_csiMutex);
        for (int i = 0; i < CSI_MAX_LINKS && n < CSI_MAX_LINKS; i++) {
            const CsiLink &l = g_links[i];
            if (!l.used || l.packets < 8) continue;
            memcpy(targets[n++], l.mac, 6);
        }
    }
    for (uint8_t i = 0; i < n; i++) {
        memcpy(frame + 4, targets[i], 6);
        memcpy(frame + 16, targets[i], 6);
        const esp_err_t e = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
        if (e == ESP_OK) g_pollOk.fetch_add(1);
        else { g_pollErr.fetch_add(1); g_pollLastErr.store((int32_t)e); }
    }
}

static void csiLinkReset(CsiLink &l) {
    memset(l.mac, 0, sizeof(l.mac));
    l.used = false;
    l.packets = 0;
    l.firstMs = 0;
    l.lastMs = 0;
    l.lastTs = 0;
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
    l.fmtLen = 0;
    l.liveBins = 0;
    l.pairsSnap = 0;
    l.pairRate = 0.0f;
}

static bool csiLinkUsable(const CsiLink &l) {
    if (!l.used || l.packets < CSI_LINK_MIN_PKTS) return false;
    if ((millis() - l.lastMs) >= CSI_LINK_STALE_MS) return false;
    const uint64_t ex = csiExcludeMac.load();
    if (ex != 0) {
        uint64_t m = 0;
        for (int i = 0; i < 6; i++) m = (m << 8) | l.mac[i];
        if ((m >> 8) == (ex >> 8)) return false;
    }
    return l.rssi >= CSI_LINK_MIN_RSSI;
}

static float csiGateEta(uint32_t thrMilli) {
    return thrMilli ? ((float)thrMilli / 1000.0f) : CSI_SIG_ETA;
}

static float csiTriggerRatio(float gateStat) {
    const float r = gateStat / csiGateEta(csiThresholdMilli.load());
    return (r > 0.0f) ? r : 0.0f;
}

static uint8_t csiUsableCount() {
    uint8_t n = 0;
    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        if (csiLinkUsable(g_links[i])) n++;
    }
    return n;
}

static uint8_t csiArmedCount() {
    uint8_t n = 0;
    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        if (csiLinkUsable(g_links[i]) && g_links[i].sc.settled()) n++;
    }
    return n;
}

static uint8_t csiWindowCapableCount() {
    uint8_t n = 0;
    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        const CsiLink &l = g_links[i];
        if (!csiLinkUsable(l) || !l.sc.settled()) continue;
        if (l.pairRate >= CSI_LINK_MIN_PAIR_RATE) n++;
    }
    return n;
}

static int csiNeedLinks(int armedLinks) {
    int need = (armedLinks * CSI_AREA_LINK_NUM + CSI_AREA_LINK_DEN - 1) / CSI_AREA_LINK_DEN;
    if (need < 1) need = 1;
    const int cap = (int)csiAreaRadiosNeeded.load();
    if (cap > 0 && need > cap) need = cap;
    if (cap >= 2 && need < 2) need = 2;
    return need;
}

static bool csiSameRadio(const uint8_t *a, const uint8_t *b) {
    return memcmp(a + 1, b + 1, 4) == 0;
}

static int csiCountRadios(bool movingOnly) {
    uint8_t reps[CSI_MAX_LINKS][6];
    int n = 0;
    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        const CsiLink &l = g_links[i];
        if (!l.used) continue;
        if (movingOnly) {
            if (!l.motion) continue;
        } else if (!csiLinkUsable(l) || !l.sc.settled()) {
            continue;
        }
        bool dup = false;
        for (int j = 0; j < n; j++) {
            if (csiSameRadio(reps[j], l.mac)) { dup = true; break; }
        }
        if (dup) continue;
        memcpy(reps[n], l.mac, 6);
        n++;
    }
    return n;
}

static CsiLink *csiFindLink(const uint8_t *mac) {
    CsiLink *freeSlot = nullptr;
    CsiLink *worstUnsettled = nullptr;
    CsiLink *worstSettled = nullptr;

    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        CsiLink &l = g_links[i];
        if (l.used && memcmp(l.mac, mac, CSI_RADIO_KEY_LEN) == 0) return &l;
        if (!l.used) {
            if (!freeSlot) freeSlot = &l;
            continue;
        }
        if (l.motion) continue;
        if (l.pairRate >= CSI_LINK_MIN_PAIR_RATE) continue;
        CsiLink *&cand = l.sc.settled() ? worstSettled : worstUnsettled;
        if (!cand || l.pairRate < cand->pairRate ||
            (l.pairRate == cand->pairRate && (int32_t)(l.lastMs - cand->lastMs) < 0)) cand = &l;
    }

    CsiLink *slot = freeSlot;
    if (!slot) {
        CsiLink *worst = worstUnsettled ? worstUnsettled : worstSettled;
        if (!worst) return nullptr;
        slot = worst;
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

    if (al.rising) {
        Serial.printf("[CSI] MOTION %s score=%.2f mad=%.4f floor=%.4f rssi=%d\n",
                      mac.c_str(), al.score, al.mad, al.floorMad, al.rssi);
    } else {
        Serial.printf("[CSI] CLEAR %s dwell=%us\n", mac.c_str(), al.dwell);
    }
}

static void csiProcess(const CsiEvent &ev) {
    float a[CSI_NSUB];
    if (ev.fwInvalid) g_fwSkip.fetch_add(1);
    int liveBins = 0;
    if (!csiAmplitudesLen(ev.buf, ev.len, ev.fwInvalid, a, &liveBins)) return;
    if (!ev.usable) return;

    if (csiRawDump.load()) {
        String row = "CSIR," + String(ev.ts) + "," + macFmt6(ev.mac) + "," +
                     String(ev.rssi) + "," + String(ev.ch) + "," + String((int)sizeof(ev.buf));
        for (int i = 0; i < (int)sizeof(ev.buf); i++) {
            row += "," + String((int)ev.buf[i]);
        }
        row += ",L" + String((int)ev.len) + ",F" + String(ev.fwInvalid ? 1 : 0);
        Serial.println(row);
    }

    CsiAlert alert = {};

    {
        std::lock_guard<std::mutex> lock(g_csiMutex);

        CsiLink *lp = csiFindLink(ev.mac);
        if (!lp) return;
        CsiLink &l = *lp;

        const uint32_t now = millis();
        const uint32_t dtUs = l.lastTs ? (uint32_t)(ev.ts - l.lastTs) : 0xFFFFFFFFu;
        l.lastTs = ev.ts;
        l.lastMs = now;
        l.rssi = ev.rssi;
        l.packets++;

        if (l.fmtLen == 0) l.fmtLen = ev.len;
        else if (l.fmtLen != ev.len) { g_rejFmt.fetch_add(1); return; }
        l.liveBins = (uint8_t)liveBins;

        if (!l.sc.update(a, l.motion, dtUs)) return;
        if (l.sc.score > l.peakScore) l.peakScore = l.sc.score;

        if (csiRawDump.load()) {
            Serial.printf("CSIT,%lu,%s,%.3f,%.5f,%.5f,%d\n",
                          (unsigned long)now, macFmt6(l.mac).c_str(),
                          l.sc.score, l.sc.mad, l.sc.floorMad, l.rssi);
        }


        const uint32_t consecNeeded = csiConsecNeeded.load();
        const uint32_t hold = csiHoldMs.load();
        const float gateEta = csiGateEta(csiThresholdMilli.load());

        const uint32_t dt = (l.lastTickMs && now > l.lastTickMs) ? (now - l.lastTickMs) : 0;
        l.lastTickMs = now;

        const bool sigAbove = l.sc.psiValid && l.sc.sigVar >= gateEta && l.sc.sigZ >= CSI_SIG_Z_GATE;

        if (sigAbove) {
            l.lastAboveMs = now;
            if (l.consec < 255) l.consec++;
            l.elevMs += dt;
            if (l.elevMs > CSI_ELEV_CAP_MS) l.elevMs = CSI_ELEV_CAP_MS;
        } else {
            l.consec = 0;
            const uint32_t decay = dt * CSI_ELEV_DECAY;
            l.elevMs = (l.elevMs > decay) ? (l.elevMs - decay) : 0;
        }

        if (!l.sc.settled()) return;

        if (!csiLinkUsable(l)) return;


        const bool heldLongEnough = l.elevMs >= CSI_MOTION_MIN_MS;

        if (!l.motion && heldLongEnough && l.consec >= consecNeeded) {
            l.motion = true;
            l.motionStartMs = now;
            l.events++;
            g_csiMotionEvents.fetch_add(1);
            csiStageAlert(alert, l, true);
        } else if (l.motion && !sigAbove &&
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
        const CsiLink *target = nullptr;

        for (int i = 0; i < CSI_MAX_LINKS; i++) {
            CsiLink &l = g_links[i];
            if (!l.used) continue;

            const uint32_t pnow = l.sc.acfPairs;
            const float dpps = (float)(uint32_t)(pnow - l.pairsSnap) * 0.5f;
            l.pairsSnap = pnow;
            l.pairRate += 0.5f * (dpps - l.pairRate);
            if (csiLinkUsable(l) && (!target || l.rssi > target->rssi)) target = &l;

            const bool stale = (now - l.lastMs) >= CSI_LINK_STALE_MS;
            if (!stale) continue;

            if (l.motion) {
                l.motion = false;
                csiStageAlert(alerts[i], l, false);
            }
            l.consec = 0;
            l.elevMs = 0;
            if ((now - l.lastMs) >= CSI_LINK_FORGET_MS) l.used = false;
        }
        if (target) {
            memcpy(g_probeTarget, target->mac, 6);
            g_probeTargetSet = true;
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
        v.z = l.sc.acfZ;
        v.sig = csiTriggerRatio(l.sc.sigVar);
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
        uint8_t armed;
        {
            std::lock_guard<std::mutex> lock(g_csiMutex);
            usable = csiUsableCount();
            armed = csiArmedCount();
        }
        r += "Usable links: " + String(usable) + "\n";
        r += "Armed links: " + String(armed) + "\n";
        if (usable == 0) {
            r += "BLIND - no link reaches " + String((int)CSI_LINK_MIN_RSSI) + "dBm.\n"
                 "Motion cannot be detected. Move the node nearer an active AP or pick a busier channel.\n";
        } else if (armed == 0) {
            r += "BLIND - " + String(usable) + " link(s) in range but none armed.\n"
                 "Motion cannot be detected until a link settles.\n";
        }
    }
    r += "CSI records: " + String(g_csiSeen.load()) +
         "  rate: " + String(rate, 1) + "/s\n";
    r += "Rejected (FCS/40MHz/short): " + String(g_csiRejected.load()) + "\n";
    r += "Queue drops: " + String(g_csiDropped.load()) + "\n";
    r += "Motion events: " + String(g_csiMotionEvents.load()) + "\n";
    r += "Threshold: " + String(csiGateEta(csiThresholdMilli.load()), 3) +
         "x  Hold: " + String(csiHoldMs.load()) + "ms\n";
    r += "Min motion: " + String(csiAreaDutyMinS.load()) +
         "s  Spots: " + String(csiAreaRadiosNeeded.load()) + "\n\n";

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
    uint8_t armedNow;
    {
        std::lock_guard<std::mutex> lock(g_csiMutex);
        usableNow = csiUsableCount();
        armedNow = csiArmedCount();
    }
    j += ",\"usable\":" + String(usableNow);
    j += ",\"armed\":" + String(armedNow);
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
    j += ",\"threshold\":" + String(csiGateEta(csiThresholdMilli.load()), 3);
    j += ",\"dutyMinS\":" + String(csiAreaDutyMinS.load());
    j += ",\"spots\":" + String(csiAreaRadiosNeeded.load());
    j += ",\"voteFrac\":" + String(CSI_VOTE_FRAC, 2);
    j += ",\"uptime\":" + String(g_csiRunStartMs ? ((g_csiEndMs && g_csiEndMs >= g_csiRunStartMs ? g_csiEndMs : millis()) - g_csiRunStartMs) / 1000 : 0);
    j += ",\"sinceMotion\":" + String(g_areaLastMotionMs ? (int32_t)((millis() - g_areaLastMotionMs) / 1000) : -1);
    j += ",\"areaEvents\":" + String(g_epTotal);
    j += ",\"episodes\":[";
    for (uint8_t i = 0; i < g_epCount; i++) {
        const CsiEpisode &e = g_eps[(uint8_t)((g_epHead + CSI_EPISODES - 1 - i) % CSI_EPISODES)];
        if (i) j += ",";
        j += "{\"at\":\"" + String(e.at) + "\",\"dwell\":" + String(e.dwellSec) +
             ",\"peak\":" + String(e.open ? g_epPeak : e.peak, 2) +
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
        float liveLvl = (float)g_heatSum / (float)g_heatCurSec;
        if (liveLvl > 1.0f) liveLvl = 1.0f;
        j += String((uint8_t)(liveLvl * 255.0f + 0.5f));
    }
    j += "]";
    j += ",\"hot\":[";
    for (uint8_t i = 0; i < g_heatLen; i++) {
        if (i) j += ",";
        j += String(g_heatHot[i]);
    }
    if (g_heatCurSec > 0) {
        if (g_heatLen) j += ",";
        j += String(g_epTotal != g_heatEvSnap ? 1 : 0);
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
        j += ",\"z\":" + String(v.z, 2);
        j += ",\"sig\":" + String(v.sig, 2);
        j += ",\"events\":" + String(v.events);
        j += ",\"age\":" + String(v.ageMs / 1000);
        j += ",\"motion\":" + String(v.motion ? "true" : "false") + "}";
    }

    j += "]}";
    return j;
}

void csiClearCalibration() {
    csiThresholdMilli.store(0);
    prefs.putUInt("csiThr3", 0);
    Serial.println("[CSI] Manual trigger cleared - back to the compiled default");
}

void setCsiConfig(uint8_t channel, float threshold, uint32_t holdMs, uint32_t consec,
                  bool rawDump, bool telemetry) {
    if (channel <= 14) csiPinnedChannel.store(channel);
    if (threshold <= 0.0f) csiThresholdMilli.store(0);
    else if (threshold >= 0.005f && threshold <= 20.0f) csiThresholdMilli.store((uint32_t)(threshold * 1000.0f + 0.5f));
    if (holdMs >= 500 && holdMs <= 120000) csiHoldMs.store(holdMs);
    if (consec >= 1 && consec <= 50) csiConsecNeeded.store(consec);
    csiRawDump.store(rawDump);
    if (csiTelemetry.load() != telemetry) Serial.printf("[CSI] telemetry %s\n", telemetry ? "on" : "off");
    csiTelemetry.store(telemetry);

    if (prefs.isKey("csiCh")) prefs.remove("csiCh");
    prefs.putUInt("csiThr3", csiThresholdMilli.load());
    prefs.putUInt("csiHold", csiHoldMs.load());
    prefs.putUInt("csiCons", csiConsecNeeded.load());
}

void setCsiAreaConfig(uint32_t dutyMinS, uint32_t radiosNeeded) {
    if (dutyMinS >= 2 && dutyMinS <= 60) csiAreaDutyMinS.store(dutyMinS);
    if (radiosNeeded >= 1 && radiosNeeded <= 12) csiAreaRadiosNeeded.store(radiosNeeded);
    prefs.putUInt("csiDuty", csiAreaDutyMinS.load());
    prefs.putUInt("csiRad", csiAreaRadiosNeeded.load());
}

void loadCsiConfigFromPrefs() {
    if (prefs.isKey("csiThr2")) {
        prefs.remove("csiThr2");
        Serial.println("[CSI] removed stale csiThr2 from NVS (pre-sigvar threshold)");
    }
    csiPinnedChannel.store(0);
    uint32_t thrStored = prefs.getUInt("csiThr3", 0);
    if (thrStored != 0 && (thrStored < 5 || thrStored > 600)) thrStored = 0;
    csiThresholdMilli.store(thrStored);
    csiHoldMs.store(prefs.getUInt("csiHold", 5000));
    csiConsecNeeded.store(prefs.getUInt("csiCons", 3));
    csiAreaDutyMinS.store(prefs.getUInt("csiDuty", csiAreaDutyMinS.load()));
    csiAreaRadiosNeeded.store(prefs.getUInt("csiRad", csiAreaRadiosNeeded.load()));
    csiNoTx.store((uint8_t)prefs.getUInt("csiNoTx", 0));
    csiAllowRandom.store((uint8_t)prefs.getUInt("csiRnd", 0));
}

void setCsiNoTx(bool noTx) {
    csiNoTx.store(noTx ? 1 : 0);
    prefs.putUInt("csiNoTx", noTx ? 1 : 0);
    Serial.printf("[CSI] %s\n", noTx ? "listen only - this node will not transmit"
                                     : "transmit allowed - sends a probe request when traffic is thin");
}

static bool csiMoveRadio(uint8_t ch) {
    if (WiFi.softAPgetStationNum() > 0) {
        wifi_config_t apCfg = {};
        if (esp_wifi_get_config(WIFI_IF_AP, &apCfg) == ESP_OK && apCfg.ap.channel != ch) {
            apCfg.ap.channel = ch;
            if (apCfg.ap.csa_count == 0) apCfg.ap.csa_count = 3;
            const esp_err_t r = esp_wifi_set_config(WIFI_IF_AP, &apCfg);
            Serial.printf("[CSI] AP channel switch announced to ch%u (csa_count=%u): %s\n",
                          ch, apCfg.ap.csa_count, esp_err_to_name(r));
            if (r == ESP_OK) {
                vTaskDelay(pdMS_TO_TICKS(400));
                uint8_t priCh = 0;
                wifi_second_chan_t secCh = WIFI_SECOND_CHAN_NONE;
                if (esp_wifi_get_channel(&priCh, &secCh) == ESP_OK && priCh == ch) return true;
            }
        }
    }
    return esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE) == ESP_OK;
}

static void csiForceHt20() {
    wifi_bandwidths_t bw = {};
    bw.ghz_2g = WIFI_BW_HT20;
    bw.ghz_5g = WIFI_BW_HT20;
    const esp_err_t sta = esp_wifi_set_bandwidths(WIFI_IF_STA, &bw);
    const esp_err_t ap = esp_wifi_set_bandwidths(WIFI_IF_AP, &bw);
    Serial.printf("[CSI] bandwidth HT20 sta=%s ap=%s\n",
                  esp_err_to_name(sta), esp_err_to_name(ap));
}

static bool csiArmCsi(uint8_t ch) {
    csiMoveRadio(ch);
    csiForceHt20();

    wifi_csi_config_t cfg = {};
#if CONFIG_SOC_WIFI_HE_SUPPORT
    cfg.enable = 1;
    cfg.acquire_csi_legacy = 1;
    cfg.acquire_csi_force_lltf = CSI_FORCE_LLTF;
    cfg.acquire_csi_ht20 = 1;
    cfg.acquire_csi_ht40 = 1;
    cfg.acquire_csi_vht = 0;
    cfg.acquire_csi_su = 0;
    cfg.acquire_csi_mu = 0;
    cfg.acquire_csi_dcm = 0;
    cfg.acquire_csi_beamformed = 0;
    cfg.acquire_csi_he_stbc_mode = 2;
    cfg.val_scale_cfg = 0;
    cfg.lltf_bit_mode = 0;
    cfg.dump_ack_en = (csiSolicitMs.load() != 0) || !csiNoTx.load();
#else
    cfg.lltf_en = true;
    cfg.htltf_en = true;
    cfg.stbc_htltf2_en = true;
    cfg.ltf_merge_en = false;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = (csiSolicitMs.load() != 0) || !csiNoTx.load();
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
    filter.filter_mask = csiMgmtOnly.load()
                             ? WIFI_PROMIS_FILTER_MASK_MGMT
                             : (WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA);
    esp_wifi_set_promiscuous_filter(&filter);
    Serial.printf("[CSI] promisc filter=%s\n", csiMgmtOnly.load() ? "MGMT" : "MGMT|DATA");
    esp_wifi_set_promiscuous_rx_cb(&csi_prom_cb);
    esp_wifi_set_ps(WIFI_PS_NONE);

    esp_err_t rp = esp_wifi_set_promiscuous(true);
    if (rp != ESP_OK) {
        Serial.printf("[CSI] promiscuous enable failed: %s\n", esp_err_to_name(rp));
        return false;
    }

    csiMoveRadio(ch);
    csiForceHt20();
    vTaskDelay(pdMS_TO_TICKS(50));

    wifi_csi_config_t cfg = {};
#if CONFIG_SOC_WIFI_HE_SUPPORT
    cfg.enable = 1;
    cfg.acquire_csi_legacy = 1;
    cfg.acquire_csi_force_lltf = CSI_FORCE_LLTF;
    cfg.acquire_csi_ht20 = 1;
    cfg.acquire_csi_ht40 = 1;
    cfg.acquire_csi_vht = 0;
    cfg.acquire_csi_su = 0;
    cfg.acquire_csi_mu = 0;
    cfg.acquire_csi_dcm = 0;
    cfg.acquire_csi_beamformed = 0;
    cfg.acquire_csi_he_stbc_mode = 2;
    cfg.val_scale_cfg = 0;
    cfg.lltf_bit_mode = 0;
    cfg.dump_ack_en = (csiSolicitMs.load() != 0) || !csiNoTx.load();
#else
    cfg.lltf_en = true;
    cfg.htltf_en = true;
    cfg.stbc_htltf2_en = true;
    cfg.ltf_merge_en = false;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = (csiSolicitMs.load() != 0) || !csiNoTx.load();
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
        if (g_gring == nullptr) {
            const size_t bytes = sizeof(float) * CSI_MAX_LINKS * CsiScorer::windowFloats();
            g_gring = static_cast<float *>(heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
            Serial.printf("[CSI] psi window ring %s (%u bytes)\n", g_gring ? "allocated" : "ALLOC FAILED", (unsigned)bytes);
        }
        for (int i = 0; i < CSI_MAX_LINKS; i++) {
            g_links[i].sc.attachWindow(g_gring ? (g_gring + (size_t)i * CsiScorer::windowFloats()) : nullptr);
            csiLinkReset(g_links[i]);
        }
    }

    g_csiSeen.store(0);
    g_csiDropped.store(0);
    g_csiRejected.store(0);
    g_csiMotionEvents.store(0);
    g_promFrames.store(0);
    g_areaMotion = false;
    g_areaCand = false;
    g_areaCandSince = 0;
    memset(g_areaDuty, 0, sizeof(g_areaDuty));
    g_areaDutyPos = 0;
    g_areaSinceMs = 0;
    g_areaLastMotionMs = 0;
    csiEpisodesReset();
    g_heatLen = 0;
    g_heatSec = 60;
    g_heatStep = 0;
    g_heatSum = 0;
    g_heatHotCur = 0;
    g_heatCurSec = 0;
    g_heatEvSnap = g_epTotal;
    g_csiStartMs = millis();
    g_csiRunStartMs = g_csiStartMs;
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

    if (!csiRadioStart(ch ? ch : apHomeChannel())) {
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
        csiMoveRadio(ch);
        vTaskDelay(pdMS_TO_TICKS(50));
        xQueueReset(csiQueue);
        if (!csiArmCsi(ch)) Serial.println("[CSI] re-arm after survey failed");
    }

    g_csiActiveChannel = ch;
    g_csiSeen.store(0);
    g_csiRejected.store(0);
    g_csiDropped.store(0);
    g_phyDsss.store(0);
    g_phyOfdm.store(0);
    g_phyHt.store(0);
    g_phyOther.store(0);
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
            csiMoveRadio(ch);
            vTaskDelay(pdMS_TO_TICKS(30));
            if (esp_wifi_get_channel(&priCh, &secCh) == ESP_OK) {
                Serial.printf("[CSI] radio channel after re-apply: ch%u\n", priCh);
                if (priCh != ch) {
                    Serial.printf("[CSI] channel change REFUSED, running on ch%u not ch%u\n",
                                  priCh, ch);
                    g_csiActiveChannel = priCh;
                }
            }
        }
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
    uint32_t statSeenSnap = 0;
    uint32_t lastRollMs = millis();
    uint32_t lastStallMs = millis();
    uint32_t lastSeenSnap = 0;
    uint32_t lastRejSnap = 0;
    uint32_t blindSinceMs = 0;
    uint32_t lastRehopMs = 0;
    uint16_t blindMask = 0;
    uint32_t rollSeenSnap = 0;
    uint32_t lastSolicitMs = millis();
    uint32_t lastSolicitSeen = 0;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - startMs) < duration * 1000 && !stopRequested)) {

        CsiEvent ev;
        const uint32_t solicitMs = csiSolicitMs.load();
        if (xQueueReceive(csiQueue, &ev, pdMS_TO_TICKS(solicitMs ? 5 : 100)) == pdTRUE) {
            csiProcess(ev);
            for (uint16_t burst = 0; burst < CSI_DRAIN_BURST; burst++) {
                if (xQueueReceive(csiQueue, &ev, 0) != pdTRUE) break;
                csiProcess(ev);
            }
        }

        const uint32_t now = millis();


        if (now - lastExpireMs >= 2000) {
            lastExpireMs = now;
            csiExpireLinks();

            int movingLinks = 0;
            int armedLinks = 0;
            float peak = 0.0f;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                armedLinks = csiCountRadios(false);
                movingLinks = csiCountRadios(true);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].motion) continue;
                    if (g_links[i].sc.score > peak) peak = g_links[i].sc.score;
                }
            }

            const int needLinks = csiNeedLinks(armedLinks);

            g_areaDuty[g_areaDutyPos] = (uint8_t)(movingLinks >= needLinks ? 1 : 0);
            g_areaDutyPos = (uint8_t)((g_areaDutyPos + 1) % CSI_AREA_DUTY_SLOTS);
            uint32_t dutySec = 0;
            for (uint8_t s = 0; s < CSI_AREA_DUTY_SLOTS; s++) dutySec += g_areaDuty[s] * 2u;
            const bool areaNow = (dutySec >= csiAreaDutyMinS.load()) && (movingLinks >= needLinks);
            if (areaNow) g_areaLastMotionMs = now;
            if (csiTelemetry.load()) {
                Serial.printf("[CSIA] mv=%d armed=%d need=%d duty=%u peak=%.2f area=%d\n",
                              movingLinks, armedLinks, needLinks, (unsigned)dutySec, peak, areaNow ? 1 : 0);
            }

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
                    Serial.printf("[CSI] AREA MOTION (held %us) links=%u/%u peak=%.2f\n",
                                  CSI_AREA_DEBOUNCE_MS / 1000, (unsigned)movingLinks,
                                  (unsigned)csiNeedLinks(armedLinks), peak);
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
            {
                float peakNow = 0.0f;
                {
                    std::lock_guard<std::mutex> lock(g_csiMutex);
                    for (int i = 0; i < CSI_MAX_LINKS; i++) {
                        const CsiLink &l = g_links[i];
                        if (!l.used || !l.sc.settled() || l.packets < CSI_LINK_MIN_PKTS) continue;
                        if (!csiLinkUsable(l)) continue;
                        const float r = csiTriggerRatio(l.sc.sigVar);
                        if (r > peakNow) peakNow = r;
                    }
                }
                if (g_areaMotion && peakNow > g_epPeak) g_epPeak = peakNow;
                csiHeatPush(g_areaMotion, peakNow);
            }
            if (uxQueueMessagesWaiting(csiQueue) == 0) {
                String snap = getCsiResults();
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = std::string(snap.c_str());
            }
        }

        if (solicitMs) {
            if (now - lastSolicitMs >= solicitMs) {
                csiPollClients();
                csiSolicit();
                lastSolicitMs = now;
            }
        } else if (now - lastSolicitMs >= 1000) {
            const uint32_t seenNow = g_csiUsedSeen.load();
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
            uint8_t armedRoll = 0;
            uint8_t windowRoll = 0;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                usableRoll = csiUsableCount();
                armedRoll = csiArmedCount();
                windowRoll = csiWindowCapableCount();
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].sc.settled()) continue;
                    if (g_links[i].motion) movingRoll++;
                    if (g_links[i].sc.score > peakRoll) peakRoll = g_links[i].sc.score;
                }
            }
            Serial.printf("[CSI] STATE %s peak=%.2f links=%d usable=%u armed=%u fast=%u need=%u events=%u up=%us\n",
                          windowRoll == 0 ? "BLIND" : (g_areaMotion ? "MOVE" : "quiet"),
                          peakRoll, movingRoll, usableRoll, armedRoll, windowRoll,
                          (unsigned)csiNeedLinks(armedRoll),
                          g_csiMotionEvents.load(), (now - g_csiStartMs) / 1000);
            if (armedRoll == 0 && usableRoll > 0) {
                Serial.printf("[CSI] BLIND: %u link(s) in range but none armed - cannot detect motion\n",
                              usableRoll);
            }
            if (windowRoll == 0 && armedRoll > 0) {
                Serial.printf("[CSI] BLIND: %u armed link(s) but none reaches %.1f pkt/s - cannot fill a window on ch%u\n",
                              armedRoll, CSI_LINK_MIN_PAIR_RATE, g_csiActiveChannel);
            }
            if (g_memcpyBadLenRejects) {
                Serial.printf("[WIFI] blob bad-length memcpy rejected: n=%u count=%u\n",
                              (unsigned)g_memcpyBadLenLast, (unsigned)g_memcpyBadLenRejects);
            }
            const uint32_t rollSeenNow = g_csiSeen.load();
            const uint32_t rollRecords = rollSeenNow - rollSeenSnap;
            rollSeenSnap = rollSeenNow;
            const bool starved = (rollRecords < CSI_SOLICIT_FLOOR * 60u);
            if (starved) {
                Serial.printf("[CSI] STARVED: %u records in 60s on ch%u - too little traffic to detect motion\n",
                              rollRecords, g_csiActiveChannel);
            }
            if (windowRoll == 0 || starved) {
                if (usableRoll == 0)
                    Serial.printf("[CSI] BLIND: no link reaches %ddBm - cannot detect motion on ch%u\n",
                                  (int)CSI_LINK_MIN_RSSI, g_csiActiveChannel);
                if (blindSinceMs == 0) blindSinceMs = now;
                if (autoChannel && (now - blindSinceMs) >= CSI_BLIND_REHOP_MS &&
                    (lastRehopMs == 0 || (now - lastRehopMs) >= CSI_REHOP_COOLDOWN_MS)) {
                    const uint32_t blindFor = (now - blindSinceMs) / 1000;
                    lastRehopMs = now;
                    blindSinceMs = 0;
                    const uint16_t curBit = (g_csiActiveChannel <= 14) ? (uint16_t)(1u << g_csiActiveChannel) : 0;
                    blindMask |= curBit;
                    uint8_t next = csiSurveyPickChannel(CSI_SURVEY_DWELL_MS, blindMask);
                    if (next == 0) {
                        blindMask = curBit;
                        next = csiSurveyPickChannel(CSI_SURVEY_DWELL_MS, blindMask);
                    }
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
                blindMask = 0;
            }
        }

        if (now - lastStatMs >= 15000) {
            const uint32_t statMs = now - lastStatMs;
            lastStatMs = now;
            const uint32_t statSeenNow = g_csiSeen.load();
            const float statRateNow = (float)(statSeenNow - statSeenSnap) * 1000.0f /
                                      (float)statMs;
            statSeenSnap = statSeenNow;
            const uint32_t span = now - startMs;
            float statAcfMax = 0.0f, statAcfMin = 1.0f, statVoteMax = 0.0f;
            float statZMax = 0.0f, statFloorMax = 0.0f, statSigMax = 0.0f;
            uint8_t statLinks = 0, statPassEta = 0, statPassVote = 0;
            uint32_t statPairs = 0;
            float statPrMax = 0.0f;
            {
                const uint32_t thrMilli = csiThresholdMilli.load();
                std::lock_guard<std::mutex> lock(g_csiMutex);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    const CsiLink &l = g_links[i];
                    if (!l.used) continue;
                    if (l.pairRate > statPrMax) statPrMax = l.pairRate;
                    if (!l.sc.settled() || !csiLinkUsable(l)) continue;
                    statLinks++;
                    if (l.sc.acf > statAcfMax) statAcfMax = l.sc.acf;
                    if (l.sc.acf < statAcfMin) statAcfMin = l.sc.acf;
                    if (l.sc.vote > statVoteMax) statVoteMax = l.sc.vote;
                    if (l.sc.sigVar >= csiGateEta(thrMilli) && l.sc.sigZ >= CSI_SIG_Z_GATE) statPassEta++;
                    if (l.sc.vote >= CSI_VOTE_FRAC) statPassVote++;
                    if (l.sc.acfZ > statZMax) statZMax = l.sc.acfZ;
                    if (l.sc.sigVar > statSigMax) statSigMax = l.sc.sigVar;
                    if (l.sc.acfFloor > statFloorMax) statFloorMax = l.sc.acfFloor;
                    statPairs += l.sc.acfPairs;
                }
            }
            Serial.printf("[CSI] ch%u records=%u rate=%.1f/s rejected=%u drops=%u events=%u | "
                          "links=%u acf=%.3f..%.3f vote=%.2f z=%.1f sig=%.4f acffloor=%.3f pairs=%u pr=%.1f "
                          "pass-eta=%u pass-vote=%u fmtdrop=%u fw=%u frames=%u tx=%u/%u err=%d poll=%u/%u perr=%d sta=%u "
                          "len=%u/%u:%u %u/%u:%u ce=%u/%u celen=%u stale=%u "
                          "phy=b:%u/g:%u/ht:%u/x:%u now=%.1f/s\n",
                          g_csiActiveChannel, g_csiSeen.load(),
                          (float)g_csiSeen.load() * 1000.0f / (float)(span ? span : 1),
                          g_csiRejected.load(), g_csiDropped.load(), g_csiMotionEvents.load(),
                          statLinks, statLinks ? statAcfMin : 0.0f, statAcfMax, statVoteMax,
                          statZMax, statSigMax, statFloorMax, statPairs, statPrMax,
                          statPassEta, statPassVote, g_rejFmt.load(), g_fwSkip.load(), g_promFrames.load(),
                          g_solicitOk.load(), g_solicitErr.load(), (int)g_solicitLastErr.load(),
                          g_pollOk.load(), g_pollErr.load(), (int)g_pollLastErr.load(),
                          (unsigned)g_apStas.num,
                          (unsigned)g_lenVal[0], (unsigned)g_lenFmt[0], (unsigned)g_lenCnt[0],
                          (unsigned)g_lenVal[1], (unsigned)g_lenFmt[1], (unsigned)g_lenCnt[1],
                          g_ceVld.load(), g_ceInvld.load(), g_ceLen.load(), g_rejStale.load(),
                          g_phyDsss.load(), g_phyOfdm.load(), g_phyHt.load(), g_phyOther.load(),
                          statRateNow);
            if (g_areaMotion) {
                Serial.printf("[CSI] AREA HELD %us on ch%u\n",
                              (unsigned)((now - g_areaSinceMs) / 1000), g_csiActiveChannel);
            }
            if (csiTelemetry.load()) {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    const CsiLink &l = g_links[i];
                    if (!l.used) continue;
                    Serial.printf("[CSIL] %s rssi=%d set=%d use=%d mot=%d vote=%.2f psi=%.3f acf=%.3f sig=%.4f score=%.2f psiz=%.1f pfloor=%.3f pr=%.1f lag=%u/%u/%u/%u/%u pspread=%.4f phold=%u consec=%u elev=%u above=%u\n",
                                  macFmt6(l.mac).c_str(), l.rssi, l.sc.settled() ? 1 : 0,
                                  csiLinkUsable(l) ? 1 : 0, l.motion ? 1 : 0,
                                  l.sc.vote, l.sc.psi, l.sc.acf, l.sc.sigVar, l.sc.score, l.sc.psiZ, l.sc.psiFloor, l.pairRate,
                                  (unsigned)l.sc.lagBkt[0], (unsigned)l.sc.lagBkt[1],
                                  (unsigned)l.sc.lagBkt[2], (unsigned)l.sc.lagBkt[3],
                                  (unsigned)l.sc.lagBkt[4], l.sc.psiSpread, (unsigned)(l.sc.psiHoldUs / 1000u),
                                  (unsigned)l.consec, (unsigned)l.elevMs,
                                  (unsigned)(l.lastAboveMs ? (millis() - l.lastAboveMs) : 0));
                }
            }
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

    finalResults = String();

    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}
