#include "csi.h"
#include "network.h"
#include "scanner.h"
#include "hardware.h"
#include "detect.h"
#include "main.h"

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
std::atomic<uint32_t> csiThresholdMilli{1500};
std::atomic<uint32_t> csiHoldMs{5000};
std::atomic<uint32_t> csiConsecNeeded{3};

static const uint32_t CSI_LINK_STALE_MS = 20000;
static const uint32_t CSI_SURVEY_DWELL_MS = 700;
static const uint32_t CSI_CAL_MS = 20000;
static const float CSI_CAL_MARGIN = 1.50f;
static const float CSI_TRIG_MIN = 1.15f;
static const float CSI_TRIG_MAX = 6.0f;

static std::atomic<bool> g_surveyMode{false};
static std::atomic<uint32_t> g_surveyHits{0};
static std::atomic<uint32_t> g_surveyTx{0};
static uint8_t g_surveyMacs[16][6];
static uint8_t g_surveyMacCount = 0;

static const uint8_t CSI_HEAT_CELLS = 120;
static uint8_t g_heat[CSI_HEAT_CELLS];
static uint8_t g_heatLen = 0;
static uint16_t g_heatSec = 5;
static uint32_t g_heatSum = 0;
static uint16_t g_heatCurSec = 0;

static void csiHeatPush(float act) {
    uint16_t q = (uint16_t)(act * 50.0f);
    if (q > 255) q = 255;
    g_heatSum += q;
    g_heatCurSec++;
    if (g_heatCurSec < g_heatSec) return;

    const uint8_t cell = (uint8_t)(g_heatSum / g_heatCurSec);
    g_heatSum = 0;
    g_heatCurSec = 0;

    if (g_heatLen < CSI_HEAT_CELLS) {
        g_heat[g_heatLen++] = cell;
    } else {
        for (uint8_t i = 0; i < CSI_HEAT_CELLS / 2; i++) {
            g_heat[i] = (uint8_t)(((uint16_t)g_heat[i * 2] + (uint16_t)g_heat[i * 2 + 1]) / 2);
        }
        g_heatLen = CSI_HEAT_CELLS / 2;
        g_heatSec *= 2;
        g_heat[g_heatLen++] = cell;
    }
}

static const uint16_t CSI_DRAIN_BURST = 64;
static const uint32_t CSI_MOTION_MIN_MS = 2000;
static const uint32_t CSI_AREA_DEBOUNCE_MS = 15000;
static bool g_areaMotion = false;
static bool g_areaCand = false;
static uint32_t g_areaCandSince = 0;
static uint32_t g_areaSinceMs = 0;
static uint32_t g_areaLastMotionMs = 0;

static bool g_calActive = false;
static float g_calSum = 0.0f;
static uint32_t g_calSamples = 0;
static float g_calTrigger = 0.0f;

struct CsiEvent {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t ch;
    uint32_t ts;
    int8_t buf[128];
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
    uint32_t aboveSinceMs;
    uint32_t motionStartMs;
    uint32_t events;
};

static CsiLink g_links[CSI_MAX_LINKS];
static std::mutex g_csiMutex;
static QueueHandle_t csiQueue = nullptr;

static std::atomic<uint32_t> g_csiSeen{0};
static std::atomic<uint32_t> g_csiDropped{0};
static std::atomic<uint32_t> g_csiRejected{0};
static std::atomic<uint32_t> g_csiMotionEvents{0};
static uint32_t g_csiStartMs = 0;
static uint32_t g_csiEndMs = 0;
static uint8_t g_csiActiveChannel = 0;

// cppcheck-suppress constParameterCallback // wifi_csi_cb_t signature is fixed by esp_wifi_set_csi_rx_cb
static void csi_rx_cb(void *ctx, wifi_csi_info_t *info) {
    if (!info || !info->buf || !csiQueue) return;

    const wifi_pkt_rx_ctrl_t &rx = info->rx_ctrl;
    if (rx.rx_state != 0) {
        g_csiRejected.fetch_add(1);
        return;
    }
#if CONFIG_SOC_WIFI_HE_SUPPORT
    if (rx.second != 0 ||
        (rx.cur_bb_format != RX_BB_FORMAT_11G && rx.cur_bb_format != RX_BB_FORMAT_HT)) {
        g_csiRejected.fetch_add(1);
        return;
    }
#else
    if (rx.cwb != 0 || rx.secondary_channel != 0) {
        g_csiRejected.fetch_add(1);
        return;
    }
#endif
    if (info->len < 128) {
        g_csiRejected.fetch_add(1);
        return;
    }

    const uint8_t *m = info->mac;
    if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0) {
        g_csiRejected.fetch_add(1);
        return;
    }

    if (g_surveyMode.load()) {
        g_surveyHits.fetch_add(1);
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
    memcpy(ev.buf, info->buf, 128);

    g_csiSeen.fetch_add(1);
    if (xQueueSend(csiQueue, &ev, 0) != pdTRUE) g_csiDropped.fetch_add(1);
}

static uint8_t csiSurveyPickChannel(uint32_t dwellMs) {
    std::vector<uint8_t> chans;
    for (uint8_t c : CHANNELS) {
        if (c >= 1 && c <= 14) chans.push_back(c);
    }
    if (chans.empty()) chans = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    Serial.printf("[CSI] Surveying %u channels for traffic (%ums each)...\n",
                  (unsigned)chans.size(), dwellMs);

    uint8_t best = chans[0];
    uint32_t bestHits = 0;
    uint32_t bestTx = 0;

    for (uint8_t ch : chans) {
        if (stopRequested) break;

        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(30));

        g_surveyHits.store(0);
        g_surveyTx.store(0);
        g_surveyMacCount = 0;
        g_surveyMode.store(true);
        vTaskDelay(pdMS_TO_TICKS(dwellMs));
        g_surveyMode.store(false);

        const uint32_t hits = g_surveyHits.load();
        const uint32_t tx = g_surveyTx.load();
        const float rate = (float)hits * 1000.0f / (float)dwellMs;
        Serial.printf("[CSI]   ch%-3u %5u records  %5.1f/s  %u transmitters\n", ch, hits, rate, tx);

        if (hits > bestHits) {
            bestHits = hits;
            bestTx = tx;
            best = ch;
        }
    }

    if (bestHits == 0) {
        Serial.println("[CSI] No CSI-eligible traffic on any surveyed channel");
        return 0;
    }

    Serial.printf("[CSI] Selected ch%u (%u records, %.1f/s, %u transmitters)\n",
                  best, bestHits, (float)bestHits * 1000.0f / (float)dwellMs, bestTx);
    return best;
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
    l.aboveSinceMs = 0;
    l.motionStartMs = 0;
    l.events = 0;
}

static CsiLink *csiFindLink(const uint8_t *mac) {
    CsiLink *freeSlot = nullptr;
    CsiLink *oldest = nullptr;

    for (int i = 0; i < CSI_MAX_LINKS; i++) {
        CsiLink &l = g_links[i];
        if (l.used && memcmp(l.mac, mac, 6) == 0) return &l;
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
                     String(ev.rssi) + "," + String(ev.ch) + ",64";
        for (int idx = 0; idx < 64; idx++) {
            row += "," + String((int)ev.buf[idx * 2]) + "," + String((int)ev.buf[idx * 2 + 1]);
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

        const float thresh = (float)csiThresholdMilli.load() / 1000.0f;
        const uint32_t consecNeeded = csiConsecNeeded.load();
        const uint32_t hold = csiHoldMs.load();

        if (l.sc.score >= thresh) {
            if (l.consec == 0) l.aboveSinceMs = now;
            l.lastAboveMs = now;
            if (l.consec < 255) l.consec++;
        } else {
            l.consec = 0;
            l.aboveSinceMs = 0;
        }

        if (g_calActive || !l.sc.settled()) return;

        if (l.packets < CSI_LINK_MIN_PKTS) return;

        const bool heldLongEnough = l.aboveSinceMs && (now - l.aboveSinceMs) >= CSI_MOTION_MIN_MS;

        if (!l.motion && l.consec >= consecNeeded && heldLongEnough) {
            l.motion = true;
            l.motionStartMs = now;
            l.events++;
            g_csiMotionEvents.fetch_add(1);
            csiStageAlert(alert, l, true);
        } else if (l.motion && l.sc.score < thresh && (now - l.lastAboveMs) >= hold) {
            l.motion = false;
            l.consec = 0;
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

    bool anyMotion = false;
    for (int i = 0; i < n; i++) if (views[i].motion) anyMotion = true;

    String j = "{\"channel\":" + String(g_csiActiveChannel);
    j += ",\"records\":" + String(g_csiSeen.load());
    j += ",\"rate\":" + String(rate, 2);
    j += ",\"rejected\":" + String(g_csiRejected.load());
    j += ",\"drops\":" + String(g_csiDropped.load());
    j += ",\"events\":" + String(g_csiMotionEvents.load());
    j += ",\"motion\":" + String(anyMotion ? "true" : "false");
    j += ",\"threshold\":" + String((float)csiThresholdMilli.load() / 1000.0f, 2);
    j += ",\"calibrated\":" + String(prefs.getBool("csiCalDone", false) ? "true" : "false");
    j += ",\"uptime\":" + String(g_csiStartMs ? ((g_csiEndMs ? g_csiEndMs : millis()) - g_csiStartMs) / 1000 : 0);
    j += ",\"sinceMotion\":" + String(g_areaLastMotionMs ? (int32_t)((millis() - g_areaLastMotionMs) / 1000) : -1);
    j += ",\"heatSec\":" + String(g_heatSec);
    j += ",\"heat\":[";
    for (uint8_t i = 0; i < g_heatLen; i++) {
        if (i) j += ",";
        j += String(g_heat[i]);
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
    if (threshold >= 1.2f && threshold <= 20.0f) csiThresholdMilli.store((uint32_t)(threshold * 1000.0f));
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
    csiThresholdMilli.store(prefs.getUInt("csiThr", 1500));
    csiHoldMs.store(prefs.getUInt("csiHold", 5000));
    csiConsecNeeded.store(prefs.getUInt("csiCons", 3));
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
    esp_wifi_set_promiscuous_rx_cb(NULL);

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
    cfg.dump_ack_en = 0;
#else
    cfg.lltf_en = true;
    cfg.htltf_en = false;
    cfg.stbc_htltf2_en = false;
    cfg.ltf_merge_en = false;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = false;
#endif

    esp_err_t rc = esp_wifi_set_csi_config(&cfg);
    if (rc != ESP_OK) {
        Serial.printf("[CSI] set_csi_config failed: %s\n", esp_err_to_name(rc));
        esp_wifi_set_promiscuous(false);
        return false;
    }

    esp_err_t rb = esp_wifi_set_csi_rx_cb(&csi_rx_cb, nullptr);
    if (rb != ESP_OK) {
        Serial.printf("[CSI] set_csi_rx_cb failed: %s\n", esp_err_to_name(rb));
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
    sentinel_kill();

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
    g_calActive = false;
    g_calSum = 0.0f;
    g_calSamples = 0;
    g_calTrigger = 0.0f;
    g_areaMotion = false;
    g_areaCand = false;
    g_areaCandSince = 0;
    g_areaSinceMs = 0;
    g_areaLastMotionMs = 0;
    g_heatLen = 0;
    g_heatSec = 5;
    g_heatSum = 0;
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

    Serial.printf("[CSI] Pinned to ch%u - web UI reachable only while ch%u is the SoftAP channel\n", ch, ch);

    if (csiAutoTrigger.load()) {
        g_calActive = true;
        Serial.printf("[CSI] Learning trigger from this area for %us - keep it empty\n", CSI_CAL_MS / 1000);
    } else {
        Serial.printf("[CSI] Trigger %.2fx (self-normalising, no setup needed)\n",
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

        if (g_calActive && (now - g_csiStartMs) >= CSI_CAL_MS) {
            std::lock_guard<std::mutex> lock(g_csiMutex);
            g_calActive = false;
            if (g_calSamples >= 50) {
                const float stillMean = g_calSum / (float)g_calSamples;
                float t = stillMean * CSI_CAL_MARGIN;
                if (t < CSI_TRIG_MIN) t = CSI_TRIG_MIN;
                if (t > CSI_TRIG_MAX) t = CSI_TRIG_MAX;
                g_calTrigger = t;
                csiThresholdMilli.store((uint32_t)(t * 1000.0f));
                prefs.putUInt("csiThr", csiThresholdMilli.load());
                prefs.putBool("csiCalDone", true);
                Serial.printf("[CSI] Calibrated: baseline mean %.2fx over %u samples -> trigger %.2fx (saved)\n",
                              stillMean, g_calSamples, t);
            } else {
                Serial.printf("[CSI] Calibration skipped: only %u scored samples in %us, keeping trigger %.2fx\n",
                              g_calSamples, CSI_CAL_MS / 1000,
                              (float)csiThresholdMilli.load() / 1000.0f);
            }
        }

        if (now - lastExpireMs >= 2000) {
            lastExpireMs = now;
            csiExpireLinks();

            int movingLinks = 0;
            float peak = 0.0f;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].motion) continue;
                    movingLinks++;
                    if (g_links[i].sc.score > peak) peak = g_links[i].sc.score;
                }
            }

            const bool areaNow = (movingLinks > 0);
            if (areaNow) g_areaLastMotionMs = now;

            if (areaNow != g_areaCand) {
                g_areaCand = areaNow;
                g_areaCandSince = now;
            }

            if (g_areaCand != g_areaMotion && (now - g_areaCandSince) >= CSI_AREA_DEBOUNCE_MS) {
                g_areaMotion = g_areaCand;
                if (g_areaMotion) {
                    g_areaSinceMs = g_areaCandSince;
                    if (meshEnabled) {
                        meshEnqueuePrio(getNodeId() + ": CSI_MOTION: CH=" + String(g_csiActiveChannel) +
                                        " N=" + String(movingLinks) +
                                        " S=" + String(peak, 2), PRIO_EVENT);
                    }
                    Serial.printf("[CSI] AREA MOTION (held %us)\n", CSI_AREA_DEBOUNCE_MS / 1000);
                } else {
                    const uint32_t dwell = (g_areaCandSince - g_areaSinceMs) / 1000;
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
                    std::lock_guard<std::mutex> lock(g_csiMutex);
                    for (int i = 0; i < CSI_MAX_LINKS; i++) {
                        if (g_links[i].used && g_links[i].sc.settled() &&
                            g_links[i].packets >= CSI_LINK_MIN_PKTS &&
                            g_links[i].sc.score > peakNow)
                            peakNow = g_links[i].sc.score;
                    }
                }
                csiHeatPush(peakNow);
            }
            if (uxQueueMessagesWaiting(csiQueue) == 0) {
                String snap = getCsiResults();
                std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
                antihunter::lastResults = std::string(snap.c_str());
            }
        }

        if (now - lastRollMs >= 60000) {
            lastRollMs = now;
            float peakRoll = 0.0f;
            int movingRoll = 0;
            {
                std::lock_guard<std::mutex> lock(g_csiMutex);
                for (int i = 0; i < CSI_MAX_LINKS; i++) {
                    if (!g_links[i].used || !g_links[i].sc.settled()) continue;
                    if (g_links[i].motion) movingRoll++;
                    if (g_links[i].sc.score > peakRoll) peakRoll = g_links[i].sc.score;
                }
            }
            Serial.printf("[CSI] STATE %s peak=%.2f links=%d events=%u up=%us\n",
                          g_areaMotion ? "MOVE" : "quiet", peakRoll, movingRoll,
                          g_csiMotionEvents.load(), (now - g_csiStartMs) / 1000);
        }

        if (now - lastStatMs >= 15000) {
            lastStatMs = now;
            const uint32_t span = now - startMs;
            Serial.printf("[CSI] ch%u records=%u rate=%.1f/s rejected=%u drops=%u events=%u\n",
                          g_csiActiveChannel, g_csiSeen.load(),
                          (float)g_csiSeen.load() * 1000.0f / (float)(span ? span : 1),
                          g_csiRejected.load(), g_csiDropped.load(), g_csiMotionEvents.load());
        }
    }

    {
        CsiAlert finalAlerts[CSI_MAX_LINKS] = {};
        {
            std::lock_guard<std::mutex> lock(g_csiMutex);
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
