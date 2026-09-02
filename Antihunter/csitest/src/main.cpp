#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <math.h>

static const uint8_t TEST_CH = 11;
static const uint32_t PHASE_MS = 20000;
static const int ROUNDS = 12;

struct Phase {
    const char *name;
    bool htltf;
    bool stbc;
    bool merge;
};

static const Phase PHASES[] = {
    {"lltf-only",        false, false, false},
    {"lltf+ht",          true,  false, false},
    {"lltf+ht+stbc",     true,  true,  false},
    {"lltf+ht+stbc+mrg", true,  true,  true},
};
static const int NPHASE = sizeof(PHASES) / sizeof(PHASES[0]);

static volatile uint32_t cnt128 = 0, cnt256 = 0, cnt384 = 0, cntOther = 0, cntTotal = 0;
static volatile double corrSum128 = 0.0;
static volatile uint32_t corrN128 = 0;
static volatile double corrSumHT = 0.0;
static volatile uint32_t corrNHT = 0;
static volatile double corrSumCtl = 0.0;
static volatile uint32_t corrNCtl = 0;
static volatile uint32_t promFrames = 0;

static float corrOf(const float *a, int n) {
    double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    int m = 0;
    for (int k = 0; k < n - 1; k++) {
        const double x = a[k], y = a[k + 1];
        if (x <= 0.0 && y <= 0.0) continue;
        sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y;
        m++;
    }
    if (m < 8) return NAN;
    const double num = m * sxy - sx * sy;
    const double den = sqrt((m * sxx - sx * sx) * (m * syy - sy * sy));
    if (den <= 0.0) return NAN;
    return (float)(num / den);
}

static float adjCorrFirst128(const int8_t *b, float *ctlOut) {
    float a[64];
    for (int k = 0; k < 64; k++) {
        const float im = (float)b[k * 2];
        const float re = (float)b[k * 2 + 1];
        a[k] = sqrtf(im * im + re * re);
    }
    float sh[64];
    for (int k = 0; k < 64; k++) sh[k] = a[(k * 29 + 7) & 63];
    *ctlOut = corrOf(sh, 64);
    return corrOf(a, 64);
}

static void csiCb(void *ctx, wifi_csi_info_t *info) {
    (void)ctx;
    if (!info || !info->buf) return;
    const int len = info->len;
    cntTotal++;
    if (len == 128) cnt128++;
    else if (len == 256) cnt256++;
    else if (len == 384) cnt384++;
    else cntOther++;
    if (len < 128) return;
    float ctl = NAN;
    const float r = adjCorrFirst128(info->buf, &ctl);
    if (!isnan(r)) {
        if (len == 128) { corrSum128 += r; corrN128++; }
        else { corrSumHT += r; corrNHT++; }
    }
    if (!isnan(ctl)) { corrSumCtl += ctl; corrNCtl++; }
}

static void promCb(void *buf, wifi_promiscuous_pkt_type_t t) { (void)buf; (void)t; promFrames++; }

static void applyPhase(const Phase &p) {
    esp_wifi_set_csi(false);
    wifi_csi_config_t cfg = {};
    cfg.lltf_en = true;
    cfg.htltf_en = p.htltf;
    cfg.stbc_htltf2_en = p.stbc;
    cfg.ltf_merge_en = p.merge;
    cfg.channel_filter_en = false;
    cfg.manu_scale = false;
    cfg.shift = 0;
    cfg.dump_ack_en = false;
    esp_err_t a = esp_wifi_set_csi_rx_cb(&csiCb, nullptr);
    esp_err_t b = esp_wifi_set_csi_config(&cfg);
    esp_err_t c = esp_wifi_set_csi(true);
    Serial.printf("[PHASE] %-16s htltf=%d stbc=%d merge=%d  cb=%d cfg=%d en=%d\n",
                  p.name, p.htltf, p.stbc, p.merge, (int)a, (int)b, (int)c);
}

static void resetCounters() {
    cnt128 = cnt256 = cnt384 = cntOther = cntTotal = 0;
    corrSum128 = corrSumHT = corrSumCtl = 0.0;
    corrN128 = corrNHT = corrNCtl = 0;
    promFrames = 0;
}

void setup() {
    Serial.begin(115200);
    delay(2500);
    Serial.println();
    Serial.println("=== CSI CONFIG A/B - ch11, 90s per phase ===");

    WiFi.mode(WIFI_AP_STA);
    delay(100);
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, "US", 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&promCb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(TEST_CH, WIFI_SECOND_CHAN_NONE);
    delay(50);
}

void loop() {
    for (int round = 0; round < ROUNDS; round++) {
        for (int i = 0; i < NPHASE; i++) {
            applyPhase(PHASES[i]);
            resetCounters();
            const uint32_t t0 = millis();
            while (millis() - t0 < PHASE_MS) delay(200);
            const uint32_t tot = cntTotal;
            const uint32_t pf = promFrames;
            const float r128 = corrN128 ? (float)(corrSum128 / corrN128) : NAN;
            const float rht = corrNHT ? (float)(corrSumHT / corrNHT) : NAN;
            const float rctl = corrNCtl ? (float)(corrSumCtl / corrNCtl) : NAN;
            Serial.printf("[RESULT] r%02d %-16s prom=%u rec=%u yield=%.4f  128=%u 256=%u 384=%u"
                          "  corr128=%.3f corrHT=%.3f ctl=%.3f\n",
                          round, PHASES[i].name, (unsigned)pf, (unsigned)tot,
                          pf ? (float)tot / (float)pf : 0.0f,
                          (unsigned)cnt128, (unsigned)cnt256, (unsigned)cnt384,
                          r128, rht, rctl);
        }
    }
    Serial.println("[RESULT] ==== A/B COMPLETE ====");
    while (true) delay(1000);
}
