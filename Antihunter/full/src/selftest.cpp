#ifdef WIFI_SELFTEST
#include <Arduino.h>
#include <WiFi.h>
#include <vector>
#include <Preferences.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "scanner.h"
#include "network.h"
#include "hardware.h"

extern std::vector<uint8_t> CHANNELS;
extern std::vector<uint8_t> g_activeChannels;
extern Preferences prefs;

static int g_pass = 0, g_fail = 0;

static void ck(const char *name, bool ok) {
    Serial.printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

static bool listHas(const std::vector<uint8_t> &v, uint8_t ch) {
    for (uint8_t c : v) if (c == ch) return true;
    return false;
}

static bool allInRange(const std::vector<uint8_t> &v, int lo, int hi) {
    if (v.empty()) return false;
    for (uint8_t c : v) if (c < lo || c > hi) return false;
    return true;
}

// Section 1: config layer (no radio) — the new band/channel logic.
static void testConfigLayer() {
    Serial.println("\n-- [1] Config layer (channel parse + band filter) --");

    parseChannelsCSV("1,6,11,36,149");
    ck("parse accepts 2.4 ch (6)", listHas(CHANNELS, 6));
    ck("parse accepts 5GHz ch 36", listHas(CHANNELS, 36));
    ck("parse accepts 5GHz ch 149", listHas(CHANNELS, 149));

    parseChannelsCSV("36,52,100,149");
    ck("parse accepts UNII ch 36", listHas(CHANNELS, 36));
    ck("parse rejects DFS ch 52", !listHas(CHANNELS, 52));
    ck("parse rejects DFS ch 100", !listHas(CHANNELS, 100));

    parseChannelsCSV("1,6,11,36,40,44,48,149,153,157,161,165");

    setBandMode(0);
    ck("band=2.4 -> activeChannels all in 1..14", allInRange(g_activeChannels, 1, 14));

    setBandMode(1);
    ck("band=5G  -> activeChannels all in 36..165", allInRange(g_activeChannels, 36, 165));

    setBandMode(2);
    ck("band=both -> activeChannels has 2.4 (6)", listHas(g_activeChannels, 6));
    ck("band=both -> activeChannels has 5GHz (36)", listHas(g_activeChannels, 36));

    setBandMode(255);
    ck("setBandMode clamps out-of-range to <=2", rfConfig.bandMode <= 2);
}

static const char *errName(esp_err_t e) { return e == ESP_OK ? "OK" : esp_err_to_name(e); }

// Section 2: radio band mode + regulatory.
static void testBandModeRadio() {
    Serial.println("\n-- [2] Radio band mode + country --");

    esp_err_t rc = esp_wifi_set_country_code(COUNTRY, true);
    ck("esp_wifi_set_country_code(US,true)==OK", rc == ESP_OK);
    Serial.printf("     ret=%s\n", errName(rc));

    struct { uint8_t v; wifi_band_mode_t m; const char *n; } modes[] = {
        {0, WIFI_BAND_MODE_2G_ONLY, "2G_ONLY"},
        {1, WIFI_BAND_MODE_5G_ONLY, "5G_ONLY"},
        {2, WIFI_BAND_MODE_AUTO,    "AUTO"},
    };
    for (auto &bm : modes) {
        esp_err_t r = esp_wifi_set_band_mode(bm.m);
        Serial.printf("  set_band_mode(%s) ret=%s\n", bm.n, errName(r));
        ck(bm.n, r == ESP_OK);
        wifi_band_mode_t got = WIFI_BAND_MODE_AUTO;
        if (esp_wifi_get_band_mode(&got) == ESP_OK)
            ck("readback matches", got == bm.m);
    }
}

// Section 3: channel tuning per band — the proof 5GHz is reachable.
static void tuneSet(const uint8_t *chs, size_t n, const char *label, bool mustPass) {
    int ok = 0;
    for (size_t i = 0; i < n; i++) {
        esp_err_t r = esp_wifi_set_channel(chs[i], WIFI_SECOND_CHAN_NONE);
        uint8_t prim = 0; wifi_second_chan_t sec;
        esp_wifi_get_channel(&prim, &sec);
        bool good = (r == ESP_OK) && (prim == chs[i]);
        if (good) ok++;
        Serial.printf("     ch%-3u set=%s readback=%u\n", chs[i], errName(r), prim);
    }
    if (mustPass) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%s: %d/%u channels tuned", label, ok, (unsigned)n);
        ck(buf, ok == (int)n);
    } else {
        Serial.printf("  [INFO] %s: %d/%u tuned (cross-band, informational)\n", label, ok, (unsigned)n);
    }
}

static void testChannelTuning() {
    Serial.println("\n-- [3] Channel tuning per band --");
    static const uint8_t ch24[] = {1, 6, 11};
    static const uint8_t ch5[]  = {36, 40, 44, 48, 149, 153, 157, 161, 165};

    esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY);
    Serial.println("  band=2G_ONLY:");
    tuneSet(ch24, sizeof(ch24), "2.4GHz in-band", true);
    tuneSet(ch5, sizeof(ch5), "5GHz under 2G_ONLY", false);

    esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY);
    Serial.println("  band=5G_ONLY:");
    tuneSet(ch5, sizeof(ch5), "5GHz in-band", true);

    esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    Serial.println("  band=AUTO:");
    tuneSet(ch24, sizeof(ch24), "2.4GHz under AUTO", true);
    tuneSet(ch5, sizeof(ch5), "5GHz under AUTO", true);
}

// Section 4: promiscuous sniffer path.
static void promiscNoop(void *buf, wifi_promiscuous_pkt_type_t t) { (void)buf; (void)t; }

static void testPromiscuous() {
    Serial.println("\n-- [4] Promiscuous path --");
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    ck("set_promiscuous_filter==OK", esp_wifi_set_promiscuous_filter(&filter) == ESP_OK);
    ck("set_promiscuous_rx_cb==OK", esp_wifi_set_promiscuous_rx_cb(&promiscNoop) == ESP_OK);
    ck("set_promiscuous(true)==OK", esp_wifi_set_promiscuous(true) == ESP_OK);
    esp_wifi_set_channel(36, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
    ck("set_promiscuous(false)==OK", esp_wifi_set_promiscuous(false) == ESP_OK);
    esp_wifi_set_promiscuous_rx_cb(NULL);
}

// Section 5: list scan (WiFi.scanNetworks) per band — real APs, passive RX only.
static void scanBand(wifi_band_mode_t m, const char *label) {
    esp_wifi_set_band_mode(m);
    delay(100);
    int n = WiFi.scanNetworks(false, true);
    int n5 = 0;
    for (int i = 0; i < n; i++) if (WiFi.channel(i) >= 36) n5++;
    Serial.printf("  [%s] scanNetworks=%d  (2.4GHz=%d, 5GHz=%d)\n", label, n, n - n5, n5);
    WiFi.scanDelete();
    if (n >= 0) g_pass++; else { g_fail++; Serial.printf("  [FAIL] %s scan returned %d\n", label, n); }
}

static void testListScan() {
    Serial.println("\n-- [5] List scan per band (real APs, passive) --");
    esp_wifi_set_country_code(COUNTRY, true);
    scanBand(WIFI_BAND_MODE_2G_ONLY, "2G_ONLY");
    scanBand(WIFI_BAND_MODE_5G_ONLY, "5G_ONLY");
    scanBand(WIFI_BAND_MODE_AUTO, "AUTO");
}

void runWifiSelftest() {
    delay(2000);
    Serial.println("\n============================================");
    Serial.println("        WIFI SELFTEST  (ESP32-C5)");
    Serial.println("============================================");

    prefs.begin("antihunter", false);

    testConfigLayer();

    WiFi.persistent(false);
    WiFi.mode(WIFI_MODE_STA);
    delay(300);
    wifi_mode_t mode;
    ck("WiFi STA mode active", esp_wifi_get_mode(&mode) == ESP_OK && mode == WIFI_MODE_STA);

    testBandModeRadio();
    testChannelTuning();
    testPromiscuous();
    testListScan();

    setBandMode(DEFAULT_BAND_MODE);

    Serial.println("\n============================================");
    Serial.printf("  RESULT: %d PASSED, %d FAILED\n", g_pass, g_fail);
    Serial.println(g_fail == 0 ? "  ALL WIFI PATHS OK" : "  SEE FAILURES ABOVE");
    Serial.println("============================================\n");
}
#endif
