#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <RTClib.h>
#include <TinyGPSPlus.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>
#include <esp_heap_caps.h>

#ifdef ARDUINO_XIAO_ESP32C5
#define MESH_RX_PIN 7
#define MESH_TX_PIN 23
#define VIBRATION_PIN 0
#define SD_CS_PIN   1
#define SD_CLK_PIN  8
#define SD_MISO_PIN 9
#define SD_MOSI_PIN 10
#define GPS_RX_PIN 12
#define GPS_TX_PIN 11
#define RTC_SDA_PIN 25
#define RTC_SCL_PIN 24
#else
#define MESH_RX_PIN 4
#define MESH_TX_PIN 5
#define VIBRATION_PIN 2
#define SD_CS_PIN   1
#define SD_CLK_PIN  7
#define SD_MISO_PIN 8
#define SD_MOSI_PIN 9
#define GPS_RX_PIN 44
#define GPS_TX_PIN 43
#define RTC_SDA_PIN 3
#define RTC_SCL_PIN 6
#endif

static uint32_t passCount = 0, failCount = 0, skipCount = 0;

static void result(const char *name, int state, const String &detail) {
    const char *tag = state > 0 ? "PASS" : (state < 0 ? "SKIP" : "FAIL");
    if (state > 0) passCount++; else if (state < 0) skipCount++; else failCount++;
    Serial.printf("[TEST] %-10s %s  %s\n", name, tag, detail.c_str());
}

static void listSD(const String &dir, uint32_t &n, uint32_t &bytes) {
    File root = SD.open(dir.c_str());
    if (!root || !root.isDirectory()) { if (root) root.close(); return; }
    File f = root.openNextFile();
    while (f) {
        const String path = dir + "/" + String(f.name());
        if (f.isDirectory()) {
            Serial.printf("[SDLIST] DIR  %s\n", path.c_str());
            f.close();
            listSD(path, n, bytes);
        } else {
            Serial.printf("[SDLIST] %8u  %s\n", (unsigned)f.size(), path.c_str());
            n++; bytes += (uint32_t)f.size();
            f.close();
        }
        f = root.openNextFile();
    }
    root.close();
}

static void testChip() {
    result("chip", 1, String(ESP.getChipModel()) + " rev" + String(ESP.getChipRevision()) +
                      " " + String(ESP.getChipCores()) + " core, flash " +
                      String(ESP.getFlashChipSize() / (1024 * 1024)) + "MB");
    const uint32_t ps = ESP.getPsramSize();
    result("psram", ps > 0 ? 1 : 0, ps ? String(ps / (1024 * 1024)) + "MB, " +
           String(ESP.getFreePsram() / 1024) + "KB free" : "not detected");
    result("heap", ESP.getFreeHeap() > 100000 ? 1 : 0,
           String(ESP.getFreeHeap() / 1024) + "KB internal free");
}

static void testSD() {
    SPI.begin(SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
    if (!SD.begin(SD_CS_PIN, SPI, 4000000)) {
        result("sd", 0, "mount failed - card absent, unformatted, or wiring");
        return;
    }
    const uint64_t mb = SD.cardSize() / (1024ULL * 1024ULL);
    File w = SD.open("/selftest.tmp", FILE_WRITE);
    if (!w) { result("sd", 0, String((unsigned)mb) + "MB mounted but not writable"); return; }
    w.println("selftest"); w.close();
    File r = SD.open("/selftest.tmp");
    const bool ok = r && r.readStringUntil('\n').startsWith("selftest");
    if (r) r.close();
    SD.remove("/selftest.tmp");
    result("sd", ok ? 1 : 0, String((unsigned)mb) + "MB, write+read+delete " + (ok ? "OK" : "FAILED"));
}

static void testRTC() {
    Wire.begin(RTC_SDA_PIN, RTC_SCL_PIN);
    RTC_DS3231 rtc;
    if (!rtc.begin(&Wire)) { result("rtc", 0, "DS3231 not responding on I2C"); return; }
    const DateTime a = rtc.now();
    const bool lost = rtc.lostPower();
    delay(1100);
    const DateTime b = rtc.now();
    const bool ticking = (b.unixtime() != a.unixtime());
    result("rtc", ticking ? 1 : 0,
           String(ticking ? "ticking, " : "NOT ticking, ") +
           String(a.year()) + "-" + String(a.month()) + "-" + String(a.day()) +
           (lost ? " (lost power, needs set)" : ""));
}

static void testGPS() {
    Serial1.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    TinyGPSPlus gps;
    uint32_t chars = 0;
    const uint32_t end = millis() + 8000;
    while (millis() < end) {
        while (Serial1.available()) { gps.encode(Serial1.read()); chars++; }
        delay(5);
    }
    const uint32_t sentences = gps.passedChecksum();
    const uint32_t bad = gps.failedChecksum();
    if (chars == 0) { result("gps", 0, "no data on the UART - check wiring"); Serial1.end(); return; }
    if (sentences == 0) {
        result("gps", 0, String(chars) + " bytes but no valid NMEA sentence" +
               (bad ? " (" + String(bad) + " checksum failures)" : ""));
    } else {
        result("gps", 1, String(sentences) + " valid NMEA sentences, " + String(chars) +
               " bytes in 8s" + (bad ? ", " + String(bad) + " checksum fails" : ""));
    }
    Serial1.end();
}

static void testVibration() {
    pinMode(VIBRATION_PIN, INPUT);
    uint32_t highs = 0;
    for (int i = 0; i < 200; i++) { if (digitalRead(VIBRATION_PIN)) highs++; delay(5); }
    result("vibration", (highs > 0 && highs < 200) ? 1 : -1,
           String(highs) + "/200 samples high" +
           ((highs == 0) ? " (idle - tap the board to confirm)"
                         : (highs == 200 ? " (stuck high - check wiring)" : " (responding)")));
}

static void testMeshUART() {
    Serial2.begin(115200, SERIAL_8N1, MESH_RX_PIN, MESH_TX_PIN);
    delay(200);
    Serial2.println("SELFTEST");
    const uint32_t end = millis() + 3000;
    uint32_t got = 0;
    while (millis() < end) { while (Serial2.available()) { Serial2.read(); got++; } delay(5); }
    result("mesh", got > 0 ? 1 : -1,
           got ? String(got) + " bytes back from the radio" : "no reply - radio absent or not wired");
    Serial2.end();
}

static void testWiFi() {
    WiFi.mode(WIFI_AP);
    const bool ap = WiFi.softAP("AH-SELFTEST", "selftest123", 6, 0, 4);
    delay(500);
    result("wifi.ap", ap ? 1 : 0, ap ? "SoftAP up on ch6, " + WiFi.softAPIP().toString() : "softAP() failed");
    WiFi.mode(WIFI_STA);
    const int n = WiFi.scanNetworks(false, true, false, 200);
    result("wifi.scan", n >= 0 ? 1 : 0, n >= 0 ? String(n) + " networks seen" : "scan failed");
    WiFi.scanDelete();
    WiFi.mode(WIFI_OFF);
}

static void testBLE() {
    NimBLEDevice::init("AH-SELFTEST");
    NimBLEScan *scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    NimBLEScanResults res = scan->getResults(4000, false);
    result("ble", 1, String(res.getCount()) + " BLE devices in 4s");
    scan->clearResults();
    NimBLEDevice::deinit(true);
}


extern "C" {
extern volatile uint32_t g_memcpyBadLenRejects;
extern volatile uint32_t g_memcpyBadLenLast;
}

static void testMemcpyGuard() {
    Serial.println("[TEST] blob memcpy length guard");
    uint8_t *dst = (uint8_t *)ps_malloc(256);
    if (!dst) { result("memcpy", -1, "no PSRAM"); return; }
    static uint8_t src[256];
    for (int i = 0; i < 256; i++) { dst[i] = 0xA5; src[i] = (uint8_t)i; }

    volatile size_t good = 64;
    memcpy(dst, src, good);
    bool copied = true;
    for (int i = 0; i < 64; i++) if (dst[i] != (uint8_t)i) copied = false;
    for (int i = 64; i < 256; i++) if (dst[i] != 0xA5) copied = false;
    Serial.printf("[TEST]   control: 64-byte copy %s\n", copied ? "OK" : "WRONG");

    uint32_t before = g_memcpyBadLenRejects;
    for (int i = 0; i < 256; i++) dst[i] = 0x5A;
    volatile size_t bad = (size_t)0xffffffe4u;
    Serial.printf("[TEST]   issuing memcpy(psram, internal, %d) - the exact panic length\n", (int)(int32_t)bad);
    Serial.flush();
    memcpy(dst, src, bad);
    uint32_t after = g_memcpyBadLenRejects;

    bool intact = true;
    for (int i = 0; i < 256; i++) if (dst[i] != 0x5A) intact = false;
    Serial.printf("[TEST]   survived; rejects %u -> %u, last n=0x%08x, dst intact=%s\n",
                  (unsigned)before, (unsigned)after, (unsigned)g_memcpyBadLenLast,
                  intact ? "yes" : "NO");
    free(dst);
    if (copied && after == before + 1 && intact) result("memcpy", 1, "bad length rejected, good copy intact");
    else result("memcpy", 0, "guard did not behave as specified");
}

void setup() {
    Serial.begin(115200);
    delay(2500);
    Serial.println();
    Serial.println("=== ANTIHUNTER HARDWARE SELF-TEST ===");
    Serial.println("[TEST] no firmware config is written, nothing is saved");
    Serial.println();

    testChip();
    testSD();
    testRTC();
    testGPS();
    testVibration();
    testMeshUART();
    testWiFi();
    testBLE();
    testMemcpyGuard();

    Serial.println();
    uint32_t n = 0, bytes = 0;
    Serial.println("[SDLIST] ==== SD card contents ====");
    listSD("", n, bytes);
    Serial.printf("[SDLIST] ==== %u files, %u bytes ====\n", (unsigned)n, (unsigned)bytes);

    Serial.println();
    Serial.printf("[TEST] ==== %u passed, %u failed, %u skipped ====\n",
                  (unsigned)passCount, (unsigned)failCount, (unsigned)skipCount);
    Serial.println(failCount == 0 ? "[TEST] RESULT: PASS" : "[TEST] RESULT: FAIL");
    Serial.println("[TEST] SELFTEST COMPLETE");
}

void loop() { delay(1000); }
