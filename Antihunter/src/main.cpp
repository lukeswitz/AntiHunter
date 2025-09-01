#include <Arduino.h>
#include <Preferences.h>
#include "network.h"
#include "scanner.h" 
#include "hardware.h"

// Global configuration
Preferences prefs;
volatile bool stopRequested = false;

// Global state
ScanMode currentScanMode = SCAN_WIFI;
int cfgBeeps = 2;
int cfgGapMs = 80;
String lastResults;
std::vector<uint8_t> CHANNELS;

// Task handles
TaskHandle_t workerTaskHandle = nullptr;
TaskHandle_t blueTeamTaskHandle = nullptr;

// Helper functions
String macFmt6(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", 
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}

bool parseMac6(const String &in, uint8_t out[6]) {
    String t;
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        if (isxdigit((int)c)) t += (char)toupper(c);
    }
    if (t.length() != 12) return false;
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    return true;
}

inline uint16_t u16(const uint8_t *p) { 
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8); 
}

bool isZeroOrBroadcast(const uint8_t *mac) {
    bool all0 = true, allF = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) all0 = false;
        if (mac[i] != 0xFF) allF = false;
    }
    return all0 || allF;
}

inline int clampi(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

void parseChannelsCSV(const String &csv) {
    CHANNELS.clear();
    if (csv.indexOf("..") >= 0) {
        int a = csv.substring(0, csv.indexOf("..")).toInt();
        int b = csv.substring(csv.indexOf("..") + 2).toInt();
        for (int ch = a; ch <= b; ch++) {
            if (ch >= 1 && ch <= 14) CHANNELS.push_back((uint8_t)ch);
        }
    } else {
        int start = 0;
        while (start < csv.length()) {
            int comma = csv.indexOf(',', start);
            if (comma < 0) comma = csv.length();
            int ch = csv.substring(start, comma).toInt();
            if (ch >= 1 && ch <= 14) CHANNELS.push_back((uint8_t)ch);
            start = comma + 1;
        }
    }
    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
}

void setup() {
    delay(1000);
    Serial.begin(115200);
    delay(300);
    Serial.println("\n=== Antihunter v4 Boot ===");
    Serial.println("WiFi+BLE dual-mode scanner");
    delay(1000);
    
    initializeHardware();
    initializeSD();
    initializeGPS();
    delay(3000);
    // testGPSPins(); // GPS diagnostic for testing
    initializeScanner();
    initializeNetwork(); 
    
    Serial.println("=== Boot Complete ===");
    Serial.printf("Web UI: http://192.168.4.1/ (SSID: %s, PASS: %s)\n", AP_SSID, AP_PASS);
}

void loop() {
    updateGPSLocation();
    delay(200); 
}
