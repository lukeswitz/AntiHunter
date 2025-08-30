#include "hardware.h"
#include "scanner.h"
#include "network.h"

extern Preferences prefs;
extern int cfgBeeps, cfgGapMs;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;

// getDiagnostics vars
extern volatile bool scanning;
extern volatile int totalHits;
extern volatile uint32_t framesSeen;
extern volatile uint32_t bleFramesSeen;
extern volatile bool trackerMode;
extern std::set<String> uniqueMacs;
extern uint32_t lastScanSecs;
extern bool lastScanForever;
extern String macFmt6(const uint8_t *m);
extern size_t getTargetCount();
extern void getTrackerStatus(uint8_t mac[6], int8_t &rssi, uint32_t &lastSeen, uint32_t &packets);


// Buzzer control
#if BUZZER_IS_PASSIVE
static bool buzzerInit = false;

static void buzzerInitIfNeeded(uint32_t f) {
    if (!buzzerInit) {
        ledcAttach(BUZZER_PIN, f, 10);
        buzzerInit = true;
    } else {
        ledcDetach(BUZZER_PIN);
        ledcAttach(BUZZER_PIN, f, 10);
    }
}

static void buzzerTone(uint32_t f) {
    buzzerInitIfNeeded(f);
    ledcWrite(BUZZER_PIN, 512); // 50% duty cycle
}

static void buzzerOff() {
    if (buzzerInit) ledcWrite(BUZZER_PIN, 0);
}

#else
static void buzzerTone(uint32_t) {
    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(BUZZER_PIN, HIGH);
}

static void buzzerOff() {
    digitalWrite(BUZZER_PIN, LOW);
}
#endif

void beepOnce(uint32_t freq, uint32_t ms) {
    buzzerTone(freq);
    delay(ms);
    buzzerOff();
}

void beepPattern(int count, int gap_ms) {
    if (count < 1) return;
    for (int i = 0; i < count; i++) {
        beepOnce();
        if (i != count - 1) delay(gap_ms);
    }
}

void initializeHardware() {
    Serial.println("Loading preferences...");
    prefs.begin("ouispy", false);
    
    cfgBeeps = prefs.getInt("beeps", 2);
    cfgGapMs = prefs.getInt("gap", 80);
    
    Serial.printf("Hardware initialized: beeps=%d, gap=%dms\n", cfgBeeps, cfgGapMs);
}

void saveConfiguration() {
    prefs.putInt("beeps", cfgBeeps);
    prefs.putInt("gap", cfgGapMs);
}

int getBeepsPerHit() {
    return cfgBeeps;
}

int getGapMs() {
    return cfgGapMs;
}

String getDiagnostics() {
    String s;
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";
    
    s += "Scan Mode: " + modeStr + "\n";
    s += String("Scanning: ") + (scanning ? "yes" : "no") + "\n";
    s += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    s += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
    s += "Total hits: " + String(totalHits) + "\n";
    s += "Country: " + String(COUNTRY) + "\n";
    s += "Current channel: " + String(WiFi.channel()) + "\n";
    s += "AP IP: " + WiFi.softAPIP().toString() + "\n";
    s += "Unique devices: " + String((int)uniqueMacs.size()) + "\n";
    s += "Targets: " + String(getTargetCount()) + "\n";

    if (trackerMode) {
        uint8_t trackerMac[6];
        int8_t trackerRssi;
        uint32_t trackerLastSeen, trackerPackets;
        getTrackerStatus(trackerMac, trackerRssi, trackerLastSeen, trackerPackets);
        
        s += "Tracker: target=" + macFmt6(trackerMac) + " lastRSSI=" + String((int)trackerRssi) + "dBm";
        s += "  lastSeen(ms ago)=" + String((unsigned)(millis() - trackerLastSeen));
        s += " pkts=" + String((unsigned)trackerPackets) + "\n";
    }
    s += "Last scan secs: " + String((unsigned)lastScanSecs) + (lastScanForever ? " (forever)" : "") + "\n";
    
    float temp_c = temperatureRead();
    float temp_f = (temp_c * 9.0 / 5.0) + 32.0;
    s += "ESP32 Temp: " + String(temp_c, 1) + "°C / " + String(temp_f, 1) + "°F\n";

    s += "Beeps/Hit: " + String(cfgBeeps) + "  Gap(ms): " + String(cfgGapMs) + "\n";
    s += "WiFi Channels: ";
    for (auto c : CHANNELS) {
        s += String((int)c) + " ";
    }
    s += "\n";

    return s;
}