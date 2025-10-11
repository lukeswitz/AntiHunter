#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <NimBLEAddress.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEScan.h>
#include <algorithm>
#include <string>
#include <mutex>
#include "scanner.h"
#include "hardware.h"
#include "network.h"
#include "triangulation.h"
#include "baseline.h"
#include "main.h"

extern "C"
{
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_coexist.h"
}

// AP handlers
void radioStartSTA();
void radioStopSTA();

// Scanner state variables
static std::vector<Target> targets;
QueueHandle_t macQueue = nullptr;
std::set<String> uniqueMacs;
std::set<String> seenDevices;
std::map<String, uint32_t> deviceLastSeen;
const uint32_t DEDUPE_WINDOW = 30000;
std::vector<Hit> hitsLog;
static esp_timer_handle_t hopTimer = nullptr;
static uint32_t lastScanStart = 0, lastScanEnd = 0;
uint32_t lastScanSecs = 0;
bool lastScanForever = false;
static std::map<String, String> apCache;
static std::map<String, String> bleDeviceCache;
static unsigned long lastSnifferScan = 0;
const unsigned long SNIFFER_SCAN_INTERVAL = 10000;

// BLE 
NimBLEScan *pBLEScan;
static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);

// Scan intervals
uint32_t WIFI_SCAN_INTERVAL = 4000;
uint32_t BLE_SCAN_INTERVAL = 2000;

// Scanner status variables
volatile bool scanning = false;
volatile int totalHits = 0;
volatile uint32_t framesSeen = 0;
volatile uint32_t bleFramesSeen = 0;

std::map<String, DeviceHistory> deviceHistory;
uint32_t deviceAbsenceThreshold = 120000;
uint32_t reappearanceAlertWindow = 300000;
int8_t significantRssiChange = 20;

std::vector<Allowlist> allowlist;

// Detection system variables
std::vector<DeauthHit> deauthLog;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;
bool deauthDetectionEnabled = false;
QueueHandle_t deauthQueue = nullptr;
volatile uint32_t req_frames = 0;
volatile uint32_t resp_frames = 0; 
volatile uint32_t bleAnomalyCount = 0;
QueueHandle_t bleAnomalyQueue = nullptr;

// Deauth Detection
std::map<String, uint32_t> deauthSourceCounts;
std::map<String, uint32_t> deauthTargetCounts;
std::map<String, std::vector<uint32_t>> deauthTimings;

// External declarations
extern Preferences prefs;
extern volatile bool stopRequested;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;
extern TaskHandle_t blueTeamTaskHandle;
extern String macFmt6(const uint8_t *m);
extern bool parseMac6(const String &in, uint8_t out[6]);
extern bool isZeroOrBroadcast(const uint8_t *mac);


// Helper functions 
inline uint16_t u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

inline int clampi(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

static bool parseMacLike(const String &ln, Target &out)
{
    String t;
    for (size_t i = 0; i < ln.length(); ++i)
    {
        char c = ln[i];
        if (isxdigit((int)c))
            t += (char)toupper(c);
    }
    if (t.length() == 12)
    {
        for (int i = 0; i < 6; i++)
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6)
    {
        for (int i = 0; i < 3; i++)
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 3;
        return true;
    }
    return false;
}

size_t getTargetCount()
{
    return targets.size();
}

String getTargetsList()
{
    String out;
    for (auto &t : targets)
    {
        if (t.len == 6)
        {
            char b[18];
            snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                     t.bytes[0], t.bytes[1], t.bytes[2], t.bytes[3], t.bytes[4], t.bytes[5]);
            out += b;
        }
        else
        {
            char b[9];
            snprintf(b, sizeof(b), "%02X:%02X:%02X", t.bytes[0], t.bytes[1], t.bytes[2]);
            out += b;
        }
        out += "\n";
    }
    return out;
}

void saveTargetsList(const String &txt)
{
    prefs.putString("maclist", txt);
    targets.clear();
    int start = 0;
    while (start < txt.length())
    {
        int nl = txt.indexOf('\n', start);
        if (nl < 0)
            nl = txt.length();
        String line = txt.substring(start, nl);
        line.trim();
        if (line.length())
        {
            Target t;
            if (parseMacLike(line, t))
            {
                targets.push_back(t);
            }
        }
        start = nl + 1;
    }
}

static inline bool matchesMac(const uint8_t *mac)
{
    for (auto &t : targets)
    {
        if (t.len == 6)
        {
            bool eq = true;
            for (int i = 0; i < 6; i++)
            {
                if (mac[i] != t.bytes[i])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
                return true;
        }
        else
        {
            if (mac[0] == t.bytes[0] && mac[1] == t.bytes[1] && mac[2] == t.bytes[2])
            {
                return true;
            }
        }
    }
    return false;
}

static void hopTimerCb(void *)
{
    static size_t idx = 0;
    if (CHANNELS.empty())
        return;
    idx = (idx + 1) % CHANNELS.size();
    esp_wifi_set_channel(CHANNELS[idx], WIFI_SECOND_CHAN_NONE);
}

static int periodFromRSSI(int8_t rssi)
{
    const int rMin = -90, rMax = -30, pMin = 120, pMax = 1000;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int period = (int)(pMax - a * (pMax - pMin));
    return period;
}

static int freqFromRSSI(int8_t rssi)
{
    const int rMin = -90, rMax = -30, fMin = 2000, fMax = 4500;
    int r = clampi(rssi, rMin, rMax);
    float a = float(r - rMin) / float(rMax - rMin);
    int f = (int)(fMin + a * (fMax - fMin));
    return f;
}

static void IRAM_ATTR detectDeauthFrame(const wifi_promiscuous_pkt_t *ppkt) {
    if (!deauthDetectionEnabled) return;
    
    const uint8_t *payload = ppkt->payload;
    
    // Check for deauth (0xA0) or disassoc (0xC0) frames
    if (payload[0] == 0xA0 || payload[0] == 0xC0) {
        DeauthHit hit;
        memcpy(hit.srcMac, payload + 10, 6);
        memcpy(hit.destMac, payload + 4, 6);
        memcpy(hit.bssid, payload + 16, 6);
        hit.reasonCode = (payload[24] | (payload[25] << 8));
        hit.rssi = ppkt->rx_ctrl.rssi;
        hit.channel = ppkt->rx_ctrl.channel;
        hit.timestamp = millis();
        hit.isDisassoc = (payload[0] == 0xA0);
        hit.isBroadcast = (memcmp(hit.destMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0);
        
        bool isAttack = false;
        
        // Broadcast deauth = always suspicious
        if (hit.isBroadcast) {
            isAttack = true;
        } else {
            // Track targeted attacks
            static std::map<String, uint32_t> targetedClients;
            static std::map<String, uint32_t> lastDeauthTime;
            
            String destMacStr = macFmt6(hit.destMac);
            targetedClients[destMacStr]++;
            
            if (lastDeauthTime.count(destMacStr) > 0) {
                uint32_t timeSince = millis() - lastDeauthTime[destMacStr];
                if (timeSince < 10000 && targetedClients[destMacStr] >= 2) {
                    isAttack = true;
                }
            }
            lastDeauthTime[destMacStr] = millis();
        }
        
        if (isAttack || hit.isBroadcast) {
            deauthLog.push_back(hit);
            
            if (hit.isDisassoc) {
                uint32_t temp = disassocCount;
                disassocCount = temp + 1;
            } else {
                uint32_t temp = deauthCount;
                deauthCount = temp + 1;
            }
            
            String alert = "[DEAUTH] " + String(hit.isDisassoc ? "DISASSOC" : "DEAUTH") + 
                          " " + macFmt6(hit.srcMac) + "->" + macFmt6(hit.destMac) + 
                          " Reason:" + String(hit.reasonCode);
            Serial.println(alert);
            logToSD(alert);
            
            if (meshEnabled) {
                String meshAlert = getNodeId() + ": " + alert;
                if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                    Serial1.println(meshAlert);
                }
            }
        }
    }
}


// Main NimBLE callback
class MyBLEScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) {
        bleFramesSeen = bleFramesSeen + 1;

        uint8_t mac[6];
        NimBLEAddress addr = advertisedDevice->getAddress();
        String macStr = addr.toString().c_str();
        if (!parseMac6(macStr, mac)) return;

        String deviceName = "Unknown";
        if (advertisedDevice->haveName()) {
            std::string nimbleName = advertisedDevice->getName();
            if (nimbleName.length() > 0) {
                deviceName = "";
                for (size_t i = 0; i < nimbleName.length() && i < 31; i++) {
                    uint8_t c = (uint8_t)nimbleName[i];
                    if (c >= 32 && c <= 126) {
                        deviceName += (char)c;
                    }
                }
                if (deviceName.length() == 0) {
                    deviceName = "Unknown";
                }
            }
        }

        if (matchesMac(mac)) {
            Hit h;
            memcpy(h.mac, mac, 6);
            h.rssi = advertisedDevice->getRSSI();
            h.ch = 0;
            strncpy(h.name, deviceName.c_str(), sizeof(h.name) - 1);
            h.name[sizeof(h.name) - 1] = '\0';
            h.isBLE = true;

            if (macQueue) {
                if (xQueueSend(macQueue, &h, pdMS_TO_TICKS(10)) != pdTRUE) {
                    Serial.printf("[BLE] Queue full for %s\n", macStr.c_str());
                }
            }
        }
    }
};

void snifferScanTask(void *pv)
{
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                 (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    Serial.printf("[SNIFFER] Starting device scan %s\n",
                  forever ? "(forever)" : String("for " + String(duration) + "s").c_str());

    radioStartSTA();

    scanning = true;
    uniqueMacs.clear();
    hitsLog.clear();
    apCache.clear();
    bleDeviceCache.clear();
    totalHits = 0;
    framesSeen = 0;
    bleFramesSeen = 0;
    stopRequested = false;
    lastScanStart = millis();
    lastScanSecs = duration;
    lastScanForever = forever;

    int networksFound = 0;
    unsigned long lastBLEScan = 0;
    unsigned long lastWiFiScan = 0;
    const unsigned long BLE_SCAN_INTERVAL = 4000;
    const unsigned long WIFI_SCAN_INTERVAL = 2000;

    NimBLEScan *bleScan = nullptr;

    BLEDevice::init("");
    bleScan = BLEDevice::getScan();
    bleScan->setActiveScan(true);
    bleScan->setInterval(100);
    bleScan->setWindow(99);

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < duration * 1000 && !stopRequested))
    {
        if (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)
        {
            lastWiFiScan = millis();

            Serial.println("[SNIFFER] Scanning WiFi networks...");
            networksFound = WiFi.scanNetworks(false, true, false, 120);

            if (networksFound > 0)
            {
                for (int i = 0; i < networksFound; i++)
                {
                    String bssid = WiFi.BSSIDstr(i);
                    String ssid = WiFi.SSID(i);
                    int32_t rssi = WiFi.RSSI(i);
                    uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0)
                    {
                        ssid = "[Hidden]";
                    }

                    if (apCache.find(bssid) == apCache.end())
                    {
                        apCache[bssid] = ssid;
                        uniqueMacs.insert(bssid);

                        Hit h;
                        memcpy(h.mac, bssidBytes, 6);
                        h.rssi = rssi;
                        h.ch = WiFi.channel(i);
                        strncpy(h.name, ssid.c_str(), sizeof(h.name) - 1);
                        h.name[sizeof(h.name) - 1] = '\0';
                        h.isBLE = false;

                        hitsLog.push_back(h);

                        if (matchesMac(bssidBytes)) {
                            totalHits = totalHits + 1;
                        }

                        String logEntry = "WiFi AP: " + bssid + " SSID: " + ssid +
                                          " RSSI: " + String(rssi) + "dBm CH: " + String(WiFi.channel(i));

                        if (gpsValid)
                        {
                            logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                        }

                        Serial.println("[SNIFFER] " + logEntry);
                        logToSD(logEntry);

                        uint8_t mac[6];
                        if (parseMac6(bssid, mac) && matchesMac(mac))
                        {
                            sendMeshNotification(h);
                        }
                    }
                }
            }

            Serial.printf("[SNIFFER] WiFi scan found %d networks\n", networksFound);
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        if (millis() - lastBLEScan >= BLE_SCAN_INTERVAL || lastBLEScan == 0)
        {
            lastBLEScan = millis();

            Serial.println("[SNIFFER] Scanning BLE devices...");

            if (bleScan)
            {
                // Use getResults for blocking scan
                NimBLEScanResults scanResults = bleScan->getResults(2000, false);

                for (int i = 0; i < scanResults.getCount(); i++)
                {
                    const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                    String macStr = device->getAddress().toString().c_str();

                    if (bleDeviceCache.find(macStr) == bleDeviceCache.end())
                    {
                        String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                        String cleanName = "";
                        for (size_t j = 0; j < name.length(); j++)
                        {
                            char c = name[j];
                            if (c >= 32 && c <= 126)
                            {
                                cleanName += c;
                            }
                        }
                        if (cleanName.length() == 0)
                            cleanName = "Unknown";
                        
                        bleDeviceCache[macStr] = cleanName;
                        uniqueMacs.insert(macStr);
                        
                        uint8_t mac[6];
                        if (parseMac6(macStr, mac))
                        {
                            Hit h;
                            memcpy(h.mac, mac, 6);
                            h.rssi = device->getRSSI();
                            h.ch = 0;
                            strncpy(h.name, cleanName.c_str(), sizeof(h.name) - 1);
                            h.name[sizeof(h.name) - 1] = '\0';
                            h.isBLE = true;
                            hitsLog.push_back(h);
                            
                            String logEntry = "BLE Device: " + macStr + " Name: " + cleanName +
                                            " RSSI: " + String(device->getRSSI()) + "dBm";

                                if (gpsValid)
                                {
                                    logEntry += " GPS: " + String(gpsLat, 6) + "," + String(gpsLon, 6);
                                }

                                Serial.println("[SNIFFER] " + logEntry);
                                logToSD(logEntry);

                                if (matchesMac(mac))
                                {
                                    sendMeshNotification(h);
                                    totalHits = totalHits + 1;
                                }
                            }
                        }
                    }

                bleScan->clearResults();
                Serial.printf("[SNIFFER] BLE scan found %d devices\n", scanResults.getCount());
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }

        Serial.printf("[SNIFFER] Total: WiFi APs=%d, BLE=%d, Unique=%d, Hits=%d\n",
                      apCache.size(), bleDeviceCache.size(), uniqueMacs.size(), totalHits);

        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (bleScan)
    {
        bleScan->stop();
        delay(100);
        BLEDevice::deinit(false);
        delay(200);
    }
    
    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = 
            "Sniffer scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Total hits: " + std::to_string(totalHits) + "\n" +
            "Unique devices: " + std::to_string(uniqueMacs.size()) + "\n\n";
        
        std::vector<Hit> sortedHits = hitsLog;
        std::sort(sortedHits.begin(), sortedHits.end(), 
                [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

        int shown = 0;
        for (const auto& hit : sortedHits) {
            if (shown++ >= 100) break;
            
            results += (hit.isBLE ? "BLE  " : "WiFi ");
            results += macFmt6(hit.mac).c_str();
            results += " RSSI=" + std::to_string(hit.rssi) + "dBm";
            
            if (!hit.isBLE && hit.ch > 0) {
                results += " CH=" + std::to_string(hit.ch);
            }
            
            if (strlen(hit.name) > 0 && strcmp(hit.name, "WiFi") != 0 && strcmp(hit.name, "Unknown") != 0) {
                results += " \"";
                results += hit.name;
                results += "\"";
            }
            
            results += "\n";
        }
        
        if (sortedHits.size() > 100) {
            results += "... (" + std::to_string(sortedHits.size() - 100) + " more)\n";
        }

        antihunter::lastResults = results;
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

String getSnifferCache()
{
    String result = "=== Sniffer Cache ===\n\n";
    result += "WiFi APs: " + String(apCache.size()) + "\n";
    for (const auto &entry : apCache)
    {
        result += entry.first + " : " + entry.second + "\n";
    }
    result += "\nBLE Devices: " + String(bleDeviceCache.size()) + "\n";
    for (const auto &entry : bleDeviceCache)
    {
        result += entry.first + " : " + entry.second + "\n";
    }
    return result;
}

void blueTeamTask(void *pv) {
    int duration = (int)(intptr_t)pv;
    bool forever = (duration <= 0);

    String startMsg = forever ? String("[BLUE] Starting deauth detection (forever)\n")
                              : String("[BLUE] Starting deauth detection for " + String(duration) + "s\n");
    Serial.print(startMsg);
    
    deauthLog.clear();
    deauthCount = 0;
    disassocCount = 0;
    deauthDetectionEnabled = true;
    stopRequested = false;
    deauthSourceCounts.clear();
    deauthTargetCounts.clear();
    deauthTimings.clear();

    if (deauthQueue) {
        vQueueDelete(deauthQueue);
    }
    
    deauthQueue = xQueueCreate(256, sizeof(DeauthHit));
    
    uint32_t scanStart = millis();
    uint32_t nextStatus = millis() + 5000;
    uint32_t lastCleanup = millis();
    DeauthHit hit;

    radioStartSTA();

    const int BATCH_LIMIT = 4;

    while ((forever && !stopRequested) || 
           (!forever && (int)(millis() - scanStart) < duration * 1000 && !stopRequested)) {
        
            int processed = 0;
        
            while (processed++ < BATCH_LIMIT && xQueueReceive(deauthQueue, &hit, 0) == pdTRUE) {
                

                if (deauthLog.size() < 1000) {
                    deauthLog.push_back(hit);
                }
                
                String alert = String(hit.isDisassoc ? "DISASSOC" : "DEAUTH");
                if (hit.isBroadcast) {
                    alert += " [BROADCAST]";  // Deauth flood
                } else {
                    alert += " [TARGETED]";   // Targeted attack
                }
                alert += " SRC:" + macFmt6(hit.srcMac) + " DST:" + macFmt6(hit.destMac);
                alert += " RSSI:" + String(hit.rssi) + "dBm CH:" + String(hit.channel);
                alert += " Reason:" + String(hit.reasonCode);

                Serial.println("[ALERT] " + alert);
                logToSD(alert);

                if (meshEnabled) {
                    String meshAlert = getNodeId() + ": ATTACK: " + alert;
                    if (gpsValid) {
                        meshAlert += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
                    }
                    if (Serial1.availableForWrite() >= (int)meshAlert.length()) {
                        Serial1.println(meshAlert);
                    }
                }
            }
        
        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("[BLUE] Deauth:%u Disassoc:%u Total:%u\n", 
                         deauthCount, disassocCount, (unsigned)deauthLog.size());
            nextStatus += 5000;
        }
        
        if (millis() - lastCleanup > 60000) {
            if (deauthTimings.size() > 100) {
                std::map<String, std::vector<uint32_t>> newTimings;
                for (auto& entry : deauthTimings) {
                    if (entry.second.size() > 20) {
                        auto &vec = entry.second;
                        newTimings[entry.first] = std::vector<uint32_t>(vec.end() - 20, vec.end());
                    } else {
                        newTimings[entry.first] = entry.second;
                    }
                }
                deauthTimings = std::move(newTimings);
            }
            lastCleanup = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    deauthDetectionEnabled = false;
    
    radioStopSTA();
    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        
        std::string results = "Deauth Detection Results\n";
        results += "Duration: " + (forever ? "Forever" : std::to_string(duration)) + "s\n";
        results += "Deauth frames: " + std::to_string(deauthCount) + "\n";
        results += "Disassoc frames: " + std::to_string(disassocCount) + "\n";
        results += "Total attacks: " + std::to_string(deauthLog.size()) + "\n\n";

        int show = min((int)deauthLog.size(), 100);
        for (int i = 0; i < show; i++) {
            const auto &h = deauthLog[i];
            results += std::string(h.isDisassoc ? "DISASSOC" : "DEAUTH");
            
            if (h.isBroadcast) {
                results += " [BROADCAST]";
            } else if (deauthTargetCounts[macFmt6(h.destMac)] >= 3) {
                results += " [TARGETED]";
            }
            
            results += " ";
            results += std::string(macFmt6(h.srcMac).c_str()) + " -> " + std::string(macFmt6(h.destMac).c_str());
            results += " BSSID:" + std::string(macFmt6(h.bssid).c_str());
            results += " RSSI:" + std::to_string(h.rssi) + "dBm";
            results += " CH:" + std::to_string(h.channel);
            results += " Reason:" + std::to_string(h.reasonCode) + "\n";
        }

        if ((int)deauthLog.size() > show) {
            results += "... (" + std::to_string((int)deauthLog.size() - show) + " more)\n";
        }
        
        antihunter::lastResults = results;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));
    blueTeamTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{

    if (!buf) return;
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;

    if (droneDetectionEnabled) {
        processDronePacket(ppkt->payload, ppkt->rx_ctrl.sig_len, ppkt->rx_ctrl.rssi);
    }

    detectDeauthFrame(ppkt);
    framesSeen = framesSeen + 1;
    if (!ppkt || ppkt->rx_ctrl.sig_len < 24)
        return;

    const uint8_t *p = ppkt->payload;
    uint16_t fc = u16(p);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t tods = (fc >> 8) & 0x1;
    uint8_t fromds = (fc >> 9) & 0x1;

    const uint8_t *a1 = p + 4, *a2 = p + 10, *a3 = p + 16, *a4 = p + 24;
    uint8_t cand1[6], cand2[6];
    bool c1 = false, c2 = false;

    if (ftype == 0)
    {
        if (!isZeroOrBroadcast(a2))
        {
            memcpy(cand1, a2, 6);
            c1 = true;
        }
        if (!isZeroOrBroadcast(a3))
        {
            memcpy(cand2, a3, 6);
            c2 = true;
        }
    }
    else if (ftype == 2)
    {
        if (!tods && !fromds)
        {
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a3))
            {
                memcpy(cand2, a3, 6);
                c2 = true;
            }
        }
        else if (tods && !fromds)
        {
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a1))
            {
                memcpy(cand2, a1, 6);
                c2 = true;
            }
        }
        else if (!tods && fromds)
        {
            if (!isZeroOrBroadcast(a3))
            {
                memcpy(cand1, a3, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand2, a2, 6);
                c2 = true;
            }
        }
        else
        {
            if (!isZeroOrBroadcast(a2))
            {
                memcpy(cand1, a2, 6);
                c1 = true;
            }
            if (!isZeroOrBroadcast(a3))
            {
                memcpy(cand2, a3, 6);
                c2 = true;
            }
        }
    }
    else
    {
        return;
    }


    if (c1 && matchesMac(cand1))
    {
        Hit h;
        memcpy(h.mac, cand1, 6);
        h.rssi = ppkt->rx_ctrl.rssi;
        h.ch = ppkt->rx_ctrl.channel;
        strncpy(h.name, "WiFi", sizeof(h.name) - 1);
        h.name[sizeof(h.name) - 1] = '\0';
        h.isBLE = false;

        BaseType_t w = false;
        if (macQueue)
        {
            xQueueSendFromISR(macQueue, &h, &w);
            if (w)
                portYIELD_FROM_ISR();
        }
    }
    if (c2 && matchesMac(cand2))
    {
        Hit h;
        memcpy(h.mac, cand2, 6);
        h.rssi = ppkt->rx_ctrl.rssi;
        h.ch = ppkt->rx_ctrl.channel;
        strncpy(h.name, "WiFi", sizeof(h.name) - 1);
        h.name[sizeof(h.name) - 1] = '\0';
        h.isBLE = false;

        BaseType_t w = false;
        if (macQueue)
        {
            xQueueSendFromISR(macQueue, &h, &w);
            if (w)
                portYIELD_FROM_ISR();
        }
    }

}

// ---------- Radio common ----------
static void radioStartWiFi()
{
    // Clean initialization
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        Serial.printf("[RADIO] WiFi init error: %d\n", err);
        return;
    }
    
    WiFi.mode(WIFI_MODE_STA);
    delay(500);
    
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    
    err = esp_wifi_start();
    if (err != ESP_OK) {
        Serial.printf("[RADIO] WiFi start error: %d\n", err);
        return;
    }
    delay(300);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    
    // Setup channel hopping with cleanup check
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    
    const esp_timer_create_args_t targs = {
        .callback = &hopTimerCb, 
        .arg = nullptr, 
        .dispatch_method = ESP_TIMER_TASK, 
        .name = "hop"
    };
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, 300000); // 300ms
}

static void radioStopWiFi()
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (hopTimer)
    {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    esp_wifi_stop();
    esp_wifi_deinit();
}

static void radioStopBLE()
{
    if (pBLEScan)
    {
        pBLEScan->stop();
        BLEDevice::deinit(false);
        pBLEScan = nullptr;
    }
}

static void radioStartBLE()
{
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setScanCallbacks(new MyBLEScanCallbacks(), true);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(160);    
    pBLEScan->setWindow(80); 
}

void radioStopSTA() {
    Serial.println("[RADIO] Stopping STA mode");
    
    // Stop promiscuous but keep AP running
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    delay(50);
    
    // Stop channel hopping
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    
    // Stop BLE if running
    if (pBLEScan) {
        pBLEScan->stop();
        BLEDevice::deinit(false);
        pBLEScan = nullptr;
    }
    
    // Switch back to AP only mode
    WiFi.mode(WIFI_AP);
    delay(100);
}

void radioStartSTA() {
    Serial.println("[RADIO] Starting STA mode");
    
    // Use AP_STA mode instead of just STA
    WiFi.mode(WIFI_AP_STA);
    delay(100);
    
    // Configure STA for scanning while keeping AP alive
    wifi_country_t ctry = {.schan = 1, .nchan = 14, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    memcpy(ctry.cc, COUNTRY, 2);
    ctry.cc[2] = 0;
    esp_wifi_set_country(&ctry);
    
    // Start promiscuous on STA interface
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);
    
    if (CHANNELS.empty()) CHANNELS = {1, 6, 11};
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
    
    // Setup channel hopping
    if (hopTimer) {
        esp_timer_stop(hopTimer);
        esp_timer_delete(hopTimer);
        hopTimer = nullptr;
    }
    
    const esp_timer_create_args_t targs = {
        .callback = &hopTimerCb, 
        .arg = nullptr, 
        .dispatch_method = ESP_TIMER_TASK, 
        .name = "hop"
    };
    esp_timer_create(&targs, &hopTimer);
    esp_timer_start_periodic(hopTimer, 300000);
    
    // Start BLE if needed
    if (currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) {
        radioStartBLE();
    }
}

void initializeScanner()
{
    Serial.println("Loading targets...");
    String txt = prefs.getString("maclist", "");
    saveTargetsList(txt);
    Serial.printf("Loaded %d targets\n", targets.size());
    
    Serial.println("Loading allowlist...");
    String wtxt = prefs.getString("allowlist", "");
    saveAllowlist(wtxt);
    Serial.printf("Loaded %d allowlist entries\n", allowlist.size());
}

// Scan tasks
void listScanTask(void *pv) {
    int secs = (int)(intptr_t)pv;
    bool forever = (secs <= 0);

    // Clear old results
    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);
        antihunter::lastResults.clear();
    }

    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" :
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    Serial.printf("[SCAN] List scan %s (%s)...\n",
                  forever ? "(forever)" : String(String("for ") + secs + " seconds").c_str(),
                  modeStr.c_str());

    stopRequested = false;
    
    if (macQueue) {
        vQueueDelete(macQueue);
        macQueue = nullptr;
        vTaskDelay(pdMS_TO_TICKS(50)); // Let deletion complete
    }
    
    macQueue = xQueueCreate(512, sizeof(Hit));
    if (!macQueue) {
        Serial.println("[SCAN] ERROR: Failed to create macQueue");
        workerTaskHandle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    uniqueMacs.clear();
    hitsLog.clear();
    totalHits = 0;
    std::set<String> seenTargets;
    framesSeen = 0;
    bleFramesSeen = 0;
    scanning = true;
    lastScanStart = millis();
    lastScanSecs = secs;
    lastScanForever = forever;

    vTaskDelay(pdMS_TO_TICKS(200));
    
    radioStartSTA();
    
    vTaskDelay(pdMS_TO_TICKS(100));

    uint32_t nextStatus = millis() + 1000;
    std::map<String, uint32_t> deviceLastSeen;
    const uint32_t DEDUPE_WINDOW = 3000;
    uint32_t lastWiFiScan = 0;
    uint32_t lastBLEScan = 0;
    Hit h;

    while ((forever && !stopRequested) ||
           (!forever && (int)(millis() - lastScanStart) < secs * 1000 && !stopRequested)) {

        if ((int32_t)(millis() - nextStatus) >= 0) {
            Serial.printf("Status: Tracking %d devices... WiFi frames=%u BLE frames=%u\n",
                         (int)uniqueMacs.size(), (unsigned)framesSeen, (unsigned)bleFramesSeen);
            nextStatus += 1000;
        }

        if ((currentScanMode == SCAN_WIFI || currentScanMode == SCAN_BOTH) &&
            (millis() - lastWiFiScan >= WIFI_SCAN_INTERVAL || lastWiFiScan == 0)) {
            lastWiFiScan = millis();
            int networksFound = WiFi.scanNetworks(false, true, false, 120);
            if (networksFound > 0) {
                for (int i = 0; i < networksFound; i++) {
                    String bssid = WiFi.BSSIDstr(i);
                    bssid.toUpperCase();
                    String ssid = WiFi.SSID(i);
                    int32_t rssi = WiFi.RSSI(i);
                    uint8_t ch = WiFi.channel(i);
                    uint8_t *bssidBytes = WiFi.BSSID(i);

                    if (ssid.length() == 0) ssid = "[Hidden]";

                    uint32_t now = millis();
                    bool shouldProcess = (deviceLastSeen.find(bssid) == deviceLastSeen.end() ||
                                          (now - deviceLastSeen[bssid] >= DEDUPE_WINDOW));

                    if (!shouldProcess) continue;

                    String origBssid = WiFi.BSSIDstr(i);
                    uint8_t mac[6];
                    bool isMatch;
                    if (triangulationActive) {
                        // Only match the specific triangulation target
                        isMatch = parseMac6(origBssid, mac) && 
                                (memcmp(mac, triangulationTarget, 6) == 0);
                    } else {
                        // Normal mode: match against target list
                        isMatch = parseMac6(origBssid, mac) && matchesMac(mac);
                    }

                    uniqueMacs.insert(bssid);

                    Hit wh;
                    memcpy(wh.mac, bssidBytes, 6);
                    wh.rssi = rssi;
                    wh.ch = ch;
                    strncpy(wh.name, ssid.c_str(), sizeof(wh.name) - 1);
                    wh.name[sizeof(wh.name) - 1] = '\0';
                    wh.isBLE = false;

                    if (isMatch) {
                        if (macQueue) {
                            if (xQueueSend(macQueue, &wh, pdMS_TO_TICKS(10)) != pdTRUE) {
                                Serial.printf("[SCAN] Queue full for target %s\n", origBssid.c_str());
                            }
                        }
                    } else {
                        hitsLog.push_back(wh);
                        deviceLastSeen[bssid] = now;
                    }
                }
                WiFi.scanDelete();
            }
            framesSeen += networksFound;
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan &&
            (millis() - lastBLEScan >= BLE_SCAN_INTERVAL || lastBLEScan == 0)) {
            lastBLEScan = millis();
            NimBLEScanResults scanResults = pBLEScan->getResults(2000, false);
            for (int i = 0; i < scanResults.getCount(); i++) {
                const NimBLEAdvertisedDevice* device = scanResults.getDevice(i);
                String macStrOrig = device->getAddress().toString().c_str();
                String macStr = macStrOrig;
                macStr.toUpperCase();
                String name = device->haveName() ? String(device->getName().c_str()) : "Unknown";
                int8_t rssi = device->getRSSI();

                uint32_t now = millis();
                bool shouldProcess = (deviceLastSeen.find(macStr) == deviceLastSeen.end() ||
                                      (now - deviceLastSeen[macStr] >= DEDUPE_WINDOW));

                if (!shouldProcess) continue;

                uint8_t mac[6];
                bool isMatch;
                if (triangulationActive) {
                    isMatch = parseMac6(macStrOrig, mac) && 
                            (memcmp(mac, triangulationTarget, 6) == 0);
                } else {
                    isMatch = parseMac6(macStrOrig, mac) && matchesMac(mac);
                }

                uniqueMacs.insert(macStr);

                if (isMatch) {
                    Hit bh;
                    memcpy(bh.mac, mac, 6);
                    bh.rssi = rssi;
                    bh.ch = 0;
                    strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                    bh.name[sizeof(bh.name) - 1] = '\0';
                    bh.isBLE = true;
                    if (macQueue) {
                        if (xQueueSend(macQueue, &bh, pdMS_TO_TICKS(10)) != pdTRUE) {
                            Serial.printf("[SCAN] Queue full for target %s\n", macStrOrig.c_str());
                        }
                    }
                } else {
                    Hit bh;
                    if (parseMac6(macStrOrig, mac)) {
                        memcpy(bh.mac, mac, 6);
                        bh.rssi = rssi;
                        bh.ch = 0;
                        strncpy(bh.name, name.c_str(), sizeof(bh.name) - 1);
                        bh.name[sizeof(bh.name) - 1] = '\0';
                        bh.isBLE = true;
                        hitsLog.push_back(bh);
                        deviceLastSeen[macStr] = now;
                    }
                }
            }
            pBLEScan->clearResults();
            bleFramesSeen += scanResults.getCount();
        }

        while (xQueueReceive(macQueue, &h, 0) == pdTRUE) {
            String macStrOrig = macFmt6(h.mac);
            String macStr = macStrOrig;
            macStr.toUpperCase();
            uint32_t now = millis();

            if (isAllowlisted(h.mac)) {
                continue;
            }

            if (deviceLastSeen.find(macStr) != deviceLastSeen.end()) {
                if (now - deviceLastSeen[macStr] < DEDUPE_WINDOW) continue;
            }

            deviceLastSeen[macStr] = now;
            uniqueMacs.insert(macStr);
            hitsLog.push_back(h);

            if (seenTargets.find(macStr) == seenTargets.end()) {
                seenTargets.insert(macStr);
                totalHits = totalHits + 1;
            }

            String logEntry = String(h.isBLE ? "BLE" : "WiFi") + " " + macStrOrig +
                              " RSSI=" + String(h.rssi) + "dBm";
            if (!h.isBLE && h.ch > 0) logEntry += " CH=" + String(h.ch);
            if (strlen(h.name) > 0 && strcmp(h.name, "WiFi") != 0 && strcmp(h.name, "Unknown") != 0) {
                logEntry += " Name=" + String(h.name);
            }
            if (gpsValid) {
                logEntry += " GPS=" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }

            Serial.printf("[HIT] %s\n", logEntry.c_str());
            logToSD(logEntry);
            sendMeshNotification(h);
        }

        if ((currentScanMode == SCAN_BLE || currentScanMode == SCAN_BOTH) && pBLEScan) {
            static uint32_t lastBLEScan = 0;
            if (millis() - lastBLEScan >= 3000) {
                NimBLEScanResults scanResults = pBLEScan->getResults(1000, false);
                pBLEScan->clearResults();
                lastBLEScan = millis();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (triangulationActive) {
        Serial.println("[SCAN] Triangulation active at scan end, stopping triangulation");
        stopTriangulation();
    }

    scanning = false;
    lastScanEnd = millis();

    {
        std::lock_guard<std::mutex> lock(antihunter::lastResultsMutex);

        std::string results =
            "List scan - Mode: " + std::string(modeStr.c_str()) +
            " Duration: " + (forever ? "Forever" : std::to_string(secs)) + "s\n" +
            "WiFi Frames seen: " + std::to_string(framesSeen) + "\n" +
            "BLE Frames seen: " + std::to_string(bleFramesSeen) + "\n" +
            "Target hits: " + std::to_string(totalHits) + "\n\n";

        std::map<String, Hit> hitsMap;
        for (const auto& targetMacStr : seenTargets) {
            Hit bestHit;
            int8_t bestRssi = -128; 
            bool found = false;

            String targetMac = targetMacStr; 
            for (const auto& hit : hitsLog) {
                String hitMacStrOrig = macFmt6(hit.mac);
                String hitMacStr = hitMacStrOrig;
                hitMacStr.toUpperCase();
                if (hitMacStr == targetMac && hit.rssi > bestRssi) {
                    bestHit = hit;
                    bestRssi = hit.rssi;
                    found = true;
                }
            }

            if (found) {
                hitsMap[targetMac] = bestHit;
            }
        }

        if (hitsMap.empty()) {
            results += "No targets detected.\n";
        } else {
            // Sort hits by RSSI
            std::vector<Hit> sortedHits;
            for (const auto& entry : hitsMap) {
                sortedHits.push_back(entry.second);
            }
            std::sort(sortedHits.begin(), sortedHits.end(),
                      [](const Hit& a, const Hit& b) { return a.rssi > b.rssi; });

            int show = sortedHits.size();
            if (show > 200) show = 200;
            for (int i = 0; i < show; i++) {
                const auto &e = sortedHits[i];
                results += std::string(e.isBLE ? "BLE " : "WiFi");
                String macOut = macFmt6(e.mac);
                results += " " + std::string(macOut.c_str());
                results += " RSSI=" + std::to_string(e.rssi) + "dBm";
                if (!e.isBLE && e.ch > 0) results += " CH=" + std::to_string(e.ch);
                if (strlen(e.name) > 0 && strcmp(e.name, "WiFi") != 0 && strcmp(e.name, "Unknown") != 0) {
                    results += " Name=" + std::string(e.name);
                }
                results += "\n";
            }
            if (static_cast<int>(sortedHits.size()) > show) {
                results += "... (" + std::to_string(sortedHits.size() - show) + " more)\n";
            }
        }

        bool hasTriangulation = (antihunter::lastResults.find("=== Triangulation Results ===") != std::string::npos);
            
        if (hasTriangulation) {
            antihunter::lastResults = results + "\n\n" + antihunter::lastResults;
        } else if (triangulationNodes.size() > 0) {
            antihunter::lastResults = antihunter::lastResults + "\n\n=== List Scan Results ===\n" + results;
        } else {
            antihunter::lastResults = results;
        }
        
        Serial.printf("[DEBUG] Results stored: %d chars\n", results.length());
    }
    
    radioStopSTA();
    delay(500);
    
    vTaskDelay(pdMS_TO_TICKS(100));
    workerTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

void cleanupMaps() {
    const size_t MAX_MAP_SIZE = 100;
    const size_t MAX_TIMING_SIZE = 50;
    const size_t MAX_LOG_SIZE = 500;
    const uint32_t EVICTION_AGE_MS = 30000;
    uint32_t now = millis();

    if (deauthSourceCounts.size() > MAX_MAP_SIZE) {
        std::vector<String> toRemove;
        for (const auto& entry : deauthSourceCounts) {
            if (entry.second < 2) {
                toRemove.push_back(entry.first);
            }
        }
        for (const auto& key : toRemove) {
            deauthSourceCounts.erase(key);
            deauthTargetCounts.erase(key);
            deauthTimings.erase(key);
        }
        for (auto it = deauthTimings.begin(); it != deauthTimings.end(); ) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(), [now](uint32_t t) { return now - t > EVICTION_AGE_MS; }), vec.end());
            if (vec.size() > MAX_TIMING_SIZE) {
                vec.erase(vec.begin(), vec.begin() + (vec.size() - MAX_TIMING_SIZE));  // Vector OK here
            }
            if (vec.empty()) {
                it = deauthTimings.erase(it);  // Safe erase with post-increment
            } else {
                ++it;
            }
        }
    }
    if (deauthQueue) xQueueReset(deauthQueue);  // Flush old hits

    // Clean deauth logs (vector - trim oldest)
    if (deauthLog.size() > MAX_LOG_SIZE) {
        deauthLog.erase(deauthLog.begin(), deauthLog.begin() + (deauthLog.size() - MAX_LOG_SIZE));
    }
}


// Allowlist

static bool parseAllowlistEntry(const String &ln, Allowlist &out)
{
    String t;
    for (size_t i = 0; i < ln.length(); ++i)
    {
        char c = ln[i];
        if (isxdigit((int)c))
            t += (char)toupper(c);
    }
    if (t.length() == 12)
    {
        for (int i = 0; i < 6; i++)
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 6;
        return true;
    }
    if (t.length() == 6)
    {
        for (int i = 0; i < 3; i++)
        {
            out.bytes[i] = (uint8_t)strtoul(t.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        out.len = 3;
        return true;
    }
    return false;
}

size_t getAllowlistCount()
{
    return allowlist.size();
}

String getAllowlistText()
{
    String out;
    for (auto &w : allowlist)
    {
        if (w.len == 6)
        {
            char b[18];
            snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                     w.bytes[0], w.bytes[1], w.bytes[2], w.bytes[3], w.bytes[4], w.bytes[5]);
            out += b;
        }
        else
        {
            char b[9];
            snprintf(b, sizeof(b), "%02X:%02X:%02X", w.bytes[0], w.bytes[1], w.bytes[2]);
            out += b;
        }
        out += "\n";
    }
    return out;
}

void saveAllowlist(const String &txt)
{
    prefs.putString("allowlist", txt);
    allowlist.clear();
    int start = 0;
    while (start < txt.length())
    {
        int nl = txt.indexOf('\n', start);
        if (nl < 0) nl = txt.length();
        String ln = txt.substring(start, nl);
        ln.trim();
        if (ln.length() > 0)
        {
            Allowlist w;
            if (parseAllowlistEntry(ln, w))
            {
                allowlist.push_back(w);
            }
        }
        start = nl + 1;
    }
}

bool isAllowlisted(const uint8_t *mac)
{
    for (auto &w : allowlist)
    {
        if (w.len == 6)
        {
            if (memcmp(w.bytes, mac, 6) == 0) return true;
        }
        else if (w.len == 3)
        {
            if (memcmp(w.bytes, mac, 3) == 0) return true;
        }
    }
    return false;
}