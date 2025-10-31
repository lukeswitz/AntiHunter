#include "main.h"
#include "triangulation.h"
#include <SPI.h>
#include <Arduino.h>
#include <Preferences.h>
#include "network.h"
#include "scanner.h" 
#include "hardware.h"
#include <SD.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include "esp_wifi.h"


Preferences prefs;
ScanMode currentScanMode = SCAN_WIFI;
std::vector<uint8_t> CHANNELS = {1, 6, 11};
volatile bool stopRequested = false;

unsigned long lastNodeIdSend = 0;
unsigned long lastRTCUpdate = 0;

TaskHandle_t workerTaskHandle = nullptr;
TaskHandle_t blueTeamTaskHandle = nullptr;

std::string antihunter::lastResults = "No scan data yet.";
std::mutex antihunter::lastResultsMutex;

void uartForwardTask(void *parameter) {
  static String meshBuffer = "";
  
  for (;;) {
    while (Serial1.available()) {
      uint32_t rxMicros = micros();
      
      char c = Serial1.read();
      Serial.write(c);
      
      if (c == '\n' || c == '\r') {
        if (meshBuffer.length() > 0) {
          Serial.printf("[MESH RX] %s\n", meshBuffer.c_str());
          
          String toProcess = meshBuffer;
          String senderId = "";
          int colonPos = meshBuffer.indexOf(": ");
          if (colonPos > 0) {
            senderId = meshBuffer.substring(0, colonPos);
            toProcess = meshBuffer.substring(colonPos + 2);
          }
          
          if (toProcess.startsWith("TIME_SYNC_REQ:")) {
            processMeshTimeSyncWithDelay(senderId, toProcess, rxMicros);
          } else {
            processMeshMessage(toProcess);
          }
          
          meshBuffer = "";
        }
      } else {
        meshBuffer += c;
        if (meshBuffer.length() > 1024) {
          meshBuffer = "";
        }
      }
    }
    delay(2);
  }
}

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

void sendNodeIdUpdate() {
    float esp_temp = temperatureRead();
    float esp_temp_f = (esp_temp * 9.0 / 5.0) + 32.0;
    String timestamp = getFormattedTimestamp();
    timestamp.replace(" ", "_");
    
    String nodeMsg = "[NODE_HB] " + getNodeId() + 
                     " Time:" + timestamp + 
                     " Temp:" + String(esp_temp, 1) + "C/" + String(esp_temp_f, 1) + "F";
    
    if (gpsValid) {
        nodeMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    
    Serial.println(nodeMsg);
    sendToSerial1(nodeMsg, true);
}
void randomizeMacAddress() {
    uint8_t newMACAddress[6];
    newMACAddress[0] = (random(0, 256) & 0xFE) | 0x02;
    for (int i = 1; i < 6; i++) {
        newMACAddress[i] = random(0, 256);
    }
    
    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, newMACAddress);
    
    Serial.printf("[MAC] Randomized MAC: %02x:%02x:%02x:%02x:%02x:%02x (status: %d)\n",
                  newMACAddress[0], newMACAddress[1], newMACAddress[2],
                  newMACAddress[3], newMACAddress[4], newMACAddress[5], err);
}

void setup() {
    delay(1000);
    Serial.begin(115200);
    delay(300);
    Serial.println("\n=== Antihunter v5 Boot ===");
    Serial.println("WiFi+BLE dual-mode scanner");

    delay(400);
    initializeHardware();
    delay(10);
    initializeDroneDetector();
    delay(20);
    initializeSD();
    
    if (waitForInitialConfig()) {
        delay(1000);
    }

    delay(500);
    loadConfiguration();
    initializeNetwork();
    delay(500);
    initializeGPS();
    delay(1000);
    initializeRTC();
    delay(500);
    initializeVibrationSensor();
    initializeScanner();
    
    xTaskCreatePinnedToCore(uartForwardTask, "UARTForwardTask", 4096, NULL, 2, NULL, 1);
    delay(120);

    Serial.println("===== ANTIHUNTER BOOT COMPLETE =====");
    Serial.printf("WEB UI: http://192.168.4.1/ (SSID: %s, PASS: %s)\n", AP_SSID, AP_PASS);
    Serial.printf("RANDOMIZED MAC: %s\n", WiFi.softAPmacAddress().c_str());
    
    delay(2000);
}

void loop() {
    static unsigned long lastSaveSend = 0;

     // Handle serial time setting
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd.startsWith("SETTIME:")) {
            time_t epoch = cmd.substring(8).toInt();
            if (epoch > 1609459200 && setRTCTimeFromEpoch(epoch)) {
                Serial.println("OK: RTC set");
                broadcastToTerminal("[RTC] OK: RTC set");
            }
        }
    }
    
    if (millis() - lastSaveSend > 600000) {
      saveConfiguration();
      sendNodeIdUpdate();
      lastSaveSend = millis();
    }

    if (millis() - lastRTCUpdate > 1000) {
        updateRTCTime();
        updateGPSLocation();
        disciplineRTCFromGPS();
        lastRTCUpdate = millis();
    }

    if (tamperEraseActive) {
        checkTamperTimeout();
    }

    processUSBToMesh();
    checkAndSendVibrationAlert();

  delay(100);
}