#include "main.h"
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


Preferences prefs;;
ScanMode currentScanMode = SCAN_WIFI;
std::vector<uint8_t> CHANNELS = {1, 6, 11};
volatile bool stopRequested = false;

TaskHandle_t workerTaskHandle = nullptr;
TaskHandle_t blueTeamTaskHandle = nullptr;

std::string antihunter::lastResults = "No scan data yet.";
std::mutex antihunter::lastResultsMutex;

void uartForwardTask(void *parameter) {
  static String meshBuffer = "";
  
  for (;;) {
    while (Serial1.available()) {
      char c = Serial1.read();
      Serial.write(c);
      
      if (c == '\n' || c == '\r') {
        if (meshBuffer.length() > 0) {
          Serial.printf("[MESH RX] %s\n", meshBuffer.c_str());
          String toProcess = meshBuffer;
          int colonPos = meshBuffer.indexOf(": ");
          if (colonPos > 0) {
            toProcess = meshBuffer.substring(colonPos + 2);
          }
          processMeshMessage(toProcess);
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
    String nodeMsg = "[NODE_ID] " + getNodeId();
    // Add GPS coordinates if available
    if (gpsValid) {
        nodeMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
    }
    Serial.println(nodeMsg);
    // send mesh
    if (Serial1.availableForWrite() >= nodeMsg.length()) {
        Serial1.println(nodeMsg);
    }
}

void setup() {
    delay(1000);
    Serial.begin(115200);
    delay(300);
    Serial.println("\n=== Antihunter v5 Boot ===");
    Serial.println("WiFi+BLE dual-mode scanner");
    
    delay(1000);

    initializeHardware();
    delay(10);
    initializeNetwork();  // starts AP and mesh UART
    delay(500);
    initializeSD();
    initializeGPS();
    delay(500);
    initializeVibrationSensor();
    initializeScanner();
    
    xTaskCreatePinnedToCore(uartForwardTask, "UARTForwardTask", 4096, NULL, 2, NULL, 1);
    delay(120);

    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = 30000,
        .idle_core_mask = 0,
        .trigger_panic = true
    };

    Serial.println("=== Boot Complete ===");
    Serial.printf("Web UI: http://192.168.4.1/ (SSID: %s, PASS: %s)\n", AP_SSID, AP_PASS);
    Serial.printf("Mesh @ 115200 on pins %d,%d\n", MESH_RX_PIN, MESH_TX_PIN);
    
    delay(2000);
}

void loop() {
    // NodeID HB every 15 minutes
    static unsigned long lastNodeIdSend = 0;
    if (millis() - lastNodeIdSend > 900000) {
      sendNodeIdUpdate();
      lastNodeIdSend = millis();
  }
  updateGPSLocation();
  processUSBToMesh();
  checkAndSendVibrationAlert();

  delay(120);
}