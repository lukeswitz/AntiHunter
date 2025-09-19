#include "hardware.h"
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include "esp_wifi.h"


extern Preferences prefs;
extern ScanMode currentScanMode;
extern std::vector<uint8_t> CHANNELS;

// GPS
TinyGPSPlus gps;
HardwareSerial GPS(2);
bool sdAvailable = false;
String lastGPSData = "No GPS data";
float gpsLat = 0.0, gpsLon = 0.0;
bool gpsValid = false;

// Viration Sensor
volatile bool vibrationDetected = false;
unsigned long lastVibrationTime = 0;
unsigned long lastVibrationAlert = 0;
const unsigned long VIBRATION_ALERT_INTERVAL = 5000; 

// Diagnostics
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


void initializeHardware()
{
    Serial.println("Loading preferences...");
    prefs.begin("ouispy", false);

    String nodeId = prefs.getString("nodeId", "");
    if (nodeId.length() == 0)
    {
        uint64_t chipid = ESP.getEfuseMac();
        nodeId = "NODE_" + String((uint32_t)(chipid >> 32), HEX) + String((uint32_t)chipid, HEX);
        prefs.putString("nodeId", nodeId);
    }
    setNodeId(nodeId);
    Serial.println("[NODE_ID] " + nodeId);
    Serial.printf("Hardware initialized: nodeID=%s\n", nodeId);
}

void saveConfiguration()
{
  // TODO save wifi channels and other granular stuff
}

String getDiagnostics() {
    static unsigned long lastDiagTime = 0;
    static unsigned long lastSDTime = 0;
    static String cachedDiag = "";
    static String cachedSDInfo = "";
    
    if (millis() - lastDiagTime < 5000 && cachedDiag.length() > 0) {
        return cachedDiag;
    }
    lastDiagTime = millis();
    
    String s;
    String modeStr = (currentScanMode == SCAN_WIFI) ? "WiFi" : 
                     (currentScanMode == SCAN_BLE) ? "BLE" : "WiFi+BLE";

    s += "Scan Mode: " + modeStr + "\n";
    s += String("Scanning: ") + (scanning ? "yes" : "no") + "\n";
    s += "WiFi Frames seen: " + String((unsigned)framesSeen) + "\n";
    s += "BLE Frames seen: " + String((unsigned)bleFramesSeen) + "\n";
    s += "Total hits: " + String(totalHits) + "\n";
    s += "Current channel: " + String(WiFi.channel()) + "\n";
    s += "AP IP: " + WiFi.softAPIP().toString() + "\n";
    s += "Unique devices: " + String((int)uniqueMacs.size()) + "\n";
    s += "Targets: " + String(getTargetCount()) + "\n";
    s += "Mesh Node ID: " + getNodeId() + "\n";
    s += "Vibration sensor: " + String(lastVibrationTime > 0 ? "Active" : "Standby") + "\n";
    if (lastVibrationTime > 0) {
        unsigned long vibrationTime = lastVibrationTime;
        unsigned long seconds = vibrationTime / 1000;
        unsigned long minutes = seconds / 60;
        unsigned long hours = minutes / 60;
        
        seconds = seconds % 60;
        minutes = minutes % 60;
        hours = hours % 24;
        
        char timeStr[12];
        snprintf(timeStr, sizeof(timeStr), "%02lu:%02lu:%02lu", hours, minutes, seconds);
        
        unsigned long agoSeconds = (millis() - lastVibrationTime) / 1000;
        
        s += "Last Movement: " + String(timeStr) + " (" + String(agoSeconds) + "s ago)\n";
    }

    s += "SD Card: " + String(sdAvailable ? "Available" : "Not available") + "\n";
    if (sdAvailable) {
        if (millis() - lastSDTime > 30000 || cachedSDInfo.length() == 0) {
            lastSDTime = millis();
            cachedSDInfo = "";
            
            uint64_t cardSize = SD.cardSize() / (1024 * 1024);
            uint8_t cardType = SD.cardType();
            String cardTypeStr = (cardType == CARD_MMC) ? "MMC" :
                                 (cardType == CARD_SD) ? "SDSC" :
                                 (cardType == CARD_SDHC) ? "SDHC" : "UNKNOWN";
            cachedSDInfo += "SD Card Type: " + cardTypeStr + "\n";
            cachedSDInfo += "SD Card Size: " + String(cardSize) + "MB\n";

            File root = SD.open("/");
            if (root) {
                cachedSDInfo += "SD Card Files:\n";
                while (true) {
                    File entry = root.openNextFile();
                    if (!entry)
                        break;

                    String fileName = String(entry.name());
                    if (fileName.startsWith(".")) {
                        entry.close();
                        continue;
                    }

                    cachedSDInfo += "  " + fileName + " (" + String(entry.size()) + " bytes)\n";
                    entry.close();
                }
                root.close();
            } else {
                cachedSDInfo += "Failed to read SD card files.\n";
            }
        }
        s += cachedSDInfo;
    }

    s += "GPS: ";
    if (gpsValid) {
        s += "Locked\n";
    } else {
        s += "Waiting for data\n";
    }

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
    
    s += "WiFi Channels: ";
    for (auto c : CHANNELS) {
        s += String((int)c) + " ";
    }
    s += "\n";

    cachedDiag = s;
    return s;
}

void initializeSD()
{
    Serial.println("Initializing SD card...");
    Serial.printf("[SD] Pins SCK=%d MISO=%d MOSI=%d CS=%d\n", SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);

    SPI.end();
    SPI.begin(SD_CLK_PIN, SD_MISO_PIN, SD_MOSI_PIN);
    delay(100);

    const uint32_t tryFreqs[] = {1000000, 4000000, 8000000, 10000000};
    for (uint32_t f : tryFreqs)
    {
        Serial.printf("[SD] Trying frequency: %lu Hz\n", f);
        if (SD.begin(SD_CS_PIN, SPI, f))
        {
            Serial.println("SD card initialized successfully");
            sdAvailable = true;

            uint8_t cardType = SD.cardType();
            Serial.print("SD Card Type: ");
            if (cardType == CARD_MMC)
            {
                Serial.println("MMC");
            }
            else if (cardType == CARD_SD)
            {
                Serial.println("SDSC");
            }
            else if (cardType == CARD_SDHC)
            {
                Serial.println("SDHC");
            }
            else
            {
                Serial.println("UNKNOWN");
            }

            uint64_t cardSize = SD.cardSize() / (1024 * 1024);
            Serial.printf("SD Card Size: %lluMB\n", cardSize);
            return;
        }
        delay(100);
    }
    Serial.println("SD card initialization failed");
}

void initializeGPS() {
    Serial.println("Initializing GPS…");

    // Grow buffer and start UART
    GPS.setRxBufferSize(2048);
    GPS.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    // Give it a moment to start spitting characters
    delay(120);
    unsigned long start = millis();
    bool sawSentence = false;
    while (millis() - start < 2000) {
        if (GPS.available()) {
            char c = GPS.read();
            if (gps.encode(c)) {
                sawSentence = true;
                break;
            }
        }
    }

    if (sawSentence) {
        Serial.println("[GPS] GPS module responding (NMEA detected)");
    } else {
        Serial.println("[GPS] No NMEA data – check wiring or allow cold-start time");
        Serial.println("[GPS] First fix can take 5–15 minutes outdoors");
    }

    // Send startup GPS status to server
    sendStartupStatus();

    Serial.printf("[GPS] UART on RX:%d TX:%d\n", GPS_RX_PIN, GPS_TX_PIN);
}

void sendStartupStatus() {
    float temp_c = temperatureRead();
    float temp_f = (temp_c * 9.0 / 5.0) + 32.0;

    String startupMsg = getNodeId() + ": STARTUP: System initialized";
    startupMsg += " GPS:";
    startupMsg += (gpsValid ? "LOCKED" : "SEARCHING");
    startupMsg += "TEMP: " + String(temp_c, 1) + "°C / " + String(temp_f, 1) + "°F\n";
    startupMsg += " SD:";
    startupMsg += (sdAvailable ? "OK" : "FAIL");
    startupMsg += " Status:ONLINE";
    
    Serial.printf("[STARTUP] %s\n", startupMsg.c_str());
    
    if (Serial1.availableForWrite() >= startupMsg.length()) {
        Serial1.println(startupMsg);
        Serial1.flush();
    }
    
    logToSD(startupMsg);
}

void sendGPSLockStatus(bool locked) {
    String gpsMsg = getNodeId() + ": GPS: ";
    gpsMsg += (locked ? "LOCKED" : "LOST");
    if (locked) {
        gpsMsg += " Location:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
        gpsMsg += " Satellites:" + String(gps.satellites.value());
        gpsMsg += " HDOP:" + String(gps.hdop.hdop(), 2);
    }
    
    Serial.printf("[GPS] %s\n", gpsMsg.c_str());
    
    if (Serial1.availableForWrite() >= gpsMsg.length()) {
        Serial1.println(gpsMsg);
        Serial1.flush();
    }
    
    logToSD("GPS Status: " + gpsMsg);
}

void updateGPSLocation() {
    static unsigned long lastDataTime = 0;
    static bool wasLocked = false;

    while (GPS.available() > 0) {
        char c = GPS.read();
        if (gps.encode(c)) {
            lastDataTime = millis();

            bool nowLocked = gps.location.isValid();
            
            if (nowLocked) {
                gpsLat = gps.location.lat();
                gpsLon = gps.location.lng();
                gpsValid = true;
                lastGPSData = "Lat: " + String(gpsLat, 6)
                            + ", Lon: " + String(gpsLon, 6)
                            + " (" + String((millis() - lastDataTime) / 1000) 
                            + "s ago)";
                
                if (!wasLocked && nowLocked) {
                    sendGPSLockStatus(true);
                }
            } else {
                gpsValid = false;
                lastGPSData = "No valid GPS fix (" 
                            + String((millis() - lastDataTime) / 1000)
                            + "s ago)";
                
                if (wasLocked && !nowLocked) {
                    sendGPSLockStatus(false);
                }
            }
            
            wasLocked = nowLocked;
        }
    }

    if (lastDataTime > 0 && millis() - lastDataTime > 30000) {
        if (gpsValid) {
            gpsValid = false;
            sendGPSLockStatus(false);
        }
        lastGPSData = "No data for " 
                    + String((millis() - lastDataTime) / 1000)
                    + "s";
    }
}


void logToSD(const String &data) {
    if (!sdAvailable) return;
    
    static uint32_t totalWrites = 0;
    static File logFile;
    
    if (!SD.exists("/")) {
        SD.mkdir("/");
    }

    if (!logFile || totalWrites % 50 == 0) {
        if (logFile) {
            logFile.close();
        }
        logFile = SD.open("/antihunter.log", FILE_APPEND);
        if (!logFile) {
            logFile = SD.open("/antihunter.log", FILE_WRITE);
            if (!logFile) {
                Serial.println("[SD] Failed to open log file");
                return;
            }
        }
    }
    
    uint32_t ts = millis();
    uint8_t hours = (ts / 3600000) % 24;
    uint8_t mins = (ts / 60000) % 60;
    uint8_t secs = (ts / 1000) % 60;
    
    logFile.printf("[%02d:%02d:%02d] %s\n", hours, mins, secs, data.c_str());
    
    // Batch flush every 10 writes 
    if (++totalWrites % 10 == 0) {
        logFile.flush();
    }
    static unsigned long lastSizeCheck = 0;
    if (millis() - lastSizeCheck > 10000) {
        File checkFile = SD.open("/antihunter.log", FILE_READ);
        if (checkFile) {
            Serial.printf("[SD] Log file size: %lu bytes\n", checkFile.size());
            checkFile.close();
        }
        lastSizeCheck = millis();
    }
}

void logVibrationEvent(int sensorValue) {
    String event = String(sensorValue ? "Motion" : "Impact") + " detected";
    if (gpsValid) {
        event += " @" + String(gpsLat, 4) + "," + String(gpsLon, 4);
    }
    logToSD(event);
    Serial.printf("[MOTION] %s\n", event.c_str());
}

String getGPSData()
{
    return lastGPSData;
}

// Vibration Sensor
void IRAM_ATTR vibrationISR() {
    vibrationDetected = true;
    lastVibrationTime = millis();
}

void initializeVibrationSensor() {
    pinMode(VIBRATION_PIN, INPUT);
    attachInterrupt(digitalPinToInterrupt(VIBRATION_PIN), vibrationISR, RISING);
    Serial.println("[VIBRATION] Sensor initialized on GPIO1");
}

void checkAndSendVibrationAlert() {
    if (vibrationDetected) {
        vibrationDetected = false;
        
        // Only send alert if enough time has passed since last alert
        if (millis() - lastVibrationAlert > VIBRATION_ALERT_INTERVAL) {
            lastVibrationAlert = millis();
            
            // Format timestamp as HH:MM:SS
            unsigned long currentTime = lastVibrationTime;
            unsigned long seconds = currentTime / 1000;
            unsigned long minutes = seconds / 60;
            unsigned long hours = minutes / 60;
            
            seconds = seconds % 60;
            minutes = minutes % 60;
            hours = hours % 24;
            
            char timeStr[12];
            snprintf(timeStr, sizeof(timeStr), "%02lu:%02lu:%02lu", hours, minutes, seconds);
            int sensorValue = digitalRead(VIBRATION_PIN);
            
            String vibrationMsg = getNodeId() + ": VIBRATION: Movement detected at " + String(timeStr) + " (sensor=" + String(sensorValue) + ")";
            
            // Add GPS if we have it
            if (gpsValid) {
                vibrationMsg += " GPS:" + String(gpsLat, 6) + "," + String(gpsLon, 6);
            }
            
            Serial.printf("[VIBRATION] Sending mesh alert: %s\n", vibrationMsg.c_str());
            
            if (Serial1.availableForWrite() >= vibrationMsg.length()) {
                Serial1.println(vibrationMsg);
                Serial1.flush();
            }
            
            logVibrationEvent(sensorValue);
            
        } else {
            Serial.printf("[VIBRATION] Alert rate limited - %lums since last alert\n", millis() - lastVibrationAlert);
        }
    }
}