#pragma once
#include <Arduino.h>
#include <atomic>

#define PCAP_RADIO_WIFI 0
#define PCAP_RADIO_BLE  1

#define PCAP_BAND_24    0
#define PCAP_BAND_5     1
#define PCAP_BAND_BOTH  2

extern std::atomic<bool> pcapBleEnabled;

void pcapCaptureTask(void *pv);
void setPcapConfig(uint8_t radio, uint8_t band, const String &channelsCsv,
                   uint16_t dwellMs, bool mgmtOnly);
void setPcapAutoTriggered(bool autoTriggered);
void setPcapAutoLimits(uint32_t budgetMB, uint32_t freeFloorMB);
uint32_t getPcapAutoBudgetMB();
uint32_t getPcapFreeFloorMB();
void loadPcapPrefs();
void pcapOnBleAdv(const uint8_t *addr, uint8_t addrType, uint8_t advType,
                  const uint8_t *payload, uint16_t payloadLen, uint16_t advLen,
                  const uint8_t *targetAddr, int8_t rssi);
String getPcapResults();
String getPcapStatusJson();
String getPcapListJson();
String getPcapFilePath();
bool pcapNameIsValid(const String &name);
bool pcapDeleteFile(const String &name);
uint32_t pcapDeleteAll();
bool pcapDualBandCapable();
