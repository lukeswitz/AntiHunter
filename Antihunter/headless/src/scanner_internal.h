#pragma once
// Shared internals for the scanner translation units (scanner.cpp + scanner_probe.cpp).
#include "scanner.h"
#include <mutex>
#include <set>
#include <map>

// ---- Probe-subsystem shared types ----
using ProbeDevicesMap = std::map<String, ProbeDevice, std::less<String>,
    PsramAllocator<std::pair<const String, ProbeDevice>>>;
using StringSetPsram = std::set<String, std::less<String>, PsramAllocator<String>>;

// ---- Probe-subsystem globals (defined in scanner.cpp) ----
extern ProbeDevicesMap probeDevices;
extern std::mutex probeMutex;
extern StringSetPsram uniqueSsids;
extern StringSetPsram respondedSsids;

// ---- Probe SSID helpers (defined in scanner_probe.cpp, called from snifferScanTask) ----
void addProbeSsid(ProbeDevice &dev, const char *ssid, bool fromResponse = false);
bool extractSsidFromIE(const uint8_t *payload, uint16_t frameLen, uint16_t ieStart, char *ssidBuf, size_t ssidBufSize);
bool extractSsidFromProbe(const uint8_t *payload, uint16_t frameLen, char *ssidBuf, size_t ssidBufSize, bool *isWildcard = nullptr);

// ---- Shared scanner helpers (defined in scanner.cpp, called from scanner_probe.cpp) ----
bool matchesMac(const uint8_t *mac);
String sanitizeAscii(const char *s, size_t maxLen);

// ---- Shared scanner state (ScanMode from network.h; NimBLEScan from NimBLE headers) ----
extern std::atomic<bool> scanning;
extern std::atomic<bool> stopRequested;
extern ScanMode currentScanMode;
extern NimBLEScan *pBLEScan;
