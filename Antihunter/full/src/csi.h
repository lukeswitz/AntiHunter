#pragma once
#include <Arduino.h>
#include <atomic>
#include "csi_metric.h"

#define CSI_MAX_LINKS 12

struct CsiLinkView {
    char mac[18];
    uint32_t packets;
    uint32_t ageMs;
    uint32_t events;
    int8_t rssi;
    float rate;
    float mad;
    float floorMad;
    float spread;
    float score;
    float acf;
    float vote;
    float z;
    float peakScore;
    bool motion;
};

extern std::atomic<bool> csiRawDump;
extern std::atomic<bool> csiTelemetry;
extern std::atomic<bool> csiAutoTrigger;
extern std::atomic<uint8_t> csiPinnedChannel;
extern std::atomic<uint32_t> csiThresholdMilli;
extern std::atomic<uint64_t> csiExcludeMac;
extern std::atomic<uint32_t> csiHoldMs;
extern std::atomic<uint32_t> csiConsecNeeded;
extern std::atomic<uint32_t> csiSolicitMs;

void csiMotionTask(void *pv);
String getCsiResults();
String getCsiJson();
void setCsiConfig(uint8_t channel, float threshold, uint32_t holdMs, uint32_t consec,
                  bool rawDump, bool telemetry, bool autoTrigger);
void loadCsiConfigFromPrefs();
void csiClearCalibration();
bool csiClearResults();
