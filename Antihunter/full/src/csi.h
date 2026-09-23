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
    float sig;
    float peakScore;
    bool motion;
};

extern std::atomic<bool> csiRawDump;
extern std::atomic<bool> csiTelemetry;
extern std::atomic<uint8_t> csiPinnedChannel;
extern std::atomic<uint32_t> csiThresholdMilli;
extern std::atomic<uint64_t> csiExcludeMac;
extern std::atomic<uint32_t> csiHoldMs;
extern std::atomic<uint32_t> csiAreaDutyMinS;
extern std::atomic<uint32_t> csiAreaRadiosNeeded;
void setCsiAreaConfig(uint32_t dutyMinS, uint32_t radiosNeeded);
extern std::atomic<uint32_t> csiConsecNeeded;
extern std::atomic<uint32_t> csiSolicitMs;
extern std::atomic<uint8_t> csiNoTx;
extern std::atomic<uint8_t> csiAllowRandom;
void setCsiNoTx(bool noTx);
extern std::atomic<uint8_t> csiMgmtOnly;
extern std::atomic<bool> csiRequireCeVld;

void csiMotionTask(void *pv);
String getCsiResults();
String getCsiJson();
void setCsiConfig(uint8_t channel, float threshold, uint32_t holdMs, uint32_t consec,
                  bool rawDump, bool telemetry);
void loadCsiConfigFromPrefs();
void csiClearCalibration();
bool csiClearResults();
