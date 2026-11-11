#pragma once
#include <Arduino.h>

typedef void *SemaphoreHandle_t;
typedef uint32_t TickType_t;
#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
inline int xSemaphoreTake(SemaphoreHandle_t, TickType_t) { return pdTRUE; }
inline void xSemaphoreGive(SemaphoreHandle_t) {}

extern SemaphoreHandle_t serial1Mutex;
bool meshEnqueue(const String &msg, bool priority = false);
String getNodeId();
