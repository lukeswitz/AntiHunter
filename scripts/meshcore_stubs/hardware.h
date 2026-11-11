#pragma once
#include <Arduino.h>

uint32_t getEventTimestamp();
extern unsigned long lastSaveTime;
void saveConfiguration();
