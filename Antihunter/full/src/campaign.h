#pragma once
#include <Arduino.h>

#define CAMPAIGN_FILE "/campaigns.csv"

void campaignInit();
const char *campaignName();
bool campaignStart(const String &name);
bool campaignStop();
