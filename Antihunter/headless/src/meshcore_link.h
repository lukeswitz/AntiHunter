#pragma once
#include <Arduino.h>

extern bool g_meshcoreTransport;

void meshcoreLoadPref();
void meshcoreSetTransport(bool on);
void meshcoreWriteText(const String &msg);
void meshcoreFeedByte(uint8_t c);
bool meshcoreNextText(String &outText);
uint16_t meshcoreTextCap();
void meshcorePoll();
