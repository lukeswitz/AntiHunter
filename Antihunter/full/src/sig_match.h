#pragma once
#include <stddef.h>
#include <stdint.h>

static const uint16_t SIG_NONE = 0xFFFF;

uint16_t sigMatch(const uint8_t *mac, bool isBLE, const char *name, const uint8_t *adv, size_t advLen);
const char *sigFleetName(uint16_t idx);
const char *sigFleetKind(uint16_t idx);
