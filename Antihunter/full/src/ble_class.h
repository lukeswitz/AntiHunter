#pragma once
#include <stddef.h>
#include <stdint.h>

extern volatile bool bleClassifyEnabled;
bool bleClassify(const uint8_t *adv, size_t len, char *out, size_t outLen);
