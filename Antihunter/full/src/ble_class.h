#pragma once
#include <stddef.h>
#include <stdint.h>

bool bleClassify(const uint8_t *adv, size_t len, char *out, size_t outLen);
