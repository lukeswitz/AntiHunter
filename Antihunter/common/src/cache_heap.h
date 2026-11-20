#pragma once

#include <cstddef>

// PSRAM region for RAM caches; the rest of PSRAM stays with WiFi, LWIP, BLE and the web server.
bool cacheHeapInit(size_t systemBytes);
void *cacheHeapAlloc(size_t bytes);
void cacheHeapRelease(void *p);
size_t cacheHeapSize();
size_t cacheHeapFreeBytes();
size_t cacheHeapMinFreeBytes();
size_t cacheHeapSystemMinFreeBytes();

using CacheShedFn = size_t (*)(void *ctx);
void cacheHeapAddShedder(const void *owner, CacheShedFn fn, void *ctx);
size_t cacheHeapShedOthers(const void *owner);
bool cacheHeapMakeRoom(size_t bytes, const void *owner, CacheShedFn shedSelf, void *ctx);
