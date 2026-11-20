#pragma once

inline int g_stubTask = 0;
inline void *xTaskGetCurrentTaskHandle() { return &g_stubTask; }
