#pragma once
#include <mutex>
#include <string>
#include "esp_task_wdt.h" 

namespace antihunter {
    extern std::string lastResults;
    extern std::mutex lastResultsMutex;
}