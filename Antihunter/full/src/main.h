#pragma once
#include <mutex>
#include <string>

namespace antihunter {
    extern std::string lastResults;
    extern std::mutex lastResultsMutex;
}