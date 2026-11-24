#pragma once
#include <Arduino.h>
#include <atomic>
#include <functional>
#include <memory>
#include <vector>

struct LogView {
    const char *path = nullptr;
    uint32_t off = 0;
    uint32_t lim = 50;
    String sortKey;
    bool asc = false;
    String q;
    std::vector<String> keys;
    String topKey;
    String campTag;
    bool fresh = false;
    uint32_t rangeFrom = 0;
    uint32_t rangeTo = 0;
    std::atomic<bool> done{false};
    String out;
    std::function<void()> then;
};

const char *logViewPath(const String &id);
bool logViewStart(std::shared_ptr<LogView> v);
