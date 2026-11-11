#pragma once
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <string>
#include <vector>

class String {
public:
    std::string s;
    String() {}
    String(const char *c) : s(c ? c : "") {}
    String(const std::string &x) : s(x) {}
    unsigned int length() const { return (unsigned int)s.size(); }
    const char *c_str() const { return s.c_str(); }
    void reserve(unsigned int n) { s.reserve(n); }
    String &operator+=(const String &o) { s += o.s; return *this; }
    String &operator+=(const char *o) { s += o; return *this; }
    String &operator+=(char c) { s += c; return *this; }
    String substring(unsigned int a, unsigned int b) const {
        if (a > s.size()) a = (unsigned int)s.size();
        if (b > s.size()) b = (unsigned int)s.size();
        return String(s.substr(a, b > a ? b - a : 0));
    }
    String substring(unsigned int a) const { return substring(a, (unsigned int)s.size()); }
    bool startsWith(const String &p) const { return s.compare(0, p.s.size(), p.s) == 0; }
    int indexOf(const char *p) const {
        size_t i = s.find(p);
        return i == std::string::npos ? -1 : (int)i;
    }
    void remove(unsigned int i, unsigned int n) { s.erase(i, n); }
    bool operator==(const char *o) const { return s == o; }
};
inline String operator+(const String &a, const char *b) { return String(a.s + b); }

extern uint32_t g_fakeMillis;
inline uint32_t millis() { return g_fakeMillis; }
inline void vTaskDelay(uint32_t ticks) { g_fakeMillis += ticks; }

struct HostSerial {
    void printf(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        std::vprintf(fmt, ap);
        va_end(ap);
    }
};
extern HostSerial Serial;

struct HostRadioSerial {
    std::deque<uint8_t> rx;
    std::vector<uint8_t> tx;
    std::function<void(const std::vector<uint8_t> &frame)> onFrame;
    size_t write(const uint8_t *b, size_t n) {
        tx.insert(tx.end(), b, b + n);
        while (tx.size() >= 3 && tx[0] == 0x3C) {
            size_t len = tx[1] | (tx[2] << 8);
            if (tx.size() < 3 + len) break;
            std::vector<uint8_t> frame(tx.begin() + 3, tx.begin() + 3 + len);
            frames.push_back(frame);
            tx.erase(tx.begin(), tx.begin() + 3 + len);
            if (onFrame) onFrame(frame);
        }
        return n;
    }
    void flush() {}
    int available() { return (int)rx.size(); }
    int read() {
        if (rx.empty()) return -1;
        int c = rx.front();
        rx.pop_front();
        return c;
    }
    void reply(const std::vector<uint8_t> &payload) {
        rx.push_back(0x3E);
        rx.push_back((uint8_t)(payload.size() & 0xFF));
        rx.push_back((uint8_t)(payload.size() >> 8));
        rx.insert(rx.end(), payload.begin(), payload.end());
    }
    std::vector<std::vector<uint8_t>> frames;
};
extern HostRadioSerial Serial1;
