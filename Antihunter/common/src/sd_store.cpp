#include "hardware.h"
#include "campaign.h"
#include <Arduino.h>
#include <atomic>
#include <algorithm>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <SD.h>
#include <SPI.h>
#include "esp_heap_caps.h"

uint32_t SafeSD::lastCheckTime = 0;
bool SafeSD::lastCheckResult = false;

uint32_t SafeSD::sdMountFailures = 0;
uint32_t SafeSD::sdWriteRetries = 0;
uint32_t SafeSD::lastMountLogMs = 0;

uint32_t sdMountedHz = SD_SPI_HZ;

static File s_sysLog;
static const char *const SYS_LOG_PATH = "/antihunter.log";

std::recursive_mutex &SafeSD::fileLock() {
    static std::recursive_mutex m;
    return m;
}

void sdCloseSysLogIf(const char *path) {
    if (path && s_sysLog && strcmp(path, SYS_LOG_PATH) == 0) s_sysLog.close();
}

bool SafeSD::checkAvailability() {
    static std::mutex sdCheckMutex;
    std::lock_guard<std::mutex> lock(sdCheckMutex);
    uint32_t now = millis();
    const uint32_t retryMs = CHECK_INTERVAL_MS << (sdMountFailures < 5 ? sdMountFailures : 5);
    if (lastCheckTime != 0 && now - lastCheckTime < retryMs) {
        return lastCheckResult;
    }
    const bool was = lastCheckResult;
    lastCheckResult = SD.begin(SD_CS_PIN, SPI, sdMountedHz);
    lastCheckTime = millis();
    sdAvailable = lastCheckResult;
    if (!lastCheckResult) {
        sdMountFailures++;
        if (was || sdMountFailures == 1 || now - lastMountLogMs >= MOUNT_LOG_INTERVAL_MS) {
            lastMountLogMs = now;
            Serial.printf("[SAFE_SD] SD unavailable - mount has failed %lu times. "
                          "The card needs checking or reformatting; the node is running without storage.\n",
                          (unsigned long)sdMountFailures);
        }
    } else if (!was && sdMountFailures) {
        Serial.printf("[SAFE_SD] SD recovered after %lu failed mounts\n",
                      (unsigned long)sdMountFailures);
        sdMountFailures = 0;
    }
    return lastCheckResult;
}

bool SafeSD::isAvailable() {
    return checkAvailability();
}

fs::File SafeSD::open(const char* path, const char* mode) {
    if (!checkAvailability()) {
        return File();
    }

    fs::File f = SD.open(path, mode);
    SdWriter f_w(f);
    if (!f) {
        Serial.printf("[SAFE_SD] Failed to open: %s\n", path);
    }
    return f;
}

bool SafeSD::exists(const char* path) {
    if (!checkAvailability()) {
        return false;
    }
    return SD.exists(path);
}


bool SafeSD::remove(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot remove %s - SD unavailable\n", path);
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(fileLock());
    sdCloseSysLogIf(path);
    bool result = SD.remove(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to remove: %s\n", path);
    }
    return result;
}

bool SafeSD::rename(const char* from, const char* to) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot rename %s - SD unavailable\n", from);
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(fileLock());
    sdCloseSysLogIf(from);
    sdCloseSysLogIf(to);
    SD.remove(to);
    bool result = SD.rename(from, to);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to rename %s -> %s\n", from, to);
    }
    return result;
}

bool SafeSD::mkdir(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot mkdir %s - SD unavailable\n", path);
        return false;
    }

    bool result = SD.mkdir(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to mkdir: %s\n", path);
    }
    return result;
}

bool SafeSD::rmdir(const char* path) {
    if (!checkAvailability()) {
        Serial.printf("[SAFE_SD] Cannot rmdir %s - SD unavailable\n", path);
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(fileLock());
    bool result = SD.rmdir(path);
    if (!result) {
        Serial.printf("[SAFE_SD] Failed to rmdir: %s\n", path);
    }
    return result;
}

size_t SafeSD::write(fs::File& file, const uint8_t* data, size_t len) {
    if (!file || !checkAvailability()) {
        Serial.println("[SAFE_SD] Write failed - file invalid or SD unavailable");
        return 0;
    }

    errno = 0;
    size_t written = file.write(data, len);
    if (written == len) return written;
    const int firstErr = errno;

    // ff.c f_write checks fp->err first and ABORT latches it, so only a reopen clears the handle.
    delay(30);
    errno = 0;
    const size_t more = file.write(data + written, len - written);
    const int retryErr = errno;
    written += more;
    if (more) sdWriteRetries++;

    if (written != len) {
        const int reported = retryErr ? retryErr : firstErr;
        Serial.printf("[SAFE_SD] Partial write after retries: %u/%u bytes (errno %d/%d: %s)\n",
                      (unsigned)written, (unsigned)len, firstErr, retryErr,
                      reported ? strerror(reported) : "none");
    }
    return written;
}

size_t SafeSD::read(fs::File& file, uint8_t* data, size_t len) {
    if (!file || !checkAvailability()) {
        Serial.println("[SAFE_SD] Read failed - file invalid or SD unavailable");
        return 0;
    }

    size_t bytesRead = file.read(data, len);
    if (bytesRead != len) {
        Serial.printf("[SAFE_SD] Partial read: %d/%d bytes\n", bytesRead, len);
    }
    return bytesRead;
}

bool SafeSD::flush(fs::File& file) {
    if (!file || !checkAvailability()) {
        return false;
    }
    file.flush();
    return true;
}

void SafeSD::forceRecheck() {
    lastCheckTime = 0;
}

size_t SafeSD::size(const char *path) {
    std::lock_guard<std::recursive_mutex> lock(fileLock());
    sdCloseSysLogIf(path);
    if (!exists(path)) return 0;
    File f = open(path, FILE_READ);
    if (!f) return 0;
    const size_t sz = f.size();
    f.close();
    return sz;
}

bool sdCommitStaged(const char *tmpPath, const char *finalPath, const char *bakPath, size_t expectedBytes) {
    std::lock_guard<std::recursive_mutex> lock(SafeSD::fileLock());
    File verify = SafeSD::open(tmpPath, FILE_READ);
    size_t written = verify ? verify.size() : 0;
    if (verify) verify.close();

    if (written == 0 || (expectedBytes && written != expectedBytes)) {
        Serial.printf("[SD] ERROR: staged %s is %u of %u bytes - previous file kept\n", finalPath, (unsigned)written,
                      (unsigned)expectedBytes);
        SafeSD::remove(tmpPath);
        return false;
    }

    bool hadFile = SafeSD::exists(finalPath);
    if (hadFile && !SafeSD::rename(finalPath, bakPath)) {
        Serial.printf("[SD] ERROR: could not back up %s - previous file kept\n", finalPath);
        SafeSD::remove(tmpPath);
        return false;
    }

    if (!SafeSD::rename(tmpPath, finalPath)) {
        Serial.printf("[SD] ERROR: failed to commit %s - restoring previous\n", finalPath);
        if (hadFile) {
            SafeSD::rename(bakPath, finalPath);
        }
        SafeSD::remove(tmpPath);
        return false;
    }
    return true;
}

static uint64_t sdKeyMix(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

static bool sdKeySetInsert(uint64_t *t, uint32_t mask, uint64_t key, uint64_t h) {
    const uint64_t v = key + 1;
    uint32_t i = (uint32_t)(h >> 32) & mask;
    while (t[i]) {
        if (t[i] == v) return false;
        i = (i + 1) & mask;
    }
    t[i] = v;
    return true;
}

int32_t sdCompactNewestPerKey(const char *path, const char *tmpPath, const char *bakPath, size_t recSize,
                              uint64_t (*keyOf)(uint8_t *rec), const char *tag) {
    static const uint32_t kMaxSlots = 131072;
    static const size_t kChunkBytes = 32 * 1024;
    File in = SafeSD::open(path, FILE_READ);
    if (!in) return -1;
    const uint32_t total = (uint32_t)(in.size() / recSize);
    if (total == 0) { in.close(); return -1; }

    uint32_t slots = 4096;
    while (slots < total * 2u && slots < kMaxSlots) slots <<= 1;
    uint64_t *set = nullptr;
    while (!set && slots >= 4096) {
        set = static_cast<uint64_t *>(heap_caps_malloc((size_t)slots * sizeof(uint64_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (!set) slots >>= 1;
    }
    const size_t chunkRecs = kChunkBytes / recSize;
    uint8_t *rbuf = static_cast<uint8_t *>(heap_caps_malloc(chunkRecs * recSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    uint8_t *wbuf = static_cast<uint8_t *>(heap_caps_malloc(chunkRecs * recSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    File out = (set && rbuf && wbuf) ? SafeSD::open(tmpPath, FILE_WRITE) : File();
    if (!out) {
        in.close();
        heap_caps_free(set);
        heap_caps_free(rbuf);
        heap_caps_free(wbuf);
        Serial.printf("[%s] Compaction skipped: not enough memory or SD unavailable\n", tag);
        return -1;
    }

    const uint32_t perPass = slots / 2;
    const uint32_t passes = (total + perPass - 1) / perPass;
    const uint32_t mask = slots - 1;
    const uint32_t t0 = millis();
    uint32_t kept = 0;
    size_t wlen = 0;
    bool ok = true;
    for (uint32_t p = 0; p < passes && ok; p++) {
        memset(set, 0, (size_t)slots * sizeof(uint64_t));
        uint32_t pos = total;
        while (pos > 0 && ok) {
            const uint32_t n = pos < chunkRecs ? pos : (uint32_t)chunkRecs;
            pos -= n;
            in.seek((size_t)pos * recSize);
            if (SafeSD::read(in, rbuf, (size_t)n * recSize) != (size_t)n * recSize) { ok = false; break; }
            for (uint32_t j = n; j-- > 0;) {
                uint8_t *rec = rbuf + (size_t)j * recSize;
                const uint64_t key = keyOf(rec);
                const uint64_t h = sdKeyMix(key);
                if ((uint32_t)(h % passes) != p) continue;
                if (!sdKeySetInsert(set, mask, key, h)) continue;
                memcpy(wbuf + wlen, rec, recSize);
                wlen += recSize;
                kept++;
                if (wlen + recSize > chunkRecs * recSize) {
                    if (SafeSD::write(out, wbuf, wlen) != wlen) ok = false;
                    wlen = 0;
                }
            }
            vTaskDelay(1);
        }
    }
    if (ok && wlen && SafeSD::write(out, wbuf, wlen) != wlen) ok = false;
    in.close();
    out.close();
    heap_caps_free(set);
    heap_caps_free(rbuf);
    heap_caps_free(wbuf);
    if (!ok) {
        SafeSD::remove(tmpPath);
        Serial.printf("[%s] Compaction stopped because an SD read or write failed. The old record is kept.\n", tag);
        return -1;
    }
    if (!sdCommitStaged(tmpPath, path, bakPath)) return -1;
    SafeSD::remove(bakPath);
    Serial.printf("[%s] Compacted %u records to %u devices in %u ms (%u passes)\n",
                  tag, (unsigned)total, (unsigned)kept, (unsigned)(millis() - t0), (unsigned)passes);
    return (int32_t)kept;
}

int32_t sdReadNewestRecords(const char *path, size_t recSize, uint64_t (*keyOf)(uint8_t *rec),
                            const uint64_t *sortedKeys, size_t n, uint8_t *out, uint8_t *hit) {
    if (n == 0) return 0;
    const size_t chunkRecs = (32 * 1024) / recSize;
    uint8_t *rbuf = static_cast<uint8_t *>(heap_caps_malloc(chunkRecs * recSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    File f = rbuf ? SafeSD::open(path, FILE_READ) : File();
    if (!f) {
        heap_caps_free(rbuf);
        return -1;
    }
    int32_t found = 0;
    uint32_t chunks = 0;
    for (;;) {
        const size_t got = SafeSD::read(f, rbuf, chunkRecs * recSize) / recSize;
        if (got == 0) break;
        for (size_t r = 0; r < got; r++) {
            uint8_t *rec = rbuf + r * recSize;
            const uint64_t key = keyOf(rec);
            const uint64_t *pos = std::lower_bound(sortedKeys, sortedKeys + n, key);
            if (pos == sortedKeys + n || *pos != key) continue;
            const size_t idx = (size_t)(pos - sortedKeys);
            if (!hit[idx]) found++;
            memcpy(out + idx * recSize, rec, recSize);
            hit[idx] = 1;
        }
        if ((++chunks & 0x7) == 0) vTaskDelay(1);
    }
    const bool complete = f.size() - f.position() < recSize;
    f.close();
    heap_caps_free(rbuf);
    if (!complete) Serial.printf("[SD] Read of %s stopped early\n", path);
    return complete ? found : -1;
}

std::atomic<uint32_t> g_sdRecordsMoved{0};
std::atomic<uint32_t> g_sdRecordsNotSaved{0};

void SdLineBatch::reserve() {
    if (!buf_) buf_ = static_cast<char *>(heap_caps_malloc(kBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
}

bool SdLineBatch::flush() {
    if (!len_) return true;
    std::lock_guard<std::recursive_mutex> sdLock(SafeSD::fileLock());
    File f = SafeSD::open(path_, FILE_APPEND);
    const size_t pos = f ? f.size() : 0;
    const size_t wrote = f ? SafeSD::write(f, reinterpret_cast<const uint8_t *>(buf_), len_) : 0;
    if (f) f.close();
    if (wrote != len_) {
        if (wrote) truncate((String("/sd") + path_).c_str(), pos);
        Serial.printf("[SD] Write to %s failed: %u records kept in memory for the next save\n", path_, (unsigned)lines_);
        return false;
    }
    len_ = 0;
    lines_ = 0;
    return true;
}

void SdLineBatch::add(const char *line, size_t len) {
    if (!buf_ || len + 1 > kBytes || (len_ + len + 1 > kBytes && !flush())) {
        File f = SafeSD::open(path_, FILE_APPEND);
        size_t wrote = 0;
        if (f) {
            wrote = SafeSD::write(f, reinterpret_cast<const uint8_t *>(line), len);
            wrote += SafeSD::write(f, reinterpret_cast<const uint8_t *>("\n"), 1);
            f.close();
        }
        if (wrote != len + 1) {
            Serial.printf("[SD] Write to %s failed: 1 record was not saved\n", path_);
            g_sdRecordsNotSaved++;
        }
        return;
    }
    memcpy(buf_ + len_, line, len);
    len_ += len;
    buf_[len_++] = '\n';
    lines_++;
}

static uint8_t sdBootCmd(uint8_t cmd, uint32_t arg, uint8_t crc) {
    digitalWrite(SD_CS_PIN, LOW);
    SPI.transfer(0xFF);
    SPI.transfer(0x40 | cmd);
    SPI.transfer((uint8_t)(arg >> 24));
    SPI.transfer((uint8_t)(arg >> 16));
    SPI.transfer((uint8_t)(arg >> 8));
    SPI.transfer((uint8_t)arg);
    SPI.transfer(crc);
    if (cmd == 12) SPI.transfer(0xFF);
    uint8_t r1 = 0xFF;
    for (int i = 0; i < 10 && (r1 & 0x80); i++) r1 = SPI.transfer(0xFF);
    return r1;
}

static void sdBootRelease(uint32_t busyMs) {
    const uint32_t t0 = millis();
    while (millis() - t0 < busyMs && SPI.transfer(0xFF) != 0xFF) {}
    digitalWrite(SD_CS_PIN, HIGH);
    SPI.transfer(0xFF);
}

static bool sdBootReadSector0() {
    sdBootCmd(17, 0, 0xFF);
    uint8_t tok = 0xFF;
    const uint32_t t0 = millis();
    while (millis() - t0 < 500 && (tok = SPI.transfer(0xFF)) == 0xFF) {}
    if (tok == 0xFE)
        for (int i = 0; i < 514; i++) SPI.transfer(0xFF);
    sdBootRelease(0);
    return tok == 0xFE;
}

void sdEndInterruptedTransfer() {
    SPI.beginTransaction(SPISettings(400000, MSBFIRST, SPI_MODE0));
    digitalWrite(SD_CS_PIN, HIGH);
    for (int i = 0; i < 10; i++) SPI.transfer(0xFF);
    digitalWrite(SD_CS_PIN, LOW);
    const uint8_t first = SPI.transfer(0xFF);
    sdBootRelease(500);
    uint8_t r0 = sdBootCmd(0, 0, 0x95);
    sdBootRelease(0);
    bool stopped = false;
    if (r0 != 0x01) {
        sdBootCmd(12, 0, 0x61);
        sdBootRelease(500);
        stopped = true;
        r0 = sdBootCmd(0, 0, 0x95);
        sdBootRelease(0);
    }
    bool readable = false;
    if (r0 == 0x01) {
        sdBootCmd(8, 0x1AA, 0x87);
        for (int i = 0; i < 4; i++) SPI.transfer(0xFF);
        sdBootRelease(0);
        uint8_t r41 = 0xFF;
        const uint32_t t0 = millis();
        do {
            sdBootCmd(55, 0, 0x65);
            sdBootRelease(0);
            r41 = sdBootCmd(41, 0x40000000, 0x77);
            sdBootRelease(0);
        } while (r41 == 0x01 && millis() - t0 < 3000);
        readable = sdBootReadSector0();
        if (!readable) {
            sdBootCmd(12, 0, 0x61);
            sdBootRelease(500);
            stopped = true;
            readable = sdBootReadSector0();
        }
    }
    SPI.endTransaction();
    if (first != 0xFF || stopped)
        Serial.printf("[SD] Card was still in a transfer from before the reset (output 0x%02X); %s\n", first,
                      readable ? "stopped it, card ready" : "card still not readable");
}

void logToSD(const String &data) {
    if (!SafeSD::isAvailable()) return;

    std::lock_guard<std::recursive_mutex> sdLock(SafeSD::fileLock());
    File &logFile = s_sysLog;

    if (!logFile) {
        logFile = SafeSD::open(SYS_LOG_PATH, FILE_APPEND);
        if (!logFile) {
            Serial.println("[SD] Failed to open log file");
            return;
        }
    }

    // Use RTC time if available, otherwise fall back to millis
    String timestamp = getFormattedTimestamp();
    if (timestamp.length() == 19 && timestamp[4] == '-') {
        timestamp += " " + nodeTZAbbrev(nodeLocalToEpoch(timestamp.substring(0, 4).toInt(), timestamp.substring(5, 7).toInt(),
                                                         timestamp.substring(8, 10).toInt(), timestamp.substring(11, 13).toInt(),
                                                         timestamp.substring(14, 16).toInt()));
    }

    const char *camp = campaignName();
    String line = "[" + timestamp + "] " + (camp[0] ? String("[C:") + camp + "] " : String()) + data + "\n";
    const uint8_t *lineBytes = reinterpret_cast<const uint8_t *>(line.c_str());
    const auto dropPartial = [&](size_t wrote) {
        logFile.close();
        File r = SD.open(SYS_LOG_PATH, FILE_READ);
        const size_t sz = r ? r.size() : 0;
        if (r) r.close();
        if (wrote && sz >= wrote) truncate((String("/sd") + SYS_LOG_PATH).c_str(), sz - wrote);
    };
    size_t wrote = SafeSD::write(logFile, lineBytes, line.length());
    if (wrote != line.length()) {
        dropPartial(wrote);
        logFile = SafeSD::open(SYS_LOG_PATH, FILE_APPEND);
        if (!logFile) {
            Serial.println("[SD] Failed to open log file");
            return;
        }
        wrote = SafeSD::write(logFile, lineBytes, line.length());
        if (wrote != line.length()) {
            dropPartial(wrote);
            g_sdRecordsNotSaved++;
            return;
        }
    }

    static uint32_t lastLogSync = 0;
    if (millis() - lastLogSync >= 1000) {
        logFile.flush();
        lastLogSync = millis();
    }

    static unsigned long lastSizeCheck = 0;
    if (millis() - lastSizeCheck > 10000) {
        if (logFile) {
            const size_t sz = logFile.size();
            Serial.printf("[SD] Log file size: %lu bytes\n", (unsigned long)sz);
            if (sz > 1048576) {
                SafeSD::rename(SYS_LOG_PATH, "/antihunter_old.log");
                Serial.println("[SD] Rotated /antihunter.log -> /antihunter_old.log");
            }
        }
        lastSizeCheck = millis();
    }
}

void logToSDClose() {
    std::lock_guard<std::recursive_mutex> sdLock(SafeSD::fileLock());
    if (s_sysLog) s_sysLog.close();
}

void logEventToSD(const char* path, const String& jsonLine) {
    logEventsToSD(path, &jsonLine, 1);
}

void logEventsToSD(const char* path, const String* lines, size_t count) {
    if (!SafeSD::isAvailable() || count == 0) return;

    // Heap-floor guard: under a flood, drop the SD write rather than crash; detectors still count and alert in RAM.
    if (ESP.getFreeHeap() < 20000) {
        static uint32_t s_lastHeapWarnMs = 0;
        uint32_t nowMs = millis();
        if (nowMs - s_lastHeapWarnMs > 5000) {
            s_lastHeapWarnMs = nowMs;
            Serial.printf("[HEAP-GUARD] dropping SD log (%s) — free heap %u\n",
                          path, (unsigned)ESP.getFreeHeap());
        }
        g_sdRecordsNotSaved += (uint32_t)count;
        return;
    }

    std::lock_guard<std::recursive_mutex> sdLock(SafeSD::fileLock());
    File f = SafeSD::open(path, FILE_APPEND);
    if (!f) {
        Serial.printf("[SD] Failed to open %s for event log\n", path);
        g_sdRecordsNotSaved += (uint32_t)count;
        return;
    }
    const char *camp = campaignName();
    size_t end = f.size();
    size_t saved = 0;
    for (; saved < count; saved++) {
        const String &jsonLine = lines[saved];
        SdWriter f_w(f);
        if (camp[0] && jsonLine.length() > 1 && jsonLine[0] == '{' && jsonLine[1] != '}') {
            f_w.println(String("{\"campaign\":\"") + camp + "\"," + jsonLine.substring(1));
        } else {
            f_w.println(jsonLine);
        }
        if (!f_w.ok()) break;
        end += f_w.bytes();
    }
    f.close();
    size_t curSize = end;
    if (saved != count) {
        truncate((String("/sd") + path).c_str(), end);
        g_sdRecordsNotSaved += (uint32_t)(count - saved);
        Serial.printf("[SD] %s: event lines not fully saved (%u of %u lost)\n", path, (unsigned)(count - saved), (unsigned)count);
    }

    if (curSize > 1048576) {
        String rotated = String(path);
        int dotIdx = rotated.lastIndexOf('.');
        if (dotIdx > 0) {
            rotated = rotated.substring(0, dotIdx) + "_old" + rotated.substring(dotIdx);
        } else {
            rotated += "_old";
        }
        if (SafeSD::rename(path, rotated.c_str())) Serial.printf("[SD] Rotated %s -> %s\n", path, rotated.c_str());
    }
}
