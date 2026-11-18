#pragma once
#include <Arduino.h>
#include <FS.h>
#include <SD.h>
#include <atomic>
#include <mutex>
#include <stdint.h>

class SafeSD {
private:
    static uint32_t lastCheckTime;
    static bool lastCheckResult;
    static const uint32_t CHECK_INTERVAL_MS = 1000;
    static const uint32_t MOUNT_LOG_INTERVAL_MS = 60000;
    static uint32_t sdMountFailures;
    static uint32_t sdWriteRetries;
    static uint32_t lastMountLogMs;
    static bool checkAvailability();

public:
    static bool isAvailable();
    static fs::File open(const char* path, const char* mode = FILE_READ);
    static bool exists(const char* path);
    static bool remove(const char* path);
    static bool rename(const char* from, const char* to);
    static bool mkdir(const char* path);
    static bool rmdir(const char* path);
    static size_t write(fs::File& file, const uint8_t* data, size_t len);
    static size_t read(fs::File& file, uint8_t* data, size_t len);
    static bool flush(fs::File& file);
    static void forceRecheck();
    static uint32_t mountFailureCount();
    static uint32_t writeRetryCount();
    static std::recursive_mutex &fileLock();
    static size_t readAt(const char* path, size_t offset, uint8_t* buf, size_t len);
    static size_t size(const char* path);
};

// Replaces finalPath with the fully written tmpPath; the old file survives any failure.
bool sdCommitStaged(const char *tmpPath, const char *finalPath, const char *bakPath, size_t expectedBytes = 0);

// Rewrites a file of fixed-size records keeping exactly the newest (last) record per key; returns records kept, or -1 with the file unchanged.
int32_t sdCompactNewestPerKey(const char *path, const char *tmpPath, const char *bakPath, size_t recSize,
                              uint64_t (*keyOf)(uint8_t *rec), const char *tag);

// One sequential pass over a fixed-record file: copies the newest record of each key in sortedKeys[n] to out[i] and sets hit[i]; returns records found, or -1 if the file or buffer is unavailable.
int32_t sdReadNewestRecords(const char *path, size_t recSize, uint64_t (*keyOf)(uint8_t *rec),
                            const uint64_t *sortedKeys, size_t n, uint8_t *out, uint8_t *hit);

// Records moved from memory to SD, and records that could not be written to SD; reported in /diag, SUMMARY and SCAN_DONE.
extern std::atomic<uint32_t> g_sdRecordsMoved;
extern std::atomic<uint32_t> g_sdRecordsNotSaved;

// Collects lines in one PSRAM buffer and appends them to an SD file in a single write.
class SdLineBatch {
public:
    explicit SdLineBatch(const char *path) : path_(path) {}
    void reserve();
    void add(const char *line, size_t len);
    bool flush();
    void discard() { len_ = 0; lines_ = 0; }
private:
    static constexpr size_t kBytes = 32 * 1024;
    const char *path_;
    char *buf_ = nullptr;
    size_t len_ = 0;
    uint32_t lines_ = 0;
};

// Print wrapper so print/println/printf/serializeJson all go through the retrying write
class SdWriter : public Print {
public:
    explicit SdWriter(fs::File &f) : _f(f) {}
    size_t write(uint8_t c) override { return count(SafeSD::write(_f, &c, 1), 1); }
    size_t write(const uint8_t *b, size_t n) override { return count(SafeSD::write(_f, b, n), n); }
    bool ok() const { return !_short; }
    size_t bytes() const { return _bytes; }
private:
    size_t count(size_t got, size_t want) {
        _bytes += got;
        if (got != want) _short = true;
        return got;
    }
    fs::File &_f;
    size_t _bytes = 0;
    bool _short = false;
};

extern uint32_t sdMountedHz;
void sdCloseSysLogIf(const char *path);
void sdEndInterruptedTransfer();
void logToSD(const String &data);
void logToSDClose();
void logEventToSD(const char* path, const String& jsonLine);
void logEventsToSD(const char* path, const String* lines, size_t count);
