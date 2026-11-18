#include "sd_store.h"

uint32_t SafeSD::mountFailureCount() {
    return sdMountFailures;
}

uint32_t SafeSD::writeRetryCount() {
    return sdWriteRetries;
}

size_t SafeSD::readAt(const char *path, size_t offset, uint8_t *buf, size_t len) {
    std::lock_guard<std::recursive_mutex> lock(fileLock());
    sdCloseSysLogIf(path);
    if (!exists(path)) return 0;
    File f = open(path, FILE_READ);
    if (!f) return 0;
    size_t n = 0;
    if (offset < f.size() && f.seek(offset)) n = f.read(buf, len);
    f.close();
    return n;
}
