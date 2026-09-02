#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

extern "C" {

void *__real_memcpy(void *dst, const void *src, size_t n);

volatile uint32_t g_memcpyBadLenRejects = 0;
volatile uint32_t g_memcpyBadLenLast = 0;

void *IRAM_ATTR __wrap_memcpy(void *dst, const void *src, size_t n) {
    if (__builtin_expect((n & 0x80000000u) != 0u, 0)) {
        g_memcpyBadLenLast = (uint32_t)n;
        __sync_fetch_and_add(&g_memcpyBadLenRejects, 1u);
        return dst;
    }
    return __real_memcpy(dst, src, n);
}

}
