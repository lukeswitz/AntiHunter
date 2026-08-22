#pragma once
#include <stdint.h>
#include <math.h>
#include <string.h>

#define CSI_NSUB 47

static const uint8_t CSI_SUB_IDX[CSI_NSUB] = {
    2,  3,  4,  5,  6,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 22, 23, 24, 25, 26,
    38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
    54, 55, 56, 58, 59, 60, 61, 62, 63
};

static const float CSI_FAST_ALPHA = 0.25f;
static const float CSI_SLOW_ALPHA = 0.01f;
static const float CSI_WARM_ALPHA = 0.2f;
static const float CSI_FLOOR_ALPHA = 0.01f;
static const float CSI_FLOOR_MIN = 0.0004f;
static const uint16_t CSI_WARMUP_PKTS = 40;
static const uint16_t CSI_FLOOR_SETTLE_PKTS = 450;

static inline bool csiAmplitudes(const int8_t *buf, float *out) {
    float sum = 0.0f;
    for (int k = 0; k < CSI_NSUB; k++) {
        const int idx = CSI_SUB_IDX[k];
        const float im = (float)buf[idx * 2];
        const float re = (float)buf[idx * 2 + 1];
        const float mag = sqrtf(im * im + re * re);
        out[k] = mag;
        sum += mag;
    }
    if (sum <= 0.0f) return false;
    const float norm = (float)CSI_NSUB / sum;
    for (int k = 0; k < CSI_NSUB; k++) out[k] *= norm;
    return true;
}

struct CsiScorer {
    float fast[CSI_NSUB];
    float slow[CSI_NSUB];
    float floorMad;
    float mad;
    float score;
    uint16_t warm;
    uint16_t scored;

    bool settled() const { return scored >= CSI_FLOOR_SETTLE_PKTS; }

    void reset() {
        for (int k = 0; k < CSI_NSUB; k++) { fast[k] = 0.0f; slow[k] = 0.0f; }
        floorMad = 0.0f;
        mad = 0.0f;
        score = 0.0f;
        warm = 0;
        scored = 0;
    }

    bool update(const float *a, bool holdFloor) {
        if (warm < CSI_WARMUP_PKTS) {
            if (warm == 0) {
                for (int k = 0; k < CSI_NSUB; k++) { fast[k] = a[k]; slow[k] = a[k]; }
            } else {
                for (int k = 0; k < CSI_NSUB; k++) {
                    fast[k] += CSI_WARM_ALPHA * (a[k] - fast[k]);
                    slow[k] += CSI_WARM_ALPHA * (a[k] - slow[k]);
                }
            }
            warm++;
            return false;
        }

        for (int k = 0; k < CSI_NSUB; k++) fast[k] += CSI_FAST_ALPHA * (a[k] - fast[k]);

        float num = 0.0f;
        float den = 0.0f;
        for (int k = 0; k < CSI_NSUB; k++) {
            const float w = slow[k];
            num += w * fabsf(fast[k] - slow[k]);
            den += w;
        }
        if (den <= 0.0f) return false;
        const float d = num / den;

        for (int k = 0; k < CSI_NSUB; k++) slow[k] += CSI_SLOW_ALPHA * (a[k] - slow[k]);

        mad = d;
        if (floorMad <= 0.0f) floorMad = d;
        if (!holdFloor) floorMad += CSI_FLOOR_ALPHA * (d - floorMad);
        if (floorMad < CSI_FLOOR_MIN) floorMad = CSI_FLOOR_MIN;

        score = mad / floorMad;
        if (scored < 0xFFFF) scored++;
        return true;
    }
};
