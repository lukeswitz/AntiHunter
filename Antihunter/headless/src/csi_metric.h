#pragma once
#include <stdint.h>
#include <math.h>
#include <string.h>
#if defined(__has_include)
#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif
#endif

#if CONFIG_SOC_WIFI_HE_SUPPORT
#define CSI_BUF_BYTES 114
#define CSI_LEN_LLTF 106
#define CSI_LEN_HTLTF 114
#define CSI_NRAW 57
#define CSI_NSUB 57
#define CSI_F_EFF 17.8f
#define CSI_F_EFF_PER_BIN (CSI_F_EFF / 52.0f)

static const uint8_t CSI_SUB_IDX[CSI_NRAW] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56
};
#else
#define CSI_BUF_BYTES 128
#define CSI_NSUB 47
#define CSI_F_EFF 46.0f

static const uint8_t CSI_SUB_IDX[CSI_NSUB] = {
    2,  3,  4,  5,  6,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 22, 23, 24, 25, 26,
    38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
    54, 55, 56, 58, 59, 60, 61, 62, 63
};
#endif

static const float CSI_FAST_ALPHA = 0.25f;
static const float CSI_SLOW_ALPHA = 0.01f;
static const float CSI_WARM_ALPHA = 0.2f;
static const float CSI_FLOOR_ALPHA = 0.01f;
static const uint8_t CSI_FLOOR_HIST = 120;
static const uint16_t CSI_FLOOR_SAMPLE_EVERY = 32;
static const float CSI_FLOOR_QUANT = 100000.0f;
static const float CSI_VAR_ALPHA = 0.005f;
static const float CSI_VAR_W_FLOOR = 0.01f;
static const float CSI_ACF_ALPHA = 0.00167f;
static const uint16_t CSI_ACF_T = 600;
static const uint16_t CSI_ACF_ARM_PAIRS = 4 * CSI_ACF_T;
static const uint32_t CSI_ACF_LAG_US = 33333;
static const uint32_t CSI_ACF_LAG_MIN_US = 20000;
static const uint32_t CSI_ACF_LAG_MAX_US = 50000;
static const float CSI_ACF_Z = 5.5f;
static const float CSI_ACF_NULL_Z = 2.0f;
static inline float csiNullMaxFloorForBins(int liveBins) {
    const float f = CSI_F_EFF_PER_BIN * (float)(liveBins > 0 ? liveBins : 1);
    return -1.0f / (float)CSI_ACF_T + CSI_ACF_NULL_Z / sqrtf((f > 1.0f ? f : 1.0f) * (float)CSI_ACF_T);
}
static inline float csiNullMaxFloor() {
    return -1.0f / (float)CSI_ACF_T + CSI_ACF_NULL_Z / sqrtf(CSI_F_EFF * (float)CSI_ACF_T);
}
static inline float csiEtaForBins(int liveBins) {
    const float f = CSI_F_EFF_PER_BIN * (float)(liveBins > 0 ? liveBins : 1);
    return -1.0f / (float)CSI_ACF_T + CSI_ACF_Z / sqrtf((f > 1.0f ? f : 1.0f) * (float)CSI_ACF_T);
}
static inline float csiEtaFromNull() {
    return -1.0f / (float)CSI_ACF_T + CSI_ACF_Z / sqrtf(CSI_F_EFF * (float)CSI_ACF_T);
}
static const float CSI_ACF_ETA_SUB = 0.25f;
static const float CSI_ACF_MIN_VAR = 1e-6f;
static const uint8_t CSI_ACF_HIST = 120;
static const uint16_t CSI_ACF_SAMPLE_EVERY = 32;
static const float CSI_ACF_QUANT = 10000.0f;
static const float CSI_ACF_MIN_SPREAD = 0.02f;
static const uint8_t CSI_ACF_MIN_HIST = 12;
static const float CSI_ACF_Z_PER_ETA = 30.0f;
static const float CSI_VOTE_FRAC = 0.0f;
static const float CSI_FLOOR_MIN = 0.0004f;
static const uint16_t CSI_WARMUP_PKTS = 40;
static const uint16_t CSI_FLOOR_SETTLE_PKTS = 450;
static const float CSI_SPREAD_ALPHA = 0.02f;
static const float CSI_LINK_MIN_SPREAD = 0.03f;
static const uint32_t CSI_LINK_MIN_PKTS = 60;
static const float CSI_LINK_ARM_SEC = 60.0f;
static const float CSI_LINK_MIN_PAIR_RATE = (float)CSI_ACF_T / CSI_LINK_ARM_SEC;
static const int8_t CSI_LINK_MIN_RSSI = -92;
static const int8_t CSI_SURVEY_MIN_RSSI = -85;

#if CONFIG_SOC_WIFI_HE_SUPPORT
static inline int csiWord12(const uint8_t *u) {
    int v = (int)u[0] | ((int)u[1] << 8);
    return (v >= 2048) ? (v - 4096) : v;
}

static inline int csiSubCount(uint16_t len) {
    return (int)(len / 2);
}

static inline bool csiAmplitudesLen(const int8_t *buf, uint16_t len, bool firstWordInvalid, float *out, int *liveOut) {
    const int n = csiSubCount(len);
    if (n < 8 || n > CSI_NSUB) return false;
    const int k0 = firstWordInvalid ? 2 : 0;
    if (n - k0 < 8) return false;
    float sum = 0.0f;
    int m = 0;
    for (int k = k0; k < n; k++) {
        if (k == n / 2) continue;
        const float im = (float)buf[k * 2];
        const float re = (float)buf[k * 2 + 1];
        const float mag = sqrtf(im * im + re * re);
        out[m++] = mag;
        sum += mag;
    }
    if (m < 8) return false;
    if (sum <= 0.0f) return false;
    const float norm = (float)m / sum;
    for (int k = 0; k < m; k++) out[k] *= norm;
    for (int k = m; k < CSI_NSUB; k++) out[k] = 0.0f;
    if (liveOut) *liveOut = m;
    return true;
}
#else
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
#endif

struct CsiScorer {
    float fast[CSI_NSUB];
    float slow[CSI_NSUB];
    float var[CSI_NSUB];
    float prevG[CSI_NSUB];
    float mG[CSI_NSUB];
    float mVar[CSI_NSUB];
    float mCov[CSI_NSUB];
    float acf;
    float vote;
    float acfFloor;
    float acfSpread;
    float acfZ;
    uint16_t ahist[CSI_ACF_HIST];
    uint8_t ahlen;
    uint8_t ahpos;
    uint16_t asampCount;
    float floorCache;
    float floorMad;
    float mad;
    float score;
    uint16_t warm;
    uint16_t scored;
    float scoreMean;
    float scoreVar;
    uint16_t hist[CSI_FLOOR_HIST];
    uint8_t hlen;
    uint8_t hpos;
    uint16_t sampCount;
    uint32_t acfPairs;
    uint8_t prevValid;
    uint32_t lagAccum;

    bool settled() const { return scored >= CSI_FLOOR_SETTLE_PKTS && acfPairs >= CSI_ACF_ARM_PAIRS; }
    float spread() const { return scoreVar > 0.0f ? sqrtf(scoreVar) : 0.0f; }

    void reset() {
        for (int k = 0; k < CSI_NSUB; k++) {
            fast[k] = 0.0f; slow[k] = 0.0f; var[k] = 0.0f;
            prevG[k] = 0.0f; mG[k] = 0.0f; mVar[k] = 0.0f; mCov[k] = 0.0f;
        }
        acf = 0.0f;
        vote = 0.0f;
        acfFloor = 0.0f;
        acfSpread = CSI_ACF_MIN_SPREAD;
        acfZ = 0.0f;
        ahlen = 0;
        ahpos = 0;
        asampCount = 0;
        floorCache = 0.0f;
        floorMad = 0.0f;
        mad = 0.0f;
        score = 0.0f;
        warm = 0;
        scored = 0;
        scoreMean = 0.0f;
        scoreVar = 0.0f;
        hlen = 0;
        hpos = 0;
        sampCount = 0;
        acfPairs = 0;
        prevValid = 0;
        lagAccum = 0;
    }

    float acfHistStats(float *spreadOut) const {
        uint16_t tmp[CSI_ACF_HIST];
        for (uint8_t i = 0; i < ahlen; i++) tmp[i] = ahist[i];
        for (uint8_t i = 1; i < ahlen; i++) {
            uint16_t v = tmp[i];
            int16_t j = (int16_t)i - 1;
            while (j >= 0 && tmp[j] > v) { tmp[j + 1] = tmp[j]; j--; }
            tmp[j + 1] = v;
        }
        const float med = (float)tmp[ahlen / 2] / CSI_ACF_QUANT - 1.0f;
        const float q1 = (float)tmp[ahlen / 4] / CSI_ACF_QUANT - 1.0f;
        const float q3 = (float)tmp[(3 * ahlen) / 4] / CSI_ACF_QUANT - 1.0f;
        float sp = (q3 - q1) / 1.349f;
        if (sp < CSI_ACF_MIN_SPREAD) sp = CSI_ACF_MIN_SPREAD;
        *spreadOut = sp;
        return med;
    }

    float histMedian() const {
        uint16_t tmp[CSI_FLOOR_HIST];
        for (uint8_t i = 0; i < hlen; i++) tmp[i] = hist[i];
        for (uint8_t i = 1; i < hlen; i++) {
            uint16_t v = tmp[i];
            int8_t j = (int8_t)i - 1;
            while (j >= 0 && tmp[j] > v) { tmp[j + 1] = tmp[j]; j--; }
            tmp[j + 1] = v;
        }
        return (float)tmp[hlen / 2] / CSI_FLOOR_QUANT;
    }

    bool update(const float *a, bool holdFloor, uint32_t dtUs) {
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
            const float w = sqrtf(var[k]) + CSI_VAR_W_FLOOR;
            num += w * fabsf(fast[k] - slow[k]);
            den += w;
        }
        if (den <= 0.0f) return false;
        const float d = num / den;

        for (int k = 0; k < CSI_NSUB; k++) {
            const float dev = a[k] - slow[k];
            slow[k] += CSI_SLOW_ALPHA * dev;
            var[k] += CSI_VAR_ALPHA * (dev * dev - var[k]);
        }

        mad = d;

        const uint32_t lagUs = (prevValid && dtUs <= 0xFFFFFFFFu - lagAccum) ? (lagAccum + dtUs) : dtUs;
        const bool lagOk = (lagUs >= CSI_ACF_LAG_MIN_US && lagUs <= CSI_ACF_LAG_MAX_US);
        const bool lagStale = (lagUs > CSI_ACF_LAG_MAX_US);

        if (lagOk && prevValid) {
            float psi = 0.0f;
            int nf = 0;
            int nvote = 0;
            for (int k = 0; k < CSI_NSUB; k++) {
                const float G = a[k] * a[k];
                if (acfPairs == 0) {
                    mG[k] = G;
                } else {
                    const float dG = G - mG[k];
                    const float dP = prevG[k] - mG[k];
                    mCov[k] += CSI_ACF_ALPHA * (dG * dP - mCov[k]);
                    mVar[k] += CSI_ACF_ALPHA * (dG * dG - mVar[k]);
                    mG[k] += CSI_ACF_ALPHA * dG;
                    if (mVar[k] > CSI_ACF_MIN_VAR * mG[k] * mG[k]) {
                        float p = mCov[k] / mVar[k];
                        if (p > 1.0f) p = 1.0f;
                        if (p < -1.0f) p = -1.0f;
                        psi += p;
                        nf++;
                        if (p > CSI_ACF_ETA_SUB) nvote++;
                    }
                }
            }
            acfPairs++;
            acf = (nf > 0) ? (psi / (float)nf) : 0.0f;
            vote = (nf > 0) ? ((float)nvote / (float)nf) : 0.0f;
        }

        if (lagOk || lagStale || !prevValid) {
            for (int k = 0; k < CSI_NSUB; k++) prevG[k] = a[k] * a[k];
            prevValid = 1;
            lagAccum = 0;
        } else {
            lagAccum = lagUs;
        }

        if (lagOk && !holdFloor && acfPairs >= CSI_ACF_ARM_PAIRS &&
            ++asampCount >= CSI_ACF_SAMPLE_EVERY) {
            asampCount = 0;
            float aq = (acf + 1.0f) * CSI_ACF_QUANT;
            if (aq < 0.0f) aq = 0.0f;
            if (aq > 65535.0f) aq = 65535.0f;
            ahist[ahpos] = (uint16_t)aq;
            ahpos = (uint8_t)((ahpos + 1) % CSI_ACF_HIST);
            if (ahlen < CSI_ACF_HIST) ahlen++;
            acfFloor = acfHistStats(&acfSpread);
        }
        acfZ = (ahlen >= CSI_ACF_MIN_HIST) ? ((acf - acfFloor) / acfSpread) : 0.0f;

        if (!holdFloor && ++sampCount >= CSI_FLOOR_SAMPLE_EVERY) {
            sampCount = 0;
            float q = d * CSI_FLOOR_QUANT;
            if (q > 65535.0f) q = 65535.0f;
            hist[hpos] = (uint16_t)q;
            hpos = (uint8_t)((hpos + 1) % CSI_FLOOR_HIST);
            if (hlen < CSI_FLOOR_HIST) hlen++;
            floorCache = histMedian();
        }
        floorMad = (hlen > 0) ? floorCache : d;
        if (floorMad < CSI_FLOOR_MIN) floorMad = CSI_FLOOR_MIN;

        score = mad / floorMad;
        if (scored < 0xFFFF) scored++;

        const float sd = score - scoreMean;
        scoreMean += CSI_SPREAD_ALPHA * sd;
        scoreVar += CSI_SPREAD_ALPHA * (sd * sd - scoreVar);
        return true;
    }
};
