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
static const uint8_t CSI_FLOOR_HIST = 120;
static const uint16_t CSI_FLOOR_SAMPLE_EVERY = 32;
static const float CSI_FLOOR_QUANT = 100000.0f;
static const float CSI_VAR_ALPHA = 0.005f;
static const float CSI_VAR_W_FLOOR = 0.01f;
static const float CSI_ACF_ALPHA = 0.0167f;
static const uint16_t CSI_ACF_T = 60;
static const float CSI_ACF_ETA = 0.10f;
static const float CSI_ACF_ETA_SUB = 0.25f;
static const float CSI_VOTE_FRAC = 0.50f;
static const float CSI_FLOOR_MIN = 0.0004f;
static const uint16_t CSI_WARMUP_PKTS = 40;
static const uint16_t CSI_FLOOR_SETTLE_PKTS = 450;
static const float CSI_SPREAD_ALPHA = 0.02f;
static const float CSI_LINK_MIN_SPREAD = 0.03f;
static const uint32_t CSI_LINK_MIN_PKTS = 60;
static const int8_t CSI_LINK_MIN_RSSI = -92;
static const int8_t CSI_SURVEY_MIN_RSSI = -85;

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
    float var[CSI_NSUB];
    float prevG[CSI_NSUB];
    float mG[CSI_NSUB];
    float mG2[CSI_NSUB];
    float mGG[CSI_NSUB];
    float acf;
    float vote;
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

    bool settled() const { return scored >= CSI_FLOOR_SETTLE_PKTS; }
    float spread() const { return scoreVar > 0.0f ? sqrtf(scoreVar) : 0.0f; }

    void reset() {
        for (int k = 0; k < CSI_NSUB; k++) {
            fast[k] = 0.0f; slow[k] = 0.0f; var[k] = 0.0f;
            prevG[k] = 0.0f; mG[k] = 0.0f; mG2[k] = 0.0f; mGG[k] = 0.0f;
        }
        acf = 0.0f;
        vote = 0.0f;
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

    bool update(const float *a, bool /*holdFloor*/) {
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

        float psi = 0.0f;
        int nf = 0;
        int nvote = 0;
        for (int k = 0; k < CSI_NSUB; k++) {
            const float G = a[k] * a[k];
            if (scored > 0) {
                mGG[k] += CSI_ACF_ALPHA * (G * prevG[k] - mGG[k]);
                mG[k] += CSI_ACF_ALPHA * (G - mG[k]);
                mG2[k] += CSI_ACF_ALPHA * (G * G - mG2[k]);
                const float m2 = mG[k] * mG[k];
                const float v = mG2[k] - m2;
                if (v > 1e-12f) {
                    float p = (mGG[k] - m2) / v;
                    if (p > 1.0f) p = 1.0f;
                    if (p < -1.0f) p = -1.0f;
                    psi += p;
                    nf++;
                    if (p > CSI_ACF_ETA_SUB) nvote++;
                }
            }
            prevG[k] = G;
        }
        acf = (nf > 0) ? (psi / (float)nf) : 0.0f;
        vote = (nf > 0) ? ((float)nvote / (float)nf) : 0.0f;

        if (++sampCount >= CSI_FLOOR_SAMPLE_EVERY) {
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
