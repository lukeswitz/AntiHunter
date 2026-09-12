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
static const uint8_t CSI_FLOOR_HIST = 120;
static const uint16_t CSI_FLOOR_SAMPLE_EVERY = 32;
static const float CSI_FLOOR_QUANT = 100000.0f;
static const float CSI_VAR_ALPHA = 0.005f;
static const float CSI_VAR_W_FLOOR = 0.01f;
static const float CSI_ACF_ALPHA = 0.0167f;
static const uint16_t CSI_ACF_T = 60;
static const uint32_t CSI_ACF_LAG_MIN_US = 8000;
static const uint32_t CSI_ACF_LAG_MAX_US = 1000000;
static const float CSI_ACF_ETA = 0.10f;
static const float CSI_SIG_ETA = 0.050f;
static const float CSI_PSI_K = 3.0f;
static const float CSI_PSI_Z = 3.0f;

static inline float csiAnalyticEta() {
    const float T = 1.0f / CSI_ACF_ALPHA;
    return -1.0f / T + CSI_PSI_K * sqrtf(1.0f / ((float)CSI_NSUB * T));
}
static const float CSI_ACF_ETA_SUB = 0.10f;
static const uint8_t CSI_ACF_HIST = 120;
static const uint16_t CSI_ACF_SAMPLE_EVERY = 32;
static const float CSI_ACF_QUANT = 10000.0f;
static const float CSI_ACF_MIN_SPREAD = 0.02f;
static const uint8_t CSI_ACF_MIN_HIST = 12;
static const float CSI_VOTE_FRAC = 0.50f;
static const float CSI_FLOOR_MIN = 0.0004f;
static const uint16_t CSI_WARMUP_PKTS = 40;
static const uint16_t CSI_FLOOR_SETTLE_PKTS = 450;
static const uint16_t CSI_ACF_SETTLE_PAIRS = 450;
static const float CSI_SPREAD_ALPHA = 0.02f;
static const float CSI_LINK_MIN_SPREAD = 0.03f;
static const uint32_t CSI_LINK_MIN_PKTS = 60;
static const float CSI_LINK_ARM_SEC = 60.0f;
static const float CSI_LINK_MIN_PAIR_RATE = (float)CSI_ACF_T / CSI_LINK_ARM_SEC;
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
    float mGG[CSI_NSUB];
    float mG2[CSI_NSUB];
    float mD2[CSI_NSUB];
    float acf;
    float sigVar;
    float vote;
    float psi;
    float acfFloor;
    float acfSpread;
    float acfZ;
    float psiFloor;
    float psiSpread;
    float psiZ;
    bool psiValid;
    uint16_t ahist[CSI_ACF_HIST];
    uint8_t ahlen;
    uint8_t ahpos;
    uint16_t asampCount;
    uint16_t phist[CSI_ACF_HIST];
    uint8_t phlen;
    uint8_t phpos;
    uint16_t psampCount;
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
    uint32_t lagSkips;
    uint32_t lagBkt[5];
    uint8_t prevValid;
    uint32_t lagAccum;

    bool settled() const { return scored >= CSI_FLOOR_SETTLE_PKTS && acfPairs >= CSI_ACF_SETTLE_PAIRS; }
    float spread() const { return scoreVar > 0.0f ? sqrtf(scoreVar) : 0.0f; }

    void reset() {
        for (int k = 0; k < CSI_NSUB; k++) {
            fast[k] = 0.0f; slow[k] = 0.0f; var[k] = 0.0f;
            prevG[k] = 0.0f; mG[k] = 0.0f; mGG[k] = 0.0f; mG2[k] = 0.0f; mD2[k] = 0.0f;
        }
        acf = 0.0f;
        sigVar = 0.0f;
        vote = 0.0f;
        psi = 0.0f;
        acfFloor = 0.0f;
        acfSpread = CSI_ACF_MIN_SPREAD;
        acfZ = 0.0f;
        psiFloor = 0.0f;
        psiSpread = CSI_ACF_MIN_SPREAD;
        psiZ = 0.0f;
        psiValid = false;
        phlen = 0;
        phpos = 0;
        psampCount = 0;
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
        lagSkips = 0;
        for (int i = 0; i < 5; i++) lagBkt[i] = 0;
        prevValid = 0;
        lagAccum = 0;
    }

    float psiHistStats(float *spreadOut) const {
        uint16_t tmp[CSI_ACF_HIST];
        for (uint8_t i = 0; i < phlen; i++) tmp[i] = phist[i];
        for (uint8_t i = 1; i < phlen; i++) {
            uint16_t v = tmp[i];
            int16_t j = (int16_t)i - 1;
            while (j >= 0 && tmp[j] > v) { tmp[j + 1] = tmp[j]; j--; }
            tmp[j + 1] = v;
        }
        const float med = (float)tmp[phlen / 2] / CSI_ACF_QUANT - 1.0f;
        const float q1 = (float)tmp[phlen / 4] / CSI_ACF_QUANT - 1.0f;
        const float q3 = (float)tmp[(3 * phlen) / 4] / CSI_ACF_QUANT - 1.0f;
        float sp = (q3 - q1) / 1.349f;
        if (sp < CSI_ACF_MIN_SPREAD) sp = CSI_ACF_MIN_SPREAD;
        *spreadOut = sp;
        return med;
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

        float psiPos = 0.0f;
        float psiSq = 0.0f;
        float sigAcc = 0.0f;
        int nsig = 0;
        int nf = 0;
        int nvote = 0;
        float psiAll = 0.0f;
        const bool lagOk = (dtUs >= CSI_ACF_LAG_MIN_US && dtUs <= CSI_ACF_LAG_MAX_US);
        if (dtUs != 0xFFFFFFFFu) {
            const int bi = (dtUs < 50000) ? 0 : (dtUs < 200000) ? 1 : (dtUs < 1000000) ? 2 : (dtUs < 3000000) ? 3 : 4;
            if (lagBkt[bi] < 0xFFFFFFFFu) lagBkt[bi]++;
        }
        if (!lagOk && lagSkips < 0xFFFFFFFFu) lagSkips++;
        for (int k = 0; k < CSI_NSUB; k++) {
            const float G = a[k] * a[k];
            if (acfPairs > 0 && prevValid) {
                const float dG = G - prevG[k];
                mGG[k] += CSI_ACF_ALPHA * (G * prevG[k] - mGG[k]);
                mG[k] += CSI_ACF_ALPHA * (G - mG[k]);
                mG2[k] += CSI_ACF_ALPHA * (G * G - mG2[k]);
                mD2[k] += CSI_ACF_ALPHA * (dG * dG - mD2[k]);
                {
                    const float tv = mG2[k] - mG[k] * mG[k];
                    if (tv > 1e-12f) {
                        const float sv = tv - mD2[k] * 0.5f;
                        sigAcc += (sv > 0.0f) ? sv : 0.0f;
                        nsig++;
                    }
                }
                const float m2 = mG[k] * mG[k];
                const float v = mG2[k] - m2;
                if (v > 1e-12f) {
                    float p = (mGG[k] - m2) / v;
                    if (p > 1.0f) p = 1.0f;
                    if (p < -1.0f) p = -1.0f;
                    if (p > 0.0f) {
                        psiPos += p;
                        psiSq += p * p;
                    }
                    nf++;
                    psiAll += p;
                    if (p > CSI_ACF_ETA_SUB) nvote++;
                }
            }
            prevG[k] = G;
        }
        if (acfPairs < 0xFFFFFFFFu) acfPairs++;
        prevValid = 1;
        acf = (psiPos > 1e-6f) ? (psiSq / psiPos) : 0.0f;
        sigVar = (nsig > 0) ? (sigAcc / (float)nsig) : 0.0f;
        vote = (nf > 0) ? ((float)nvote / (float)nf) : 0.0f;
        psi = (nf > 0) ? (psiAll / (float)nf) : 0.0f;
        psiValid = (nf > 0);

        if (!holdFloor &&
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

        const bool psiBaseline = (phlen < CSI_ACF_MIN_HIST) ||
                                 (psi <= psiFloor + CSI_PSI_Z * psiSpread);
        if (psiValid && psiBaseline && !holdFloor && ++psampCount >= CSI_ACF_SAMPLE_EVERY) {
            psampCount = 0;
            float pq = (psi + 1.0f) * CSI_ACF_QUANT;
            if (pq < 0.0f) pq = 0.0f;
            if (pq > 65535.0f) pq = 65535.0f;
            phist[phpos] = (uint16_t)pq;
            phpos = (uint8_t)((phpos + 1) % CSI_ACF_HIST);
            if (phlen < CSI_ACF_HIST) phlen++;
            psiFloor = psiHistStats(&psiSpread);
        }
        psiZ = (psiValid && phlen >= CSI_ACF_MIN_HIST) ? ((psi - psiFloor) / psiSpread) : 0.0f;

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
