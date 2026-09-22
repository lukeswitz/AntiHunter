#pragma once
#include <stdint.h>
#include <math.h>
#include <string.h>

#define CSI_NSUB 47
#define CSI_WINDOW_PSI 1

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
static const float CSI_ACF_ETA = 0.10f;
static const float CSI_PSI_ETA = 0.140f;
static const float CSI_PSI_Z = 2.0f;

static const int CSI_AREA_LINK_NUM = 1;
static const int CSI_AREA_LINK_DEN = 2;
static const int CSI_AREA_LINK_CAP = 2;
static const float CSI_ACF_ETA_SUB = 0.10f;
static const uint8_t CSI_ACF_HIST = 120;
static const uint16_t CSI_ACF_SAMPLE_EVERY = 32;
static const float CSI_ACF_QUANT = 10000.0f;
static const float CSI_ACF_MIN_SPREAD = 0.02f;
static const float CSI_SIG_MIN_SPREAD = 0.01f;
static const float CSI_SIG_QUANT = 20000.0f;
static const uint32_t CSI_PSI_HOLD_MAX_US = 60000000;
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
    float sigFloor;
    float sigSpread;
    float sigZ;
    uint16_t shist[CSI_ACF_HIST];
    uint8_t shlen;
    uint8_t shpos;
    uint16_t ssampCount;
    bool psiValid;
    uint16_t ahist[CSI_ACF_HIST];
    uint8_t ahlen;
    uint8_t ahpos;
    uint16_t asampCount;
    uint16_t phist[CSI_ACF_HIST];
    uint8_t phlen;
    uint8_t phpos;
    uint16_t psampCount;
    uint32_t psiHoldUs;
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
    uint32_t lagBkt[5];
    uint8_t prevValid;
    float *gring;
    float *gS1;
    float *gS2;
    float *gP;
    uint8_t gpos;
    uint8_t gcnt;

    bool settled() const { return scored >= CSI_FLOOR_SETTLE_PKTS; }
    bool psiHistReady() const { return phlen >= CSI_ACF_MIN_HIST; }
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
        sigFloor = 0.0f;
        sigSpread = CSI_SIG_MIN_SPREAD;
        sigZ = 0.0f;
        shlen = 0;
        shpos = 0;
        ssampCount = 0;
        psiValid = false;
        phlen = 0;
        phpos = 0;
        psampCount = 0;
        psiHoldUs = 0;
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
        for (int i = 0; i < 5; i++) lagBkt[i] = 0;
        prevValid = 0;
        gpos = 0;
        gcnt = 0;
        if (gS1 && gS2 && gP) {
            for (int k = 0; k < CSI_NSUB; k++) { gS1[k] = 0.0f; gS2[k] = 0.0f; gP[k] = 0.0f; }
        }
    }

    void attachWindow(float *block) {
        gring = block;
        gS1 = block ? block + (size_t)CSI_ACF_T * CSI_NSUB : nullptr;
        gS2 = gS1 ? gS1 + CSI_NSUB : nullptr;
        gP = gS2 ? gS2 + CSI_NSUB : nullptr;
    }

    static size_t windowFloats() { return (size_t)CSI_ACF_T * CSI_NSUB + 3u * CSI_NSUB; }

    float windowPsi(const float *a) {
        if (!gring || !gS1) return -2.0f;
        const uint8_t T = (uint8_t)CSI_ACF_T;
        const bool full = (gcnt >= T);
        const uint8_t lastIdx = (uint8_t)((gpos + T - 1) % T);
        const uint8_t secondIdx = (uint8_t)((gpos + 1) % T);
        for (int k = 0; k < CSI_NSUB; k++) {
            const float G = a[k] * a[k];
            if (full) {
                const float old = gring[gpos * CSI_NSUB + k];
                gS1[k] -= old;
                gS2[k] -= old * old;
                gP[k] -= old * gring[secondIdx * CSI_NSUB + k];
            }
            if (gcnt > 0) gP[k] += gring[lastIdx * CSI_NSUB + k] * G;
            gS1[k] += G;
            gS2[k] += G * G;
            gring[gpos * CSI_NSUB + k] = G;
        }
        gpos = (uint8_t)((gpos + 1) % T);
        if (gcnt < T) gcnt++;
        if (gcnt < T) return -2.0f;
        const uint8_t firstIdx = gpos;
        const uint8_t newIdx = (uint8_t)((gpos + T - 1) % T);
        const float n = (float)gcnt;
        float sum = 0.0f;
        int nb = 0;
        for (int k = 0; k < CSI_NSUB; k++) {
            const float m = gS1[k] / n;
            const float v0 = gS2[k] / n - m * m;
            if (v0 <= 1e-9f) continue;
            const float sa = gS1[k] - gring[firstIdx * CSI_NSUB + k];
            const float sb = gS1[k] - gring[newIdx * CSI_NSUB + k];
            float p = (gP[k] - m * (sa + sb) + (n - 1.0f) * m * m) / (n * v0);
            if (p > 1.0f) p = 1.0f;
            if (p < -1.0f) p = -1.0f;
            sum += p;
            nb++;
        }
        return (nb > 0) ? (sum / (float)nb) : -2.0f;
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

    float sigHistStats(float *spreadOut) const {
        uint16_t tmp[CSI_ACF_HIST];
        for (uint8_t i = 0; i < shlen; i++) tmp[i] = shist[i];
        for (uint8_t i = 1; i < shlen; i++) {
            uint16_t v = tmp[i];
            int16_t j = (int16_t)i - 1;
            while (j >= 0 && tmp[j] > v) { tmp[j + 1] = tmp[j]; j--; }
            tmp[j + 1] = v;
        }
        const float med = (float)tmp[shlen / 2] / CSI_SIG_QUANT;
        const float q1 = (float)tmp[shlen / 4] / CSI_SIG_QUANT;
        const float q3 = (float)tmp[(3 * shlen) / 4] / CSI_SIG_QUANT;
        float sp = (q3 - q1) / 1.349f;
        if (sp < CSI_SIG_MIN_SPREAD) sp = CSI_SIG_MIN_SPREAD;
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
        if (dtUs != 0xFFFFFFFFu) {
            const int bi = (dtUs < 50000) ? 0 : (dtUs < 200000) ? 1 : (dtUs < 1000000) ? 2 : (dtUs < 3000000) ? 3 : 4;
            if (lagBkt[bi] < 0xFFFFFFFFu) lagBkt[bi]++;
        }
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
        const float wpsi = windowPsi(a);
        psi = (wpsi > -1.5f) ? wpsi : 0.0f;
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

        if (holdFloor) {
            if (dtUs != 0xFFFFFFFFu && psiHoldUs < CSI_PSI_HOLD_MAX_US) psiHoldUs += dtUs;
        } else {
            psiHoldUs = 0;
        }
        const bool psiHoldExpired = (psiHoldUs >= CSI_PSI_HOLD_MAX_US);
        const bool psiBaseline = (phlen < CSI_ACF_MIN_HIST) ||
                                 (psi <= psiFloor + CSI_PSI_Z * psiSpread);
        if (psiValid && psiBaseline && (!holdFloor || psiHoldExpired) && ++psampCount >= CSI_ACF_SAMPLE_EVERY) {
            psampCount = 0;
            float pq = (psi + 1.0f) * CSI_ACF_QUANT;
            if (pq < 0.0f) pq = 0.0f;
            if (pq > 65535.0f) pq = 65535.0f;
            phist[phpos] = (uint16_t)pq;
            phpos = (uint8_t)((phpos + 1) % CSI_ACF_HIST);
            if (phlen < CSI_ACF_HIST) phlen++;
            psiFloor = psiHistStats(&psiSpread);
        }
        psiZ = (psiValid && psiHistReady()) ? ((psi - psiFloor) / psiSpread) : 0.0f;

        const bool sigBaseline = (shlen < CSI_ACF_MIN_HIST) ||
                                 (sigVar <= sigFloor + CSI_PSI_Z * sigSpread) ||
                                 psiHoldExpired;
        if (psiValid && sigBaseline && ++ssampCount >= CSI_ACF_SAMPLE_EVERY) {
            ssampCount = 0;
            float sq = sigVar * CSI_SIG_QUANT;
            if (sq < 0.0f) sq = 0.0f;
            if (sq > 65535.0f) sq = 65535.0f;
            shist[shpos] = (uint16_t)sq;
            shpos = (uint8_t)((shpos + 1) % CSI_ACF_HIST);
            if (shlen < CSI_ACF_HIST) shlen++;
            sigFloor = sigHistStats(&sigSpread);
        }
        sigZ = (psiValid && shlen >= CSI_ACF_MIN_HIST) ? ((sigVar - sigFloor) / sigSpread) : 0.0f;

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
