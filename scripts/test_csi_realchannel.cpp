#include "csi_metric.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

// Channel profile and noise measured on hardware from the [PROF] dump of the
// CSI firmware found on /dev/cu.usbmodem212301, n=699 packets, rssi -88, nf -97.
static const float MEAS_AMP[64] = {
    0.05f, 17.43f, 18.25f, 18.76f, 19.27f, 19.70f, 19.52f, 18.82f,
    17.86f, 16.90f, 15.25f, 14.31f, 13.92f, 14.38f, 14.66f, 14.35f,
    13.76f, 13.36f, 13.20f, 12.92f, 12.74f, 12.15f, 11.94f, 11.51f,
    11.04f, 10.40f,  9.43f,  0.00f,  0.00f,  0.00f,  0.00f,  0.00f,
     0.00f,  0.00f,  0.00f,  0.00f,  0.00f,  0.00f,  5.00f,  4.78f,
     5.00f,  5.37f,  5.60f,  5.85f,  6.14f,  6.34f,  6.46f,  6.59f,
     6.93f,  7.20f,  7.31f,  7.55f,  7.29f,  7.90f,  9.31f, 11.37f,
    12.95f, 13.98f, 14.74f, 15.15f, 15.15f, 15.17f, 15.34f, 15.82f
};
static const float MEAS_NOISE_SD = 2.90f;

static unsigned long rngState = 987654321UL;
static float gauss() {
    float s = 0.0f;
    for (int i = 0; i < 12; i++) {
        rngState = rngState * 1103515245UL + 12345UL;
        s += (float)((rngState >> 16) & 0x7fff) / 32767.0f;
    }
    return s - 6.0f;
}

static void makePacket(int8_t *buf, const float *amp, float pert, float noiseSd) {
    for (int idx = 0; idx < 64; idx++) {
        const float base = amp[idx];
        const float mag = base * (1.0f + pert * sinf(idx * 0.83f + 1.7f));
        const float ph = 0.37f * idx + 2.1f;
        float re = mag * cosf(ph) + noiseSd * gauss();
        float im = mag * sinf(ph) + noiseSd * gauss();
        if (re > 127.0f) re = 127.0f; if (re < -127.0f) re = -127.0f;
        if (im > 127.0f) im = 127.0f; if (im < -127.0f) im = -127.0f;
        buf[idx * 2] = (int8_t)im;
        buf[idx * 2 + 1] = (int8_t)re;
    }
}

struct FlatScorer {
    float ema[CSI_NSUB];
    float floorMad, mad, score;
    uint16_t warm;
    void reset() {
        for (int k = 0; k < CSI_NSUB; k++) ema[k] = 0.0f;
        floorMad = mad = score = 0.0f; warm = 0;
    }
    bool update(const float *a, bool hold) {
        if (warm < CSI_WARMUP_PKTS) {
            if (warm == 0) { for (int k = 0; k < CSI_NSUB; k++) ema[k] = a[k]; }
            else { for (int k = 0; k < CSI_NSUB; k++) ema[k] += CSI_WARM_ALPHA * (a[k] - ema[k]); }
            warm++; return false;
        }
        float d = 0.0f;
        for (int k = 0; k < CSI_NSUB; k++) d += fabsf(a[k] - ema[k]);
        d /= (float)CSI_NSUB;
        for (int k = 0; k < CSI_NSUB; k++) ema[k] += 0.06f * (a[k] - ema[k]);
        mad = d;
        if (floorMad <= 0.0f) floorMad = d;
        if (!hold) floorMad += CSI_FLOOR_ALPHA * (d - floorMad);
        if (floorMad < CSI_FLOOR_MIN) floorMad = CSI_FLOOR_MIN;
        score = mad / floorMad;
        return true;
    }
};

template <typename S>
static void run(S &s, float pert, int n, bool hold, float *outMean, float *outMax) {
    int8_t buf[128];
    float a[CSI_NSUB];
    float sum = 0.0f, mx = 0.0f;
    int c = 0;
    for (int i = 0; i < n; i++) {
        makePacket(buf, MEAS_AMP, pert, MEAS_NOISE_SD);
        if (!csiAmplitudes(buf, a)) continue;
        if (!s.update(a, hold)) continue;
        sum += s.score; if (s.score > mx) mx = s.score; c++;
    }
    *outMean = c ? sum / c : 0.0f;
    *outMax = mx;
}

int main() {
    printf("Measured channel: rssi -88, nf -97 (~9 dB SNR), ampSD %.2f absolute\n", MEAS_NOISE_SD);
    printf("Active subcarriers span meanAmp %.2f..%.2f -> relative noise %.0f%%..%.0f%%\n\n",
           4.78f, 19.70f, 100.0f * MEAS_NOISE_SD / 19.70f, 100.0f * MEAS_NOISE_SD / 4.78f);

    const float perts[] = {0.00f, 0.02f, 0.05f, 0.10f, 0.15f, 0.25f, 0.40f};
    printf("%-12s | %-18s | %-18s\n", "perturb", "FLAT peak score", "WEIGHTED peak score");
    printf("-------------|--------------------|--------------------\n");

    float flatStill = 0.0f, wStill = 0.0f;
    for (unsigned i = 0; i < sizeof(perts) / sizeof(perts[0]); i++) {
        const float p = perts[i];

        FlatScorer f; f.reset();
        float fm, fx;
        run(f, 0.0f, 600, false, &fm, &fx);
        run(f, p, 60, p > 0.0f, &fm, &fx);

        CsiScorer w; w.reset();
        float wm, wx;
        run(w, 0.0f, 600, false, &wm, &wx);
        run(w, p, 60, p > 0.0f, &wm, &wx);

        if (p == 0.0f) { flatStill = fx; wStill = wx; }
        printf("%9.0f%%   | %8.2fx          | %8.2fx\n", p * 100.0f, fx, wx);
    }

    printf("\nstill-state peak: flat %.2fx, weighted %.2fx\n", flatStill, wStill);

    printf("\n-- separability (peak motion score / peak still score) --\n");
    for (unsigned i = 1; i < sizeof(perts) / sizeof(perts[0]); i++) {
        const float p = perts[i];
        FlatScorer f; f.reset();
        float fm, fx; run(f, 0.0f, 600, false, &fm, &fx); run(f, p, 60, true, &fm, &fx);
        CsiScorer w; w.reset();
        float wm, wx; run(w, 0.0f, 600, false, &wm, &wx); run(w, p, 60, true, &wm, &wx);
        printf("  perturb %4.0f%%  flat %5.2fx  weighted %5.2fx  gain %+.0f%%\n",
               p * 100.0f, fx / flatStill, wx / wStill,
               100.0f * ((wx / wStill) / (fx / flatStill) - 1.0f));
    }

    printf("\nOK\n");
    return 0;
}
