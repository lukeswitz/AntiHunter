#include "csi_metric.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long rngState = 12345;
static float frand() {
    rngState = rngState * 1103515245UL + 12345UL;
    return (float)((rngState >> 16) & 0x7fff) / 32767.0f;
}

static void makePacket(int8_t *buf, const float *chanReal, const float *chanImag, float noise) {
    for (int idx = 0; idx < 64; idx++) {
        float re = chanReal[idx] + noise * (frand() - 0.5f);
        float im = chanImag[idx] + noise * (frand() - 0.5f);
        if (re > 127.0f) re = 127.0f;
        if (re < -127.0f) re = -127.0f;
        if (im > 127.0f) im = 127.0f;
        if (im < -127.0f) im = -127.0f;
        buf[idx * 2] = (int8_t)im;
        buf[idx * 2 + 1] = (int8_t)re;
    }
}

static float feed(CsiScorer &s, const float *re, const float *im, float noise, int n, bool holdFloor) {
    int8_t buf[128];
    float a[CSI_NSUB];
    float last = 0.0f;
    for (int i = 0; i < n; i++) {
        makePacket(buf, re, im, noise);
        if (!csiAmplitudes(buf, a)) continue;
        if (s.update(a, holdFloor)) last = s.score;
    }
    return last;
}

static float feedPeak(CsiScorer &s, const float *re, const float *im, float noise, int n, bool holdFloor) {
    int8_t buf[128];
    float a[CSI_NSUB];
    float peak = 0.0f;
    for (int i = 0; i < n; i++) {
        makePacket(buf, re, im, noise);
        if (!csiAmplitudes(buf, a)) continue;
        if (s.update(a, holdFloor) && s.score > peak) peak = s.score;
    }
    return peak;
}

int main() {
    float re[64], im[64];
    for (int i = 0; i < 64; i++) {
        re[i] = 30.0f + 20.0f * sinf(i * 0.31f);
        im[i] = 25.0f + 20.0f * cosf(i * 0.17f);
    }

    CsiScorer s;
    s.reset();

    float stillScore = feed(s, re, im, 3.0f, 400, false);
    printf("still:  score=%.3f mad=%.5f floor=%.5f\n", stillScore, s.mad, s.floorMad);
    assert(s.warm >= CSI_WARMUP_PKTS);
    assert(stillScore < 2.5f);

    float gainOnly[64], gainOnlyIm[64];
    for (int i = 0; i < 64; i++) {
        gainOnly[i] = re[i] * 0.35f;
        gainOnlyIm[i] = im[i] * 0.35f;
    }
    float agcScore = feedPeak(s, gainOnly, gainOnlyIm, 1.0f, 60, false);
    printf("agc:    peak=%.3f floor=%.5f\n", agcScore, s.floorMad);
    assert(agcScore < 2.5f);

    CsiScorer m;
    m.reset();
    feed(m, re, im, 3.0f, 400, false);
    float quietFloor = m.floorMad;

    float mre[64], mim[64];
    for (int i = 0; i < 64; i++) {
        mre[i] = re[i] + 14.0f * sinf(i * 0.9f);
        mim[i] = im[i] - 14.0f * cosf(i * 0.7f);
    }
    float motionScore = feedPeak(m, mre, mim, 3.0f, 40, true);
    printf("motion: peak=%.3f floor=%.5f (quiet floor %.5f)\n", motionScore, m.floorMad, quietFloor);
    assert(motionScore > 2.5f);

    CsiScorer f;
    f.reset();
    feed(f, re, im, 3.0f, 400, false);
    float floorBefore = f.floorMad;
    feed(f, mre, mim, 3.0f, 300, true);
    printf("hold:   floor before=%.5f after=%.5f\n", floorBefore, f.floorMad);
    assert(f.floorMad == floorBefore);

    CsiScorer d;
    d.reset();
    feed(d, re, im, 3.0f, 400, false);
    float driftBefore = d.floorMad;
    feed(d, mre, mim, 3.0f, 300, false);
    printf("drift:  floor before=%.5f after=%.5f\n", driftBefore, d.floorMad);
    assert(d.floorMad > driftBefore);

    CsiScorer z;
    z.reset();
    int8_t zero[128] = {0};
    float a[CSI_NSUB];
    assert(!csiAmplitudes(zero, a));
    printf("zero:   rejected\n");

    printf("\n-- false positives on a still channel (trigger 2.5x, 3 consecutive) --\n");
    for (int trial = 0; trial < 3; trial++) {
        CsiScorer fp;
        fp.reset();
        feed(fp, re, im, 3.0f, 200, false);

        int8_t buf[128];
        float amp[CSI_NSUB];
        int over = 0, runs = 0, consec = 0, scored = 0;
        for (int i = 0; i < 20000; i++) {
            makePacket(buf, re, im, 3.0f);
            if (!csiAmplitudes(buf, amp)) continue;
            if (!fp.update(amp, false)) continue;
            scored++;
            if (fp.score >= 2.5f) {
                over++;
                consec++;
                if (consec == 3) runs++;
            } else {
                consec = 0;
            }
        }
        printf("still %d: %d/%d packets over 2.5x, %d would have latched (3 consecutive)\n",
               trial, over, scored, runs);
        assert(runs == 0);
    }

    printf("\n-- sensitivity: channel perturbation vs peak score (noise 3.0 on |h| ~ %.1f) --\n",
           [&]{ float s2 = 0; for (int i = 0; i < 64; i++) s2 += sqrtf(re[i]*re[i] + im[i]*im[i]); return s2 / 64.0f; }());
    const float fracs[] = {0.01f, 0.02f, 0.03f, 0.05f, 0.08f, 0.12f, 0.20f, 0.35f};
    float tripFrac = -1.0f;
    for (unsigned fi = 0; fi < sizeof(fracs) / sizeof(fracs[0]); fi++) {
        const float f2 = fracs[fi];
        float pre[64], pim[64];
        for (int i = 0; i < 64; i++) {
            const float h = sqrtf(re[i] * re[i] + im[i] * im[i]);
            pre[i] = re[i] + f2 * h * sinf(i * 0.9f);
            pim[i] = im[i] - f2 * h * cosf(i * 0.7f);
        }
        CsiScorer p;
        p.reset();
        feed(p, re, im, 3.0f, 400, false);
        float peak = feedPeak(p, pre, pim, 3.0f, 40, true);
        printf("  perturbation %5.1f%% of |h| -> peak score %6.2fx  %s\n",
               f2 * 100.0f, peak, peak >= 2.5f ? "LATCH" : "quiet");
        if (tripFrac < 0.0f && peak >= 2.5f) tripFrac = f2;
    }
    assert(tripFrac > 0.0f);
    printf("  trips at >= %.0f%% channel perturbation under 3.0-unit per-packet noise\n", tripFrac * 100.0f);

    printf("\n-- tuning tradeoff: trigger vs still-channel false latches (20000 still packets) --\n");
    const float trigs[] = {1.5f, 1.8f, 2.0f, 2.5f, 3.0f};
    for (unsigned ti = 0; ti < sizeof(trigs) / sizeof(trigs[0]); ti++) {
        const float trig = trigs[ti];

        CsiScorer fp;
        fp.reset();
        feed(fp, re, im, 3.0f, 200, false);
        int8_t buf[128];
        float amp[CSI_NSUB];
        int runs = 0, consec = 0;
        for (int i = 0; i < 20000; i++) {
            makePacket(buf, re, im, 3.0f);
            if (!csiAmplitudes(buf, amp)) continue;
            if (!fp.update(amp, false)) continue;
            if (fp.score >= trig) { consec++; if (consec == 3) runs++; }
            else consec = 0;
        }

        float smallest = -1.0f;
        for (unsigned fi = 0; fi < sizeof(fracs) / sizeof(fracs[0]); fi++) {
            const float f2 = fracs[fi];
            float pre[64], pim[64];
            for (int i = 0; i < 64; i++) {
                const float h = sqrtf(re[i] * re[i] + im[i] * im[i]);
                pre[i] = re[i] + f2 * h * sinf(i * 0.9f);
                pim[i] = im[i] - f2 * h * cosf(i * 0.7f);
            }
            CsiScorer p;
            p.reset();
            feed(p, re, im, 3.0f, 400, false);
            if (feedPeak(p, pre, pim, 3.0f, 40, true) >= trig) { smallest = f2; break; }
        }

        printf("  trigger %.1fx -> %3d false latches, detects >= %.0f%% perturbation\n",
               trig, runs, smallest * 100.0f);
    }

    printf("\nOK\n");
    return 0;
}
