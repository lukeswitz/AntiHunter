#include "csi_metric.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static unsigned long rngState = 12345;
static float frand() {
    rngState = rngState * 1103515245UL + 12345UL;
    return (float)((rngState >> 16) & 0x7fff) / 32767.0f;
}

static const int NSC = 64;
static const float BW = 20e6f;
static float gauss() {
    float u = frand(), v = frand();
    if (u < 1e-7f) u = 1e-7f;
    return sqrtf(-2.0f * logf(u)) * cosf(6.2831853f * v);
}
struct Path { float amp, delay, dopp, phase; };
static void channelAt(const Path *p, int np, float t, float *re, float *im) {
    for (int k = 0; k < NSC; k++) {
        const float fk = ((float)k - NSC / 2.0f) * (BW / NSC);
        float sr = 0.0f, si = 0.0f;
        for (int i = 0; i < np; i++) {
            const float ph = p[i].phase + 6.2831853f * p[i].dopp * t - 6.2831853f * fk * p[i].delay;
            sr += p[i].amp * cosf(ph);
            si += p[i].amp * sinf(ph);
        }
        re[k] = sr;
        im[k] = si;
    }
}
static void quantize(const float *re, const float *im, float noise, int8_t *buf) {
    float pw = 0.0f;
    for (int k = 0; k < NSC; k++) pw += re[k] * re[k] + im[k] * im[k];
    const float rms = sqrtf(pw / NSC);
    const float g = (rms > 0.0f) ? (45.0f / rms) : 1.0f;
    for (int k = 0; k < NSC; k++) {
        float r = g * re[k] + noise * gauss();
        float q = g * im[k] + noise * gauss();
        if (r > 127.0f) r = 127.0f;
        if (r < -127.0f) r = -127.0f;
        if (q > 127.0f) q = 127.0f;
        if (q < -127.0f) q = -127.0f;
        buf[k * 2] = (int8_t)lrintf(q);
        buf[k * 2 + 1] = (int8_t)lrintf(r);
    }
}
static void mkStatic(Path *p, int &np) {
    np = 0;
    for (int i = 0; i < 6; i++) {
        p[np].amp = 1.0f / (1.0f + i * 0.6f);
        p[np].delay = (float)i * 25e-9f;
        p[np].dopp = 0.0f;
        p[np].phase = frand() * 6.2831853f;
        np++;
    }
}
static void addWalker(Path *p, int &np, float scale) {
    const float fd[4] = {1.5f, 3.0f, 6.5f, 11.0f};
    const float amp[4] = {0.30f, 0.22f, 0.15f, 0.10f};
    for (int i = 0; i < 4; i++) {
        p[np].amp = amp[i] * scale;
        p[np].delay = (110.0f + 15.0f * i) * 1e-9f;
        p[np].dopp = fd[i];
        p[np].phase = frand() * 6.2831853f;
        np++;
    }
}

struct Gate { uint32_t packets = 0, consec = 0, elevMs = 0; bool motion = false; };

static bool gateStep(Gate &g, const CsiScorer &s, uint32_t dtMs) {
    const bool relAbove = s.shlen >= CSI_ACF_MIN_HIST && s.sigVar >= CSI_REL_MIN_SIG &&
                          s.sigVar >= CSI_REL_FLOOR_K * s.sigFloor;
    const bool sigAbove = s.psiValid && (s.sigVar >= CSI_SIG_ETA || relAbove) && s.sigZ >= CSI_SIG_Z_GATE;
    if (sigAbove) {
        if (g.consec < 255) g.consec++;
        g.elevMs += dtMs;
        if (g.elevMs > 6000) g.elevMs = 6000;
    } else {
        g.consec = 0;
        const uint32_t d = dtMs * 2;
        g.elevMs = g.elevMs > d ? g.elevMs - d : 0;
    }
    if (!s.settled() || g.packets < CSI_LINK_MIN_PKTS) return false;
    if (!g.motion && g.elevMs >= 300 && g.consec >= 3) { g.motion = true; return true; }
    return false;
}

static void homeTrials(float fps, float noise, int trials, int &hits, int &falses) {
    static float *hwin = static_cast<float *>(calloc(CsiScorer::windowFloats(), sizeof(float)));
    hits = falses = 0;
    const uint32_t dt = (uint32_t)(1e6f / fps);
    for (int tr = 0; tr < trials; tr++) {
        Path p[16]; int np;
        mkStatic(p, np);
        CsiScorer s; s.attachWindow(hwin); s.reset();
        Gate g;
        float re[NSC], im[NSC], a[CSI_NSUB];
        int8_t buf[128];
        double t = 0.0;
        bool falseHit = false;
        for (int i = 0; i < (int)(fps * 120.0f); i++) {
            t += dt / 1e6;
            channelAt(p, np, (float)t, re, im);
            quantize(re, im, noise, buf);
            if (!csiAmplitudes(buf, a)) continue;
            g.packets++;
            if (s.update(a, g.motion, dt) && gateStep(g, s, dt / 1000)) falseHit = true;
        }
        if (falseHit) falses++;
        g.motion = false; g.consec = 0; g.elevMs = 0;
        addWalker(p, np, 1.0f);
        for (int i = 0; i < (int)(fps * 60.0f); i++) {
            t += dt / 1e6;
            channelAt(p, np, (float)t, re, im);
            quantize(re, im, noise, buf);
            if (!csiAmplitudes(buf, a)) continue;
            g.packets++;
            if (s.update(a, g.motion, dt) && gateStep(g, s, dt / 1000)) { hits++; break; }
        }
    }
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
        if (s.update(a, holdFloor, 20000)) last = s.score;
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
        if (s.update(a, holdFloor, 20000) && s.score > peak) peak = s.score;
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
    printf("hold:   floor before=%.5f after=%.5f (ratio %.2f)\n",
           floorBefore, f.floorMad, f.floorMad / floorBefore);
    assert(f.floorMad < floorBefore * 1.5f);
    assert(f.floorMad > floorBefore * 0.5f);

    CsiScorer d;
    d.reset();
    feed(d, re, im, 3.0f, 400, false);
    float driftBefore = d.floorMad;
    feed(d, mre, mim, 3.0f, 300, false);
    printf("drift:  floor before=%.5f after=%.5f\n", driftBefore, d.floorMad);
    assert(d.floorMad > driftBefore);

    CsiScorer z;
    z.reset();
    const int8_t zero[128] = {0};
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
            if (!fp.update(amp, false, 20000)) continue;
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
            if (!fp.update(amp, false, 20000)) continue;
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

    printf("== quiet link is below the gate from the moment it arms ==\n");
    {
        CsiScorer q; q.reset();
        int8_t qbuf[128];
        float qa[CSI_NSUB];
        int n = 0;
        int armN = 0;
        float worst = 0.0f;
        while (n < 1000) {
            makePacket(qbuf, re, im, 3.0f);
            n++;
            if (!csiAmplitudes(qbuf, qa)) continue;
            q.update(qa, false, 20000);
            if (q.settled() && !armN) armN = n;
            if (q.settled() && q.sigVar > worst) worst = q.sigVar;
        }
        printf("   armed after %d packets  worst quiet sig after arming=%.4f  gate=%.3f\n",
               armN, worst, CSI_SIG_ETA);
        assert(armN > 0);
        assert(worst < CSI_SIG_ETA);
    }

    printf("== AP channel floor: CSI_HOME_MIN_FPS=%.0f/s from one transmitter ==\n", CSI_HOME_MIN_FPS);
    {
        assert(!csiHomeChannelOk(0, 10000));
        assert(!csiHomeChannelOk(119, 10000));
        assert(csiHomeChannelOk(120, 10000));
        assert(!csiHomeChannelOk(120, 0));
        int hitFloor = 0, hitHalf = 0, falseQuiet = 0;
        const float noises[3] = {2.0f, 4.0f, 8.0f};
        for (float nz : noises) {
            int h, fq;
            homeTrials(CSI_HOME_MIN_FPS, nz, 20, h, fq);
            hitFloor += h; falseQuiet += fq;
            homeTrials(CSI_HOME_MIN_FPS / 2.0f, nz, 20, h, fq);
            hitHalf += h; falseQuiet += fq;
        }
        printf("   walker caught at %.0f/s: %d/60   at %.0f/s: %d/60   false alerts while quiet: %d/120\n",
               CSI_HOME_MIN_FPS, hitFloor, CSI_HOME_MIN_FPS / 2.0f, hitHalf, falseQuiet);
        assert(hitFloor >= 50);
        assert(hitHalf <= 10);
    }

    printf("\nOK\n");
    return 0;
}
