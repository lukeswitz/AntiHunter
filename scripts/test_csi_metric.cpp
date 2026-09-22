#include "csi_metric.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static const int NSC = 64;
static const float BW = 20e6f;

static unsigned long rngState = 12345;
static float frand() {
    rngState = rngState * 1103515245UL + 12345UL;
    return (float)((rngState >> 16) & 0x7fff) / 32767.0f;
}
static float gauss() {
    float u = frand(), v = frand();
    if (u < 1e-7f) u = 1e-7f;
    return sqrtf(-2.0f * logf(u)) * cosf(6.2831853f * v);
}

static void makePacket(int8_t *buf, const float *chanReal, const float *chanImag, float noise) {
    for (int idx = 0; idx < NSC; idx++) {
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

struct Path { float amp, delay, dopp, phase; };

// dopp != 0 is a moving scatterer, so the channel varies in time
static void channelAt(const Path *p, int np, float t, float *re, float *im) {
    for (int k = 0; k < NSC; k++) {
        const float fk = ((float)k - NSC / 2.0f) * (BW / NSC);
        float sr = 0.0f, si = 0.0f;
        for (int i = 0; i < np; i++) {
            const float ph = p[i].phase + 6.2831853f * p[i].dopp * t - 6.2831853f * fk * p[i].delay;
            sr += p[i].amp * cosf(ph);
            si += p[i].amp * sinf(ph);
        }
        re[k] = sr; im[k] = si;
    }
}

static void quantize(const float *re, const float *im, float noise, int8_t *buf) {
    float p = 0.0f;
    for (int k = 0; k < NSC; k++) p += re[k] * re[k] + im[k] * im[k];
    const float rms = sqrtf(p / NSC);
    const float g = (rms > 0.0f) ? (45.0f / rms) : 1.0f;
    for (int k = 0; k < NSC; k++) {
        float r = g * re[k] + noise * gauss();
        float q = g * im[k] + noise * gauss();
        if (r > 127.0f) r = 127.0f; if (r < -127.0f) r = -127.0f;
        if (q > 127.0f) q = 127.0f; if (q < -127.0f) q = -127.0f;
        buf[k * 2]     = (int8_t)lrintf(q);
        buf[k * 2 + 1] = (int8_t)lrintf(r);
    }
}

static float feed(CsiScorer &s, const float *re, const float *im, float noise, int n,
                  bool holdFloor, uint32_t dtUs) {
    int8_t buf[128];
    float a[CSI_NSUB];
    float last = 0.0f;
    for (int i = 0; i < n; i++) {
        makePacket(buf, re, im, noise);
        if (!csiAmplitudes(buf, a)) continue;
        if (s.update(a, holdFloor, dtUs)) last = s.score;
    }
    return last;
}

static float feedPeak(CsiScorer &s, const float *re, const float *im, float noise, int n,
                      bool holdFloor, uint32_t dtUs) {
    int8_t buf[128];
    float a[CSI_NSUB];
    float peak = 0.0f;
    for (int i = 0; i < n; i++) {
        makePacket(buf, re, im, noise);
        if (!csiAmplitudes(buf, a)) continue;
        if (s.update(a, holdFloor, dtUs) && s.score > peak) peak = s.score;
    }
    return peak;
}

static void feedChannel(CsiScorer &s, const Path *p, int np, float noise, int n,
                        uint32_t dtUs, bool holdFloor) {
    float re[NSC], im[NSC], a[CSI_NSUB];
    int8_t buf[128];
    double t = 0.0;
    for (int i = 0; i < n; i++) {
        t += (double)dtUs / 1e6;
        channelAt(p, np, (float)t, re, im);
        quantize(re, im, noise, buf);
        if (!csiAmplitudes(buf, a)) continue;
        s.update(a, holdFloor, dtUs);
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
static void addMover(Path *p, int &np, float fd) {
    p[np].amp = 0.45f; p[np].delay = 120e-9f; p[np].dopp = fd;
    p[np].phase = frand() * 6.2831853f; np++;
}

// a walking body is torso plus limbs, so it radiates a Doppler spread, not one tone
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

int main() {
    Path p[16]; int np;
    const uint32_t LAG = 33333;
    const float ETA = CSI_ACF_ETA;

    printf("== WiDetect null: static channel, noise only ==\n");
    printf("   paper: rho_hat ~ N(-1/T, 1/T); T=%u -> mean %.4f\n",
           CSI_ACF_T, -1.0f / (float)CSI_ACF_T);
    {
        mkStatic(p, np);
        static float win[CsiScorer::windowFloats()];
        CsiScorer s; s.attachWindow(win); s.reset();
        feedChannel(s, p, np, 2.0f, 6000, LAG, false);
        printf("   psi=%+.4f acf=%+.4f vote=%.2f pairs=%u\n", s.psi, s.acf, s.vote, s.acfPairs);
        assert(fabsf(s.psi) < ETA);
        assert(s.acfPairs > CSI_ACF_T);
    }

    printf("== motion: walking body, Doppler spread 1.5-11 Hz ==\n");
    {
        const float mag[4] = {1.0f, 0.6f, 0.35f, 0.2f};
        for (int i = 0; i < 4; i++) {
            mkStatic(p, np);
            addWalker(p, np, mag[i]);
            CsiScorer s; s.reset();
            feedChannel(s, p, np, 2.0f, 6000, LAG, false);
            printf("   scale=%.2f  acf=%+.4f vote=%.2f  %s\n",
                   mag[i], s.acf, s.vote, s.acf >= ETA ? "DETECT" : "miss");
            assert(s.acf > ETA);
        }
    }

    printf("== known blind spot: a single tone at 1/(4*tau) = %.1f Hz ==\n",
           1e6f / (4.0f * (float)LAG));
    {
        const float fds[3] = {3.0f, 5.0f, 7.5f};
        for (int i = 0; i < 3; i++) {
            mkStatic(p, np);
            addMover(p, np, fds[i]);
            CsiScorer s; s.reset();
            feedChannel(s, p, np, 2.0f, 6000, LAG, false);
            printf("   fD=%4.1f Hz  acf=%+.4f  theory cos(2*pi*fD*tau)=%+.4f\n",
                   fds[i], s.acf, cosf(6.2831853f * fds[i] * (float)LAG / 1e6f));
        }
    }

    printf("== lag buckets: dt classifies into lagBkt, no pair is rejected ==\n");
    {
        mkStatic(p, np);
        CsiScorer fast; fast.reset();
        feedChannel(fast, p, np, 2.0f, 2000, 10000, false);
        printf("   dt=10000us -> pairs=%u bkt0=%u\n", fast.acfPairs, fast.lagBkt[0]);
        assert(fast.acfPairs > 0);
        assert(fast.lagBkt[0] > 0);

        CsiScorer slow; slow.reset();
        feedChannel(slow, p, np, 2.0f, 2000, 4000000, false);
        printf("   dt=4000000us -> pairs=%u bkt4=%u\n", slow.acfPairs, slow.lagBkt[4]);
        assert(slow.acfPairs > 0);
        assert(slow.lagBkt[4] > 0);
    }

    printf("== holdFloor must actually freeze the floors ==\n");
    {
        mkStatic(p, np);
        CsiScorer base; base.reset();
        feedChannel(base, p, np, 2.0f, 3000, LAG, false);
        const float fBefore = base.acfFloor, mBefore = base.floorMad;

        mkStatic(p, np); addWalker(p, np, 1.0f);

        CsiScorer held = base;
        feedChannel(held, p, np, 2.0f, 3000, LAG, true);
        printf("   held: acfFloor %.4f -> %.4f   madfloor %.5f -> %.5f\n",
               fBefore, held.acfFloor, mBefore, held.floorMad);
        assert(held.acfFloor == fBefore);
        assert(held.floorMad == mBefore);

        CsiScorer freeRun = base;
        feedChannel(freeRun, p, np, 2.0f, 3000, LAG, false);
        printf("   free: acfFloor %.4f -> %.4f\n", fBefore, freeRun.acfFloor);
        assert(freeRun.acfFloor != fBefore);
    }

    printf("== separation at the operating threshold ==\n");
    {
        static float qwin[CsiScorer::windowFloats()];
        static float mwin[CsiScorer::windowFloats()];
        mkStatic(p, np);
        CsiScorer q; q.attachWindow(qwin); q.reset();
        feedChannel(q, p, np, 2.0f, 6000, LAG, false);

        mkStatic(p, np); addWalker(p, np, 1.0f);
        CsiScorer m; m.attachWindow(mwin); m.reset();
        feedChannel(m, p, np, 2.0f, 6000, LAG, false);

        printf("   quiet psi=%+.4f sig=%.4f   moving psi=%+.4f sig=%.4f   gate=%.3f\n",
               q.psi, q.sigVar, m.psi, m.sigVar, CSI_SIG_ETA);
        assert(q.psi < m.psi);
        assert(q.sigVar < CSI_SIG_ETA);
        assert(m.sigVar > CSI_SIG_ETA);
    }

    printf("== fixed-channel generator: AGC step must not read as motion ==\n");
    {
        float re[NSC], im[NSC], lo[NSC], loIm[NSC];
        for (int i = 0; i < NSC; i++) {
            re[i] = 30.0f + 20.0f * sinf(i * 0.31f);
            im[i] = 25.0f + 20.0f * cosf(i * 0.17f);
            lo[i] = re[i] * 0.35f;
            loIm[i] = im[i] * 0.35f;
        }
        static float awin[CsiScorer::windowFloats()];
        CsiScorer s; s.attachWindow(awin); s.reset();
        feed(s, re, im, 3.0f, 3000, false, LAG);
        const float quietSig = s.sigVar;
        feedPeak(s, lo, loIm, 1.0f, 200, false, LAG);
        printf("   quiet sig=%.4f  after 9dB gain step sig=%.4f  gate=%.3f\n",
               quietSig, s.sigVar, CSI_SIG_ETA);
        assert(s.sigVar < CSI_SIG_ETA);
    }

    printf("\nOK\n");
    return 0;
}
