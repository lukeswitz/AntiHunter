#!/usr/bin/env python3
"""Audit AntiHunter CSI serial logs.

Reads whole logs, not tails. Handles multi-day rollover. Segments into
configuration epochs (boot / channel lock / trigger change) so no statistic
is ever computed across a config change. Cross-references an operator marks
file so occupancy labels come from the record, not from memory.

  csi_audit.py LOG [LOG ...] [--marks FILE] [--epochs] [--window HH:MM-HH:MM]
"""
import re, sys, os, argparse, statistics as st

TS = re.compile(r'^(\d\d):(\d\d):(\d\d) ')

def load(path):
    """Return [(abs_sec, line)] with day rollover resolved."""
    base = 0; prev = None; out = []
    with open(path, errors='replace') as fh:
        for line in fh:
            m = TS.match(line)
            if not m:
                continue
            t = int(m.group(1))*3600 + int(m.group(2))*60 + int(m.group(3))
            if prev is not None and t < prev - 3600:
                base += 86400
            prev = t
            out.append((base + t, line.rstrip('\n')))
    return out

def hhmm(s):
    return "%02d:%02d" % (s // 3600 % 24, s // 60 % 60)

def dayof(s):
    return s // 86400

class Epoch:
    def __init__(self, start, channel=None, trigger=None, reason=""):
        self.start = start; self.end = start
        self.channel = channel; self.trigger = trigger; self.reason = reason
        self.state = []      # (t, word, movingLinks, armed)
        self.area = []       # (t, 1|0)
        self.sig = []
        self.records = []    # (t, cumulative records)
        self.flat = 0
        self.boots = 0

def epochs(rows):
    """Split on boot, channel lock, or an acked trigger change."""
    eps = []
    cur = Epoch(rows[0][0], reason="log start")
    ch = trig = None
    for t, l in rows:
        newep = None
        if 'rst:0x' in l:
            newep = ("boot", ch, trig)
        m = re.search(r'Radio locked to ch(\d+)', l)
        if m:
            ch = int(m.group(1)); newep = ("ch%d" % ch, ch, trig)
        # only the board's OWN ack counts; mesh relays another node's ack verbatim
        m = re.search(r'\[MESH TX\] \w+: CSI_CFG_ACK:T=([0-9.]+)', l)
        if m:
            trig = float(m.group(1)); newep = ("trigger=%.3f" % trig, ch, trig)
        if re.search(r'\[MESH TX\] \w+: CSI_RECAL_ACK', l):
            trig = None; newep = ("recal", ch, None)
        if newep:
            cur.end = t
            if cur.state or cur.area:
                eps.append(cur)
            cur = Epoch(t, channel=newep[1], trigger=newep[2], reason=newep[0])
            continue

        cur.end = t
        if 'rst:0x' in l:
            cur.boots += 1
        m = re.search(r'\[CSI\] STATE (\w+) .*links=(\d+)', l)
        if m:
            a = re.search(r'armed=(\d+)', l)
            cur.state.append((t, m.group(1), int(m.group(2)),
                              int(a.group(1)) if a else -1))
        if '[CSI] AREA MOTION' in l: cur.area.append((t, 1))
        elif '[CSI] AREA CLEAR' in l: cur.area.append((t, 0))
        m = re.search(r'sig=([0-9.]+)', l)
        if m:
            v = float(m.group(1))
            if v > 0: cur.sig.append(v)
        m = re.search(r'records=(\d+)', l)
        if m: cur.records.append((t, int(m.group(1))))
        if 'DROP' in l and 'flat' in l: cur.flat += 1
    if cur.state or cur.area:
        eps.append(cur)
    return eps

def duty(area, lo, hi):
    """Fraction of [lo,hi] in MOTION, carrying state in from before lo."""
    if hi <= lo: return 0.0
    cur = 0
    for t, v in area:
        if t <= lo: cur = v
        else: break
    mot = 0; prev = lo
    for t, v in area:
        if t <= lo or t > hi: continue
        if cur: mot += t - prev
        prev = t; cur = v
    if cur: mot += hi - prev
    return 100.0 * mot / (hi - lo)

def rate(records, lo, hi):
    sel = [(t, r) for t, r in records if lo <= t <= hi]
    if len(sel) < 2: return 0.0
    span = sel[-1][0] - sel[0][0]
    return (sel[-1][1] - sel[0][1]) / span if span else 0.0

def marks(path):
    out = []
    if not path or not os.path.exists(path): return out
    for line in open(path, errors='replace'):
        m = re.match(r'^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) (.*)', line)
        if m:
            out.append((int(m.group(4))*3600+int(m.group(5))*60+int(m.group(6)),
                        m.group(3), m.group(7).strip()))
    return out

def report(path, args):
    rows = load(path)
    if not rows:
        print("%s: no timestamped lines" % path); return
    name = os.path.basename(path)
    span = (rows[-1][0] - rows[0][0]) / 3600.0
    print("=" * 78)
    print("%s   %d lines   %.1f h   %s -> %s" %
          (name, len(rows), span, hhmm(rows[0][0]), hhmm(rows[-1][0])))
    eps = epochs(rows)
    print("%d configuration epochs" % len(eps))
    print("-" * 78)
    print("%-6s %-6s %-9s %5s %6s %6s %6s %7s %7s %6s" %
          ("start", "dur_h", "cfg", "ch", "trig", "armed", "AREA", "AREA/h", "rec/s", "blind%"))
    for e in eps:
        dur = (e.end - e.start) / 3600.0
        if dur < args.min_hours: continue
        armed = [a for _, _, _, a in e.state if a >= 0]
        blind = [w for _, w, _, _ in e.state if w == 'BLIND']
        n_area = sum(1 for _, v in e.area if v == 1)
        print("%-6s %-6.2f %-9s %5s %6s %6.1f %6d %7.1f %7.1f %6.0f" % (
            hhmm(e.start), dur, e.reason[:9],
            e.channel if e.channel else "-",
            ("%.3f" % e.trigger) if e.trigger else "-",
            st.mean(armed) if armed else 0,
            n_area, n_area / dur if dur else 0,
            rate(e.records, e.start, e.end),
            100.0 * len(blind) / len(e.state) if e.state else 0))
    if args.sig:
        print("-" * 78)
        for e in eps:
            if len(e.sig) < 20: continue
            s = sorted(e.sig)
            print("  %s  sig n=%4d  p50=%.4f p95=%.4f p99=%.4f max=%.4f" % (
                hhmm(e.start), len(s), s[len(s)//2], s[int(len(s)*.95)],
                s[int(len(s)*.99)], s[-1]))
    M = marks(args.marks)
    if M:
        print("-" * 78)
        print("operator marks:")
        for t, day, txt in M:
            print("  %s  %s" % (hhmm(t), txt[:88]))

ap = argparse.ArgumentParser()
ap.add_argument("logs", nargs="+")
ap.add_argument("--marks", default=os.path.expanduser("~/Desktop/csi_marks.txt"))
ap.add_argument("--sig", action="store_true", help="per-epoch sigVar percentiles")
ap.add_argument("--min-hours", type=float, default=0.05)
args = ap.parse_args()
for p in args.logs:
    report(p, args)
