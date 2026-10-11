#!/usr/bin/env python3
import argparse
import collections
import datetime
import json
import pathlib
import re
import time

MIN_EPOCH = 946684800
LOG_RE = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|[^\]]*)\]\s*(?:\[C:([^\]]*)\]\s*)?(.*)$")


def campaigns(sd):
    runs, open_ = [], {}
    path = sd / "campaigns.csv"
    if not path.exists():
        return runs
    for line in path.read_text(errors="replace").splitlines():
        p = line.strip().split(",")
        if len(p) < 3 or not p[1]:
            continue
        ev, name, epoch = p[0], p[1], int(p[2] or 0)
        if ev == "START":
            open_[name] = {"name": name, "from": epoch, "to": 0}
            runs.append(open_[name])
        elif ev == "STOP" and name in open_:
            open_.pop(name)["to"] = epoch
    return runs


def epoch_of(v):
    if isinstance(v, (int, float)) and v > MIN_EPOCH:
        return v
    if isinstance(v, str) and re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", v):
        return time.mktime(time.strptime(v[:19], "%Y-%m-%d %H:%M:%S"))
    return None


def row_span(row):
    lo = next((e for e in (epoch_of(row.get(k)) for k in ("first", "t", "timestamp", "epoch")) if e), None)
    hi = epoch_of(row.get("last")) or lo
    return (lo or hi, hi) if (lo or hi) else None


def group_of(row):
    return row.get("type") or row.get("vendor") or row.get("v") or row.get("src") or row.get("mac")


def rows(sd):
    log = sd / "antihunter.log"
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            m = LOG_RE.match(line)
            if m:
                msg = m.group(3)
                yield "antihunter.log", {"t": m.group(1), "_camp": m.group(2), "_grp": re.split(r"[\s:]", msg, maxsplit=1)[0]}
    for f in sorted(sd.glob("*.jsonl")):
        for line in f.read_text(errors="replace").splitlines():
            try:
                yield f.name, json.loads(line)
            except json.JSONDecodeError:
                continue


def report(sd, rng, tag):
    per = collections.defaultdict(lambda: {"n": 0, "lo": None, "hi": None, "macs": set(), "grp": collections.Counter()})
    for name, row in rows(sd):
        span = row_span(row)
        hit = (tag and row.get("_camp") == tag) or (rng is None) or (span and span[1] >= rng[0] and span[0] <= rng[1])
        if not hit:
            continue
        s = per[name]
        s["n"] += 1
        if span:
            s["lo"] = span[0] if s["lo"] is None else min(s["lo"], span[0])
            s["hi"] = span[1] if s["hi"] is None else max(s["hi"], span[1])
        mac = row.get("mac") or row.get("src")
        if mac:
            s["macs"].add(mac)
        g = row.get("_grp") or group_of(row)
        if g:
            s["grp"][str(g)] += 1
    return per


def fmt(e):
    return datetime.datetime.fromtimestamp(e).strftime("%Y-%m-%d %H:%M:%S") if e else "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sd", type=pathlib.Path)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--campaign")
    ap.add_argument("--from", dest="frm")
    ap.add_argument("--to")
    a = ap.parse_args()
    runs = campaigns(a.sd)
    if a.list:
        for r in runs:
            print(f"{r['name']:<24} {fmt(r['from'])} -> {fmt(r['to']) if r['to'] else 'active'}")
        return
    rng, tag = None, None
    if a.campaign:
        hits = [r for r in runs if r["name"] == a.campaign]
        if not hits:
            raise SystemExit(f"no campaign named {a.campaign} in campaigns.csv")
        rng = (min(r["from"] for r in hits), max((r["to"] or time.time()) for r in hits))
        tag = a.campaign
    elif a.frm or a.to:
        rng = (epoch_of(a.frm) or 0 if a.frm else 0, epoch_of(a.to) if a.to else time.time())
    total = 0
    for name, s in sorted(report(a.sd, rng, tag).items()):
        total += s["n"]
        top = ", ".join(f"{k} {v}" for k, v in s["grp"].most_common(5))
        print(f"{name:<22} rows={s['n']:<6} {fmt(s['lo'])} -> {fmt(s['hi'])}  macs={len(s['macs'])}  top: {top}")
    print(f"total rows={total}")


def _selfcheck():
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    t0 = 1791580000
    (d / "campaigns.csv").write_text(f"START,op1,{t0},10\nSTOP,op1,{t0 + 100},110\n")
    (d / "deauth.jsonl").write_text(json.dumps({"t": t0 + 50, "src": "AA"}) + "\n" + json.dumps({"t": t0 + 500, "src": "BB"}) + "\n")
    (d / "antihunter.log").write_text("[00:01:00] [C:op1] CAMPAIGN START op1\n[00:02:00] other\n")
    per = report(d, (t0, t0 + 100), "op1")
    assert per["deauth.jsonl"]["n"] == 1 and per["deauth.jsonl"]["macs"] == {"AA"}, per
    assert per["antihunter.log"]["n"] == 1, per
    assert campaigns(d) == [{"name": "op1", "from": t0, "to": t0 + 100}]


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--selfcheck"]:
        _selfcheck()
        print("SELFCHECK_PASS")
    else:
        main()
