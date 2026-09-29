#!/usr/bin/env python3
"""Generate src/sig_catalog.h from a Fieldwatch signature export (MIT, Off Grid Pete LLC).

Usage:
    python3 scripts/gen_sig_catalog.py <fieldwatch-signatures-v2.json> [out.h]

Writes to stdout when no output path is given.
Fleets of kind ISP are dropped (router OUIs; V= vendor lookup already names them).
Fleets are ordered by KIND_RANK so the matcher's first hit is the most relevant class.
Rule kinds the firmware cannot evaluate are counted on stderr and skipped:
VENDOR_IE_OUI (list scans do not keep Wi-Fi IEs) and SERVICE_UUID values that are
neither 16-bit nor 128-bit.
"""

import collections
import json
import re
import sys

DROP_KINDS = {"ISP"}
KIND_RANK = [
    "HACKING", "SURVEILLANCE", "LAW_ENFORCEMENT", "DRONE", "CAMERA", "FINDER",
    "GLASSES", "VEHICLE", "LOCK", "WEARABLE", "AUDIO", "PHONE", "HEALTH", "HOME",
    "THERMOSTAT", "MESH", "SIGNAGE", "BEACON",
]
ORDER_BEFORE = {"fleet-osmo": "fleet-dji"}
RADIO = {None: 0, "WIFI": 1, "BLE": 2}
NAME_MAX = 24
MFG_PREFIX_MAX = 18
SVC_PREFIX_MAX = 12


def hex_only(s):
    return re.sub(r"[^0-9A-Fa-f]", "", s).upper()


def c_str(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def c_bytes(b, width):
    if len(b) > width:
        raise ValueError("%d bytes exceed field width %d" % (len(b), width))
    return "{" + (",".join("0x%02X" % x for x in b) if b else "0") + "}"


def order_fleets(fleets):
    rank = {k: i for i, k in enumerate(KIND_RANK)}
    fleets = sorted(
        (f for f in fleets if f["kind"] not in DROP_KINDS and f.get("enabled", True)),
        key=lambda f: rank.get(f["kind"], len(KIND_RANK)),
    )
    for first, second in ORDER_BEFORE.items():
        ids = [f["id"] for f in fleets]
        if first in ids and second in ids and ids.index(first) > ids.index(second):
            f = fleets.pop(ids.index(first))
            fleets.insert(ids.index(second), f)
    return fleets


def build(src):
    data = json.load(open(src, encoding="utf-8"))
    fleets = order_fleets(data["fleets"])
    kinds = []
    for f in fleets:
        if f["kind"] not in kinds:
            kinds.append(f["kind"])

    ouis, macp, names, u16, u128, mfg, svc = [], [], [], [], [], [], []
    skipped = collections.Counter()
    for idx, f in enumerate(fleets):
        if not f.get("matchAny", True):
            skipped["matchAll-fleet"] += 1
        if f.get("minPeers", 0) > 0 or f.get("clusterByOui") or f.get("sequentialMac"):
            skipped["cluster-fleet"] += 1
        for r in f["rules"]:
            if not r.get("enabled", True):
                continue
            k, radio = r["kind"], RADIO[r.get("radio")]
            h = hex_only(r["text"])
            if k == "OUI" and len(h) == 6:
                ouis.append((bytes.fromhex(h), radio, idx))
            elif k in ("OUI", "MAC_PREFIX") and 6 <= len(h) <= 12 and len(h) % 2 == 0:
                macp.append((bytes.fromhex(h), radio, idx))
            elif k in ("NAME_CONTAINS", "NAME_GLOB") and r["text"].strip():
                names.append((idx, radio, 1 if k == "NAME_GLOB" else 0, r["text"]))
            elif k == "SERVICE_UUID" and len(h) == 4:
                u16.append((int(h, 16), radio, idx))
            elif k == "SERVICE_UUID" and len(h) == 32:
                u128.append((bytes.fromhex(h)[::-1], radio, idx))
            elif k == "MANUFACTURER_ID":
                mfg.append((r["companyId"], b"", radio, idx))
            elif k == "MANUFACTURER_DATA" and hex_only(r["dataPrefixHex"]):
                p = bytes.fromhex(hex_only(r["dataPrefixHex"]))
                if len(p) > MFG_PREFIX_MAX:
                    skipped["mfg-prefix-too-long"] += 1
                    continue
                mfg.append((r["companyId"], p, radio, idx))
            elif k == "SERVICE_DATA":
                p = bytes.fromhex(hex_only(r["dataPrefixHex"])) if hex_only(r["dataPrefixHex"]) else b""
                if len(p) > SVC_PREFIX_MAX:
                    skipped["svc-prefix-too-long"] += 1
                    continue
                uu = int(h, 16) if len(h) == 4 else 0
                if len(h) not in (0, 4):
                    skipped["svc-uuid-not-16bit"] += 1
                    continue
                contains = 1 if (not r["text"].strip() and p) else 0
                svc.append((uu, contains, p, radio, idx))
            else:
                skipped[k + ("" if k != "SERVICE_UUID" else "-len%d" % len(h))] += 1
    ouis.sort(key=lambda t: (t[0], t[2]))
    return data, fleets, kinds, ouis, macp, names, u16, u128, mfg, svc, skipped


def emit(src, out):
    data, fleets, kinds, ouis, macp, names, u16, u128, mfg, svc, skipped = build(src)
    w = out.write
    w("#pragma once\n\n")
    w("// Fieldwatch catalogVersion %s (c) 2026 Off Grid Pete LLC, MIT License. https://github.com/OffGridPete/Fieldwatch\n\n" % data.get("catalogVersion"))
    w("#include <stdint.h>\n\n")
    w("struct SigFleet { const char *id; const char *name; uint8_t kind; };\n")
    w("struct SigOui { uint8_t oui[3]; uint8_t radio; uint16_t fleet; };\n")
    w("struct SigMacPrefix { uint8_t mac[6]; uint8_t len; uint8_t radio; uint16_t fleet; };\n")
    w("struct SigName { uint16_t fleet; uint8_t radio; uint8_t glob; const char *pat; };\n")
    w("struct SigUuid16 { uint16_t uuid; uint8_t radio; uint16_t fleet; };\n")
    w("struct SigUuid128 { uint8_t uuid[16]; uint8_t radio; uint16_t fleet; };\n")
    w("struct SigMfg { uint16_t company; uint8_t len; uint8_t radio; uint16_t fleet; uint8_t prefix[%d]; };\n" % MFG_PREFIX_MAX)
    w("struct SigSvcData { uint16_t uuid; uint8_t contains; uint8_t len; uint8_t radio; uint16_t fleet; uint8_t prefix[%d]; };\n\n" % SVC_PREFIX_MAX)

    w("static const char *const SIG_KINDS[] = {\n")
    for k in kinds:
        w("    %s,\n" % c_str(k))
    w("};\n\n")

    w("static const SigFleet SIG_FLEETS[] = {\n")
    for f in fleets:
        nm = re.sub(r"\s+", "_", f["name"].strip())[:NAME_MAX]
        w("    {%s, %s, %d},\n" % (c_str(f["id"]), c_str(nm), kinds.index(f["kind"])))
    w("};\n")
    w("static const uint16_t SIG_FLEET_COUNT = %d;\n\n" % len(fleets))

    def table(ctype, name, rows, fmt):
        w("static const %s %s[] = {\n" % (ctype, name))
        for r in rows:
            w("    %s,\n" % fmt(r))
        if not rows:
            w("    {},\n")
        w("};\n")
        w("static const uint16_t %s_COUNT = %d;\n\n" % (name, len(rows)))

    table("SigOui", "SIG_OUI", ouis, lambda r: "{%s, %d, %d}" % (c_bytes(r[0], 3), r[1], r[2]))
    table("SigMacPrefix", "SIG_MACP", macp, lambda r: "{%s, %d, %d, %d}" % (c_bytes(r[0], 6), len(r[0]), r[1], r[2]))
    table("SigName", "SIG_NAME", names, lambda r: "{%d, %d, %d, %s}" % (r[0], r[1], r[2], c_str(r[3])))
    table("SigUuid16", "SIG_UUID16", u16, lambda r: "{0x%04X, %d, %d}" % (r[0], r[1], r[2]))
    table("SigUuid128", "SIG_UUID128", u128, lambda r: "{%s, %d, %d}" % (c_bytes(r[0], 16), r[1], r[2]))
    table("SigMfg", "SIG_MFG", mfg, lambda r: "{0x%04X, %d, %d, %d, %s}" % (r[0], len(r[1]), r[2], r[3], c_bytes(r[1], MFG_PREFIX_MAX)))
    table("SigSvcData", "SIG_SVC", svc, lambda r: "{0x%04X, %d, %d, %d, %d, %s}" % (r[0], r[1], len(r[2]), r[3], r[4], c_bytes(r[2], SVC_PREFIX_MAX)))

    sys.stderr.write("fleets=%d oui=%d macp=%d name=%d uuid16=%d uuid128=%d mfg=%d svc=%d\n" % (
        len(fleets), len(ouis), len(macp), len(names), len(u16), len(u128), len(mfg), len(svc)))
    sys.stderr.write("skipped=%s\n" % dict(skipped))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as out:
            emit(sys.argv[1], out)
    else:
        emit(sys.argv[1], sys.stdout)


if __name__ == "__main__":
    main()
