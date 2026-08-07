#!/usr/bin/env python3
"""Generate src/oui_table.h for both firmware trees from the IEEE MA-L registry.

Usage:
    python3 scripts/gen_oui_table.py [oui.csv]

Downloads https://standards-oui.ieee.org/oui/oui.csv when no path is given.
Emits a sorted OUI -> vendor-name table for binary search by lookupOuiVendor().
TOP_ORGS caps the table at the N organisations holding the most OUI blocks; _ALWAYS
names orgs that are kept regardless of block count. NAME_MAX must stay under the
vendor field width in scanner.h (char vendor[24]).
"""

import collections
import csv
import io
import re
import sys
import urllib.request

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT_PATHS = [
    "Antihunter/full/src/oui_table.h",
    "Antihunter/headless/src/oui_table.h",
]
NAME_MAX = 20
TOP_ORGS = 400

_SUFFIX = re.compile(
    r"\s*(,|\s)\s*("
    r"co\.?,?\s*ltd\.?|company\s+limited|ltd\.?|limited|inc\.?|incorporated|"
    r"corp\.?|corporate|corporation|gmbh|s\.?a\.?s?\.?|b\.?v\.?|a/s|oy|ab|plc|"
    r"llc|l\.?p\.?|pte\.?|pvt\.?|s\.?r\.?l\.?|kg|ag|nv|co\.?"
    r")\.?\s*$",
    re.I,
)

_GENERIC = re.compile(
    r"\s*("
    r"technolog(y|ies)|technical|electronics?|electric(al)?|communications?|"
    r"networks?|networking|systems?|international|industr(y|ies|ial)|digital|"
    r"information|equipment|manufactur\w*|holdings?|group|solutions?|devices?|"
    r"products?|precision|research|development|enterprises?|america|usa|global"
    r")\s*$",
    re.I,
)


_ALWAYS = re.compile(
    r"^("
    r"flock|axon|verkada|ring|nest|wyze|arlo|axis|ubiquiti|skydio|dji|sz dji|"
    r"parrot|shotspotter|genetec|avigilon|bosch|hanwha|vivotek|amcrest|reolink|"
    r"cellebrite|hikvision|dahua|tesla|motorola|garmin|tile|life360|"
    r"raspberry|microsoft|sonos|roku|bose|fitbit|nintendo|valve|ecobee|irobot|"
    r"chamberlain|belkin|wemo|august|yale|schlage|logitech|gopro|anker|itead|"
    r"shelly|particle|adafruit|sparkfun|pine64|nordic|dialog|realtek|broadcom|"
    r"marvell|mediatek|qualcomm|atheros|ralink|sierra|u-blox|ublox|telit|"
    r"quectel|espressif|silicon lab|texas instrument|nxp|st microelectronics|"
    r"stmicro|infineon|cypress|microchip|renesas|amazon|google|apple|samsung|"
    r"intel|sony|lg elec|panasonic|sharp|toshiba|hitachi|canon|nikon|epson|"
    r"brother|lexmark|xerox|dell|lenovo|asus|acer|msi|gigabyte|razer|"
    r"netgear|linksys|d-link|tp-link|zyxel|aruba|ruckus|meraki|mikrotik|"
    r"synology|qnap|western digital|seagate|hp inc|hewlett|honeywell|ecovacs|"
    r"roborock|xiaomi|oneplus|oppo|vivo|realme|nothing|fairphone|"
    r"pixart|texas|segway|ninebot|vanmoof|rad power|bird|lime"
    r")\b",
    re.I,
)


def normalize(name):
    n = name.strip().strip('"')
    prev = None
    while prev != n:
        prev = n
        n = _SUFFIX.sub("", n).strip().rstrip(",&").strip()
        n = _GENERIC.sub("", n).strip().rstrip(",&").strip()
    if not n:
        n = name.strip()
    n = re.sub(r"[^\x20-\x7e]", " ", n)
    return re.sub(r"\s+", " ", n).strip()


def truncate(n):
    if len(n) <= NAME_MAX:
        return n
    cut = n[:NAME_MAX]
    if " " in cut and not n[NAME_MAX].isspace():
        head = cut.rsplit(" ", 1)[0]
        if len(head) * 2 >= NAME_MAX:
            return head
    return cut.rstrip()


def load(path):
    if path:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            return list(csv.DictReader(f))
    with urllib.request.urlopen(OUI_CSV_URL, timeout=180) as r:
        text = r.read().decode("utf-8", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def main():
    rows = load(sys.argv[1] if len(sys.argv) > 1 else None)

    recs = {}
    for r in rows:
        assign = (r.get("Assignment") or "").strip().upper()
        if not re.fullmatch(r"[0-9A-F]{6}", assign):
            continue
        name = truncate(normalize(r.get("Organization Name") or ""))
        if not name:
            continue
        recs[int(assign, 16)] = name

    if TOP_ORGS:
        counts = collections.Counter(recs.values())
        keep = {n for n, _ in counts.most_common(TOP_ORGS)}
        keep |= {n for n in recs.values() if _ALWAYS.search(n)}
        recs = {o: n for o, n in recs.items() if n in keep}

    names = sorted(set(recs.values()))
    if len(names) > 0xFFFF:
        sys.exit("name pool exceeds uint16 index range")
    idx = {n: i for i, n in enumerate(names)}

    ouis = sorted(recs)
    pool = sum(len(n) + 1 for n in names)

    out = io.StringIO()
    out.write("#pragma once\n\n")
    out.write("#include <stdint.h>\n\n")
    out.write("struct OuiEntry {\n")
    out.write("    uint8_t oui[3];\n")
    out.write("    uint16_t nameIdx;\n")
    out.write("} __attribute__((packed));\n\n")

    out.write("static const char *const OUI_NAMES[] = {\n")
    for n in names:
        out.write('    "%s",\n' % n.replace("\\", "\\\\").replace('"', '\\"'))
    out.write("};\n\n")

    out.write("static const OuiEntry OUI_TABLE[] = {\n")
    for o in ouis:
        out.write(
            "    {{0x%02X,0x%02X,0x%02X},%u},\n"
            % ((o >> 16) & 0xFF, (o >> 8) & 0xFF, o & 0xFF, idx[recs[o]])
        )
    out.write("};\n\n")
    out.write("static const uint32_t OUI_TABLE_SIZE = %u;\n" % len(ouis))

    for path in OUT_PATHS:
        with open(path, "w", encoding="ascii") as f:
            f.write(out.getvalue())

    print(
        "%u OUIs, %u names, %u B pool, ~%u B flash -> %s"
        % (
            len(ouis),
            len(names),
            pool,
            len(ouis) * 5 + pool + len(names) * 4,
            ", ".join(OUT_PATHS),
        )
    )


if __name__ == "__main__":
    main()
