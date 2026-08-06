#!/usr/bin/env python3

import argparse
import re
import shutil
import subprocess
import sys
import time

try:
    from serial.tools import list_ports
except ImportError:
    print("ERROR: pyserial not installed.  pip install pyserial")
    sys.exit(1)

MESH_VIDPID = {(0x10C4, 0xEA60), (0x1A86, 0x55D4), (0x1A86, 0x7523)}
MESH_PINS = {"heltec-v3": (19, 20), "t114": (10, 9)}

FIELDS = (
    ("screen", r'"screenOnSecs":\s*(\d+)', "display.screen_on_secs", "s"),
    ("carousel", r'"autoScreenCarouselSecs":\s*(\d+)', "display.auto_screen_carousel_secs", "s"),
    ("wake on move", r'"wakeOnTapOrMotion":\s*(\w+)', "display.wake_on_tap_or_motion", ""),
    ("led heartbeat", r'"ledHeartbeatDisabled":\s*(\w+)', "device.led_heartbeat_disabled", ""),
    ("bluetooth", r'"bluetooth":\s*{[^}]*?"enabled":\s*(\w+)', "bluetooth.enabled", ""),
    ("ble mode", r'"mode":\s*"(RANDOM_PIN|FIXED_PIN|NO_PIN)"', "bluetooth.mode", ""),
    ("ble pin", r'"fixedPin":\s*(\d+)', "bluetooth.fixed_pin", ""),
    ("serial module", r'"serial":\s*{[^}]*?"enabled":\s*(\w+)', "serial.enabled", ""),
    ("serial mode", r'"mode":\s*"(TEXTMSG|PROTO|SIMPLE|NMEA|CALTOPO|WS85|VE_DIRECT)"', "serial.mode", ""),
    ("serial baud", r'"baud":\s*"?(BAUD_\d+)"?', "serial.baud", ""),
    ("serial rx", r'"rxd":\s*(\d+)', "serial.rxd", ""),
    ("serial tx", r'"txd":\s*(\d+)', "serial.txd", ""),
    ("region", r'"region":\s*"?(\w+)"?', "lora.region", ""),
)


def check_deps():
    missing = []
    if not shutil.which("meshtastic"):
        missing.append(("meshtastic CLI", "pip3 install --upgrade 'meshtastic[cli]'"))
    try:
        __import__("serial")
    except ImportError:
        missing.append(("pyserial", "pip3 install --upgrade pyserial"))
    if missing:
        print("Missing prerequisites:\n")
        for what, how in missing:
            print(f"  {what:<16} {how}")
        print("")
        sys.exit(1)

    p = subprocess.run(["meshtastic", "--version"], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        print("meshtastic CLI will not run:\n" + ((p.stdout or "") + (p.stderr or ""))[-300:])
        sys.exit(1)
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", (p.stdout or "") + (p.stderr or ""))
    if not m:
        print("could not read the meshtastic version — continuing")
        return
    ver = tuple(int(x) for x in m.groups())
    print(f"meshtastic {'.'.join(map(str, ver))}")
    if ver < (2, 7, 5):
        print("That version crashes on --set with current protobuf ('FieldDescriptor' has no")
        print("attribute 'label').  Upgrade first:  pip3 install --upgrade 'meshtastic[cli]'")
        sys.exit(1)


def die(msg):
    print("ERROR: " + msg)
    sys.exit(1)


def find_radio():
    hits = [p.device for p in list_ports.comports()
            if (p.vid, p.pid) in MESH_VIDPID and "SLAB" not in p.device]
    if not hits:
        die("no Meshtastic radio found on USB (CP2102 / CH340 / CH9102)")
    if len(hits) > 1:
        print("Radios found:")
        for i, h in enumerate(hits):
            print(f"  {i + 1}. {h}")
        v = input("Which one [1]: ").strip() or "1"
        return hits[(int(v) - 1) if v.isdigit() and 0 < int(v) <= len(hits) else 0]
    return hits[0]


def mesh(port, args, timeout=300):
    cmd = ["meshtastic", "--port", port] + args
    print("$ " + " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def read_config(port, tries=3):
    for attempt in range(tries):
        rc, out = mesh(port, ["--info"], timeout=180)
        if rc == 0:
            return out
        if attempt < tries - 1:
            print("  radio not answering yet, retrying...")
            # poll: the serial API only answers once the radio has booted
            time.sleep(3)
    die("radio never answered --info")


def snapshot(info):
    out = {}
    for label, pattern, _, unit in FIELDS:
        m = re.search(pattern, info)
        out[label] = (m.group(1) + unit) if m else "-"
    return out


def show(before, after=None):
    width = max(len(k) for k in before)
    print("\n" + "-" * (width + 30))
    if after:
        print(f"{'setting':<{width}}  {'before':<12}  after")
        print("-" * (width + 30))
        for k in before:
            mark = " " if before[k] == after[k] else "*"
            print(f"{k:<{width}}  {before[k]:<12}  {after[k]} {mark}")
    else:
        print(f"{'setting':<{width}}  value")
        print("-" * (width + 30))
        for k, v in before.items():
            print(f"{k:<{width}}  {v}")
    print("-" * (width + 30))


def build(args):
    sets = []
    if args.screen is not None:
        secs = "0" if args.screen == "on" else "1" if args.screen == "off" else args.screen
        if not secs.isdigit():
            die("--screen takes on, off, or a number of seconds")
        sets += ["--set", "display.screen_on_secs", secs,
                 "--set", "display.auto_screen_carousel_secs", "0",
                 "--set", "display.wake_on_tap_or_motion", "false" if args.screen == "off" else "true"]
    if args.led is not None:
        sets += ["--set", "device.led_heartbeat_disabled", "true" if args.led == "off" else "false"]
    if args.ble is not None:
        sets += ["--set", "bluetooth.enabled", "true" if args.ble == "on" else "false"]
    if args.pin is not None:
        if args.pin == "none":
            sets += ["--set", "bluetooth.enabled", "true", "--set", "bluetooth.mode", "NO_PIN"]
        elif args.pin == "random":
            sets += ["--set", "bluetooth.enabled", "true", "--set", "bluetooth.mode", "RANDOM_PIN"]
        elif args.pin.isdigit() and len(args.pin) == 6:
            sets += ["--set", "bluetooth.enabled", "true",
                     "--set", "bluetooth.mode", "FIXED_PIN",
                     "--set", "bluetooth.fixed_pin", args.pin]
        else:
            die("--pin takes 6 digits, 'none', or 'random'")
    if args.serial is not None:
        if args.serial == "off":
            sets += ["--set", "serial.enabled", "false"]
        else:
            rx, tx = MESH_PINS[args.board]
            sets += ["--set", "serial.enabled", "true",
                     "--set", "serial.mode", "TEXTMSG",
                     "--set", "serial.baud", "BAUD_115200",
                     "--set", "serial.rxd", str(rx),
                     "--set", "serial.txd", str(tx)]
    if args.region is not None:
        sets += ["--set", "lora.region", args.region.upper()]
    return sets


def ask(prompt, default=None):
    try:
        v = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    except EOFError:
        v = ""
    return v or (default or "")


def human(cur):
    led = cur.get("led heartbeat")
    ble_mode = cur.get("ble mode", "-")
    pin = cur.get("ble pin", "-")
    return {
        "screen": f"blanks after {cur.get('screen', '-')}" if cur.get("screen") not in ("0s", "-")
                  else ("always on" if cur.get("screen") == "0s" else "-"),
        "led": "off" if led == "true" else "on" if led == "false" else "-",
        "ble": "on" if cur.get("bluetooth") == "true" else "off" if cur.get("bluetooth") == "false" else "-",
        "pair": ("no pin" if ble_mode == "NO_PIN" else
                 f"fixed pin {pin}" if ble_mode == "FIXED_PIN" else
                 "random pin (shown on screen)" if ble_mode == "RANDOM_PIN" else "-"),
        "serial": (f"{cur.get('serial mode', '?')} "
                   f"{cur.get('serial baud', '?').replace('BAUD_', '')} "
                   f"rx={cur.get('serial rx', '?')} tx={cur.get('serial tx', '?')}")
                  if cur.get("serial module") == "true" else "off",
        "region": cur.get("region", "-"),
    }


def menu(cur, board):
    now, pending = human(cur), []

    def choose(title, options, current):
        print(f"\n{title}   (now: {current})")
        for i, (label, _) in enumerate(options):
            print(f"  {i + 1}. {label}")
        print("  0. leave it alone")
        v = ask("Choice", "0")
        if not v.isdigit() or not 0 < int(v) <= len(options):
            return None
        return options[int(v) - 1][1]

    while True:
        print("\n" + "=" * 52)
        print("  1. Screen          " + now["screen"])
        print("  2. Status LED      " + now["led"])
        print("  3. Bluetooth       " + now["ble"])
        print("  4. BLE pairing     " + now["pair"])
        print("  5. Serial module   " + now["serial"])
        print("  6. LoRa region     " + now["region"])
        print("=" * 52)
        if pending:
            print("  pending: " + "; ".join(p[0] for p in pending))
        print("  a. apply    q. quit without applying")
        pickv = ask("Pick", "a").lower()

        if pickv == "q":
            return []
        if pickv == "a":
            return [arg for _, args in pending for arg in args]

        if pickv == "1":
            v = choose("Screen", [("off — blank after 1s", ["--set", "display.screen_on_secs", "1",
                                                            "--set", "display.wake_on_tap_or_motion", "false"]),
                                  ("on — stay lit", ["--set", "display.screen_on_secs", "0",
                                                     "--set", "display.wake_on_tap_or_motion", "true"]),
                                  ("timeout in seconds", "ASK")], now["screen"])
            if v == "ASK":
                secs = ask("Seconds", "30")
                v = ["--set", "display.screen_on_secs", secs if secs.isdigit() else "30"]
            if v:
                pending.append((f"screen {'off' if v[2] == '1' else 'on' if v[2] == '0' else v[2] + 's'}", v))
        elif pickv == "2":
            v = choose("Status LED", [("off", ["--set", "device.led_heartbeat_disabled", "true"]),
                                      ("on", ["--set", "device.led_heartbeat_disabled", "false"])], now["led"])
            if v:
                pending.append((f"led {'off' if v[2] == 'true' else 'on'}", v))
        elif pickv == "3":
            v = choose("Bluetooth", [("on", ["--set", "bluetooth.enabled", "true"]),
                                     ("off", ["--set", "bluetooth.enabled", "false"])], now["ble"])
            if v:
                pending.append((f"bluetooth {v[2]}", v))
        elif pickv == "4":
            v = choose("BLE pairing", [("fixed pin", "ASK"),
                                       ("no pin at all", ["--set", "bluetooth.enabled", "true",
                                                          "--set", "bluetooth.mode", "NO_PIN"]),
                                       ("random pin (needs a readable screen)",
                                        ["--set", "bluetooth.enabled", "true",
                                         "--set", "bluetooth.mode", "RANDOM_PIN"])], now["pair"])
            if v == "ASK":
                pin = ask("Six digits", "123456")
                if not (pin.isdigit() and len(pin) == 6):
                    print("  needs to be exactly 6 digits — skipped")
                    continue
                v = ["--set", "bluetooth.enabled", "true", "--set", "bluetooth.mode", "FIXED_PIN",
                     "--set", "bluetooth.fixed_pin", pin]
                pending.append((f"ble pin {pin}", v))
            elif v:
                pending.append(("ble " + v[-1].lower().replace("_", " "), v))
        elif pickv == "5":
            rx, tx = MESH_PINS[board]
            v = choose(f"Serial module ({board}: rx={rx} tx={tx})",
                       [("on — AntiHunter TEXTMSG 115200",
                         ["--set", "serial.enabled", "true", "--set", "serial.mode", "TEXTMSG",
                          "--set", "serial.baud", "BAUD_115200",
                          "--set", "serial.rxd", str(rx), "--set", "serial.txd", str(tx)]),
                        ("off", ["--set", "serial.enabled", "false"])], now["serial"])
            if v:
                pending.append((f"serial {'on' if v[2] == 'true' else 'off'}", v))
        elif pickv == "6":
            print("\nRegion controls whether the radio may transmit. UNSET = receive only.")
            reg = ask("Region (US, EU_868, ANZ, ... or blank to leave)", "")
            if reg:
                pending.append((f"region {reg.upper()}", ["--set", "lora.region", reg.upper()]))


def main():
    ap = argparse.ArgumentParser(
        description="Harden a Meshtastic radio: screen, LED, BLE pairing, serial module.",
        epilog="With no options it just prints the current settings.")
    ap.add_argument("--port", help="serial port (auto-detected if omitted)")
    ap.add_argument("--board", choices=tuple(MESH_PINS), default="heltec-v3",
                    help="board type, sets the serial-module pins (default heltec-v3)")
    ap.add_argument("--screen", metavar="on|off|SECS",
                    help="'off' blanks after 1s, 'on' stays lit, or give seconds")
    ap.add_argument("--led", choices=("on", "off"), help="status LED heartbeat")
    ap.add_argument("--ble", choices=("on", "off"), help="Bluetooth on or off")
    ap.add_argument("--pin", metavar="NNNNNN|none|random",
                    help="BLE pairing: 6-digit fixed pin, 'none', or 'random'")
    ap.add_argument("--serial", choices=("on", "off"),
                    help="AntiHunter serial module (TEXTMSG, 115200, board pins)")
    ap.add_argument("--region", help="LoRa region, e.g. US. UNSET means receive only")
    args = ap.parse_args()

    check_deps()

    port = args.port or find_radio()
    print(f"radio: {port}")

    before = snapshot(read_config(port))
    sets = build(args)
    if not sets:
        show(before)
        if not sys.stdin.isatty():
            print("\nNothing changed. Pass --screen/--led/--ble/--pin/--serial to apply settings.")
            return 0
        sets = menu(before, args.board)
        if not sets:
            print("\nNothing changed.")
            return 0
    else:
        show(before)
    print("\nApplying...")
    rc, out = mesh(port, sets)
    if rc != 0:
        print(out[-600:])
        die("the radio rejected the settings")

    after = snapshot(read_config(port))
    show(before, after)

    changed = [k for k in before if before[k] != after[k]]
    print(f"\n{len(changed)} setting(s) changed" + (": " + ", ".join(changed) if changed else ""))
    if args.pin and args.pin not in ("none", "random"):
        print(f"Pair with pin {args.pin}. Forget the device on your phone first if it was")
        print("already paired — an old bond fails with 'encryption is insufficient'.")
    if after.get("region") == "UNSET":
        print("Region is UNSET: the radio receives but will not transmit until you set one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
