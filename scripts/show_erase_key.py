#!/usr/bin/env python3
Import("env")
import re
import time
import serial

KEY_RE = re.compile(r"\[ERASE\] Erase key: (\S+) \(generated")


def show_erase_key(source, target, env):
    port = env.get("UPLOAD_PORT")
    if not port:
        return
    print("\n[ERASE] Waiting for the node to report its erase key (up to 90 s)...")
    try:
        ser = serial.Serial(port, 115200, timeout=1)
    except serial.SerialException as e:
        print(f"[ERASE] Could not open {port}: {e}. Run 'pio device monitor' and reboot the node to see the key.\n")
        return
    start = time.time()
    last_skip = 0.0
    result = None
    while time.time() - start < 90:
        if time.time() - start < 45 and time.time() - last_skip > 2:
            ser.write(b"SKIP\n")
            last_skip = time.time()
        line = ser.readline().decode("utf-8", errors="ignore").strip()
        m = KEY_RE.search(line)
        if m:
            result = m.group(1)
            break
        if "[ERASE] Erase key: set by you" in line:
            result = ""
            break
    ser.close()
    if result:
        print("\n" + "=" * 50)
        print(f"  ERASE KEY:  {result}")
        print("  WRITE THIS DOWN. You need it to wipe this node.")
        print("  LOST IT? Run 'pio run -t erase', then upload again, for a new key.")
        print("=" * 50 + "\n")
    elif result == "":
        print("[ERASE] This node keeps the erase key you set earlier.")
        print("[ERASE] Lost it? Run 'pio run -t erase', then upload again, for a new key.\n")
    else:
        print("[ERASE] No key line seen. Run 'pio device monitor' and reboot the node to see it.\n")


env.AddPostAction("upload", show_erase_key)
