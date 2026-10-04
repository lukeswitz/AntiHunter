# AntiHunter v1.0.4

Apple services detection, BLE device class table, baseline "Watch for changes", Target vendor tag, v1.0.3 fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.4 | ESP32-S3 | v1.0.3 (2026-09-29) |
| Beta | v1.0.4-beta1 | ESP32-S3 | v1.0.3-beta1 (2026-09-29) |
| Experimental | v1.0.4-c5exp1 | XIAO ESP32-C5 | v1.0.3-c5exp1 (2026-09-29) |

## New (full firmware)

- Apple services detection: BLE Continuity type (AirDrop, Handoff, AirPods, Hey Siri, Tethering, iPhone activity state) or GAP appearance category, as a badge in Device scan, Target scan and Baseline results, and on baseline anomaly alerts (`Class:`).
- BLE device class from 16-bit service UUID, service data or company ID (208 UUIDs, 108 companies, Bluetooth SIG assigned numbers): Phone, Wearable, Audio, Tag, Vehicle, Health, Home, Lock, Camera, Drone, Glasses, Radio, Beacon, Input, shown as `Class-Vendor` in the same badge. 4 KB flash, no RAM.
- Target scan RSSI trend badge per target: `CLOSING`, `OPENING`, `STEADY` after 4 sightings, `WAIT` before.
- Baseline "Watch for changes from now": button or `@ALL BASELINE_WATCH` while a baseline runs; results add "Since <time>" listing devices new here, gone, or moving closer/away (by the RSSI threshold), with before → after signal.
- Target mesh alerts end with `V=<vendor>` (first word of the OUI vendor, e.g. `V=NETGEAR`) when the MAC is not randomized. Full and headless.
- Device classes each have their own color on every badge, light and dark themes.
- Baseline anomalies as a table: New, Returned and Moved pills with counts, device, radio, class or vendor, signal and detail.
- Class summary table (devices per class, strongest signal) at the top of Device scan results and the cached baseline device list.
- The web page reloads itself when the node runs new firmware.
- Results: BLE blue, Wi-Fi green.

## Fixed

- Scan start no longer moves the radio off the softAP channel while a client is connected; the web UI stays up (full).
- Deauth scan no longer starts BLE.
- Sentinel BLE attack table: Flipper Zero matched by its service UUID 0x3080-0x3083; the old 0x0FBA company ID belongs to Cosonic.
- Mesh RX task stack in internal RAM.
- Device scan name shown after the MAC, HTML-escaped.
- Schedule list: same-day blocks read "Today", not next week.
- Locally modified builds get a unique web UI ETag.
- Docs: mesh command reference and Operator's Guide (rev 1.1, PDF) list every firmware command; Beta-only commands marked.

## Upgrade

Settings and SD card files survive a flash.

All three builds attach to the one v1.0.4 release.
Per channel: `antihunter-<full|headless>-<version>.bin`; C5 uses `.factory.bin`.
Also `bootloader`, `partitions` and `SHA256SUMS` per version.
Builds are reproducible; verify with `shasum -a 256`.

| | Stable | Beta | Experimental (C5) |
|---|---|---|---|
| Web flasher channel | Stable | Beta | Experimental — ESP32-C5 |
| Script channel | 1 | 2 | 3 |
| Branch | `main` | `beta` | `feat/c5` |
| PlatformIO full | `AntiHunter-full` | `AntiHunter-full` | `AntiHunter-c5-full` |
| PlatformIO mesh-only | `AntiHunter-headless` | `AntiHunter-headless` | `AntiHunter-c5-headless` |

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge.
Pick the channel, then Full or Headless.

**Flasher script** (Python 3, esptool, pyserial), same on every branch:

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

`-c` sets device settings; `-l` lists firmware.

**PlatformIO**: `-t upload` keeps settings and the SD card.

Stable:

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload        # web UI
pio run -e AntiHunter-headless -t upload    # mesh only
```

Beta:

```bash
git clone -b beta https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
pio run -e AntiHunter-headless -t upload
```

Experimental (C5):

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload
pio run -e AntiHunter-c5-headless -t upload
```
