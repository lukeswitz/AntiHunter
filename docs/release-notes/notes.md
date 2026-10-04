# AntiHunter v1.0.4

Apple services detection, Fieldwatch catalog, baseline A/B, v1.0.3 fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.4 | ESP32-S3 | v1.0.3 (2026-09-29) |
| Beta | v1.0.4-beta1 | ESP32-S3 | v1.0.3-beta1 (2026-09-29) |
| Experimental | v1.0.4-c5exp1 | XIAO ESP32-C5 | v1.0.3-c5exp1 (2026-09-29) |

## New (full firmware)

- Apple services detection: BLE Continuity type (AirDrop, Handoff, AirPods, Hey Siri, Tethering, iPhone activity state) or GAP appearance category, as a badge in Device scan, Target scan and Baseline results, and on baseline anomaly alerts (`Class:`).
- Fieldwatch catalog v84 match (OUI, name, UUID, manufacturer and service data) in the same badge.
- Target scan RSSI trend badge per target: `CLOSING`, `OPENING`, `STEADY` after 4 sightings, `WAIT` before.
- Baseline A/B marker: Mark A/B button while a baseline runs; results add an A/B Slice section with devices new after the mark, gone after it, and moved by the RSSI threshold.
- Results: BLE blue, Wi-Fi green.

## Fixed

- Scan start no longer moves the radio off the softAP channel while a client is connected; the web UI stays up (full).
- Deauth scan no longer starts BLE.
- Mesh RX task stack in internal RAM.
- Device scan name shown after the MAC, HTML-escaped.
- Schedule list: same-day blocks read "Today", not next week.
- Locally modified builds get a unique web UI ETag.

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
