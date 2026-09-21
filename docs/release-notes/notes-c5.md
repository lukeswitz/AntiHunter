# AntiHunter v1.0.3-c5exp1 (experimental, XIAO ESP32-C5)

Experimental channel · Previous C5 build v1.0.2-c5exp1 (2026-08-13)

Everything in [v1.0.3-beta1](https://github.com/lukeswitz/AntiHunter/releases/tag/v1.0.3-beta1) on a dual-band board, plus the C5-only items below. Breadboard the C5 and test it before you solder anything: a C5 soldered into a PCB can only go back to stable firmware by desoldering it and fitting an ESP32-S3.

## New

- **CSI motion detection, in testing on the C5.** Same feature as the S3 beta, with its own presets: Medium is the level this board was scored at, Low and High are scaled from it. It runs and detects, but separates movement from background less cleanly than an S3 in the same room; the cause is open. Prefer an S3 where detection matters. Detail and open issues: [docs/ESP32-C5.md](https://github.com/lukeswitz/AntiHunter/blob/feat/c5/docs/ESP32-C5.md).
- **Packet capture picks the band.** 2.4 GHz, 5 GHz, or both, from the Scan tab or the `band` field of `PCAP_START`.

## Upgrade

Settings in NVS and files on the SD card survive a flash without erase.

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Channel Experimental – XIAO ESP32-C5, then Full or Headless.

**Flasher script**: fetch it as in the beta notes and pick channel 3 (Experimental).

**PlatformIO**:

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload
```

`AntiHunter-c5-headless` for the mesh-only build.

## Thanks

- rcbm. and d3mo for the bug reports.
