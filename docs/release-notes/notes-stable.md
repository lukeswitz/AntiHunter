# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

Packet capture to SD, a Sentinel that fights back, local-time logs, and the memory fix behind the long-scan crash.

## New

- **Packet capture to SD.** Wireshark-ready pcap: WiFi with radiotap, BLE advertisements as link-layer PDUs. Start it from the Scan tab or with `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`; `PCAP_STOP` ends it. A capture stops on its own at the size cap (8–300 MB, default 100, `PCAP_LIMITS:<MB>`), at the free-space floor, or after repeated write failures, and the stop line lists the channels it visited.
- **Sentinel attack response.** On a confirmed attack with a source MAC, run what you pick — triangulate, capture, device discovery, probe sweep, drone RID — each for its own duration, one after another.
- **Vibration auto-scan.** System tab → Sensor Alerts: choose the scan that runs when the node is bumped, packet capture included. Mesh: `VIBSCAN_SET`, `VIBSCAN_STATUS`.
- **Local time.** Logs and capture names in your timezone, DST included. The RTC keeps the clock; the GPS fix tells the node which zone it sits in. Before the first fix after a boot it shows UTC.
- **SD self-repair.** `SD_REPAIR:ON` lets a node rebuild an unmountable card on its own. Off by default — rebuilding erases it.
- **Fleet roster** (web UI, System tab): every mesh node and radio, with mode, uptime and temperature; privacy toggle.
- **Hidden SoftAP** (web UI, RF Settings): stops the beacon. Not access control.
- **Accent colors** (web UI, System tab): five schemes for the Stop and Clear buttons and the Sentinel banners. Buttons default to electric cyan, Sentinel to ice blue.
- Captures list on the Scan tab: download, delete, delete-all behind a confirmation.
- Data Explorer privacy toggle.
- Method dropdown regrouped: Recon, Detection, Capture.
- Mesh on/off is saved across reboots.
- SD bus runs at 16 MHz (was 400 kHz), with 4 MHz and 400 kHz fallbacks.
- Boot prints a `[MEM]` ladder and a `[HEAP]` line every 30 s, so a memory report can be read off the serial log.

## Fixed

- **Long BLE device scans no longer abort in `fopen`** (field report). NimBLE's pools and small allocations moved to PSRAM. v1.0.2 aborted at 194 injected devices with 1,672 B of internal RAM left; this build held 98,376 B at 200.
- **Baseline no longer reboots under dense RF.** Device history keyed by MAC and held in PSRAM, task locals freed on exit (leaked ~96 B per device per scan), resident task stacks in PSRAM (18,432 B freed), NimBLE's per-window scan cache capped at 200 (150 in baseline; the number of devices seen is not capped), two use-after-free windows closed, and baseline's exit now stops promiscuous mode and the hop timer.
- `STOP` no longer waits on a scan that can't finish.
- `DEVICE_SCAN_START` honors `+PROBE` in any position; `SCAN_START:mode:secs:FOREVER` runs forever without a channel list.
- Baseline no longer runs forever when only another panel's Forever box was ticked (web UI).
- Peer node reports are never run as commands.
- Emoji-only Meshtastic sender names no longer drop commands (#31).
- Triangulation target MAC is read atomically; a torn read used to drop a peer's RSSI report.
- Results snapshot is written to a temp file and renamed, so a power cut can't leave a partial one.
- SD writes retry with backoff on a busy card; a failed mount retries with a bus re-init, is logged once a minute and counted in Diagnostics; SD chip-select is driven high before the SPI bus starts.
- Log file is held open across writes and reopened only after a failed write.
- Scan Results page no longer freezes mid-scan; `/results` streams from PSRAM. Results clear when a new scan starts; the UI polls only the open tab; the page reloads itself when the browser lands on a different node.
- Baseline results rebuild every 2 s and only on change; theme toggle stays in the mobile scan header; Diagnostics `Mesh TX` line no longer sticks at draining.
- AP MAC randomization fix.
- `memcpy` length guard against a WiFi driver underflow.

## Hardware

- DIGINODE v2 side-charge enclosure, single-body model: `One-Piece-Housing-SideCharge-Version.stl`.
- Revised full side-charge housing: `FullSideChargeHousing.stl`.
- Front cover with a hidden 10 mm fan: `FrontCover-Hidden-Fan-10mm.stl`.
- Assembly manual, BOM links and welcome note updated.

## Upgrade

Settings in NVS and files on the SD card survive a flash without erase.

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Channel Stable, then Full or Headless.

**Flasher script** (needs Python 3, esptool and pyserial):

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

Pick channel 1 (Stable). `-e` erases first, `-c` sets device parameters during the flash, `-l` lists the firmware.

**PlatformIO**:

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
```

`AntiHunter-headless` for the mesh-only build. `-t erase` wipes the chip first.

## Thanks

- rcbm. and d3mo for the bug reports.
