# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

Motion detection from the WiFi already in the air, packet capture to SD, a Sentinel that fights back, local-time logs, and the memory fix behind the long-scan crash.

## New

- **CSI motion detection** (experimental beta, ESP32-S3). A node senses people moving through a space by how their bodies disturb the WiFi signals already around it — nothing worn, no network joined, and it reports through walls. Scan tab → CSI Motion with Low / Medium / High presets, or `CSI_MOTION_START:secs[:CH<n>][:FOREVER]` over mesh with `CSI_CFG`, `CSI_RECAL`, `CSI_STATUS`, `CSI_JSON`, `CSI_EXCLUDE`. Alerts go out as `CSI_MOTION:` / `CSI_CLEAR:` on mesh, serial and SD. Listen-only by default; `ALLOW_TRANSMIT` lets the node send probe requests when the air is too quiet. Sensitivity is per receiver, so set it in the room it will live in. On the ESP32-C5 it is in testing: it runs, but separates movement from background less cleanly than an S3. No long-run false-alarm rate is measured yet.
- **CSI movement view** (web UI): quiet / moving / can't-measure state, a movement log, and a whole-session heat strip whose blocks shade by movement strength, the strongest link over its trigger averaged across the block — tap a block for its time. Blocks widen from 1 to 5, 15, 30 minutes and up as the session ages. Clearing results clears the CSI history too.
- **Packet capture to SD.** Wireshark-ready pcap: WiFi with radiotap, BLE advertisements as link-layer PDUs. Start it from the Scan tab, on vibration, or with `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`; `PCAP_STOP` ends it. A capture stops on its own at the size cap (8–300 MB, default 100, `PCAP_LIMITS:<MB>` or the Sentinel panel), at the free-space floor, or after repeated write failures, and the stop line lists the channels it visited.
- **Sentinel attack response.** On a confirmed attack with a source MAC, run what you pick — triangulate, capture, device discovery, probe sweep, drone RID — each for its own duration, one after another.
- **Local time.** Logs and capture names in your timezone, DST included. The RTC keeps the clock; the GPS fix tells the node which zone it sits in. Before the first fix after a boot it shows UTC.
- **SD self-repair.** System tab → Node Configuration, or `SD_REPAIR:ON`: a node rebuilds an unmountable card on its own, and Repair now does it on demand. Off by default — rebuilding erases it.
- **Fleet roster** (web UI, System tab): every mesh node and radio, with mode, uptime and temperature; privacy toggle.
- **Hidden SoftAP** (web UI, RF Settings): stops the beacon. Not access control.
- **Accent colors** (web UI, System tab): five schemes for the Stop and Clear buttons, and five for the Sentinel banners and movement hits. Buttons default to electric cyan, Sentinel and movement to ice blue.
- `MESH_TX_CANCEL` (and the UI cancel) clears the mesh queue without stopping the scan; a queued backlog no longer blocks starting one.
- Headless: discovered devices persist across scans.
- Captures list on the Scan tab: download, delete, delete-all behind a confirmation.
- Data Explorer privacy toggle.
- Method dropdown regrouped: Recon, Detection, Capture.
- Mesh on/off is saved across reboots.
- SD bus runs at 16 MHz (was 400 kHz), with 4 MHz and 400 kHz fallbacks.
- Boot prints a `[MEM]` ladder and a `[HEAP]` line every 30 s; task-creation failures are logged with the free and largest internal block.

## Fixed

- **Long BLE device scans no longer abort in `fopen`** (field report on v1.0.2). NimBLE's pools and small allocations moved to PSRAM. The previous beta aborted at 123 injected devices with 11,676 B of internal RAM left; this build held 64,404 B at 200.
- **Baseline no longer reboots under dense RF.** Device history keyed by MAC and held in PSRAM, task locals freed on exit (leaked ~96 B per device per scan), resident task stacks in PSRAM (18,432 B freed), NimBLE's per-window scan cache capped at 200 (150 in baseline; the number of devices seen is not capped), two use-after-free windows closed, and baseline's exit now stops promiscuous mode and the hop timer.
- `STOP` no longer waits on a scan that can't finish.
- `DEVICE_SCAN_START` honors `+PROBE` in any position; `SCAN_START:mode:secs:FOREVER` runs forever without a channel list.
- Baseline no longer runs forever when only another panel's Forever box was ticked (web UI).
- Peer node reports are never run as commands.
- Emoji-only Meshtastic sender names no longer drop commands (#31).
- Triangulation target MAC is read atomically; a torn read used to drop a peer's RSSI report. Headless honors a stop during the ACK and report waits, and its baseline MAC queue sends go through the guarded path.
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

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Channel Beta, then Full or Headless.

**Flasher script** (needs Python 3, esptool and pyserial):

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/beta/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

Pick channel 2 (Beta). `-e` erases first, `-c` sets device parameters during the flash, `-l` lists the firmware.

**PlatformIO**:

```bash
git clone -b beta https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
```

`AntiHunter-headless` for the mesh-only build. `-t erase` wipes the chip first.

## Thanks

- rcbm. and d3mo for the bug reports.
