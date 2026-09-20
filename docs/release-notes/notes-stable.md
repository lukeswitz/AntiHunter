# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

## What's Changed

### Both FW

- **Packet capture to SD**: Wireshark pcap, WiFi radiotap, BLE PDUs.
  - `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`, `PCAP_STOP`, vibration mode 8, Scan tab.
  - Capture keeps hopping with the web UI connected.
  - Stop line reports channels visited.
  - Captures list sorts newest first.
  - Capture stops at size cap, free-space floor, or write failures.
  - Cap 8–300 MB, default 100: Scan tab or `PCAP_LIMITS`.
  - Mesh reply says `R=SIZECAP` or `R=WRITEFAIL`.

> [!WARNING]
> Stop a capture before cutting power or resetting. FAT has no power-fail protection; an
> interrupted write can leave the card unreadable until reformatted. `SD_REPAIR:ON` lets the
> node rebuild its own card (erases it).

- Peer status lines no longer run as commands.
- Local time on all boards; UTC without GPS.
- SD writes retry on a busy card.
- Reset mid-capture far less likely to corrupt the card.
- Sync after each write; mount retries with bus re-init.
- `SD_REPAIR:ON` rebuilds a bad card (erases it, off by default).
- Failed mounts counted and shown in Diagnostics.
- Triangulation target MAC read and written atomically.
- Baseline no longer panics under dense RF.
- Internal-heap floor before SD opens removed.
- Task stacks in PSRAM; log file held open.
- NimBLE per-window scan cache capped at 200 (150 baseline).
  - Cleared every window; total devices seen is unbounded.
- Device-history table in PSRAM, bounded by free heap.
- Two use-after-free windows closed (BLE task, scan buffer).
- Baseline teardown clears promiscuous mode and hop timer.
- Emoji sender names no longer drop mesh commands.
- Long BLE scans no longer abort in `fopen` (field report).
  - NimBLE pools in PSRAM; small mallocs PSRAM-first.
  - v1.0.2 aborted at 194 devices; flat at 200 now.
- AP MAC randomization fix.
- `STOP` ends scans immediately, not after 60 s.
- `DEVICE_SCAN_START` honors `+PROBE` in any position.
- `SCAN_START:mode:secs:FOREVER` runs forever without a channel list.
- Results snapshot written to temp file, then renamed.
- Boot logs a `[MEM]` ladder of free internal RAM.

| Build | Rebooted at | Lowest free internal heap |
|---|---|---|
| Unfixed | ~700 devices (`ESP_RST_PANIC`) | 508 B |
| Fixed — ESP32-S3 | 9,200+, no reboot (test stopped) | 33,528 B |
| Fixed — ESP32-C5 | 11,375, no reboot (test stopped) | 19,884 B |

### Full FW

- Scan Results no longer stalls; `/results` streams from PSRAM.
- Web UI polls only the visible tab; taps land.
- Baseline results rebuild every 2 s, only on change.
- **Fleet roster** (System tab): mesh nodes, mode/uptime/temp/hits/GPS, privacy redaction.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS, default off.
  - Stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): five choices; destructive controls and Sentinel banners.
  - Sentinel defaults to copper.
- Dark theme destructive controls: acid lime, was brick red.
- Page reloads when the browser lands on a different node.
- **Captures list** (Scan tab): size, download, delete, delete-all with confirm.
  - The file being recorded cannot be deleted.
- Recon & Detection method list regrouped: Recon, Detection, Capture.
- Theme toggle stays in the mobile scan header.
- Unclosed container element in web UI markup fixed.

### Flasher

- Hidden AP toggle for full firmware.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body: `SinglePrintSideChargeHousing.stl`.

## Upgrade notes

- Flash via web flasher. S3 stable on `main`; C5 on the Experimental channel.
- No config changes; baselines read as-is.

## Thanks

- rcbm. and d3mo for the bug reports.
