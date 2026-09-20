# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

**Headline:** Packet capture to SD, CSI motion detection, and Baseline no longer reboots under dense RF or long runs.

## What's Changed

### Both FW

- **Packet capture to SD**: Wireshark pcap, WiFi radiotap, BLE PDUs.
  - `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`, `PCAP_STOP`, vibration mode 8, Scan tab.
  - C5 band select: 2.4 GHz, 5 GHz, or both.
  - Capture keeps hopping with the web UI connected.
  - Stop line reports channels visited.
  - C5 5 GHz capture recorded 2.4 GHz; fixed.
  - Captures list sorts newest first.
  - Capture stops at size cap, free-space floor, or write failures.
  - Cap 8–300 MB, default 100: Scan tab, Sentinel panel, `PCAP_LIMITS`.
  - Mesh reply says `R=SIZECAP` or `R=WRITEFAIL`.

> [!WARNING]
> Stop a capture before cutting power or resetting. FAT has no power-fail protection; an
> interrupted write can leave the card unreadable until reformatted. `SD_REPAIR:ON` lets the
> node rebuild its own card (erases it).

- Peer status lines no longer run as commands.
- Local time on all boards; UTC without GPS.
- All SD writers retry on a busy card.
- Reset mid-capture no longer corrupts the card.
- Sync after each write; mount retries with bus re-init.
- `SD_REPAIR:ON` rebuilds a bad card (erases it, off by default).
- Failed mounts counted and shown in Diagnostics.
- **Sentinel attack response**: triangulate, capture, discovery, probe sweep, drone RID.
  - Run in turn, each with its own duration.
  - Auto captures pruned to a size budget.
- **CSI motion detection**: experimental beta on S3, in testing on C5.
  - Detects movement from ambient WiFi; nothing worn or joined.
  - Reports through walls.
  - Alerts to serial, SD and mesh.
  - Alerts need several transmitters disturbed, held over time.
  - Sensitivity is per receiver; S3 and C5 values differ.
  - C5 separates movement less cleanly than S3; cause open.
  - No long-run false-alarm rate yet.
- Triangulation target MAC read and written atomically.
- Baseline no longer panics under dense RF.
- Internal-heap floor before SD opens removed.
- Task stacks in PSRAM; log file held open.
- NimBLE per-window scan cache capped at 200 (150 baseline).
  - Cleared every window; total devices seen is unbounded.
- Device-history table in PSRAM, bounded by free heap.
- Two use-after-free windows closed (BLE task, scan buffer).
- Baseline teardown clears promiscuous mode and hop timer.
- Task-creation failures reported, not wedged.
- Mesh TX cancel no longer kills the scan.
- Emoji sender names no longer drop mesh commands.
- Long BLE scans no longer abort in `fopen` (field report).
  - NimBLE pools in PSRAM; small mallocs PSRAM-first.
  - Aborted at 53 devices before; flat at 200 now.
- AP MAC randomization fix.
- `STOP` no longer waits on a scan that can't finish.
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
- **CSI movement view**: quiet/moving/can't-measure state, movement log, heat strip.
  - Heat blocks shaded by movement events, eight accent-color steps.
  - Blocks widen (1, 5, 15 min) as sessions age.
- **Fleet roster** (System tab): mesh nodes, mode/uptime/temp/hits/GPS, privacy redaction.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS, default off.
  - Stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): five choices; destructive controls, Sentinel, movement.
  - Sentinel and movement default to copper.
- Dark theme destructive controls: acid lime, was brick red.
- **Captures list** (Scan tab): size, download, delete, delete-all with confirm.
  - The file being recorded cannot be deleted.
- Recon & Detection method list regrouped: Recon, Detection, Capture.
- Clearing results clears the CSI history.
- Theme toggle stays in the mobile scan header.
- Unclosed container element in web UI markup fixed.

### Flasher

- Hidden AP toggle for full firmware.
- C5 experimental channel carries the same CSI, Fleet, fixes.
- C5 motion detection is in testing; prefer an S3.
  - C5 sensitivity is its own; S3 values don't transfer.
  - See [docs/ESP32-C5.md](../ESP32-C5.md) for C5 detail.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body: `SinglePrintSideChargeHousing.stl`.

## Upgrade notes

- Flash via web flasher. No config changes; baselines read as-is.

## Thanks

- rcbm. and d3mo for the bug reports.
