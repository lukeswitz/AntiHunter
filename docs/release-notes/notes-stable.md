# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

## What's Changed

### Both FW

- **Guard against a bad memcpy length in the WiFi library.** Its sniffer receive path computes a copy length by subtraction with no lower bound, so a short receive block underflows it and the copy runs off the end of mapped PSRAM as `Cache error / MMU entry fault`. `memcpy` is wrapped and lengths with bit 31 set are rejected; nothing legitimate on an 8 MB-PSRAM part reaches that size. The fault was reproduced on the beta channel, not on this one — on stable the window is narrower and it is carried here as hardening.
- **Triangulation target MAC is read and written atomically.** It was a plain 6-byte array written memset-then-memcpy while the web task, the sniffer callback and the scan task read it unsynchronised; a reader landing in that window saw a partly-written MAC, and at the match gate that silently dropped the peer's RSSI report.
- **Baseline no longer reboots** (`ESP_RST_PANIC`) under dense RF or long scans — internal-RAM exhaustion across several baseline paths fixed.
- **The SD card is never refused a write.** An earlier build put an internal-heap floor in front of every SD open, which turned a memory shortage into a node that silently stopped logging. The floor is gone. The memory it was covering for was found instead: resident task stacks moved to PSRAM, and the log file is held open across writes rather than reopened per line, so `fopen` is not on the hot path at all.
- BLE result buffer bounded — 150 in baseline, 200 in device/probe/triangulation/drone.
- Device-history table moved to PSRAM and bounded by free heap.
- Closed two use-after-free windows (baseline vs BLE radio task; WiFi scan-buffer pointer across an alloc).
- Baseline radio teardown fixed — no leftover promiscuous mode or hop timer, no competing WiFi scans mid-run.
- Mesh enable persists across reboot.
- An emoji in the Meshtastic sender name no longer drops the command.
- **A long BLE device scan no longer aborts inside `fopen`.** Reported from the field with the backtrace intact: v1.0.2 in a BLE device scan ran internal RAM down to `LOW: 1660 bytes free` and died in newlib's `lock_init_generic`, which aborts when the FreeRTOS lock every open file needs cannot be allocated. Internal RAM has no error path there. The drain was every unique BLE device costing a few hundred bytes of internal for its `String` keys, on top of NimBLE's pools sitting in internal because the Arduino core pins `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL` and the library's PSRAM flag is inert. NimBLE's pools now come from PSRAM through a linker wrap, and the malloc routing threshold is 16 bytes instead of 64 so small keys go to PSRAM first. Reproduced with a second node advertising a rotating BLE address at the board: v1.0.2 aborted at 194 unique devices; this build held 98780 bytes free at 200, flat.
- **The AP MAC is actually randomized.** `esp_wifi_set_mac` ran before WiFi was initialised and returned `ESP_ERR_WIFI_NOT_INIT` every boot, so the AP kept its factory MAC. It now runs between `esp_wifi_stop` and `esp_wifi_start`.
- **`STOP` ends a running scan at once.** `stopAllScans` called `WiFi.scanDelete()` right after `esp_wifi_scan_stop()`; `scanDelete` clears the scanning flag, the core's scan-done handler then returns early, and a task waiting on the scan rode out the 60 s timeout. Measured: 58 s to stop before, same second after.
- **`+PROBE` on `DEVICE_SCAN_START` is honored.** The full build ignored the documented token; headless matched it but compared the third field literally, so `FOREVER:+PROBE` dropped FOREVER. Both tokenize the command.
- **`SCAN_START:mode:secs:FOREVER` runs forever.** Without a channel list the third field was ignored and the scan ran for `secs` on default channels.
- **The results snapshot is written atomically.** It was truncated in place, so a power cut mid-write left a partial file that was restored at boot. It is written to a temp file, length-checked, then renamed.
- Boot prints a `[MEM]` ladder — free internal RAM after each init stage and at scan start — so the next memory report can be read off the log.

| Build | Rebooted at | Lowest free internal heap |
|---|---|---|
| Unfixed | ~700 devices (`ESP_RST_PANIC`) | 508 B |
| Fixed — ESP32-S3 | 9,200+, no reboot (test stopped) | 33,528 B |
| Fixed — ESP32-C5 | 11,375, no reboot (test stopped) | 19,884 B |

### Full FW

- Scan Results no longer stalls mid-scan — `/results` streams from one PSRAM copy, the poll times out at 5 s, and text is marked seen only after it renders.
- Baseline results rebuild on the 2 s timer and only when something changed (was every packet, with serial spam).
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): recolor the destructive controls and Sentinel banners, five choices across all three themes, held in the browser. Sentinel defaults to copper.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colors).
- Theme toggle stays in the mobile scan header.
- The page reloads itself when the browser lands on a different node — settings forms were loaded once and posted to whichever node the AP had switched to.

### Flasher

- Hidden AP toggle for full firmware.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl` (tripod inset centered, geometry otherwise unchanged).

## Upgrade notes

- Flash through the web flasher. S3 stable is on `main`; the C5 build ships through the Experimental channel.
- No configuration changes required. Existing SD baselines are read as-is.
