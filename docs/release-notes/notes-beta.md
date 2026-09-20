# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

**Headline:** Packet capture to SD, CSI motion detection, and Baseline Detection no longer reboots under dense RF or on long runs.

## What's Changed

### Both FW

- **Packet capture to SD** (full + headless): writes a standard pcap Wireshark opens. WiFi frames carry a full radiotap header with channel, data rate and RSSI; BLE advertisements are written as link-layer PDUs so they dissect as ADV_IND, ADV_DIRECT_IND and SCAN_RSP. Band select on C5 covers 2.4 GHz, 5 GHz or both. `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]` and `PCAP_STOP` over mesh, vibration auto-scan mode 8, or the Scan tab. `CH` names the channels to hop; without it the node uses its configured list for the band.
- **A capture keeps hopping while the web UI is connected.** `esp_wifi_set_channel` is refused for every channel once a station associates with the soft AP, and the capture silently parked on one channel. A capture now visits channels the way the scanner already did, through a passive `esp_wifi_scan_start` with a home-channel dwell, so the driver returns to the AP channel by itself and the link survives. The stop line reports `channels visited N/N (ch=frames/visits)`, so an empty channel is distinguishable from a skipped one.
- **5 GHz capture recorded 2.4 GHz.** A 5 GHz or dual-band capture on C5 wrote only 2.4 GHz frames: the capture path set the regulatory 5 GHz channel mask but never the radio band mode, so the channel set had nowhere to go and its return value was discarded. The band mode is applied and the result of every channel change is now checked and counted.
- **A node no longer runs another node's status line as a command.** Every mesh payload without an `@` prefix was passed to the command dispatcher, sender included, so one node announcing `PCAP_START: WIFI D=60` made its peers start captures of their own — and because that announcement is not in command grammar, they ran at the 300 s default instead of the 60 s asked for. A payload carrying a node id is now treated as a report; operator commands still arrive as `@ALL` or `@NODE`.
- **Captures list newest first.** The capture list sorted on the raw filename, so every `wifi_` file ranked above every `ble_` file whatever its timestamp and BLE captures sank to the bottom of the list. It now sorts on the timestamp in the name.
- **Timestamps show local time on every board.** The GPS-derived local time added last release reached only one firmware tree; the others still stamped filenames and log lines in UTC. Without a GPS lock the display falls back to UTC.
- **Packet capture is bounded.** A capture used to run until stopped, and a forever run filled the card, drove every write to failure and left the filesystem damaged. It now stops on its own at a file size cap, at the free-space floor, or after three consecutive failed writes, and the mesh reply says which: `R=SIZECAP` or `R=WRITEFAIL`. The cap is 8 to 300 MB, 100 MB by default, on the Scan tab, in the sentinel auto-response panel, or over mesh with `PCAP_LIMITS`. The free-space floor now applies to every capture; it previously only guarded automatic ones, which is how a mesh-started capture bypassed it.

> [!WARNING]
> Stop a capture before cutting power or resetting the node. FAT has no power-fail
> protection, so an interruption mid-write can leave the SD card unreadable until it is
> reformatted, and the node then runs with no storage at all. `SD_REPAIR:ON` lets a node
> rebuild its own card, which recovers most cases but not all, and erases the card.
- **SD writes survive a busy card.** An SD card acknowledges writes quickly until its internal buffers fill, then stalls while its controller commits to flash. The SD library waits a fixed 500 ms and gives up, so every write after that point returned zero while the node carried on as if the data had landed. Writes now flush and retry with backoff, and every writer in the firmware routes through that path: baseline, config, event log, results snapshot, probes, device database, detect features, randomization. Measured on a C5: the same capture went from 27 short writes to none.
- **A reset during a capture no longer costs the card.** FAT has no power-fail protection, so a reset mid-write left the card unmountable until a human wiped it. The filesystem is now synced after each write rather than on a timer, and the mount path retries with a full bus re-init. Measured on a C5: 1 of 4 resets survived before, 5 of 5 after. A node can also rebuild its own card with `SD_REPAIR:ON`, off by default because rebuilding erases it. A failed mount now reports its count and shows in Diagnostics instead of retrying silently forever.
- **Sentinel attack response**: pick which actions run on a confirmed attack with a source MAC — triangulate, packet capture, device discovery, probe sweep, drone RID — each with its own duration. Only one can hold the radio, so several selected run in that order one at a time as the radio frees up. Automatic captures are pruned against a size budget and a free-space floor.
- **CSI motion detection** (full + headless, **experimental beta on the ESP32-S3, in testing on the ESP32-C5**): detects people moving through a space using the WiFi already in the air — nothing worn, no network joined, no transmitter installed. Coverage is not confined to the room; movement through a wall reports too. Movement alerts go to serial, SD and mesh peers. A node reports motion only when the configured number of distinct transmitters are disturbed at once and that has held for an accumulated time within a rolling minute, so one noisy neighbour cannot hold an alert open. Sensitivity is per receiver, not per site: two chips side by side settle at different levels, each carries its own default, and a value moved from one to the other silences or floods it. Scored against labelled walk-ins in one room, the C5 separates movement from background less cleanly than the S3; the cause is open. No long-run false-alarm rate is asserted yet.
- **Triangulation target MAC is read and written atomically.** It was a plain 6-byte array written memset-then-memcpy while the web task, the sniffer callback and the scan task read it unsynchronised; a reader landing in that window saw a partly-written MAC, and at the match gate that silently dropped the peer's RSSI report.
- **Baseline no longer reboots** (`ESP_RST_PANIC`) under dense RF or long scans — internal-RAM exhaustion across several baseline paths fixed.
- **The SD card is never refused a write.** An earlier build put an internal-heap floor in front of every SD open, which turned a memory shortage into a node that silently stopped logging. The floor is gone. The memory it was covering for was found instead: resident task stacks moved to PSRAM, and the log file is held open across writes rather than reopened per line, so `fopen` is not on the hot path at all.
- BLE result buffer bounded — 150 in baseline, 200 in device/probe/triangulation/drone.
- Device-history table moved to PSRAM and bounded by free heap.
- Closed two use-after-free windows (baseline vs BLE radio task; WiFi scan-buffer pointer across an alloc).
- Baseline radio teardown fixed — no leftover promiscuous mode or hop timer, no competing WiFi scans mid-run.
- Task-creation failures are reported instead of leaving the node wedged.
- Mesh enable persists across reboot.
- Mesh TX can be cancelled without killing the running scan.
- An emoji in the Meshtastic sender name no longer drops the command.
- **A long BLE device scan no longer aborts inside `fopen`.** Reported from the field with the backtrace intact: v1.0.2 in a BLE device scan ran internal RAM down to `LOW: 1660 bytes free` and died in newlib's `lock_init_generic`, which aborts when the FreeRTOS lock every open file needs cannot be allocated. Internal RAM has no error path there. The drain was every unique BLE device costing a few hundred bytes of internal for its `String` keys, on top of NimBLE's pools sitting in internal because the Arduino core pins `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL` and the library's PSRAM flag is inert. NimBLE's pools now come from PSRAM through a linker wrap, and the malloc routing threshold is 16 bytes instead of 64 so small keys go to PSRAM first. Reproduced with a second node advertising a rotating BLE address at the board: the previous beta aborted at 53 unique devices with `LOW: 11676`; this build held 64508 bytes free at 200, flat.
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
- Web UI polls only the visible page. The 1 s Scan Results re-render ran on every tab and swallowed taps on the page tab bar.
- Baseline results rebuild on the 2 s timer and only when something changed (was every packet, with serial spam).
- **CSI movement view**: says whether the room is quiet, moving, or can't be measured; a movement log with the live peak of an open episode; and a whole-session heat strip rendered on the device. Each block of the strip is shaded by how many movement events started inside it, in eight steps of the selected accent color; blocks widen from one minute to five, fifteen and beyond as the session ages.
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): recolor the destructive controls, Sentinel banners and the movement hit color, five choices across all three themes, held in the browser. Sentinel and movement default to copper.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colors).
- **Captures list** on the Scan tab: collapsible, one line per file with size, download and delete, delete-all behind a confirmation, and the file being recorded cannot be deleted.
- Recon & Detection method list regrouped into Recon, Detection and Capture.
- Clearing results clears the CSI history with it.
- Theme toggle stays in the mobile scan header.
- Fixed an unclosed container element in the web UI markup.

### Flasher

- Hidden AP toggle for full firmware.
- C5 experimental channel carries the same CSI, Fleet and fixes for testing.
- Motion detection on a C5 is in testing. It runs and detects, but separates movement from
  background less cleanly than an S3 in the same room, and its default sensitivity is its own —
  an S3 value does not transfer. Prefer an S3 where detection matters. See
  [docs/ESP32-C5.md](../ESP32-C5.md) for C5 detail and the open upstream issues.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl`.

## Upgrade notes

- Flash through the web flasher. No configuration changes required; existing SD baselines are read as-is.
