# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

**Headline:** Packet capture to SD, CSI motion detection, and Baseline Detection no longer reboots under dense RF or on long runs.

## What's Changed

### Both FW

- **Packet capture to SD** (full + headless): writes a standard pcap Wireshark opens. WiFi frames carry a full radiotap header with channel, data rate and RSSI; BLE advertisements are written as link-layer PDUs so they dissect as ADV_IND, ADV_DIRECT_IND and SCAN_RSP. Band select on C5 covers 2.4 GHz, 5 GHz or both. `PCAP_START:radio:secs:band[:FOREVER]` and `PCAP_STOP` over mesh, vibration auto-scan mode 8, or the Scan tab.
- **Packet capture is bounded.** A capture used to run until stopped, and a forever run filled the card, drove every write to failure and left the filesystem damaged. It now stops on its own at a file size cap, at the free-space floor, or after three consecutive failed writes, and the mesh reply says which: `R=SIZECAP` or `R=WRITEFAIL`. The cap is 8 to 300 MB, 100 MB by default, on the Scan tab, in the sentinel auto-response panel, or over mesh with `PCAP_LIMITS`. The free-space floor now applies to every capture; it previously only guarded automatic ones, which is how a mesh-started capture bypassed it.

> [!WARNING]
> Stop a capture before cutting power or resetting the node. FAT has no power-fail
> protection, so an interruption mid-write can leave the SD card unreadable until it is
> reformatted, and the node then runs with no storage at all. `SD_REPAIR:ON` lets a node
> rebuild its own card, which recovers most cases but not all, and erases the card.
- **SD writes survive a busy card.** An SD card acknowledges writes quickly until its internal buffers fill, then stalls while its controller commits to flash. The SD library waits a fixed 500 ms and gives up, so every write after that point returned zero while the node carried on as if the data had landed. Writes now flush and retry with backoff, and every writer in the firmware routes through that path: baseline, config, event log, results snapshot, probes, device database, detect features, randomization. Measured on a C5: the same capture went from 27 short writes to none.
- **A reset during a capture no longer costs the card.** FAT has no power-fail protection, so a reset mid-write left the card unmountable until a human wiped it. The filesystem is now synced after each write rather than on a timer, and the mount path retries with a full bus re-init. Measured on a C5: 1 of 4 resets survived before, 5 of 5 after. A node can also rebuild its own card with `SD_REPAIR:ON`, off by default because rebuilding erases it. A failed mount now reports its count and shows in Diagnostics instead of retrying silently forever.
- **Sentinel attack response**: pick which actions run on a confirmed attack with a source MAC — triangulate, packet capture, device discovery, probe sweep, drone RID — each with its own duration. Only one can hold the radio, so several selected run in that order one at a time as the radio frees up. Automatic captures are pruned against a size budget and a free-space floor.
- **CSI motion detection** (full + headless): device-free WiFi motion sensing on the WiDetect ACF statistic, per-area strength, no calibration; `CSI_CFG` config, `CSI_MOTION:`/`CSI_CLEAR:` mesh debounced to two lines per episode.
- **Triangulation target MAC is read and written atomically.** It was a plain 6-byte array written memset-then-memcpy while the web task, the sniffer callback and the scan task read it unsynchronised; a reader landing in that window saw a partly-written MAC, and at the match gate that silently dropped the peer's RSSI report.
- **Baseline no longer reboots** (`ESP_RST_PANIC`) under dense RF or long scans — internal-RAM exhaustion across several baseline paths fixed.
- SD writes fail soft under low heap: every SD open checks the internal-heap floor instead of aborting in `fopen`.
- BLE result buffer bounded — 150 in baseline, 200 in device/probe/triangulation/drone.
- Device-history table moved to PSRAM and bounded by free heap.
- Closed two use-after-free windows (baseline vs BLE radio task; WiFi scan-buffer pointer across an alloc).
- Baseline radio teardown fixed — no leftover promiscuous mode or hop timer, no competing WiFi scans mid-run.
- Task-creation failures are reported instead of leaving the node wedged.
- Mesh enable persists across reboot.
- Mesh TX can be cancelled without killing the running scan.
- An emoji in the Meshtastic sender name no longer drops the command.

| Build | Rebooted at | Lowest free internal heap |
|---|---|---|
| Unfixed | ~700 devices (`ESP_RST_PANIC`) | 508 B |
| Fixed — ESP32-S3 | 9,200+, no reboot (test stopped) | 33,528 B |
| Fixed — ESP32-C5 | 11,375, no reboot (test stopped) | 19,884 B |

### Full FW

- Scan Results no longer stalls mid-scan — `/results` streams from one PSRAM copy, the poll times out at 5 s, and text is marked seen only after it renders.
- Web UI polls only the visible page. The 1 s Scan Results re-render ran on every tab and swallowed taps on the page tab bar.
- Baseline results rebuild on the 2 s timer and only when something changed (was every packet, with serial spam).
- **CSI movement view**: plain-language state, a movement log, and a whole-session heat strip rendered on the device.
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): recolor the destructive controls, Sentinel banners and the movement hit color, five choices across all three themes, held in the browser.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colors).
- **Captures list** on the Scan tab: collapsible, one line per file with size, download and delete, delete-all behind a confirmation, and the file being recorded cannot be deleted.
- Recon & Detection method list regrouped into Recon, Detection and Capture.
- Clearing results clears the CSI history with it.
- Theme toggle stays in the mobile scan header.
- Fixed an unclosed container element in the web UI markup.

### Flasher

- Hidden AP toggle for full firmware.
- C5 experimental channel carries the same CSI, Fleet and fixes for testing.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl`.

## Upgrade notes

- Flash through the web flasher. No configuration changes required; existing SD baselines are read as-is.
