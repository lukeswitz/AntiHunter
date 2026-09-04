# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

## What's Changed

### Both FW

- **Packet capture to SD** (full + headless): writes a standard pcap Wireshark opens. WiFi frames carry a full radiotap header with channel, data rate and RSSI; BLE advertisements are written as link-layer PDUs so they dissect as ADV_IND, ADV_DIRECT_IND and SCAN_RSP. Start it from the Scan tab, or over mesh with `PCAP_START:radio:secs:band[:FOREVER]` and `PCAP_STOP`.
- **Packet capture is bounded.** A capture used to run until stopped, and a forever run filled the card, drove every write to failure and left the filesystem damaged. It now stops on its own at a file size cap you set, 8 to 300 MB and 100 MB by default, at the free-space floor, or after three consecutive failed writes, and the mesh reply says which: `R=SIZECAP` or `R=WRITEFAIL`. The free-space floor now applies to every capture; it previously only guarded automatic ones, which is how a mesh-started capture bypassed it.
- **SD writes survive a busy card.** A card acknowledges writes quickly until its internal buffers fill, then stalls while its controller commits to flash. The SD library waits a fixed 500 ms and gives up, so every write after that returned zero while the node carried on as if the data had landed. Writes now flush and retry with backoff.
- **A reset during a capture is far less likely to cost the card.** FAT has no power-fail protection, so a reset mid-write could leave the card unmountable until it was wiped. The filesystem is synced after each write rather than on a timer, and the mount path retries with a bus re-init. Set the cap on the Scan tab, in the sentinel auto-response panel, or over mesh with `PCAP_LIMITS`. A node can rebuild its own card with `SD_REPAIR:ON`, off by default because rebuilding erases it. A failed mount now reports its count and shows in Diagnostics instead of retrying silently.

> [!WARNING]
> Stop a capture before cutting power or resetting the node. FAT has no power-fail
> protection, so an interruption mid-write can leave the SD card unreadable until it is
> reformatted, and the node then runs with no storage at all. `SD_REPAIR:ON` lets a node
> rebuild its own card, which recovers most cases but not all, and erases the card.
- **Sentinel attack response**: pick which actions run on a confirmed attack with a source MAC — triangulate, packet capture, device discovery, probe sweep, drone RID — each with its own duration. Only one can hold the radio, so several selected run in that order one at a time as the radio frees up. Automatic captures are pruned against a size budget and a free-space floor.
- **Triangulation target MAC is read and written atomically.** It was a plain 6-byte array written memset-then-memcpy while the web task, the sniffer callback and the scan task read it unsynchronised; a reader landing in that window saw a partly-written MAC, and at the match gate that silently dropped the peer's RSSI report.
- **Baseline no longer reboots** (`ESP_RST_PANIC`) under dense RF or long scans — internal-RAM exhaustion across several baseline paths fixed.
- SD writes fail soft under low heap: every SD open checks the internal-heap floor instead of aborting in `fopen`.
- BLE result buffer bounded — 150 in baseline, 200 in device/probe/triangulation/drone.
- Device-history table moved to PSRAM and bounded by free heap.
- Closed two use-after-free windows (baseline vs BLE radio task; WiFi scan-buffer pointer across an alloc).
- Baseline radio teardown fixed — no leftover promiscuous mode or hop timer, no competing WiFi scans mid-run.
- Mesh enable persists across reboot.
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
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colors** (System tab): recolor the destructive controls and Sentinel banners, five choices across all three themes, held in the browser.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colors).
- **Captures list** on the Scan tab: collapsible, one row per file with a WiFi or BLE icon, the capture time, size, and download and delete icons. Delete-all sits behind a confirmation, and the file being recorded cannot be deleted.
- Recon & Detection method list regrouped into Recon, Detection and Capture.
- Theme toggle stays in the mobile scan header.
- Fixed an unclosed container element in the web UI markup.

### Flasher

- Hidden AP toggle for full firmware.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl` (tripod inset centered, geometry otherwise unchanged).

## Upgrade notes

- Flash through the web flasher. S3 stable is on `main`; the C5 build ships through the Experimental channel.
- No configuration changes required. Existing SD baselines are read as-is.
