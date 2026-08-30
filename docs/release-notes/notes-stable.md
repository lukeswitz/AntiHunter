# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

**Headline:** Baseline Detection no longer reboots under dense RF or on long runs.

## What's Changed

### Both FW

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
- Baseline results rebuild on the 2 s timer and only when something changed (was every packet, with serial spam).
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colours** (System tab): recolour the destructive controls and Sentinel banners, five choices across all three themes, held in the browser.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colours).
- Theme toggle stays in the mobile scan header.

### Flasher

- Hidden AP toggle for full firmware.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl` (tripod inset centred, geometry otherwise unchanged).

## Upgrade notes

- Flash through the web flasher. S3 stable is on `main`; the C5 build ships through the Experimental channel.
- No configuration changes required. Existing SD baselines are read as-is.
