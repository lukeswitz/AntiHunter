# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

**Headline:** CSI motion detection, and Baseline Detection no longer reboots under dense RF or on long runs.

## What's Changed

### Both FW

- **CSI motion detection** (full + headless): device-free WiFi motion sensing on the WiDetect ACF statistic, per-area strength, no calibration; `CSI_CFG` config, `CSI_MOTION:`/`CSI_CLEAR:` mesh debounced to two lines per episode.
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
- Baseline results rebuild on the 2 s timer and only when something changed (was every packet, with serial spam).
- **CSI movement view**: plain-language state, a movement log, and a whole-session heat strip rendered on the device.
- **Fleet roster** (System tab): live mesh node/radio roster, a card for this node, per-node mode/uptime/temp/hits/GPS, privacy redaction, collapsible.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS (default off), carried in config export/import and `/wifi-config`; stops the beacon, not access control.
- Data Explorer privacy toggle.
- **Accent Colours** (System tab): recolour the destructive controls, Sentinel banners and the movement hit colour, five choices across all three themes, held in the browser.
- Dark theme destructive controls are now acid lime (was brick red; still selectable under Accent Colours).
- Clearing results clears the CSI history with it.
- Theme toggle stays in the mobile scan header.

### Flasher

- Hidden AP toggle for full firmware.
- C5 experimental channel carries the same CSI, Fleet and fixes for testing.

### Hardware

- DIGINODE v2 side-charge enclosure prints as one body — `SinglePrintSideChargeHousing.stl`.

## Upgrade notes

- Flash through the web flasher. No configuration changes required; existing SD baselines are read as-is.
