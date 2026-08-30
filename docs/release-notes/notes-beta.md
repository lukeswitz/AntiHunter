# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

Headline: CSI motion detection, and Baseline Detection no longer reboots under dense RF or on long runs.

## What's Changed

### Both FW

- CSI motion detection. The node reads WiFi channel state information and reports movement in the area, no target device required. Detection runs on an autocorrelation statistic rather than raw amplitude. Strength is reported per area, not per link, and no calibration step is required before use. Configured over `CSI_CFG`, emits `CSI_MOTION:` and `CSI_CLEAR:` on the mesh, debounced to two lines per episode. Present in both the full and headless trees.
- Baseline Detection could reset the device with `[Recovered after reset: PANIC]`, most often in busy areas or after a long scan. Root cause was internal-RAM exhaustion: several baseline paths spent the small internal heap until an allocation failed and the firmware aborted.
- SD writes fail soft under low heap. Opening a file allocates from internal RAM, and when that RAM is gone the underlying `fopen` aborts instead of returning an error. Every SD open now checks the internal-heap floor first and skips the write if it is too low. Applied to every SD path in the app, not only baseline.
- BLE result buffer is bounded — 150 in baseline, 200 in the device, probe, triangulation and drone scans. It was unbounded and lived in internal RAM.
- Device-history table lives in PSRAM. It no longer consumes internal heap as it grows, and is additionally bounded by free heap.
- Two use-after-free windows closed. Baseline read the BLE result list while the radio task was still writing to it, and held a pointer into the WiFi scan buffer across an allocation that other tasks could free.
- Radio teardown fixed. Ending a baseline run on Full left promiscuous mode and the channel-hop timer running, and baseline could start competing WiFi scans while active.
- Task creation failures are reported instead of leaving the node wedged.
- Mesh enable state persists across reboot.
- Mesh TX can be cancelled without killing the running scan.
- An emoji in the Meshtastic sender name dropped the command.

Baseline was measured on hardware with a second ESP32 flooding the node with rotating BLE and WiFi devices. The failure point is the total distinct devices tracked when the node rebooted.

| Build | Rebooted at | Lowest free internal heap |
|---|---|---|
| Unfixed | ~700 devices (`ESP_RST_PANIC`) | 508 bytes |
| Fixed — ESP32-S3 | 9,200+, no reboot, test stopped | 33,528 bytes |
| Fixed — ESP32-C5 | 11,375, no reboot, test stopped | 19,884 bytes |

### Full FW

- Movement view for CSI: plain-language state, a movement log, and a whole-session heat strip rendered on the device.
- Hidden SoftAP. RF Settings checkbox, `apHidden` in NVS, default off, carried in config export and import and on `/wifi-config`. The boot banner reports hidden or broadcast. Hidden stops the beacon; it is not access control.
- Fleet roster in the web UI.
- Data Explorer privacy toggle.
- Accent Colors, in the System tab. Sets the color of the destructive controls — STOP, the wipe buttons, Clear, error toasts, danger badges — of the Sentinel banners and of the movement hit color. Five choices each, applied across all three themes. Held in the browser, not written to the node.
- On the dark theme the destructive controls are acid lime, was brick red. Light and cyber are unchanged. Brick red is still available under Accent Colors.
- Clearing results clears the CSI history with it.
- Theme toggle stays in the mobile scan header.

### Flasher

- Hidden AP toggle for full firmware.

## Upgrade notes

- Flash as usual through the web flasher.
- No configuration changes are required. Existing baselines on SD are read as-is.
