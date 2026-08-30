# AntiHunter v1.0.3

Stable release. Headline: Baseline Detection no longer reboots under dense RF or long runs. Applies to the S3 (`main`/`beta`) and C5 (experimental) builds, full and headless.

- [Baseline stability](#baseline-stability)
- [Other changes](#other-changes)
- [Upgrade notes](#upgrade-notes)

---

## Baseline stability

Baseline Detection could reset the device with `[Recovered after reset: PANIC]`, most often in busy areas or after the device had been scanning for a while. Root cause was internal-RAM exhaustion: several baseline paths spent the small internal heap until an allocation failed and the firmware aborted. Reproduced on hardware at 6000+ tracked devices with a decoded backtrace, then fixed at the source.

What changed:

- **SD writes fail soft under low heap.** Opening a file allocates from internal RAM; when that RAM is exhausted the underlying `fopen` aborts instead of returning an error. Every SD open now checks the internal-heap floor first and skips the write if it is too low, so a starved heap drops one write instead of rebooting. This guard is applied to every SD path in the app, not just baseline.
- **BLE result buffer is bounded.** The BLE scan result list was unbounded and lived in internal RAM; a dense environment grew it without limit. It is now capped.
- **Device-history table moved off internal RAM.** The per-device history is now keyed so the whole table lives in PSRAM. It no longer consumes internal heap as it grows, and is additionally bounded by free heap.
- **BLE scan-result race removed.** Baseline read the BLE result list while the radio task was still writing to it. Baseline now stops the scan before reading and restarts after, closing a use-after-free window.
- **WiFi scan-result race removed.** Baseline held a pointer into the WiFi scan buffer across an allocation while other tasks could free it. It now copies the address immediately.
- **Radio teardown fixed.** On the full build, ending a baseline run left promiscuous mode and the channel-hop timer running. Baseline now shuts them down on exit, and no longer starts competing WiFi scans while a baseline is active.

Measured on an S3 under an identical dual-radio stress load (BLE advert flood + WiFi beacon flood), 7000+ tracked devices:

| | Before | After |
|---|---|---|
| Lowest free internal heap | 508 bytes | 33,528 bytes |
| Reboots during the run | 1 (`ESP_RST_PANIC`) | 0 |

## Other changes

- Data Explorer privacy toggle.
- Mesh enable state persists across reboot.
- Theme toggle kept in the mobile scan header.
- Fleet roster in the full web UI.
- Mesh sender-name handling; emoji sender no longer drops commands (#31).

## Upgrade notes

- Flash as usual through the web flasher. S3 stable is on `main`/`beta`; the C5 build ships through the Experimental channel.
- No configuration changes are required. Existing baselines on SD are read as-is.
