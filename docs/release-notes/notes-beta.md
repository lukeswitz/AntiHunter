# AntiHunter v1.0.2-beta1 (beta)

Beta channel · Previous release v1.0.1-beta2 (2026-08-07)

## What's Changed

### Both FW

- Randomized Device Tracer: a MAC could be linked into a second identity, so a track listed MACs belonging to other tracks and its badges showed their T- ids. A MAC is now attributed to the identity that already owns it.
- Randomized Device Tracer: identity files already written to SD are repaired on load — MACs held by more than one identity are dropped from every identity but their owner.
- Mesh send interval default is 3000 ms, was 5000 ms. Applies to the NVS seed, the no-SD fallback, and the web field.
- Device Scan and Probe Scan no longer drop BLE for a whole run when the BLE radio finishes coming up after the scan starts.
- A slow BLE bring-up is no longer recorded as a permanent failure. Randomization in BLE-only mode used to abort every scan until reboot.
- `ATTACKER_TRILAT:on` turned attacker triangulation off. Only a numeric argument worked; `on` and `true` are now accepted.
- Target Scan swept one channel per pass instead of all of them, so it reported roughly a third of the devices a Device Scan found in the same spot. Measured on hardware: Unique 24 before, 70 after, against 75 for a Device Scan.
- Baseline learns WiFi client stations, not just APs. It ran with promiscuous capture off, so anything that was not an AP never entered the baseline.
- Triangulation no longer refuses to pin above channel 14, which blocked every 5 GHz target on C5.

### Headless FW

- Sentinel fixed, was not starting or accepting commands
- Sentinel booted pinned to a single channel no matter what mode was set. Boot overwrote the saved scan/pin setting, discarding both the NVS value and any `sentinel_scan` sent in the setup config, so sentinel only ever heard one channel. The reason for that overwrite — channel hopping breaking the node's own AP — does not apply to Headless, which has no AP. Verified on hardware: an evil-twin on channel 2 is now caught after a cold boot with no commands sent.
- Device Scan, Target Scan and Baseline run an active all-channel sweep again. It was removed on 2026-07-31 in favour of passive capture and never restored on Headless, leaving Device Scan reporting `WiFi APs=0` over a full minute. Hardware after the fix: 53 APs.
- Target Scan in WiFi+BLE mode started BLE before the WiFi mode switch landed on top of it, so BLE was skipped.
- BLE devices advertising Apple continuity are marked `APPLE` in sniffer results, matching Full.

### Full FW

- `GROUP`, `DETECT_CFG`, `DETECT_CFG_GET`, `INCIDENTS` and `INCIDENTS_CLEAR` now work over mesh. They were Headless-only, so a Full node driven over LoRa could start scans but could not configure detectors without bringing up the AP and opening the browser.

- Randomization results: each MAC row and the track header carry that track's own Track ID.
- Randomization results: Live sessions starts collapsed, stays open once you open it, and sits below the Track ID cards.

### Flasher

- Sentinel & Detectors config panel is hidden on the Stable channel. Stable firmware builds with `AH_SENTINEL=0` and silently dropped those keys.

### Experimental

On the Experimental C5 flasher channel, for testing:

- ESP32-C5 full and headless carry the same randomization identity fix.
- ESP32-C5 full and headless carry the same sentinel channel-mode, `ATTACKER_TRILAT`, `APPLE` and Full-mesh-command changes.

### Docs

- README: Full vs Headless — what each build can do, and which result fields are data both builds emit versus rendering only the web UI does
- README: `GROUP` membership, `DETECT_CFG` coverage, and that group changes persist to NVS
- README: deployment steps by tier
- README: mesh radio setup with `scripts/meshtastic_config.py`
- README: images served from the repo, capped at 1200px wide
- BOM: image attribution disclaimer
