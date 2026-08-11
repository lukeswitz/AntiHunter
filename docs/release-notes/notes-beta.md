# AntiHunter v1.0.2-beta1 (beta)

Beta channel · Previous release v1.0.1-beta2 (2026-08-07)

## What's Changed

### Both FW

- Randomized Device Tracer: a MAC could be linked into a second identity, so a track listed MACs belonging to other tracks and its badges showed their T- ids. A MAC is now attributed to the identity that already owns it.
- Randomized Device Tracer: identity files already written to SD are repaired on load — MACs held by more than one identity are dropped from every identity but their owner.
- Mesh send interval default is 3000 ms, was 5000 ms. Applies to the NVS seed, the no-SD fallback, and the web field.
- Device Scan and Probe Scan no longer drop BLE for a whole run when the BLE radio finishes coming up after the scan starts.
- A slow BLE bring-up is no longer recorded as a permanent failure. Randomization in BLE-only mode used to abort every scan until reboot.

### Full FW

- Randomization results: each MAC row and the track header carry that track's own Track ID.
- Randomization results: Live sessions starts collapsed, stays open once you open it, and sits below the Track ID cards.

### Flasher

- Sentinel & Detectors config panel is hidden on the Stable channel. Stable firmware builds with `AH_SENTINEL=0` and silently dropped those keys.

### Experimental

On the Experimental C5 flasher channel, for testing:

- ESP32-C5 full and headless carry the same randomization identity fix.

### Docs

- README: deployment steps by tier
- README: mesh radio setup with `scripts/meshtastic_config.py`
- README: images served from the repo, capped at 1200px wide
- BOM: image attribution disclaimer
