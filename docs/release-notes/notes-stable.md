# AntiHunter v1.0.2 (stable)

Stable channel · Previous release v1.0.1 (2026-08-07)

## What's Changed

### Both FW

- Randomized Device Tracer: a MAC could be linked into a second identity, so tracks listed other tracks' MACs and T- ids. A MAC now stays with the identity that owns it.
- Randomized Device Tracer: identity files on SD are repaired on load — a MAC held by several identities is dropped from all but its owner.
- Mesh send interval default 3000 ms, was 5000 ms. NVS seed, no-SD fallback and web field.
- Device Scan and Probe Scan no longer drop BLE for the whole run when the BLE radio comes up after the scan starts.
- A slow BLE bring-up is no longer a permanent failure. It used to abort every BLE-only randomization scan until reboot.
- Target Scan swept one channel per pass, not all of them, reporting a third of what a Device Scan saw. On hardware: Unique 24 before, 70 after, against 75 for a Device Scan.
- Baseline learns WiFi client stations, not just APs. It ran with promiscuous capture off, so non-APs never entered the baseline.

### Headless FW

- Device Scan, Target Scan and Baseline sweep all channels again. Passive capture replaced the sweep on 2026-07-31 and was never restored here, leaving `WiFi APs=0` over a full minute. After the fix: 53 APs.
- Target Scan in WiFi+BLE started BLE before the WiFi mode switch landed on top of it, so BLE was skipped.
- BLE devices advertising Apple continuity are marked `APPLE`, matching Full.

### Full FW

- Randomization results: each MAC row and the track header carry that track's own Track ID.
- Randomization results: Live sessions starts collapsed, stays open once opened, and sits below the Track ID cards.

### Flasher

- Sentinel & Detectors panel is hidden on Stable. Stable builds with `AH_SENTINEL=0` and silently dropped those keys.
- `flashAntihunter.sh` no longer clones a third-party esptool. It uses `esptool` or `esptool.py` from your PATH, or prints the apt/dnf/pacman/brew install command and stops.
- Flashing requires accepting the Legal Disclaimer; the flash button stays disarmed until the box is ticked.
