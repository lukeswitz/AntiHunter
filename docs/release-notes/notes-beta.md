# AntiHunter v1.0.2-beta1 (beta)

Beta channel · Previous release v1.0.1-beta2 (2026-08-07)

## What's Changed

### Both FW

- Randomized Device Tracer: a MAC could be linked into a second identity, so tracks listed other tracks' MACs and T- ids. A MAC now stays with the identity that owns it.
- Randomized Device Tracer: identity files on SD are repaired on load — a MAC held by several identities is dropped from all but its owner.
- Mesh send interval default 3000 ms, was 5000 ms. NVS seed, no-SD fallback and web field.
- Device Scan and Probe Scan no longer drop BLE for the whole run when the BLE radio comes up after the scan starts.
- A slow BLE bring-up is no longer a permanent failure. It used to abort every BLE-only randomization scan until reboot.
- `SENTINEL_MODE` persists. It applied at runtime but was never written to NVS, so a reboot lost it.
- `ATTACKER_TRILAT:on` turned attacker triangulation off. Only a number worked; `on` and `true` are now accepted.
- Target Scan swept one channel per pass, not all of them, reporting a third of what a Device Scan saw. On hardware: Unique 24 before, 70 after, against 75 for a Device Scan.
- Baseline learns WiFi client stations, not just APs. It ran with promiscuous capture off, so non-APs never entered the baseline.
- Triangulation no longer refuses to pin above channel 14, which blocked every 5 GHz target on C5.
- Sentinel evil-twin `SSID_COLLISION` alerted on ordinary neighbour networks — two vendors sharing an SSID was the whole test, and at scan start every AP is new. Sentinel now learns an SSID's vendor OUIs for five minutes and alerts only on an OUI outside that baseline. A twin already transmitting at boot is inside the baseline and will not raise this reason; `TWIN_MULTICH`, `TSF_RESTART` and `SELF_CLONE` are unchanged.
- Mesh `EVILTWIN` carries the SSID: `EVILTWIN:<bssid>:<reason>:<rssi>:<ssid>`.

### Headless FW

- Sentinel booted pinned to one channel whatever the mode. Boot overwrote the saved scan/pin setting, discarding the NVS value and any `sentinel_scan` from the setup config. The rationale for that overwrite — hopping breaking the node's own AP — is Full-only; Headless has no AP. On hardware: an evil-twin on channel 2 is now caught after a cold boot with no commands sent.
- Device Scan, Target Scan and Baseline sweep all channels again. Passive capture replaced the sweep on 2026-07-31 and was never restored here, leaving `WiFi APs=0` over a full minute. After the fix: 53 APs.
- Target Scan in WiFi+BLE started BLE before the WiFi mode switch landed on top of it, so BLE was skipped.
- BLE devices advertising Apple continuity are marked `APPLE`, matching Full.

### Full FW

- `GROUP`, `DETECT_CFG`, `DETECT_CFG_GET`, `INCIDENTS` and `INCIDENTS_CLEAR` work over mesh. Headless-only before, so a Full node on LoRa could start scans but not configure detectors without the AP and a browser.
- Randomization results: each MAC row and the track header carry that track's own Track ID.
- Randomization results: Live sessions starts collapsed, stays open once opened, and sits below the Track ID cards.

### Flasher

- Sentinel & Detectors panel is hidden on Stable. Stable builds with `AH_SENTINEL=0` and silently dropped those keys.
- `flashAntihunter.sh` no longer clones a third-party esptool. It uses `esptool` or `esptool.py` from your PATH, or prints the apt/dnf/pacman/brew install command and stops.
- Flashing requires accepting the Legal Disclaimer; the flash button stays disarmed until the box is ticked.

### Experimental

On the Experimental C5 flasher channel, for testing:

- ESP32-C5 full and headless carry the same randomization identity fix.
- ESP32-C5 full and headless carry the same sentinel channel-mode, `ATTACKER_TRILAT`, `APPLE`, `SSID_COLLISION` and Full-mesh-command changes.
