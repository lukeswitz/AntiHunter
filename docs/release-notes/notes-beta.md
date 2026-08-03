# AntiHunter v1.0.1-beta1 (beta)

Beta channel · Previous release v0.9.5 (2026-05-23)

## What's New

### Full FW

- Web UI rebuilt: mobile-responsive layout, single-row status header with auto-scrolling chips, one-card results, live sparklines, tabs rebuilt for readability.
- Tap any MAC in results to copy it to the clipboard.
- Mesh TX/RX queue status with a cancel button; Mesh Commands panel on the Live tab.
- Web privacy mode: redacts GPS, coordinates, SSIDs, device names, and node IDs.
- AP security selector (WPA2 / WPA3, PMF-capable).
- RF presets (50/50 WiFi/BLE split) with per-preset scan times shown.
- Tiered factory reset (full / config / data) from the web UI.
- Mesh command audit log to SD, serial, and `/api/mesh_cmd.jsonl` (every privileged command with issuing radio).

### Headless FW

- WiFi discovery is now passive: promiscuous all-channel capture for device, list, and baseline scans, no active probe frames. No SoftAP — quieter operation.
- No web UI: every scan, detector, and config listed under Both is driven over mesh commands and serial.
- Sentinel can run headless (serial / mesh only).

### Both

- Sentinel WiFi attack-detection engine, wired to mesh I/O: evil twin, KARMA bait, PMKID harvest, probe/auth flood, deauth, SAE flood, handshake capture, WiFi jamming, FragAttacks, and mesh spoof / command-injection / flood. Attacker-tool attribution (Marauder, Bruce). Heavy false-positive hardening (KRACK and whole-frame PN-replay emits removed; randomized/LAA BSSIDs skipped).
- Attacker reverse-triangulation: a confirmed attack carrying a source MAC (deauth flood, SAE DoS, PMKID, evil-twin, auth/probe flood, KARMA) auto-triangulates the offender. Opt-in, per-MAC cooldown.
- Vibration auto-scan: sensor movement auto-starts a chosen scan (all-device, probe, rand-MAC, list, drone, deauth, baseline); skips if a scan is running or in battery-saver.
- Per-device distance estimate and vendor (BLE SIG / OUI) in results output.
- Drone Remote ID over BLE and WiFi, full ODID parse, WiFi+BLE fused; scan-mode selector, transport tag, map link; mesh alerts on seen and disappear.
- Randomized-MAC tracer capacity raised 50/30 → 256/128, auto-eviction, 60s stale cleanup; devices flagged as randomized across other scans.
- Triangulation: weighted NLLS solver with real GDOP (replaces triplet averaging); distance calibration fixed; bad GPS anchors rejected; live position streamed as reports arrive.
- Mesh: priority queues, configurable dedup TTL, 230-byte frames, faster drain; fleet-wide scan-kill fixed (STOP_ACK no longer re-parsed as STOP).
- Authenticated remote erase: PSK-keyed HMAC-SHA256 challenge with a 300s one-time nonce; legacy token fallback until a PSK is set.
- CRC-fail (FCS) frames are rejected before any parser, so corrupt frames no longer produce duplicate or garbage devices.
- Deauth detection rides Sentinel's verdict: engine-confirmed, higher targeted threshold, ISR retransmit drops.
- Default WiFi channel set is 1-11.
- Platform: Arduino core 2.x → 3.x.

## Fixes

- Baseline STOP and anomaly reporting are now ~50ms (were ~30s); ~54-device crash fixed (MACs re-keyed to packed 64-bit in PSRAM).
- Long-run and cross-scan crashes: containers and queues moved to PSRAM, heap threshold lowered, more free heap at boot.
- BLE crashes: mesh-drain init race, NimBLE IPC stack overflow, NimBLE 2.x zero-devices.
- Randomization BOTH-mode reboot fixed.
- Concurrency audit: mutexes and lock-free ISR snapshots across WiFi RX, deauth, drone, sniffer, baseline, and triangulation; RSSI overflow and stack over-write fixed.
- Web results watchdog reboot fixed (compute-first, 2s cache); first-scan results no longer discarded.
- Config change mid-scan crash guarded (channel vector reallocated under the hop timer / RX callback).
- Identities no longer wiped each reboot (boot-timestamp underflow, micros() rollover).
- Mesh: double-strip that dropped triangulation / time-sync fixed; self-node update no longer stalls RX.
- Drone telemetry merge no longer drops speed / heading / height / vspeed; TLV/OUI out-of-bounds reads fixed; per-drone cooldown.
- AP client drops fixed (DHCPS re-apply killed, power-save off).
- Atomic config saves (`.bak` / `.tmp`); no config wipe on RECONFIG.
- Node IDs uppercased and validated on all mesh and NVS paths (were causing silent @TARGET misses).
- Malformed SSIDs rejected before results, mesh, and log.
