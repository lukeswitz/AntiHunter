# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-13)

## New

### Both FW

- **CSI motion detection** (experimental beta, ESP32-S3): movement in a room from ambient WiFi; nothing worn or joined.
  - Reports through walls.
  - Scan tab → CSI Motion; presets Low / Medium / High.
  - Mesh: `CSI_MOTION_START:secs[:CH<n>][:FOREVER]`, `CSI_CFG`, `CSI_RECAL`, `CSI_STATUS`, `CSI_JSON`, `CSI_EXCLUDE`.
  - Listen-only by default; `ALLOW_TRANSMIT` lets the node send probe requests for more traffic.
  - Alerts: `CSI_MOTION:` / `CSI_CLEAR:` on mesh, serial and SD.
  - Sensitivity is per receiver; a value tuned on one board does not transfer.
  - ESP32-C5: in testing; separates movement from background less cleanly.
  - No long-run false-alarm rate measured yet.
- **Packet capture to SD**: Wireshark pcap, WiFi radiotap, BLE PDUs.
  - `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`, `PCAP_STOP`, vibration mode 8, Scan tab.
  - Stops at a size cap (8–300 MB, default 100), free-space floor, or write failures.
  - Size cap: Scan tab, Sentinel panel, or `PCAP_LIMITS:<MB>`.
  - Stop line reports channels visited.
- **Sentinel attack response**: triangulate, capture, discovery, probe sweep, drone RID; each timed, run in turn.
- `SD_REPAIR:ON` lets a node rebuild an unmountable card (erases it; off by default).
- `MESH_TX_CANCEL` and the UI cancel clear the mesh queue without stopping the scan.
- **Local time, at last.** Logs and capture names use your timezone, DST included, worked out from the GPS fix. UTC until it locks.
- SD bus at 16 MHz (was 400 kHz); 4 MHz and 400 kHz fallbacks.
- Mesh on/off saved across reboots.
- Boot `[MEM]` ladder and a `[HEAP]` line every 30 s on serial.
- Task-creation failures logged with free and largest internal block.
- Headless: discovered devices persist across scans (device DB).

### Full FW

- **CSI movement view**: quiet / moving / can't measure, movement log, whole-session heat strip.
  - Heat blocks shaded by movement events, eight accent-color steps; tap for time.
  - Blocks widen from 1 to 5, 15, 30 min and up as the session ages.
- **Fleet roster** (System tab): mesh nodes and radios, per-node mode/uptime/temp, privacy toggle.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS, default off. Stops the beacon only.
- **Accent Colors** (System tab): five choices; destructive controls, Sentinel, movement hits.
  - Sentinel and movement default to copper; dark-theme danger defaults to acid lime.
- Data Explorer privacy toggle.
- Captures list on the Scan tab: download, delete, delete-all with confirm.
- Method dropdown regrouped: Recon, Detection, Capture.
- Results clear when a new scan starts; clearing results clears the CSI history.
- Page reloads when the browser lands on a different node.
- Web UI polls only the open tab.

## Fixed

### Both FW

- Long BLE device scans no longer abort in `fopen` (field report on v1.0.2).
  - NimBLE pools and small allocations now come from PSRAM.
  - Pre-fix beta: abort at 123 injected devices, 11,676 B free. Now 64,404 B at 200.
- Baseline no longer reboots under dense RF.
  - Device history keyed by MAC, in PSRAM, bounded by free heap.
  - Task locals freed before task exit (leaked ~96 B per device per scan).
  - Resident task stacks in PSRAM (18,432 B internal freed).
  - NimBLE per-window scan cache capped at 200 (150 baseline); total devices seen is not capped.
  - Two use-after-free windows closed (baseline BLE task, WiFi scan buffer).
  - Baseline exit stops promiscuous mode and the hop timer; no competing scans mid-run.
- A queued mesh backlog no longer blocks starting a scan.
- Log file held open across writes; reopened only after a failed write.
- Results snapshot written to a temp file, then renamed.
- SD writes retry with backoff on a busy card.
- SD mount retries with a bus re-init; failures logged once a minute, counted in Diagnostics.
- SD chip-select driven high before the SPI bus starts.
- Peer node reports are never run as commands.
- Emoji-only Meshtastic sender names no longer drop commands (#31).
- Triangulation target MAC is atomic; torn reads dropped peer RSSI reports.
- Diagnostics `Mesh TX` line no longer sticks at draining.
- `STOP` no longer waits on a scan that can't finish.
- `DEVICE_SCAN_START` honors `+PROBE` in any position.
- `SCAN_START:mode:secs:FOREVER` runs forever without a channel list.
- AP MAC randomization fix.
- `memcpy` length guard against a WiFi driver underflow.
- Headless: triangulation stop is honored during the ACK and report waits.
- Headless: baseline MAC queue sends go through the guarded path.

### Full FW

- Scan Results page no longer freezes mid-scan; `/results` streams from PSRAM.
- Theme toggle stays in the mobile scan header during a scan.
- Baseline results rebuild every 2 s, only on change.

## Hardware

- DIGINODE v2 side-charge enclosure single-body model: `One-Piece-Housing-SideCharge-Version.stl`.
- Revised full side-charge housing: `FullSideChargeHousing.stl`.
- Front cover with a hidden 10 mm fan: `FrontCover-Hidden-Fan-10mm.stl`.
- Assembly manual, BOM links and welcome note updated.

## Upgrade

Settings in NVS and files on the SD card survive a flash without erase.

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Channel Beta, then Full or Headless.

**Flasher script** (needs Python 3, esptool and pyserial):

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/beta/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

Pick channel 2 (Beta). `-e` erases first, `-c` sets device parameters during the flash, `-l` lists the firmware.

**PlatformIO**:

```bash
git clone -b beta https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
```

`AntiHunter-headless` for the mesh-only build. `-t erase` wipes the chip first.

## Thanks

- rcbm. and d3mo for the bug reports.
