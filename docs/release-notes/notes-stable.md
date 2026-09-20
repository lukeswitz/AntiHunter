# AntiHunter v1.0.3 (stable)

Stable channel · Previous release v1.0.2 (2026-08-13)

## New

### Both FW

- **Packet capture to SD**: Wireshark pcap, WiFi radiotap, BLE PDUs.
  - `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`, `PCAP_STOP`, Scan tab.
  - Stops at a size cap (8–300 MB, default 100), free-space floor, or write failures.
  - Size cap: Scan tab or `PCAP_LIMITS:<MB>`.
  - Stop line reports channels visited.
- **Vibration auto-scan** (System tab → Sensor Alerts): pick the scan that runs when the node is bumped, packet capture included. Mesh: `VIBSCAN_SET`, `VIBSCAN_STATUS`.
- **Sentinel attack response**: triangulate, capture, discovery, probe sweep, drone RID; each timed, run in turn.
- `SD_REPAIR:ON` lets a node rebuild an unmountable card (erases it; off by default).
- **Local time.** Logs and capture names in your timezone, DST included. The RTC keeps the clock; the GPS fix tells the node which zone it sits in. Before the first fix after a boot it shows UTC.
- SD bus at 16 MHz (was 400 kHz); 4 MHz and 400 kHz fallbacks.
- Mesh on/off saved across reboots.
- Boot `[MEM]` ladder and a `[HEAP]` line every 30 s on serial.

### Full FW

- **Fleet roster** (System tab): mesh nodes and radios, per-node mode/uptime/temp, privacy toggle.
- **Hidden SoftAP**: RF Settings toggle, `apHidden` in NVS, default off. Stops the beacon only.
- **Accent Colors** (System tab): five choices for destructive controls and Sentinel banners.
  - Sentinel defaults to copper; dark-theme danger defaults to acid lime.
- Data Explorer privacy toggle.
- Captures list on the Scan tab: download, delete, delete-all with confirm.
- Method dropdown regrouped: Recon, Detection, Capture.
- Results clear when a new scan starts.
- Page reloads when the browser lands on a different node.
- Web UI polls only the open tab.

## Fixed

### Both FW

- Long BLE device scans no longer abort in `fopen` (field report).
  - NimBLE pools and small allocations now come from PSRAM.
  - v1.0.2: abort at 194 injected devices, 1,672 B free. Now 98,376 B at 200.
- Baseline no longer reboots under dense RF.
  - Device history keyed by MAC, in PSRAM, bounded by free heap.
  - Task locals freed before task exit (leaked ~96 B per device per scan).
  - Resident task stacks in PSRAM (18,432 B internal freed).
  - NimBLE per-window scan cache capped at 200 (150 baseline); total devices seen is not capped.
  - Two use-after-free windows closed (baseline BLE task, WiFi scan buffer).
  - Baseline exit stops promiscuous mode and the hop timer; no competing scans mid-run.
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

### Full FW

- Scan Results page no longer freezes mid-scan; `/results` streams from PSRAM.
- Baseline no longer runs forever when only the other panel's Forever box was ticked; a hidden Forever box no longer submits.
- Theme toggle stays in the mobile scan header during a scan.
- Baseline results rebuild every 2 s, only on change.

## Hardware

- DIGINODE v2 side-charge enclosure single-body model: `One-Piece-Housing-SideCharge-Version.stl`.
- Revised full side-charge housing: `FullSideChargeHousing.stl`.
- Front cover with a hidden 10 mm fan: `FrontCover-Hidden-Fan-10mm.stl`.
- Assembly manual, BOM links and welcome note updated.

## Upgrade

Settings in NVS and files on the SD card survive a flash without erase.

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Channel Stable, then Full or Headless.

**Flasher script** (needs Python 3, esptool and pyserial):

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

Pick channel 1 (Stable). `-e` erases first, `-c` sets device parameters during the flash, `-l` lists the firmware.

**PlatformIO**:

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
```

`AntiHunter-headless` for the mesh-only build. `-t erase` wipes the chip first.

## Thanks

- rcbm. and d3mo for the bug reports.
