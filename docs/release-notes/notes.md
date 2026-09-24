# AntiHunter v1.0.3

CSI motion, packet capture, Sentinel response, local time, fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.3 | ESP32-S3 | v1.0.2 (2026-08-13) |
| Beta | v1.0.3-beta1 | ESP32-S3 | v1.0.2-beta1 (2026-08-13) |
| Experimental | v1.0.3-c5exp1 | XIAO ESP32-C5 | v1.0.2-c5exp1 (2026-08-13) |

## New

- **Packet capture to SD.** Wireshark-ready pcap, WiFi and BLE.
  - Start from the Scan tab, vibration, or `PCAP_START`.
  - `PCAP_START:radio:secs:band[:CH<list>][:FOREVER]`; `PCAP_STOP` ends it.
  - Size cap 8–300 MB, default 100 (`PCAP_LIMITS:<MB>`).
  - Also stops at the free-space floor or repeated write failures.
  - The stop line lists the channels visited.
- **Sentinel attack response.** Runs your picks on a confirmed attack.
  - Triangulate, capture, discovery, probe sweep, drone RID.
  - Each runs for its own duration, one after another.
- **Vibration auto-scan** (new on stable): a bump starts a scan.
  - System tab → Sensor Alerts; packet capture included.
  - Mesh: `VIBSCAN_SET`, `VIBSCAN_STATUS`.
- **Local time.** Logs and capture names use your timezone.
  - DST included. The RTC keeps time; GPS sets the zone.
  - Shows UTC until the first fix after boot.
- **SD self-repair.** Rebuilds an unmountable card. Off by default.
  - System tab → Node Configuration, or `SD_REPAIR:ON`.
  - "Repair now" runs it on demand. Rebuilding erases the card.
- **Fleet roster** (System tab): nodes, radios, mode, uptime, temperature.
- **Hidden SoftAP** (RF Settings): stops the beacon. Not access control.
- **Accent colors** (System tab): five schemes for buttons and banners.
- Captures list on the Scan tab: download, delete, delete-all.
- Data Explorer privacy toggle.
- Method dropdown regrouped: Recon, Detection, Capture.
- `MESH_TX_CANCEL` clears the mesh queue; the scan keeps running.
- A queued backlog no longer blocks starting a scan.
- Mesh on/off is saved across reboots.
- SD bus at 16 MHz; 4 MHz, 400 kHz fallbacks.
- Boot prints a `[MEM]` ladder; `[HEAP]` every 30 s.
- The web flasher and script `-c` set all of these.

### Beta and C5

- **CSI motion detection** (S3 beta, C5 testing).
  - Detects people moving, through walls.
  - Scan tab → CSI Motion, or the mesh commands below.
  - Ignores randomized MACs by default.

| Command | Does |
|---|---|
| `CSI_MOTION_START:secs[:CH<n>][:FOREVER]` | Start |
| `CSI_CFG:SENSITIVITY=LOW\|MEDIUM\|HIGH` | Sensitivity |
| `CSI_CFG:BROADCAST=OFF` | Stop probing |
| `CSI_CFG:ALLOW_RANDOM=ON` | Use randomized MACs |
| `CSI_CFG:SPOTS=<n>` | Devices needed to alert |
| `CSI_CFG:MIN_MOTION=<s>` / `CLEAR_AFTER=<s>` | Alert and clear timing |
| `CSI_CFG:CH=<n>` | Pin a channel; `0` picks |
| `CSI_EXCLUDE:<MAC>` | Ignore a MAC until reboot |
| `CSI_STATUS` / `CSI_JSON` | Report |
| `CSI_RECAL` | Clear a saved threshold |

> [!IMPORTANT]
> **Transmits by default.** Probes are visible. Check local law.

- **CSI movement view** (web UI): state, log, heat strip.
- Accent colors also cover movement hits.
- Headless: discovered devices persist across scans.
- Task-creation failures log the free and largest block.

### C5 only

> [!NOTE]
> **Breadboard the C5 before soldering.**
> A soldered C5 can't return to stable firmware.

- **CSI motion, in testing on the C5.** Own presets.
  - Detects less cleanly than an S3.
  - Details: [docs/ESP32-C5.md](https://github.com/lukeswitz/AntiHunter/blob/feat/c5/docs/ESP32-C5.md).
- **Packet capture band:** 2.4 GHz, 5 GHz, or both.

## Fixed

- **Long BLE scans no longer abort in `fopen`.**
  - NimBLE pools and small allocations moved to PSRAM.
- **Baseline no longer reboots under dense RF.**
  - Device history and task stacks moved to PSRAM.
  - Task memory freed on exit.
  - NimBLE scan cache capped.
  - Two use-after-free windows closed.
  - Exit stops promiscuous mode and the hop timer.
- `STOP` no longer waits on a scan that can't finish.
- `DEVICE_SCAN_START` honors `+PROBE` in any position.
- `SCAN_START:mode:secs:FOREVER` runs without a channel list.
- Baseline no longer runs forever from another panel's box.
- Peer node reports are never run as commands.
- Emoji-only Meshtastic sender names no longer drop commands (#31).
- **Console output no longer feeds itself** (#32).
  - The node discards inbound lines starting with `[`.
  - Byte echo behind `AH_USB_ECHO`, off by default.
  - `[DEBUG_RAW]` behind `AH_DEBUG_VERBOSE`, off by default.
  - USB input logs as `[USB CMD]`.
- `BATTERY_SAVER_STATUS` replies are recognized again (#32).
- **Erase PSK always set.** Made on first boot.
  - Printed on USB at boot.
  - Every erase command and web wipe needs it.
  - See README → Secure Data Destruction.
- Rate-limiter log reads `barrel_free=`, not `barrel=` (#32).
- Triangulation target MAC read atomically; RSSI reports no longer dropped.
- Beta and C5: headless honors a stop during ACK waits.
- Beta and C5: headless baseline queue uses the guarded path.
- Beta and C5: the CSI channel survey runs again.
  - `CSI_CFG:CH=` is a real token; the pin isn't saved.
- Beta and C5: CSI arming no longer needs psiZ.
- Beta: S3 CSI defaults to Low (0.140/8s/1 spot).
- Beta: web presets match the mesh presets.
- Headless: `DEVICE_DB_CLEAR` clears the device database over mesh.
- Results snapshot written atomically; a power cut can't corrupt it.
- SD writes retry with backoff on a busy card.
- A failed SD mount retries with a bus re-init.
- SD chip-select is driven high before SPI starts.
- Log file held open; reopened only after a failed write.
- Scan Results page no longer freezes mid-scan.
- `/results` streams from PSRAM and clears on a new scan.
- The UI polls only the open tab.
- Data tab loads SD logs a page at a time.
- The page reloads when the browser lands on another node.
- Baseline results rebuild every 2 s, only on change.
- Theme toggle stays in the mobile scan header.
- Diagnostics `Mesh TX` no longer sticks at draining.
- Flasher script: the default preset now sends `1` (Balanced).
- Flasher script: a blank AP password keeps the firmware default.
- AP MAC randomization fix.
- `memcpy` length guard against a WiFi driver underflow.

## Hardware

- DIGINODE v2 single-body side-charge enclosure: `One-Piece-Housing-SideCharge-Version.stl`.
- Revised side-charge housing: `FullSideChargeHousing.stl`.
- Front cover with a hidden 10 mm fan: `FrontCover-Hidden-Fan-10mm.stl`.
- Assembly manual, BOM links and welcome note updated.

## Upgrade

Settings and SD card files survive a flash.

All three builds attach to the one v1.0.3 release.
Per channel: `antihunter-<full|headless>-<version>.bin`; C5 uses `.factory.bin`.
Also `bootloader`, `partitions` and `SHA256SUMS` per version.
Builds are reproducible; verify with `shasum -a 256`.

| | Stable | Beta | Experimental (C5) |
|---|---|---|---|
| Web flasher channel | Stable | Beta | Experimental — ESP32-C5 |
| Script channel | 1 | 2 | 3 |
| Branch | `main` | `beta` | `feat/c5` |
| PlatformIO full | `AntiHunter-full` | `AntiHunter-full` | `AntiHunter-c5-full` |
| PlatformIO mesh-only | `AntiHunter-headless` | `AntiHunter-headless` | `AntiHunter-c5-headless` |

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge.
Pick the channel, then Full or Headless.

**Flasher script** (Python 3, esptool, pyserial), same on every branch:

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

`-c` sets device settings; `-l` lists firmware.

**PlatformIO**: `-t upload` keeps settings and the SD card.

Stable:

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload        # web UI
pio run -e AntiHunter-headless -t upload    # mesh only
```

Beta:

```bash
git clone -b beta https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
pio run -e AntiHunter-headless -t upload
```

Experimental (C5):

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload
pio run -e AntiHunter-c5-headless -t upload
```

### Thanks

- d3mocide (#31): emoji radio names made nodes ignore commands.
- rcbm.: long BLE device scans crashed the node.
- nconder (#32): console output fed back and flooded the log.
- nconder: nodes had no erase PSK until one was set.
