<div align="center">

[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![Stable](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?filter=!*-beta*&label=stable&color=2ea44f)](https://github.com/lukeswitz/AntiHunter/releases/latest)
[![Beta](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&filter=*-beta*&label=beta&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)
</div>


<p align="center">
  
  <img src="https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO/blob/main/TopREADMElogo.png?raw=true" alt="AntiHunter Command Center Logo" width="320" />

<div align="center">
  <a href="#features">Features</a> • <a href="#getting-started">Quick Start</a> • <a href="#hardware">DIY Build</a>  
</div>
  <h3 align="center">DIGI Detection Node 2.4GHz WiFi/BLE Firmware</h3>
</p>

> Beta version with new features in development. Potential stability issues and unexpected behavior may occur.

### News:

- `May 2026` - New **[Sentinel](#g-sentinel--counterintel-engine)** counterintel layer: passive WiFi attack detection.
- `Jan 2026` - Featured in [Best 20 XIAO Projects in 2025](https://www.seeedstudio.com/blog/2026/01/29/best-xiao-projects/)

# Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Detection Modes](#detection-modes)
4. [Secure Data Destruction](#secure-data-destruction)
5. [RF Configuration](#rf-configuration)
6. [System Architecture](#system-architecture)
7. [Hardware](#hardware)
8. [Getting Started](#getting-started)
9. [Mesh Commands](#mesh-commands)
10. [API Reference](#api-reference)
11. [Acknowledgments](#acknowledgments)
12. [Legal](#legal-disclaimer)

---

## Overview

- Open-source wireless sensor node for perimeter defense and spectrum awareness. 
- ESP32-S3 with WiFi/BLE scanning, GPS, SD logging, vibration sensing and LoRa mesh networking. 
- Deploy one node or a distributed network- each scans independently and coordinates over mesh. 




<img width="2046" height="1395" alt="image" src="https://github.com/user-attachments/assets/66817c73-58db-4697-b4e9-38f8ba449c4c" />

## Features


| Feature | What it does | Scan modes |
|---------|-------------|------------|
| **Target Scan** | MAC/OUI/SSID watchlist with instant mesh alerts | WiFi, BLE, or both |
| **Device Scanner** | Captures all nearby WiFi and BLE devices with RSSI, channels, names | WiFi, BLE, or both |
| **Probe Request Scanner** | Passive sniffer -- reveals SSIDs devices are searching for | WiFi, BLE, or both |
| **Ghost SSID Detection** | Flags probed SSIDs with no responding AP nearby | Probe / Device scan |
| **Baseline Anomaly Detection** | Learn-then-alert: spots new, missing, and changed devices | WiFi + BLE |
| **MAC Randomization Correlation** | Links randomized MACs to persistent identities via behavioral signatures | WiFi + BLE |
| **Deauth Attack Detection** | Real-time deauth/disassoc frame detection with source tracking | WiFi promiscuous |
| **Sentinel Counterintel** | Passive detection of attacker-tool activity (deauth/beacon/auth/assoc floods, SAE DoS, karma, evil-twin, probe floods, handshake capture); per-detector toggles, mesh broadcast, and optional persistent start-on-boot | WiFi promiscuous |
| **Drone RID Detection** | Identifies drones broadcasting Remote ID (ODID/ASTM F3411, French ID) | WiFi beacon/NAN |
| **Triangulation** | Multi-node RSSI-based location estimation via mesh (experimental) | WiFi, BLE |
| **Mesh Networking** | LoRa mesh via Meshtastic -- alerts, remote commands, coordination | UART serial |
| **Secure Data Destruction** | Tamper-triggered or remote wipe with post-wipe obfuscation | Vibration / mesh |
| **Privacy Mode** | One-click MAC/GPS/SSID redaction for screenshots | Web UI button |
| **Battery Saver** | 80MHz CPU, light sleep, reduced GPS, mesh heartbeat only | Mesh command |
| **Allowlist** | Global device allowlist -- ignored across all scan modes | Web UI / API |
| **Data Explorer** | Review findings, device logs and scan data | Web UI / API |

<img width="959" height="1398" alt="image" src="https://github.com/user-attachments/assets/8d043f93-e5ee-495e-9aef-574d17d8b740" />


### Use Cases

- Perimeter security and intrusion detection
- Penetration testing and wireless security auditing
- Counter-UAV operations and airspace monitoring
- Surveillance detection and OPSEC audits
- Device fingerprinting across MAC randomization
- Probe analysis and rogue device detection
- Event security and monitoring

---

## Detection Modes

<!-- <img width="1308" height="812" alt="Screenshot 2026-04-15 at 11 26 49 AM" src="https://github.com/user-attachments/assets/e34f42b9-a39e-41a7-8619-516a4a59f0bf" /> -->

### 1. Target Scan

<img width="1179" height="797" alt="image" src="https://github.com/user-attachments/assets/cf3c0b1e-e2f8-48ba-9fb3-655a498ad34e" />


Maintain a watchlist of MAC addresses (full or OUI prefix), SSIDs, or identity IDs (`T-XXXX`). Scans WiFi channels and BLE frequencies, alerting on detection via web UI, mesh, and command center.

- WiFi-only, BLE-only, or combined scanning
- Global allowlist filters out known devices
- Logs RSSI, channel, GPS, and device names to SD
- Real-time alerts over mesh network

### 2. Triangulation (Experimental)

Multiple nodes scan for a target simultaneously. Each records RSSI and GPS coordinates. Data is aggregated over mesh for weighted trilateration with Kalman filtering.

> [!TIP]
> Target RSSI above -80 produces better results for BLE devices

- Outputs: GPS coordinates, confidence, estimated uncertainty (m), average HDOP
- Google Maps link sent over mesh
- Per-target distance tuning multipliers (0.1x - 5.0x)

> Heltec v3 recommended. T114's small buffer causes latency.

<details>
<summary>RF Environment Calibration</summary>

Path loss model: `distance = 10^((RSSI0 - RSSI) / (10 * n))`

| Environment | WiFi n | BLE n | WiFi RSSI0 | BLE RSSI0 | Use Case |
|-------------|--------|-------|------------|-----------|----------|
| Open Sky | 2.0 | 2.0 | -23 dBm | -60 dBm | Clear LOS, minimal obstruction |
| Suburban | 2.7 | 2.5 | -24 dBm | -62 dBm | Light foliage, scattered buildings |
| Indoor | 3.2 | 2.9 | -25 dBm | -65 dBm | Typical indoor, some walls |
| Indoor Dense | 4.0 | 3.5 | -27 dBm | -69 dBm | Office spaces, many partitions |
| Industrial | 4.8 | 4.0 | -30 dBm | -73 dBm | Heavy obstruction, machinery |

</details>

## 3. Detection Sniffers

### A. Device Scanner

<!-- <img width="800" alt="Device Scanner" src="https://github.com/user-attachments/assets/c8a5d38b-9020-48c9-8bc4-f22d7c64a8df" /> -->

Captures all WiFi and BLE devices in range. Records MACs, SSIDs, signal strength, names, and channels.

- Check **Capture Probes** to piggyback probe request collection onto the device scan. When enabled, probe requests are captured alongside normal scanning and fed into the probe database (MAC, vendor, RSSI, SSIDs, randomization status):

<!-- <img width="800" alt="image" src="https://github.com/user-attachments/assets/060c1483-916c-45f7-87b8-58ec6a78e4d6" /> -->

### B. Baseline Anomaly Detection

<img width="1421" height="1208" alt="image" src="https://github.com/user-attachments/assets/1e7d31ff-6565-49d7-8cd4-d4b54c5fe5f8" />

Two-phase scan: establish a baseline of known devices, then monitor for anomalies -- new devices, disappearances, reappearances, and significant RSSI changes. Persistent storage survives reboots.

- RAM cache: 200-500 devices, SD overflow: 1K-100K devices (default 1500 without SD)
- Automatic tiering between RAM and SD

> [!TIP]
> A longer initial scan produces more reliable baselines.

<!-- <img width="850" alt="Screenshot 2026-04-15 at 11 24 28 AM" src="https://github.com/user-attachments/assets/0fb0094e-ade2-41d5-996a-217e7e0e7824" /> -->

### C. Deauth Attack Detection

WiFi deauth/disassoc frame sniffer with real-time detection. Integrates with randomization tracking for source identification.

<!-- <img width="858" height="382" alt="Deauth Detection" src="https://github.com/user-attachments/assets/1b1e77db-a479-4cfd-beae-e13a7187cae4" /> -->

### D. Drone RID Detection

Detects drones broadcasting Remote ID per FAA/EASA standards. Supports ODID/ASTM F3411 (NAN action frames, beacon frames) and French drone ID (OUI 0x6a5c35). Extracts UAV ID, pilot location, and flight telemetry. Mesh alerts and SD logging.

### E. MAC Randomization Correlation (Experimental)

> [!TIP]
> Use the Privacy button to redact MACs, GPS, and SSIDs before sharing screenshots. SSIDs are hashed as `net#XXXX` for correlation without exposure.

<!-- <img width="861" height="721" alt="Randomization Analyzer" src="https://github.com/user-attachments/assets/1939e7b1-dcac-46e6-aae9-c08032bbb340" /> -->

Links randomized MAC addresses to persistent device identities using behavioral signatures: IE fingerprinting, channel sequencing, timing, RSSI patterns, and sequence number correlation. Assigns identity IDs (`T-XXXX`) with SD persistence.

- Up to 256 simultaneous identities, 128 linked MACs each (LRU eviction of oldest identity at cap; stale tracks pruned every 60s)
- Dual signature support (full and minimal IE patterns)
- Confidence-based linking with adaptive thresholds
- Detects global MAC leaks and WiFi-BLE correlation

### F. Probe Request Scanner

<img width="1200" alt="image" src="https://github.com/user-attachments/assets/6f0397d3-aeb8-46fe-9700-f0c3e5be7579" />

Goes beyond probe request capture: correlates all three 802.11 address fields to detect ghost SSIDs (networks that exist only in the device's history), identify which APs responded, and catch silent devices via destination address matching.

<!-- <img width="500" alt="image" src="https://github.com/user-attachments/assets/99a894e1-1ab2-4dda-959d-29cb7880a637" /> -->

- **Three-field correlation**: Probe requests (addr2=source), probe responses (addr1=client, addr2=AP, addr3=BSSID), and destination address matching all feed into a single per-device record
- **Destination address (addr1) matching**: Detects when probe requests are addressed TO a target MAC -- catches silent or sleeping devices that never transmit their own identity
- **Ghost SSID detection**: Cross-references probe requests against probe responses to flag SSIDs with no responding AP nearby. Ghost SSIDs appear prefixed with `~` (e.g., `~"HomeNetwork"` vs `"CoffeeShop"`) and reveal networks the device connected to elsewhere -- location history, home/work networks, travel patterns
- SSID watchlist: add SSIDs to the target list alongside MACs and OUIs
- OUI vendor identification (68-vendor table)
- MAC randomization detection (locally-administered bit check)
- Mesh alerting for watchlist hits (60s dedup cooldown)
- RSSI min/max/current tracking, up to 4 probed SSIDs per device

### G. Sentinel — Counterintel Engine

Passive WiFi monitoring that flags attacker-tool activity by frame signatures plus behavioral fallbacks


Tuned and tested against both popular consumer ESP32 attack firmware and professional Linux tooling, so detection isn't tied to one tool's byte templates.

**Verified against:** airgeddon, aireplay-ng, bettercap, wifite, mdk4, angryoxide, eaphammer, hostapd-mana, wifipumpkin3, hcxdumptool, purpose-built test scripts, and common consumer ESP32 attack firmware.

Detectors are organized into toggleable groups. Each detection logs to serial + SD and broadcasts to mesh peers.

<img width="1535" height="1711" alt="image" src="https://github.com/user-attachments/assets/0862b4fc-cb66-447b-bfa7-94dfc4bb5970" />

| Group | Detectors | How they're caught |
|---|---|---|
| **DoS** | Deauth flood, deauth forge, broadcast deauth, AP-targeted deauth, beacon flood, auth flood, assoc-sleep, SAE DoS | Fixed/rotated deauth seqCtrl + reason codes, impersonation bursts, beacon-spam rate + static templates, open-system auth flood, assoc-req PM-bit floods, SAE commit floods (algo 3 / txn 1) |
| **Rogue AP** | Evil-twin, OWE abuse, Karma / MANA | Clone of our own AP (SSID/BSSID collision); OWE-transition downgrade; bait-probe answered by an AP that never beacons that SSID |
| **Recon** | PMKID harvest, probe flood, handshake capture | Orphaned-M1 / KDE PMKID solicitation; fixed-seq + behavioral probe spam (≥15 MACs/SSID/5s); forced & passive EAPOL M1–M4 capture |
| **Physical** | FragAttacks, TSF / multi-channel twin, WiFi interference | A-MSDU PN reuse / mixed-key frags; same BSSID on ≥2 channels within 5s; per-channel PDR-vs-RSSI collapse (CRC-fail flood) |
| **Mesh disruption** | Self-spoof, channel flood, command injection | Own node-id seen inbound; inbound rate DoS; privileged command from a sender with no benign history (the node's own Meshtastic channel) |

**Field-verified on hardware** (confirmed firing against the live tools above): deauth (flood/forge/AP-targeted), beacon flood, auth flood, assoc-sleep, SAE DoS, karma, evil-twin, probe flood, handshake capture.

**Experimental** (implemented + signature-grounded, hardware field-test pending): OWE abuse, PMKID harvest, FragAttacks, TSF multi-channel twin, WiFi interference, mesh disruption.

**Behavioral fallbacks** (survive template changes): SSID-rotate forge, behavioral probe-flood, EAPOL-capture bait, broadcast-deauth-while-beaconing.

**Outputs:** `[DETECT]` serial lines + per-detector SD `.jsonl` + mesh broadcast to peer nodes for quorum confirmation.

**Control & boot:** Start/stop from the Sentinel tab. Off at boot by default; opt into a persistent **Start-on-Boot** setting via the Web Flasher / Configurator / `SENTINEL_BOOT` mesh command — when enabled it auto-starts at power-on and survives reboot.
---

## Secure Data Destruction

Tamper detection and emergency data wiping.

<!-- ![Secure Data Destruction](https://github.com/user-attachments/assets/bdd8825d-82aa-46d4-b20c-3ebf7ca0dd9f)  -->

- **Auto-erase on tampering**: Vibration-triggered destruction (disabled by default)
- **Setup delay**: Grace period after enabling for deployment
- **Manual secure wipe**: Via web interface
- **Remote force erase**: Mesh-commanded with token auth (5-min expiry, device-specific)
- **Obfuscation**: Plants a dummy IoT weather config after wipe

> **Warning**: Data destruction is permanent and irreversible.

<details>
<summary>Auto-Erase Configuration</summary>

| Parameter | Range | Description |
|-----------|-------|-------------|
| Setup delay | 30s - 10min | Grace period before auto-erase activates |
| Vibrations required | 2-5 | Movement count to trigger |
| Detection window | 10-60s | Time frame for vibration detection |
| Erase delay | 10-300s | Countdown before destruction |
| Cooldown period | 5-60min | Minimum time between tamper attempts |

**Usage:**
1. Enable auto-erase via web interface with setup delay
2. Configure thresholds for your environment
3. Deploy and walk away during setup period
4. Monitor mesh alerts for tamper events
5. Remote erase (authenticated): provision a pre-shared key once with `@NODE CONFIG_ERASE_PSK:<secret>`, then use the HMAC challenge-response below.

**Authenticated remote erase (HMAC challenge-response):**

1. Provision the key once (persists in NVS): `@NODE CONFIG_ERASE_PSK:<secret>`
2. Request a one-time challenge: `@NODE ERASE_REQUEST` → node replies `ERASE_TOKEN:<nonce> Expires:300s` (fresh nonce each request, valid 300s).
3. Compute the response off-device:
   ```python
   import hmac, hashlib
   nonce  = "AH_a1b2c3d4_e5f6a7b8_00012345"   # the token only, not the whole line
   secret = "<secret>"
   print(hmac.new(secret.encode(), nonce.encode(), hashlib.sha256).hexdigest())
   ```
4. Force within 300s: `@NODE ERASE_FORCE:<hmac-hex>` → match wipes; wrong/expired → `ERASE_ACK:DENIED`.

The secret never traverses the mesh (only the public nonce and the HMAC do); a sniffed response is useless once the nonce changes. Without a provisioned PSK, the legacy `ERASE_FORCE:<token>` echo path applies (unauthenticated) — provision a PSK to harden.

**Web wipe:** once a PSK is provisioned, `/erase/request` and `/factory-wipe` require the PSK in the confirm field instead of the legacy `WIPE_ALL_DATA`/`FACTORY_WIPE` strings. Web wipe stays AP-only (not reachable over mesh).

</details>

---

## RF Configuration

<!-- <img width="815" height="616" alt="RF Configuration" src="https://github.com/user-attachments/assets/0463de41-dd3c-4d85-a4c7-bc6ada393488" /> -->

### Scan Presets

| Preset | WiFi Chan Time | WiFi Scan Int | BLE Scan Int | BLE Scan Dur | RSSI Threshold | Use Case |
|--------|----------------|---------------|--------------|--------------|----------------|----------|
| Relaxed | 300ms | 8000ms | 4000ms | 3000ms | -80 dBm | Low power |
| Balanced | 160ms | 6000ms | 3000ms | 3000ms | -95 dBm | General use (default) |
| Aggressive | 110ms | 4000ms | 2000ms | 2000ms | -70 dBm | Fast detection, high coverage |
| Custom | User-defined | User-defined | User-defined | User-defined | User-defined | Fine-tuned |

Configure via web interface at `http://192.168.4.1` or API. All settings persist to NVS and SD.

<details>
<summary>Parameter Tuning</summary>

- **WiFi Channel Time**: Duration per channel (50-300ms). Shorter = faster coverage.
- **WiFi Scan Interval**: Time between scan cycles (1000-10000ms).
- **BLE Scan Interval**: Time between BLE cycles (1000-10000ms).
- **BLE Scan Duration**: Active scanning per cycle (1000-5000ms). Longer improves discovery but reduces WiFi scan frequency.
- **RSSI Threshold**: Global signal filter (-100 to -10 dBm). Triangulation is exempt.
- **WiFi Channels**: Comma-separated (1,6,11) or range (1..14). Default: 1,6,11.

> [!TIP]
> Lower intervals = faster detection, higher power. Higher intervals = reduced power, may miss brief transmissions.

</details>

---

## System Architecture

<img width="1407" height="913" alt="System Architecture" src="https://github.com/user-attachments/assets/67348f3d-6613-462c-8e0f-dad419e43f9a" />

Nodes function independently and coordinate via Meshtastic mesh networking.

**Workflow:** Detection -> Data collection (RSSI, GPS, timestamp) -> Mesh broadcast -> Command center aggregation

**[AntiHunter Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO):** Aggregates data from all nodes with real-time mapping and visualization.

---

## Hardware

> [!IMPORTANT]
> Requires regulated 5V power supply. Unregulated battery sources cause voltage instability.

### Assembling the PCB
 
- Illustrated [assembly manual](https://github.com/lukeswitz/AntiHunter/blob/main/hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)

### Core Components

- **Seeed XIAO ESP32-S3** (minimum 8MB flash)
- **Meshtastic board**: Heltec v3.2 (recommended) or T114. Alternatives in [discussions](https://github.com/lukeswitz/AntiHunter/discussions).
- **GPS, SDHC, vibration, and RTC modules**

<details>
<summary>Bill of Materials</summary>

CORE COMPONENTS
- 1x Seeed Studio XIAO ESP32-S3
- 1x Heltec WiFi LoRa 32 V3.2 (T114 also compatible, V3.2 preferred)
- 1x ATGM336H GPS Module
- 1x Micro SD SDHC TF Card Adapter Reader Module
- 1x SD Card (FAT32, 16GB recommended)
- 1x SW-420 Vibration Sensor
- 1x DS3231 Real Time Clock Module
- 1x KSD9700 Normally Open Thermal Wire Sensor (30-40C)

CONNECTORS & FASTENERS
- 6x JST 2.54 2-Pin Terminals (2.0mm JST also fits)
- 10x M3 Mounting Inserts
- 2x M3x15mm Brass Standoffs
- 1x 1/4" Tripod Insert
- 1x JST Power Male Cable (for switch to board connection)
- 8x M3 Flat Top Screws (for enclosure)
- 6x M3 Screws (for PCB and power board)

ANTENNA & CABLING
- 3x U.FL to SMA Pigtail Cable (SMA bulkhead, 10-20cm)
- 1x 6dBi Antenna 2.4GHz (WiFi/BLE)
- 1x 6dBi Antenna LoRa (region-dependent: 868MHz EU / 915MHz US / 923MHz Asia)
- 1x GNSS Helix Antenna (L1/L5)

POWER & THERMAL
- 1x 30mm 5V Fan - JST (2.0mm JST also fits)
- 1x 3-Pin Mini On/Off Switch
- 1x Type-C 15W 3A 5V Fast Charge UPS Power Supply
  (2S 18650 Charger Module DC-DC Step Up Booster Converter, 88x41x22mm)

ENCLOSURE
- 1x Weatherproof Enclosure (3D printable)
  - STL files: [hw folder](https://github.com/lukeswitz/AntiHunter/tree/main/hw/Prototype_STL_Files)
- Assembly manual: [PDF](https://github.com/lukeswitz/AntiHunter/blob/main/hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)

</details>

<details>
<summary>Pinout Reference</summary>

XIAO ESP32S3 [Pin Diagram](https://camo.githubusercontent.com/29816f5888cbba2564bd0e0add96cd723a730cb65c81e48aa891f0f9c20471cd/68747470733a2f2f66696c65732e736565656473747564696f2e636f6d2f77696b692f536565656453747564696f2d5849414f2d455350333253332f696d672f322e6a7067)

> [!IMPORTANT]
> Pin assignments may evolve. Verify compatibility with your board revision.

| Function | GPIO | Description |
|----------|------|-------------|
| Vibration Sensor | 2 | SW-420 tamper detection (interrupt) |
| RTC SDA | 6 | DS3231 I2C data |
| RTC SCL | 3 | DS3231 I2C clock |
| GPS RX | 44 | NMEA data receive |
| GPS TX | 43 | GPS transmit (unused) |
| SD CS | 1 | SD card chip select |
| SD SCK | 7 | SPI clock |
| SD MISO | 8 | SPI MISO |
| SD MOSI | 9 | SPI MOSI |
| Mesh RX | 4 | Meshtastic UART receive |
| Mesh TX | 5 | Meshtastic UART transmit |

</details>

---

## Getting Started

### Web Flasher & Configurator (Recommended)

Flash and configure directly from your browser -- no tools to install. Requires Chrome or Edge on desktop.

1. **[Open Web Flasher](https://lukeswitz.github.io/AntiHunter/)** -- select Full or Headless, choose a **Release Channel** (Stable or Beta), plug in your ESP32-S3, and click Connect & Flash.

- The channel selector pulls the matching firmware from the `stable` or `beta` release branch.
- Choose "Erase Device" during process if upgrading from pre v0.9.2 firmware or to clear saved settings from flash memory.

   > Preferences are also saved and synced to/from SD storage. If corrupted, the settings will self-heal. 

2. Optional: After flashing, set the configuration choices and press send to device. 

   - Use it to change settings without using the device (especially useful for headless FW).
   - The **Sentinel & Detectors** section configures the full detection engine: persistent *Start Sentinel on Boot*, radio mode, every detector enable/disable, mesh-broadcast flags, and detector thresholds — full parity with the web UI's Detectors tab. Anything left on *Default* keeps the firmware setting.

### CLI Flash

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/beta/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

The script first asks for a **release channel** (Stable or Beta), then Full or Headless. Stable pulls from `main`, Beta from `beta`.

Use `-c` to configure device parameters during flash, `-e` to erase flash first, `-l` to list available firmware.

**Post-flash:**

- **Full firmware**: Connect to `Antihunter` WiFi AP (password: `antihunt3r123`), open `http://192.168.4.1`. Configure RF settings, detection modes, and change the AP credentials in RF Settings.
- **Headless firmware**: Serial monitor or mesh commands only.

### Build from Source

**Prerequisites:** PlatformIO, Git, USB cable. Optional: VS Code with PlatformIO extension.

```bash
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
```

```bash
pio device list                                    # List connected devices
pio run -e AntiHunter-full -t upload               # Flash full firmware (web UI)
pio run -e AntiHunter-headless -t upload           # Flash headless firmware
pio device monitor -e AntiHunter-full              # Serial monitor
pio run -e AntiHunter-full -t erase -t upload      # Clean flash (erase + upload)
```

**Build environments:**
- `AntiHunter-full` -- Web server (ESPAsyncWebServer, AsyncTCP) with AP dashboard
- `AntiHunter-headless` -- Minimal dependencies, no web UI, mesh/serial only

---

## Mesh Network Integration

Meshtastic LoRa mesh via UART for long-range distributed sensing.

- **Connection**: TEXTMSG mode, 115200 baud. Pins: `10 RX / 9 TX` (T114), `19 RX / 20 TX` (Heltec V3)
- **Protocol**: Standard Meshtastic serial, public and encrypted channels
- **Rate limiting**: 3s intervals (configurable)
- **Addressing**: `@ALL COMMAND` for broadcast, `@AH01 COMMAND` for a specific node. Node IDs: 2-5 alphanumeric chars.

### Mesh TX Architecture (v0.9.5+)

Scan tasks (sniffer/baseline/drone/randdet/blueteam) are **pure producers**. They enqueue device-broadcast messages into a 256-entry PSRAM-backed FreeRTOS queue (`meshTxQueue`) and exit immediately when the scan ends. A dedicated background consumer task (`meshTxTask`) drains the queue at the LoRa airtime cap via the existing token-bucket rate limiter (`SerialRateLimiter`, 200 bytes per 3 s ≈ 67 B/s).

**Consequences**:
- Starting a new scan never waits on prior scan's mesh TX. Drain happens in background.
- `/stop` (web UI or mesh STOP command) flushes the queue immediately (cancels pending TX).
- Header badge `Mesh TX K/N` shows live drain progress; auto-hides when queue empty.

### Cross-Scan Dedup

To save airtime on repeated scans of the same RF environment, broadcast `DEVICE:` messages are deduplicated by MAC address with a configurable TTL.

| Setting | Effect |
|---------|--------|
| `meshDedupTtl = 0` (disabled) | Every scan broadcasts every observed device. No skip. |
| `meshDedupTtl = 300` (5 min, default) | If a MAC was broadcast in the last 5 min, skip it on subsequent scans within that window. |
| `meshDedupTtl = 3600` (1 hr max) | Hourly per-MAC airtime cap. Tightest savings. |

**Applies only to**: sniffer + baseline `DEVICE:` broadcasts. Never applied to triangulation (`T_F:/T_C:/T_D:` need multi-RSSI), anomaly alerts (`ANOMALY:`, `DEVICE_DISAPPEARED:`, etc.), drone alerts (`DRONE:`), attack alerts (`DEAUTH_FLOOD:`, `ATTACK:`), summaries (`SCAN_DONE:`, `BLUE_DONE:`, etc.), or randomization identities (`IDENTITY:`).

**SCAN_DONE reporting**: with dedup enabled, `TX=N DUP=M` reflects N MACs broadcast this scan window and M MACs skipped due to dedup. Total unique devices observed = `U=N+M` (approximately).

**Configure via**:
- Web UI: Network Settings → Mesh Dedup TTL
- HTTP: `POST /mesh-dedup-ttl?ttl=N` where N is seconds (0=disable)
- Mesh: `@ALL CONFIG_DEDUP_TTL:N` (sec)
- Clear cache: `POST /mesh-dedup-clear` (forces all MACs to re-broadcast on next scan)

## Mesh Commands

All timestamps UTC. Node IDs: 2-5 alphanumeric characters (A-Z, 0-9), no spaces.

> [!TIP]
> `@ALL` broadcasts to all nodes. Replace with a node ID for targeted commands.

### Core

| Command | Description | Example |
|---------|-------------|---------|
| `STATUS` | System status (mode, scan state, hits, temp, uptime, GPS) | `@ALL STATUS` |
| `STOP` | Stop all operations | `@ALL STOP` |

### Configuration

| Command | Parameters | Example |
|---------|------------|---------|
| `CONFIG_TARGETS` | Pipe-delimited MACs, OUI prefixes, or SSIDs | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33\|MyNetwork` |
| `CONFIG_NODEID` | 2-5 alphanumeric ID | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | Threshold (-128 to -10) | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | Comma-separated channels | `@ALL CONFIG_CHANNELS:1,6,11` |
| `CONFIG_DEDUP_TTL` | Seconds 0-3600 (0=disable cross-scan MAC dedup) | `@ALL CONFIG_DEDUP_TTL:300` |
| `CONFIG_ERASE_PSK` | Pre-shared key for authenticated remote erase (empty clears it) | `@AH01 CONFIG_ERASE_PSK:my-secret-key` |

### Scanning

| Command | Parameters | Example |
|---------|------------|---------|
| `SCAN_START` | `mode:secs:channels[:FOREVER]` (0=WiFi, 1=BLE, 2=Both) | `@ALL SCAN_START:2:300:1,6,11` |
| `DEVICE_SCAN_START` | `mode:secs[:FOREVER[:+PROBE]]` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | `duration[:FOREVER]` (min 60s) | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | None | `@ALL BASELINE_STATUS` |
| `DRONE_START` | `secs[:FOREVER]` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `secs[:FOREVER]` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `mode:secs[:FOREVER]` | `@ALL RANDOMIZATION_START:2:300` |
| `PROBE_START` | `mode:secs[:FOREVER][:+ALL]` (0=WiFi, 1=BLE, 2=Both). `+ALL` broadcasts every probe over mesh, not just target matches. | `@ALL PROBE_START:2:300:+ALL` |
| `PROBE_STOP` | None | `@ALL PROBE_STOP` |

The `+PROBE` flag on `DEVICE_SCAN_START` enables probe request capture during device scans, populating the probe database alongside normal device discovery.

### Sentinel

| Command | Parameters | Example |
|---------|------------|---------|
| `SENTINEL_ON` / `SENTINEL_OFF` | None | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | None | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | `defend` (pin AP channel) or `scan` (hop all channels) | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | `1`/`0` — persist auto-start on boot (NVS `sentBoot`) | `@ALL SENTINEL_BOOT:1` |

<details>
<summary>Triangulation Commands</summary>

| Command | Parameters | Example |
|---------|------------|---------|
| `TRIANGULATE_START` | `target:duration[:rfEnv[:wifiPwr:blePwr]]` rfEnv: 0=OpenSky, 1=Suburban, 2=Indoor, 3=IndoorDense, 4=Industrial. wifiPwr/blePwr: 0.1-5.0 | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.5:0.8` |
| `TRIANGULATE_STOP` | None | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | None | `@AH01 TRIANGULATE_RESULTS` |

</details>

<details>
<summary>Security Commands</summary>

| Command | Parameters | Example |
|---------|------------|---------|
| `ERASE_REQUEST` | None | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | Auth token | `@AH02 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | None | `@AH01 ERASE_CANCEL` |
| `AUTOERASE_ENABLE` | `setup:erase:vibs:window:cooldown` (seconds, except vibs count) | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300` |
| `AUTOERASE_DISABLE` | None | `@AH01 AUTOERASE_DISABLE` |
| `AUTOERASE_STATUS` | None | `@AH01 AUTOERASE_STATUS` |
| `VIBRATION_STATUS` | None | `@AH01 VIBRATION_STATUS` |
| `VIBRATION_ON` | None | `@AH01 VIBRATION_ON` |
| `VIBRATION_OFF` | None | `@AH01 VIBRATION_OFF` |

</details>

<details>
<summary>Battery Saver Commands</summary>

| Command | Parameters | Example |
|---------|------------|---------|
| `BATTERY_SAVER_START` | `interval_minutes` (1-30, default 5) | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | None | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | None | `@AH01 BATTERY_SAVER_STATUS` |

Stops WiFi/BLE scanning, reduces CPU to 80MHz, enables light sleep, GPS polled once per minute. Mesh UART stays active. Heartbeat format:

```
NODE_ID: HEARTBEAT: Temp:XXC GPS:lat,lon Battery:SAVER
```

</details>

<details>
<summary>Heartbeat Commands</summary>

Periodic status broadcast over mesh. **Disabled by default.**

| Command | Parameters | Example |
|---------|------------|---------|
| `HB_ON` | None | `@AH01 HB_ON` |
| `HB_OFF` | None | `@AH01 HB_OFF` |
| `HB_INTERVAL` | `minutes` (1-60) | `@AH01 HB_INTERVAL:10` |

Format: `NODE_ID: Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC [GPS:lat,lon]`

</details>

<details>
<summary>Alert Message Formats</summary>

| Alert Type | Format |
|------------|--------|
| Target Detected | `NODE_ID: Target: TYPE MAC RSSI:dBm [Name:name] [GPS=lat,lon]` |
| Baseline Anomaly | `NODE_ID: ANOMALY-NEW/RETURN/RSSI: TYPE MAC RSSI:dBm [details]` |
| Deauth Attack | `NODE_ID: ATTACK: DEAUTH SRC:MAC DST:MAC RSSI:dBm CH:N` |
| Triangulation Data | `NODE_ID: T_D: MAC RSSI:dBm Type:WiFi/BLE GPS=lat,lon HDOP=X.XX` |
| Triangulation Final | `NODE_ID: T_F: MAC=addr GPS=lat,lon CONF=85.5 UNC=12.3` |
| Triangulation Complete | `NODE_ID: T_C: MAC=addr Nodes=N [Google Maps link]` |
| Probe Watchlist Hit | `NODE_ID: PROBE_HIT: MAC RSSI:dBm SSID:"network" [GHOST] [GPS=lat,lon]` |
| Tamper Detected | `NODE_ID: TAMPER_DETECTED: Auto-erase in Xs [GPS:lat,lon]` |
| Status Response | `NODE_ID: STATUS: Mode:TYPE Scan:STATE Hits:N Temp:XXC Up:HH:MM:SS GPS=lat,lon` |

</details>

---

## API Reference

> [!NOTE]
> All timestamps UTC. Full firmware only.

### Core

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/diag` | GET | System diagnostics |
| `/stop` | GET | Stop all operations |
| `/config` | GET/POST | System configuration (JSON) |
| `/clear-results` | POST | Clear all scan results |

### Scanning

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Start target scan (`mode`, `secs`, `forever`, `ch`, `triangulate`, `targetMac`) |
| `/sniffer` | POST | Start detection scan (`detection`, `secs`, `forever`, `randomizationMode`, `probeScanMode`, `captureProbes`) |
| `/drone` | POST | Start drone RID detection (`secs`, `forever`) |

### Results

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/results` | GET | Latest scan/triangulation results |
| `/sniffer-cache` | GET | Cached device detections |
| `/probe-results` | GET | Probe request results |
| `/deauth-results` | GET | Deauth attack logs |
| `/randomization-results` | GET | Randomization correlation results |
| `/baseline-results` | GET | Baseline anomaly results |
| `/drone-results` | GET | Drone detection results |
| `/drone-log` | GET | Drone event log (JSON) |

### Probe Database

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/probedb` | GET | Probe database (JSON: mac, vendor, SSIDs, RSSI, randomization status) |
| `/api/probedb/clear` | POST | Clear probe database |
| `/api/probes.jsonl` | GET | Stream probe log from SD (JSONL) |

### Data Explorer

The **Data** tab in the web UI provides a searchable, sortable view of all SD-logged scan data. Select a dataset from the dropdown, search across any column, click column headers to sort, and page through results.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/deauth.jsonl` | GET | Deauth/disassoc attack log (JSONL) |
| `/api/deauth/clear` | POST | Clear deauth log (RAM + SD) |
| `/api/drones.jsonl` | GET | Drone RID detection log (JSONL) |
| `/api/drones/clear` | POST | Clear drone log (RAM + SD) |
| `/api/vibrations.jsonl` | GET | Vibration/tamper event log (JSONL) |
| `/api/vibrations/clear` | POST | Clear vibration log (SD) |
| `/api/antihunter.log` | GET | System event log (text) |
| `/api/antihunter.log/clear` | POST | Clear system log |

Available datasets: Probe Devices, Probe Events, Deauth Attacks, Drone Detections, Vibration Events, Baseline Stats, and System Log. All datasets support export (download the raw file) and clear (with confirmation). The headless firmware logs the same data to SD without the web UI.

<details>
<summary>Configuration Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/node-id` | GET/POST | Get/set node ID (1-16 chars) |
| `/mesh-interval` | GET/POST | Get/set mesh send interval (1500-30000ms) |
| `/save` | POST | Save target configuration |
| `/export` | GET | Export target MAC list |
| `/allowlist-export` | GET | Export allowlist |
| `/allowlist-save` | POST | Save allowlist |
| `/api/time` | POST | Set RTC time from Unix timestamp |

</details>

<details>
<summary>Sentinel / Detection Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/detect/config` | GET | Current detector config (JSON: every detector enable, mesh-broadcast flag, threshold) |
| `/api/detect/config` | POST | Set detector config. JSON body of `{key:bool/int}` — same keys returned by GET (e.g. `pmkid`, `eviltwin`, `sae`, `karma`, `probe_flood`, `assoc_sleep`, `mesh_*` flags, thresholds). The Web Flasher/Configurator sends these under a nested `detectors` object at flash time. |
| `/api/detect/health` | GET | Detector runtime health (heap, queue depth, drops, per-detector counts) |
| `/api/sentinel/status` | GET | Sentinel running state |
| `/api/sentinel/start` / `/api/sentinel/stop` | POST | Start/stop the Sentinel engine |
| `/api/incidents.json` | GET | Recent incident ring (JSON) |
| `/api/incidents.jsonl` | GET | Full incident log from SD (JSONL) |
| `/api/incidents` | DELETE | Clear all incidents (RAM + SD) |

Each incident record carries: `ts` (device uptime ms), **`epoch`** (RTC Unix seconds — `0` if RTC unset; used by the Analysis tab to show real timestamps), `node`, `src`, `type`, `raw`.

Persistent boot setting: `sentinelBoot` (bool) in the configurator JSON / NVS pref `sentBoot` — auto-starts the Sentinel at power-on when true.

</details>

<details>
<summary>RF Configuration Endpoints</summary>

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/rf-config` | GET | - | RF config (JSON) |
| `/rf-config` | POST | `preset` (0-2) | Apply preset: 0=Relaxed, 1=Balanced, 2=Aggressive |
| `/rf-config` | POST | `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `wifiChannels`, `globalRssiThreshold` | Full custom config |
| `/rf-config` | POST | `globalRssiThreshold` (-100 to -10) | RSSI threshold only |
| `/wifi-config` | GET | - | WiFi AP settings (JSON) |
| `/wifi-config` | POST | `ssid` (1-32), `pass` (8-63 or empty) | Update AP credentials (triggers reboot) |

</details>

<details>
<summary>Baseline Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/baseline/status` | GET | Baseline scan status (JSON) |
| `/baseline/stats` | GET | Baseline statistics (JSON) |
| `/baseline/config` | GET/POST | Baseline config (`rssiThreshold`, `baselineDuration`, `ramCacheSize`, `sdMaxDevices`, `absenceThreshold`, `reappearanceWindow`, `rssiChangeDelta`) |
| `/baseline/reset` | POST | Reset baseline |

</details>

<details>
<summary>Triangulation Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/triangulate/start` | POST | Start (`mac`, `duration`, `rfEnv`, optional `wifiPwr`/`blePwr` 0.1-5.0) |
| `/triangulate/stop` | POST | Stop triangulation |
| `/triangulate/status` | GET | Status (JSON) |
| `/triangulate/results` | GET | Results |
| `/triangulate/nodes` | GET | Connected triangulation nodes |
| `/triangulate/calibrate` | POST | Calibrate path loss (`mac`, `distance`) |

</details>

<details>
<summary>Randomization, Security, and Hardware Endpoints</summary>

**Randomization:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/randomization/reset` | POST | Reset randomization detection |
| `/randomization/clear-old` | POST | Clear old identities (optional `age`) |
| `/randomization/identities` | GET | Tracked identities (JSON) |

**Security:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/erase/status` | GET | Erasure status |
| `/erase/request` | POST | Request secure erase (`confirm`=erase PSK if provisioned, else `WIPE_ALL_DATA`; optional `reason`) |
| `/erase/psk-status` | GET | JSON `{pskSet:bool}` — UI uses this to swap placeholder/label between PSK and legacy code |
| `/erase/cancel` | POST | Cancel erase sequence |
| `/factory-wipe` | POST | Wipe all SD + reset NVS (`confirm`=erase PSK if provisioned, else `FACTORY_WIPE`); reboots |
| `/secure/status` | GET | Tamper detection status |
| `/secure/abort` | POST | Abort tamper sequence |
| `/config/autoerase` | GET/POST | Auto-erase config |
| `/battery-saver` | GET | Battery saver (`action`=start/stop/status, `interval`) |

**Hardware:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gps` | GET | GPS status and location |
| `/sd-status` | GET | SD card status |
| `/drone/status` | GET | Drone detection status (JSON) |
| `/mesh` | POST | Enable/disable mesh |
| `/mesh-test` | GET | Test mesh connectivity |
| `/mesh-hb` | POST | Enable/disable heartbeat (`enabled=true\|false`) |
| `/mesh-hb-interval` | POST | Set heartbeat interval (`interval=1-60` minutes) |
| `/vibration` | POST | Toggle vibration sensor |

</details>

---

## Acknowledgments

Original concept and hardware design by @TheRealSirHaXalot. Get [involved](https://github.com/lukeswitz/AntiHunter/discussions) -- PRs, issues, and docs contributions welcome.


This project includes code from [opendroneid-core-c](https://github.com/opendroneid/opendroneid-core-c), licensed under the Apache License 2.0. Copyright (C) Intel Corporation and OpenDroneID contributors

## Legal Disclaimer

<details>
<summary>Full Disclaimer</summary>

```
AntiHunter (AH) is provided for lawful, authorized use only -- such as research,
training, and security operations on systems and radio spectrum you own or have
explicit written permission to assess. You are solely responsible for compliance
with all applicable laws and policies, including privacy/data-protection (e.g.,
GDPR), radio/telecom regulations (LoRa ISM band limits, duty cycle), and export
controls. Do not use AH to track, surveil, or target individuals, or to collect
personal data without a valid legal basis and consent where required.

Authors and contributors are not liable for misuse, damages, or legal
consequences arising from use of this project.

By using AH, you accept full responsibility for your actions and agree to
indemnify the authors and contributors against any claims related to your use.

These tools are designed for ethical blue team use, such as securing events,
auditing networks, or training exercises.

THE SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT
SHALL THE DEVELOPERS, MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, STRICT
LIABILITY, OR OTHERWISE, ARISING FROM OR IN CONNECTION WITH THE SOFTWARE,
INCLUDING ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY,
OR PUNITIVE DAMAGES.

BY ACCESSING, DOWNLOADING, INSTALLING, COMPILING, EXECUTING, OR OTHERWISE USING
THE SOFTWARE, YOU ACCEPT THIS DISCLAIMER AND THESE LIMITATIONS OF LIABILITY.
```

</details>
