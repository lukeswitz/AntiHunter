<div align="center">

[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![Pre-release](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)

</div>

<p align="center">
  <img src="https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO/blob/main/TopREADMElogo.png?raw=true" alt="AntiHunter Command Center Logo" width="320" />
</p>

> [!NOTE]
> **Early Release** - Alpha version. Expect stability issues, breaking changes, and unexpected behavior. Hardware requirements and features are rapidly evolving.
>
> DIGI Detection Node 2.4GHz WiFi/BLE firmware. Standalone or for use with the [AntiHunter Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO).

## Table of Contents

1. [Overview](#overview)
2. [Primary Detection Modes](#primary-detection-modes)
3. [Sensor Integration](#sensor-integration)
4. [Secure Data Destruction](#secure-data-destruction)
5. [RF Configuration](#rf-configuration)
6. [System Architecture](#system-architecture)
7. [Hardware Requirements](#hardware-requirements)
8. [Getting Started](#getting-started)
9. [Mesh Command Reference](#mesh-command-reference)
10. [API Reference](#api-reference)
11. [Credits](#credits)
12. [Disclaimer](#legal-disclaimer)

<a href="https://www.tindie.com/stores/teamantihunter/?ref=offsite_badges&utm_source=sellers_teamantihunter&utm_medium=badges&utm_campaign=badge_medium"><img src="https://d2ss6ovg47m0r5.cloudfront.net/badges/tindie-mediums.png" alt="I sell on Tindie" width="150" height="78"></a>

#### Project Updates

- `Feb. 02 2026`: **AntiHunter is live on Tindie.** Stock added on a rolling basis.
- `Feb. 01 2026`: Illustrated [assembly guide](https://github.com/lukeswitz/AntiHunter/blob/main/hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf) now available for the DIGINODE.
- `Jan. 29 2026`: Featured in [Best 20 XIAO Projects in 2025](https://www.seeedstudio.com/blog/2026/01/29/best-xiao-projects/).

## Overview

**AntiHunter** is a low-cost, open-source distributed perimeter defense system for wireless network security and operational awareness. Built on ESP32-S3 with mesh networking, it creates a scalable sensor network for real-time threat detection, device mapping, and perimeter security.

The system combines WiFi/BLE scanning, GPS positioning, environmental sensors, and distributed coordination to provide a digital and physical "tripwire", transforming spectrum activity into actionable security intelligence.

## Primary Detection Modes

![image](https://github.com/user-attachments/assets/b3be1602-c651-41d2-9caf-c2e4956d3aff)

### 1. List/Target Scan Mode

Maintain a watchlist of target MAC addresses (full 6-byte) or OUI prefixes (3-byte vendor IDs). AntiHunter sweeps WiFi channels and BLE frequencies, providing immediate alerts and detailed logging on detection.

- Target monitoring by MAC address or vendor OUI prefix
- WiFi-only, BLE-only, or combined scanning
- Global user-configurable allowlist
- Logs RSSI, channel, GPS coordinates, and device names to SD card
- Real-time alerts via web interface, command center, and mesh network

### 2. Triangulation/Trilateration (Distributed)

**`Experimental`**

<img width="859" height="899" alt="Triangulation diagram" src="https://github.com/user-attachments/assets/c76bb177-ce4e-42db-aafb-fd360b7f49e2" />

Coordinates multiple nodes across a mesh network for precise location tracking. Each node simultaneously scans for a target, recording RSSI and GPS coordinates. Data is aggregated and forwarded over mesh for RSSI-based trilateration processing.

- Multi-node coordination across mesh network
- GPS integration from each contributing node
- RSSI-based weighted trilateration with Kalman filtering
- Outputs: Average HDOP, GPS coordinates, confidence, estimated uncertainty (m), GPS quality
- Google Maps link sent over mesh with details

> The BOM antennas/MCUs are calibrated for the official PCB. Adjustment may be needed in `triangulation.cpp` constants.

> **Experimental T114 Support:** Small buffer and slow speed causes latency. Heltec v3 recommended.

<details>
<summary>RF Environment Calibration and Distance Tuning</summary>

#### Passive Detection Range (ESP32 + 5 dBi Antenna)

Ranges assume passive scanning. Active transmission achieves greater distances.

Path loss model: `distance = 10^((RSSI0 - RSSI) / (10 * n))`

| Environment | WiFi n | BLE n | WiFi RSSI0 | BLE RSSI0 | Use Case |
|-------------|--------|-------|------------|-----------|----------|
| Open Sky | 2.0 | 2.0 | -23 dBm | -60 dBm | Clear LOS, minimal obstruction |
| Suburban | 2.7 | 2.5 | -24 dBm | -62 dBm | Light foliage, scattered buildings |
| Indoor | 3.2 | 2.9 | -25 dBm | -65 dBm | Typical indoor, some walls |
| Indoor Dense | 4.0 | 3.5 | -27 dBm | -69 dBm | Office spaces, many partitions |
| Industrial | 4.8 | 4.0 | -30 dBm | -73 dBm | Heavy obstruction, machinery |

> Values calibrated for 5 dBi RX antenna gain with empirical verification from ESP32-S3 measurements (Feb 2026). Conservative calibration -- adaptive system fine-tunes for higher-gain antennas (up to 8 dBi). BLE has higher path loss exponent due to lower TX power and increased multipath susceptibility. Auto-calibration refines values during triangulation operations.

#### Distance Tuning (Target-Specific)

Fine-tune calculated distances per target using multipliers (0.1x - 5.0x):
- **< 1.0**: Target appears closer (increase sensitivity) -- e.g., 0.5x = 2x closer
- **> 1.0**: Target appears farther (reduce false positives) -- e.g., 2.0x = 2x farther
- **Default**: 1.0x (no adjustment)
- **Bounds**: WiFi max 50m, BLE max 30m (after multiplier)

</details>

### 3. Detection and Analysis Sniffers

#### A. Device Scanner

Captures all WiFi and Bluetooth devices in range. Records MAC addresses, SSIDs, signal strength, names, and channels for complete 2.4GHz spectrum visibility.

<img width="869" height="454" alt="Device Scanner" src="https://github.com/user-attachments/assets/c8a5d38b-9020-48c9-8bc4-f22d7c64a8df" />

#### B. Baseline Anomaly Detection

Two-phase scanning: establishes baseline, then monitors for anomalies (new devices, disappearances, reappearances, significant RSSI changes). Configurable RAM cache (200-500 devices) and SD storage (1K-100K devices, defaults to 1500 without SD). Persistent storage with automatic tiering survives reboots.

Use cases: distributed "trail cam" for intruders, perimeter security, surveillance detection, threat identification.

<img width="870" height="346" alt="Baseline Detection" src="https://github.com/user-attachments/assets/6204a8e5-418d-49fd-b99c-c1d9c31ee3f2" />

#### C. Deauthentication Attack Scan

WiFi deauth/disassoc attack sniffer with frame filtering, real-time detection, and integration with randomization tracking for source identification.

<img width="858" height="382" alt="Deauth Detection" src="https://github.com/user-attachments/assets/1b1e77db-a479-4cfd-beae-e13a7187cae4" />

#### D. Drone RID Detection

Identifies drones broadcasting Remote ID (FAA/EASA compliant). Supports ODID/ASTM F3411 protocols (NAN action frames and beacon frames), French drone ID format (OUI 0x6a5c35). Extracts UAV ID, pilot location, and flight telemetry. Sends immediate mesh alerts and logs to SD card and two API endpoints.

#### E. MAC Randomization Analyzer

**`Experimental`**

Traces device identities across randomized MAC addresses using behavioral signatures: IE fingerprinting, channel sequencing, timing analysis, RSSI patterns, and sequence number correlation. Assigns unique identity IDs (`T-XXXX`) with persistent SD storage.

- Up to 30 simultaneous identities with up to 50 linked MACs each
- Dual signature support (full and minimal IE patterns)
- Confidence-based linking with threshold adaptation
- Detects global MAC leaks and WiFi-BLE device correlation

<img width="861" height="721" alt="Randomization Analyzer" src="https://github.com/user-attachments/assets/1939e7b1-dcac-46e6-aae9-c08032bbb340" />

### Use Cases

- Perimeter security and intrusion detection
- WiFi penetration testing, security auditing, and MAC randomization analysis
- Device fingerprinting and persistent identification across randomization
- Counter-UAV operations and airspace awareness
- Event security and monitoring
- Red team detection and defensive operations
- Wireless threat hunting, forensics, and privacy assessments

---

## Sensor Integration

![Sensor integration photo](https://github.com/user-attachments/assets/35752f4a-bc78-4834-a652-e72622d5d732)

| Sensor | Interface | Description |
|--------|-----------|-------------|
| **GPS** | UART2 (RX=GPIO44, TX=GPIO43) 9600 baud | TinyGPS++ NMEA parsing. Location, altitude, satellite data. API at `/gps`. |
| **SD Card** | SPI | Logs to `/antihunter.log` with timestamps, MACs, RSSI, GPS. Web interface shows storage stats. |
| **Vibration/Tamper** | SW-420 (interrupt) | Interrupt-driven with 3s rate limiting. Mesh alerts with GPS and timestamps. |
| **RTC** | DS3231 via I2C | NTP sync on flash, fallback to system time and GPS. Drift correction. All timestamps UTC. |

---

## Secure Data Destruction

Tamper detection and emergency data wiping to protect data from unauthorized access.

![Secure Data Destruction](https://github.com/user-attachments/assets/bdd8825d-82aa-46d4-b20c-3ebf7ca0dd9f)

- **Auto-erase on tampering**: Configurable vibration-triggered destruction (disabled by default)
- **Setup delay**: Grace period after enabling to complete deployment
- **Manual secure wipe**: Via web interface
- **Remote force erase**: Mesh-commanded with token authentication (5-min expiry, device-specific)
- **Obfuscation**: Creates a dummy IoT weather device config after wipe

> **Warning**: Data destruction is permanent and irreversible. Configure thresholds carefully.

<details>
<summary>Auto-Erase Configuration Parameters</summary>

| Parameter | Range | Description |
|-----------|-------|-------------|
| Setup delay | 30s - 10min | Grace period before auto-erase activates |
| Vibrations required | 2-5 | Movement count to trigger |
| Detection window | 10-60s | Time frame for vibration detection |
| Erase delay | 10-300s | Countdown before destruction |
| Cooldown period | 5-60min | Minimum time between tamper attempts |

**Usage:**
1. Enable auto-erase via web interface with appropriate setup delay
2. Configure thresholds for deployment environment
3. Deploy device and walk away during setup period
4. Monitor mesh alerts for tamper events
5. Remote erase: `@NODE ERASE_REQUEST` to generate token, then `@NODE ERASE_FORCE:<token>`

</details>

---

## RF Configuration

<img width="815" height="616" alt="RF Configuration" src="https://github.com/user-attachments/assets/0463de41-dd3c-4d85-a4c7-bc6ada393488" />

### Scan Presets

| Preset | WiFi Chan Time | WiFi Scan Int | BLE Scan Int | BLE Scan Dur | RSSI Threshold | Use Case |
|--------|----------------|---------------|--------------|--------------|----------------|----------|
| Relaxed | 300ms | 8000ms | 4000ms | 3000ms | -80 dBm | Low power, stealthy |
| Balanced | 160ms | 6000ms | 3000ms | 3000ms | -90 dBm | General use (default) |
| Aggressive | 110ms | 4000ms | 2000ms | 2000ms | -70 dBm | Fast detection, high coverage |
| Custom | User-defined | User-defined | User-defined | User-defined | User-defined | Fine-tuned |

Configure via web interface at `http://192.168.4.1` or API endpoints. All settings persist to NVS and SD card.

<details>
<summary>Parameter Definitions and Tuning Notes</summary>

- **WiFi Channel Time**: Duration per channel (50-300ms). Shorter = faster coverage.
- **WiFi Scan Interval**: Time between scan cycles (1000-10000ms).
- **BLE Scan Interval**: Time between BLE cycles (1000-10000ms).
- **BLE Scan Duration**: Active scanning per cycle (1000-5000ms). Longer improves discovery but reduces WiFi scan frequency.
- **RSSI Threshold**: Global signal filter (-100 to -10 dBm). Lower captures distant signals; higher focuses on nearby. Triangulation is exempt.
- **WiFi Channels**: Comma-separated (1,6,11) or range (1..14). Default: 1,6,11.

Lower intervals = faster detection, higher power. Higher intervals = reduced power, may miss brief transmissions. Adjust based on deployment environment, power budget, and regulatory constraints.

</details>

---

## System Architecture

<img width="1407" height="913" alt="System Architecture" src="https://github.com/user-attachments/assets/67348f3d-6613-462c-8e0f-dad419e43f9a" />

AntiHunter operates as a distributed sensor network. Nodes function independently while contributing to the overall security picture via Meshtastic mesh networking.

**Workflow:** Local detection -> Target identification -> Data collection (RSSI, GPS, timestamp) -> Mesh broadcast -> Command center aggregation

**Command Center Integration:** Aggregates data from all nodes, provides real-time mapping and visualization, enables coordinated response operations. Public release coming soon.

---

## Hardware Requirements

- Enclosure STL files: [hw folder](https://github.com/lukeswitz/AntiHunter/tree/main/hw/Prototype_STL_Files)
- Assembly manual: [PDF](https://github.com/lukeswitz/AntiHunter/blob/main/hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)


> [!IMPORTANT]
> Requires regulated 5V power supply. Unregulated battery sources cause voltage instability that may disable or damage components.

### Core Components

- **ESP32-S3 Development Board** (minimum 8MB flash)
- **Meshtastic Board**: Heltec v3.2 (recommended) or T114. Alternatives in [discussions](https://github.com/lukeswitz/AntiHunter/discussions).
- **GPS, SDHC, Vibration, and RTC modules**

<details>
<summary>Full Bill of Materials (Single PCB)</summary>

- 1x Seeed Studio XIAO ESP32-S3
- 1x Heltec WiFi LoRa 32 V3.2 (T114 also compatible, V3.2 preferred)
- 1x ATGM336H GPS Module
- 1x Micro SD SDHC TF Card Adapter Reader Module (SPI)
- 1x SD Card (FAT32, 16GB recommended)
- 1x SW-420 Vibration Sensor
- 1x DS3231 Real Time Clock Module
- 1x KSD9700 Normally Open Thermal Wire Sensor (30-40C)
- 6x JST 2.54 2-Pin Terminals (2.0 JST also works)
- 3x U.FL to SMA Pigtail Cable (SMA bulkhead, 10-20cm)
- 1x 6dBi Antenna 2.4GHz (WiFi/BLE)
- 1x 6dBi Antenna LoRa (region-dependent: 868MHz EU / 915MHz US / 923MHz Asia)
- 1x GNSS Helix Antenna (L1/L5)
- 1x 30mm 5V Fan
- 1x 3 Pin Mini On/Off Switch

</details>

<details>
<summary>Pinout Reference</summary>

XIAO ESP32S3 [Pin Diagram](https://camo.githubusercontent.com/29816f5888cbba2564bd0e0add96cd723a730cb65c81e48aa891f0f9c20471cd/68747470733a2f2f66696c65732e736565656473747564696f2e636f6d2f77696b692f536565656453747564696f2d5849414f2d455350333253332f696d672f322e6a7067)

> [!IMPORTANT]
> Pin assignments and hardware requirements will evolve. Always verify compatibility with your specific board.

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

### Quick Flasher

Precompiled binaries for rapid deployment:

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

<details>
<summary>Headless Configuration (Optional)</summary>

Requires bootloader and partitions files from `Dist/` in the same directory.

```bash
./flashAntihunter.sh -c
```

</details>

**Post-Flash Setup:**

- **Full Firmware**: Connect to `Antihunter` WiFi AP (password: `antihunt3r123`), access `http://192.168.4.1`, configure RF settings and detection modes, change SSID/password in RF Settings.
- **Headless Firmware**: Use serial monitor or mesh commands.

### Development Setup

**Prerequisites:** PlatformIO, Git, USB cable. Optional: VS Code with PlatformIO IDE extension.

```bash
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
```

```bash
pio device list
pio run -e AntiHunter-full -t upload
pio run -e AntiHunter-headless -t upload
pio device monitor -e AntiHunter-full

# Clean deployment (erase + upload)
pio run -e AntiHunter-full -t erase -t upload
```

**Environments:**
- **Full**: Includes web server (ESPAsyncWebServer, AsyncTCP) for AP dashboard
- **Headless**: Minimal dependencies, ideal for distributed/background deployment

---

## Mesh Network Integration

AntiHunter integrates with Meshtastic LoRa mesh networks via UART, creating a long-range sensor network.

- **Connection**: Mode: `TEXTMSG`, Speed: `115200 baud`, Pins: `10 RX / 9 TX` (T114), `19 RX / 20 TX` (Heltec V3)
- **Protocol**: Standard Meshtastic serial, public and encrypted channels (protobuf in development)
- **Rate Limiting**: 3-second intervals prevent mesh flooding (configurable)
- **Addressing**: `@ALL COMMAND` for broadcast, `@AH01 COMMAND` for specific node. Node IDs: 2-5 alphanumeric characters.

## Mesh Command Reference

> [!NOTE]
> All timestamps UTC. Node IDs: 2-5 alphanumeric characters (A-Z, 0-9).

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `STATUS` | System status (mode, scan state, hits, temp, uptime, GPS) | `@ALL STATUS` |
| `STOP` | Stop all operations | `@ALL STOP` |

### Configuration Commands

| Command | Parameters | Example |
|---------|------------|---------|
| `CONFIG_TARGETS` | Pipe-delimited MACs or OUI prefixes | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33` |
| `CONFIG_NODEID` | 2-5 alphanumeric ID | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | Threshold (-128 to -10) | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | Comma-separated channels | `@ALL CONFIG_CHANNELS:1,6,11` |

### Scanning Commands

| Command | Parameters | Example |
|---------|------------|---------|
| `SCAN_START` | `mode:secs:channels[:FOREVER]` (0=WiFi, 1=BLE, 2=Both) | `@ALL SCAN_START:2:300:1,6,11` |
| `DEVICE_SCAN_START` | `mode:secs[:FOREVER]` | `@ALL DEVICE_SCAN_START:2:300` |
| `BASELINE_START` | `duration[:FOREVER]` (min 60s) | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | None | `@ALL BASELINE_STATUS` |
| `DRONE_START` | `secs[:FOREVER]` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `secs[:FOREVER]` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `mode:secs[:FOREVER]` | `@ALL RANDOMIZATION_START:2:300` |

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

</details>

<details>
<summary>Battery Saver Commands</summary>

| Command | Parameters | Example |
|---------|------------|---------|
| `BATTERY_SAVER_START` | `interval_minutes` (1-30, default 5) | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | None | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | None | `@AH01 BATTERY_SAVER_STATUS` |

Battery saver stops all WiFi/BLE scanning, reduces CPU to 80MHz, enables light sleep, reduces GPS polling to once per minute. Mesh UART stays active. Heartbeat format:

```
NODE_ID: HEARTBEAT: Temp:XXC GPS:lat,lon Battery:SAVER
```

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
| Tamper Detected | `NODE_ID: TAMPER_DETECTED: Auto-erase in Xs [GPS:lat,lon]` |
| Status Response | `NODE_ID: STATUS: Mode:TYPE Scan:STATE Hits:N Temp:XXC Up:HH:MM:SS GPS=lat,lon` |

</details>

---

## API Reference

> [!NOTE]
> All API timestamps use UTC.

### Core Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web interface |
| `/diag` | GET | System diagnostics |
| `/stop` | GET | Stop all operations |
| `/config` | GET | System configuration (JSON) |
| `/config` | POST | Update channels and target list |

### Scanning and Detection

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Start WiFi/BLE scan (`mode`, `secs`, `forever`, `ch`, `triangulate`, `targetMac`) |
| `/sniffer` | POST | Start detection mode (`detection`, `secs`, `forever`, `randomizationMode`) |
| `/drone` | POST | Start drone RID detection (`secs`, `forever`) |

### Results and Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/results` | GET | Latest scan/triangulation results |
| `/sniffer-cache` | GET | Cached device detections |
| `/drone-results` | GET | Drone detection results |
| `/drone-log` | GET | Drone event logs (JSON) |
| `/deauth-results` | GET | Deauth attack logs |
| `/randomization-results` | GET | Randomization detection results |
| `/baseline-results` | GET | Baseline detection results |

<details>
<summary>Configuration Management Endpoints</summary>

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
<summary>RF Configuration Endpoints</summary>

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/rf-config` | GET | - | Get RF config (JSON) |
| `/rf-config` | POST | `preset` (0-2) | Apply preset: 0=Relaxed, 1=Balanced, 2=Aggressive |
| `/rf-config` | POST | `preset`, `globalRssiThreshold` | Preset with custom RSSI |
| `/rf-config` | POST | `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `wifiChannels`, `globalRssiThreshold` | Full custom config |
| `/rf-config` | POST | `globalRssiThreshold` (-100 to -10) | Update RSSI threshold only |
| `/wifi-config` | GET | - | Get WiFi AP settings (JSON) |
| `/wifi-config` | POST | `ssid` (1-32), `pass` (8-63 or empty) | Update AP credentials (triggers 3s reboot) |

</details>

<details>
<summary>Baseline Detection Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/baseline/status` | GET | Baseline scan status (JSON) |
| `/baseline/stats` | GET | Detailed baseline statistics (JSON) |
| `/baseline/config` | GET/POST | Get/update baseline config (`rssiThreshold`, `baselineDuration`, `ramCacheSize`, `sdMaxDevices`, `absenceThreshold`, `reappearanceWindow`, `rssiChangeDelta`) |
| `/baseline/reset` | POST | Reset baseline detection |

</details>

<details>
<summary>Triangulation Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/triangulate/start` | POST | Start triangulation (`mac`, `duration`, `rfEnv`, optional `wifiPwr`/`blePwr` 0.1-5.0) |
| `/triangulate/stop` | POST | Stop triangulation |
| `/triangulate/status` | GET | Triangulation status (JSON) |
| `/triangulate/results` | GET | Triangulation results |
| `/triangulate/calibrate` | POST | Calibrate path loss (`mac`, `distance`) |

</details>

<details>
<summary>Randomization, Security, and Hardware Endpoints</summary>

**Randomization Detection:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/randomization/reset` | POST | Reset randomization detection |
| `/randomization/clear-old` | POST | Clear old identities (optional `age`) |
| `/randomization/identities` | GET | Tracked device identities (JSON) |

**Security and Erasure:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/erase/status` | GET | Erasure status |
| `/erase/request` | POST | Request secure erase (`confirm`=WIPE_ALL_DATA, optional `reason`) |
| `/erase/cancel` | POST | Cancel tamper erase sequence |
| `/secure/status` | GET | Tamper detection status |
| `/secure/abort` | POST | Abort tamper sequence |
| `/config/autoerase` | GET/POST | Get/update auto-erase config |
| `/battery-saver` | GET | Battery saver control (`action`=start/stop/status, `interval`) |

**Hardware and Status:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gps` | GET | GPS status and location |
| `/sd-status` | GET | SD card status and health |
| `/drone/status` | GET | Drone detection status (JSON) |
| `/mesh` | POST | Enable/disable mesh networking |
| `/mesh-test` | GET | Test mesh connectivity |

</details>

---

## Credits

AntiHunter is the result of collaborative development by security researchers, embedded systems engineers, and open-source contributors. Original concept and hardware design by @TheRealSirHaXalot.

Get [involved](https://github.com/lukeswitz/AntiHunter/discussions). Contributions via pull requests, issue reports, and documentation improvements are welcome.

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
