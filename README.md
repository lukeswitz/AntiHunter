<div align="center">

[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![Pre-release](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)

</div>

<div align="center">
<img width="500" alt="image" src="https://github.com/user-attachments/assets/da532c1f-9e59-45ff-9ea9-1af17ddea2ec" />
   
   Standalone firmware, or use in conjunction with the powerful [AntiHunter Command Center ](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO)
</div>



## Table of Contents

1. [Firmware Overview](#overview)
2. [Primary Detection Modes](#primary-detection-modes)
3. [System Architecture](#system-architecture)
4. [Secure Data Destruction](#secure-data-destruction)
5. [RF Configuration](#rf-configuration)
6. [Hardware Requirements](#hardware-requirements)
7. [Getting Started](#getting-started)
   - [Quick Flasher](#quick-flasher)
   - [Development Setup](#development-setup)
8. [Mesh Command Reference](#mesh-command-reference)
9. [API Reference](#api-reference)

> [!NOTE]  
> **Early Release** - This is an alpha version. Expect stability issues, breaking changes, and unexpected behavior. Hardware requirements and features are rapidly evolving.

## Overview

**AntiHunter** is a low-cost, open-source distributed perimeter defense system for wireless network security and operational awareness. It enables comprehensive monitoring and protection of wireless environments, transforming spectrum activity into actionable security intelligence.

Built on the ESP32-S3 platform with mesh networking, AntiHunter creates a scalable sensor network for real-time threat detection, device mapping, and perimeter security. The system combines WiFi/BLE scanning, GPS positioning, environmental sensors, and distributed coordination to provide a digital and physical "tripwire".

## Primary Detection Modes

![image](https://github.com/user-attachments/assets/b3be1602-c651-41d2-9caf-c2e4956d3aff)

## 1. List/Target Scan Mode

Maintain a watchlist of target MAC addresses (full 6-byte) or OUI prefixes (first 3-byte vendor IDs). AntiHunter systematically sweeps designated WiFi channels and BLE frequencies, providing immediate alerts and detailed logging when targets are detected.

**Features:**
- **Target Monitoring**: Track specific devices by MAC address or vendor OUI prefix
- **Dual Protocol Scanning**: WiFi-only, BLE-only, or combined WiFi+BLE modes
- **Global Allowlist**: User configurable, applies to all scans
- **Logging**: Records RSSI, channel, GPS coordinates, and device names to SD card
- **Real-time Alerts**: Immediate notifications via web interface, command center and mesh network

---

## 2. Triangulation/Trilateration (Distributed)

**`Experimental Feature`**

<img width="859" height="899" alt="Screenshot 2025-11-26 at 7 00 25 AM" src="https://github.com/user-attachments/assets/c76bb177-ce4e-42db-aafb-fd360b7f49e2" />

Triangulation coordinates multiple AntiHunter nodes across a mesh network to achieve precise location tracking of target devices. Each node simultaneously scans for the specified target, recording signal strength (RSSI) and GPS coordinates, syncing RTCs for precision. Detection data is aggregated and forwarded over mesh to the AP and command center for more advanced trilateration processing.

**Key Capabilities:**
- **Multi-node Coordination**: Distributed scanning across mesh network nodes
- **GPS Integration**: Each node contributes location data for accurate positioning
- **Weighted GPS Trilateration**:
  - Method: Weighted trilateration + Kalman filtering
  - Metrics: Average HDOP, GPS Coordinates, Confidence, Est. Uncertainty (m), Sync Status, GPS Quality
  - Output: Google Maps link sent over mesh with details

**Experimental T114 Support:**
> Small buffer and slow speed causes some latency. Using a Heltec v3 is recommended but not required.

#### Optimal Node Placement for RF Triangulation (2.4 GHz)

| Nodes | Geometry | Angular Sep | Urban Spacing | Rural Spacing | Coverage | GDOP | Notes |
|-------|----------|-------------|---------------|---------------|----------|------|-------|
| 3 | Equilateral Triangle | 120° | 25-35m | 50-70m | 800-1,200 m² | 4-6 | Minimum viable, mobile deployments |
| 4 | Square | 90° | 30-40m | 60-85m | 1,200-2,000 m² | 3-5 | Small buildings, perimeters |
| 5 | Regular Pentagon | 72° | 35-45m | 75-95m | 2,000-3,200 m² | 2-4 | Medium area coverage |
| 6 | Regular Hexagon | 60° | 40-50m | 85-105m | 3,500-4,500 m² | 2-4 | Large perimeter, optimal standard |
| 7 | Hexagon + Center | 60° perimeter | 45-55m | 95-115m | 5,000-6,500 m² | 1-3 | Dense/3D, one node at zenith |
| 8+ | Octagon/Circle | 45° | 50-65m | 100-130m | 6,500-10,000 m² | 1-3 | Wide area, events |

#### Range Reference (2.4 GHz)
- **WiFi Urban**: 30-50m | **Rural**: 80-150m LoS
- **BLE Urban**: 10-30m | **Rural**: 40-100m LoS
- **Wall Attenuation**: -20 to -30 dB urban, -10 to -15 dB drywall

---

## 3. Detection & Analysis Sniffers

### A. Device Scanner
- Captures all WiFi and Bluetooth devices in range
- Records MAC addresses, SSIDs, signal strength, names and channels
- Provides complete 2.4GHz wireless spectrum visibility
<img width="869" height="454" alt="Screenshot 2025-11-26 at 7 16 57 AM" src="https://github.com/user-attachments/assets/c8a5d38b-9020-48c9-8bc4-f22d7c64a8df" />


### B. Baseline Anomaly Detection

- Two-phase scanning: establishes baseline, then monitors for anomalies
- Detects new devices, disappeared/reappeared devices, significant RSSI changes
- Configurable RAM cache (200-500 devices) and SD storage (1K-100K devices). Defaults to 1500 devices if no SD card.
- Persistent storage with automatic tiering, survives reboots
- Real-time mesh alerts with GPS coordinates and anomaly reasons
- Use cases: distributed "trail cam" for poachers/trespassers, perimeter security, surveillance detection, threat identification
<img width="870" height="346" alt="Screenshot 2025-11-26 at 7 06 20 AM" src="https://github.com/user-attachments/assets/6204a8e5-418d-49fd-b99c-c1d9c31ee3f2" />


### C. Deauthentication Attack Scan
- WiFi deauth/disassoc attack sniffer with frame filtering and real-time detection
- Integration with randomization tracking for source identification
<img width="858" height="382" alt="Screenshot 2025-11-26 at 7 18 03 AM" src="https://github.com/user-attachments/assets/1b1e77db-a479-4cfd-beae-e13a7187cae4" />



### D. Drone RID Detection
- Identifies drones broadcasting Remote ID (FAA/EASA compliant)
- Supports ODID/ASTM F3411 protocols (NAN action frames and beacon frames)
- Detects French drone ID format (OUI 0x6a5c35)
- Extracts UAV ID, pilot location, and flight telemetry data
- Sends immediate mesh alerts with drone detection data, logs to SD card and two API endpoints for data

### E. MAC Randomization Analyzer

**`Experimental Feature`**

- Traces device identities across randomized MAC addresses using behavioral signatures
- IE fingerprinting, channel sequencing, timing analysis, RSSI patterns, and sequence number correlation
- Assigns unique identity IDs (format: `T-XXXX`) with persistent SD storage
- Supports up to 30 simultaneous device identities with up to 50 linked MACs each
- Dual signature support (full and minimal IE patterns)
- Confidence-based linking with threshold adaptation
- Detects global MAC leaks and WiFi-BLE device correlation
<img width="861" height="721" alt="Screenshot 2025-11-26 at 7 09 06 AM" src="https://github.com/user-attachments/assets/1939e7b1-dcac-46e6-aae9-c08032bbb340" />

---

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
![095B0BC8-1A8D-4EBD-9D95-976288F0F86E_1_201_a](https://github.com/user-attachments/assets/35752f4a-bc78-4834-a652-e72622d5d732)

### **GPS Positioning**
- **Interface**: UART2 (RX=GPIO44, TX=GPIO43) at 9600 baud using TinyGPS++
- **Functionality**: Parses NMEA sentences for location, altitude, and satellite data
- **Web Interface**: Real-time GPS status and fix quality
- **API Endpoint**: `/gps` returns current latitude/longitude coordinates
- **Integration**: All detection events include GPS coordinates when available

### **SD Card Logging**
- **Interface**: SPI
- **Storage**: Logs to `/antihunter.log` with timestamps, detection types, and metadata
- **Format**: Structured entries including MAC addresses, RSSI, GPS data, and timestamps
- **Diagnostics**: Web interface shows storage status and usage stats

### **Vibration/Tamper Detection**
- **Sensor**: SW-420 vibration sensor
- **Detection**: Interrupt-driven monitoring with 3-second rate limiting
- **Alerts**: Mesh network notifications with GPS coordinates and timestamps
- **Format**: `NODE_ABC: VIBRATION: Movement detected at HH:MM:SS GPS:lat,lon`
- **Status**: Real-time sensor state displayed in diagnostics panel

### **Real-Time Clock (RTC)**
- **Module**: DS3231 RTC via I2C
- **Functionality**: Accurate timekeeping during power outages and GPS synchronization
- **Features**: Automatic time sync from NTP on flash with fallback to system time and GPS, sync status monitoring & obedience/drift  correction.
- **Web Interface**: Current time display and synchronization status
- **Time Zone**: All timestamps use UTC (Coordinated Universal Time)

--- 

## Secure Data Destruction
AntiHunter includes tamper detection and emergency data wiping capabilities to protect data from unauthorized access

![9FEB36B3-6914-4601-A532-FC794C755B0E_1_201_a](https://github.com/user-attachments/assets/bdd8825d-82aa-46d4-b20c-3ebf7ca0dd9f)

### Features
- **Auto-erase on tampering**: Configurable vibration detection triggers automatic data destruction
- **Setup delay**: Grace period after enabling auto-erase to complete deployment and walk away
- **Manual secure wipe**: Web interface for operator-initiated data destruction  
- **Remote force erase**: Immediate mesh-commanded data destruction with token authentication
- **Mesh integration**: Real-time tamper alerts and erase status monitoring
- **Token-based authentication**: Time-limited tokens prevent unauthorized mesh erase commands

### Configuration
Configure auto-erase settings via the web interface:
- **Setup delay**: Grace period before auto-erase becomes active (30 seconds - 10 minutes)
- **Vibrations required**: Number of device movements to trigger (2-5)
- **Detection window**: Time frame for vibration detection (10-60 seconds)
- **Erase delay**: Countdown period before data destruction (10-300 seconds)
- **Cooldown period**: Minimum time between tamper attempts (5-60 minutes)

### Security
- Auto-erase is **disabled by default** for safety
- Setup delay prevents accidental triggering during deployment
- `ERASE_FORCE` requires device-generated authentication tokens that expire in 5 minutes
- Tokens are device-specific and generated via `ERASE_REQUEST` command on target device
- Overwrites SD buffer, erases all (including hidden) files and folders
- Creates a dummy IoT weather device config file for obfuscation 

### Usage
1. Enable auto-erase via web interface with appropriate setup delay
2. Configure detection thresholds based on deployment environment
3. Deploy device and walk away during setup period
4. Monitor mesh alerts for tamper detection events
5. For remote erase: Send `@NODE ERASE_REQUEST` to generate token, then use received token with `@NODE ERASE_FORCE:<token>`

> **Warning**: Data destruction is permanent and irreversible. Configure thresholds carefully to prevent false triggers.
---

## RF Configuration

<img width="815" height="616" alt="image" src="https://github.com/user-attachments/assets/0463de41-dd3c-4d85-a4c7-bc6ada393488" />


AntiHunter provides adjustable RF scan parameters to optimize detection performance for different operational scenarios.

### Scan Presets

| Preset | WiFi Chan Time | WiFi Scan Int | BLE Scan Int | BLE Scan Dur | RSSI Threshold | Use Case |
|--------|----------------|---------------|--------------|--------------|----------------|----------|
| **Relaxed** | 300ms | 8000ms | 4000ms | 3000ms | -80 dBm | Low power, stealthy operations |
| **Balanced** | 160ms | 6000ms | 3000ms | 3000ms | -90 dBm | General use, default configuration |
| **Aggressive** | 110ms | 4000ms | 2000ms | 2000ms | -70 dBm | Fast detection, high coverage |
| **Custom** | User-defined | User-defined | User-defined | User-defined | User-defined | Fine-tuned for specific requirements |

### Parameter Definitions

- **WiFi Channel Time**: Duration per WiFi channel (50-300ms)
- **WiFi Scan Interval**: Time between WiFi scan cycles (1000-10000ms)
- **BLE Scan Interval**: Time between BLE scan cycles (1000-10000ms)
- **BLE Scan Duration**: Active BLE scanning duration per cycle (1000-5000ms)
- **RSSI Threshold**: Global signal strength filter in dBm (-100 to -10). Filters weak signals from general scans; triangulation operations exempt from filtering
- **WiFi Channels**: Comma-separated list (1,6,11) or range (1..14) of 2.4GHz channels. Default: 1,6,11 if not specified

### Configuration Methods

Configure via web interface at `http://192.168.4.1` or API endpoints (see API Reference below). All settings persist to NVS and SD card when available.

### Operational Considerations

- **Lower intervals**: Faster detection, higher power consumption
- **Higher intervals**: Reduced power, may miss brief transmissions
- **Channel time**: Affects WiFi hop rate; shorter = faster coverage
- **BLE duration**: Longer improves discovery but reduces WiFi scan frequency
- **RSSI threshold**: Lower values (-100) capture distant/weak signals; higher (-60) focus on nearby devices. Triangulation exempt from filtering
- **Channel selection**: Use 1,6,11 for focused monitoring or 1..14 for comprehensive coverage

Adjust parameters based on deployment environment, power budget, target detection requirements, and regulatory constraints.

---

## System Architecture

<img width="1407" height="913" alt="image" src="https://github.com/user-attachments/assets/67348f3d-6613-462c-8e0f-dad419e43f9a" />

### **Distributed Node Network**
AntiHunter operates as a distributed sensor network where each node functions independently while contributing to the overall security picture. Nodes communicate via Meshtastic mesh networking, enabling:

- **Scalable Coverage**: Deploy multiple nodes to cover large areas
- **Redundant Detection**: Multiple nodes improve detection reliability
- **Distributed Processing**: Local decision-making with centralized coordination
- **Resilient Communications**: Mesh networking ensures connectivity in challenging environments

### **Operational Workflow**
1. **Local Detection**: Each node performs independent WiFi/BLE scanning based on configured parameters
2. **Target Identification**: Matches detected devices against configured watchlists
3. **Data Collection**: Records detection metadata (RSSI, GPS, timestamp, etc.)
4. **Mesh Coordination**: Broadcasts alerts and status to other nodes and command center
5. **Central Processing**: Command center aggregates data for advanced analytics and visualization

### **Command Center Integration**
While individual nodes provide standalone capability, the full system power comes from integration with a central command center that:
- Aggregates detection data from all nodes
- Provides real-time mapping and visualization
- Enables coordinated/scheduled response operations
- A lot more... stay tuned, public release soon. 

---

## Hardware Requirements

_PCBs and kits are in final production. Tindie link coming soon_
![807BFBDE-0DD4-4504-823A-820551452662_1_105_c](https://github.com/user-attachments/assets/8dae424f-10ad-4f19-a3f3-a07061e7633f)

### Enclosure STL Files
- Find them in the hw folder [here](https://github.com/lukeswitz/AntiHunter/tree/main/hw/Prototype_STL_Files)

> [!IMPORTANT]
> Requires regulated 5V power supply. Unregulated battery sources cause voltage instability that may disable or damage components.

### **Core Components**
- **ESP32-S3 Development Board**
  - Minimum 8MB flash memory required for reliable operation)
- **Meshtastic Board** Heltec v3.2 (recommended) or T114
  - Other alternatives can be found in the [discussions](https://github.com/lukeswitz/AntiHunter/discussions)
- **GPS, SDHC, Vibration and RTC modules**

### Bill of Materials (Single PCB)
- 1x Seeed Studio XIAO ESP32-S3
- 1x Heltec WiFi LoRa 32 V3.2 (Heltec T114 also compatible, V3.2 preferred)
- 1x ATGM336H GPS Module
- 1x Micro SD SDHC TF Card Adapter Reader Module with SPI
- 1x SD Card (Formatted FAT32, 16GB recommended)
- 1x SW-420 Vibration Sensor
- 1x DS3231 Real Time Clock Module
- 1x KSD9700 Normally Open Thermal Wire Sensor (30-40°C)
- 6x JST 2.54 2-Pin Terminals _(2.0 JST can be used in place)_
- 2x U.FL to SMA Pigtail Cable (SMA bulkhead, 10-20cm length)
- 2x 8dBi Antenna 2.4GHz (for WiFi/BLE)
- 2x 8dBi Antenna LoRa (region-dependent: 868MHz EU / 915MHz US / 923MHz Asia)
- 1x 30mm 5V Fan
- 1x 3 Pin Mini On/Off Switch 


### **Pinout Reference**

- XIAO ESP32S3 [Pin Diagram](https://camo.githubusercontent.com/29816f5888cbba2564bd0e0add96cd723a730cb65c81e48aa891f0f9c20471cd/68747470733a2f2f66696c65732e736565656473747564696f2e636f6d2f77696b692f536565656453747564696f2d5849414f2d455350333253332f696d672f322e6a7067)

> [!IMPORTANT]  
> **Hardware Note**: This is an early-stage project. Pin assignments and hardware requirements will evolve as the system matures. Always verify compatibility with your specific board.

| **Function** | **GPIO Pin** | **Description** |
|--------------|--------------|-----------------|
| Vibration Sensor | GPIO2 | SW-420 tamper detection (interrupt) |
| RTC SDA | GPIO6 | DS3231 I2C data line |
| RTC SCL | GPIO3 | DS3231 I2C clock line |
| GPS RX | GPIO44 | NMEA data receive |
| GPS TX | GPIO43 | GPS transmit (unused) |
| SD CS | GPIO1 | SD card chip select |
| SD SCK | GPIO7 | SPI clock |
| SD MISO | GPIO8 | SPI master-in slave-out |
| SD MOSI | GPIO9 | SPI master-out slave-in |
| Mesh RX | GPIO4 | Meshtastic UART receive |
| Mesh TX | GPIO5 | Meshtastic UART transmit |

---

## Getting Started

### Quick Flasher

For rapid deployment without building from source, precompiled binaries are available.

```bash
# Download the script, erase and flash:
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh

chmod +x flashAntihunter.sh

./flashAntihunter.sh
```

**Headless Configuration (Optional):**

Configuration on flash requires the bootloader and partitions files from `Dist/` folder in the same directory.
```bash
# Run the flasher script with interactive NVS configuration (Headless Firmware)
./flashAntihunter.sh -c
```

**Flashing Process:**
1. Connect your ESP32-S3 board via USB
2. Run the flasher script and follow prompts
3. Device will reboot with AntiHunter firmware

**Post-Flash Setup:**

**Full Firmware:**
- Connect to `Antihunter` WiFi AP (password: `antihunt3r123`)
- Access web interface at `http://192.168.4.1`
- Configure RF settings, detection modes, and security parameters
- Change SSID and password in RF Settings panel

**Headless Firmware:**
- Use serial monitor or mesh commands (see Command Reference section)

### Development Setup

For developers and advanced users:

**Prerequisites:**
- PlatformIO
- Git
- USB cable for programming and debugging
- Optional: Visual Studio Code with PlatformIO IDE extension

**Repository Setup:**
```bash
# Clone the AntiHunter repository
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
```

**Firmware Flashing:**

**Option 1 - PlatformIO Command Line:**
```bash
# Verify device detection
pio device list

# Upload full environment
pio run -e AntiHunter-full -t upload

# Upload headless environment  
pio run -e AntiHunter-headless -t upload

# Monitor with auto-config from platformio.ini
pio device monitor -e AntiHunter-full

# Erase + upload (clean deployment)
pio run -e AntiHunter-full -t erase -t upload
```

**Option 2 - Using VS Code:**

1. **Select Environment**: Click the environment selector in PlatformIO's status bar:
   - Choose `AntiHunter-full` for web interface version
   - Choose `AntiHunter-headless` for mesh-only version

2. **Build & Upload**: Click the "Upload" button (→) in the PlatformIO status bar

3. **Monitor Output**: Use the Serial Monitor to verify successful boot

**Environment Notes:**
- **Full**: Includes web server (ESPAsyncWebServer, AsyncTCP) for AP dashboard
- **Headless**: Minimal dependencies, ideal for distributed deployment and background operation

---

## Mesh Network Integration

AntiHunter integrates with Meshtastic LoRa mesh networks via UART serial communication, creating a robust long-range sensor network.

### **Key Features**
- **Extended Range**: LoRa mesh extends detection beyond WiFi/Bluetooth range
- **Node Coordination**: Distributed scanning and data sharing across nodes
- **Remote Control**: Command and control via mesh messages
- **Alert Propagation**: Real-time threat notifications across the network
- **Position Reporting**: GPS coordinates included in all relevant alerts

### **Hardware Configuration**
- **Connection**: **Mode: `TEXTMSG`;Speed: `115200 baud` ;Pins `10 RX / 9 TX` for T114 and `19 RX / 20 TX` for the Heltec V3**
- **Protocol**: Standard Meshtastic serial, public and encrypted channels _(protobuf support in development)_

### **Network Behavior**
- **Alert Rate Limiting**: 3-second intervals prevent mesh flooding, configurable. 
- **Node Identification**: Each device uses a configurable Node ID for addressing.
- **Broadcast Commands**: `@ALL` commands coordinate multiple nodes
- **Targeted Control**: `@AH01` commands address specific node `AH01`
- **Status Reporting**: Periodic heartbeats and operational status

## Mesh Command Reference

> [!NOTE]
> All timestamps in mesh commands and alerts use UTC (Coordinated Universal Time).

### Node Addressing Format
- **Specific Node**: `@ABC12 COMMAND` - Targets individual node
- **All Nodes**: `@ALL COMMAND` - Broadcast to entire network
- **Node ID**: 2-5 alphanumeric characters (A-Z, 0-9)
- **Response**: All responses prefixed with sending Node ID

> [!IMPORTANT]
> Node IDs must be 2-5 alphanumeric characters (A-Z, 0-9). Valid examples: `AB`, `A1C`, `XYZ99`, `12345`. This format is required for C2 integration

### Command Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `mode` | `0`, `1`, `2` | WiFi Only, BLE Only, WiFi+BLE |
| `secs` | `0-86400` | Duration in seconds (0 or omit for continuous) |
| `forever` | `1` or present | Run indefinitely |
| `ch` | `1,6,11` or `1..14` | WiFi channels (CSV or range) |
| `triangulate` | `1` | Enable multi-node triangulation |
| `targetMac` | `AA:BB:CC:DD:EE:FF` | Target device MAC address |


## **Mesh Commands**

| Command | Parameters | Description | Example |
|---------|------------|-------------|---------|
| `STATUS` | None | Reports system status (mode, scan state, hits, unique MACs, temperature, uptime, GPS, HDOP) | `@ALL STATUS` |
| `CONFIG_CHANNELS` | `channels` (CSV/range) | Configures WiFi channels | `@AH02 CONFIG_CHANNELS:1,6,11` |
| `CONFIG_TARGETS` | `macs` (pipe-delimited) | Updates target watchlist | `@ALL CONFIG_TARGETS:AA:BB:CC\|DD:EE:FF` |
| `CONFIG_RSSI` | `threshold` (-128 to -10) | Sets RSSI signal strength threshold for detections | `@AH02 CONFIG_RSSI:-65` |
| `CONFIG_NODEID` | `id` (2-5 alphanumeric) | Updates node identifier (A-Z, 0-9 only) | `@AH02 CONFIG_NODEID:AH03` |
| `SCAN_START` | `mode:secs:channels[:FOREVER]` | Starts scanning (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL SCAN_START:2:300:1..14` |
| `DEVICE_SCAN_START` | `mode:secs[:FOREVER]` | Starts device discovery scan (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL DEVICE_SCAN_START:2:300` |
| `DRONE_START` | `secs[:FOREVER]` | Starts drone RID detection (WiFi only, max 86400 secs) | `@ALL DRONE_START:600` |
| `DEAUTH_START` | `secs[:FOREVER]` | Starts deauthentication attack detection (max 86400 secs) | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `mode:secs[:FOREVER]` | Starts MAC randomization detection (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL RANDOMIZATION_START:2:600` |
| `BASELINE_START` | `duration[:FOREVER]` | Initiates baseline environment establishment (max 86400 secs) | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | None | Reports baseline detection status (scanning, established, device count, anomalies) | `@ALL BASELINE_STATUS` |
| `STOP` | None | Stops all operations | `@ALL STOP` |
| `VIBRATION_STATUS` | None | Checks tamper sensor status | `@AH02 VIBRATION_STATUS` |
| `TRIANGULATE_START` | `target:duration` | Initiates triangulation for target MAC (AA:BB:CC:DD:EE:FF) or Identity ID (T-XXXX) with duration in seconds. **Must send to @ALL** | `@ALL TRIANGULATE_START:AA:BB:CC:DD:EE:FF:300` or `@ALL TRIANGULATE_START:T-002F:300` |
| `TRIANGULATE_STOP` | None | Halts ongoing triangulation operation | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | None | Retrieves calculated triangulation results | `@NODE1 TRIANGULATE_RESULTS` |
| `ERASE_REQUEST` | None | Requests erase token from device (auto-generates if none exists, valid for 5 minutes) | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | `token` | Forces emergency data erasure with auth token | `@AH02 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | None | Cancels ongoing erasure sequence | `@ALL ERASE_CANCEL` |
| `AUTOERASE_ENABLE` | `[setupDelay:eraseDelay:vibs:window:cooldown]` (optional, all in seconds) | Enables auto-erase with optional parameters. Defaults: 120s setup, 30s erase, 3 vibs, 20s window, 300s cooldown | `@AH01 AUTOERASE_ENABLE` or `@AH01 AUTOERASE_ENABLE:60:30:3:20:300` |
| `AUTOERASE_DISABLE` | None | Disables auto-erase feature | `@AH01 AUTOERASE_DISABLE` |
| `AUTOERASE_STATUS` | None | Reports auto-erase configuration and status | `@AH01 AUTOERASE_STATUS` |

---

## **Mesh Alert Messages**

### Detection & RF Attack Alerts

| Alert Type | Format | Example |
|------------|--------|---------|
| **Target Detected** | `NODE_ID: Target: TYPE MAC RSSI:dBm [Name:name] [GPS=lat,lon]` | `NODE_ABC: Target: WiFi AA:BB:CC:DD:EE:FF RSSI:-62 Name:Device GPS=40.7128,-74.0060` |
| **Device Discovered** | `NODE_ID: DEVICE:MAC W/B RSSI [CN] [N:Name]` | `NODE_ABC: DEVICE:AA:BB:CC:DD:EE:FF W -65 C6 N:MyRouter` |
| **Drone Detected** | `NODE_ID: DRONE: MAC ID:id Rrssi GPS:lat,lon ALT:alt SPD:speed OP:lat,lon` | `NODE_ABC: DRONE: AA:BB:CC:DD:EE:FF ID:1234567890ABCDEF R-65 GPS:40.712800,-74.006000 ALT:123.5 SPD:25.5 OP:40.712800,-74.006000` |
| **Baseline Anomaly - New** | `NODE_ID: ANOMALY-NEW: TYPE MAC RSSI:dBm [Name:name]` | `NODE_ABC: ANOMALY-NEW: WiFi AA:BB:CC:DD:EE:FF RSSI:-45 Name:Unknown` |
| **Baseline Anomaly - Return** | `NODE_ID: ANOMALY-RETURN: TYPE MAC RSSI:dBm [Name:name]` | `NODE_ABC: ANOMALY-RETURN: BLE AA:BB:CC:DD:EE:FF RSSI:-55` |
| **Baseline Anomaly - RSSI** | `NODE_ID: ANOMALY-RSSI: TYPE MAC Old:dBm New:dBm Delta:dBm` | `NODE_ABC: ANOMALY-RSSI: WiFi AA:BB:CC:DD:EE:FF Old:-75 New:-45 Delta:30` |
| **Deauth Attack (Long)** | `NODE_ID: ATTACK: DEAUTH/DISASSOC [BROADCAST]/[TARGETED] SRC:MAC DST:MAC RSSI:dBm CH:N [GPS=lat,lon]` | `NODE_ABC: ATTACK: DEAUTH [TARGETED] SRC:AA:BB:CC:DD:EE:FF DST:11:22:33:44:55:66 RSSI:-45dBm CH:6` |
| **Deauth Attack (Short)** | `NODE_ID: ATTACK: DEAUTH/DISASSOC MAC->MAC Rrssi Cchannel` | `NODE_ABC: ATTACK: DEAUTH AA:BB:CC:DD:EE:FF->11:22:33:44:55:66 R-45 C6` |
| **Triangulation Data** | `NODE_ID: TARGET_DATA: MAC Hits=N RSSI:dBm [GPS=lat,lon HDOP=X.XX]` | `NODE_ABC: TARGET_DATA: AA:BB:CC:DD:EE:FF Hits=42 RSSI:-65 GPS=40.7128,-74.0060 HDOP=1.2` |
| **Triangulation Final Result** | `NODE_ID: TRIANGULATION_FINAL: MAC=mac GPS=lat,lon CONF=confidence % UNC=uncertainty %` | `NODE_ABC: TRIANGULATION_FINAL: MAC=AA:BB:CC:DD:EE:FF GPS=40.712800,-74.006000 CONF=85.5 UNC=12.3` |
| **Triangulation Complete** | `NODE_ID: TRIANGULATE_COMPLETE: MAC=AA:BB:CC:DD:EE:FF Nodes=N [https://www.google.com/maps?q=lat,lon]` | `NODE_ABC: TRIANGULATE_COMPLETE: MAC=11:22:33:44:55:66 Nodes=5 https://www.google.com/maps?q=40.712800,-74.006000` |

### Identification & Randomization Alerts

| Alert Type | Format | Example |
|------------|--------|---------|
| **Randomization Identity** | `NODE_ID: IDENTITY:T-XXXX B/W MACs:N Conf:X.XX Sess:N Anchor:XX:XX:XX:XX:XX:XX` | `AH99: IDENTITY:T-002F W MACs:5 Conf:0.62 Sess:5 Anchor:02:9F:C2:3D:92:CE` |
| **Randomization Complete** | `NODE_ID: RANDOMIZATION_DONE: Identities=N Sessions=N TX=N PEND=N` | `AH99: RANDOMIZATION_DONE: Identities=14 Sessions=22 TX=14 PEND=0` |

### Tamper, Security & Vibration Alerts

| Alert Type | Format | Example |
|------------|--------|---------|
| **Vibration Alert** | `NODE_ID: VIBRATION: Movement detected at HH:MM:SS [GPS:lat,lon] [TAMPER_ERASE_IN:Xs]` | `NODE_ABC: VIBRATION: Movement detected at 12:34:56 GPS:40.7128,-74.0060 TAMPER_ERASE_IN:60s` |
| **Vibration Setup Mode** | `NODE_ID: VIBRATION: Movement in setup mode (active in Xs) [GPS:lat,lon]` | `NODE_ABC: VIBRATION: Movement in setup mode (active in 45s) GPS:40.7128,-74.0060` |
| **Setup Mode Active** | `NODE_ID: SETUP_MODE: Auto-erase activates in Xs` | `NODE_ABC: SETUP_MODE: Auto-erase activates in 120s` |
| **Setup Complete** | `NODE_ID: SETUP_COMPLETE: Auto-erase activated` | `NODE_ABC: SETUP_COMPLETE: Auto-erase activated` |
| **Tamper Detected** | `NODE_ID: TAMPER_DETECTED: Auto-erase in Xs [GPS:lat,lon]` | `NODE_ABC: TAMPER_DETECTED: Auto-erase in 60s GPS:40.7128,-74.0060` |
| **Tamper Cancelled** | `NODE_ID: TAMPER_CANCELLED` | `NODE_ABC: TAMPER_CANCELLED` |
| **Erase Executing** | `NODE_ID: ERASE_EXECUTING: reason [GPS:lat,lon]` | `NODE_ABC: ERASE_EXECUTING: Tamper timeout GPS:40.7128,-74.0060` |
| **Erase Complete** | `NODE_ID: ERASE_ACK:COMPLETE` | `NODE_ABC: ERASE_ACK:COMPLETE` |
| **Erase Cancelled** | `NODE_ID: ERASE_ACK:CANCELLED` | `NODE_ABC: ERASE_ACK:CANCELLED` |

### Status, Sync & System Commands

| Alert Type | Format | Example |
|------------|--------|---------|
| **Startup Status** | `NODE_ID: STARTUP: System initialized GPS:LOCKED/SEARCHING TEMP:XXC` | `NODE_ABC: STARTUP: System initialized GPS:LOCKED TEMP:42.3C` |
| **Status Response** | `NODE_ID: STATUS: Mode:TYPE Scan:ACTIVE/IDLE Hits:N Temp:XX.XC/XX.XF Up:HH:MM:SS [GPS=lat,lon HDOP=X.X]` | `NODE_ABC: STATUS: Mode:WiFi+BLE Scan:ACTIVE Hits:142 Temp:42.3C Up:03:24:15 GPS=40.712800,-74.006000 HDOP=1.2` |
| **Node Heartbeat** | `NODE_ID: Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC [GPS:lat,lon]` | `NODE_ABC: Time:2025-10-28_14:32:15 Temp:42.3C GPS:40.7128,-74.0060` |
| **GPS Locked** | `NODE_ID: GPS: LOCKED Location=lat,lon Satellites:N HDOP:X.XX` | `NODE_ABC: GPS: LOCKED Location=40.7128,-74.0060 Satellites=8 HDOP=1.23` |
| **GPS Lost** | `NODE_ID: GPS: LOST` | `NODE_ABC: GPS: LOST` |
| **RTC Sync** | `NODE_ID: RTC_SYNC: GPS/NTP` | `NODE_ABC: RTC_SYNC: GPS` |
| **Time Sync Request** | `NODE_ID: TIME_SYNC_REQ:epoch:subsec:micros:propDelay` | `NODE_ABC: TIME_SYNC_REQ:1725000000:5000:123456:0` |
| **Time Sync Response** | `NODE_ID: TIME_SYNC_RESP:epoch:subsec:micros:propDelay` | `NODE_ABC: TIME_SYNC_RESP:1725000000:5000:123456:50` |

### Configuration Acknowledgments

| Alert Type | Format | Example |
|------------|--------|---------|
| **Channels Config ACK** | `NODE_ID: CONFIG_ACK:CHANNELS:channels` | `NODE_ABC: CONFIG_ACK:CHANNELS:1,6,11` |
| **Targets Config ACK** | `NODE_ID: CONFIG_ACK:TARGETS:OK` | `NODE_ABC: CONFIG_ACK:TARGETS:OK` |
| **RSSI Config ACK (Success)** | `NODE_ID: CONFIG_ACK:RSSI:OK` | `NODE_ABC: CONFIG_ACK:RSSI:OK` |
| **RSSI Config Error** | `NODE_ID: CONFIG_ACK:RSSI:INVALID_RANGE` | `NODE_ABC: CONFIG_ACK:RSSI:INVALID_RANGE` |
| **Node ID Config ACK (Success)** | `NODE_ID: CONFIG_ACK:NODE_ID:OK` | `NODE_ABC: CONFIG_ACK:NODE_ID:OK` |
| **Node ID Config Error (Invalid Chars)** | `NODE_ID: CONFIG_ACK:NODE_ID:INVALID_CHARS` | `NODE_ABC: CONFIG_ACK:NODE_ID:INVALID_CHARS` |
| **Node ID Config Error (Invalid Length)** | `NODE_ID: CONFIG_ACK:NODE_ID:INVALID_LENGTH` | `NODE_ABC: CONFIG_ACK:NODE_ID:INVALID_LENGTH` |

### Operation Acknowledgments

| Alert Type | Format | Example |
|------------|--------|---------|
| **Scan ACK** | `NODE_ID: SCAN_ACK:STARTED` | `NODE_ABC: SCAN_ACK:STARTED` |
| **Device Scan ACK** | `NODE_ID: DEVICE_SCAN_ACK:STARTED` | `NODE_ABC: DEVICE_SCAN_ACK:STARTED` |
| **Drone ACK** | `NODE_ID: DRONE_ACK:STARTED` | `NODE_ABC: DRONE_ACK:STARTED` |
| **Deauth ACK** | `NODE_ID: DEAUTH_ACK:STARTED` | `NODE_ABC: DEAUTH_ACK:STARTED` |
| **Randomization ACK** | `NODE_ID: RANDOMIZATION_ACK:STARTED` | `NODE_ABC: RANDOMIZATION_ACK:STARTED` |
| **Baseline ACK** | `NODE_ID: BASELINE_ACK:STARTED` | `NODE_ABC: BASELINE_ACK:STARTED` |
| **Baseline Status** | `NODE_ID: BASELINE_STATUS: Scanning:YES/NO Established:YES/NO Devices:N Anomalies:N Phase1:INACTIVE/ACTIVE/COMPLETE` | `NODE_ABC: BASELINE_STATUS: Scanning:YES Established:NO Devices:42 Anomalies:3 Phase1:ACTIVE` |
| **Triangulation ACK (Success)** | `NODE_ID: TRIANGULATE_ACK:TARGET` | `NODE_ABC: TRIANGULATE_ACK:AA:BB:CC:DD:EE:FF` or `NODE_ABC: TRIANGULATE_ACK:T-0001` |
| **Triangulation ACK (Error)** | `NODE_ID: TRIANGULATE_ACK:INVALID_FORMAT` | `NODE_ABC: TRIANGULATE_ACK:INVALID_FORMAT` |
| **Triangulation Results Start** | `NODE_ID: TRIANGULATE_RESULTS_START` | `NODE_ABC: TRIANGULATE_RESULTS_START` |
| **Triangulation Results End** | `NODE_ID: TRIANGULATE_RESULTS_END` | `NODE_ABC: TRIANGULATE_RESULTS_END` |
| **Triangulation Results (No Data)** | `NODE_ID: TRIANGULATE_RESULTS:NO_DATA` | `NODE_ABC: TRIANGULATE_RESULTS:NO_DATA` |
| **Triangulation Stop ACK** | `NODE_ID: TRIANGULATE_STOP_ACK` | `NODE_ABC: TRIANGULATE_STOP_ACK` |
| **Stop ACK** | `NODE_ID: STOP_ACK:OK` | `NODE_ABC: STOP_ACK:OK` |
| **Erase Token Response** | `NODE_ID: ERASE_TOKEN:token Expires:300s` | `NODE_ABC: ERASE_TOKEN:AH_12345678_87654321_00001234 Expires:300s` |
| **Erase ACK (Complete)** | `NODE_ID: ERASE_ACK:COMPLETE` | `NODE_ABC: ERASE_ACK:COMPLETE` |
| **Erase ACK (Cancelled)** | `NODE_ID: ERASE_ACK:CANCELLED` | `NODE_ABC: ERASE_ACK:CANCELLED` |
| **AutoErase Enabled ACK** | `NODE_ID: AUTOERASE_ACK:ENABLED Setup:Xs Erase:Xs Vibs:N Window:Xs Cooldown:Xs` | `NODE_ABC: AUTOERASE_ACK:ENABLED Setup:120s Erase:30s Vibs:3 Window:20s Cooldown:300s` |
| **AutoErase Disabled ACK** | `NODE_ID: AUTOERASE_ACK:DISABLED` | `NODE_ABC: AUTOERASE_ACK:DISABLED` |
| **AutoErase Status (Disabled)** | `NODE_ID: AUTOERASE_STATUS: Enabled:NO` | `NODE_ABC: AUTOERASE_STATUS: Enabled:NO` |
| **AutoErase Status (Active)** | `NODE_ID: AUTOERASE_STATUS: Enabled:YES SetupMode:ACTIVE/COMPLETE TamperActive:YES/NO [EraseIn:Xs] Setup:Xs Erase:Xs Vibs:N Window:Xs Cooldown:Xs` | `NODE_ABC: AUTOERASE_STATUS: Enabled:YES SetupMode:COMPLETE TamperActive:YES EraseIn:25s Setup:120s Erase:30s Vibs:3 Window:20s Cooldown:300s` |
| **Erase Token (AP FW)** | `NODE_ID: WIPE_TOKEN:token_string` | `NODE_ABC: WIPE_TOKEN:AH_12AB34CD_56EF78GH_1234567890` |
| **Reboot ACK** | `NODE_ID: REBOOT_ACK` | `NODE_ABC: REBOOT_ACK` |
---

## API Reference

> [!NOTE]
> All timestamps in API responses use UTC (Coordinated Universal Time).

### Core Operations
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/` | GET | - | Main web interface |
| `/diag` | GET | - | System diagnostics |
| `/stop` | GET | - | Stop all operations |
| `/config` | GET | - | Get system configuration (JSON) |
| `/config` | POST | `channels`, `targets` | Update channels and target list |

### Scanning & Detection
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/scan` | POST | `mode`, `secs`, `forever`, `ch`, `triangulate`, `targetMac` | Start WiFi/BLE scan |
| `/sniffer` | POST | `detection`, `secs`, `forever`, `randomizationMode` | Start detection mode (device-scan, deauth, baseline, randomization) |
| `/drone` | POST | `secs`, `forever` | Start drone RID detection |

### Results & Logs
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/results` | GET | - | Latest scan/triangulation results |
| `/sniffer-cache` | GET | - | Cached device detections |
| `/drone-results` | GET | - | Drone detection results |
| `/drone-log` | GET | - | Drone event logs (JSON) |
| `/deauth-results` | GET | - | Deauth attack logs |
| `/randomization-results` | GET | - | Randomization detection results |
| `/baseline-results` | GET | - | Baseline detection results |

### Configuration Management
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/node-id` | GET/POST | `id` | Get/set node ID (1-16 chars) |
| `/mesh-interval` | GET/POST | `interval` | Get/set mesh send interval (1500-30000ms) |
| `/save` | POST | `list` | Save target configuration |
| `/export` | GET | - | Export target MAC list |
| `/allowlist-export` | GET | - | Export allowlist |
| `/allowlist-save` | POST | `list` | Save allowlist |
| `/api/time` | POST | `epoch` | Set RTC time from Unix timestamp |

### RF Configuration
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/rf-config` | GET | - | Get RF configuration (JSON: preset, wifiChannelTime, wifiScanInterval, bleScanInterval, bleScanDuration, wifiChannels, globalRssiThreshold) |
| `/rf-config` | POST | `preset` (0-2) | Apply preset: 0=Relaxed, 1=Balanced, 2=Aggressive |
| `/rf-config` | POST | `preset` (0-2), `globalRssiThreshold` (-100 to -10) | Apply preset with custom RSSI threshold |
| `/rf-config` | POST | `wifiChannelTime` (50-300), `wifiScanInterval` (1000-10000), `bleScanInterval` (1000-10000), `bleScanDuration` (1000-5000), `wifiChannels` ("1,6,11" or "1..14"), `globalRssiThreshold` (-100 to -10) | Custom RF configuration with all parameters |
| `/rf-config` | POST | `globalRssiThreshold` (-100 to -10) | Update RSSI threshold only |
| `/wifi-config` | GET | - | Get WiFi AP settings (JSON: ssid, pass) |
| `/wifi-config` | POST | `ssid` (1-32 chars), `pass` (8-63 chars or empty) | Update AP credentials (triggers 3s reboot) |

### Baseline Detection
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/baseline/status` | GET | - | Baseline scan status (JSON) |
| `/baseline/stats` | GET | - | Detailed baseline statistics (JSON) |
| `/baseline/config` | GET/POST | `rssiThreshold`, `baselineDuration`, `ramCacheSize`, `sdMaxDevices`, `absenceThreshold`, `reappearanceWindow`, `rssiChangeDelta` | Get/update baseline configuration |
| `/baseline/reset` | POST | - | Reset baseline detection |

### Triangulation
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/triangulate/start` | POST | `mac`, `duration` | Start triangulation for target MAC (≥60 secs) |
| `/triangulate/stop` | POST | - | Stop triangulation |
| `/triangulate/status` | GET | - | Get triangulation status (JSON) |
| `/triangulate/results` | GET | - | Get triangulation results |
| `/triangulate/calibrate` | POST | `mac`, `distance` | Calibrate path loss for target |

### Randomization Detection
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/randomization/reset` | POST | - | Reset randomization detection |
| `/randomization/clear-old` | POST | `age` (optional) | Clear old device identities |
| `/randomization/identities` | GET | - | Get tracked device identities (JSON) |

### Security & Erasure
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/erase/status` | GET | - | Check erasure status |
| `/erase/request` | POST | `confirm` (WIPE_ALL_DATA), `reason` (optional) | Request secure erase (local device only) |
| `/erase/cancel` | POST | - | Cancel tamper erase sequence |
| `/secure/status` | GET | - | Tamper detection status |
| `/secure/abort` | POST | - | Abort tamper sequence |
| `/config/autoerase` | GET/POST | `enabled`, `delay`, `cooldown`, `vibrationsRequired`, `detectionWindow`, `setupDelay` | Get/update auto-erase configuration |

### Hardware & Status
| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/gps` | GET | - | Current GPS status and location |
| `/sd-status` | GET | - | SD card status and health |
| `/drone/status` | GET | - | Drone detection status (JSON) |
| `/mesh` | POST | `enabled` | Enable/disable mesh networking |
| `/mesh-test` | GET | - | Test mesh connectivity |

---

## Credits

AntiHunter is the result of collaborative development by security researchers, embedded systems engineers, and open-source contributors. Original concept and hardware design by @TheRealSirHaXalot.

Get [involved](https://github.com/lukeswitz/AntiHunter/discussions). The project continues to evolve through community contributions. Contributions via pull requests, issue reports, and documentation improvements are welcome. 

## Legal Disclaimer

```
AntiHunter (AH) is provided for lawful, authorized use only—such as research, training, and security operations on systems and radio spectrum you own or have explicit written permission to assess. You are solely responsible for compliance with all applicable laws and policies, including privacy/data-protection (e.g., GDPR), radio/telecom regulations (LoRa ISM band limits, duty cycle), and export controls. Do not use AH to track, surveil, or target individuals, or to collect personal data without a valid legal basis and consent where required.

Authors and contributors are not liable for misuse, damages, or legal consequences arising from use of this project.
By using AHCC, you accept full responsibility for your actions and agree to indemnify the authors and contributors against any claims related to your use.
These tools are designed for ethical blue team use, such as securing events, auditing networks, or training exercises. To implement in code, ensure compliance with local laws (e.g., FCC regulations on transmissions) and pair with a directional antenna for enhanced accuracy.

THE SOFTWARE IN THIS REPOSITORY (“SOFTWARE”) IS PROVIDED “AS IS” AND “AS AVAILABLE,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, OR RELIABILITY. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL THE DEVELOPERS, MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OF OR OTHER DEALINGS IN THE SOFTWARE, INCLUDING WITHOUT LIMITATION ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, OR LOSS OF DATA, PROFITS, GOODWILL, OR BUSINESS INTERRUPTION, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

YOU ALONE ARE RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS, REGULATIONS, AND THIRD-PARTY RIGHTS. NO ADVICE OR INFORMATION, WHETHER ORAL OR WRITTEN, OBTAINED FROM THE PROJECT OR THROUGH THE SOFTWARE, CREATES ANY WARRANTY OR OBLIGATION NOT EXPRESSLY STATED HEREIN. IF APPLICABLE LAW DOES NOT ALLOW THE EXCLUSION OF CERTAIN WARRANTIES OR LIMITATION OF LIABILITY, THE DEVELOPERS’, MAINTAINERS’, AND CONTRIBUTORS’ AGGREGATE LIABILITY SHALL NOT EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID (IF ANY) FOR THE COPY OF THE SOFTWARE THAT GAVE RISE TO THE CLAIM, OR (B) USD $0.

NOTWITHSTANDING ANYTHING TO THE CONTRARY, THE PROJECT MAINTAINERS SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING FROM OR RELATED TO ANY THIRD-PARTY INTELLECTUAL PROPERTY CLAIMS, INCLUDING BUT NOT LIMITED TO ATTORNEYS' FEES, SETTLEMENT COSTS, OR INJUNCTIVE RELIEF.

BY USING THIS SOFTWARE, YOU ACKNOWLEDGE THE INHERENT RISKS ASSOCIATED WITH INTELLECTUAL PROPERTY COMPLIANCE AND ASSUME FULL RESPONSIBILITY FOR ENSURING YOUR USE COMPLIES WITH ALL APPLICABLE LAWS AND THIRD-PARTY RIGHTS.

BY ACCESSING, DOWNLOADING, INSTALLING, COMPILING, EXECUTING, OR OTHERWISE USING THE SOFTWARE, YOU ACCEPT THIS DISCLAIMER AND THESE LIMITATIONS OF LIABILITY.
```
