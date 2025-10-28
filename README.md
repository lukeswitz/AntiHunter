[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![Pre-release](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/commits/main/)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)

# AntiHunter

## Table of Contents

1. [Overview](#overview)
2. [Core Capabilities](#core-capabilities)
3. [System Architecture](#system-architecture)
4. [Secure Data Destruction](#secure-data-destruction)
5. [Hardware Requirements](#hardware-requirements)
6. [Getting Started](#getting-started)
   - [Quick Flasher](#quick-flasher)
   - [Development Setup](#development-setup)
   - [Firmware Flashing](#firmware-flashing)
7. [Web Interface](#web-interface)
8. [Mesh Network Integration](#mesh-network-integration)
9. [Command Reference](#command-reference)
10. [API Endpoints](#api-endpoints)

> [!NOTE]  
> **Early Release** - This is an alpha version. Expect stability issues, breaking changes, and unexpected behavior. Hardware requirements and features are rapidly evolving.

## Overview

**AntiHunter** is a low-cost, open-source distributed perimeter defense system for wireless network security and operational awareness. It enables comprehensive monitoring and protection of wireless environments, transforming spectrum activity into actionable security intelligence for defensive operations.

Built on the ESP32-S3 platform with mesh networking, AntiHunter creates a scalable sensor network for real-time threat detection, device mapping, and perimeter security. The system combines WiFi/BLE scanning, GPS positioning, environmental sensors, and distributed coordination to provide a digital and physical "tripwire". 

## Core Capabilities

### Primary Detection Modes

#### 1. **List Scan Mode**
Maintain a watchlist of target MAC addresses (full 6-byte) or OUI prefixes (first 3-byte vendor IDs). AntiHunter systematically sweeps designated WiFi channels and BLE frequencies, providing immediate alerts and detailed logging when targets are detected.

- **Targeted Monitoring**: Track specific devices by MAC address or vendor OUI prefix
- **Dual Protocol Scanning**: WiFi-only, BLE-only, or combined WiFi+BLE modes
- **Global Allowlist**: User configurable, applies to all scans. 
- **Logging**: Records RSSI, channel, GPS coordinates, and device names to SD card
- **Real-time Alerts**: Immediate notifications via web interface, AH command center and mesh network. 

#### 2. Triangulation/Trilateration  (Distributed)
Triangulation coordinates multiple AntiHunter nodes across a mesh network to achieve precise location tracking of target devices. Each node simultaneously scans for the specified target, recording signal strength (RSSI) and GPS coordinates, syncing RTCs for precision. Detection data is aggregated and forwarded over mesh to the AP and command center for more advanced trilateration processing.

**`EXPERIMENTAL T114 SUPPORT:`** small buffer and slow speed causes some latency. Using a Heltec v3 is recommended but not required.

- **Multi-node Coordination**: Distributed scanning across mesh network nodes
- **GPS Integration**: Each node contributes location data for accurate positioning
- **Weighted GPS Trilateration**: - Method: Weighted trilateration + Kalman filtering. Average HDOP, GPS Coordinates, Confidence, Est.Uncertainty (m), Sync Status, GPS Quality. Google Maps link sent over mesh with details. 
- **AH Command Center Integration**: Data forwarded for centralized processing, MQTT broker and mapping. 

#### 3. **Detection & Analysis**
Wireless environment analysis combining general device discovery, baseline anomaly detection, and specialized Remote ID drone detection.

**Device Scanner**
- Captures all WiFi and Bluetooth devices in range
- Records MAC addresses, SSIDs, signal strength, names and channels
- Provides complete 2.4GHz wireless spectrum visibility

**Baseline Anomaly Detection**
- Two-phase scanning: establishes baseline, then monitors for anomalies
- Detects new devices, disappeared/reappeared devices, significant RSSI changes
- Configurable RAM cache (200-500 devices) and SD storage (1K-100K devices). **Defaults to 1500 devices if no SD card**
- Persistent storage with automatic tiering, survives reboots
- Real-time mesh alerts with GPS coordinates and anomaly reasons
- Use cases: distributed "trail cam" for poachers/trespassers, perimeter security, surveillance detection, threat identification

**Deauthentication Attack Scan**
- WiFi deauth/disassoc attack sniffer with frame filtering and real-time detection
- Integration with randomization tracking for source identification

**Drone RID Detection**
- Identifies drones broadcasting Remote ID (FAA/EASA compliant)
- Supports ODID/ASTM F3411 protocols (NAN action frames and beacon frames)
- Detects French drone ID format (OUI 0x6a5c35)
- Extracts UAV ID, pilot location, and flight telemetry data
- Sends immediate mesh alerts with drone detection data, logs to SD card and two API endpoints for data

**MAC Randomization Analysis**

**`EXPERIMENTAL FEATURE`**

- Traces device identities across randomized MAC addresses using behavioral signatures
- IE fingerprinting, channel sequencing, timing analysis, RSSI patterns, and sequence number correlation
- Assigns unique identity IDs (format: `T-XXXX`) with persistent SD storage
- Supports up to 30 simultaneous device identities with up to 50 linked MACs each
- Dual signature support (full and minimal IE patterns)
- Confidence-based linking with threshold adaptation
- Detects global MAC leaks and WiFi-BLE device correlation

**Use Cases**

- Perimeter security and intrusion detection
- WiFi penetration testing, security auditing, and MAC randomization analysis
- Device fingerprinting and persistent identification across randomization
- Counter-UAV operations and airspace awareness
- Infrastructure drone monitoring
- Event security and monitoring
- Red team detection and defensive operations
- Wireless threat hunting, forensics, and privacy assessments
---

### Sensor Integration

#### **GPS Positioning**
- **Interface**: UART2 (RX=GPIO44, TX=GPIO43) at 9600 baud using TinyGPS++
- **Functionality**: Parses NMEA sentences for location, altitude, and satellite data
- **Web Interface**: Real-time GPS status and fix quality
- **API Endpoint**: `/gps` returns current latitude/longitude coordinates
- **Integration**: All detection events include GPS coordinates when available

#### **SD Card Logging**
- **Interface**: SPI
- **Storage**: Logs to `/antihunter.log` with timestamps, detection types, and metadata
- **Format**: Structured entries including MAC addresses, RSSI, GPS data, and timestamps
- **Diagnostics**: Web interface shows storage status and usage stats

#### **Vibration/Tamper Detection**
- **Sensor**: SW-420 vibration sensor
- **Detection**: Interrupt-driven monitoring with 3-second rate limiting
- **Alerts**: Mesh network notifications with GPS coordinates and timestamps
- **Format**: `NODE_ABC: VIBRATION: Movement detected at HH:MM:SS GPS:lat,lon`
- **Status**: Real-time sensor state displayed in diagnostics panel

#### **Real-Time Clock (RTC)**
- **Module**: DS3231 RTC via I2C
- **Functionality**: Accurate timekeeping during power outages and GPS synchronization
- **Features**: Automatic time sync from NTP on flash with fallback to system time and GPS, sync status monitoring & obedience/drift  correction. 
- **Web Interface**: Current time display and synchronization status

--- 

## Secure Data Destruction

AntiHunter includes tamper detection and emergency data wiping capabilities to protect data from unauthorized access.

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
- `ERASE_FORCE` requires web-generated authentication tokens that expire in 5 minutes
- Overwrites SD buffer, erases all (including hidden) files and folders
- Creates a dummy IoT weather device config file for obfuscation 

### Usage
1. Enable auto-erase via web interface with appropriate setup delay
2. Configure detection thresholds based on deployment environment
3. Deploy device and walk away during setup period
4. Monitor mesh alerts for tamper detection events
5. Use web interface to generate authenticated mesh erase tokens for remote destruction

> **Warning**: Data destruction is permanent and irreversible. Configure thresholds carefully to prevent false triggers.

---

## System Architecture

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
- Performs advanced trilateration calculations
- Provides real-time mapping and visualization
- Enables coordinated response operations
- Maintains historical threat intelligence


## Hardware Requirements

_PCBs and kits are in production!_

### Enclosure STL Files
- Provided by @TheRealSirHaXalot, find them in the hw folder [here](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/hw/Prototype_STL_Files)

### **Core Components**
- **ESP32-S3 Development Board** (Seeed Studio XIAO ESP32S3 recommended)
  - Minimum 8MB flash memory required for reliable operation)
- **Meshtastic Board** (LoRa-based mesh networking) Heltec v3.2 (recommended) or T114
- **GPS Module** (NMEA-compatible)
- **SD Card Module** 
- **SW-420 Vibration Sensor**
- **DS3231 RTC Module**

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

### **Quick Flasher**

For rapid deployment without building from source, precompiled binaries are available:

**Linux/macOS:**
```bash
# Download the flasher script
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh

# Run the flasher script with default configuration (Full AP Firmware)
./flashAntihunter.sh

```

- Optional Headless Config:

**`NOTE`: Configuration on flash** erase process requires the bootloader and partitions files from inside `Dist/` folder to be in the same directory:

```bash
# Run the flasher script with interactive configuration (Headless Firmware)
./flashAntihunter.sh -c -e
```

**Process:**
1. Connect your ESP32-S3 board via USB
2. Run the flasher script, follow prompts
3. The device will reboot with AntiHunter firmware

Full Firmware:
- Connect to the `Antihunter` WiFi AP (password: `ouispy123`)
- Access the web interface at `http://192.168.4.1`

Headless Firmware:
- Use the [commands list](https://github.com/lukeswitz/AntiHunter/edit/main/README.md#command-reference) below to interact with the device

### **Development Setup**

For developers and advanced users:

#### **Prerequisites**
- **PlatformIO**
- **Git** for repository management
- **USB cable** for programming and debugging
- **Optional: Visual Studio Code** with PlatformIO IDE extension

#### **Repository Setup**
```bash
# Clone the AntiHunter repository
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
```

#### **Firmware Flashing**

### Option 1 - PIO command line:

```bash
# Ensure PlatformIO Core is installed
pip install -U platformio
pio --version

# From inside AntiHunter folder containing platformio.ini:

# Build and upload Full environment (with web interface)
pio run -e AntiHunter-full -t upload
pio device monitor -e AntiHunter-full

# Or build and upload Headless environment (mesh only comms)
pio run -e AntiHunter-headless -t upload
pio device monitor -e AntiHunter-headless
```

### Option 2 - Using VS Code:

1. **Select Environment**: Click the environment selector in PlatformIO's status bar at the bottom:
   - Choose `AntiHunter-full` for the web interface version
   - Choose `AntiHunter-headless` for the mesh only version

2. **Build & Upload**: Click the "Upload" button (→) in the PlatformIO status bar

3. **Monitor Output**: Use the Serial Monitor to verify successful boot

**Environment Notes:**
- **Full**: Includes web server (ESPAsyncWebServer, AsyncTCP) for AP dashboard
- **Headless**: Minimal dependencies, ideal for AHCC/background operation
---

## Web Interface

After flashing, AntiHunter creates a WiFi access point for configuration and monitoring. The ESP32 will randomize its MAC address on each boot. 

### **Connection**
1. **Join Network**: Connect to `Antihunter` WiFi AP
   - **Password**: `ouispy123`
   - **IP Address**: `192.168.4.1`
2. **Access Interface**: Open browser to `http://192.168.4.1`

**Change** SSID and password in the AP under RF Settings. 

### **Main Interface Sections**

#### **Target Configuration**
- **Watchlist Management**: Add/remove MAC addresses and OUI prefixes
- **Allow List**: Devices to exclude from alerts and scans
- **Format**: Full MAC (`AA:BB:CC:DD:EE:FF`), OUI (`AA:BB:CC`), or by `T-XXXX` grouped ID
- **Export/Import**: Save/load target lists for deployment
- **Validation**: Real-time format checking and duplicate detection

#### **Scanning Operations**
- **List Scan**: Area surveillance for configured targets
  - **Modes**: WiFi Only, BLE Only, WiFi+BLE Combined
  - **Duration**: Configurable scan time (0 = continuous)
  - **Channels**: Custom WiFi channel selection (`1,6,11` or `1..14`)
  - **Triangulation**: Enable multi-node tracking (requires mesh, GPS, RTC
  
  - **RF Settings**: Choose from three presets or use custom scan intervals and channel timing.
  - **Results Sorting**: Easily find your target using six ordering methods
    

- **Triangulation Mode**:
  - **Target MAC**: Specify device for location tracking
  - **Node Coordination**: Automatically syncs with mesh network
  - **Duration**: Tracking period for position calculations
  - **Status**: Shows participating nodes and signal data

#### **Detection & Analysis**
- **Device Discovery**: General scanning for all WiFi/BLE devices
- **Baseline Anomaly Scan**: Be alerted to new/approaching devices
- **MAC Randomization Analyzer**: Discover, correlate and de-randomize
- **Deauthentication Attack Detection**: Spots WiFi deauth packet traces 
- **Drone WiFi RID**: Detect remote ID compliant drones & pilots

#### **System Diagnostics**
**Overview Tab:**
- Real-time system status and performance metrics
- Detection statistics (frames seen, hits, unique devices)
- Temperature monitoring and uptime tracking

**Hardware Tab:**
- GPS status and satellite information
- SD card storage usage and file management
- RTC time synchronization status
- Vibration sensor state and history

**Network Tab:**
- Mesh connectivity and node status
- WiFi access point configuration
- Channel usage and scanning parameters

#### **Configuration**
- **Node Identification**: Set unique node ID (1-16 characters)
- **Mesh Integration**: Enable/disable Meshtastic communications
- **Mesh Interval**: Control the frequency of alerts over mesh to match your use case

---

## Mesh Network Integration

AntiHunter integrates with Meshtastic LoRa mesh networks via UART serial communication, creating a robust long-range sensor network.

### **Key Features**
- **Extended Range**: LoRa mesh extends detection beyond WiFi/Bluetooth range
- **Node Coordination**: Distributed scanning and data sharing across nodes
- **Remote Control**: Command and control via mesh messages
- **Alert Propagation**: Real-time threat notifications across the network
- **Position Reporting**: GPS coordinates included in all relevant alerts

### **Hardware Integration**
- **Connection**: **Mode: `TEXTMSG`;Speed: 115200 baud;Pins 9 TX / 10 RX for T114 and 19/20 for the Heltec V3**
- **Protocol**: Standard Meshtastic serial, public and encrypted channels

### **Network Behavior**
- **Alert Rate Limiting**: 3-second intervals prevent mesh flooding, configurable. 
- **Node Identification**: Each device uses a configurable Node ID for addressing. 
- **Broadcast Commands**: `@ALL` commands coordinate multiple nodes
- **Targeted Control**: `@NODE_XX` commands address specific nodes
- **Status Reporting**: Periodic heartbeats and operational status

## Command Reference

### **Node Addressing**
- **Specific Node**: `@NODE_22 COMMAND` - Targets individual node
- **All Nodes**: `@ALL COMMAND` - Broadcast to entire network
- **Node ID Format**: Up to 16 alphanumeric characters
- **Response Format**: All responses prefixed with sending Node ID

---
## **Parameter Reference**

### **Scan Parameters**
- `mode`: `0` = WiFi Only, `1` = BLE Only, `2` = WiFi+BLE
- `secs`: Duration in seconds (0 or omit for continuous, max 86400)
- `forever`: `1` or present = Run indefinitely
- `ch`: WiFi channels (CSV: `1,6,11` or range: `1..14`)
- `triangulate`: `1` = Enable multi-node triangulation
- `targetMac`: Target device MAC address (format: `AA:BB:CC:DD:EE:FF`)

---

## **Mesh Commands**

| Command | Parameters | Description | Example |
|---------|------------|-------------|---------|
| `STATUS` | None | Reports system status (mode, scan state, hits, targets, unique MACs, temperature, uptime, GPS) | `@ALL STATUS` |
| `CONFIG_CHANNELS` | `channels` (CSV/range) | Configures WiFi channels | `@NODE_22 CONFIG_CHANNELS:1,6,11` |
| `CONFIG_TARGETS` | `macs` (pipe-delimited) | Updates target watchlist | `@ALL CONFIG_TARGETS:AA:BB:CC\|DD:EE:FF` |
| `SCAN_START` | `mode:secs:channels[:FOREVER]` | Starts scanning (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL SCAN_START:2:300:1..14` |
| `DEVICE_SCAN_START` | `mode:secs[:FOREVER]` | Starts device discovery scan (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL DEVICE_SCAN_START:2:300` |
| `DRONE_START` | `secs[:FOREVER]` | Starts drone RID detection (WiFi only, max 86400 secs) | `@ALL DRONE_START:600` |
| `DEAUTH_START` | `secs[:FOREVER]` | Starts deauthentication attack detection (max 86400 secs) | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `mode:secs[:FOREVER]` | Starts MAC randomization detection (mode: 0=WiFi, 1=BLE, 2=Both) | `@ALL RANDOMIZATION_START:2:600` |
| `BASELINE_START` | `duration[:FOREVER]` | Initiates baseline environment establishment (max 86400 secs) | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | None | Reports baseline detection status (scanning, established, device count, anomalies) | `@ALL BASELINE_STATUS` |
| `STOP` | None | Stops all operations | `@ALL STOP` |
| `VIBRATION_STATUS` | None | Checks tamper sensor status | `@NODE_22 VIBRATION_STATUS` |
| `TRIANGULATE_START` | `MAC/Identity:duration` | Initiates triangulation for target MAC or Identity ID (format: T-xxxxx) | `@ALL TRIANGULATE_START:AA:BB:CC:DD:EE:FF:300` |
| `TRIANGULATE_STOP` | None | Halts ongoing triangulation operation | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | None | Retrieves calculated triangulation results for all nodes | `@NODE_22 TRIANGULATE_RESULTS` |
| `ERASE_FORCE` | `token` | Forces emergency data erasure with auth token | `@NODE_22 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | None | Cancels ongoing erasure sequence | `@ALL ERASE_CANCEL` |

---

### **Mesh Alert Messages**

| Alert Type | Format | Example |
|------------|--------|---------|
| **Target Detected** | `NODE_ID: Target: TYPE MAC RSSI:dBm [Name] [GPS=lat,lon]` | `NODE_ABC: Target: WiFi AA:BB:CC:DD:EE:FF RSSI:-62 Name:Device GPS=40.7128,-74.0060` |
| **Vibration Alert** | `NODE_ID: VIBRATION: Movement at HH:MM:SS [GPS=lat,lon]` | `NODE_ABC: VIBRATION: Movement at 12:34:56 GPS=40.7128,-74.0060` |
| **GPS Status** | `NODE_ID: GPS: STATUS Location:lat,lon Satellites:N HDOP:X.XX` | `NODE_ABC: GPS: LOCKED Location=40.7128,-74.0060 Satellites=8 HDOP=1.23` |
| **RTC Sync** | `NODE_ID: RTC_SYNC: YYYY-MM-DD HH:MM:SS UTC` | `NODE_ABC: RTC_SYNC: 2025-09-19 12:34:56 UTC` |
| **Node Heartbeat** | `[NODE_HB] NODE_ID Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC/XX.XF [GPS:lat,lon]` | `[NODE_ABC] NODE_ABC Time:2025-10-28_14:32:15 Temp:42.3C/108.1F GPS:40.7128,-74.0060` |
| **Setup Mode** | `NODE_ID: SETUP_MODE: Auto-erase activates in Xs` | `NODE_ABC: SETUP_MODE: Auto-erase activates in 120s` |
| **Config ACK** | `NODE_ID: CONFIG_ACK:TYPE:VALUE` | `NODE_ABC: CONFIG_ACK:CHANNELS:1,6,11` |
| **Scan ACK** | `NODE_ID: SCAN_ACK:STARTED` | `NODE_ABC: SCAN_ACK:STARTED` |
| **Device Scan ACK** | `NODE_ID: DEVICE_SCAN_ACK:STARTED` | `NODE_ABC: DEVICE_SCAN_ACK:STARTED` |
| **Drone ACK** | `NODE_ID: DRONE_ACK:STARTED` | `NODE_ABC: DRONE_ACK:STARTED` |
| **Deauth ACK** | `NODE_ID: DEAUTH_ACK:STARTED` | `NODE_ABC: DEAUTH_ACK:STARTED` |
| **Randomization ACK** | `NODE_ID: RANDOMIZATION_ACK:STARTED` | `NODE_ABC: RANDOMIZATION_ACK:STARTED` |
| **Baseline ACK** | `NODE_ID: BASELINE_ACK:STARTED` | `NODE_ABC: BASELINE_ACK:STARTED` |
| **Baseline Status** | `NODE_ID: BASELINE_STATUS: Scanning:YES/NO Established:YES/NO Devices:N Anomalies:N Phase1:ACTIVE/COMPLETE` | `NODE_ABC: BASELINE_STATUS: Scanning:YES Established:NO Devices=42 Anomalies=3 Phase1:ACTIVE` |
| **Triangulation ACK** | `NODE_ID: TRIANGULATE_ACK:TARGET` | `NODE_ABC: TRIANGULATE_ACK:AA:BB:CC:DD:EE:FF` or `NODE_ABC: TRIANGULATE_ACK:T-sensor001` |
| **Triangulation Results** | `NODE_ID: TRIANGULATE_RESULTS_START` ... results ... `NODE_ID: TRIANGULATE_RESULTS_END` | Multi-line result output |
| **Triangulation Stop ACK** | `NODE_ID: TRIANGULATE_STOP_ACK` | `NODE_ABC: TRIANGULATE_STOP_ACK` |
| **Erase ACK** | `NODE_ID: ERASE_ACK:STATUS` | `NODE_ABC: ERASE_ACK:COMPLETE` or `NODE_ABC: ERASE_ACK:CANCELLED` |

---

### **Command Workflow Example**

#### Basic Operations
    @ALL STATUS
    @NODE_22 STATUS
    @ALL STOP
    @NODE_22 CONFIG_CHANNELS:1,6,11
    @ALL CONFIG_CHANNELS:1..14
    @NODE_22 CONFIG_TARGETS:AA:BB:CC:DD:EE:FF|11:22:33:44:55:66

#### Detection & Analysis
    @ALL DEVICE_SCAN_START:2:300
    @NODE_22 DEVICE_SCAN_START:2:300:FOREVER
    @ALL DRONE_START:600
    @NODE_22 DRONE_START:600:FOREVER
    @ALL DEAUTH_START:300
    @NODE_22 DEAUTH_START:300:FOREVER
    @ALL RANDOMIZATION_START:2:600
    @NODE_22 RANDOMIZATION_START:0:600:FOREVER

#### Baseline Detection
    @ALL BASELINE_START:300
    @NODE_22 BASELINE_START:600:FOREVER
    @ALL BASELINE_STATUS

#### Scanning
    @ALL SCAN_START:0:60:1,6,11
    @NODE_22 SCAN_START:2:300:1..14:FOREVER
    @ALL SCAN_START:1:120:1,6,11

#### Triangulation
    @ALL TRIANGULATE_START:AA:BB:CC:DD:EE:FF:300
    @NODE_22 TRIANGULATE_START:T-sensor001:600
    @ALL TRIANGULATE_STOP
    @NODE_22 TRIANGULATE_RESULTS

#### Security
    @NODE_22 VIBRATION_STATUS
    @NODE_22 ERASE_FORCE:AH_12345678_87654321_00001234
    @ALL ERASE_CANCEL

---

## **API Endpoints**

### **Core Functionality**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/` | GET | Main web interface | None |
| `/export` | GET | Export target MAC list | None |
| `/results` | GET | Latest scan/triangulation results | None |
| `/save` | POST | Save target configuration | `list` (text) |
| `/stop` | GET | Stop all operations | None |
| `/diag` | GET | System diagnostics | None |
| `/sniffer-cache` | GET | View cached device detections | None |

---

### **Node Configuration**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/node-id` | GET | Get current node ID | None |
| `/node-id` | POST | Set node ID | `id` (1-16 chars) |
| `/mesh-interval` | GET | Get mesh send interval | None |
| `/mesh-interval` | POST | Set mesh send interval | `interval` (1500-30000 ms) |
| `/config` | GET | Get system configuration | None |
| `/config` | POST | Update configuration | `channels` (CSV), `targets` (pipe-delimited) |
| `/api/time` | POST | Set RTC time from epoch | `epoch` (Unix timestamp, 1609459200-2147483647) |

---

### **Scanning Operations**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/scan` | POST | Start WiFi/BLE scan | `mode` (0=WiFi, 1=BLE, 2=Both), `secs` (0-86400), `forever`, `ch` (CSV/range), `triangulate`, `targetMac` |
| `/sniffer` | POST | Start detection mode | `detection` (device-scan, deauth, baseline, randomization-detection), `secs` (0-86400), `forever`, `randomizationMode` (for randomization-detection) |

---

### **Baseline Detection**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/baseline/status` | GET | Baseline scan status (JSON) | None |
| `/baseline/stats` | GET | Detailed baseline statistics (JSON) | None |
| `/baseline/config` | GET | Get baseline configuration (JSON) | None |
| `/baseline/config` | POST | Update baseline configuration | `rssiThreshold` (dBm), `baselineDuration` (secs), `ramCacheSize`, `sdMaxDevices`, `absenceThreshold` (secs), `reappearanceWindow` (secs), `rssiChangeDelta` (dBm) |
| `/baseline/reset` | POST | Reset baseline detection | None |
| `/baseline-results` | GET | View baseline detection results | None |

---

### **Drone Detection**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/drone` | POST | Start drone detection | `secs` (0-86400), `forever` |
| `/drone-results` | GET | View drone detection results | None |
| `/drone-log` | GET | Access drone event logs (JSON) | None |
| `/drone/status` | GET | Drone detection status (JSON) | None |

---

### **Deauthentication Detection**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/deauth-results` | GET | View deauthentication attack logs | None |

---

### **Randomization Detection**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/randomization-results` | GET | View randomization detection results | None |
| `/randomization/reset` | POST | Reset randomization detection | None |
| `/randomization/clear-old` | POST | Clear old device identities | `age` (seconds, optional) |
| `/randomization/identities` | GET | Get tracked device identities (JSON) | None |

---

### **Triangulation**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/triangulate/start` | POST | Start triangulation for target MAC | `mac` (AA:BB:CC:DD:EE:FF), `duration` (≥60 secs) |
| `/triangulate/stop` | POST | Stop triangulation | None |
| `/triangulate/status` | GET | Get triangulation status (JSON) | None |
| `/triangulate/results` | GET | Get triangulation results | None |
| `/triangulate/calibrate` | POST | Calibrate path loss for target | `mac` (AA:BB:CC:DD:EE:FF), `distance` (meters) |

---

### **Allowlist Management**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/allowlist-export` | GET | Export allowlist | None |
| `/allowlist-save` | POST | Save allowlist | `list` (text) |

---

### **Security & Erasure**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/erase/status` | GET | Check erasure status | None |
| `/erase/request` | POST | Request secure erase | `confirm` (WIPE_ALL_DATA), `reason` (optional) |
| `/erase/cancel` | POST | Cancel tamper erase sequence | None |
| `/secure/status` | GET | Tamper detection status | None |
| `/secure/abort` | POST | Abort tamper sequence | None |
| `/secure/destruct` | POST | Execute immediate secure wipe | `confirm` (WIPE_ALL_DATA) |
| `/secure/generate-token` | POST | Generate remote erase token | `target` (node ID), `confirm` (GENERATE_ERASE_TOKEN) |
| `/config/autoerase` | GET | Get auto-erase configuration (JSON) | None |
| `/config/autoerase` | POST | Update auto-erase configuration | `enabled` (true/false), `delay` (10000-300000ms), `cooldown` (60000-3600000ms), `vibrationsRequired` (2-10), `detectionWindow` (5000-120000ms), `setupDelay` (30000-600000ms) |

---

### **Mesh Networking**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/mesh` | POST | Enable/disable mesh networking | `enabled` (true/false) |
| `/mesh-test` | GET | Test mesh connectivity | None |

---

### **GPS & Hardware**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/gps` | GET | Current GPS status and location | None |
| `/sd-status` | GET | SD card status and health | None |

---

### **RF Configuration**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/rf-config` | GET | Get RF scan configuration (JSON) | None |
| `/rf-config` | POST | Update RF configuration | `preset` (uint8_t) OR `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration` |

---

### **WiFi Configuration**
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/wifi-config` | GET | Get WiFi AP settings (JSON) | None |
| `/wifi-config` | POST | Update WiFi AP settings | `ssid` (1-32 chars, required), `pass` (8-63 chars or empty, optional) |

## Credits

AntiHunter is the result of collaborative development by security researchers, embedded systems engineers, and open-source contributors.

**Team Antihunter**: Conceived by the visionary @TheRealSirHaXalot, a hardware development and design engineer who brings this endeavor to life. We collaborate on innovative concepts, transforming them into tangible reality.

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
