<div align="center">

[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![Pre-release](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)

</div>

<div align="center">
<img width="50%" height="50%" alt="image" src="https://github.com/user-attachments/assets/7fc3f42a-b582-4f67-820f-a0384a410480" />
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
8. [Web Interface](#web-interface)
9. [Mesh Network Integration](#mesh-network-integration)
10. [Command Reference](#command-reference)
11. [API Reference](#api-reference)

> [!NOTE]  
> **Early Release** - This is an alpha version. Expect stability issues, breaking changes, and unexpected behavior. Hardware requirements and features are rapidly evolving.

## Overview

**AntiHunter** is a low-cost, open-source distributed perimeter defense system for wireless network security and operational awareness. It enables comprehensive monitoring and protection of wireless environments, transforming spectrum activity into actionable security intelligence for defensive operations.

Built on the ESP32-S3 platform with mesh networking, AntiHunter creates a scalable sensor network for real-time threat detection, device mapping, and perimeter security. The system combines WiFi/BLE scanning, GPS positioning, environmental sensors, and distributed coordination to provide a digital and physical "tripwire". 


## Primary Detection Modes

![image](https://github.com/user-attachments/assets/b3be1602-c651-41d2-9caf-c2e4956d3aff)

### 1. **List Scan Mode**
Maintain a watchlist of target MAC addresses (full 6-byte) or OUI prefixes (first 3-byte vendor IDs). AntiHunter systematically sweeps designated WiFi channels and BLE frequencies, providing immediate alerts and detailed logging when targets are detected.

- **Targeted Monitoring**: Track specific devices by MAC address or vendor OUI prefix
- **Dual Protocol Scanning**: WiFi-only, BLE-only, or combined WiFi+BLE modes
- **Global Allowlist**: User configurable, applies to all scans. 
- **Logging**: Records RSSI, channel, GPS coordinates, and device names to SD card
- **Real-time Alerts**: Immediate notifications via web interface, AH command center and mesh network. 

### 2. Triangulation/Trilateration  (Distributed)
Triangulation coordinates multiple AntiHunter nodes across a mesh network to achieve precise location tracking of target devices. Each node simultaneously scans for the specified target, recording signal strength (RSSI) and GPS coordinates, syncing RTCs for precision. Detection data is aggregated and forwarded over mesh to the AP and command center for more advanced trilateration processing.

**`EXPERIMENTAL T114 SUPPORT:`** small buffer and slow speed causes some latency. Using a Heltec v3 is recommended but not required.

- **Multi-node Coordination**: Distributed scanning across mesh network nodes
- **GPS Integration**: Each node contributes location data for accurate positioning
- **Weighted GPS Trilateration**: - Method: Weighted trilateration + Kalman filtering. Average HDOP, GPS Coordinates, Confidence, Est.Uncertainty (m), Sync Status, GPS Quality. Google Maps link sent over mesh with details

### 3. **Detection & Analysis Sniffers**
   
   **A. Device Scanner**
   - Captures all WiFi and Bluetooth devices in range
   - Records MAC addresses, SSIDs, signal strength, names and channels
   - Provides complete 2.4GHz wireless spectrum visibility
   
   **B. Baseline Anomaly Detection**
   - Two-phase scanning: establishes baseline, then monitors for anomalies
   - Detects new devices, disappeared/reappeared devices, significant RSSI changes
   - Configurable RAM cache (200-500 devices) and SD storage (1K-100K devices). Defaults to 1500 devices if no SD card. 
   - Persistent storage with automatic tiering, survives reboots
   - Real-time mesh alerts with GPS coordinates and anomaly reasons
   - Use cases: distributed "trail cam" for poachers/trespassers, perimeter security, surveillance detection, threat identification
   
   **C. Deauthentication Attack Scan**
   - WiFi deauth/disassoc attack sniffer with frame filtering and real-time detection
   - Integration with randomization tracking for source identification
   
   **D. Drone RID Detection**
   - Identifies drones broadcasting Remote ID (FAA/EASA compliant)
   - Supports ODID/ASTM F3411 protocols (NAN action frames and beacon frames)
   - Detects French drone ID format (OUI 0x6a5c35)
   - Extracts UAV ID, pilot location, and flight telemetry data
   - Sends immediate mesh alerts with drone detection data, logs to SD card and two API endpoints for data
   
   **E. MAC Randomization Analyzer**
   ![384F3718-6308-477C-B882-477FCF25578C_4_5005_c](https://github.com/user-attachments/assets/601def0d-c5f0-4089-ac33-3b59b51eae48)

   **`EXPERIMENTAL FEATURE`**
   - Traces device identities across randomized MAC addresses using behavioral signatures
   - IE fingerprinting, channel sequencing, timing analysis, RSSI patterns, and sequence number correlation
   - Assigns unique identity IDs (format: `T-XXXX`) with persistent SD storage
   - Supports up to 30 simultaneous device identities with up to 50 linked MACs each
   - Dual signature support (full and minimal IE patterns)
   - Confidence-based linking with threshold adaptation
   - Detects global MAC leaks and WiFi-BLE device correlation


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

## RF Configuration

AntiHunter provides adjustable RF scan parameters to optimize detection performance for different operational scenarios. Configuration is available through both the web interface and API endpoints.

### Scan Presets

| Preset | WiFi Channel Time | WiFi Scan Interval | BLE Scan Interval | BLE Scan Duration | Use Case |
|--------|-------------------|-------------------|-------------------|-------------------|----------|
| **Relaxed** | 300ms | 8000ms | 4000ms | 3000ms | Low power, stealthy operations |
| **Balanced** | 160ms | 6000ms | 3000ms | 3000ms | General use, default configuration |
| **Aggressive** | 110ms | 4000ms | 2000ms | 2000ms | Fast detection, high coverage |
| **Custom** | User-defined | User-defined | User-defined | User-defined | Fine-tuned for specific requirements |

### Parameter Definitions

- **WiFi Channel Time**: Duration spent on each WiFi channel (50-300ms)
- **WiFi Scan Interval**: Time between WiFi scan cycles (1000-10000ms)
- **BLE Scan Interval**: Time between BLE scan cycles (1000-10000ms)
- **BLE Scan Duration**: Active BLE scanning duration per cycle (1000-5000ms)
- **WiFi Channels**: Comma-separated list (1,6,11) or range (1..14) of 2.4GHz channels to scan

### Channel Configuration

WiFi channels accept two formats:
- **Range**: `1..14` scans all channels from 1 to 14
- **CSV**: `1,6,11` scans only specified channels

Valid channels: 1-14 (2.4GHz band). Default: 1,6,11 if no channels specified.

### Web Interface Configuration

1. Navigate to the web interface at `http://192.168.4.1`
2. Locate the RF Settings section
3. Select a preset from the dropdown or choose "Custom" for manual tuning
4. For custom configuration:
   - Adjust individual timing parameters
   - Specify WiFi channels using CSV or range notation
5. Click "Save RF Settings" to apply changes

### API Configuration

**Get current RF settings:**
```
GET /rf-config
```

**Update RF settings (preset):**
```
POST /rf-config
Content-Type: application/x-www-form-urlencoded

preset=1
```

**Update RF settings (custom with channels):**
```
POST /rf-config
Content-Type: application/x-www-form-urlencoded

wifiChannelTime=120&wifiScanInterval=5000&bleScanInterval=2500&bleScanDuration=2500&channels=1,6,11
```

### Configuration Persistence

All RF settings are automatically persisted to NVS (non-volatile storage) and restored on reboot. When an SD card is present, settings are also saved to `/config.json` for backup and portability across devices.

### Operational Considerations

- **Lower intervals**: Increase detection speed and coverage but consume more power
- **Higher intervals**: Reduce power consumption and RF noise but may miss brief transmissions
- **Channel time**: Affects WiFi channel hop rate; shorter times provide faster channel coverage
- **BLE duration**: Longer durations improve BLE device discovery but reduce WiFi scan frequency
- **Channel selection**: Limit to specific channels (1,6,11) for focused monitoring or use full range (1..14) for comprehensive coverage

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
- Performs advanced trilateration calculations
- Provides real-time mapping and visualization
- Enables coordinated response operations
- Maintains historical threat intelligence


## Hardware Requirements

_PCBs and kits are in final production. Tindie link coming soon_

### Enclosure STL Files
- Find them in the hw folder [here](https://github.com/lukeswitz/AntiHunter/tree/main/hw/Prototype_STL_Files)

### **Core Components**
- **ESP32-S3 Development Board** (Seeed Studio XIAO ESP32S3 recommended)
  - Minimum 8MB flash memory required for reliable operation)
- **Meshtastic Board** (LoRa-based mesh networking) Heltec v3.2 (recommended) or T114
- **GPS Module** (NMEA-compatible)
- **SD Card Module** (FAT32, 16GB)
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

### Quick Flasher

For rapid deployment without building from source, precompiled binaries are available.

**Linux/macOS:**
```bash
# Download the flasher script
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh

# Run the flasher script with default configuration (Full AP Firmware)
./flashAntihunter.sh
```

**Headless Configuration (Optional):**

Configuration on flash requires the bootloader and partitions files from `Dist/` folder in the same directory.
```bash
# Run the flasher script with interactive configuration (Headless Firmware)
./flashAntihunter.sh -c -e
```

**Flashing Process:**
1. Connect your ESP32-S3 board via USB
2. Run the flasher script and follow prompts
3. Device will reboot with AntiHunter firmware

**Post-Flash Setup:**

**Full Firmware:**
- Connect to `Antihunter` WiFi AP (password: `ouispy123`)
- Access web interface at `http://192.168.4.1`
- Change SSID and password in RF Settings

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

## Web Interface

Access the AntiHunter web interface after flashing:
- Connect to `Antihunter` WiFi AP (password: `ouispy123`)
- Navigate to `http://192.168.4.1`
- Configure RF settings, detection modes, and security parameters

Change SSID and password in RF Settings panel.

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

### Node Addressing Format
- **Specific Node**: `@NODE_22 COMMAND` - Targets individual node
- **All Nodes**: `@ALL COMMAND` - Broadcast to entire network
- **Node ID**: Up to 16 alphanumeric characters
- **Response**: All responses prefixed with sending Node ID

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
| `TRIANGULATE_START` | `target:duration` | Initiates triangulation for target MAC (AA:BB:CC:DD:EE:FF) or Identity ID (T-XXXX) with duration in seconds | `@ALL TRIANGULATE_START:AA:BB:CC:DD:EE:FF:300` or `@ALL TRIANGULATE_START:T-002F:300` |
| `TRIANGULATE_STOP` | None | Halts ongoing triangulation operation | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | None | Retrieves calculated triangulation results for all nodes | `@NODE_22 TRIANGULATE_RESULTS` |
| `ERASE_FORCE` | `token` | Forces emergency data erasure with auth token | `@NODE_22 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | None | Cancels ongoing erasure sequence | `@ALL ERASE_CANCEL` |

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
| **Deauth Attack (Short)** | `NODE_ID: ATTACK: DEAUTH/DISASSOC SRC->DST RX CHN` | `NODE_ABC: ATTACK: DEAUTH AA:BB:CC:DD:EE:FF->11:22:33:44:55:66 R-45 C6` |

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
| **Startup Status** | `NODE_ID: STARTUP: System initialized GPS:LOCKED/SEARCHING TEMP:XXC SD:OK/FAIL Status:ONLINE` | `NODE_ABC: STARTUP: System initialized GPS:LOCKED TEMP:42.3C SD:OK Status:ONLINE` |
| **Node Heartbeat** | `NODE_ID Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC [GPS:lat,lon]` | `[NODE_HB] NODE_ABC Time:2025-10-28_14:32:15 Temp:42.3C GPS:40.7128,-74.0060` |
| **GPS Locked** | `NODE_ID: GPS: LOCKED Location=lat,lon Satellites:N HDOP:X.XX` | `NODE_ABC: GPS: LOCKED Location=40.7128,-74.0060 Satellites=8 HDOP=1.23` |
| **GPS Lost** | `NODE_ID: GPS: LOST` | `NODE_ABC: GPS: LOST` |
| **RTC Sync** | `NODE_ID: RTC_SYNC: GPS/NTP` | `NODE_ABC: RTC_SYNC: GPS` |
| **Time Sync Request** | `NODE_ID: TIME_SYNC_REQ:epoch:subsec:micros:propDelay` | `NODE_ABC: TIME_SYNC_REQ:1725000000:5000:123456:0` |
| **Time Sync Response** | `NODE_ID: TIME_SYNC_RESP:epoch:subsec:micros:propDelay` | `NODE_ABC: TIME_SYNC_RESP:1725000000:5000:123456:50` |
| **Config ACK** | `NODE_ID: CONFIG_ACK:TYPE:VALUE` | `NODE_ABC: CONFIG_ACK:CHANNELS:1,6,11` |
| **Scan ACK** | `NODE_ID: SCAN_ACK:STARTED` | `NODE_ABC: SCAN_ACK:STARTED` |
| **Device Scan ACK** | `NODE_ID: DEVICE_SCAN_ACK:STARTED` | `NODE_ABC: DEVICE_SCAN_ACK:STARTED` |
| **Drone ACK** | `NODE_ID: DRONE_ACK:STARTED` | `NODE_ABC: DRONE_ACK:STARTED` |
| **Deauth ACK** | `NODE_ID: DEAUTH_ACK:STARTED` | `NODE_ABC: DEAUTH_ACK:STARTED` |
| **Randomization ACK** | `NODE_ID: RANDOMIZATION_ACK:STARTED` | `NODE_ABC: RANDOMIZATION_ACK:STARTED` |
| **Baseline ACK** | `NODE_ID: BASELINE_ACK:STARTED` | `NODE_ABC: BASELINE_ACK:STARTED` |
| **Baseline Status** | `NODE_ID: BASELINE_STATUS: Scanning:YES/NO Established:YES/NO Devices:N Anomalies:N Phase1:ACTIVE/COMPLETE` | `NODE_ABC: BASELINE_STATUS: Scanning:YES Established:NO Devices:42 Anomalies:3 Phase1:ACTIVE` |
| **Triangulation ACK** | `NODE_ID: TRIANGULATE_ACK:TARGET` | `NODE_ABC: TRIANGULATE_ACK:AA:BB:CC:DD:EE:FF` or `NODE_ABC: TRIANGULATE_ACK:T-0001` |
| **Triangulation Results** | `NODE_ID: TRIANGULATE_RESULTS_START` ... results ... `NODE_ID: TRIANGULATE_RESULTS_END` | Multi-line result output |
| **Triangulation Stop ACK** | `NODE_ID: TRIANGULATE_STOP_ACK` | `NODE_ABC: TRIANGULATE_STOP_ACK` |
| **Stop ACK** | `NODE_ID: STOP_ACK:OK` | `NODE_ABC: STOP_ACK:OK` |
| **Wipe Token** | `NODE_ID: WIPE_TOKEN:token_string` | `NODE_ABC: WIPE_TOKEN:AH_12AB34CD_56EF78GH_1234567890` |
| **Reboot ACK** | `NODE_ID: REBOOT_ACK` | `NODE_ABC: REBOOT_ACK` |


---

## API Reference

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
| `/rf-config` | GET | - | Get RF scan configuration (JSON) |
| `/rf-config` | POST | `preset` OR `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `channels` | Update RF configuration |
| `/wifi-config` | GET/POST | `ssid`, `pass` | Get/update WiFi AP settings |

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
| `/erase/request` | POST | `confirm` (WIPE_ALL_DATA), `reason` (optional) | Request secure erase |
| `/erase/cancel` | POST | - | Cancel tamper erase sequence |
| `/secure/status` | GET | - | Tamper detection status |
| `/secure/abort` | POST | - | Abort tamper sequence |
| `/secure/destruct` | POST | `confirm` (WIPE_ALL_DATA) | Execute immediate secure wipe |
| `/secure/generate-token` | POST | `target`, `confirm` (GENERATE_ERASE_TOKEN) | Generate remote erase token |
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
