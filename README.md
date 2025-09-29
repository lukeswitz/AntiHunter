[![Pre-release](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/commits/main/)
[![GitHub repo size](https://img.shields.io/github/repo-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter/src)

<img width="90%" height="90%" src="https://github.com/user-attachments/assets/89a970a4-3f95-4b3d-8788-0d09ff33110d"/>

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

Built on the ESP32-S3 platform with mesh networking, AntiHunter creates a scalable sensor network for real-time threat detection, device tracking, and perimeter security. The system combines WiFi/BLE scanning, GPS positioning, environmental sensors, and distributed coordination to provide robust wireless security capabilities.

## Core Capabilities

### Primary Detection Modes

#### 1. **List Scan Mode**
Maintain a watchlist of target MAC addresses (full 6-byte) or OUI prefixes (first 3-byte vendor IDs). AntiHunter systematically sweeps designated WiFi channels and BLE frequencies, providing immediate alerts and detailed logging when targets are detected.

**Key Features:**
- **Targeted Monitoring**: Track specific devices by MAC address or vendor OUI prefix
- **Dual Protocol Scanning**: WiFi-only, BLE-only, or combined WiFi+BLE modes
- **Logging**: Records RSSI, channel, GPS coordinates, and device names to SD card
- **Real-time Alerts**: Immediate notifications via web interface, AH command center and mesh network. 
- **Use Cases**:
  - Passive monitoring of authorized devices in secure environments
  - Wireless survey and network auditing
  - Rogue access point and suspicious beacon identification

#### 2. **Experimental: Triangulation  (Distributed Tracking)**
Triangulation coordinates multiple AntiHunter nodes across a mesh network to achieve precise location tracking of target devices. Each node simultaneously scans for the specified target, recording signal strength (RSSI) and GPS coordinates. Detection data is aggregated and forwarded to the command center for advanced trilateration processing.

**Key Features:**
- **Multi-node Coordination**: Distributed scanning across mesh network nodes
- **GPS Integration**: Each node contributes location data for accurate positioning
- **Real-time Tracking**: Continuous monitoring with position updates
- **AH Command Center Integration**: Data forwarded for centralized processing, MQTT broker and mapping. 
- **Use Cases**:
  - Perimeter defense and intrusion detection
  - Asset tracking and geofencing
  - Incident response and tactical operations
  - Large-area device monitoring

#### 3. **Detection & Analysis**
Comprehensive wireless environment analysis combining general device discovery, baseline anomaly detection, and specialized Remote ID drone detection.

**Device Scanner:**
- Captures all WiFi and Bluetooth devices in range
- Records MAC addresses, SSIDs, signal strength, and channels
- Provides complete 2.4GHz wireless spectrum visibility

**Baseline Anomaly Detection:**
- Two-phase scanning: establishes normal environment baseline, then monitors for new devices
- Configurable RSSI threshold for proximity-based alerting
- Real-time progress tracking with WiFi/BLE device breakdown
- Use cases: perimeter awareness, detecting approaching devices, identifying new threats

**RID Drone Detection:**
- Identifies drones broadcasting Remote ID (FAA/EASA compliant)
- Supports ODID/ASTM F3411 protocols (NAN action frames and beacon frames)
- Detects French drone ID format (OUI 0x6a5c35)
- Extracts UAV ID, pilot location, flight telemetry, and operator information
- Sends immediate mesh alerts with drone detection data, logs to SD card and two API endpoints for data

**Coming: Threat Detection Capabilities:**
- Deauth/disassoc attack detection (flood and targeted)
- WiFi Pineapple and rogue access point identification
- Pwnagotchi device detection
- Evil twin and multi-SSID attack detection
- Beacon flood and probe request flood monitoring
- EAPOL handshake capture detection
- Karma attack identification

**Use Cases:**
- Airport and critical infrastructure drone monitoring
- Counter-UAS operations and airspace security
- Perimeter security and intrusion detection
- WiFi penetration testing and security auditing
- Event security and crowd monitoring
- Red team detection and defensive operations
- Wireless threat hunting and forensics

---

### Sensor Integration

#### **GPS Positioning**
- **Interface**: UART2 (RX=GPIO44, TX=GPIO43) at 9600 baud using TinyGPS++
- **Functionality**: Parses NMEA sentences for location, altitude, and satellite data
- **Web Interface**: Real-time GPS status, last known position, and fix quality
- **API Endpoint**: `/gps` returns current latitude/longitude coordinates
- **Integration**: All detection events include GPS coordinates when available

#### **SD Card Logging**
- **Interface**: SPI (CS=GPIO2, SCK=GPIO7, MISO=GPIO8, MOSI=GPIO9)
- **Storage**: Logs to `/antihunter.log` with timestamps, detection types, and metadata
- **Format**: Structured entries including MAC addresses, RSSI, GPS data, and timestamps
- **Diagnostics**: Web interface shows storage status and usage statistics

#### **Vibration/Tamper Detection**
- **Sensor**: SW-420 vibration sensor connected to GPIO1
- **Detection**: Interrupt-driven monitoring with 5-second rate limiting
- **Alerts**: Mesh network notifications with GPS coordinates and timestamps
- **Format**: `NODE_ABC: VIBRATION: Movement detected at HH:MM:SS GPS:lat,lon`
- **Status**: Real-time sensor state displayed in diagnostics panel

#### **Real-Time Clock (RTC)**
- **Module**: DS3231 RTC via I2C (SDA=GPIO6, SCL=GPIO3)
- **Functionality**: Accurate timekeeping during power outages and GPS synchronization
- **Features**: Automatic time sync from GPS, manual time setting, sync status monitoring
- **Web Interface**: Current time display and synchronization status

--- 

## Secure Data Destruction

AntiHunter includes tamper detection and emergency data wiping capabilities to protect surveillance data from unauthorized access.

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
- All erase attempts are logged with GPS coordinates and timestamps
- Secure wipe process overwrites data before deletion

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
6. **Response Actions**: Local and coordinated responses based on threat assessment

### **Command Center Integration**
While individual nodes provide standalone capability, the full system power comes from integration with a central command center that:
- Aggregates detection data from all nodes
- Performs advanced trilateration calculations
- Provides real-time mapping and visualization
- Enables coordinated response operations
- Maintains historical threat intelligence

## Hardware Requirements

_PCBs and kits in production_

<img width="500" src="https://github.com/user-attachments/assets/1cdfc65f-3dd3-4290-9ae9-adbfecaf7381">


### **Core Components**
- **ESP32-S3 Development Board** (Seeed Studio XIAO ESP32S3 recommended)
  - Minimum 8MB flash memory required for reliable operation
  - Supports WiFi 2.4GHz and Bluetooth Low Energy scanning
- **Meshtastic Board** (LoRa-based mesh networking)
  - Extends operational range beyond WiFi/Bluetooth limits
- **GPS Module** (NMEA-compatible)
  - UART2 connection (RX=GPIO44, TX=GPIO43) at 9600 baud
  - Provides location data for all detections
- **SD Card Module** (microSD compatible)
  - SPI connection for persistent logging
  - Stores detection history and system diagnostics

### **Environmental Sensors**
- **SW-420 Vibration Sensor**
  - GPIO1 connection for tamper/movement detection
  - Interrupt-driven monitoring with mesh alerts
- **DS3231 RTC Module**
  - I2C connection (SDA=GPIO6, SCL=GPIO3)

### **Pinout Reference**

> [!IMPORTANT]  
> **Hardware Note**: This is an early-stage project. Pin assignments and hardware requirements will evolve as the system matures. Always verify compatibility with your specific board.

| **Function** | **GPIO Pin** | **Description** |
|--------------|--------------|-----------------|
| Vibration Sensor | GPIO1 | SW-420 tamper detection (interrupt) |
| RTC SDA | GPIO6 | DS3231 I2C data line |
| RTC SCL | GPIO3 | DS3231 I2C clock line |
| GPS RX | GPIO44 | NMEA data receive |
| GPS TX | GPIO43 | GPS transmit (unused) |
| SD CS | GPIO2 | SD card chip select |
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
# Download and run the flasher script
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

**Process:**
1. Connect your ESP32-S3 board via USB
2. Run the flasher script
3. The device will reboot with AntiHunter firmware
4. Connect to the `Antihunter` WiFi AP (password: `ouispy123`)
5. Access the web interface at `http://192.168.4.1`

### **Development Setup**

For developers and advanced users:

#### **Prerequisites**
- **Visual Studio Code** with PlatformIO IDE extension
- **Git** for repository management
- **ESP32-S3 development board** (8MB flash minimum)
- **USB cable** for programming and debugging
- **Optional**: Hardware components for full functionality

#### **Repository Setup**
```bash
# Clone the AntiHunter repository
git clone https://github.com/lukeswitz/AntiHunter.git AntiHunter_Project
cd AntiHunter_Project

# Open in VS Code (with PlatformIO extension)
code .
```

PlatformIO will automatically detect the `platformio.ini` configuration file and set up the development environment.

#### **Firmware Flashing**

1. **Connect Hardware**: Plug your ESP32-S3 board into USB
2. **Select Environment**: In VS Code's PlatformIO toolbar, select the `AntiHunter` environment
3. **Build & Upload**: Click the "Upload" button (→) in the PlatformIO status bar
4. **Monitor Output**: Use the Serial Monitor to verify successful boot


## Web Interface

After flashing, AntiHunter creates a WiFi access point for configuration and monitoring.

<img width="1077" height="1211" alt="s" src="https://github.com/user-attachments/assets/d8a4522a-9158-446a-8211-8e8a8d21f158" />

### **Connection**
1. **Join Network**: Connect to `Antihunter` WiFi AP
   - **Password**: `ouispy123`
   - **IP Address**: `192.168.4.1`
2. **Access Interface**: Open browser to `http://192.168.4.1`

### **Main Interface Sections**

#### **Target Configuration**
- **Watchlist Management**: Add/remove MAC addresses and OUI prefixes
- **Format**: Full MAC (`AA:BB:CC:DD:EE:FF`) or OUI (`AA:BB:CC`)
- **Export/Import**: Save/load target lists for deployment
- **Validation**: Real-time format checking and duplicate detection

#### **Scanning Operations**
- **List Scan**: Area surveillance for configured targets
  - **Modes**: WiFi Only, BLE Only, WiFi+BLE Combined
  - **Duration**: Configurable scan time (0 = continuous)
  - **Channels**: Custom WiFi channel selection (`1,6,11` or `1..14`)
  - **Triangulation**: Enable multi-node tracking (requires mesh, GPS, RTC)

- **Triangulation Mode**:
  - **Target MAC**: Specify device for location tracking
  - **Node Coordination**: Automatically syncs with mesh network
  - **Duration**: Tracking period for position calculations
  - **Status**: Shows participating nodes and signal data

#### **Detection & Analysis**
- **Device Discovery**: General scanning for all WiFi/BLE devices
- **Drone WiFi RID**: Detect remote ID compliant drones & pilots
- **Cache Viewer**: Recent device history and signal patterns

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

#### **Network Configuration**
- **Node Identification**: Set unique node ID (1-16 characters)
- **Mesh Integration**: Enable/disable Meshtastic communications

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
- **Connection**: UART1 (RX=GPIO4, TX=GPIO5) at 115200 baud
- **Protocol**: Standard Meshtastic serial interface
- **Configuration**: Set the device to the following under Serial Settings

![image](https://github.com/user-attachments/assets/76a74acc-b14b-433a-86ea-b817ccec0343)


### **Network Behavior**
- **Alert Rate Limiting**: 10-second intervals prevent mesh flooding
- **Node Identification**: Each device uses a unique Node ID prefix
- **Broadcast Commands**: `@ALL` commands coordinate multiple nodes
- **Targeted Control**: `@NODE_XX` commands address specific nodes
- **Status Reporting**: Periodic heartbeats and operational status

## Command Reference

> [!IMPORTANT]
> Node and command names are case sensitive 

### **Node Addressing**
- **Specific Node**: `@NODE_22 COMMAND` - Targets individual node
- **All Nodes**: `@ALL COMMAND` - Broadcast to entire network
- **Node ID Format**: Up to 16 alphanumeric characters
- **Response Format**: All responses prefixed with sending Node ID

### **Core Commands**

## Mesh Commands

| Command | Parameters | Description | Example |
|---------|------------|-------------|---------|
| `STATUS` | None | Reports current system status | `@NODE_22 STATUS` |
| `CONFIG_CHANNELS` | `list` (CSV/range) | Configures WiFi channels | `@NODE_22 CONFIG_CHANNELS:1,6,11` |
| `CONFIG_TARGETS` | `macs` (pipe-delimited) | Updates target watchlist | `@NODE_22 CONFIG_TARGETS:AA:BB:CC\|DD:EE:FF` |
| `SCAN_START` | `m:s:ch[:F]` | Starts scanning operation | `@NODE_22 SCAN_START:0:60:1,6,11` |
| `TRIANGULATE_START` | `MAC:s` | Initiates triangulation | `@NODE_22 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:300` |
| `STOP` | None | Stops all operations | `@NODE_22 STOP` |
| `VIBRATION_STATUS` | None | Checks tamper sensor status | `@NODE_22 VIBRATION_STATUS` |
| `ERASE_FORCE` | `token` | Forces emergency data erasure | `@NODE_22 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | None | Cancels ongoing erasure | `@NODE_22 ERASE_CANCEL` |
| `ERASE_STATUS` | None | Checks erasure status | `@NODE_22 ERASE_STATUS` |

## Specialized Detection Modes

| Command | Parameters | Description | Example |
|---------|------------|-------------|---------|
| `DRONE_DETECT` | `detection`, `secs`, `forever` | Detects drones via remote ID | `@ALL DRONE:drone-detection:60` |
| `DEAUTH_DETECT` | `detection`, `secs`, `forever` | Detects deauthentication attacks | `@ALL DEAUTH:deauth:120` |
| `BEACON_FLOOD_DETECT` | `detection`, `secs`, `forever` | Detects beacon flooding | `@ALL BEACON:beacon-flood:300` |
| `KARMA_DETECT` | `detection`, `secs`, `forever` | Karma attack detection | `@ALL KARMA:karma:180` |
| `PROBE_FLOOD_DETECT` | `detection`, `secs`, `forever` | Probe flood detection | `@ALL PROBE:probe-flood:240` |
| `BLE_SPAM_DETECT` | `detection`, `secs`, `forever` | BLE advertisement spam detection | `@ALL BLE:ble-spam:180` |

## Security Features

### Emergency Data Erasure
- **ERASE_FORCE**: Requires authentication token to initiate secure erasure
- **ERASE_CANCEL**: Aborts ongoing erasure sequences
- **ERASE_STATUS**: Monitors erasure progress and status

### Auto-Erase Configuration
Configurable parameters:
- `autoEraseEnabled`: Toggle auto-erasure on/off
- `autoEraseDelay`: Time before activation (milliseconds)
- `autoEraseCooldown`: Recovery period after erasure (milliseconds)
- `vibrationsRequired`: Number of vibrations to trigger
- `detectionWindow`: Time window for vibration detection
- `setupDelay`: Activation delay after power-up

## API Endpoints

### Core Functionality
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web interface |
| `/export` | GET | Export target MAC list |
| `/results` | GET | Latest scan/triangulation results |
| `/save` | POST | Save configuration changes |
| `/node-id` | POST/GET | Node identifier management |
| `/scan` | POST | Start scanning operation |
| `/gps` | GET | Current GPS status and location |
| `/sd-status` | GET | SD card status and health |
| `/stop` | GET | Stop all operations |
| `/config` | GET/POST | System configuration |
| `/mesh` | POST | Enable/disable mesh networking |
| `/mesh-test` | GET | Test mesh connectivity |

### Detection Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/drone` | POST | Start drone detection |
| `/drone-results` | GET | View drone detection results |
| `/drone-log` | GET | Access drone event logs |
| `/sniffer` | POST | Start generic sniffer operation |
| `/sniffer-cache` | GET | View cached device detections |
| `/deauth-results` | GET | View deauthentication attack logs |

## Alert Messages

| Alert Type | Format | Example |
|------------|--------|---------|
| **Target Detected** | `NODE_ID: Target: TYPE MAC RSSI:dBm [Name] [GPS=lat,lon]` | `NODE_ABC: Target: WiFi AA:BB:CC:DD:EE:FF RSSI:-62 Name:Device GPS=40.7128,-74.0060` |
| **Vibration Alert** | `NODE_ID: VIBRATION: Movement at HH:MM:SS [GPS=lat,lon]` | `NODE_ABC: VIBRATION: Movement at 12:34:56 GPS=40.7128,-74.0060` |
| **GPS Status Change** | `NODE_ID: GPS: STATUS Location:lat,lon Satellites:N HDOP:X.XX` | `NODE_ABC: GPS: LOCKED Location=40.7128,-74.0060 Satellites=8 HDOP=1.23` |
| **RTC Sync** | `NODE_ID: RTC_SYNC: YYYY-MM-DD HH:MM:SS UTC` | `NODE_ABC: RTC_SYNC: 2025-09-19 12:34:56 UTC` |
| **Node Heartbeat** | `[NODE_ID] NODE_ID GPS:lat,lon` | `[NODE_ABC] NODE_ABC GPS=40.7128,-74.0060` |

## Diagnostics

### System Diagnostics Endpoint
- `/diag` provides comprehensive system diagnostics including:
  - Hardware status (temperature, voltage)
  - Network configuration (AP, mesh)
  - Scan statistics
  - Memory usage
  - Error logs

### **Parameter Reference**

**Scan Parameters:**
- `mode`: `0` = WiFi Only, `1` = BLE Only, `2` = WiFi+BLE
- `secs`: Duration in seconds (0 = continuous operation)
- `forever`: `1` = Run indefinitely
- `ch`: WiFi channels (`1,6,11` or `1..14`)

**Triangulation Parameters:**
- `triangulate`: `1` = Enable multi-node tracking
- `targetMac`: Target device MAC address for location tracking

**Detection Modes:**
- `device-scan`: General WiFi/BLE device discovery

In testing:
- `deauth`: Deauthentication attack detection
- `beacon-flood`: Rogue beacon flood monitoring
- `karma`: Karma attack detection
- `probe-flood`: Probe request flood detection
- `ble-spam`: BLE advertisement spam detection

## Credits

AntiHunter is the result of collaborative development by security researchers, embedded systems engineers, and open-source contributors.

The project continues to evolve through community contributions. Contributions via pull requests, issue reports, and documentation improvements are welcome.

## Legal Disclaimer

```
AntiHunter (AH) is provided for lawful, authorized use only—such as research, training, and security operations on systems and radio spectrum you own or have explicit written permission to assess. You are solely responsible for compliance with all applicable laws and policies, including privacy/data-protection (e.g., GDPR), radio/telecom regulations (LoRa ISM band limits, duty cycle), and export controls. Do not use AH to track, surveil, or target individuals, or to collect personal data without a valid legal basis and consent where required.

The software is provided “AS IS” without warranty of any kind. Authors and contributors are not liable for misuse, damages, or legal consequences arising from use of this project.
By using AHCC, you accept full responsibility for your actions and agree to indemnify the authors and contributors against any claims related to your use.
These tools are designed for ethical blue team use, such as securing events, auditing networks, or training exercises. To implement in code, ensure compliance with local laws (e.g., FCC regulations on transmissions) and pair with a directional antenna for enhanced accuracy.

THE SOFTWARE IN THIS REPOSITORY (“SOFTWARE”) IS PROVIDED “AS IS” AND “AS AVAILABLE,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, OR RELIABILITY. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL THE DEVELOPERS, MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OF OR OTHER DEALINGS IN THE SOFTWARE, INCLUDING WITHOUT LIMITATION ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, OR LOSS OF DATA, PROFITS, GOODWILL, OR BUSINESS INTERRUPTION, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

YOU ALONE ARE RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS, REGULATIONS, AND THIRD-PARTY RIGHTS. NO ADVICE OR INFORMATION, WHETHER ORAL OR WRITTEN, OBTAINED FROM THE PROJECT OR THROUGH THE SOFTWARE, CREATES ANY WARRANTY OR OBLIGATION NOT EXPRESSLY STATED HEREIN. IF APPLICABLE LAW DOES NOT ALLOW THE EXCLUSION OF CERTAIN WARRANTIES OR LIMITATION OF LIABILITY, THE DEVELOPERS’, MAINTAINERS’, AND CONTRIBUTORS’ AGGREGATE LIABILITY SHALL NOT EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID (IF ANY) FOR THE COPY OF THE SOFTWARE THAT GAVE RISE TO THE CLAIM, OR (B) USD $0.

BY ACCESSING, DOWNLOADING, INSTALLING, COMPILING, EXECUTING, OR OTHERWISE USING THE SOFTWARE, YOU ACCEPT THIS DISCLAIMER AND THESE LIMITATIONS OF LIABILITY.
```
