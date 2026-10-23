# RadarNode

> [!WARNING]
> **Experimental.** Test build `v0.1.0-radarexp2`, published as a binary only. Its source branch is not public, so this repository cannot build it.

RadarNode is firmware for a 24 GHz radar node. It detects a moving target, then scans Wi-Fi and BLE to record which devices were present. It runs on the same PCB and the same LoRa mesh as the DIGI node, and it appears in DIGI node lists.

- [How it works](#how-it-works)
- [Hardware](#hardware)
- [Build & Flash](#build--flash)
- [Web UI](#web-ui)
- [Configuration](#configuration)
- [Mesh Commands](#mesh-commands)
- [Mesh Output](#mesh-output)
- [API Reference](#api-reference)

---

## How it works

The radar runs continuously. When it confirms a moving target, the node logs a detection to the SD card and sends it to the mesh. If RF enrichment is on and the sweep cooldown has passed, the node also scans BLE and Wi-Fi (2.4 and 5 GHz) and sends the top 3 devices with the detection.

A detection holds the target's distance, speed, angle, direction and class, plus the Wi-Fi and BLE devices seen at that moment.

| State | Meaning |
|---|---|
| `IDLE` | No target. |
| `TRIGGERED` | Target confirmed and detection recorded. |
| `LINGER` | Target lost. The node waits (3 s by default) before returning to `IDLE`. |

**Target classes** are `UNKNOWN`, `PERSON` and `VEHICLE`. The node votes on the class over recent frames, so a new track reads `UNKNOWN` at first. `PERSON` fits speeds up to 20 km/h and `VEHICLE` fits speeds from 15 km/h.

**Alarm.** The node raises an alarm when a target moves in the set Direction, is inside Alarm Distance, moves at or above Alarm Speed, is within Alarm Angle of straight ahead, and matches Alarm Class. Angle and class default to open (90°, any class), so by default only distance and speed decide.

**Traffic baseline.** The node learns the normal detection rate and device count over a set time, then reports how current activity compares.

---

## Hardware

RadarNode uses a XIAO ESP32-C5 on the standard AntiHunter PCB. Remove the RTC. The HLK-LD2451 radar uses the RTC's pads.

| Function | Pin | GPIO | Notes |
|---|---|---|---|
| Mesh UART RX | D3 | 7 | From the Meshtastic radio TX. |
| Mesh UART TX | D4 | 23 | To the Meshtastic radio RX. |
| Radar RX | D2 | 25 | From HLK **TX**. Old RTC **Data**/SDA pad. |
| Radar TX | D5 | 24 | To HLK **RX**. Old RTC **Clock**/SCL pad. |
| GPS RX | D7 | 12 | From GPS TX. |
| GPS TX | D6 | 11 | To GPS RX. |
| SD CS | D0 | 1 | |
| SD SCK | D8 | 8 | |
| SD MISO | D9 | 9 | |
| SD MOSI | D10 | 10 | |

The mesh and the radar use the C5's two hardware UARTs, so GPS runs on SoftwareSerial at 9600 baud.

### Wiring the HLK-LD2451

Connect two wires to the RTC header. Take power from the fan rail, not from this header.

| RTC header pin | Connect to |
|---|---|
| **Data** (SDA) | HLK **TX** |
| **Clock** (SCL) | HLK **RX** |
| **GND** | Leave empty. |
| Vcc | Leave empty. |
| NC | Leave empty. |

> [!IMPORTANT]
> The HLK-LD2451 needs **5 V at 300 mA or more**. The XIAO's 3V3 pin cannot supply that. The radar's data lines are 3.3 V, so they connect directly with no level shifter.
>
> **Do not take the radar's ground from the RTC header.** A bench supply grounded there does not work. Take both 5 V and ground from the board's fan rail (+/-), and jumper the thermal switch to reach it.

At boot, the serial console confirms the link:

```
[RADAR] Starting sensor RX=GPIO25 TX=GPIO24 @ 115200
[RADAR] restore saved config ... -> maxDist=<m>m dir=<d> minSpd=<s>km/h delay=<s>s trig=<n> snr=<n>
```

If the restore line never appears, the sensor is not answering. Check in this order: TX/RX orientation, that power and ground come from the fan rail, and that the 5 V rail holds under load.

---

## Build & Flash

Flash `Dist/radarnode-c5-v0.1.0-radarexp2.factory.bin` with either tool:

- The web flasher: choose Experimental, then RadarNode.
- `Dist/flashAntihunter.sh`: choose channel 3 (Experimental), then RadarNode.

---

## Web UI

The node hosts its own access point. Connect to it and open `http://192.168.4.1/`.

The default access point name is `RN-` plus the last bytes of the MAC address. You change the name and password in Config. The node ID is `RN` plus three random digits (`RN100` to `RN999`).

| Panel | Shows |
|---|---|
| Scope | Live radar sweep with range rings to 100 m, a 20° field of view, the target track and a callout. |
| Activity (Timeline / Heatmap / Distance) | Rolling detection history. |
| RF Enrichment | Candidates from the last sweep: score, band, MAC, name, manufacturer, signal bars and dBm. |
| Traffic Baseline | Learning state, and how current activity compares to the learned baseline. |
| DiGI Mesh | Nodes seen on the mesh, typed `RADAR` or `DIGI`. |
| Detection Log | One record per detection. Expand a record to see the candidates captured with it. |

The header has a light/dark theme toggle, a redaction toggle and the Config panel.

**Redaction** replaces MACs with `XX:XX` and device names with `REDACTED`, for screenshots. Manufacturer names and BLE type labels such as `Handoff` stay visible. The browser remembers the setting.

**Column width.** Drag the divider between the scope and the results. Double-click it to reset.

---

## Configuration

Set these in the Config panel or with `POST /api/radar/config`. The node saves them to flash.

### Detection

| Setting | Range | Default | What it does |
|---|---|---|---|
| Max Distance | 10-100 m | 80 | Ignores targets beyond this range. |
| Direction | away / toward / both | both | Which way a target must travel to count. |
| Min Speed | 0-120 km/h | 1 | Ignores slower targets. The Alarm settings use m/s. |
| Report Delay | 0-255 s | 1 | Time the sensor holds a target before reporting it. |
| Distance Scale | 0.1-5.0 | 1.0 | Multiplier on reported range. 1.0 applies no correction. |

### Sensitivity

| Setting | Range | Default | What it does |
|---|---|---|---|
| Trigger Count | 1-10 | 1 | Consecutive hits needed before the sensor reports a target. |
| SNR Threshold | 0-8 | 4 | Signal strength a return needs. `0` is the most sensitive and `8` the least. |

### Alarm

| Setting | What it does | Web UI range | `RADAR_CONFIG` key and range | Default |
|---|---|---|---|---|
| Alarm Distance | Alarms inside this range. | 1-100 m | `DIST`, above 0 to 200 m | 50 |
| Alarm Speed | Alarms at or above this speed. | 0-80 m/s | `SPD`, above 0 to 50 m/s | 5 |
| Alarm Angle | Alarms within this angle of straight ahead. | 1-90° | `ANG`, above 0 to 90° | 90 |
| Alarm Class | Alarms only on this class. | Any / Person / Vehicle | `CLS`: `0` any, `1` person, `2` vehicle | Any |

### RF Enrichment

| Setting | Range | Default | What it does |
|---|---|---|---|
| Enabled | on/off | on | Scans BLE and Wi-Fi when the radar triggers. |
| Sweep Cooldown | 0-600 s | 15 | Minimum gap between sweeps. |
| Linger | 1-60 s | 3 | How long the node stays `TRIGGERED` after the last radar frame. |
| RSSI Floor | -100 to -30 dBm | -95 | Drops devices with a weaker signal. |
| BLE Dwell | 500-10000 ms | 2000 | How long each sweep listens for BLE. |

**Sweep now** forces a sweep regardless of radar state, cooldown or the Enabled setting. On the serial console, `s` does the same and `d` prints peripheral diagnostics.

---

## Mesh Commands

Address a command as `@ALL <CMD>` to reach every node, or `@<NODEID> <CMD>` to reach one node.

| Command | What it does | Reply |
|---|---|---|
| `STATUS` | Reports the node's state. | `STATUS: TYPE:RADAR …` |
| `SCAN_START:<any>` | Forces an RF sweep. The node ignores the text after the colon. | `SCAN_ACK:STARTED` |
| `STOP` | Stops the running sweep. | `STOP_ACK:OK` |
| `BASELINE:START[:secs]` | Starts learning the traffic baseline. `secs` is the learning time in seconds. The default is 300 and the minimum is 60. | `BASELINE:ACK:START:<secs>` |
| `BASELINE:STOP` | Stops learning. | `BASELINE:ACK:STOP` |
| `BASELINE:STATUS` | Returns the baseline state as JSON. | `BASELINE:STATUS:{…}` |
| `RADAR_CONFIG:DIST=<m> SPD=<m/s> ANG=<deg> CLS=<0-2>` | Sets the alarm thresholds. | `RADAR_CONFIG_ACK:OK …` or `RADAR_CONFIG_ACK:ERR Invalid params` |
| `TIME_SYNC_REQ:` | Asks for the node's clock. | `TIME_SYNC_RESP:<epoch>:0:<micros>:0` |

`TIME_SYNC_RESP` carries the node's Unix time (`<epoch>`, seconds) and its microsecond counter (`<micros>`).

The `RADAR_CONFIG` fields are the keys in the [Alarm table](#alarm): `DIST` in meters, `SPD` in meters per second, `ANG` in degrees and `CLS` as a class number. Leave a field out to keep its current value. If any value is out of range, the node changes nothing and replies with the error. With `CLS` set to `1` or `2`, the first frames of a new track read `UNKNOWN` and do not alarm.

---

## Mesh Output

```
<NODEID>: STARTUP: System initialized GPS:<state> TEMP: <c>C / <f>F
<NODEID>: STATUS: TYPE:RADAR RADAR:<state> SCAN:<Y|N> GPS:<state> Temp:<c>C Up:<s> DETS:<n> ALMS:<n>
<NODEID> DET <dist>m <speed>km/h <angle>° <twd|awy> <CLASS>[ ALM]
<NODEID> SCAN done: <n> WiFi <n> BLE <n> moving +<lag>ms
<NODEID> CAND<1-3> <MAC> <rssi>dBm <WiFi|BLE> ["name"|manufacturer][ mov]
```

| Field | Meaning |
|---|---|
| `Up` | Seconds since boot. |
| `DETS`, `ALMS` | Detections and alarms since boot. |
| `twd`, `awy` | The target moves toward the sensor (`twd`) or away from it (`awy`). |
| `ALM` | This detection raised the alarm. |
| `CAND1` to `CAND3` | The top three devices from the sweep. Moving devices (`mov`) come first, then the rest by score. |

`TYPE:RADAR` tells the RadarNode mesh list and the Command Center that the sender is a RadarNode. A peer with no `TYPE` field counts as `RADAR` if it reports a `RADAR:` field, and as DIGI otherwise. DIGI Full reads both fields for its fleet list. DIGI Headless does not.

---

## API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Web UI. |
| GET | `/api/info` | Node ID, IP, timestamp and GPS state. |
| GET | `/api/diag` | Peripheral diagnostics. |
| GET | `/api/radar/stats` | Detection and alarm counters. |
| GET | `/api/radar/config` | Current configuration. |
| POST | `/api/radar/config` | Set configuration. |
| POST | `/api/scan` | Force a sweep. |
| GET | `/api/events` | Recent detection events. |
| GET | `/api/detlog.jsonl` | Detection log, one JSON object per line. |
| DELETE | `/api/detlog` | Clear the detection log. |
| GET | `/api/log.csv` | Radar samples as CSV. |
| GET | `/api/baseline` | Baseline state. |
| POST | `/api/baseline/start` | Start learning. Body: `{"duration":<min>}`. |
| POST | `/api/baseline/stop` | Stop learning. |
| GET | `/api/mesh` | Known mesh peers. |
| POST | `/api/mesh/status-all` | Broadcast `@ALL STATUS`. |
| POST | `/api/config` | Set the access point name and password. |
| POST | `/api/restart` | Reboot. |

WebSockets: `/ws` carries radar samples, `/scanws` carries sweep results and `/log` carries the console.
