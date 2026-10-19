# RadarNode

> [!WARNING]
> **Experimental.** Test build `v0.1.0-radarexp2`, published as a binary only. Its source branch is not public, so this repository can't build it.

A 24GHz radar node that detects a moving target, then sweeps Wi-Fi and BLE to record which devices were present at that moment. It is separate firmware from the DIGI node, on the same PCB and the same LoRa mesh, and appears in DIGI node lists.

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

The radar runs all the time. When it confirms a moving target, the node logs a detection to SD and the mesh and, if RF enrichment is on and the sweep cooldown has passed, scans BLE and Wi-Fi (2.4 and 5 GHz). The top 3 devices from that sweep go out with the detection.

A detection holds distance, speed, angle, direction and target class from the radar, plus the Wi-Fi/BLE devices seen at that moment.

| State | Meaning |
|---|---|
| `IDLE` | No target |
| `TRIGGERED` | Target confirmed, detection recorded |
| `LINGER` | Target lost, waiting before returning to idle (default 3 s) |

**Target classes**: `UNKNOWN`, `PERSON`, `VEHICLE`. The class is voted over recent frames, so a new track reads `UNKNOWN` for its first frames. `PERSON` fits walking speeds up to 20 km/h, `VEHICLE` speeds from 15 km/h up.

**Alarm**: raised when a target moves in the set Direction, inside Alarm Distance, at or above Alarm Speed, within Alarm Angle of straight ahead, and matches Alarm Class. Angle and class default to open (90°, any class), so by default only distance and speed decide.

**Traffic baseline**: learns the normal detection rate and device count over a set time, then reports how current activity compares.

---

## Hardware

XIAO ESP32-C5 on the standard AntiHunter PCB. The HLK-LD2451 takes the RTC's footprint — the RTC is removed on a RadarNode.

| Function | Pin | GPIO | Notes |
|---|---|---|---|
| Mesh UART RX← | D3 | 7 | from Meshtastic radio TX |
| Mesh UART TX→ | D4 | 23 | to Meshtastic radio RX |
| Radar RX← | D2 | 25 | from HLK **TX** — old RTC **Data**/SDA pad |
| Radar TX→ | D5 | 24 | to HLK **RX** — old RTC **Clock**/SCL pad |
| GPS RX← | D7 | 12 | from GPS TX (SoftwareSerial) |
| GPS TX→ | D6 | 11 | to GPS RX |
| SD CS | D0 | 1 | |
| SD SCK | D8 | 8 | |
| SD MISO | D9 | 9 | |
| SD MOSI | D10 | 10 | |

Mesh and radar use the C5's two hardware UARTs, so GPS runs on SoftwareSerial at 9600 baud.

### Wiring the HLK-LD2451

Two wires into the RTC header. Power comes from the fan rail, not from this header:

| RTC header pin | Connect to |
|---|---|
| **Data** (SDA) | HLK **TX** |
| **Clock** (SCL) | HLK **RX** |
| **GND** | leave empty |
| Vcc | leave empty |
| NC | leave empty |

> [!IMPORTANT]
> The HLK-LD2451 needs **5 V at 300 mA or more** — more than the XIAO's 3V3 pin can supply. Its IO is 3.3 V, so the two data lines connect directly with no level shifting.
>
> **Do not take the radar's ground from the RTC header.** A bench supply grounded there does not work. Take both 5 V and ground from the board's fan rail (+/-), jumping the thermal switch to reach it.

Serial at boot confirms the link:

```
[RADAR] Starting sensor RX=GPIO25 TX=GPIO24 @ 115200
[RADAR] restore saved config ... -> maxDist=<m>m dir=<d> minSpd=<s>km/h delay=<s>s trig=<n> snr=<n>
```

If the restore line never appears, the sensor is not answering — check TX/RX orientation first, then that power and ground come from the fan rail rather than the RTC header, then whether the 5 V rail holds under load.

---

## Build & Flash

Flash `Dist/radarnode-c5-v0.1.0-radarexp2.factory.bin` with the web flasher (Experimental → RadarNode) or `Dist/flashAntihunter.sh` channel 3 (Experimental), then RadarNode.

---

## Web UI

The node hosts its own access point. Connect and browse to `http://192.168.4.1/`.

The default AP name is `RN-` plus the last MAC bytes; SSID and password are changeable in Config. The node ID is `RN` plus three random digits (`RN100`–`RN999`).

| Panel | Shows |
|---|---|
| Scope | Live PPI sweep — range rings to 100 m, 20° field of view, target track and callout |
| Activity (Timeline / Heatmap / Distance) | Rolling detection history |
| RF Enrichment | Candidates from the last sweep — score, band, MAC, name, manufacturer, signal bars, dBm |
| Traffic Baseline | Learning state and how current activity compares to the learned ambient |
| DiGI Mesh | Nodes seen on the mesh, typed `RADAR` or `DIGI` |
| Detection Log | Per-detection records, expandable to the candidates captured with each |

**Header controls** — theme toggle (light/dark), redaction toggle, Config panel.

**Redaction** replaces MACs with `XX:XX` and device names with `REDACTED` for screenshots. Manufacturer names and BLE type labels such as `Handoff` stay visible. The setting persists in the browser.

**Column width** — drag the divider between the scope and the results. Double-click resets it.

---

## Configuration

Config panel, or `POST /api/radar/config`. Values persist to NVS.

### Detection

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Max Distance | 10–100 m | 80 | Ignore targets beyond this range |
| Direction | away / toward / both | both | Which way a target must travel to count |
| Min Speed | 0–120 km/h | 1 | Slower targets are ignored. In km/h; the Alarm settings use m/s |
| Report Delay | 0–255 s | 1 | Time the sensor holds a target before reporting it |
| Distance Scale | 0.1–5.0 | 1.0 | Multiplier on reported range; 1.0 is uncorrected |

### Sensitivity

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Trigger Count | 1–10 | 1 | Consecutive hits before a target is reported |
| SNR Threshold | 0–8 | 4 | Signal level a return needs. `0` most sensitive, `8` least |

### Alarm

| Setting | Meaning | Web UI range | `RADAR_CONFIG` key and range | Default |
|---|---|---|---|---|
| Alarm Distance | Alarm inside this range | 1–100 m | `DIST`, above 0 to 200 m | 50 |
| Alarm Speed | Alarm at or above this speed | 0–80 m/s | `SPD`, above 0 to 50 m/s | 5 |
| Alarm Angle | Alarm within this angle of straight ahead | 1–90° | `ANG`, above 0 to 90 | 90 |
| Alarm Class | Alarm only on this class | Any / Person / Vehicle | `CLS`, `0` any, `1` person, `2` vehicle | Any |

### RF Enrichment

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Enabled | on/off | on | Sweep BLE + Wi-Fi on a radar trigger |
| Sweep Cooldown | 0–600 s | 15 | Minimum gap between sweeps |
| Linger | 1–60 s | 3 | Hold TRIGGERED after the last frame |
| RSSI Floor | −100…−30 dBm | −95 | Drop weaker devices |
| BLE Dwell | 500–10000 ms | 2000 | Listen window per sweep |

**Sweep now** forces a sweep regardless of radar state or cooldown, including when enrichment is off. The serial console does the same on `s`; `d` prints peripheral diagnostics.

---

## Mesh Commands

Addressed as `@ALL <CMD>` or `@<NODEID> <CMD>`.

| Command | Effect | Reply |
|---|---|---|
| `STATUS` | Report state | `STATUS: TYPE:RADAR …` |
| `SCAN_START:<any>` | Force an RF sweep. The argument is ignored | `SCAN_ACK:STARTED` |
| `STOP` | Stop the running sweep | `STOP_ACK:OK` |
| `BASELINE:START[:secs]` | Start learning (default 300 s, floor 60 s) | `BASELINE:ACK:START:<secs>` |
| `BASELINE:STOP` | Stop learning | `BASELINE:ACK:STOP` |
| `BASELINE:STATUS` | Baseline state as JSON | `BASELINE:STATUS:{…}` |
| `RADAR_CONFIG:DIST=<m> SPD=<m/s> ANG=<deg> CLS=<0-2>` | Set alarm thresholds | `RADAR_CONFIG_ACK:OK …` or `:ERR` |
| `TIME_SYNC_REQ:` | Clock sync | `TIME_SYNC_RESP:<epoch>:0:<micros>:0`, the node's Unix time and its microsecond counter |

`RADAR_CONFIG` keys and ranges are in the [Alarm table](#alarm). Any value out of range returns `RADAR_CONFIG_ACK:ERR Invalid params` and changes nothing. With `CLS` set to `1` or `2`, the first frames of a new track read `UNKNOWN` and don't alarm.

---

## Mesh Output

```
<NODEID>: STARTUP: System initialized GPS:<state> TEMP: <c>C / <f>F
<NODEID>: STATUS: TYPE:RADAR RADAR:<state> SCAN:<Y|N> GPS:<state> Temp:<c>C Up:<s> DETS:<n> ALMS:<n>
<NODEID> DET <dist>m <speed>km/h <angle>° <twd|awy> <CLASS>[ ALM]
<NODEID> SCAN done: <n> WiFi <n> BLE <n> moving +<lag>ms
<NODEID> CAND<1-3> <MAC> <rssi>dBm <WiFi|BLE> ["name"|manufacturer][ mov]
```

- `DET`: `twd` toward the sensor, `awy` away. `ALM` marks a detection that raised the alarm.
- `CAND1`-`CAND3`: the top three devices from the sweep, moving ones first (`mov`), then by score.
- `TYPE:RADAR` tells the RadarNode's mesh list and the Command Center that the sender is a RadarNode. A peer with no `TYPE` field counts as `RADAR` if it reports a `RADAR:` field, otherwise DIGI. DIGI Full reads both fields for its fleet list; Headless does not.

---

## API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Web UI |
| GET | `/api/info` | Node ID, IP, timestamp, GPS state |
| GET | `/api/diag` | Peripheral diagnostics |
| GET | `/api/radar/stats` | Detection and alarm counters |
| GET | `/api/radar/config` | Current configuration |
| POST | `/api/radar/config` | Set configuration |
| POST | `/api/scan` | Force a sweep |
| GET | `/api/events` | Recent detection events |
| GET | `/api/detlog.jsonl` | Detection log, JSON lines |
| DELETE | `/api/detlog` | Clear the detection log |
| GET | `/api/log.csv` | Radar samples as CSV |
| GET | `/api/baseline` | Baseline state |
| POST | `/api/baseline/start` | Start learning — `{"duration":<min>}` |
| POST | `/api/baseline/stop` | Stop learning |
| GET | `/api/mesh` | Known mesh peers |
| POST | `/api/mesh/status-all` | Broadcast `@ALL STATUS` |
| POST | `/api/config` | AP SSID and password |
| POST | `/api/restart` | Reboot |

WebSockets: `/ws` radar samples, `/scanws` sweep results, `/log` console.
