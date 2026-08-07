# RadarNode

> [!WARNING]
> **Experimental.** The radar path works — detection, RF enrichment, web UI and mesh all run — but the firmware is unreleased: no branch is published yet, no web-flasher entry, no release binaries. Source link: _(branch not yet pushed)_.

A 24GHz radar node that detects a moving target, then sweeps WiFi and BLE to record which devices were present at that moment. It joins the same LoRa mesh as DIGI nodes and appears in their node lists.

Separate firmware from the DIGI node — different sensor, different app, same PCB and same mesh.

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

The radar is the primary sensor and runs continuously. WiFi/BLE scanning is not a separate mode you launch — it is enrichment triggered by the radar.

```
HLK-LD2451 frame  ──►  radarTask
                         │  IDLE ──► TRIGGERED ──► LINGER ──► IDLE
                         │                │
                         │                ├─► detection logged to SD + mesh
                         │                └─► RF sweep (if enabled, past cooldown)
                         ▼                        │
                    traffic baseline              ├─ BLE scan
                                                  └─ WiFi scan (2.4 + 5GHz)
                                                        │
                                                        ▼
                                              candidates scored, top 3 meshed
```

A detection record holds both halves: distance, speed, angle, direction and target class from the radar, plus the WiFi/BLE candidates seen at that instant.

**State machine**

| State | Meaning |
|---|---|
| `IDLE` | No target |
| `TRIGGERED` | Target confirmed, detection recorded |
| `LINGER` | Target lost, holding before returning to idle (default 3 s) |

**Target classes** — `UNKNOWN`, `PERSON`, `VEHICLE`, voted over a 12-frame rolling history rather than per-frame, so one noisy frame cannot flip the class. `PERSON` scores on speeds up to 8 km/h and is weighted up by speed and angle variance (gait); `VEHICLE` scores from 15 km/h up and is weighted up by track stability. Both are scaled by SNR confidence, and `VEHICLE` is suppressed inside 5 m.

**Alarm** — fires only when every gate passes: the target is approaching, within Alarm Distance, at or above Alarm Speed, within `±ANG` of boresight, and of the class selected by `CLS`. Angle and class default to open (90°, any class), so out of the box only distance, speed and direction decide. Both are set over mesh with `RADAR_CONFIG` and persist across reboot.

**Traffic baseline** — learns ambient detection rate and device count over a chosen window, then reports how current activity compares. Radar events feed the detection rate; each RF sweep feeds the device count.

---

## Hardware

XIAO ESP32-C5 on the standard AntiHunter PCB. The HLK-LD2451 takes the RTC's footprint — the RTC is removed on a RadarNode.

| Function | Pin | GPIO | Notes |
|---|---|---|---|
| Mesh UART TX→ | D3 | 7 | to Meshtastic radio RX |
| Mesh UART RX← | D4 | 23 | from Meshtastic radio TX |
| Radar RX← | D2 | 25 | from HLK **TX** — old RTC **Data**/SDA pad |
| Radar TX→ | D5 | 24 | to HLK **RX** — old RTC **Clock**/SCL pad |
| GPS RX← | D7 | 12 | from GPS TX (SoftwareSerial) |
| GPS TX→ | D6 | 11 | to GPS RX |
| SD CS | D0 | 1 | |
| SD SCK | D8 | 8 | |
| SD MISO | D9 | 9 | |
| SD MOSI | D10 | 10 | |

The C5 has two hardware UARTs. Mesh takes UART0 and radar takes UART1, so GPS runs on SoftwareSerial at 9600 — the C5's LP_UART pins are fixed to back pads the XIAO does not break out.

### Wiring the HLK-LD2451

Three wires into the RTC header, plus its own power:

| RTC header pin | Connect to |
|---|---|
| **Data** (SDA) | HLK **TX** |
| **Clock** (SCL) | HLK **RX** |
| **GND** | HLK GND |
| Vcc | leave empty |
| NC | leave empty |

> [!IMPORTANT]
> The HLK-LD2451 needs **5 V at 300 mA or more** from a separate supply — not the XIAO's 3V3 pin. Its IO is 3.3 V, so the data lines connect directly with no level shifting. The supply ground must tie to the board ground; without a shared ground the UART returns garbage.

Serial at boot confirms the link:

```
[RADAR] Starting sensor RX=GPIO25 TX=GPIO24 @ 115200
[RADAR] after reset -> maxDist=60m dir=2 minSpd=1km/h
```

`maxDist=0 ... (0/1=no-response)` means the sensor is not answering — check TX/RX orientation first, then the shared ground, then whether the 5 V rail holds under load.

---

## Build & Flash

```bash
pio run -e RadarNode-c5 -t upload
```

Or via the Makefile:

```bash
make build-radar     # build
make lint-radar      # cppcheck
```

All environments build on one platform (pioarduino). Mixing in `espressif32@6.x` breaks the build — both platforms claim the `framework-arduinoespressif32` package directory at different versions and overwrite each other.

---

## Web UI

The node hosts its own access point. Connect and browse to `http://192.168.4.1/`.

The default AP name is `RN-` plus the last MAC bytes; SSID and password are changeable in Config. The node ID is `RN` plus four hex digits.

| Panel | Shows |
|---|---|
| Scope | Live PPI sweep — range rings to 100 m, 20° field of view, target track and callout |
| Distance / Speed / Heatmap | Rolling detection history |
| RF Enrichment | Candidates from the last sweep — score, band, MAC, name, manufacturer, signal bars, dBm |
| Traffic Baseline | Learning state and how current activity compares to the learned ambient |
| DiGI Mesh | Nodes seen on the mesh, typed `RADAR` or `DIGI` |
| Detection Log | Per-detection records, expandable to the candidates captured with each |

**Header controls** — theme toggle (light/dark), redaction toggle, Config panel.

**Redaction** replaces MACs with `XX:XX` and device names with `REDACTED` for screenshots. Manufacturer and class labels stay visible, so `Handoff`, `Nearby-Action` and similar remain readable. The setting persists in the browser.

**Column width** — drag the divider between the scope and the results. Double-click resets it.

---

## Configuration

Config panel, or `POST /api/radar/config`. Values persist to NVS.

### Detection

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Max Distance | 1–100 m | 60 | Ignore targets beyond this range |
| Direction | away / towards / both | both | Which way a target must travel to count |
| Min Speed | 0–250 km/h | 1 | Slower targets are ignored |
| Report Delay | 0–255 | 1 | Sensor-side hold before reporting |

### Sensitivity

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Trigger Count | 1–10 | 1 | Consecutive hits before a target is reported |
| SNR Threshold | 0–8 | 4 | Lower triggers more easily |

### Alarm

| Setting | Range | Default |
|---|---|---|
| Alarm Distance | 1–100 m | 50 |
| Alarm Speed | 0–80 m/s | 5 |

### RF Enrichment

| Setting | Range | Default | Meaning |
|---|---|---|---|
| Enabled | on/off | on | Sweep BLE + WiFi on a radar trigger |
| Sweep Cooldown | 0–600 s | 15 | Minimum gap between sweeps |
| Linger | 1–60 s | 3 | Hold TRIGGERED after the last frame |
| RSSI Floor | −100…−30 dBm | −95 | Drop weaker devices — about 100 m line of sight, matching radar range |
| BLE Dwell | 500–10000 ms | 2000 | Listen window per sweep |

**Sweep now** forces a sweep regardless of radar state or cooldown, including when enrichment is off. The serial console does the same on `s`; `d` prints peripheral diagnostics.

---

## Mesh Commands

Addressed as `@ALL <CMD>` or `@<NODEID> <CMD>`.

| Command | Effect | Reply |
|---|---|---|
| `STATUS` | Report state | `STATUS: TYPE:RADAR …` |
| `SCAN_START:<n>` | Force an RF sweep | `SCAN_ACK:STARTED` |
| `STOP` | Stop the running sweep | `STOP_ACK:OK` |
| `BASELINE:START[:secs]` | Start learning (default 300 s, floor 60 s) | `BASELINE:ACK:START:<secs>` |
| `BASELINE:STOP` | Stop learning | `BASELINE:ACK:STOP` |
| `BASELINE:STATUS` | Baseline state as JSON | `BASELINE:STATUS:{…}` |
| `RADAR_CONFIG:DIST=<m> SPD=<m/s> ANG=<deg> CLS=<0-2>` | Set alarm thresholds | `RADAR_CONFIG_ACK:OK …` or `:ERR` |
| `TIME_SYNC_REQ:` | Clock sync | `TIME_SYNC_RESP:<epoch>:0:<micros>:0` |

`RADAR_CONFIG` bounds: `DIST` 0–200 m, `SPD` 0–50 m/s, `ANG` 0–90°, `CLS` 0–2. Out of range returns `RADAR_CONFIG_ACK:ERR Invalid params` and changes nothing.

`ANG` narrows the alarm to targets within `±ANG` of boresight. `CLS` restricts it to one class — `0` any, `1` person, `2` vehicle. Because the class is voted over a rolling history, the first frames of a new track read `UNKNOWN` and will not alarm while `CLS` is non-zero.

---

## Mesh Output

```
<NODEID>: STARTUP: System initialized GPS:<state> TEMP: <c>C / <f>F
<NODEID>: STATUS: TYPE:RADAR RADAR:<state> SCAN:<Y|N> GPS:<state> Temp:<c>C Up:<s> DETS:<n> ALMS:<n>
<NODEID> DET <dist>m <speed>km/h <angle>° <twd|awy> <CLASS>[ ALARM]
<NODEID> SCAN done: <n> WiFi <n> BLE <n> moving
<NODEID> CAND<1-3> <MAC> <rssi>dBm <WiFi|BLE> [label][ mov]
```

`TYPE:RADAR` is how the RadarNode's own mesh list and the Command Center tell a RadarNode from a DIGI node. A peer reporting no `TYPE` field is treated as DIGI. DIGI firmware does not read the field.

At most **three** candidates are sent per detection, ranked by score, to bound mesh traffic.

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
