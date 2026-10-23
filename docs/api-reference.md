# API Reference

[Back](../README.md)

This page lists the HTTP routes of the Full firmware's web server. The Headless firmware has no access point and no web server. Control it with [mesh commands](mesh-commands.md).

> [!IMPORTANT]
> - Address the node by its own IP (`192.168.4.1` on its access point). A request that uses another host name, comes from another site, or carries a different `Origin` header gets `403`.
> - Every route needs HTTP Digest login: user `admin`, realm `AntiHunter`, and the web password, or the access point password until you set a web password. A missing login gets `401`. Requests from the node itself (127.0.0.1) skip the login.
> - You can turn the login off with `/web-auth`, or with `"webAuth":false` in the flasher config. Anyone on the access point can then use the web UI. Neither setting is available over the mesh.

> [!NOTE]
> Timestamps show local time from the GPS fix, with daylight saving applied. Without a GPS lock they show UTC. Fields named `epoch` are UTC seconds.

## Conventions

- POST parameters are form fields (`application/x-www-form-urlencoded`). GET parameters go in the query string.
- Replies are plain text unless the table says JSON.
- Common status codes: `400` missing or invalid parameter, `403` wrong key or password, `409` the radio is busy or the state does not allow the request, `500` a task failed to start, `507` the setting did not fit in flash storage.
- Start routes return `409` while a scan runs. Call `/stop` first.

Parameters shared by the start routes:

| Parameter | Meaning | Range | Default |
|---|---|---|---|
| `secs` | Run time in seconds. `0` runs until stopped | 0-86400 | 60 |
| `forever` | Any value (even empty) runs until `/stop`. Overrides `secs` | | off |
| `mode` | Radio: `0` Wi-Fi, `1` BLE, `2` both | 0-2 | per route |
| `ch` | Wi-Fi channels as a list (`1,6,11`) or range (`1..11`) | 1-14 | 1-11 |

## Core

| Endpoint | Method | What it does |
|---|---|---|
| `/` | GET | The web interface |
| `/diag` | GET | Diagnostics as text. Shows `Stopping: yes` until a stopped scan has exited |
| `/stop` | GET | Stops every scan and task: aborts Wi-Fi and BLE scans, stops triangulation, cancels the mesh queue, and cancels Sentinel follow-up scans |
| `/node-id` | GET | JSON: `nodeId` |
| `/node-id` | POST | `id`: 2-5 letters or digits, saved in upper case |
| `/save` | POST | `list`: replaces the target list. `400` if missing, `507` if it does not fit (4000 bytes). The running list stays unchanged on failure |
| `/export` | GET | The target list as text |
| `/allowlist-export` | GET | The allowlist as text |
| `/allowlist-save` | POST | `list`: replaces the allowlist. `409` while a scan runs |
| `/clear-results` | POST | Clears the results text |
| `/api/time` | POST | `epoch`: sets the clock, in UTC seconds from 1609459200 to 2147483647 |
| `/api/onboarding` | GET, POST | JSON: `accepted`, whether the first-run terms were accepted. POST marks them accepted and saves that to NVS and the SD card |

## Scanning

| Endpoint | Method | What it does |
|---|---|---|
| `/scan` | POST | Starts a target scan. Parameters below |
| `/sniffer` | POST | Starts the scan named by `detection`. Parameters below |
| `/drone` | POST | Starts drone Remote ID detection: `secs`, `forever`, and `droneScanMode` (`0` Wi-Fi, `1` BLE, other values both; default both) |
| `/mesh-tx/cancel` | POST | Empties the mesh send queue. The scan keeps running |

**`/scan`** has the shared parameters (`mode` default `0`). It returns `400` with "No targets" if the target list is empty. To triangulate instead, add `triangulate` (any value) and `targetMac`:

| Parameter | Meaning | Range | Default |
|---|---|---|---|
| `targetMac` | The device to locate | | |
| `rfEnv` | Surroundings: `0` open sky, `1` suburban, `2` indoor, `3` indoor dense, `4` industrial | 0-4 | 2 |
| `wifiPwr`, `blePwr` | Multipliers for Wi-Fi and BLE distance estimates | 0.1-5.0 | 1.0 |

**`/sniffer`** runs one of these scans. Choose it with `detection`; an unknown value returns `400`. All scans take `secs` and `forever`.

| `detection` | What it does | Extra parameters |
|---|---|---|
| `device-scan` (default) | Device discovery | `deviceScanMode` (0-2, default 2). `captureProbes` (any value) also collects probe requests |
| `deauth` | Deauthentication and disassociation detection | |
| `baseline` | Baseline anomaly detection. Always uses both radios | |
| `randomization-detection` | Links devices that change their MAC address | `randomizationMode` (0-2, default 2) |
| `probe-scan` | Probe request scan | `probeScanMode` (0-2, default 2). `broadcastAll` (any value) sends every probe to the mesh |
| `drone-detection` | Drone Remote ID detection | `droneScanMode` (`0` Wi-Fi, `1` BLE, other both) |
| `pcap` | Packet capture to the SD card. Needs `secs` of 1 or more, and an SD card | `pcapRadio` (`0` Wi-Fi, `1` BLE; default 0), `pcapBand` (`0` 2.4 GHz, `1` 5 GHz, `2` both; this hardware always uses 0), `pcapChannels` (channel list), `pcapDwell` (milliseconds per channel, 50-5000, default 250), `pcapMaxFile` (largest file in MB, 8-300), `pcapMgmtOnly` (any value records management frames only) |

**`/sniffer` with `detection=csi-motion` (Beta, C5)** starts CSI motion detection. It takes `secs` and `forever`, and these fields. A field you leave out keeps its saved value, except `csiRaw`, `csiNoTx`, and `csiRnd`, which turn off when you leave them out. `409` means a scan is running or the node is out of memory.

| Parameter | Meaning | Range | Default |
|---|---|---|---|
| `csiChannel` | Wi-Fi channel to watch. `0` lets the node pick | 0-14 | 0 |
| `csiThreshold` or `csiThr` | Trigger level. A higher number needs a stronger change in the signal | 0.005-20 | Beta 0.140, C5 0.020 |
| `csiHold` | Time without movement before movement clears. A value from 1 to 120 is seconds. A value from 500 to 120000 is milliseconds | 1-120 s, or 500-120000 ms | 5 s |
| `csiDwell` | Time the signal must keep changing before the node reports movement, in seconds | 2-60 | 8 |
| `csiSpots` | Number of transmitters that must show the movement | 1-12 | 2 |
| `csiConsec` | Consecutive hits one transmitter needs | 1-50 | 3 |
| `csiMeshGap` | Smallest time in seconds between two `CSI_MOTION` mesh alerts. `0` sends every alert | 0-3600 | 0 |
| `csiTelem` | Any value prints a score for every packet on USB serial. Once on, it stays on | | off |
| `csiRaw` | Any value dumps raw channel data on USB serial | | off |
| `csiNoTx` | Any value makes the node listen only. If you leave it out, the node may transmit probe requests | | off |
| `csiRnd` | Any value includes devices with randomized MAC addresses | | off |
| `csiRecal` | Any value clears the saved trigger level first | | |

`ch` sets the channel list. With `split` (any value), the list applies to this run only and the earlier list returns afterward. A `device-scan` with no `ch` uses the node's share from `/api/channel_partition`, if it has one.

## Captures

| Endpoint | Method | What it does |
|---|---|---|
| `/pcap/status` | GET | JSON: `active`, `dualBand`, `radio`, `band`, `channel`, `frames`, `bytes`, `dropped`, `elapsed`, `file`, `sd`, `budgetMB`, `floorMB`, `maxFileMB`, `freeMB` |
| `/pcap/list` | GET | JSON array of captures in `/pcap`: `name`, `size`, `active` (still being written) |
| `/pcap/download` | GET | Streams a capture. `f` is the file name (letters, digits, `_`, `-`, `.`, ending in `.pcap`). Without `f` it sends the most recent. `400` bad name, `404` no file |
| `/pcap/delete` | POST | `f`: deletes one capture. `409` if it is missing or still recording |
| `/pcap/delete-all` | POST | Deletes every capture |
| `/pcap/limits` | POST | `budgetMB`: space for captures that Sentinel starts (16 or more; default 512). `floorMB`: free space to keep on the card (default 256). `maxFileMB`: largest single file (8-300; default 100). Saved |

## Schedule

| Endpoint | Method | What it does |
|---|---|---|
| `/schedule` | GET | Text. First line: `<local time>\|<time zone>`. Then one line per block: `<next run, local time>\|<epoch>\|<repeat>\|<route>\|<options>`. Optional `now` (UTC epoch seconds) gives the node the time when it has no clock |
| `/schedule` | POST | Adds a block (parameters below), or removes one with `del` |

| Parameter | Meaning | Range |
|---|---|---|
| `at` | First run, node local time, `YYYY-MM-DDTHH:MM`. Must be after 2021-01-01 | |
| `period` | Seconds between runs. `0` runs once | 0, or 600-2678400 |
| `path` | `/scan`, `/sniffer`, or `/drone` | |
| `body` | The form fields that route takes, joined with `&`, such as `secs=600&mode=2`. No `\|` | 1024 characters |
| `del` | The block line from `/schedule`, without its leading local time | |

The node keeps 8 blocks. Replies: `400` bad input, `404` block not found, `413` schedule full.

## Results

| Endpoint | Method | What it does |
|---|---|---|
| `/results` | GET | Latest scan or triangulation results (text) |
| `/sniffer-cache` | GET | Devices cached by the running scan (text) |
| `/csi-json` | GET | (Beta, C5) CSI motion status as JSON: channel, tracked transmitters, motion events, trigger level, and the score of each transmitter |

## Fleet

The **Fleet** card on the System tab lists the senders the node hears on the mesh.

- **Nodes** have an ID of 2 to 5 letters or digits. Mode, scan state, hits, uptime, temperature, and GPS come from their `STATUS` and heartbeat lines. `type` is the value after `TYPE:` in their message, or `DIGI`. A node is online if heard within 2 minutes.
- **Other Mesh Radios** are all other senders, including the radio paired with this node. `ctrl` becomes true once the node sees an `@` command line from that sender.

The roster holds 48 entries and drops an entry after 15 minutes of silence. **Ping Nodes** broadcasts `@ALL STATUS`.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/mesh` | GET | JSON: `node`, `peers` (this node first, marked `self`), `radios` |
| `/api/mesh/ping` | POST | Broadcasts `@ALL STATUS`. `409` if the mesh is off |
| `/api/mesh/clear` | POST | Clears both rosters |
| `/api/fleet/send` | POST | Sends `@<node> <cmd>`. `node`: 2-5 letters or digits, not this node. `cmd` must start with one of `SCHED_ADD:`, `DEVICE_SCAN_START:`, `SCAN_START:`, `CAMPAIGN_START:`, `BLE_CLASSIFY:`, or equal `STOP`, `STATUS`, `CAMPAIGN_STOP`, `CAMPAIGN_STATUS`. `400` bad node or command, `409` mesh off, `413` over 230 characters, `503` mesh busy |

## Mesh settings

| Endpoint | Method | What it does |
|---|---|---|
| `/mesh` | POST | `enabled=true` or `false`: turns mesh sending on or off. Turning it off empties the queue |
| `/mesh-test` | GET | Sends a test message to the mesh |
| `/mesh-interval` | GET | JSON: `interval` |
| `/mesh-interval` | POST | `interval`: minimum milliseconds between mesh alerts, 1500-30000 |
| `/mesh-hb` | POST | `enabled=true` or `false`: the status heartbeat |
| `/mesh-hb-interval` | POST | `interval`: minutes between heartbeats, 1-60 (values outside move to the limit) |
| `/mesh-dedup-ttl` | GET | JSON: `ttl`, `min`, `max`, `session`, `count` |
| `/mesh-dedup-ttl` | POST | `ttl`: seconds before a device is reported again, 0-3600. `0` turns deduplication off. Default 300 |
| `/mesh-dedup-clear` | POST | Empties the deduplication memory |
| `/mesh-session-dedup` | POST | `on`: `1` sends only devices not yet reported this session, `0` sends all |
| `/vibration` | POST | `enabled=true` or `false`: the movement alert |
| `/vibration-scan` | GET | JSON: `enabled`, `mode`, `duration`, `cooldown` (seconds), `preempt` |
| `/vibration-scan` | POST | Saves the movement-scan settings: `enabled`, `mode`, `duration`, `cooldown`, `preempt`. `400` if `mode` is `8` and `duration` is `0` |
| `/battery-saver` | GET | Query `action`: `start`, `stop`, or `status` (default). `start` also takes `interval`, the minutes between heartbeats. `status` returns JSON: `enabled`, `interval`, `nextHeartbeat` |

Movement-scan fields:

| Field | Meaning | Range | Default |
|---|---|---|---|
| `enabled` | `true`, `1`, or `on` turns it on | | |
| `mode` | Scan to start: `0` none, `1` device discovery, `2` probe, `3` randomization, `4` target, `5` drone, `6` deauth, `7` baseline, `8` packet capture | 0-8 | |
| `duration` | Seconds. `0` runs until stopped, except mode `8` | 0-65535 | |
| `cooldown` | Seconds before the next movement can start a scan | 5-86400 | |
| `preempt` | `true`, `1`, or `on` stops a running scheduled scan to make room | | |

## Data and logs

The **Data** tab shows these logs in a searchable, sortable table. Its datasets are All Discovered Devices, Probe Devices, Probe Events, Deauth Attacks, Drone Detections, Vibration Events, Baseline Stats, Sentinel Incidents, and System Log. Headless writes the same logs to its SD card but has no web server.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/deauth.jsonl` | GET | Deauth log (JSONL). `404` if none |
| `/api/deauth/clear` | POST | Clears the deauth log in memory and on the SD card |
| `/api/drones.jsonl` | GET | Drone log (JSONL). `404` if none |
| `/api/drones/clear` | POST | Clears the drone log and the detected-drone list |
| `/api/vibrations.jsonl` | GET | Movement and tamper events (JSONL). `404` if none |
| `/api/vibrations/clear` | POST | Clears that log |
| `/api/antihunter.log` | GET | System log (text). `404` if none |
| `/api/antihunter.log/clear` | POST | Clears the system log |
| `/api/campaigns.csv` | GET | Campaign start and stop log (CSV) |
| `/data-cfg` | GET | JSON: `campaign`, `bleClassify`, `tz` (the node's time zone name, such as `UTC` or the local zone set from GPS), `tzOff` (that zone's current offset from UTC in seconds), `tzPosix` (the zone's POSIX TZ rule, `UTC0` before a GPS fix) |
| `/data-cfg` | POST | `bleClassify` (`0` or `1`), `stop` (any value ends the campaign), `campaign=<name>` (starts one; `400` unless the name uses letters, digits, `-`, `_`). Returns the same JSON as GET |
| `/api/probedb` | GET | Probe database (JSON): `mac`, `seen`, `sessions`, `first`, `last`, `rssi`, `vendor`, `name`, `rand`, `ble`, `ch`, `ssids` (up to 8) |
| `/api/probedb/clear` | POST | Clears the probe database |
| `/api/probes.jsonl` | GET | Probe log (JSONL). `404` if none |
| `/api/probes/clear` | POST | Deletes `/probes.jsonl` and `/probes_old.jsonl` |
| `/api/devicedb` | GET | Device database (JSON): `mac`, `seen`, `sessions`, `first`, `last`, `rssi`, `vendor`, `name`, `rand`, `ble`, `ch` |
| `/api/devicedb/clear` | POST | Clears the device database |

These six logs take query parameters to read the end of a large file: `/api/deauth.jsonl`, `/api/drones.jsonl`, `/api/vibrations.jsonl`, `/api/antihunter.log`, `/api/campaigns.csv`, and `/api/incidents.jsonl`.

| Parameter | Meaning | Range |
|---|---|---|
| `bytes` | Return only the last `bytes` of the file, starting at a whole line | 1024-65536 |
| `before` | With `bytes`: end the chunk at this byte offset, to page backward | |

The reply headers `X-Start` (offset of the first byte returned) and `X-Size` (file size) tell you where you are.

`vendor` is the registered company for the first 24 bits of the MAC address. A randomized MAC has no vendor. `name` is the device's advertised BLE name. The device database lives in `/devicedb.jsonl` on the SD card, survives reboots, and holds 2000 entries; the least recently seen entry goes when it is full.

<details>
<summary>Sentinel and detector endpoints</summary>

The `/api/sentinel/` routes exist only in firmware built with Sentinel, which is the default.

| Endpoint | Method | What it does |
|---|---|---|
| `/api/sentinel/status` | GET | JSON: `enabled`, `running`, `scanning` |
| `/api/sentinel/start` | POST | Starts Sentinel on Wi-Fi. `409` while a scan runs |
| `/api/sentinel/stop` | POST | Stops Sentinel |
| `/api/sentinel/boot` | GET | JSON: `boot` |
| `/api/sentinel/boot` | POST | `on`: `1` starts Sentinel at power-on. Returns the same JSON as GET |
| `/api/detect/config` | GET | JSON of every detector switch and threshold |
| `/api/detect/config` | POST | JSON body of up to 8192 bytes with the same keys. Always replies `{"ok":true}`. The [`DETECT_CFG` table](mesh-commands.md#sentinel) lists the keys, units, and defaults. The flasher sends them under `detectors` |
| `/api/detect/health` | GET | JSON: memory, queue depth, drops, per-detector counts |
| `/api/detect/session` | GET | Detector counters for this session (JSON) |
| `/api/detect/clear_session` | POST | Starts a new session and returns its JSON |
| `/api/detect/clear_all` | POST | Clears detector state and logs |
| `/api/detect/verbose` | GET | JSON: `verbose`, `mesh_peers` |
| `/api/detect/verbose/on`, `/api/detect/verbose/off` | POST | Turns verbose detector logging on or off |
| `/api/incidents.json` | GET | Recent incidents (JSON). `limit`: 1-200, default 200 |
| `/api/incidents.jsonl` | GET | Full incident log from the SD card |
| `/api/incidents`, `/api/incidents/clear` | DELETE, POST | Clears all incidents in memory and on the SD card |
| `/api/mesh_cmd.jsonl` | GET | Which radio sent each mesh command (JSONL: `ts`, `epoch`, `src`, `cmd`) |
| `/api/mesh_cmd` | DELETE | Clears that log |
| `/api/apclients.json` | GET | Stations connected to this node's access point |
| `/api/quorum` | GET | Quorum status (JSON) |
| `/api/quorum/config` | POST | `type` and `n` (above 0): peers that must agree before an alert type is raised. `400` if either is missing |
| `/api/bloom` | GET | Bloom filter statistics (JSON) |
| `/api/rid_claims` | GET | Drone Remote ID claims (JSON) |
| `/api/channel_partition` | GET | Channel assignment (JSON) |
| `/api/channel_partition` | POST | Splits channels 1-14 among this node and the peers it has heard, sends each peer its share, and returns the assignment |
| `/api/pps` | GET | GPS pulse-per-second state (JSON): `locked`, `last_edge`, `disciplined_us` |
| `/api/handshakes` | GET | Captured handshakes (JSON) |
| `/api/handshakes/stats` | GET | JSON: `count`, `krack_events` |
| `/api/attacker_hunts` | GET | Active attacker location hunts (JSON) |
| `/api/attacker_hunts/cooldown` | POST | `ms`: time before the same attacker can start another hunt (default 60000) |
| `/api/attack_response` | GET | JSON: `pending`, the follow-up actions (`attack_resp_mask` bits) waiting to run after a confirmed attack. `0` when none wait |
| `/api/attack_response/cancel` | POST | Cancels the waiting follow-up actions |
| `/api/tof` | GET | Time-of-flight peers (JSON) |
| `/api/tof/ping` | POST | `target`: peer to ping (default `*`, all) |
| `/api/tsf_skew` | GET | TSF clock-skew state (JSON) |
| `/api/karma` | GET | Karma state (JSON) |
| `/api/karma/enable` | POST | `on`: `0` or `1` (default `1`). Returns JSON `enabled` |
| `/api/karma/stats` | GET | JSON: `enabled`, `candidates`, `confirmed` |
| `/api/pwnagotchi` | GET | Pwnagotchi sightings (JSON) |
| `/api/recon` | GET | BLE recon state (JSON) |
| `/api/probegraph` | GET | Probe graph (JSON) |
| `/detect` | GET | Detector dashboard (HTML) |

Each of these clears its own state with a POST to `<route>/clear`: `/api/handshakes`, `/api/attacker_hunts`, `/api/tof`, `/api/tsf_skew`, `/api/karma`, `/api/pwnagotchi`, `/api/recon`, `/api/probegraph`.

Each detector keeps a log at `/api/<name>.jsonl`. The first group reads the log in memory, and the second reads the SD card (an empty reply if the file does not exist).

| Group | Names | Clear (POST `/api/<name>/clear`) |
|---|---|---|
| In memory | `pmkid`, `eviltwin`, `ssid_confusion`, `sae_dos`, `owe_abuse`, `fragattack`, `ble_malformed` | `eviltwin` only, and it deletes the SD file `/eviltwin.jsonl`, not the in-memory log |
| SD card | `jamming`, `meshguard`, `probe_flood`, `assoc_sleep`, `pmkid_forge`, `eapol_bait`, `deauth_flood` | All except `deauth_flood`. Clear all detector logs with `/api/detect/clear_all` |

Each incident record has `ts` (uptime in milliseconds), `epoch` (clock seconds, `0` if the clock is not set), `node`, `src` (`local`, or the sending node), `type`, and `raw`.

</details>

<details>
<summary>RF and Wi-Fi settings</summary>

| Endpoint | Method | What it does |
|---|---|---|
| `/rf-config` | GET | JSON: `preset`, `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `wifiChannels`, `globalRssiThreshold`, `rfEnv`. (C5) Also `bandMode` and `dualBand` |
| `/rf-config` | POST | Sets one of the groups below. `409` while a scan runs, `400` if nothing matched. Returns the new settings as JSON |
| `/wifi-config` | GET | JSON: `ssid`, `auth`, `hidden`, `webPassSet`, `webAuth`. Passwords are never returned |
| `/wifi-config` | POST | Sets the access point (parameters below). The node always restarts 3 seconds later |
| `/web-pass` | POST | `pass` (8-63 characters, no `:`) and `current`. `current` is the web password, or the access point password until a web password exists. `400` invalid, `403` wrong `current`. 5 wrong tries lock `/web-pass` and `/web-auth` for 10 minutes |
| `/web-auth` | POST | `enabled` (`1` login required, `0` login off) and `current`. Stored in flash, not in the SD config. `400` missing, `403` wrong `current` |

**`/rf-config` POST** takes one group of fields:

| Fields | Meaning |
|---|---|
| `bandMode` | (C5) Wi-Fi band for scans: `0` 2.4 GHz, `1` 5 GHz, `2` both. Values above 2 become 2. Saved. `dualBand` in the GET reply is `true` on boards that have both bands. Other boards store `0` |
| `rfEnv` | Default triangulation surroundings, 0-4 |
| `preset` | `0` Relaxed, `1` Balanced, `2` Aggressive. Also resets channels to 1-11. Add `globalRssiThreshold` to override the preset's threshold |
| `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `wifiChannels`, `globalRssiThreshold` | A custom setup. `wifiChannelTime` selects this group. Omitted fields keep their value |
| `globalRssiThreshold` alone | Only the signal floor, -100 to -10 dBm |

| Preset | Channel dwell | Wi-Fi scan every | BLE scan every | BLE scan lasts | Signal floor |
|---|---|---|---|---|---|
| `0` Relaxed | 300 ms | 5000 ms | 6000 ms | 3000 ms | -80 dBm |
| `1` Balanced (default) | 160 ms | 3000 ms | 4000 ms | 2000 ms | -95 dBm |
| `2` Aggressive | 110 ms | 1500 ms | 2000 ms | 1000 ms | -100 dBm |

A custom setup limits `wifiChannelTime` to 50-300 ms, `wifiScanInterval` and `bleScanInterval` to 1000-10000 ms, `bleScanDuration` to 1000-5000 ms, and `globalRssiThreshold` to -128 to -10 dBm.

**`/wifi-config` POST** parameters:

| Parameter | Meaning | Range |
|---|---|---|
| `ssid` | Network name. Required | 1-32 characters |
| `pass` | Access point password. Empty keeps the current one | 8-63 characters |
| `auth` | `0` WPA2 and WPA3, `1` WPA2 only | 0-1 |
| `hidden` | `1` hides the network name. Clients must type the name and send it in probe requests | 0-1 |

</details>

<details>
<summary>Baseline</summary>

| Endpoint | Method | What it does |
|---|---|---|
| `/baseline/stats` | GET | JSON: scan progress, device counts, anomalies, elapsed and total time |
| `/baseline/config` | GET | JSON: the settings below plus `enabled`, `established`, `deviceCount`, `anomalyCount` |
| `/baseline/config` | POST | Sets any of the settings below and saves them |
| `/baseline/reset` | POST | Resets the baseline |
| `/baseline/mark` | POST | Marks this moment in the running baseline. Changes are reported from here on. `409` if no baseline runs |

| Setting | Meaning | Unit |
|---|---|---|
| `rssiThreshold` | Weakest signal the baseline counts | dBm |
| `baselineDuration` | Length of the learning phase (0-86400; default 300) | seconds |
| `ramCacheSize` | Devices kept in memory | devices |
| `sdMaxDevices` | Devices kept on the SD card | devices |
| `absenceThreshold` | Time without a signal before a device counts as gone | seconds |
| `reappearanceWindow` | A device returning within this time raises a return alert | seconds |
| `rssiChangeDelta` | Signal change that raises a change alert | dB |

Defaults and effects are in the [README baseline section](../README.md#detection-baseline-anomaly).

</details>

<details>
<summary>Triangulation and randomization</summary>

| Endpoint | Method | What it does |
|---|---|---|
Start triangulation with `/scan` (`triangulate=1` and `targetMac`) and stop it with `/stop`. The estimate appears in `/results`.

| Endpoint | Method | What it does |
|---|---|---|
| `/triangulate/calibrate` | POST | `mac` (a reference device) and `distance` (0.5-100 m): the node listens to that device for 30 seconds and calibrates its distance estimates. `400` bad MAC or distance, `409` while a scan runs |
| `/triangulate/calibrate` | GET | JSON: `running`, `distance` (meters), `wifiRssi0` and `bleRssi0` (signal at 1 m in dBm, `null` if that radio did not calibrate). `distance` is `null` when not calibrated |
| `/triangulate/calibrate/reset` | POST | Clears the calibration. Distances go back to the RF environment values |
| `/randomization/reset` | POST | Resets randomization detection. `409` while a scan runs |
| `/randomization/clear-old` | POST | `age`: removes identities not seen for this many seconds (default 3600) |
| `/api/identity-map` | GET | JSON map from each MAC to its identity ID |

</details>

<details>
<summary>Erase, tamper, and hardware</summary>

The erase key protects the erase routes. The node makes it on first start and shows it at flash time. Pass it as `confirm`, in plain text. The node compares it in constant time. 5 wrong keys, here or over mesh, lock every erase command for 10 minutes.

| Endpoint | Method | What it does |
|---|---|---|
| `/erase/psk-status` | GET | JSON: `pskSet` (a key exists), `custom` (you changed it), `generated` (still the key the node made). While `generated` is true, `key` holds that key |
| `/erase/psk` | POST | Changes the key. `confirm` (current key), `key` (new key, 8-64 characters, no `:`). `403` wrong `confirm`, `400` missing or invalid `key` |
| `/erase/status` | GET | `INACTIVE`, `ACTIVE - Tamper erase countdown: <n> seconds remaining`, the status of a running erase, or `COMPLETED` |
| `/erase/request` | POST | Wipes settings and SD files (own key). `confirm`, optional `reason`. `400` no `confirm`, `403` wrong, `409` another wipe runs |
| `/erase/cancel` | POST | `confirm` (own key): cancels a tamper countdown |
| `/factory-wipe` | POST | `confirm` (own key) and `tier`: `full` (default) wipes settings and SD files, `config` wipes settings only, `data` wipes SD files only. Reboots afterward. `400` bad tier, `409` another wipe runs |
| `/secure/status` | GET | `INACTIVE` or `TAMPER_ACTIVE:<n>s` |
| `/config/autoerase` | GET | JSON: `enabled`, `delay`, `cooldown`, `vibrationsRequired`, `detectionWindow`, `setupDelay`, `inSetupMode`, `setupStartTime`, `currentTime`, `tamperActive`. Times in milliseconds |
| `/config/autoerase` | POST | Sets auto-erase. All of `enabled`, `delay`, `cooldown`, `vibrationsRequired`, `detectionWindow`, `setupDelay`, and `confirm` (own key) are required, else `400` |

`/config/autoerase` POST fields. Values outside the range move to the nearest limit. The mesh command `AUTOERASE_ENABLE` uses seconds and narrower ranges.

| Field | Meaning | Unit | Range |
|---|---|---|---|
| `enabled` | `true`, `1`, or `on` turns it on | | |
| `setupDelay` | Time before auto-erase arms | ms | 30000-600000 |
| `delay` | Time from tamper alert to wipe | ms | 10000-300000 |
| `vibrationsRequired` | Vibrations that start the countdown | count | 2-10 |
| `detectionWindow` | Time in which those vibrations must happen | ms | 5000-120000 |
| `cooldown` | Time before another tamper can start a countdown | ms | 60000-3600000 |

| Endpoint | Method | What it does |
|---|---|---|
| `/gps` | GET | GPS status and position (text) |
| `/sd-repair` | GET | JSON: `auto`, `mounted`, `mountFailures`, `pending` |
| `/sd-repair` | POST | `auto=1` or `0` sets automatic repair of a card that will not mount. `now` queues a remount, which erases the card if it still will not mount |

</details>
