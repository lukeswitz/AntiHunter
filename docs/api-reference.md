# API Reference

Full HTTP API for the Full firmware's web server.
Back to the [README](../README.md).

> [!NOTE]
> Timestamps show local time from the GPS fix, with daylight saving applied. Without a GPS lock they show UTC. Fields named `epoch` are UTC seconds.

### Core

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/diag` | GET | System diagnostics |
| `/stop` | GET | Fast-abort every scan/task: aborts in-flight WiFi/BLE scans, stops triangulation, cancels mesh drain. `/diag` reports `Stopping: yes` until the task actually exits |
| `/config` | GET/POST | System configuration (JSON) |
| `/clear-results` | POST | Clear all scan results |

### Scanning

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Start target scan (`mode`, `secs`, `forever`, `ch`, `triangulate`, `targetMac`). With `triangulate=1`, returns `400` and the reason if triangulation cannot start (bad/empty `targetMac`, debounce, busy task) |
| `/sniffer` | POST | Start detection scan (`detection`, `secs`, `forever`, `randomizationMode`, `probeScanMode`, `captureProbes`) |
| `/drone` | POST | Start drone RID detection (`secs`, `forever`) |
| `/pcap/status` | GET | Capture state (JSON): active, radio, band, channel, frames, bytes, dropped, elapsed, current file, `dualBand`, SD budget/floor/free in MB |
| `/pcap/list` | GET | Captures in `/pcap` (JSON): name, size, and whether that file is still being written |
| `/pcap/download` | GET | Streams a capture. `f=<name>` selects one, omit it for the most recent |
| `/pcap/delete` | POST | Deletes one capture (`f`). Refused while that file is recording |
| `/pcap/delete-all` | POST | Deletes every capture in `/pcap` |
| `/pcap/limits` | POST | Auto-capture pruning (`budgetMB`, `floorMB`), persisted |

### Results

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/results` | GET | Latest scan/triangulation results |
| `/sniffer-cache` | GET | Cached device detections |
| `/deauth-results` | GET | Deauth attack logs |
| `/randomization-results` | GET | Randomization correlation results |
| `/drone-results` | GET | Drone detection results |
| `/drone-log` | GET | Drone event log (JSON) |

### Fleet

The **Fleet** tab lists senders heard on the mesh.

**Nodes** - ids matching the node-id rule (2-5 chars, `A-Z0-9`), with mode, scan state, hits, uptime, temp
and GPS from their `STATUS` and heartbeat lines. `type` is `RADAR` on `TYPE:RADAR`, else `DIGI`. Online =
heard within 2 minutes.

**Other Mesh Radios** - every other sender id, including your own paired radio. Tagged `Control` once an
`@` line is seen from it, `Unknown` otherwise. Also shown in the Sentinel tab.

Rosters hold 48 entries in RAM, dropped after 15 minutes unheard. **Ping Nodes** broadcasts `@ALL STATUS`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mesh` | GET | Fleet roster (JSON: `node`, `peers`, `radios`) |
| `/api/mesh/ping` | POST | Broadcast `@ALL STATUS` |
| `/api/mesh/clear` | POST | Clear both rosters |

### Probe Database

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/probedb` | GET | Probe database (JSON: mac, vendor, name, SSIDs, RSSI, randomization status) |
| `/api/probedb/clear` | POST | Clear probe database |
| `/api/probes.jsonl` | GET | Stream probe log from SD (JSONL) |

`vendor` is the IEEE OUI-registered organization, resolved from the first 24 bits of the MAC.
`name` is the device's advertised BLE name. Randomized (locally administered) MACs carry no OUI
assignment and resolve to no vendor.

### Device Database

Every device seen by a Device Discovery or target scan is merged into `/devicedb.jsonl` on SD and
survives reboots. Capped at 2000 entries; the least recently seen entry is evicted when full.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devicedb` | GET | All discovered devices (JSON: mac, ble, vendor, name, rssi, ch, sessions, seen, first, last, rand) |
| `/api/devicedb/clear` | POST | Clear device database |

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

Available datasets: All Discovered Devices, Probe Devices, Probe Events, Deauth Attacks, Drone Detections, Vibration Events, Baseline Stats, Sentinel Incidents, and System Log. All datasets support export (download the raw file) and clear (with confirmation). The headless firmware logs the same data to SD without the web UI, except the device database, which is web-build only.

**Endpoints not listed above.** Each detector keeps its own SD log at `/api/<detector>.jsonl`, and most take a `/api/<detector>/clear` POST. Current detectors: `assoc_sleep`, `ble_attack`, `ble_malformed`, `deauth_ap`, `deauth_flood`, `eapol_bait`, `eviltwin`, `fragattack`, `jamming`, `meshguard`, `owe_abuse`, `pmkid`, `pmkid_forge`, `probe_ap`, `probe_flood`, `sae_dos`, `ssid_confusion`. A few return live JSON instead of a file: `/api/tsf_skew`, `/api/pwnagotchi`, `/api/recon`, `/api/karma`, `/api/handshakes`, `/api/attacker_hunts`. `GET /diag` dumps runtime state. For anything else, the full route list is the set of `server->on(` calls in `Antihunter/full/src/network.cpp`.

<details>
<summary>Configuration Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/node-id` | GET/POST | Get/set node ID (2-5 alphanumeric, A-Z 0-9) |
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
| `/api/detect/config` | POST | Set detector config. JSON body of `{key:bool/int}` - same keys returned by GET (e.g. `pmkid`, `eviltwin`, `sae`, `karma`, `probe_flood`, `assoc_sleep`, `mesh_*` flags, thresholds). The Web Flasher/Configurator sends these under a nested `detectors` object at flash time. |
| `/api/detect/health` | GET | Detector runtime health (heap, queue depth, drops, per-detector counts) |
| `/api/sentinel/status` | GET | Sentinel running state |
| `/api/sentinel/start` / `/api/sentinel/stop` | POST | Start/stop the Sentinel engine |
| `/api/incidents.json` | GET | Recent incident ring (JSON) |
| `/api/incidents.jsonl` | GET | Full incident log from SD (JSONL) |
| `/api/incidents` | DELETE | Clear all incidents (RAM + SD) |
| `/api/mesh_cmd.jsonl` | GET | Mesh command provenance audit from SD (JSONL: `ts`, `epoch`, `src` radio id, `cmd`) |
| `/api/mesh_cmd` | DELETE | Clear the mesh command audit log |
| `/api/apclients.json` | GET | Stations associated to this node's AP |

Each incident record carries: `ts` (device uptime ms), **`epoch`** (RTC Unix seconds - `0` if RTC unset; used by the Analysis tab to show real timestamps), `node`, `src`, `type`, `raw`.

Persistent boot setting: `sentinelBoot` (bool) in the configurator JSON / NVS pref `sentBoot` - auto-starts the Sentinel at power-on when true.

</details>

<details>
<summary>RF Configuration Endpoints</summary>

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/rf-config` | GET | - | RF config (JSON) |
| `/rf-config` | POST | `preset` (0-2) | Apply preset: 0=Relaxed, 1=Balanced, 2=Aggressive |
| `/rf-config` | POST | `wifiChannelTime`, `wifiScanInterval`, `bleScanInterval`, `bleScanDuration`, `wifiChannels`, `globalRssiThreshold` | Full custom config |
| `/rf-config` | POST | `globalRssiThreshold` (-100 to -10) | RSSI threshold only |
| `/rf-config` | POST | `bandMode` (0-2) | **C5 only.** Band: 0=2.4GHz, 1=5GHz, 2=both. Also returned by GET, and accepted on `/config` GET/POST and in the serial `CONFIG:` JSON |
| `/wifi-config` | GET | - | WiFi AP settings (JSON) |
| `/wifi-config` | POST | `ssid` (1-32), `pass` (8-63 or empty), `auth` (0=WPA2/WPA3, 1=WPA2), `hidden` (0/1) | Update AP credentials and mode (triggers reboot). `hidden=1` stops the SSID beacon; clients must then enter the SSID manually and will probe for it by name, so the network name travels with them. Auth remains the access control |

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
| `/triangulate/start` | POST | Start (`mac`, `duration`, `rfEnv`, optional `wifiPwr`/`blePwr` 0.1-5.0); `400` + reason if it cannot start |
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
| `/erase/request` | POST | Request secure erase (`confirm`=WIPE_ALL_DATA, optional `reason`) |
| `/erase/cancel` | POST | Cancel erase sequence |
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
