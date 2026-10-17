# API Reference

Full HTTP API for the Full firmware's web server.
Back to the [README](../README.md).

> [!NOTE]
> Timestamps show local time from the GPS fix, with daylight saving applied. Without a GPS lock they show UTC. Fields named `epoch` are UTC seconds.

> [!IMPORTANT]
> Every request must address the node by its own IP (`192.168.4.1` on the AP, or its station IP); the node's own loopback requests from the scheduler are allowed. The server returns `403` when the `Host` header names anything else, when `Sec-Fetch-Site` is `cross-site` or `same-site`, or when `Origin` is not `http://<Host>`. Responses carry no CORS headers. A page on another site can't read from the node or send it commands, and DNS-rebinding hostnames are refused.

> [!IMPORTANT]
> Every route needs HTTP Digest login, user `admin`, realm `AntiHunter`. The password is the web password, or the AP password until one is set (`/web-pass` or `webPass` in the flasher config). Without valid credentials the server returns `401` with a `WWW-Authenticate: Digest` challenge; browsers ask once and remember the login. The scheduler's loopback requests are exempt. Turn the login off with `/web-auth` or `"webAuth":false` in the flasher config (stored in NVS, not in the SD config file); then anyone on the AP can use the web UI. Neither setting is available over mesh.

### Core

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/diag` | GET | System diagnostics |
| `/stop` | GET | Fast-abort every scan/task: aborts in-flight Wi-Fi/BLE scans, stops triangulation, cancels mesh drain. `/diag` reports `Stopping: yes` until the task actually exits |
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
| `/schedule` | GET | Schedule list (text) |
| `/schedule` | POST | Add a block (`at` = `YYYY-MM-DDTHH:MM` node local time, `period` = seconds, `0` once or 600-2678400, `path` = `/scan`, `/sniffer` or `/drone`, `body` = that scan's form body), or `del=<block line>` to remove one. Max 8 blocks. `400` bad input, `404` block not found, `413` full |
| `/mesh-tx/cancel` | POST | Empty the mesh TX queue; the scan keeps running |

### Results

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/results` | GET | Latest scan/triangulation results |
| `/sniffer-cache` | GET | Cached device detections |
| `/deauth-results` | GET | Deauth attack logs |
| `/randomization-results` | GET | Randomization correlation results |
| `/drone-results` | GET | Drone detection results |
| `/drone-log` | GET | Drone event log (JSON) |
| `/csi-results` | GET | CSI motion results (text). Beta and C5 |
| `/csi-json` | GET | CSI motion state (JSON). Beta and C5 |

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
| `/api/fleet/send` | POST | Send `@<node> <cmd>` over the mesh (`node` 2-5 `A-Z0-9`, not this node; `cmd` one of `SCHED_ADD:`, `DEVICE_SCAN_START:`, `SCAN_START:`, `STOP`, `STATUS`, `CAMPAIGN_START:`, `CAMPAIGN_STOP`, `CAMPAIGN_STATUS`, `BLE_CLASSIFY:`). `400` bad node or command, `409` mesh disabled, `413` too long, `503` mesh busy |

### Probe Database

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/probedb` | GET | Probe database (JSON: mac, vendor, name, SSIDs, RSSI, randomization status) |
| `/api/probedb/clear` | POST | Clear probe database |
| `/api/probes.jsonl` | GET | Stream probe log from SD (JSONL) |
| `/api/probes/clear` | POST | Delete the probe log (`/probes.jsonl` and `/probes_old.jsonl`) |

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
| `/api/campaigns.csv` | GET | Campaign start/stop log (CSV) |
| `/data-cfg` | GET | Active campaign and BLE classifier state (JSON: `campaign`, `bleClassify`) |
| `/data-cfg` | POST | `bleClassify` (0/1), `stop` ends the campaign, `campaign=<name>` starts one (`400` if the name has characters other than letters, digits, `-`, `_`). Returns the same JSON as GET |

Available datasets: All Discovered Devices, Probe Devices, Probe Events, Deauth Attacks, Drone Detections, Vibration Events, Baseline Stats, Sentinel Incidents, and System Log. All datasets support export (download the raw file) and clear (with confirmation). The headless firmware logs the same data to SD without the web UI, except the device database, which is web-build only.

**Endpoints not listed above.** Each detector keeps its own SD log at `/api/<detector>.jsonl`, and most take a `/api/<detector>/clear` POST. Current detectors: `assoc_sleep`, `ble_attack`, `ble_malformed`, `deauth_ap`, `deauth_flood`, `eapol_bait`, `eviltwin`, `fragattack`, `jamming`, `meshguard`, `owe_abuse`, `pmkid`, `pmkid_forge`, `probe_ap`, `probe_flood`, `sae_dos`, `ssid_confusion`. A few return live JSON instead of a file: `/api/tsf_skew`, `/api/pwnagotchi`, `/api/recon`, `/api/karma`, `/api/handshakes`, `/api/attacker_hunts`. `GET /diag` dumps runtime state. For anything else, the full route list is the set of `server->on(` calls in `Antihunter/full/src/network.cpp`.

<details>
<summary>Configuration Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/node-id` | GET/POST | Get/set node ID (2-5 alphanumeric, A-Z 0-9) |
| `/mesh-interval` | GET/POST | Get/set mesh send interval (1500-30000ms) |
| `/save` | POST | Save target list (`list`). `507` if NVS rejects it (limit 4000 bytes); the running list is left unchanged |
| `/export` | GET | Export target MAC list |
| `/allowlist-export` | GET | Export allowlist |
| `/allowlist-save` | POST | Save allowlist |
| `/api/time` | POST | Set RTC time from Unix timestamp |
| `/mesh-dedup-ttl` | GET | Mesh dedup state (JSON) |
| `/mesh-dedup-ttl` | POST | Set dedup TTL (`ttl` 0-3600 seconds, `0` disables dedup) |
| `/mesh-dedup-clear` | POST | Clear the dedup cache |
| `/mesh-session-dedup` | POST | Session dedup (`on` 0/1) |
| `/mesh/drain/status` | GET | Mesh TX drain progress (JSON) |
| `/vibration-scan` | GET | Vibration auto-scan config (JSON: `enabled`, `mode`, `duration`, `cooldown` seconds, `preempt`) |
| `/vibration-scan` | POST | Set `enabled`, `mode` (0-8), `duration` (0-65535 s), `cooldown` (5-86400 s), `preempt`; saved. `400` for mode `8` (pcap) with duration `0` |
| `/api/onboarding` | GET/POST | First-run disclaimer state (JSON: `accepted`). POST marks it accepted |

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
| `/api/incidents/clear` | POST | Clear all incidents |
| `/api/pmkid.jsonl` `/api/eviltwin.jsonl` `/api/ssid_confusion.jsonl` `/api/sae_dos.jsonl` `/api/owe_abuse.jsonl` `/api/fragattack.jsonl` `/api/ble_malformed.jsonl` | GET | Recent events from that detector's RAM log (JSONL) |
| `/api/jamming.jsonl` `/api/meshguard.jsonl` `/api/ble_attack.jsonl` `/api/probe_flood.jsonl` `/api/assoc_sleep.jsonl` `/api/pmkid_forge.jsonl` `/api/eapol_bait.jsonl` `/api/deauth_flood.jsonl` `/api/deauth_ap.jsonl` `/api/probe_ap.jsonl` | GET | That detector's log from SD (JSONL); empty when the file does not exist |
| `/api/jamming/clear` `/api/meshguard/clear` `/api/ble_attack/clear` `/api/probe_flood/clear` `/api/assoc_sleep/clear` `/api/pmkid_forge/clear` `/api/eapol_bait/clear` `/api/deauth_flood/clear` `/api/eviltwin/clear` | POST | Delete that detector's SD log (`/eviltwin/clear` removes `/eviltwin.jsonl` on SD; `/api/eviltwin.jsonl` reads the RAM log) |
| `/api/sentinel/ble/start` | POST | Start the BLE scan; `409` below 60000 bytes free heap |
| `/api/sentinel/boot` | GET | Boot auto-start setting (JSON: `boot`) |
| `/api/sentinel/boot` | POST | Set boot auto-start (`on` 0/1). Returns the same JSON as GET |
| `/api/detect/session` | GET | Detector session counters (JSON) |
| `/api/detect/clear_session` | POST | Start a new session; returns the session JSON |
| `/api/detect/clear_all` | POST | Clear detector state and logs |
| `/api/detect/verbose` | GET | Verbose state and mesh peer count (JSON: `verbose`, `mesh_peers`) |
| `/api/detect/verbose/on` / `/api/detect/verbose/off` | POST | Turn verbose detector logging on/off |
| `/api/quorum` | GET | Quorum status (JSON) |
| `/api/quorum/config` | POST | Peers required for an alert type (`type`, `n` > 0); `400` if either is missing |
| `/api/bloom` | GET | Bloom filter stats (JSON) |
| `/api/rid_claims` | GET | Remote ID claims (JSON) |
| `/api/channel_partition` | GET | Channel assignment (JSON) |
| `/api/channel_partition` | POST | Split channels 1-14 across this node and the peers it has heard, send each peer its share (`CHAN_ASSIGN`), and return the assignment. A Device Scan started with no channel list then sweeps this node's share |
| `/api/pps` | GET | GPS PPS state (JSON: `locked`, `last_edge`, `disciplined_us`) |
| `/api/recon/clear` | POST | Clear BLE recon state |
| `/api/probegraph` | GET | Probe graph (JSON) |
| `/api/probegraph/clear` | POST | Clear the probe graph |
| `/api/handshakes/clear` | POST | Clear captured handshakes |
| `/api/handshakes/stats` | GET | Handshake counts (JSON: `count`, `krack_events`) |
| `/api/attacker_hunts/clear` | POST | Clear active attacker hunts |
| `/api/attacker_hunts/cooldown` | POST | Hunt cooldown (`ms`, default 60000) |
| `/api/tof` | GET | Time-of-flight peers (JSON) |
| `/api/tof/clear` | POST | Clear time-of-flight peers |
| `/api/tof/ping` | POST | Time-of-flight ping (`target`, default `*`) |
| `/api/tsf_skew/clear` | POST | Clear TSF skew state |
| `/api/karma/clear` | POST | Clear Karma state |
| `/api/karma/enable` | POST | Karma detector on/off (`on` 0/1). Returns JSON `enabled` |
| `/api/karma/stats` | GET | Karma counts (JSON: `enabled`, `candidates`, `confirmed`) |
| `/api/pwnagotchi/clear` | POST | Clear Pwnagotchi sightings |
| `/detect` | GET | Detector dashboard page (HTML) |

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
| `/wifi-config` | GET | - | Wi-Fi AP settings (JSON: `ssid`, `auth`, `hidden`, `webPassSet`, `webAuth`; passwords are not returned) |
| `/web-pass` | POST | `pass` (8-63, no `:`), `current` | Set the web login password. `current` is the web password, or the AP password until one is set. `400` invalid, `403` wrong current password; 5 wrong tries lock `/web-pass` and `/web-auth` for 10 min |
| `/web-auth` | POST | `enabled` (0/1), `current` | Turn the web login off (`0`) or on (`1`); stored in NVS, not in the SD config. `400` missing parameter, `403` wrong current password |
| `/wifi-config` | POST | `ssid` (1-32), `pass` (8-63, or empty to keep the current one), `auth` (0=WPA2/WPA3, 1=WPA2), `hidden` (0/1) | Update AP credentials and mode (triggers reboot). `hidden=1` stops the SSID beacon; clients must then enter the SSID manually and will probe for it by name, so the network name travels with them. Auth remains the access control |

</details>

<details>
<summary>Baseline Endpoints</summary>

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/baseline/status` | GET | Baseline scan status (JSON) |
| `/baseline/stats` | GET | Baseline statistics (JSON) |
| `/baseline/config` | GET/POST | Baseline config (`rssiThreshold`, `baselineDuration`, `ramCacheSize`, `sdMaxDevices`, `absenceThreshold`, `reappearanceWindow`, `rssiChangeDelta`) |
| `/baseline/reset` | POST | Reset baseline |
| `/baseline/mark` | POST | Watch for changes from now; 409 if no baseline is running |

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
| `/api/identity-map` | GET | Tracked MACs mapped to identity IDs (JSON) |

**Security:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/erase/status` | GET | Erasure status |
| `/erase/request` | POST | Request secure erase (`confirm`=erase key, optional `reason`) |
| `/erase/cancel` | POST | Cancel erase sequence |
| `/erase/psk-status` | GET | Erase key state (JSON: `pskSet`, `custom`, `apDefault`) |
| `/erase/psk` | POST | Change the erase key (`confirm` = current key, `key` = new key, 8-64 chars, no `:`). `403` wrong key, `400` invalid key |
| `/factory-wipe` | POST | Reset and reboot (`confirm` = erase key, `tier` = `full` (default), `config` or `data`). `400` bad tier, `403` wrong key, `409` erase already running |
| `/secure/status` | GET | Tamper detection status |
| `/secure/abort` | POST | Abort tamper sequence |
| `/config/autoerase` | GET/POST | Auto-erase config |
| `/battery-saver` | GET | Battery saver (`action`=start/stop/status, `interval`) |

The erase key in `confirm` on `/erase/request`, `/erase/cancel`, `/erase/psk`, `/factory-wipe`, `/secure/abort` and `/config/autoerase` POST is compared in constant time and shares the mesh erase lockout: 5 wrong keys lock all erase commands for 10 min.

**Hardware:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gps` | GET | GPS status and location |
| `/sd-status` | GET | SD card status |
| `/sd-repair` | GET | SD repair state (JSON: `auto`, `mounted`, `mountFailures`, `pending`) |
| `/sd-repair` | POST | `auto` (1/0) sets auto-repair; `now` queues a remount that erases the card only if it won't mount |
| `/drone/status` | GET | Drone detection status (JSON) |
| `/mesh` | POST | Enable/disable mesh |
| `/mesh-test` | GET | Test mesh connectivity |
| `/mesh-hb` | POST | Enable/disable heartbeat (`enabled=true\|false`) |
| `/mesh-hb-interval` | POST | Set heartbeat interval (`interval=1-60` minutes) |
| `/vibration` | POST | Toggle vibration sensor |

</details>

---
