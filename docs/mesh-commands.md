# Mesh Commands

Full command reference for controlling a node over the Meshtastic mesh.
Back to the [README](../README.md).

Timestamps show local time from the GPS fix. Without a GPS lock they show UTC. Node IDs: 2-5 alphanumeric characters (A-Z, 0-9), no spaces.

> [!TIP]
> `@ALL` broadcasts to all nodes. Replace with a node ID for targeted commands.

### Core

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `STATUS` | Report mode, scan state, hits, temp, uptime, GPS | None | `@ALL STATUS` |
| `STOP` | Stop everything running | None | `@ALL STOP` |

### Configuration

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `CONFIG_TARGETS` | Set the watchlist | Pipe-delimited MACs, OUIs, SSIDs | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33\|MyNetwork` |
| `CONFIG_NODEID` | Rename the node | 2-5 alphanumeric | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | Set the RSSI floor | -128 to -10 | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | Set the channels to sweep | Comma-separated or a range | `@ALL CONFIG_CHANNELS:1..11` |
| `CONFIG_DEDUP_TTL` | Set cross-scan MAC dedup | Seconds 0-3600, 0 disables | `@ALL CONFIG_DEDUP_TTL:300` |
| `CONFIG_SESSION_DEDUP` | Toggle per-session dedup | `0`/`1` | `@ALL CONFIG_SESSION_DEDUP:1` |
| `MESH_DEDUP_CLEAR` | Clear the dedup cache | None | `@ALL MESH_DEDUP_CLEAR` |

### Scanning

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `SCAN_START` | Hunt the watchlist | `mode:secs:channels[:FOREVER]` | `@ALL SCAN_START:2:300:1..11` |
| `DEVICE_SCAN_START` | List everything in range | `mode:secs[:FOREVER[:+PROBE]]` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | Learn the area, then flag changes | `duration[:FOREVER]`, min 60s | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | Report baseline progress | None | `@ALL BASELINE_STATUS` |
| `DRONE_START` | Watch for drone Remote ID | `secs[:FOREVER]` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | Watch for deauth attacks | `secs[:FOREVER]` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | Link randomized MACs to devices | `mode:secs[:FOREVER]` | `@ALL RANDOMIZATION_START:2:300` |
| `PROBE_START` / `PROBE_STOP` | Collect probe requests | `mode:secs[:FOREVER][:+ALL]` | `@ALL PROBE_START:2:300:+ALL` |
| `PCAP_START` / `PCAP_STOP` | Record traffic to SD as pcap. `CH` takes a comma list of channels to hop; without it the node uses its configured channels | `radio:secs:band[:CH<list>][:FOREVER]` | `@ALL PCAP_START:0:300:0:CH1,6,11` |
| `PCAP_LIMITS` | Set or read the capture file size cap, 8-300 MB. No argument reads it back | `[MB]` | `@ALL PCAP_LIMITS:150` |
| `SD_REPAIR` | Let a node rebuild an unmountable SD card by itself. `NOW` repairs once. Off by default, rebuilding erases the card | `ON\|OFF\|NOW` | `@ALL SD_REPAIR:ON` |

> [!WARNING]
> Stop a capture before cutting power or resetting the node. FAT has no power-fail
> protection, so an interruption mid-write can leave the SD card unreadable until it is
> reformatted, and the node then runs with no storage at all. `SD_REPAIR:ON` lets a node
> rebuild its own card, which recovers most cases but not all, and erases the card.

The `+PROBE` flag on `DEVICE_SCAN_START` enables probe request capture during device scans, populating the probe database alongside normal device discovery.

### Sentinel (Beta version only)

These commands are only present on Beta firmware. On Stable they are not recognized.

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `SENTINEL_ON` / `SENTINEL_OFF` | Start or stop Sentinel | None | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | Report Sentinel state | None | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | Pin a channel or hop | `defend` or `scan` | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | Auto-start at power-on | `1`/`0` | `@ALL SENTINEL_BOOT:1` |
| `GROUP` | Toggle a detector group | `<name>:<on\|off>` | `@ALL GROUP:dos:on` |
| `DETECT_CFG` | Set detector tunables | `<json>`, ≤180 chars | `@AH01 DETECT_CFG:{"pmkid":true}` |
| `DETECT_CFG_GET` | Dump the config to serial | None | `@AH01 DETECT_CFG_GET` |
| `INCIDENTS` | Dump the incident log | `[:<1-200>]` | `@AH01 INCIDENTS:50` |
| `INCIDENTS_CLEAR` | Clear the incident log | None | `@ALL INCIDENTS_CLEAR` |
| `ATTACKER_TRILAT` | Triangulate a confirmed attacker | `1`/`0`/`on`/`off` | `@ALL ATTACKER_TRILAT:1` |
| `ATTACKER_TRILAT_STATUS` | Report that setting | None | `@AH01 ATTACKER_TRILAT_STATUS` |

`GROUP` members: `dos` = eviltwin, sae, assoc_sleep · `rogue` = eviltwin, owe, karma · `recon` = pmkid, probe_flood, hshk · `physical` = frag, tsf, jam · `mesh` = mesh_guard · `all` = every member listed here.

`DETECT_CFG` sets the rest: `ssid_confusion`, `pwna`, `csa_quiet`, `rid_spoof`, `bloom_gossip`, `ble_malformed`, the 15 `mesh_*` emit toggles and the numeric thresholds. `DETECT_CFG_GET` prints every key to serial. `GROUP` and `DETECT_CFG` write to NVS. Deauth, beacon and auth detection have no toggle.

Headless has no SoftAP. `defend` pins to whatever channel the radio last used, so use `scan`.

<details>
<summary>Triangulation Commands</summary>

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `TRIANGULATE_START` | Locate a MAC across nodes | `target:duration[:rfEnv[:wifiPwr:blePwr]]` | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.0:1.0` |
| `TRIANGULATE_STOP` | Stop it | None | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | Report the fix | None | `@AH01 TRIANGULATE_RESULTS` |

</details>

<details>
<summary>Security Commands</summary>

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `ERASE_REQUEST` | Ask to wipe, returns a challenge | None | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | Wipe with the answered challenge | Auth token | `@AH02 ERASE_FORCE:AH_12345678_87654321_00001234` |
| `ERASE_CANCEL` | Abort a pending wipe | None | `@AH01 ERASE_CANCEL` |
| `AUTOERASE_ENABLE` | Wipe if the node is moved | `setup:erase:vibs:window:cooldown` | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300` |
| `AUTOERASE_DISABLE` | Turn that off | None | `@AH01 AUTOERASE_DISABLE` |
| `AUTOERASE_STATUS` | Report auto-erase state | None | `@AH01 AUTOERASE_STATUS` |
| `VIBRATION_ON` / `VIBRATION_OFF` | Enable the movement sensor | None | `@AH01 VIBRATION_ON` |
| `VIBRATION_STATUS` | Report sensor state | None | `@AH01 VIBRATION_STATUS` |
| `VIBSCAN_SET` | Start a scan when moved | `en:mode:dur[:cooldown]` | `@AH01 VIBSCAN_SET:1:2:60:60` |
| `VIBSCAN_STATUS` | Report that setting | None | `@AH01 VIBSCAN_STATUS` |
| `CONFIG_ERASE_PSK` | Set the key that authorizes a wipe | `<key>`, 1-64 chars | `@AH01 CONFIG_ERASE_PSK:myS3cretKey` |
| `FACTORY_RESET` | Reset one node, needs the key | `<FULL\|CONFIG\|DATA>:<key>` | `@AH01 FACTORY_RESET:FULL:myS3cretKey` |

`VIBSCAN_SET` modes: 0 off, 1 all-device, 2 probe-req, 3 rand-MAC, 4 list, 5 drone, 6 deauth, 7 baseline, 8 packet capture. Duration 0 runs until stopped, cooldown 5-86400s. Skipped if a scan is already running or in battery saver.

`AUTOERASE_ENABLE` and `FACTORY_RESET` require the erase PSK credential appended once `CONFIG_ERASE_PSK` has set one.

</details>

<details>
<summary>Battery Saver Commands</summary>

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `BATTERY_SAVER_START` | Drop to low power | `interval_minutes` 1-30 | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | Return to normal | None | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | Report power state | None | `@AH01 BATTERY_SAVER_STATUS` |

Stops WiFi/BLE scanning, reduces CPU to 80MHz, enables light sleep, GPS polled once per minute. Mesh UART stays active. Heartbeat format:

```
NODE_ID: HEARTBEAT: Temp:XXC GPS:lat,lon Battery:SAVER
```

</details>

<details>
<summary>Heartbeat Commands</summary>

Periodic status broadcast over mesh. **Disabled by default.**

| Command | Does | Parameters | Example |
|---------|------|------------|---------|
| `HB_ON` / `HB_OFF` | Toggle the heartbeat | None | `@AH01 HB_ON` |
| `HB_INTERVAL` | Set how often it sends | `minutes` 1-60 | `@AH01 HB_INTERVAL:10` |

Format: `NODE_ID: Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC [GPS:lat,lon]`

</details>

<details>
<summary>Alert Message Formats</summary>

| Alert Type | Format |
|------------|--------|
| Target Detected | `NODE_ID: Target: MAC RSSI:N Type:WiFi\|BLE [Name:name] [GPS=lat,lon]` |
| Baseline Anomaly | `NODE_ID: ANOMALY-NEW: TYPE MAC RSSI:N [Name:name]` · `NODE_ID: ANOMALY-RETURN: TYPE MAC RSSI:NdBm [Name:name]` · `NODE_ID: ANOMALY-RSSI: TYPE MAC Old:NdBm New:NdBm Delta:NdBm` · `NODE_ID: ANOMALY: TYPE MAC RSSI:N reason [N:name]` |
| Deauth Attack | `NODE_ID: ATTACK: DEAUTH\|DISASSOC [BROADCAST\|TARGETED] SRC:MAC DST:MAC RSSI:dBm CH:N R:reason [GPS:lat,lon]` |
| Drone Detected | `NODE_ID: DRONE: MAC ID:uavId R-dBm [GPS:lat,lon] [ALT:m] [SPD:m/s] [OP:lat,lon]` - sent once per appearance, WiFi and BLE alike. Telemetry fields are dropped if the line would exceed the mesh MTU. A drone that stays in range is never re-announced; one that returns after going stale is re-announced at most once per 120s |
| Drone Lost | `NODE_ID: DRONE_LOST: MAC [ID:uavId] AGE:secs` - sent once, 120s after the last Remote ID beacon. Not repeated while the aircraft stays away, and the Web UI keeps the detection, marked stale |
| Triangulation Data | `NODE_ID: T_D: MAC Hits=N RSSI:N [GPS=lat,lon HDOP=X.X]` - one per participating node per reporting cycle, coordinator included. Slots are assigned by node-ID order, so every node derives the same rotation |
| Triangulation Final | `NODE_ID: T_F: MAC=addr GPS=lat,lon CONF=85.5 UNC=12.3` |
| Triangulation Complete | `NODE_ID: T_C: MAC=addr Nodes=N`, plus ` GPS=lat,lon CONF=pct URL=<maps link>` when trilateration solved |
| Triangulation Cycle Start | `@ALL TRI_CYCLE_START:<ms>:<node,node,...>` - the coordinating node broadcasts it so every node in the run reports in its own slot. Sent by the firmware, not something you issue |
| Probe Watchlist Hit | `NODE_ID: PROBE_HIT MAC [Randomized\|Vendor] RSSI=dBm CH=N [SSID="network" [GHOST]] [DST]` - vendor token omitted entirely when unknown |
| Packet Capture Started | `NODE_ID: PCAP_START: WIFI\|BLE D=secs` - `D=0` means the capture runs until stopped |
| Packet Capture Done | `NODE_ID: PCAP_DONE: F=frames B=bytes D=dropped` - `D` counts frames the SD writer could not keep up with |
| Tamper Detected | `NODE_ID: TAMPER_DETECTED: Auto-erase in Xs [GPS:lat,lon]` |
| Status Response | `NODE_ID: STATUS: Mode:TYPE Scan:ACTIVE\|IDLE Hits:N Temp:XX.XC Up:HH:MM:SS [GPS:lat,lon HDOP=X.X]` |

</details>

<details>
<summary>Sentinel label reference (mesh labels and their values)</summary>

Log parsers and C2 must handle all of these. Values are taken from `detect.cpp`; anything not listed here is not emitted.

| Mesh prefix | Payload | Enumerated values |
|---|---|---|
| `DEAUTH_FORGE:<src>:<tool>:<rssi>` | tool tag | **static:** `MARAUDER` (reason=2 + seq=0xFFF0 + dur=0x013A - the template shared by ESP32Marauder, Bruce and Evil-M5Project), `MICHAEL_TKIP` (reason=14). **behavioral:** `MDK4`, `ESP_DEAUTHER`, `AIREPLAY`, `BETTERCAP` |
| `DEAUTH_FLOOD:<src>:<count>:<rssi>` | frame count | - |
| `DEAUTH_AP_TARGETED:<client>:<reason>:<count>` | client + reason code | reason is context only, see the table above |
| `BEACON_FORGE:<bssid>:<reason>:<rssi>` | forgery reason | `FORGE_TSF_STATIC`, `FORGE_BI_1000`, `FORGE_SRC_MCAST`, `FORGE_CSA_FF`, `FORGE_QUIET_ELEM`, `FORGE_SSID_ROTATE`, `FORGE_EVIL_PORTAL`, `FORGE_EVIL_PORTAL_ESP`, `FORGE_KARMA_BRUCE` |
| `BEACON_FLOOD:<rssi>` | - | serial line also carries `tool=<reason>` or `tool=-` |
| `EVILTWIN:<bssid>:<reason>:<rssi>:<ssid>` | twin reason | `SELF_CLONE`, `SELF_CLONE_OPEN`, `SSID_COLLISION`, `TWIN_MULTICH`, `TSF_RESTART` |
| `PROBE_FLOOD:<kind>:<what>:<rssi>` | flood kind | `RANDOMIZED`, `SINGLE_MAC`, `MARAUDER` (probe-request template seq=0x0001, fires on one frame) |
| `PROBE_FLOOD_BEHAVE:<ssid>:src=<n>:<rssi>` / `PROBE_FLOOD_AP:...` | - | - |
| `FRAG:<src>:<reason>` | CVE shape | `PN_GAP` (CVE-2020-26146), `MIXED_PLAIN` (CVE-2020-26147) |
| `HSHK:<bssid>:<sta>:<msg>:<replay>:<rssi>` | usable pair | `M1M2` (challenge), `M1M4`, `M2M3`, `M3M4` (authorized) |
| `PMKID_HARVEST:<src>:<bssid>:<rssi>` | tool | serial adds `tool=HCXDUMPTOOL` when the M1 replay counter is in `[0xF000,0xFFFE]` |
| `PMKID_FORGE:<src>:<bssid>:<rssi>` / `PMKID_FORGE:<src>:FAKE_M1:<rssi>` | forge kind | `FORGE_PMKID` (Marauder `BAD_MSG`, fixed PMKID `11 22 … ff 11`), `FAKE_M1` (zero ANonce; serial tag `ROGUE_M1`) |
| `EAPOL_BAIT:<src>:<sta>:<count>:<rssi>:<confidence>` | confidence | `high` (deauth carried a `DEAUTH_FORGE` tool fingerprint **and** EAPOL followed ≤2 s), `medium` (fingerprinted deauth >2 s, or unfingerprinted deauth with EAPOL ≤1 s). An unfingerprinted deauth followed by EAPOL after >1 s is a normal reassociation and does **not** alert |
| `CSA_SPOOF:<bssid>:<switch_count>` | count | fires at `switch_count ≥ 50`; Marauder hardcodes 255 |
| `QUIET_ABUSE:<bssid>:<duration_tu>` | duration | fires at `≥ 1000` TU; Marauder uses 0xFFFF |
| `KARMA_CAND:<bssid>:<distinct_ssids>` / `KARMA_CONFIRMED:<bssid>:<rssi>` | - | candidate at ≥2 distinct SSIDs on one BSSID / 60 s |
| `AUTH_FLOOD:<bssid>:<distinct_src>:<frames>` | - | open-system (algo 0) only; SAE is `SAE_DOS` |
| `SAE_DOS:<bssid>:<unmatched_commits>` | - | - |
| `JAMMING:<ch>:<pdr_pct>:<err_frames>:<noise_floor_dbm>` | - | per-channel, 1 s window, 60 s cooldown. Fires at `pdr < 30%` with `≥15` error frames whose mean RSSI is `> -70` dBm on a channel that carried a valid frame in the last 30 s. `noise_floor_dbm` is the mean `rx_ctrl.noise_floor` over every frame seen on that channel in the window, `0` when no frame reported one. `/jamming.jsonl` additionally carries `err_snr` = mean error-frame RSSI minus noise floor |
| `ASSOC_SLEEP`, `SSID_CONFUSION`, `OWE_ABUSE`, `PWNAGOTCHI`, `RECON`, `ATTACKER_HUNT` | - | single-reason detectors |

**`R:` deauth/disassoc reason codes** (IEEE 802.11-2020 Table 9-49). The value is reported
as context only - since `c0d710d` the reason code is **not** used to decide whether a frame
is an attack, because 1/2/6/7 are all normal causes. Codes seen in practice:

| Code | Meaning | Typical source |
|---|---|---|
| 1 | Unspecified reason | esp8266_deauther template; generic tools |
| 2 | Previous authentication no longer valid | **Marauder / Bruce / Evil-M5 template** (with `seq=0xFFF0`, `dur=0x013A`) |
| 3 | Deauthenticated, STA leaving | normal client roam/disconnect |
| 4 | Disassociated due to inactivity | normal AP housekeeping |
| 5 | Disassociated, AP out of resources | normal AP under load |
| 6 | Class 2 frame from non-authenticated STA | bettercap; also normal |
| 7 | Class 3 frame from non-associated STA | aireplay-ng (with `dur=0x013A`), GhostESP; also normal AP behavior |
| 8 | STA leaving BSS | normal |
| 14 | Michael MIC failure (TKIP) | `MICHAEL_TKIP` forge tag |

Any other value is passed through verbatim as `Reason code N`.

</details>

---
