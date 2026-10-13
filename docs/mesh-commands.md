# Mesh Commands

[README](../README.md)

Send `@<NODE> CMD` or `@ALL CMD`. Node ID: 2-5 chars, A-Z 0-9. `secs`: 0-86400. `mode`: `0` Wi-Fi, `1` BLE, `2` both. `FOREVER`: run until `STOP`.

### Core

| Command | Args | Reply | Example |
|---|---|---|---|
| `STATUS` | | `STATUS:` then `STATUS_BOOT:` | `@ALL STATUS` |
| `STOP` | | | `@ALL STOP` |
| `MESH_TX_CANCEL` | | `MESH_TX_CANCEL_ACK` | `@ALL MESH_TX_CANCEL` |

### Config

| Command | Args | Reply | Example |
|---|---|---|---|
| `CONFIG_TARGETS` | MACs, OUIs, SSIDs, `T-xxxx`, `\|`-separated | `CONFIG_ACK:TARGETS:OK` | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33` |
| `CONFIG_NODEID` | 2-5 A-Z 0-9 | `CONFIG_ACK:NODE_ID:OK\|INVALID_CHARS\|INVALID_LENGTH` | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | -128..-10 | `CONFIG_ACK:RSSI:OK\|INVALID_RANGE` | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | `1,6,11` or `1..11` | `CONFIG_ACK:CHANNELS:<list>` | `@ALL CONFIG_CHANNELS:1..11` |
| `CONFIG_DEDUP_TTL` | secs 0-3600, 0 off | `CONFIG_ACK:DEDUP_TTL:<n>\|INVALID` | `@ALL CONFIG_DEDUP_TTL:300` |
| `CONFIG_SESSION_DEDUP` | `0\|1` | `CONFIG_ACK:SESSION_DEDUP:<n>` | `@ALL CONFIG_SESSION_DEDUP:1` |
| `MESH_DEDUP_CLEAR` | | `DEDUP_CLEAR_ACK:OK` | `@ALL MESH_DEDUP_CLEAR` |
| `BLE_CLASSIFY` | `0\|1` | `CONFIG_ACK:BLE_CLASSIFY:<n>` | `@ALL BLE_CLASSIFY:0` |
| `CAMPAIGN_START` | name, A-Z a-z 0-9 `-` `_`, max 23 | `CAMPAIGN_ACK:START:<name>\|INVALID` | `@ALL CAMPAIGN_START:site-a` |
| `CAMPAIGN_STOP` | | `CAMPAIGN_ACK:STOP:<name>\|NONE` | `@ALL CAMPAIGN_STOP` |
| `CAMPAIGN_STATUS` | | `CAMPAIGN_STATUS:<name>\|NONE` | `@AH01 CAMPAIGN_STATUS` |

### Scan

| Command | Args | Reply | Example |
|---|---|---|---|
| `SCAN_START` | `mode:secs:channels[:FOREVER]` | `SCAN_ACK:STARTED\|BUSY\|FAILED` | `@ALL SCAN_START:2:300:1..11` |
| `DEVICE_SCAN_START` | `mode:secs[:FOREVER][:+PROBE][:CH<list>]` | `DEVICE_SCAN_ACK:STARTED\|BUSY\|FAILED` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | `secs[:FOREVER]`, min 60 | `BASELINE_ACK:STARTED\|BUSY\|FAILED` | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | | | `@ALL BASELINE_STATUS` |
| `BASELINE_WATCH` | | `BASELINE_ACK:WATCHING\|NOT_RUNNING` | `@ALL BASELINE_WATCH` |
| `DRONE_START` | `secs[:FOREVER]` | `DRONE_ACK:STARTED\|BUSY\|FAILED` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `secs[:FOREVER]` | `DEAUTH_ACK:STARTED\|BUSY\|FAILED` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `mode:secs[:FOREVER]` | `RANDOMIZATION_ACK:STARTED\|BUSY\|FAILED` | `@ALL RANDOMIZATION_START:2:300` |
| `PROBE_START` | `mode:secs[:FOREVER][:+ALL]` | `PROBE_ACK:...` | `@ALL PROBE_START:2:300:+ALL` |
| `PROBE_STOP` | | | `@ALL PROBE_STOP` |
| `PCAP_START` | `radio:secs:band[:FOREVER][:CH<list>]`, band `0` 2.4, `1` 5, `2` both | `PCAP_ACK:...` | `@ALL PCAP_START:0:300:0:CH1,6,11` |
| `PCAP_STOP` | | | `@ALL PCAP_STOP` |
| `PCAP_LIMITS` | `[MB]` 8-300 | `PCAP_LIMITS_ACK:MAXFILE=<n>MB\|INVALID` | `@ALL PCAP_LIMITS:150` |
| `PCAP_AUTO` | `[budgetMB,floorMB]` | `PCAP_AUTO_ACK:BUDGET=...\|INVALID` | `@AH01 PCAP_AUTO:512,64` |
| `PCAP_DELETE_ALL` | | count | `@AH01 PCAP_DELETE_ALL` |
| `SD_REPAIR` | `ON\|OFF\|NOW`, NOW erases the card | `SD_REPAIR_ACK:ON\|OFF\|REPAIRED\|FAILED` | `@ALL SD_REPAIR:ON` |
| `SCHED_ADD` | `YYYY-MM-DDTHH:MM\|repeat\|scan\|options`; repeat `0` or 600+; scan `/scan` `/sniffer` `/drone` | `SCHED_ACK:OK\|ERR <msg>\|INVALID` | `@ALL SCHED_ADD:2026-09-30T02:00\|86400\|/scan\|mode=2&secs=600` |
| `SCHED_LIST` | | count, entries on serial | `@AH01 SCHED_LIST` |
| `SCHED_DEL` | `n` from `SCHED_LIST` | `SCHED_ACK:DELETED\|NOT_FOUND` | `@AH01 SCHED_DEL:1` |

### Triangulation

| Command | Args | Example |
|---|---|---|
| `TRIANGULATE_START` | `MAC:secs[:rfEnv[:wifiPwr:blePwr]]` | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.0:1.0` |
| `TRIANGULATE_STOP` | | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | | `@AH01 TRIANGULATE_RESULTS` |

### Security

| Command | Args | Reply | Example |
|---|---|---|---|
| `ERASE_REQUEST` | | `ERASE_TOKEN:<token> Expires:300s\|RATE_LIMITED` | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | `key` | | `@AH02 ERASE_FORCE:<key>` |
| `ERASE_CANCEL` | `key` | | `@AH01 ERASE_CANCEL:<key>` |
| `AUTOERASE_ENABLE` | `setup:erase:vibs:window:cooldown:key`, secs | `AUTOERASE_ACK:...\|DENIED` | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300:<key>` |
| `AUTOERASE_DISABLE` | `key` | | `@AH01 AUTOERASE_DISABLE:<key>` |
| `AUTOERASE_STATUS` | | | `@AH01 AUTOERASE_STATUS` |
| `CONFIG_ERASE_PSK` | `new:current`, 8+ chars, no `:` | `SET\|DENIED\|INVALID` | `@AH01 CONFIG_ERASE_PSK:myS3cretKey:<current>` |
| `FACTORY_RESET` | `FULL\|CONFIG\|DATA:key` | `FACTORY_RESET_ACK:<tier>\|DENIED\|BAD_TIER\|BUSY` | `@AH01 FACTORY_RESET:FULL:<key>` |
| `VIBRATION_ON` / `VIBRATION_OFF` | | | `@AH01 VIBRATION_ON` |
| `VIBRATION_STATUS` | | | `@AH01 VIBRATION_STATUS` |
| `VIBSCAN_SET` | `en:mode:dur[:cooldown[:interrupt]]` | `VIBSCAN_ACK:...\|INVALID\|INVALID_MODE` | `@AH01 VIBSCAN_SET:1:2:60:300` |
| `VIBSCAN_STATUS` | | | `@AH01 VIBSCAN_STATUS` |

Erase key unset: `ERASE_ACK:SET_KEY_FIRST`. 5 bad keys: 10 min lockout.
`VIBSCAN_SET` mode: `0` off, `1` device, `2` probe, `3` rand-MAC, `4` list, `5` drone, `6` deauth, `7` baseline, `8` pcap. `dur` 0 = until stopped. `cooldown` 5-86400. `interrupt` `1` preempts a scheduled scan.

### Power

| Command | Args | Reply | Example |
|---|---|---|---|
| `BATTERY_SAVER_START` | `[min]` 1-30 | `BATTERY_SAVER_ACK:STARTED Interval:<n>min` | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | | | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | | | `@AH01 BATTERY_SAVER_STATUS` |
| `HB_ON` / `HB_OFF` | | | `@AH01 HB_ON` |
| `HB_INTERVAL` | `min` 1-60 | `HB_ACK:INTERVAL <n>min` | `@AH01 HB_INTERVAL:10` |

### Sentinel (Beta, C5)

| Command | Args | Example |
|---|---|---|
| `SENTINEL_ON` / `SENTINEL_OFF` | | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | `defend\|scan` | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | `0\|1` | `@ALL SENTINEL_BOOT:1` |
| `GROUP` | `name:on\|off` | `@ALL GROUP:dos:on` |
| `DETECT_CFG` | `json`, max 180 chars | `@AH01 DETECT_CFG:{"pmkid":true}` |
| `DETECT_CFG_GET` | | `@AH01 DETECT_CFG_GET` |
| `INCIDENTS` | `[:1-200]` | `@AH01 INCIDENTS:50` |
| `INCIDENTS_CLEAR` | | `@ALL INCIDENTS_CLEAR` |
| `ATTACKER_TRILAT` | `0\|1\|on\|off` | `@ALL ATTACKER_TRILAT:1` |
| `ATTACKER_TRILAT_STATUS` | | `@AH01 ATTACKER_TRILAT_STATUS` |
| `DETECT_JSON` | `karma\|pg\|tsf\|hshk\|pwna\|tof\|hunts\|pcap\|pcaps` | `@AH01 DETECT_JSON:pwna` |
| `DETECT_CLEAR` | same | `@AH01 DETECT_CLEAR:tsf` |
| `DETECT_COUNTS` | | `@AH01 DETECT_COUNTS` |
| `DETECT_VERBOSE` | `ON\|OFF` | `@AH01 DETECT_VERBOSE:ON` |
| `QUORUM` | `type,n` | `@ALL QUORUM:PMKID,2` |
| `KARMA_ON` / `KARMA_OFF` | transmits bait probes | `@AH01 KARMA_ON` |
| `HUNT_COOLDOWN` | ms | `@ALL HUNT_COOLDOWN:60000` |
| `TOF_PING` | `[:node]` | `@AH01 TOF_PING:AH02` |
| `ATTACK_RESPONSE_CANCEL` | | `@ALL ATTACK_RESPONSE_CANCEL` |

`GROUP`: `dos` eviltwin,sae,assoc_sleep · `rogue` eviltwin,owe,karma · `recon` pmkid,probe_flood,hshk · `physical` frag,tsf,jam · `mesh` mesh_guard · `all`.
Headless: use `SENTINEL_MODE:scan`.

### CSI Motion (Beta, C5)

| Command | Args | Example |
|---|---|---|
| `CSI_MOTION_START` | `secs[:FOREVER][:CH<n>][:TELEM][:RAW][:GAP<s>][:LISTEN_ONLY\|ALLOW_TRANSMIT][:MGMTONLY\|MGMTDATA][:SOLICIT<ms>]` | `@ALL CSI_MOTION_START:600:GAP60` |
| `CSI_CFG` | `SENSITIVITY=LOW\|MEDIUM\|HIGH\|n` `MIN_MOTION=s` `CLEAR_AFTER=s` `SPOTS=n` `BROADCAST=ON\|OFF` `ALLOW_RANDOM=ON\|OFF` `CH=n`, `:`-joined | `@ALL CSI_CFG:SENSITIVITY=LOW:BROADCAST=OFF` |
| `CSI_EXCLUDE` | `MAC\|NONE` | `@AH01 CSI_EXCLUDE:NONE` |
| `CSI_STATUS` | | `@AH01 CSI_STATUS` |
| `CSI_JSON` | | `@AH01 CSI_JSON` |
| `CSI_RECAL` | | `@ALL CSI_RECAL` |

Nodes exchange `CSI_PEER:<AP MAC>` and skip each other's MACs.

### Branch-only

| Command | Build | Args | Example |
|---|---|---|---|
| `DEVICE_DB_CLEAR` | headless, Beta, C5 | | `@AH01 DEVICE_DB_CLEAR` |
| `CONFIG_BAND` | C5 | `0` 2.4, `1` 5, `2` both | `@AH01 CONFIG_BAND:2` |

### Alerts

| Alert | Format |
|---|---|
| Target | `NODE: Target: MAC RSSI:N Type:WiFi\|BLE [Name:x] [GPS=lat,lon] [V=vendor] [C=class]` |
| Anomaly | `NODE: ANOMALY-NEW: TYPE MAC RSSI:N [Name:x]` · `ANOMALY-RETURN: TYPE MAC RSSI:NdBm [Name:x]` · `ANOMALY-RSSI: TYPE MAC Old:NdBm New:NdBm Delta:NdBm` · `ANOMALY: TYPE MAC RSSI:N reason [N:x] [C=class]` |
| Deauth | `NODE: ATTACK: DEAUTH\|DISASSOC [BROADCAST\|TARGETED] SRC:MAC DST:MAC RSSI:dBm CH:N R:reason [GPS:lat,lon]` |
| Drone | `NODE: DRONE: MAC ID:uavId R-dBm [GPS:lat,lon] [ALT:m] [SPD:m/s] [OP:lat,lon]` |
| Drone lost | `NODE: DRONE_LOST: MAC [ID:uavId] AGE:secs` |
| Tri data | `NODE: T_D: MAC Hits=N RSSI:N [GPS=lat,lon HDOP=x]` |
| Tri final | `NODE: T_F: MAC=addr GPS=lat,lon CONF=x UNC=x` |
| Tri done | `NODE: T_C: MAC=addr Nodes=N [GPS=lat,lon CONF=pct URL=link]` |
| Tri cycle | `@ALL TRI_CYCLE_START:<ms>:<node,...>` (firmware-sent) |
| Probe hit | `NODE: PROBE_HIT MAC [Randomized\|Vendor] RSSI=dBm CH=N [SSID="x" [GHOST]] [DST]` |
| PCAP | `NODE: PCAP_START: WIFI\|BLE D=secs` · `PCAP_DONE: F=frames B=bytes D=dropped` |
| Tamper | `NODE: TAMPER_DETECTED: Auto-erase in Xs [GPS:lat,lon]` |
| Status | `NODE: STATUS: Mode:TYPE Scan:ACTIVE\|IDLE Hits:N Temp:XX.XC Up:HH:MM:SS [Camp:name] [GPS:lat,lon HDOP=x]` |
| Heartbeat | `NODE: Time:YYYY-MM-DD_HH:MM:SS Temp:XX.XC [GPS:lat,lon]` · saver: `NODE: HEARTBEAT: Temp:XXC GPS:lat,lon Battery:SAVER` |

<details>
<summary>Sentinel labels</summary>

| Prefix | Values |
|---|---|
| `DEAUTH_FORGE:<src>:<tool>:<rssi>` | `MARAUDER` `MICHAEL_TKIP` `MDK4` `ESP_DEAUTHER` `AIREPLAY` `BETTERCAP` |
| `DEAUTH_FLOOD:<src>:<count>:<rssi>` | |
| `DEAUTH_AP_TARGETED:<client>:<reason>:<count>` | |
| `BEACON_FORGE:<bssid>:<reason>:<rssi>` | `FORGE_TSF_STATIC` `FORGE_BI_1000` `FORGE_SRC_MCAST` `FORGE_CSA_FF` `FORGE_QUIET_ELEM` `FORGE_SSID_ROTATE` `FORGE_EVIL_PORTAL` `FORGE_EVIL_PORTAL_ESP` `FORGE_KARMA_BRUCE` |
| `BEACON_FLOOD:<rssi>` | |
| `EVILTWIN:<bssid>:<reason>:<rssi>:<ssid>` | `SELF_CLONE` `SELF_CLONE_OPEN` `SSID_COLLISION` `TWIN_MULTICH` `TSF_RESTART` |
| `PROBE_FLOOD:<kind>:<what>:<rssi>` | `RANDOMIZED` `SINGLE_MAC` `MARAUDER` |
| `PROBE_FLOOD_BEHAVE:<ssid>:src=<n>:<rssi>` · `PROBE_FLOOD_AP:...` | |
| `FRAG:<src>:<reason>` | `PN_GAP` `MIXED_PLAIN` |
| `HSHK:<bssid>:<sta>:<msg>:<replay>:<rssi>` | `M1M2` `M1M4` `M2M3` `M3M4` |
| `PMKID_HARVEST:<src>:<bssid>:<rssi>` | |
| `PMKID_FORGE:<src>:<bssid>:<rssi>` · `PMKID_FORGE:<src>:FAKE_M1:<rssi>` | `FORGE_PMKID` `FAKE_M1` |
| `EAPOL_BAIT:<src>:<sta>:<count>:<rssi>:<conf>` | `high` `medium` |
| `CSA_SPOOF:<bssid>:<count>` | count >= 50 |
| `QUIET_ABUSE:<bssid>:<tu>` | tu >= 1000 |
| `KARMA_CAND:<bssid>:<ssids>` · `KARMA_CONFIRMED:<bssid>:<rssi>` | |
| `AUTH_FLOOD:<bssid>:<srcs>:<frames>` | |
| `SAE_DOS:<bssid>:<commits>` | |
| `JAMMING:<ch>:<pdr_pct>:<err_frames>:<noise_dbm>` | |
| `ASSOC_SLEEP` `SSID_CONFUSION` `OWE_ABUSE` `PWNAGOTCHI` `RECON` `ATTACKER_HUNT` | |

`R:` reason codes (802.11-2020 Table 9-49): `1` unspecified · `2` prev auth invalid · `3` STA leaving · `4` inactivity · `5` AP full · `6` class 2 from unauth STA · `7` class 3 from unassoc STA · `8` leaving BSS · `14` MIC failure.

</details>
