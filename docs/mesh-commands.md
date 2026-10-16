# Mesh Commands

[README](../README.md)

Send `@<NODE> CMD` or `@ALL CMD`. Node ID: 2-5 chars, A-Z 0-9. `secs`: 0-86400. `mode`: `0` Wi-Fi, `1` BLE, `2` both. `FOREVER`: run until `STOP`.

Commands are case-insensitive and accept the alias in the Alias column, e.g. `@AH01 ts:AA:BB:CC:DD:EE:FF:60` = `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60`; aliases work only on `@`-addressed lines.

### Core

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `STATUS` | `ST` | | `STATUS:` | `@ALL STATUS` |
| `SUMMARY` | `SUM` | | `SUMMARY:` | `@ALL SUMMARY` |
| `STOP` | `X` | | | `@ALL STOP` |
| `MESH_TX_CANCEL` | `MTC` | | `MESH_TX_CANCEL_ACK` | `@ALL MESH_TX_CANCEL` |

### Config

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `CONFIG_TARGETS` | `CT` | MACs, OUIs, SSIDs, `T-xxxx`, `\|`-separated | `CONFIG_ACK:TARGETS:OK` | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33` |
| `CONFIG_NODEID` | `CN` | 2-5 A-Z 0-9 | `CONFIG_ACK:NODE_ID:OK\|INVALID_CHARS\|INVALID_LENGTH` | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | `CR` | -128..-10 | `CONFIG_ACK:RSSI:OK\|INVALID_RANGE` | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | `CC` | `1,6,11` or `1..11` | `CONFIG_ACK:CHANNELS:<list>` | `@ALL CONFIG_CHANNELS:1..11` |
| `CONFIG_DEDUP_TTL` | `CDT` | secs 0-3600, 0 off | `CONFIG_ACK:DEDUP_TTL:<n>\|INVALID` | `@ALL CONFIG_DEDUP_TTL:300` |
| `CONFIG_SESSION_DEDUP` | `CSD` | `0\|1` | `CONFIG_ACK:SESSION_DEDUP:<n>` | `@ALL CONFIG_SESSION_DEDUP:1` |
| `MESH_DEDUP_CLEAR` | `MDC` | | `DEDUP_CLEAR_ACK:OK` | `@ALL MESH_DEDUP_CLEAR` |
| `BLE_CLASSIFY` | `BC` | `0\|1` | `CONFIG_ACK:BLE_CLASSIFY:<n>` | `@ALL BLE_CLASSIFY:0` |
| `CAMPAIGN_START` | `CS` | name, A-Z a-z 0-9 `-` `_`, max 23 | `CAMPAIGN_ACK:START:<name>\|INVALID` | `@ALL CAMPAIGN_START:site-a` |
| `CAMPAIGN_STOP` | `CX` | | `CAMPAIGN_ACK:STOP:<name>\|NONE` | `@ALL CAMPAIGN_STOP` |
| `CAMPAIGN_STATUS` | `CQ` | | `CAMPAIGN_STATUS:<name>\|NONE` | `@AH01 CAMPAIGN_STATUS` |

### Scan

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `SCAN_START` | `SS` | `mode:secs:channels[:FOREVER]` | `SCAN_ACK:STARTED\|BUSY\|FAILED` | `@ALL SCAN_START:2:300:1..11` |
| `DEVICE_SCAN_START` | `DS` | `mode:secs[:FOREVER][:+PROBE][:CH<list>]` | `DEVICE_SCAN_ACK:STARTED\|BUSY\|FAILED` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | `BLS` | `secs[:FOREVER]`, min 60 | `BASELINE_ACK:STARTED\|BUSY\|FAILED` | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | `BLQ` | | | `@ALL BASELINE_STATUS` |
| `BASELINE_WATCH` | `BLW` | | `BASELINE_ACK:WATCHING\|NOT_RUNNING` | `@ALL BASELINE_WATCH` |
| `DRONE_START` | `DR` | `secs[:FOREVER]` | `DRONE_ACK:STARTED\|BUSY\|FAILED` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `DA` | `secs[:FOREVER]` | `DEAUTH_ACK:STARTED\|BUSY\|FAILED` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `RS` | `mode:secs[:FOREVER]` | `RANDOMIZATION_ACK:STARTED\|BUSY\|FAILED` | `@ALL RANDOMIZATION_START:2:300` |
| `PROBE_START` | `PS` | `mode:secs[:FOREVER][:+ALL]` | `PROBE_ACK:...` | `@ALL PROBE_START:2:300:+ALL` |
| `PROBE_STOP` | `PX` | | | `@ALL PROBE_STOP` |
| `PCAP_START` | `PCS` | `radio:secs:band[:CH<list>]`, band `0` 2.4, `1` 5, `2` both; `secs` required, `0` and `FOREVER` are rejected | `PCAP_ACK:STARTED\|BUSY\|NOSD\|FAILED` | `@ALL PCAP_START:0:300:0:CH1,6,11` |
| `PCAP_STOP` | `PCX` | | | `@ALL PCAP_STOP` |
| `PCAP_LIMITS` | `PCL` | `[MB]` 8-300 | `PCAP_LIMITS_ACK:MAXFILE=<n>MB\|INVALID` | `@ALL PCAP_LIMITS:150` |
| `PCAP_AUTO` | `PCA` | `[budgetMB,floorMB]` | `PCAP_AUTO_ACK:BUDGET=...\|INVALID` | `@AH01 PCAP_AUTO:512,64` |
| `SD_REPAIR` | `SDR` | `ON\|OFF\|NOW`, NOW remounts the card and erases it only if every mount attempt fails | `SD_REPAIR_ACK:ON\|OFF\|REPAIRED\|FAILED` | `@ALL SD_REPAIR:ON` |
| `SCHED_ADD` | `SA` | `YYYY-MM-DDTHH:MM\|repeat\|scan\|options`; repeat `0` or 600+; scan `/scan` `/sniffer` `/drone` | `SCHED_ACK:OK\|ERR <msg>\|INVALID` | `@ALL SCHED_ADD:2026-09-30T02:00\|86400\|/scan\|mode=2&secs=600` |
| `SCHED_LIST` | `SL` | | count, entries on serial | `@AH01 SCHED_LIST` |
| `SCHED_DEL` | `SD` | `n` from `SCHED_LIST` | `SCHED_ACK:DELETED\|NOT_FOUND` | `@AH01 SCHED_DEL:1` |

### Triangulation

| Command | Alias | Args | Example |
|---|---|---|---|
| `TRIANGULATE_START` | `TS` | `MAC:secs[:rfEnv[:wifiPwr:blePwr]]` | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.0:1.0` |
| `TRIANGULATE_STOP` | `TX` | | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | `TR` | | `@AH01 TRIANGULATE_RESULTS` |

### Security

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `ERASE_REQUEST` | `ER` | | `ERASE_TOKEN:<token> Expires:300s\|RATE_LIMITED` | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | `EF` | `answer` | `ERASE_ACK:COMPLETE\|FAILED\|BUSY\|DENIED` | `@AH02 ERASE_FORCE:<answer>` |
| `ERASE_CANCEL` | `EC` | `answer` | `ERASE_ACK:CANCELED\|DENIED` | `@AH01 ERASE_CANCEL:<answer>` |
| `AUTOERASE_ENABLE` | `AE1` | `setup:erase:vibs:window:cooldown:answer`, secs | `AUTOERASE_ACK:...\|DENIED` | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300:<answer>` |
| `AUTOERASE_DISABLE` | `AE0` | `answer` | | `@AH01 AUTOERASE_DISABLE:<answer>` |
| `AUTOERASE_STATUS` | `AEQ` | | | `@AH01 AUTOERASE_STATUS` |
| `CONFIG_ERASE_PSK` | `CEP` | `new:current`, 8-64 chars, no `:` | `CONFIG_ACK:ERASE_PSK:SET\|DENIED\|INVALID` | `@AH01 CONFIG_ERASE_PSK:myS3cretKey:<current>` |
| `FACTORY_RESET` | `FR` | `FULL\|CONFIG\|DATA:answer` | `FACTORY_RESET_ACK:<tier>\|DENIED\|BAD_TIER\|BUSY` | `@AH01 FACTORY_RESET:FULL:<answer>` |
| `VIBRATION_ON` / `VIBRATION_OFF` | `V1` / `V0` | | | `@AH01 VIBRATION_ON` |
| `VIBRATION_STATUS` | `VQ` | | | `@AH01 VIBRATION_STATUS` |
| `VIBSCAN_SET` | `VSS` | `en:mode:dur[:cooldown[:interrupt]]` | `VIBSCAN_ACK:...\|INVALID\|INVALID_MODE` | `@AH01 VIBSCAN_SET:1:2:60:300` |
| `VIBSCAN_STATUS` | `VSQ` | | | `@AH01 VIBSCAN_STATUS` |

`answer`: send `ERASE_REQUEST`, then the first 8 (or all 64) hex characters of HMAC-SHA256 of the returned token, keyed with the erase key: `printf %s '<token>' | openssl dgst -sha256 -hmac '<key>'`. Each token takes one attempt and expires after 300 s. Mesh erase commands refuse the key itself. `CONFIG_ERASE_PSK` takes the current key.
Erase key unset: `ERASE_ACK:SET_KEY_FIRST`. 5 bad keys or answers: 10 min lockout. Keys and answers are logged as `***`.
`VIBSCAN_SET` mode: `0` off, `1` device, `2` probe, `3` rand-MAC, `4` list, `5` drone, `6` deauth, `7` baseline, `8` pcap. `dur` 0 = until stopped, except mode `8` (pcap), which needs `dur` > 0 and replies `INVALID` otherwise. `cooldown` 5-86400. `interrupt` `1` preempts a scheduled scan; that scan resumes after if 10 s or more were left. Reply ends `Pre:0|1`.

### Power

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `BATTERY_SAVER_START` | `BSS` | `[min]` 1-30 | `BATTERY_SAVER_ACK:STARTED Interval:<n>min` | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | `BSX` | | | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | `BSQ` | | | `@AH01 BATTERY_SAVER_STATUS` |
| `HB_ON` / `HB_OFF` | `HB1` / `HB0` | | | `@AH01 HB_ON` |
| `HB_INTERVAL` | `HBI` | `min` 1-60 | `HB_ACK:INTERVAL <n>min` | `@AH01 HB_INTERVAL:10` |

### Sentinel

| Command | Alias | Args | Example |
|---|---|---|---|
| `SENTINEL_ON` / `SENTINEL_OFF` | `SE1` / `SE0` | | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | `SEQ` | | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | `SEM` | `defend\|scan` | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | `SEB` | `0\|1` | `@ALL SENTINEL_BOOT:1` |
| `GROUP` | `GR` | `name:on\|off` | `@ALL GROUP:dos:on` |
| `DETECT_CFG` | `DC` | `json`, max 180 chars | `@AH01 DETECT_CFG:{"pmkid":true}` |
| `DETECT_CFG_GET` | `DCG` | | `@AH01 DETECT_CFG_GET` |
| `INCIDENTS` | `IN` | `[:1-200]` | `@AH01 INCIDENTS:50` |
| `INCIDENTS_CLEAR` | `INX` | | `@ALL INCIDENTS_CLEAR` |
| `ATTACKER_TRILAT` | `AT` | `0\|1\|on\|off` | `@ALL ATTACKER_TRILAT:1` |
| `ATTACKER_TRILAT_STATUS` | `ATQ` | | `@AH01 ATTACKER_TRILAT_STATUS` |
| `DETECT_COUNTS` | `DCN` | | `@AH01 DETECT_COUNTS` |

`GROUP`: `dos` eviltwin,sae,assoc_sleep · `rogue` eviltwin,owe,karma · `recon` pmkid,probe_flood,hshk · `physical` frag,tsf,jam · `mesh` mesh_guard · `all`.
Headless: use `SENTINEL_MODE:scan`.

### CSI Motion (Beta, C5)

| Command | Alias | Args | Example |
|---|---|---|---|
| `CSI_MOTION_START` | `CIM` | `secs[:FOREVER][:CH<n>][:TELEM][:RAW][:GAP<s>][:LISTEN_ONLY\|ALLOW_TRANSMIT][:MGMTONLY\|MGMTDATA][:SOLICIT<ms>]` | `@ALL CSI_MOTION_START:600:GAP60` |
| `CSI_CFG` | `CIC` | `SENSITIVITY=LOW\|MEDIUM\|HIGH\|n` `MIN_MOTION=s` `CLEAR_AFTER=s` `SPOTS=n` `BROADCAST=ON\|OFF` `ALLOW_RANDOM=ON\|OFF` `CH=n`, `:`-joined | `@ALL CSI_CFG:SENSITIVITY=LOW:BROADCAST=OFF` |
| `CSI_EXCLUDE` | `CIE` | `MAC\|NONE` | `@AH01 CSI_EXCLUDE:NONE` |
| `CSI_STATUS` | `CIQ` | | `@AH01 CSI_STATUS` |
| `CSI_JSON` | `CIJ` | | `@AH01 CSI_JSON` |
| `CSI_RECAL` | `CIR` | | `@ALL CSI_RECAL` |

Nodes exchange `CSI_PEER:<AP MAC>` and skip each other's MACs.

### Branch-only

| Command | Alias | Build | Args | Example |
|---|---|---|---|---|
| `DEVICE_DB_CLEAR` | `DBX` | Beta and C5 headless | | `@AH01 DEVICE_DB_CLEAR` |
| `CONFIG_BAND` | `CB` | C5 | `0` 2.4, `1` 5, `2` both | `@AH01 CONFIG_BAND:2` |

### Alerts

| Alert | Format |
|---|---|
| Target | `NODE: Target: MAC RSSI:N Type:WiFi\|BLE [Name:x] [GPS=lat,lon] [V=vendor] [C=class]` |
| Device | first row `NODE: DEVICE:AA:BB:CC:DD:EE:FF W\|B RSSI [C<ch>] [N:name]`, next rows in the same message `AABBCCDDEEFF W\|B RSSI [C<ch>] [N:name]`, one per line; `C` Wi-Fi only, name max 30 chars |
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
| Summary | `NODE: SUMMARY: Mode:TYPE Scan:ACTIVE\|IDLE Dev:N Tgt:N Hits:N [Inc:N] [Camp:name] Up:HH:MM:SS` |
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
