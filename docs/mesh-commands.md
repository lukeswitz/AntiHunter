# Mesh Commands

[Back](../README.md)

### How to send a command

Send a Meshtastic text message: `@AH01 COMMAND` for one node, `@ALL COMMAND` for every node. Arguments follow the command after `:`, as in `@AH01 INCIDENTS:50`.

- Node ID: 2-5 characters, A-Z and 0-9.
- Commands are case-insensitive. The Alias column gives a short form: `@AH01 TS:...` is `TRIANGULATE_START:...`.
- A line without `@<NODE>` or `@ALL` at the start is ignored. A misspelled command is ignored with no reply: `@AH01 INCIDENTSX` does nothing.

Arguments used by many commands:

| Argument | Meaning |
|---|---|
| `mode` | Radio: `0` Wi-Fi, `1` BLE, `2` both |
| `secs` | Run time in seconds, 0-86400 |
| `FOREVER` | Add `:FOREVER` to run until `STOP` |
| `CH<list>` | Channels, e.g. `CH1,6,11` |

## Commands

### Core

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `STATUS` | `ST` | | `STATUS:` | `@ALL STATUS` |
| `SUMMARY` | `SUM` | | `SUMMARY:` | `@ALL SUMMARY` |
| `STOP` | `X` | | `STOP_ACK:OK` | `@ALL STOP` |
| `MESH_TX_CANCEL` | `MTC` | | `MESH_TX_CANCEL_ACK`, `MESH_TX_CANCEL_ACK:EMPTY` if nothing is queued | `@ALL MESH_TX_CANCEL` |

`STOP` stops every running scan. `MESH_TX_CANCEL` drops the queued mesh messages and leaves the scan running.

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
| `SCAN_START` | `SS` | `mode:secs:channels[:FOREVER]` | `SCAN_ACK:STARTED\|BUSY\|FAILED\|INVALID` | `@ALL SCAN_START:2:300:1..11` |
| `DEVICE_SCAN_START` | `DS` | `mode:secs[:FOREVER][:+PROBE][:CH<list>]` | `DEVICE_SCAN_ACK:STARTED\|BUSY\|FAILED\|INVALID` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | `BLS` | `secs[:FOREVER]`, min 60 | `BASELINE_ACK:STARTED\|BUSY\|FAILED` | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | `BLQ` | | `BASELINE_STATUS: Scanning:.. Established:.. Devices:<n> Anomalies:<n> Phase1:..` | `@ALL BASELINE_STATUS` |
| `BASELINE_WATCH` | `BLW` | | `BASELINE_ACK:WATCHING\|NOT_RUNNING` | `@ALL BASELINE_WATCH` |
| `DRONE_START` | `DR` | `secs[:FOREVER]` | `DRONE_ACK:STARTED\|BUSY\|FAILED` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `DA` | `secs[:FOREVER]` | `DEAUTH_ACK:STARTED\|BUSY\|FAILED` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `RS` | `mode:secs[:FOREVER]` | `RANDOMIZATION_ACK:STARTED\|BUSY\|FAILED\|INVALID` | `@ALL RANDOMIZATION_START:2:300` |
| `PROBE_START` | `PS` | `mode:secs[:FOREVER][:+ALL]` | `PROBE_ACK:STARTED\|BUSY\|FAILED\|INVALID` | `@ALL PROBE_START:2:300:+ALL` |
| `PROBE_STOP` | `PX` | | `PROBE_ACK:STOPPED` | `@ALL PROBE_STOP` |
| `PCAP_START` | `PCS` | `radio:secs:band[:CH<list>]` | `PCAP_ACK:STARTED\|BUSY\|NOSD\|FAILED` | `@ALL PCAP_START:0:300:0:CH1,6,11` |
| `PCAP_STOP` | `PCX` | | `PCAP_STOP_ACK:OK` | `@ALL PCAP_STOP` |
| `PCAP_LIMITS` | `PCL` | `[MB]` 8-300 | `PCAP_LIMITS_ACK:MAXFILE=<n>MB\|INVALID` | `@ALL PCAP_LIMITS:150` |
| `PCAP_AUTO` | `PCA` | `[budgetMB,floorMB]` | `PCAP_AUTO_ACK:BUDGET=<n>MB FLOOR=<n>MB\|INVALID` | `@AH01 PCAP_AUTO:512,64` |
| `SD_REPAIR` | `SDR` | `ON\|OFF\|NOW` | `SD_REPAIR_ACK:ON\|OFF\|REPAIRED\|FAILED` | `@ALL SD_REPAIR:ON` |
| `SCHED_ADD` | `SA` | `start\|repeat\|scan\|options` | `SCHED_ACK:OK\|ERR <msg>\|INVALID` | `@ALL SCHED_ADD:2026-09-30T02:00\|86400\|/scan\|mode=2&secs=600` |
| `SCHED_LIST` | `SL` | | `SCHED_LIST:<count>`, entries on serial | `@AH01 SCHED_LIST` |
| `SCHED_DEL` | `SD` | `n` from `SCHED_LIST` | `SCHED_ACK:DELETED\|NOT_FOUND` | `@AH01 SCHED_DEL:1` |

- With `+PROBE`, device discovery also collects probe requests. With `+ALL`, the probe scanner sends every probe to the mesh, not only watchlist hits.
- `BASELINE_START` `secs` is the monitor time after the learning phase. The learning time is set in the web UI.
- `PCAP_START`: `radio` is `0` for Wi-Fi or `1` for BLE. `band` is `0` for 2.4 GHz, `1` for 5 GHz or `2` for both, and 5 GHz works only on the C5. You must give `secs`; the node rejects `0` and `FOREVER`. `PCAP_STOP` stops the capture and any other running scan.
- `PCAP_LIMITS` sets the largest size, in MB, that one capture file can reach. Sent with no value, it replies with the current limit.
- `PCAP_AUTO`: limits for captures started by Sentinel attack responses. `budgetMB` is the total size they may use (default 512, min 16). `floorMB` is the free space to keep on the card (default 256). The node deletes automatic captures until both limits hold. With no value it replies with the current limits.
- `SD_REPAIR`: `ON` lets the node rebuild the filesystem of an SD card it can't mount. `OFF` (default) never does. `NOW` remounts the card now and rebuilds it only if every mount attempt fails. Rebuilding erases the card.
- `SCHED_ADD` takes four fields separated by `|`. The node holds up to 8 entries.

  | Field | Meaning |
  |---|---|
  | `start` | Start time in the node's local time, as `YYYY-MM-DDTHH:MM` |
  | `repeat` | Seconds between runs. `0` runs once. The minimum is `600` |
  | `scan` | `/scan` for a target scan, `/sniffer` for device discovery, or `/drone` |
  | `options` | `secs=<n>` for the run length, plus `mode=<0\|1\|2>` for `/scan` |

### Triangulation

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `TRIANGULATE_START` | `TS` | `target:secs[:rfEnv[:wifiPwr:blePwr]]` | `TRI_START_ACK` from each node, `TRI_ACK:BUSY` | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.0:1.0` |
| `TRIANGULATE_STOP` | `TX` | | `TRIANGULATE_STOP_ACK` | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | `TR` | | `TRIANGULATE_RESULTS_START`, results, `TRIANGULATE_RESULTS_END`, or `TRIANGULATE_RESULTS:NO_DATA` | `@AH01 TRIANGULATE_RESULTS` |

- Send `TRIANGULATE_START` to one node. That node coordinates the run with every other node on the mesh.
- `target`: a MAC, or a tracer identity `T-xxxx`.
- `rfEnv`: `0` Open Sky, `1` Suburban, `2` Indoor (default), `3` Indoor Dense, `4` Industrial. See the RF environment table in the [README](../README.md#locate-triangulation-experimental).
- `wifiPwr`, `blePwr`: distance multipliers for Wi-Fi and BLE readings, 0.1-5.0, default 1.0.

### Erase

Every erase command except `ERASE_REQUEST` and `AUTOERASE_STATUS` takes a one-time **answer** instead of the erase key. The key never goes over the mesh, except in `CONFIG_ERASE_PSK`.

**To send an erase command:**

1. Send `@AH01 ERASE_REQUEST`. The node replies `AH01: ERASE_TOKEN:AH_<hex>_<hex>_<hex> Expires:300s`.
2. Compute the answer from the token (everything from `AH_` up to the space) and your erase key:
   ```
   printf %s 'AH_<hex>_<hex>_<hex>' | openssl dgst -sha256 -hmac '<your key>' | awk '{print $NF}' | cut -c1-8
   ```
3. Within 300 s, send the command with the answer: `@AH01 ERASE_FORCE:<answer>`.

The answer is 8 hex characters, upper or lower case. The full 64 also works. One attempt uses up the token, right or wrong, so request a new token for each command. The node holds one token at a time: a new `ERASE_REQUEST`, or a tamper trigger, replaces the old one. `ERASE_REQUEST` works once per 20 s.

| Command | Alias | Args | What it does | Reply | Example |
|---|---|---|---|---|---|
| `ERASE_REQUEST` | `ER` | | Issues a token | `ERASE_TOKEN:<token> Expires:300s\|RATE_LIMITED` | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | `EF` | `answer` | Wipes now: settings and every SD file, then writes the decoy `/weather-air-feed.txt`. Needs an SD card. The node keeps running | `ERASE_EXECUTING`, `ERASE_COMPLETE`, `ERASE_ACK:COMPLETE`, or `ERASE_ACK:FAILED\|BUSY\|DENIED` | `@AH01 ERASE_FORCE:<answer>` |
| `ERASE_CANCEL` | `EC` | `answer` | Stops a tamper countdown | `TAMPER_CANCELLED` and `ERASE_ACK:CANCELED`, or `ERASE_ACK:DENIED` | `@AH01 ERASE_CANCEL:<answer>` |
| `FACTORY_RESET` | `FR` | `tier:answer` | `FULL`: settings and SD files. `CONFIG`: settings only, SD kept. `DATA`: SD files only, settings kept. Then reboots | `FACTORY_RESET_ACK:<tier> - rebooting\|DENIED\|DENIED_NO_PSK\|BAD_TIER\|BAD_FORMAT\|BUSY` | `@AH01 FACTORY_RESET:CONFIG:<answer>` |
| `AUTOERASE_ENABLE` | `AE1` | `[setup:erase:vibs:window:cooldown:]answer` | Turns on auto-erase on tamper | `AUTOERASE_ACK:ENABLED Setup:<s>s Erase:<s>s Vibs:<n> Window:<s>s Cooldown:<s>s`, `SETUP_MODE: Auto-erase activates in <s>s`, or `AUTOERASE_ACK:DENIED` | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300:<answer>` |
| `AUTOERASE_DISABLE` | `AE0` | `answer` | Turns off auto-erase | `AUTOERASE_ACK:DISABLED\|DENIED` | `@AH01 AUTOERASE_DISABLE:<answer>` |
| `AUTOERASE_STATUS` | `AEQ` | | Shows auto-erase state and settings | `AUTOERASE_STATUS: Enabled:YES\|NO [SetupMode:.. TamperActive:.. EraseIn:<s>s Setup:.. Erase:.. Vibs:.. Window:.. Cooldown:..]` | `@AH01 AUTOERASE_STATUS` |
| `CONFIG_ERASE_PSK` | `CEP` | `new:current` | Sets the erase key. `current` is the current key, or an answer | `CONFIG_ACK:ERASE_PSK:SET\|DENIED\|INVALID` | `@AH01 CONFIG_ERASE_PSK:<new key>:<current key>` |

**Erase key.** The key is 8 to 64 characters and can't contain `:`. On Full, until you set one, the current key is the AP password once you change it from the default. With the default AP password there is no key and every erase command is refused. On Headless, set the key in the web flasher. `CONFIG_ERASE_PSK` carries the key in clear text, so send it on your own encrypted channel.

**`AUTOERASE_ENABLE` settings.** Send all five, or none to keep the current values. Values outside the range are clamped.

| Field | Meaning | Range | Default |
|---|---|---|---|
| `setup` | Seconds before auto-erase arms. Place the node and leave in this time | 30-600 | 120 |
| `erase` | Seconds from the tamper alert to the wipe. Cancel in this time | 10-300 | 30 |
| `vibs` | Vibrations needed to start the countdown | 2-5 | 3 |
| `window` | Seconds in which those vibrations must happen | 10-60 | 20 |
| `cooldown` | Seconds before another tamper can start a countdown | 300-3600 | 300 |

When a tamper starts the countdown, the node sends `TAMPER_DETECTED: Auto-erase in <s>s`. To cancel, send `ERASE_REQUEST` after that alert, then `ERASE_CANCEL:<answer>`.

**Problems**
- `ERASE_ACK:SET_KEY_FIRST`: no erase key is set. Set one as above.
- `FACTORY_RESET_ACK:DENIED_NO_PSK`: the node has no key at all. Set one, or on Full change the AP password from the default.
- `ERASE_TOKEN:RATE_LIMITED`: wait 20 s and request again.
- `DENIED`: wrong key, token older than 300 s, token already used, or replaced by a newer one. Request a new token and try again.
- `ERASE_ACK:FAILED`: no SD card, or the wipe failed.
- 5 wrong keys or answers lock every erase command for 10 minutes, on the web and over mesh. Every attempt during the lock replies `DENIED`.
- The node logs keys and answers as `***`.

### Tamper and vibration

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `VIBRATION_ON` / `VIBRATION_OFF` | `V1` / `V0` | | `VIBRATION_ON_ACK:OK` / `VIBRATION_OFF_ACK:OK` | `@AH01 VIBRATION_ON` |
| `VIBRATION_STATUS` | `VQ` | | `VIBRATION_STATUS: ENABLED\|DISABLED Last:<s>s\|never` | `@AH01 VIBRATION_STATUS` |
| `VIBSCAN_SET` | `VSS` | `on:scan:secs[:cooldown[:interrupt]]` | `VIBSCAN_ACK:OK En:.. Mode:.. Dur:..s Cd:..s Pre:..`, `INVALID`, `INVALID_MODE` | `@AH01 VIBSCAN_SET:1:2:60:300` |
| `VIBSCAN_STATUS` | `VSQ` | | `VIBSCAN_STATUS: En:.. Mode:.. Dur:..s Cd:..s Pre:..` | `@AH01 VIBSCAN_STATUS` |

`VIBRATION_ON` sends a mesh alert when the node is moved. `VIBSCAN_SET` starts a scan when the node is moved:

| Field | Meaning |
|---|---|
| `on` | `1` on, `0` off |
| `scan` | `1` device discovery, `2` probe, `3` randomized MAC tracer, `4` target, `5` drone, `6` deauth, `7` baseline, `8` packet capture |
| `secs` | Scan length in seconds. `0` runs until `STOP`, except scan `8`, which needs a length |
| `cooldown` | Seconds before the next trigger, 5-86400. Left out, it keeps the current value |
| `interrupt` | `1` interrupts a running scheduled scan. The scheduled scan resumes after if it had 10 s or more left. Default `0` |

To turn it off: `@AH01 VIBSCAN_SET:0:0:0`.

### Power

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `BATTERY_SAVER_START` | `BSS` | `[min]` 1-30, default 5 | `BATTERY_SAVER_ACK:STARTED Interval:<n>min` | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | `BSX` | | `BATTERY_SAVER_ACK:STOPPED` | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | `BSQ` | | `BATTERY_SAVER_STATUS: Enabled:YES\|NO [Interval:<n>min ...]` | `@AH01 BATTERY_SAVER_STATUS` |
| `HB_ON` / `HB_OFF` | `HB1` / `HB0` | | `HB_ACK:ENABLED` / `HB_ACK:DISABLED` | `@AH01 HB_ON` |
| `HB_INTERVAL` | `HBI` | `min` 1-60 | `HB_ACK:INTERVAL <n>min` | `@AH01 HB_INTERVAL:10` |

`min` in `BATTERY_SAVER_START` is the minutes between battery-saver heartbeats. `HB_*` sets the normal status heartbeat.

### Sentinel

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `SENTINEL_ON` / `SENTINEL_OFF` | `SE1` / `SE0` | | `SENTINEL_ACK:ON run=0\|1` / `SENTINEL_ACK:OFF` | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | `SEQ` | | `SENTINEL_STATUS: en=0\|1 run=0\|1` | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | `SEM` | `defend\|scan` | `SENTINEL_MODE_ACK:defend\|scan` | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | `SEB` | `0\|1` | `SENTINEL_BOOT_ACK:on\|off` | `@ALL SENTINEL_BOOT:1` |
| `GROUP` | `GR` | `name:on\|off` | `GROUP_ACK:OK:<name>:<on\|off>`, `GROUP_ACK:FAIL:syntax\|onoff\|unknown_group` | `@ALL GROUP:dos:on` |
| `DETECT_CFG` | `DC` | JSON | `DETECT_CFG_ACK:OK` | `@AH01 DETECT_CFG:{"pmkid":true}` |
| `DETECT_CFG_GET` | `DCG` | | `DETECT_CFG_LEN:<n> (see serial)` | `@AH01 DETECT_CFG_GET` |
| `INCIDENTS` | `IN` | `[n]` 1-200, default 20 | `INCIDENTS_LEN:<n> (see serial)` | `@AH01 INCIDENTS:50` |
| `INCIDENTS_CLEAR` | `INX` | | `INCIDENTS_CLEAR_ACK:OK` | `@ALL INCIDENTS_CLEAR` |
| `ATTACKER_TRILAT` | `AT` | `0\|1\|on\|off` | `ATTACKER_TRILAT_ACK:ON\|OFF` | `@ALL ATTACKER_TRILAT:1` |
| `ATTACKER_TRILAT_STATUS` | `ATQ` | | `ATTACKER_TRILAT_STATUS: ON\|OFF` | `@AH01 ATTACKER_TRILAT_STATUS` |
| `DETECT_COUNTS` | `DCN` | | `DETECT_COUNTS: karmaCand=<n> ...` | `@AH01 DETECT_COUNTS` |

- `SENTINEL_MODE`: `scan` hops channels, `defend` stays on the AP channel. Headless has no AP, so use `scan`.
- `SENTINEL_BOOT:1` starts Sentinel at power-on.
- `DETECT_CFG_GET` and `INCIDENTS` print the data to USB serial. Over mesh they reply only with its length.
- `ATTACKER_TRILAT:1` triangulates the source of a confirmed attack.

`GROUP` turns a set of detectors on or off:

| Group | Detectors |
|---|---|
| `dos` | Evil twin, SAE DoS, assoc-sleep |
| `rogue` (or `rogue_ap`) | Evil twin, OWE abuse, Karma bait |
| `recon` | PMKID harvest, probe flood, forced handshake |
| `physical` (or `phys`) | FragAttacks, TSF / multi-channel twin, Wi-Fi interference |
| `mesh` | Mesh disruption |
| `all` | All of the above |

`DETECT_CFG` sets one or more keys in one JSON object. `DETECT_CFG_GET` prints every key and its current value. Unknown keys are ignored and the reply is still `OK`. The whole command must fit in one mesh message.

| Keys | Value | Sets |
|---|---|---|
| `pmkid` `eviltwin` `ssid_confusion` `sae` `owe` `frag` `jam` `mesh_guard` `hshk` `pwna` `tsf` `csa_quiet` `rid_spoof` `karma` `probe_flood` `assoc_sleep` `ble_attack` `ble_malformed` | `true`/`false` | Turns that detector on or off |
| `mesh_deauth` `mesh_beacon` `mesh_auth` `mesh_assoc_sleep` `mesh_sae` `mesh_eviltwin` `mesh_owe` `mesh_karma` `mesh_pmkid` `mesh_probe_flood` `mesh_hshk` `mesh_frag` `mesh_tsf` `mesh_jam` | `true`/`false` | Sends that detector's alerts over mesh |
| `sentinel_scan` | `true`/`false` | Same as `SENTINEL_MODE:scan` / `defend` |
| `attacker_trilat` | `true`/`false` | Same as `ATTACKER_TRILAT` |
| `attack_resp_mask` | sum of `2` packet capture, `4` device discovery, `8` probe sweep, `16` drone RID, `32` interrupt the running scan | Follow-up scan after a confirmed attack. `0` (default) is off |
| `ar_secs_pcap` `ar_secs_device` `ar_secs_probe` `ar_secs_drone` `ar_secs_trilat` | seconds | Length of each follow-up. Defaults 120 for capture, 60 for the others |

Example: `@AH01 DETECT_CFG:{"attack_resp_mask":6,"ar_secs_pcap":300}` starts a 300 s capture and a device discovery after each confirmed attack.

### CSI Motion (Beta, C5)

| Command | Alias | Args | Reply | Example |
|---|---|---|---|---|
| `CSI_MOTION_START` | `CIM` | `secs[:option...]` | `CSI_ACK:STARTED\|BUSY\|FAILED` | `@ALL CSI_MOTION_START:600:GAP60` |
| `CSI_CFG` | `CIC` | `KEY=value[:KEY=value...]` | `CSI_CFG_ACK:<settings>\|INVALID` | `@ALL CSI_CFG:SENSITIVITY=LOW:SPOTS=2` |
| `CSI_EXCLUDE` | `CIE` | `MAC\|NONE` | `CSI_EXCLUDE_ACK:<MAC> (matches the first five bytes)\|NONE\|INVALID` | `@AH01 CSI_EXCLUDE:NONE` |
| `CSI_STATUS` | `CIQ` | | `CSI_STATUS_LEN:<n>`, results on serial | `@AH01 CSI_STATUS` |
| `CSI_JSON` | `CIJ` | | `CSI_JSON_LEN:<n>`, JSON on serial | `@AH01 CSI_JSON` |
| `CSI_RECAL` | `CIR` | | `CSI_RECAL_ACK:OK` | `@ALL CSI_RECAL` |

`CSI_MOTION_START` options, in any order after `secs`:

| Option | Meaning |
|---|---|
| `FOREVER` | Run until `STOP` |
| `CH<n>` | Listen on channel n, 1-14. `0` or left out picks one |
| `GAP<s>` | Minimum seconds between mesh motion alerts, 0-3600 |
| `LISTEN_ONLY` / `ALLOW_TRANSMIT` | Never transmit / send probe requests when there is too little Wi-Fi traffic |
| `SOLICIT<ms>` | Send a probe request every n ms, 10-1000. Transmits |
| `MGMTONLY` / `MGMTDATA` | Measure management frames only / management and data frames |
| `TELEM` | Print the room state to serial on each update |
| `RAW` | Print raw CSI rows and per-device motion lines to serial |

`CSI_CFG` keys:

| Key | Meaning |
|---|---|
| `SENSITIVITY` | `LOW`, `MEDIUM`, `HIGH`, or a number to set the trigger level directly. Lower numbers catch smaller movement |
| `MIN_MOTION` | Seconds of movement within the last minute before an alert |
| `CLEAR_AFTER` | Seconds a device must stay quiet before it stops counting as moving |
| `SPOTS` | Devices that must see the movement at the same time |
| `BROADCAST` | `OFF` never transmit (same as `LISTEN_ONLY`), `ON` allow probe requests. Not related to mesh alerts |
| `ALLOW_RANDOM` | `ON` also listens to randomized-MAC devices such as phones |
| `CH` | Channel, `0` picks one |

- `CSI_EXCLUDE`: ignore one device, such as another node's AP. It matches the first five bytes of the MAC. `NONE` clears it.
- `CSI_RECAL`: clears a trigger level set with `SENSITIVITY=<number>` and returns to the default.
- Nodes running CSI find each other and ignore each other's signals.

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
| Tri cycle | `@ALL TRI_CYCLE_START:<ms>:<node,...>` (firmware-sent; alias `TCS`) |
| Probe hit | `NODE: PROBE_HIT MAC [Randomized\|Vendor] RSSI=dBm CH=N [SSID="x" [GHOST]] [DST]` |
| PCAP | `NODE: PCAP_START: WIFI\|BLE D=secs` · `PCAP_DONE: F=frames B=bytes D=dropped` |
| Scan complete | `NODE: SCAN_DONE: W=wifiAPs B=bleDevices U=unique H=hits TX=sent DUP=duplicates` (device discovery) · `LIST_SCAN_DONE: Hits=n Unique=n Targets=n TX=sent PEND=unsent` (target scan) · `DRONE_DONE: Detected=n Unique=n TX=sent` · `DEAUTH_DONE: Total=n Deauth=n Disassoc=n TX=sent` · `RANDOMIZATION_DONE: Identities=n Sessions=n TX=sent` · `BASELINE_DONE: Devices=n Anomalies=n WiFi=n BLE=n TX=sent PEND=unsent`. A probe scan (`PROBE_START`) sends no completion line |
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
