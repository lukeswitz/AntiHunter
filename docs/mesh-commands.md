# Mesh Commands

[Back](../README.md)

This page lists every command a node accepts over the mesh (Meshtastic LoRa radio) and on its USB serial port. It covers the Full and Headless firmware on the main branch. A command that works on only one build says so.

## How to send a command

Send a text message that starts with the target: `@AH01 STATUS` for one node, `@ALL STATUS` for every node. Arguments follow the command name, separated by `:`, as in `@AH01 INCIDENTS:50`.

- A node ID is 2 to 5 letters or digits. Node IDs and command names are not case sensitive.
- Each command also has a short alias: `@AH01 TS:...` is `@AH01 TRIANGULATE_START:...`.
- Type argument keywords such as `FOREVER`, `CH`, and `+PROBE` in uppercase.
- A whole line can be at most 230 characters.
- The node ignores any line that does not start with `@<NODE>` or `@ALL`. It also ignores a misspelled command and sends no reply.
- Every node that receives the command answers with `<NODE>: <reply>`. This page shows only the reply text.
- Only one scan runs at a time. A start command replies `BUSY` while another scan runs. Send `STOP` first.
- The same line typed on the node's USB serial port runs the same way.

Arguments used by many commands:

| Argument | Meaning | Range |
|---|---|---|
| `mode` | Which radio to use: `0` Wi-Fi, `1` Bluetooth LE (BLE), `2` both | 0-2 |
| `secs` | How long the scan runs, in seconds. `0` runs until `STOP` | 0-86400 |
| `FOREVER` | Keyword that runs the scan until `STOP`. Same as `secs` `0` | |
| `CH<list>` | Wi-Fi channels to use, such as `CH1,6,11` or `CH1..11` | 1-14 |

## Commands

### Core

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `STATUS` | `ST` | Reports radio mode, scan state, hit count, temperature, uptime, last reset reason, campaign, and GPS position | `STATUS: Mode:WiFi+BLE Scan:IDLE Hits:0 Temp:41.5C Up:00:12:03 Rst:<reason> [Camp:<name>] [GPS:<lat>,<lon> HDOP=<n>]` | `@ALL STATUS` |
| `SUMMARY` | `SUM` | Reports the same state with device and target counts | `SUMMARY: Mode:.. Scan:.. Dev:<devices in the device database> Tgt:<targets> Hits:<n> [Inc:<incidents>] [Camp:<name>] Up:..` | `@ALL SUMMARY` |
| `STOP` | `X` | Stops every running scan and cancels pending Sentinel follow-up scans | `STOP_ACK:OK` | `@ALL STOP` |
| `MESH_TX_CANCEL` | `MTC` | Drops the messages waiting to be sent, except triangulation messages. A running scan continues | `MESH_TX_CANCEL_ACK:EMPTY` if nothing is queued. Otherwise no reply | `@ALL MESH_TX_CANCEL` |

### Config

These commands change settings and save them.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `CONFIG_TARGETS` | `CT` | Replaces the target list that target scans look for | `CONFIG_ACK:TARGETS:OK` or `:FAILED` | `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF\|11:22:33` |
| `CONFIG_NODEID` | `CN` | Changes the node's ID | `CONFIG_ACK:NODE_ID:OK`, `:INVALID_CHARS`, or `:INVALID_LENGTH` | `@AH01 CONFIG_NODEID:AH02` |
| `CONFIG_RSSI` | `CR` | Sets the weakest signal the node reports | `CONFIG_ACK:RSSI:OK` or `:INVALID_RANGE` | `@ALL CONFIG_RSSI:-80` |
| `CONFIG_CHANNELS` | `CC` | Sets the Wi-Fi channels that scans hop through | `CONFIG_ACK:CHANNELS:<list as sent>` | `@ALL CONFIG_CHANNELS:1..11` |
| `CONFIG_DEDUP_TTL` | `CDT` | Sets how long the node suppresses repeat reports of the same device | `CONFIG_ACK:DEDUP_TTL:<seconds>` or `:INVALID` | `@ALL CONFIG_DEDUP_TTL:300` |
| `CONFIG_SESSION_DEDUP` | `CSD` | Turns session deduplication on or off | `CONFIG_ACK:SESSION_DEDUP:<0\|1>` | `@ALL CONFIG_SESSION_DEDUP:1` |
| `MESH_DEDUP_CLEAR` | `MDC` | Empties the deduplication memory, so the node reports known devices again | `DEDUP_CLEAR_ACK:OK` | `@ALL MESH_DEDUP_CLEAR` |
| `BLE_CLASSIFY` | `BC` | Turns BLE device classification on or off | `CONFIG_ACK:BLE_CLASSIFY:<0\|1>` | `@ALL BLE_CLASSIFY:0` |
| `CAMPAIGN_START` | `CS` | Starts a named campaign. Logged events carry the name, and the start and stop are recorded in the campaign log | `CAMPAIGN_ACK:START:<name>` or `:INVALID` | `@ALL CAMPAIGN_START:site-a` |
| `CAMPAIGN_STOP` | `CX` | Ends the running campaign | `CAMPAIGN_ACK:STOP:<name>` or `:NONE` | `@ALL CAMPAIGN_STOP` |
| `CAMPAIGN_STATUS` | `CQ` | Reports the running campaign | `CAMPAIGN_STATUS:<name>` or `:NONE` | `@AH01 CAMPAIGN_STATUS` |
| `DEVICE_DB_CLEAR` | `DBX` | Deletes the device database | `DEVICE_DB_CLEAR_ACK:OK` | `@AH01 DEVICE_DB_CLEAR` |
| `PROBE_DB_CLEAR` | `PDX` | Deletes the probe database | `PROBE_DB_CLEAR_ACK:OK` | `@AH01 PROBE_DB_CLEAR` |

| Command | Argument | Meaning | Range | Default |
|---|---|---|---|---|
| `CONFIG_TARGETS` | list | Entries separated by `\|`. Each entry is a full MAC (`AA:BB:CC:DD:EE:FF`), a vendor prefix of the first three bytes (`AA:BB:CC`), a network name (SSID), or a tracer ID (`T-` and four characters). While a scan runs, the node stores the list but does not load it into that scan | 230 characters per line | |
| `CONFIG_NODEID` | ID | New ID, saved in upper case | 2-5 letters or digits | |
| `CONFIG_RSSI` | dBm | The node ignores devices with a weaker signal than this. `-80` ignores everything below -80 dBm | -128 to -10 | -95 |
| `CONFIG_CHANNELS` | list | Channels as a list (`1,6,11`) or a range (`1..11`). The node drops invalid entries, falls back to 1-11 if none are left, and adds its own access point channel. The reply repeats what you sent, not the cleaned list. While a scan runs the list is saved but applied afterward | 1-14 | 1-11 |
| `CONFIG_DEDUP_TTL` | seconds | Time before the node may report the same device again. `0` turns deduplication off | 0-3600 | 300 |
| `CONFIG_SESSION_DEDUP` | `0` or `1` | `1`: a repeated scan sends only devices not reported earlier in the session. Any nonzero number counts as `1` | 0-1 | |
| `BLE_CLASSIFY` | `0` or `1` | `1`: BLE devices get a class label that appears as `C=<class>` in alerts. Any nonzero number counts as `1` | 0-1 | 1 |
| `CAMPAIGN_START` | name | Letters, digits, `-` and `_`. Starting a campaign ends the running one | 1-23 characters | |

### Scan

Each command starts one scan task. `secs` is the run time.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `SCAN_START` | `SS` | Target scan. Watches the channels for devices on the target list and reports each hit | `SCAN_ACK:STARTED`, `:BUSY`, `:FAILED`, or `:INVALID` | `@ALL SCAN_START:2:300:1..11` |
| `DEVICE_SCAN_START` | `DS` | Device discovery. Lists every Wi-Fi network and BLE device it hears and adds each to the device database | `DEVICE_SCAN_ACK:STARTED`, `:BUSY`, `:FAILED`, or `:INVALID` | `@ALL DEVICE_SCAN_START:2:300:+PROBE` |
| `BASELINE_START` | `BLS` | Learns the devices around the node, then reports new, returning, and changed ones | `BASELINE_ACK:STARTED`, `:BUSY`, or `:FAILED` | `@ALL BASELINE_START:300` |
| `BASELINE_STATUS` | `BLQ` | Reports baseline progress | `BASELINE_STATUS: Scanning:<YES\|NO> Established:<YES\|NO> Devices:<n> Anomalies:<n> Phase1:<INACTIVE\|ACTIVE\|COMPLETE>` | `@ALL BASELINE_STATUS` |
| `BASELINE_WATCH` | `BLW` | Marks the current moment in a running baseline. When the baseline ends, the node sends `BASELINE_WATCH: New=<n> Gone=<n> Moved=<n> Both=<n>` for the devices before and after the mark | `BASELINE_ACK:WATCHING` or `:NOT_RUNNING` | `@ALL BASELINE_WATCH` |
| `BASELINE_RESET` | `BLR` | Deletes the learned baseline from memory and SD | `BASELINE_RESET_ACK:OK`, or `:BUSY` while a scan runs | `@AH01 BASELINE_RESET` |
| `DRONE_START` | `DR` | Listens for drone Remote ID broadcasts on both radios | `DRONE_ACK:STARTED`, `:BUSY`, or `:FAILED` | `@ALL DRONE_START:300` |
| `DEAUTH_START` | `DA` | Counts and reports deauthentication and disassociation frames (Wi-Fi frames that force a device off a network) | `DEAUTH_ACK:STARTED`, `:BUSY`, or `:FAILED` | `@ALL DEAUTH_START:300` |
| `RANDOMIZATION_START` | `RS` | Links devices that change their MAC address to one identity | `RANDOMIZATION_ACK:STARTED`, `:BUSY`, `:FAILED`, or `:INVALID` | `@ALL RANDOMIZATION_START:2:300` |
| `RANDOMIZATION_RESET` | `RRX` | Deletes the saved identities from memory and SD | `RANDOMIZATION_RESET_ACK:OK`, or `:BUSY` while a scan runs | `@AH01 RANDOMIZATION_RESET` |
| `PROBE_START` | `PS` | Collects probe requests (frames in which a device asks for a known network by name) and reports hits | `PROBE_ACK:STARTED`, `:BUSY`, `:FAILED`, or `:INVALID` | `@ALL PROBE_START:2:300:+ALL` |
| `PROBE_STOP` | `PX` | Stops the running scan. Leaves the mesh queue alone | `PROBE_ACK:STOPPED` | `@ALL PROBE_STOP` |
| `PCAP_START` | `PCS` | Records raw packets to a `.pcap` file on the SD card | `PCAP_ACK:STARTED`, `:BUSY`, `:NOSD`, or `:FAILED` | `@ALL PCAP_START:0:300:0:CH1,6,11` |
| `PCAP_STOP` | `PCX` | Stops the capture and any other running scan | `PCAP_STOP_ACK:OK` | `@ALL PCAP_STOP` |
| `PCAP_LIMITS` | `PCL` | Sets, or with no argument reports, the largest size of one capture file | `PCAP_LIMITS_ACK:MAXFILE=<n>MB` or `:INVALID` | `@ALL PCAP_LIMITS:150` |
| `PCAP_AUTO` | `PCA` | Sets, or with no argument reports, the SD space for captures that Sentinel starts after an attack | `PCAP_AUTO_ACK:BUDGET=<n>MB FLOOR=<n>MB` or `:INVALID` | `@AH01 PCAP_AUTO:512,64` |
| `SD_REPAIR` | `SDR` | Controls whether the node rebuilds an SD card it cannot mount. With no argument it reports the setting | `SD_REPAIR_ACK:ON`, `:OFF`, `:REPAIRED`, or `:FAILED` | `@ALL SD_REPAIR:ON` |
| `SCHED_ADD` | `SA` | Adds a scheduled scan | `SCHED_ACK:OK`, `SCHED_ACK:ERR <reason>`, or `SCHED_ACK:INVALID` | `@ALL SCHED_ADD:2026-11-30T02:00\|86400\|/scan\|mode=2&secs=600` |
| `SCHED_LIST` | `SL` | Counts the scheduled scans and prints them on USB serial | `SCHED_LIST:<count>` | `@AH01 SCHED_LIST` |
| `SCHED_DEL` | `SD` | Deletes one scheduled scan | `SCHED_ACK:DELETED` or `:NOT_FOUND` | `@AH01 SCHED_DEL:1` |

| Command | Argument | Meaning | Range | Default |
|---|---|---|---|---|
| `SCAN_START` | `mode`, `secs` | See the table above. Both are required, and so is the third field | | |
| `SCAN_START` | channels | Third field: a list (`1,6,11`) or range (`1..11`). Add `:FOREVER` after it to run until `STOP`. To skip the list, write `FOREVER` in the third field, or leave it empty (`SCAN_START:2:300:`) | 1-14 | 1-11 |
| `DEVICE_SCAN_START` | `mode`, `secs` | Required first, in that order | | `secs` 60 |
| `DEVICE_SCAN_START` | `+PROBE` | Also collects probe requests | | off |
| `DEVICE_SCAN_START` | `CH<list>` | Channels to hop. Left out, the node uses the share it got from a channel split, or its channel list | 1-14 | |
| `BASELINE_START` | `secs` | Monitoring time after the learning phase. A value from 1 to 59 becomes 60, and `0` monitors until `STOP`. The learning phase lasts as long as the baseline duration setting in the web UI (default 300 seconds) | 60-86400, or 0 | |
| `DRONE_START` | `secs` | Run time | 0-86400 | |
| `DEAUTH_START` | `secs` | Run time | 0-86400 | |
| `RANDOMIZATION_START` | `mode`, `secs` | Radio and run time | | `secs` 60 |
| `PROBE_START` | `mode`, `secs` | Radio and run time. `secs` below 1 becomes 1 unless you add `FOREVER` | 1-86400 | `secs` 60 |
| `PROBE_START` | `+ALL` | Sends every probe request to the mesh, not only watchlist hits | | off |
| `PCAP_START` | `radio` | `0` Wi-Fi, `1` BLE | 0-1 | 0 |
| `PCAP_START` | `secs` | Capture length. A capture needs a length: `0` and `FOREVER` return `PCAP_ACK:FAILED` | 1-86400 | 300 |
| `PCAP_START` | `band` | `0` 2.4 GHz, `1` 5 GHz, `2` both. This hardware has 2.4 GHz only, so the node always uses `0` | 0-2 | 0 |
| `PCAP_START` | `CH<list>` | Channels to capture on | 1-177 | |
| `PCAP_LIMITS` | MB | Size at which a capture file closes | 8-300 | |
| `PCAP_AUTO` | `budgetMB,floorMB` | Both, separated by a comma. `budgetMB` is the total space automatic captures may use. The node deletes automatic captures until both limits hold. `floorMB` is the free space it keeps on the card | budget 16-262144, floor 0-262144 | 512, 256 |
| `SD_REPAIR` | keyword | `ON` rebuilds a card that will not mount. `OFF` never does. `NOW` remounts the card now and rebuilds it only if every mount attempt fails. A rebuild erases the card | | `OFF` |
| `SCHED_ADD` | `start` | First run, in the node's local time, as `YYYY-MM-DDTHH:MM`. Must be after 2021-01-01 | | |
| `SCHED_ADD` | `repeat` | Seconds between runs. `0` runs once | 0, or 600-2678400 | |
| `SCHED_ADD` | `scan` | The web route to run: `/scan` target scan, `/sniffer` device discovery, or `/drone` | | |
| `SCHED_ADD` | `options` | Form fields for that route, joined with `&`, such as `mode=2&secs=600`. The [API reference](api-reference.md) lists each route's fields. No `\|` allowed | 1024 characters | |
| `SCHED_DEL` | `n` | Position in the `SCHED_LIST` output, counting from 1 | | |

Notes:

- A scheduled scan runs only after the node knows the time, from GPS, its real-time clock, or a web UI visit. The node holds 8 scheduled scans.
- `PCAP_STOP` and `PROBE_STOP` both stop whatever scan is running.
- A target scan started over the mesh does not check that the target list has entries. The web UI does.

### Triangulation

Several nodes measure the signal strength of one target and estimate its position. See [Locate: Triangulation](../README.md#locate-triangulation-experimental) for the method. Send `TRIANGULATE_START` to one node by its ID, not to `@ALL`. That node becomes the coordinator and starts every other node on the mesh.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `TRIANGULATE_START` | `TS` | Starts a triangulation run | Each other node sends `TRI_START_ACK` within about 2 seconds. A node that cannot free its radio sends `TRI_ACK:BUSY`. A malformed command gets no reply | `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:2:1.0:1.0` |
| `TRIANGULATE_STOP` | `TX` | Ends the run. Each node sends its last readings as `T_D` lines | `TRIANGULATE_STOP_ACK` | `@ALL TRIANGULATE_STOP` |
| `TRIANGULATE_RESULTS` | `TR` | Prints the current estimate | `TRIANGULATE_RESULTS_START`, the result text, `TRIANGULATE_RESULTS_END`; or `TRIANGULATE_RESULTS:NO_DATA` | `@AH01 TRIANGULATE_RESULTS` |

`TRIANGULATE_START` takes `target:secs[:rfEnv[:wifiPwr[:blePwr]]]`:

| Argument | Meaning | Range | Default |
|---|---|---|---|
| `target` | The device to locate: a MAC address, or a tracer ID that starts with `T-` | | |
| `secs` | Run time. Values outside the range are moved to the nearest limit. Zero or less is ignored | 10-3600 | |
| `rfEnv` | Surroundings, used to turn signal strength into distance: `0` open sky, `1` suburban, `2` indoor, `3` indoor dense, `4` industrial. Other values become `2`. The README has the [calibration table](../README.md#locate-triangulation-experimental) | 0-4 | 2 |
| `wifiPwr` | Multiplier for Wi-Fi distance estimates. Raise it if estimates come out too short | 0.1-5.0 | 1.0 |
| `blePwr` | Same for BLE. Out-of-range values become `1.0` | 0.1-5.0 | 1.0 |

Nodes also trade `TRI_CYCLE_START:<ms>:<node,...>` (alias `TCS`) to schedule their reports. The firmware sends it. You do not.

#### Distance calibration

Calibration replaces the RF environment's guess of signal strength at 1 m with a measurement from one node. Place a Wi-Fi access point or BLE device at a measured distance from the node, then send `CALIBRATE` to that node. The node listens to the device for 30 seconds. It saves the result to its built-in memory and the SD card, and keeps it after a reboot and when you change the RF environment. Calibrate each node on its own, and reset it when you move the node.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `CALIBRATE` | `CAL` | Calibrates this node against a reference device | `CALIBRATE_ACK:STARTED`, `CALIBRATE_ACK:BUSY` while a scan runs, or `CALIBRATE_ACK:INVALID`. When it finishes: `CALIBRATE_DONE:WIFI=<dBm>:BLE=<dBm>` (`NONE` for a radio that heard fewer than 10 readings), `CALIBRATE_DONE:FAILED`, or `CALIBRATE_DONE:STOPPED` after `STOP` | `@AH01 CALIBRATE:AA:BB:CC:DD:EE:FF:5` |
| `CALIBRATE_RESET` | `CALX` | Clears the calibration. Distances go back to the RF environment values | `CALIBRATE_ACK:RESET` | `@AH01 CALIBRATE_RESET` |

`CALIBRATE` takes `mac:meters`:

| Argument | Meaning | Range |
|---|---|---|
| `mac` | MAC address of the reference device | |
| `meters` | Measured distance from the node to the device | 0.5-100 |

The `<dBm>` values in `CALIBRATE_DONE` are the calibrated signal strength at 1 m for the current RF environment.

### Erase

A wipe cannot be undone, so the node only wipes when you prove you know its **erase key**. The node makes the key on first start, and every flasher shows it. See [Secure data destruction](../README.md#secure-data-destruction). You never send that key over the radio. Instead:

- The node gives you a **token**, a one-time random challenge, good for 5 minutes.
- You turn the token and your key into a short **answer** code.
- You send the answer. The node checks it and wipes.

A token works once, so an answer copied off the air is useless. The one exception is `CONFIG_ERASE_PSK`, which carries a key in clear text.

To send an erase command:

1. Ask for a token: `@AH01 ERASE_REQUEST`. The node replies `ERASE_TOKEN:AH_<hex>_<hex>_<hex> Expires:300s`.
2. Turn the token (from `AH_` to the space) and your key into the answer. Use **Erase Answer** on the [Web Flasher page](https://lukeswitz.github.io/AntiHunter/), which computes it in your browser and sends nothing, or a terminal:
   ```
   printf %s 'AH_<hex>_<hex>_<hex>' | openssl dgst -sha256 -hmac '<your key>' | awk '{print $NF}' | cut -c1-8
   ```
3. Within 5 minutes, send the command with the answer: `@AH01 ERASE_FORCE:<answer>`.

The answer is the first 8 hex characters of that HMAC-SHA256 (upper or lower case). The full 64 also work. Each token allows one try, right or wrong, so request a new token before each command. The node keeps only the newest token. A new `ERASE_REQUEST`, or a tamper alert, replaces it. You can request a token once every 20 seconds.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `ERASE_REQUEST` | `ER` | Issues a token | `ERASE_TOKEN:<token> Expires:300s` or `ERASE_TOKEN:RATE_LIMITED` | `@AH01 ERASE_REQUEST` |
| `ERASE_FORCE` | `EF` | Wipes the node's settings and every SD file, then writes a decoy file, `/weather-air-feed.txt`. Needs an SD card. The node keeps running | `ERASE_EXECUTING: Force command`, then `ERASE_COMPLETE` and `ERASE_ACK:COMPLETE`. Or `ERASE_ACK:FAILED`, `:BUSY`, or `:DENIED` | `@AH01 ERASE_FORCE:<answer>` |
| `ERASE_CANCEL` | `EC` | Stops a tamper countdown | `TAMPER_CANCELLED` and `ERASE_ACK:CANCELED`, or `ERASE_ACK:DENIED` | `@AH01 ERASE_CANCEL:<answer>` |
| `FACTORY_RESET` | `FR` | Wipes by tier, then reboots | `FACTORY_RESET_ACK:<tier> - rebooting`, or `:DENIED`, `:DENIED_NO_PSK`, `:BAD_TIER`, `:BAD_FORMAT`, `:BUSY` | `@AH01 FACTORY_RESET:CONFIG:<answer>` |
| `AUTOERASE_ENABLE` | `AE1` | Turns on auto-erase: the node wipes itself after it is moved | `AUTOERASE_ACK:ENABLED Setup:<s>s Erase:<s>s Vibs:<n> Window:<s>s Cooldown:<s>s`, then `SETUP_MODE: Auto-erase activates in <s>s`. Or `AUTOERASE_ACK:DENIED` | `@AH01 AUTOERASE_ENABLE:60:30:3:30:300:<answer>` |
| `AUTOERASE_DISABLE` | `AE0` | Turns off auto-erase | `AUTOERASE_ACK:DISABLED` or `:DENIED` | `@AH01 AUTOERASE_DISABLE:<answer>` |
| `AUTOERASE_STATUS` | `AEQ` | Reports auto-erase state and settings | `AUTOERASE_STATUS: Enabled:<YES\|NO>`, and when enabled: `SetupMode:`, `TamperActive:`, `EraseIn:`, `Setup:`, `Erase:`, `Vibs:`, `Window:`, `Cooldown:` | `@AH01 AUTOERASE_STATUS` |
| `CONFIG_ERASE_PSK` | `CEP` | Changes the erase key | `CONFIG_ACK:ERASE_PSK:SET`, `:DENIED`, or `:INVALID` | `@AH01 CONFIG_ERASE_PSK:<new key>:<current key>` |

| Command | Argument | Meaning |
|---|---|---|
| `FACTORY_RESET` | `tier:answer` | `FULL` wipes settings and SD files. `CONFIG` wipes settings and keeps the SD files. `DATA` wipes SD files and keeps settings |
| `CONFIG_ERASE_PSK` | `new:current` | The new key, then the current key itself or a fresh answer |
| `AUTOERASE_ENABLE` | `answer` | An answer code, last in the line. Alone (`AUTOERASE_ENABLE:<answer>`) it keeps the stored timings |

**Erase key.** A key you set is 8 to 64 characters with no `:`. `CONFIG_ERASE_PSK` carries keys in clear text, so send it only on your own encrypted channel. The node logs keys and answers as `***`.

**`AUTOERASE_ENABLE` timings.** Send all five fields before the answer, or none to keep the stored values. If you send fewer than five, the node ignores them. Values outside the range move to the nearest limit.

| Field | Meaning | Unit | Range | Default |
|---|---|---|---|---|
| `setup` | Time before auto-erase arms, so you can place the node and leave | seconds | 30-600 | 120 |
| `erase` | Time from the tamper alert to the wipe. Cancel inside this time | seconds | 10-300 | 30 |
| `vibs` | Vibrations that start the countdown | count | 2-5 | 3 |
| `window` | Time in which those vibrations must happen | seconds | 10-60 | 20 |
| `cooldown` | Time before another tamper can start a countdown | seconds | 300-3600 | 300 |

The web endpoint `/config/autoerase` uses milliseconds and wider ranges. See the [API reference](api-reference.md).

When a tamper starts the countdown, the node sends `TAMPER_DETECTED: Auto-erase in <s>s`. To cancel, send `ERASE_REQUEST`, then `ERASE_CANCEL:<answer>`.

**Problems**

- `ERASE_ACK:SET_KEY_FIRST` or `FACTORY_RESET_ACK:DENIED_NO_PSK`: the node has no key. Restart it. It makes one at boot and prints it on USB serial.
- Lost the key: reflash with **Erase device** checked. The node makes and shows a new key.
- `ERASE_TOKEN:RATE_LIMITED`: wait 20 seconds and ask again.
- `DENIED`: the answer is wrong, the token is older than 300 seconds, already used, or replaced by a newer one. Request a new token.
- `ERASE_ACK:FAILED`: no SD card, or the wipe failed.
- 5 wrong keys or answers lock every erase command for 10 minutes, on the web and over the mesh. Attempts during the lock get `DENIED`.

### Tamper and vibration

The vibration sensor detects when someone moves the node.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `VIBRATION_ON` / `VIBRATION_OFF` | `V1` / `V0` | Turns the mesh movement alert on or off | `VIBRATION_ON_ACK:OK` / `VIBRATION_OFF_ACK:OK` | `@AH01 VIBRATION_ON` |
| `VIBRATION_STATUS` | `VQ` | Reports whether the alert is on and when the last movement happened | `VIBRATION_STATUS: <ENABLED\|DISABLED> Last:<s>s` or `Last:never` | `@AH01 VIBRATION_STATUS` |
| `VIBSCAN_SET` | `VSS` | Starts a scan automatically when the node is moved | `VIBSCAN_ACK:OK En:.. Mode:.. Dur:..s Cd:..s Pre:..`, `:INVALID`, or `:INVALID_MODE` | `@AH01 VIBSCAN_SET:1:2:60:300` |
| `VIBSCAN_STATUS` | `VSQ` | Reports the movement-scan settings | `VIBSCAN_STATUS: En:.. Mode:.. Dur:..s Cd:..s Pre:..` | `@AH01 VIBSCAN_STATUS` |

`VIBSCAN_SET` takes `on:scan:secs[:cooldown[:interrupt]]`:

| Field | Meaning | Range |
|---|---|---|
| `on` | `1` on, `0` off | 0-1 |
| `scan` | Which scan to start, always on both radios: `1` device discovery, `2` probe, `3` randomized MAC tracer, `4` target scan on channels 1-11, `5` drone, `6` deauth, `7` baseline, `8` packet capture on Wi-Fi 2.4 GHz. `0` starts none | 0-8 |
| `secs` | Scan length in seconds. `0` runs until `STOP`, except scan `8`, which needs a length above 0 | 0-65535 |
| `cooldown` | Seconds before the next movement can start a scan. Left out, it keeps the current value | 5-86400 |
| `interrupt` | `1` stops a running scheduled scan to make room. The scheduled scan resumes afterward if it had 10 seconds or more left. Left out, it keeps the current value | 0-1 |

To turn the movement scan off: `@AH01 VIBSCAN_SET:0:0:0`. The `Pre:` value in the reply is the interrupt setting.

### Power

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `BATTERY_SAVER_START` | `BSS` | Stops all scans, switches off the scanning radios, lowers the CPU speed, and sends a short heartbeat at a fixed interval | `BATTERY_SAVER_ACK:STARTED Interval:<n>min` | `@AH01 BATTERY_SAVER_START:10` |
| `BATTERY_SAVER_STOP` | `BSX` | Returns to normal operation | `BATTERY_SAVER_ACK:STOPPED` | `@AH01 BATTERY_SAVER_STOP` |
| `BATTERY_SAVER_STATUS` | `BSQ` | Reports the state | `BATTERY_SAVER_STATUS: Enabled:<YES\|NO> [Interval:<n>min NextHB:<s>s] Temp:<n>C [GPS:<lat>,<lon>]` | `@AH01 BATTERY_SAVER_STATUS` |
| `HB_ON` / `HB_OFF` | `HB1` / `HB0` | Turns the normal status heartbeat on or off | `HB_ACK:ENABLED` / `HB_ACK:DISABLED` | `@AH01 HB_ON` |
| `HB_INTERVAL` | `HBI` | Sets the minutes between normal heartbeats | `HB_ACK:INTERVAL <n>min` | `@AH01 HB_INTERVAL:10` |

| Command | Argument | Meaning | Range | Default |
|---|---|---|---|---|
| `BATTERY_SAVER_START` | `min` | Minutes between battery-saver heartbeats. Out-of-range values move to the nearest limit | 1-30 | 5 |
| `HB_INTERVAL` | `min` | Minutes between normal heartbeats. Out-of-range values move to the nearest limit | 1-60 | |

### Sentinel

Sentinel is the node's threat detection. It watches for Wi-Fi attacks, interference, attack devices, and Meshtastic and MeshCore radios. It is part of both builds. The [README](../README.md#detection-sentinel) describes what it detects.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `SENTINEL_ON` / `SENTINEL_OFF` | `SE1` / `SE0` | Starts or stops Sentinel | `SENTINEL_ACK:ON run=<0\|1>` / `SENTINEL_ACK:OFF` | `@ALL SENTINEL_ON` |
| `SENTINEL_STATUS` | `SEQ` | Reports whether you switched it on (`en`) and whether the detectors run now (`run`) | `SENTINEL_STATUS: en=<0\|1> run=<0\|1>` | `@AH01 SENTINEL_STATUS` |
| `SENTINEL_MODE` | `SEM` | Chooses how the node listens | `SENTINEL_MODE_ACK:defend`, `:scan`, or `:FAIL` | `@ALL SENTINEL_MODE:scan` |
| `SENTINEL_BOOT` | `SEB` | Chooses whether Sentinel starts at power-on | `SENTINEL_BOOT_ACK:on` or `:off` | `@ALL SENTINEL_BOOT:1` |
| `GROUP` | `GR` | Turns a set of detectors on or off | `GROUP_ACK:OK:<name>:<on\|off>`, or `GROUP_ACK:FAIL:syntax`, `:onoff`, `:unknown_group` | `@ALL GROUP:dos:on` |
| `DETECT_CFG` | `DC` | Sets individual detectors and thresholds from a JSON object | `DETECT_CFG_ACK:OK` | `@AH01 DETECT_CFG:{"pmkid":true}` |
| `DETECT_CFG_GET` | `DCG` | Prints every setting on USB serial | `DETECT_CFG_LEN:<n> (see serial)` | `@AH01 DETECT_CFG_GET` |
| `INCIDENTS` | `IN` | Prints the most recent incidents on USB serial | `INCIDENTS_LEN:<n> (see serial)` | `@AH01 INCIDENTS:50` |
| `INCIDENTS_CLEAR` | `INX` | Deletes the incident log | `INCIDENTS_CLEAR_ACK:OK` | `@ALL INCIDENTS_CLEAR` |
| `DETECT_CLEAR` | `DCX` | Clears all detector state and deletes the detector logs on SD | `DETECT_CLEAR_ACK:OK` | `@AH01 DETECT_CLEAR` |
| `RADIO_KNOWN_ADD` | `RKA` | Marks a Meshtastic or MeshCore radio as known. The node stops alerting on it | `RADIO_KNOWN_ACK:OK:<count>`, `:INVALID`, or `:FAILED:FULL` | `@ALL RADIO_KNOWN_ADD:AA:BB:CC:DD:EE:FF:Meshtastic` |
| `RADIO_KNOWN_DEL` | `RKD` | Removes a radio from the known list | `RADIO_KNOWN_ACK:OK:<count>` or `:INVALID` | `@ALL RADIO_KNOWN_DEL:AA:BB:CC:DD:EE:FF` |
| `RADIO_KNOWN_CLEAR` | `RKX` | Empties the known list | `RADIO_KNOWN_ACK:OK:0` | `@AH01 RADIO_KNOWN_CLEAR` |
| `ATTACKER_TRILAT` | `AT` | Turns on locating the source of a confirmed attack by triangulation | `ATTACKER_TRILAT_ACK:ON` or `:OFF` | `@ALL ATTACKER_TRILAT:1` |
| `ATTACKER_TRILAT_STATUS` | `ATQ` | Reports that setting | `ATTACKER_TRILAT_STATUS: ON` or `OFF` | `@AH01 ATTACKER_TRILAT_STATUS` |
| `DETECT_COUNTS` | `DCN` | Reports internal detector counters | `DETECT_COUNTS: karmaCand=<n> karmaConf=<n> pwna=<n> meshradio=<n> tsf=<n> pg=<n> tof=<n> hunts=<n> hshk=<n> peers=<n> arPending=<n>` | `@AH01 DETECT_COUNTS` |

| Command | Argument | Meaning | Range | Default |
|---|---|---|---|---|
| `SENTINEL_MODE` | `scan` or `defend` | `scan` hops across channels to watch them all. `defend` stays on the access point channel. The node always starts in `defend` after a reboot | | `defend` |
| `SENTINEL_BOOT` | `0`, `1`, or `on` | `1` or `on` starts Sentinel at power-on | | |
| `GROUP` | `name:on\|off` | `on`, `1`, or `true` enables. `off`, `0`, or `false` disables. Names are in the table below | | |
| `INCIDENTS` | `n` | Number of incidents to print. Other values give 20 | 1-200 | 20 |
| `ATTACKER_TRILAT` | `0`, `1`, `on`, or `off` | Turns locating on or off | | |
| `RADIO_KNOWN_ADD` | `mac:type[:name]` | `type` is `Meshtastic` or `MeshCore`. `name` is the radio's Bluetooth name. If you leave it out, the node uses the name it last saw for that MAC | 32 radios, name up to 31 characters | |

A known radio matches by MAC. A radio that changes its Bluetooth address also matches by type and name. A radio with a fixed address that uses a known name still raises an alert. The list survives a reboot. The node waits up to 30 seconds for the name of a radio that changes its address before it alerts.

A `GROUP` name selects these detectors:

| Group | Detectors |
|---|---|
| `dos` | Evil twin, SAE flood, association sleep |
| `rogue` (or `rogue_ap`) | Evil twin, OWE downgrade, Karma bait |
| `recon` | PMKID harvest, probe flood, forced handshake, Pwnagotchi |
| `physical` (or `phys`) | FragAttacks, two-channel twin (one access point beaconing on two channels), Wi-Fi interference, interference baseline |
| `mesh` | Mesh disruption |
| `devices` | LoRa mesh radios (Meshtastic and MeshCore) |
| `all` | All of the above |

`DETECT_CFG` takes one JSON object with any of these keys. The reply is always `OK`, and the node skips keys it does not know. The whole line must fit in 230 characters. A switch is on for `true` or `1` and off for anything else. A number must be above 0. The node skips a `0`.

| Keys | Value | Sets |
|---|---|---|
| `pmkid` `eviltwin` `ssid_confusion` `sae` `owe` `frag` `jam` `jam_baseline` `mesh_guard` `hshk` `pwna` `meshradio` `tsf` `csa_quiet` `rid_spoof` `karma` `probe_flood` `assoc_sleep` `ble_malformed` | switch | Turns that detector on or off. `jam_baseline` adds the interference baseline to `jam`. `meshradio` and `jam_baseline` are off by default |
| `mesh_deauth` `mesh_beacon` `mesh_auth` `mesh_assoc_sleep` `mesh_sae` `mesh_eviltwin` `mesh_owe` `mesh_karma` `mesh_pmkid` `mesh_probe_flood` `mesh_hshk` `mesh_frag` `mesh_tsf` `mesh_jam` `mesh_meshradio` | switch | Sends that detector's alerts over the mesh. `mesh_jam` covers both interference alerts |
| `bloom_gossip` | switch | Sends this node's baseline fingerprints over the mesh every 5 minutes. Received fingerprints only show as a count on `/api/bloom`. No detector uses them |
| `sentinel_scan` | switch | Same as `SENTINEL_MODE`: `true` is `scan` |
| `attacker_trilat` | switch | Same as `ATTACKER_TRILAT` |

| Key | Meaning | Unit | Default |
|---|---|---|---|
| `pmkid_window` | Time in which a device's unfinished handshakes are counted | ms | 10000 |
| `pmkid_min_bssids` | Access points with unfinished handshakes that raise a PMKID alert | count | 3 |
| `sae_window` | Time in which SAE commit frames are counted | ms | 5000 |
| `sae_unmatched_thresh` | Commit frames without a confirm that raise an SAE flood alert | count | 10 |
| `probe_single_thresh` | Probe requests from one device in 5 seconds that raise a probe flood alert | count | 60 |
| `probe_rand_total` | Probe requests from randomized MACs in 5 seconds that raise a flood alert | count | 80 |
| `probe_rand_distinct` | Distinct randomized MACs in 5 seconds that raise the same alert | count | 60 |
| `deauth_targeted_thresh` | Deauth frames at one client that raise a targeted-deauth alert | count | 10 |
| `jam_nf_db` | How far a channel's noise floor must rise above its learned level to raise a Wi-Fi interference alert, from 3 to 30 | dB | 8 |
| `hunt_cooldown_ms` | Time before the same attacker can start another location hunt | ms | 60000 |
| `attack_resp_mask` | Follow-up actions after a confirmed attack. Add the values: `2` packet capture, `4` device discovery, `8` probe scan, `16` drone Remote ID scan, `32` stop the running scan to make room. `0` is off, and cannot be set back to `0` with this command | sum | 0 |
| `ar_secs_pcap` | Length of the follow-up capture | s | 120 |
| `ar_secs_device` `ar_secs_probe` `ar_secs_drone` `ar_secs_trilat` | Length of each other follow-up | s | 60 |

Example: `@AH01 DETECT_CFG:{"attack_resp_mask":6,"ar_secs_pcap":300}` records a 300-second capture and runs a device discovery after each confirmed attack. The mask 6 is 2 (capture) plus 4 (device discovery).

### CSI Motion (Beta, C5)

These commands exist in the Beta firmware and the Experimental C5 firmware. The main (Stable) firmware does not have them. CSI (channel state information) motion detection reports movement from changes in nearby Wi-Fi signals. See [Detection: CSI Motion](../README.md#detection-csi-motion-beta) for how it works. A start command replies `BUSY` while another scan runs.

| Command | Alias | What it does | Reply | Example |
|---|---|---|---|---|
| `CSI_MOTION_START` | `CIM` | Starts motion detection | `CSI_ACK:STARTED`, `:BUSY`, or `:FAILED` | `@ALL CSI_MOTION_START:0:FOREVER` |
| `CSI_CFG` | `CIC` | Changes the detection settings and saves them | `CSI_CFG_ACK:SENSITIVITY=<n> MIN_MOTION=<s>s CLEAR_AFTER=<s>s SPOTS=<n> CH=<n> BROADCAST=<ON\|OFF> [REQUIRE_CE=<ON\|OFF>] ALLOW_RANDOM=<ON\|OFF>`, or `CSI_CFG_ACK:INVALID` | `@AH01 CSI_CFG:SENSITIVITY=HIGH` |
| `CSI_EXCLUDE` | `CIE` | Ignores one transmitter, such as the node's own access point | `CSI_EXCLUDE_ACK:NONE`, `:<mac> (matches the first five bytes)`, or `:INVALID` | `@AH01 CSI_EXCLUDE:AA:BB:CC:DD:EE:FF` |
| `CSI_STATUS` | `CIQ` | Prints the status text on USB serial | `CSI_STATUS_LEN:<n>` | `@AH01 CSI_STATUS` |
| `CSI_JSON` | `CIJ` | Prints the same data as JSON on USB serial | `CSI_JSON_LEN:<n>` | `@AH01 CSI_JSON` |
| `CSI_RECAL` | `CIR` | Clears the sensitivity you set, so the node uses the built-in value again | `CSI_RECAL_ACK:OK` | `@ALL CSI_RECAL` |

`CSI_MOTION_START` takes `secs[:option]...`. The first field is `secs`. The options follow in any order:

| Argument | Meaning | Range | Default |
|---|---|---|---|
| `secs` | Run time in seconds. `0` runs until `STOP` | 0-86400 | |
| `FOREVER` | Runs until `STOP`. Same as `secs` `0` | | off |
| `CH<n>` | Wi-Fi channel to watch, such as `CH6`. `0`, or a value above 14, lets the node pick a channel | 0-14 | 0 |
| `TELEM` | Prints a score for every packet on USB serial | | off |
| `RAW` | Dumps the raw channel data on USB serial | | off |
| `SOLICIT<ms>` | Sends a probe request every `<ms>` milliseconds. Needs transmitting to be on. Values below 10 become 10, and values above 1000 become 1000 | 10-1000 | 0 (off) |
| `GAP<s>` | Smallest time in seconds between two `CSI_MOTION` alerts. `0` sends every alert | 0-3600 | 0 |
| `MGMTONLY` / `MGMTDATA` | Listens to management frames only, or to management and data frames | | `MGMTDATA` |
| `LISTEN_ONLY` / `ALLOW_TRANSMIT` | `LISTEN_ONLY` never transmits. `ALLOW_TRANSMIT` lets the node send probe requests when it hears too little traffic. The choice is saved | | `LISTEN_ONLY` |

`CSI_CFG` takes `key=value` fields in any order:

| Field | Meaning | Unit | Range | Default |
|---|---|---|---|---|
| `SENSITIVITY=LOW` | Fewest false alarms. Sets the trigger level, `MIN_MOTION`, and `SPOTS` to the values in the preset table below | | | |
| `SENSITIVITY=MEDIUM` (or `MED`) | Sets the preset values below | | | |
| `SENSITIVITY=HIGH` | Lower trigger and shorter wait. Expect false alarms | | | |
| `SENSITIVITY=<n>` | Trigger level. A higher number needs a stronger change in the signal. `0` returns to the built-in level | score | 0, or 0.005-20 | Beta 0.140, C5 0.020 |
| `MIN_MOTION=<s>` | Time the signal must keep changing before the node reports movement | seconds | 2-60 | 8 |
| `SPOTS=<n>` | Number of transmitters that must show the movement | count | 1-12 | 2 |
| `CLEAR_AFTER=<s>` | Time without movement before the node reports `CSI_CLEAR` | seconds | 1-120 | 5 |
| `CH=<n>` | Channel to watch. `0` lets the node pick | | 0-14 | 0 |
| `BROADCAST=ON\|OFF` | `ON` lets the node transmit probe requests when it hears too little traffic. `OFF` is listen only. `OFF`, `NO`, and `0` count as off. Any other value counts as on | | | `OFF` |
| `ALLOW_RANDOM=ON\|OFF` | Includes devices with randomized MAC addresses, such as phones. `ON`, `YES`, and `1` count as on. Any other value counts as off | | | `ON` |
| `REQUIRE_CE=ON\|OFF` | **C5 only.** Drops packets that carry no valid channel estimate. `ON`, `YES`, and `1` count as on. Any other value counts as off | | | `OFF` |

The `SENSITIVITY` presets differ between firmware:

| Preset | Trigger level (Beta) | Trigger level (C5) | `MIN_MOTION` | `SPOTS` | Extra on Beta |
|---|---|---|---|---|---|
| `LOW` | 0.140 | 0.070 | 8 | 2 | An extra per-transmitter gate, set to 0.500, is switched on |
| `MEDIUM` | 0.140 | 0.070 | 8 | 1 | The extra gate is switched off |
| `HIGH` | 0.115 | 0.056 | 4 | 1 | The extra gate is switched off |

With `SPOTS=1`, the node still needs two moving devices, unless one device's score reaches 4 times the trigger level.

Rules for `CSI_CFG`:

- The node reads fields without a keyword by position: first the trigger level, then the clear time in milliseconds (500-120000), the number of consecutive hits (1-50, default 3), the channel, and last `1` or `0` for `TELEM`. Use the keyword fields instead.
- The node refuses the whole command with `CSI_CFG_ACK:INVALID` if any value is out of range.
- After a reboot the node resets a saved trigger level outside 0.005-0.600 to the built-in level, even though `CSI_CFG` accepts values up to 20.
- `CSI_STATUS` and `CSI_JSON` print to USB serial and send only the text length over the mesh. The web UI reads the same data from `/csi-json`. See the [API reference](api-reference.md).
- `CSI_EXCLUDE` takes a MAC address, or `NONE` (or nothing) to clear the exclusion. The exclusion is not saved across a reboot.

While a CSI scan runs, the node sends `CSI_MOTION` and `CSI_CLEAR` alerts. [Alerts](#alerts) lists both.

### Branch-only

| Command | Alias | Where | What it does | Reply | Example |
|---|---|---|---|---|---|
| `CONFIG_BAND` | `CB` | C5 only | Chooses the Wi-Fi band the scans use, and saves it | `CONFIG_ACK:BAND:<n>` or `:INVALID` | `@AH01 CONFIG_BAND:2` |

| Argument | Meaning | Range | Default |
|---|---|---|---|
| band | `0` 2.4 GHz, `1` 5 GHz, `2` both. A value above 2 returns `INVALID`. On any board other than the XIAO ESP32-C5 the node stores `0` | 0-2 | |

## Alerts

Nodes send these lines on their own. `NODE` is the sender's ID.

| Alert | Format |
|---|---|
| Target hit | `NODE: Target: <mac> RSSI:<n> Type:WiFi\|BLE [Name:<x>] [GPS=<lat>,<lon>] [V=<vendor>] [C=<class>]`. The node repeats a hit on one device at most every 30 seconds, unless the signal changes by 5 dB or more or the node moves |
| Device | First row `NODE: DEVICE:AA:BB:CC:DD:EE:FF W\|B <rssi> [C<channel>] [N:<name>]`. Later rows in the same message start with the bare MAC, `AABBCCDDEEFF`. `C` is Wi-Fi only. Names are cut at 30 characters |
| Baseline anomaly | `NODE: ANOMALY-NEW: <WiFi\|BLE> <mac> RSSI:<n> [Name:<x>]`, `ANOMALY-RETURN: ... RSSI:<n>dBm`, `ANOMALY-RSSI: ... Old:<n>dBm New:<n>dBm Delta:<n>dBm`, or `ANOMALY: <WiFi\|BLE> <mac> RSSI:<n> <reason> [N:<x>] [C=<class>]` |
| Deauth | `NODE: ATTACK: DEAUTH\|DISASSOC [BROADCAST]\|[TARGETED] SRC:<mac> DST:<mac> RSSI:<n>dBm CH:<n> R:<reason> [GPS:<lat>,<lon>]`. At the end of a scan the summary form is `NODE: ATTACK: DEAUTH\|DISASSOC <src>-><dst> R<rssi> C<channel>` |
| Drone | `NODE: DRONE: <mac> ID:<uavId> R<rssi> [GPS:<lat>,<lon>] [ALT:<m>] [SPD:<m/s>] [OP:<lat>,<lon>]` |
| Drone lost | `NODE: DRONE_LOST: <mac> [ID:<uavId>] AGE:<s>` |
| Triangulation reading | `NODE: T_D: <mac> RSSI:<n> Hits=<n> Type:WiFi\|BLE [GPS=<lat>,<lon> HDOP=<x>]` |
| Triangulation result | `NODE: T_F: ... GPS=<lat>,<lon> CONF=<pct> UNC=<m>`, then `NODE: T_C: MAC=<mac> Nodes=<n> [GPS=<lat>,<lon> CONF=<pct> URL=<link>]` |
| Probe hit | `NODE: PROBE_HIT <mac> [Randomized\|<vendor>] RSSI=<n> CH=<n> [SSID="<x>" [GHOST]] [DST]` |
| Packet capture | `NODE: PCAP_START: WIFI\|BLE D=<secs>`, then `PCAP_DONE: F=<frames> B=<bytes> D=<dropped> [R=WRITEFAIL\|SIZECAP]` |
| Scan complete | Device discovery `SCAN_DONE: W=<wifi networks> B=<BLE devices> U=<unique> H=<hits> TX=<sent> DUP=<skipped repeats>`. Target scan `LIST_SCAN_DONE: Hits=<n> Unique=<n> Targets=<n> TX=<sent> PEND=<unsent>`. Also `DRONE_DONE: Detected=<n> Unique=<n> TX=<sent>`, `DEAUTH_DONE: Total=<n> Deauth=<n> Disassoc=<n> TX=<sent>`, `RANDOMIZATION_DONE: Identities=<n> Sessions=<n> TX=<sent>`, and `BASELINE_DONE: Devices=<n> Anomalies=<n> WiFi=<n> BLE=<n> TX=<sent> PEND=<unsent>`. A probe scan sends no completion line |
| CSI motion (Beta, C5) | `NODE: CSI_MOTION: CH=<n> N=<transmitters> S=<score>` when movement starts, and `NODE: CSI_CLEAR: CH=<n> D=<s>s` when it ends, with the movement time in seconds. `GAP` limits how often `CSI_MOTION` is sent |
| Movement | `NODE: VIBRATION: Movement detected at <time>`. During setup mode: `VIBRATION: Movement in setup mode (active in <s>s)` |
| Tamper | `NODE: TAMPER_DETECTED: Auto-erase in <s>s [GPS:<lat>,<lon>]`, then `TAMPER_CANCELLED` if you cancel |
| Heartbeat | `NODE: Time:YYYY-MM-DD_HH:MM:SS Temp:<n>C [GPS:<lat>,<lon>]`. In battery saver: `NODE: HEARTBEAT: Temp:<n>C GPS:<lat>,<lon>\|N/A Battery:SAVER` |

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
| `PROBE_FLOOD_BEHAVE:<ssid>:src=<n>:<rssi>` and `PROBE_FLOOD_AP:...` | |
| `FRAG:<src>:<reason>` | `PN_GAP` `MIXED_PLAIN` |
| `HSHK:<bssid>:<sta>:<msg>:<replay>:<rssi>` | `M1M2` `M1M4` `M2M3` `M3M4` |
| `PMKID_HARVEST:<src>:<bssid>:<rssi>` | |
| `PMKID_FORGE:<src>:<bssid>:<rssi>` and `PMKID_FORGE:<src>:FAKE_M1:<rssi>` | `FORGE_PMKID` `FAKE_M1` |
| `EAPOL_BAIT:<src>:<sta>:<count>:<rssi>:<conf>` | `high` `medium` |
| `CSA_SPOOF:<bssid>:<count>` | count >= 50 |
| `QUIET_ABUSE:<bssid>:<tu>` | tu >= 1000 |
| `KARMA_CAND:<bssid>:<ssids>` and `KARMA_CONFIRMED:<bssid>:<rssi>` | |
| `AUTH_FLOOD:<bssid>:<srcs>:<frames>` | |
| `SAE_DOS:<bssid>:<commits>` | |
| `JAMMING:<ch>:noise_rise:<db>` | `db`: how far the noise floor rose above its learned level |
| `JAMMING_BASELINE:<ch>:silence:<fps>` | `fps`: the channel's usual frames per second |
| `RADIO_DETECTED:<radio>:<mac>:<rssi>:<name>` | `Meshtastic` `MeshCore`. `name` is empty if the radio has not sent one yet |
| `ASSOC_SLEEP` `SSID_CONFUSION` `OWE_ABUSE` `PWNAGOTCHI` `RECON` `ATTACKER_HUNT` | |

`R:` reason codes (802.11-2020 Table 9-49): `1` unspecified, `2` prev auth invalid, `3` STA leaving, `4` inactivity, `5` AP full, `6` class 2 from unauth STA, `7` class 3 from unassoc STA, `8` leaving BSS, `14` MIC failure.

</details>
