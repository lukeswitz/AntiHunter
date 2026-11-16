# AntiHunter v1.0.5

This release shows your erase key when you flash, adds Sentinel to Stable, and removes the fixed limits on scan results.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.5 | ESP32-S3 | v1.0.4 (2026-10-04) |
| Beta | v1.0.5-beta1 | ESP32-S3 | v1.0.4-beta1 (2026-10-04) |
| Experimental | v1.0.5-c5exp1 | XIAO ESP32-C5 | v1.0.4-c5exp1 (2026-10-04) |

## Highlights

- Every flash method now shows the node's erase key. You need this key for every wipe, so write it down.
- Sentinel is now in Stable. It stays off until you start it.
- Scans no longer stop recording at a fixed device count, such as 200 Wi-Fi devices.
- Headless can now schedule scans, watch a baseline, and send commands to other nodes from its USB port.
- Scans can hear Bluetooth 5 long range, which some drones use for Remote ID.
- The Full web UI has a new Settings area, a login page, and cleaner results.

## Before you upgrade: write down your erase key

The erase key is a password you choose or the node makes for you. A wipe from the web UI or over the mesh only runs with it. This applies to every channel and to both Full and Headless.

### Get the key after you flash

1. Flash v1.0.5 as usual. Leave **Erase device** unchecked if you want to keep your settings and your current key.
2. Keep the node plugged in. Where the key appears depends on how you flashed:
   - **Web flasher:** in step 2, press **Show my erase key** and pick the same port. The key appears within a minute.
   - **Flasher script** (`flashAntihunter.sh`): after flashing, the script waits up to 90 seconds and prints the key in a box.
   - **PlatformIO** (`pio run -t upload`): after the upload, it waits up to 90 seconds and prints the key.
3. Write the key down and keep it somewhere safe.
4. Optional: replace it with a key of your own. A key is 8 to 64 characters and can't contain `:`.
   - Full web UI: System tab → **Settings** → **Danger zone**.
   - Over the mesh or USB: `CONFIG_ERASE_PSK:<new key>:<current key>`.

### When the node shows the key

- The node shows the key it made at every boot, on USB serial at 115200 baud, until you set your own.
  - A Full node also shows it under **Danger zone** → **Your erase key**.
- Once you set your own key, the node never shows it again. The flashers say the node keeps the key you set.
- A node upgraded from v1.0.4 keeps its old key. If v1.0.4 made that key, v1.0.5 shows it.
- The access point password no longer works as the erase key.

### If you lose the key

1. Reflash the node with **Erase device** checked. With the flasher script, add `-e`.
2. Read the new key as in the steps above.
3. Your settings come back from the SD card. The access point and web passwords go back to their defaults, so set them again.

### Wipe a node over the mesh

Mesh wipe commands no longer carry the key. The node gives you a one-time token, and you send back an answer made from it and your key.

1. Send `@<NODE> ERASE_REQUEST`. The node replies `ERASE_TOKEN:` and a token.
2. Open **Erase Answer** on the [web flasher page](https://lukeswitz.github.io/AntiHunter/). Paste the token and your key, then press **Get answer**.
   - The page works out the answer in your browser and sends your key nowhere.
3. Within 300 seconds, send the command with the answer, such as `@<NODE> ERASE_FORCE:<answer>`.

The same answer works for `ERASE_FORCE`, `ERASE_CANCEL`, `AUTOERASE_ENABLE`, `AUTOERASE_DISABLE`, and `FACTORY_RESET`.

- Each token allows one try. Someone who records the command can't replay it.
- The node answers one `ERASE_REQUEST` every 20 seconds.
- Five wrong answers lock erase commands for 10 minutes, on the web UI and the mesh.
- The key is never written to the SD card. Logs show it as `***`.

The full walkthrough is on the wiki at [Secure wipe](https://github.com/lukeswitz/AntiHunter/wiki/Secure-wipe).

## New

### Security

- The Full web UI now asks for a login. The user name is `admin`. The password is the access point password until you set your own.
  - Set a web password under System tab → **Settings** → **Access point** → **Web login**. It is 8 to 63 characters, with no `:`.
  - **Require login** in the same place turns the login off. Changing either setting needs the current web password.
  - Neither setting can be changed over the mesh.
- Mesh wipe commands now use a one-time answer instead of the erase key. See [Wipe a node over the mesh](#wipe-a-node-over-the-mesh).

### Mesh and Headless

- Most mesh commands have short aliases, such as `SS` for `SCAN_START` and `X` for `STOP`.
  - The [mesh command reference](https://github.com/lukeswitz/AntiHunter/blob/main/docs/mesh-commands.md) lists every alias.
- Command names, node IDs, and `@ALL` are no longer case-sensitive.
- `SUMMARY` replies with the scan state, device, target, and hit counts, incidents, the current campaign, and uptime.
- Full's `STATUS` reply now ends with the reason for the last reset, as Headless does.
- Device scans now pack several devices into each mesh message, so results reach other radios with fewer messages.
- Full's Schedule dialog can now schedule a scan on another mesh node, not only on this one.
- `DEVICE_SCAN_START` takes an optional channel list, such as `CH1,6,11`. In a split scan, each node sweeps only its own channels.
- Headless can now schedule scans and watch a baseline, as Full does.
- Full now sends a baseline summary over the mesh when a baseline ends, as Headless does.
- `FLEET_SEND:<node> <command>`, typed on a node's USB serial port, sends one command to another node over the mesh.
  - A laptop with a Headless node on USB can command every node it hears. Use `ALL` as the node to reach them all.
  - See [How to run several nodes](https://github.com/lukeswitz/AntiHunter/wiki/How-to-run-several-nodes) on the wiki.
- `FLEET` on a Headless node's USB port prints every node and radio it has heard as JSON, as Full does.
- A campaign tags a node's logs with a name you choose, so you can pull one survey out of the logs later.
  - Use `CAMPAIGN_START:<name>`, `CAMPAIGN_STOP`, and `CAMPAIGN_STATUS`. A campaign keeps running after a reboot.
  - `scripts/campaign_report.py` summarizes a copied Headless SD card by campaign or by date.
- `PROBE_DB_CLEAR`, `BASELINE_RESET`, `RANDOMIZATION_RESET`, and `DETECT_CLEAR` now work over the mesh. Before, only the Full web UI could clear this data.
- `PCAP_AUTO:<budget MB>,<keep free MB>` is a new mesh command for the packet captures that Attack response starts on its own.
  - When those captures pass the budget, or free SD space drops below the second number, the node deletes the oldest ones.
  - The defaults are 512 MB and 256 MB. On Full, the same limits are on the Sentinel tab under **Attack response**.
- `DETECT_COUNTS` replies with how many devices each Sentinel detector is tracking, such as Karma candidates, Pwnagotchis, and handshakes.
- Headless results now show the same detail as Full: Wi-Fi security, target hits, range, signal trend, and the networks a device probed for.
- Beta and C5 can use a radio running MeshCore instead of Meshtastic.
  - Switch with `MESHCORE_ON` or `MESHCORE_OFF` on the USB port, or with the **MeshCore radio** switch in the Full web UI.
  - A node uses one radio type at a time. Meshtastic and MeshCore radios can't hear each other, so put every node on the same type.
  - With MeshCore on, `meshcore-cli` on the node's USB port reaches the radio, so you can change its settings without unplugging it.
  - A MeshCore reply too long for one message is split. Every part but the last ends with ` +`.
  - See [MeshCore radio setup](https://github.com/lukeswitz/AntiHunter/wiki/MeshCore-radio-setup) on the wiki.

### Bluetooth

- `BLE_LONGRANGE:1` adds Bluetooth 5 long range to scans. It is off by default.
  - Long range takes listening time from ordinary Bluetooth. In a bench test, a window heard 25 devices with it on, 31 off.
- `BLE_CLASSIFY:0` turns off the Bluetooth device classifier to save processing time. It is on by default.
- The classifier now reads every data block in a Bluetooth advertisement, not only the first one.

### Web UI

- The System tab has one menu for **Diagnostics**, **Fleet**, and every settings section.
- **Set RTC from this browser's clock** on the System tab sets the node's clock from your browser.
- Paper dark is the new default theme.
- Results show each network's Wi-Fi security and list target hits first.
- One sort menu now works on every results list.
- The Data tab adds a campaign picker, date filters, and summary tiles.
- The Data tab can start and stop a campaign on several nodes at once.
- The Sentinel tab adds a Privacy button that hides names and addresses, and a **Mesh Radios Nearby** card.
- **Clear All Events** on the Sentinel tab now also clears the mesh command log.
- The web flasher's Sentinel settings add switches for the two new detectors: **LoRa Mesh Radios** and **Interference Baseline**.
- **Split across nodes** moved to the Scan tab. It appears under Schedule when you pick Device Discovery.
- The baseline button is now called **Compare from now**.
- Help text and messages are shorter. Bloom Gossip is now called Baseline Sharing.
- Confirm prompts now open inside the page and work from the keyboard.
- Full shows the terms of use once and saves your answer on the SD card.

### Detection

- `CALIBRATE:<mac>:<meters>` calibrates distance estimates from a device you place at a measured distance from the node.
  - The calibration is saved to the SD card. It survives reboots and flashes with **Erase device** checked.
- Sentinel can spot Meshtastic and MeshCore radios nearby. It is off by default. Turn it on with `GROUP:devices:on`.
  - `RADIO_KNOWN_ADD:<mac>:<type>` adds one of your own radios to a list that never raises an alert.
- Sentinel now alerts when the noise floor on a Wi-Fi channel jumps, which can mean interference.
  - `jam_baseline`, off by default, also alerts when a busy channel suddenly goes silent. Turn it on with `DETECT_CFG:{"jam_baseline":true}`.
- The **Recon / Harvest** card on the Sentinel tab now lists Pwnagotchi sightings. They also count on the **Deauth Flood** and **PMKID** cards.
- Target results show **Getting closer** or **Moving away**. The **Movement** switch hides these labels.
- Malformed Bluetooth alerts now include the raw advertisement bytes.
- Each Sentinel incident now records what triggered it.
- The target list now accepts tracer IDs, such as `T-00A3`, as well as MAC addresses.
- Vibration alerts now include the pulse count and the time since the last alert.
- Packet captures now record the data rate (MCS) of 802.11n frames.

## Fixed

### Security and privacy

- The node now uses random Wi-Fi and Bluetooth addresses from boot, instead of its factory addresses.
- Karma bait probes now use a new random address and network name each time. Before, every probe came from one fixed address.
- The web UI now refuses requests that come from other websites.
- The web UI no longer sends the access point password to your browser.
- The access point password is no longer saved to the SD card.
- Device and network names heard over the air can no longer inject a mesh command or HTML into the web UI.

### Mesh commands

- A command now runs only when it is addressed with `@<NODE>` or `@ALL`.
  - Before, any unaddressed line ran, including other people's Meshtastic messages on the channel.
- A command now runs only when its full name matches. Before, some commands ran on any line that began with their name.
- Scan start commands with an invalid or missing field now reply `INVALID`. Before, they stayed silent or started a scan anyway.
- `SENTINEL_MODE` and `ATTACKER_TRILAT` now reject invalid values and leave the setting unchanged.
- `SENTINEL_STATUS` now shows Sentinel as on while a scan has paused it.
- `LIST_SCAN_DONE` and `BASELINE_DONE` now report the real number of alerts sent.
- `CAMPAIGN_START` now refuses a name with invalid characters instead of quietly shortening it.
- `CONFIG_TARGETS` sent over the mesh now separates entries with `|`, because mesh messages can't contain line breaks.
- Turning off every follow-up action in Attack response now turns Attack response itself off.
- Bursts of replies no longer lose lines on Meshtastic radios.
- Commands from USB, the mesh, and the scheduler now run one at a time, in order.
- Commands typed on USB no longer get lost or merged with the line before.
- `STOP` now cancels an Attack response that is waiting to start.
- `ERASE_FORCE` now replies when the wipe finishes, fails, or is already running.
- `FACTORY_RESET` now reports success or failure over the mesh before the node reboots.
- A Wi-Fi channel range with a huge end, such as `1..2147483647`, no longer hangs the node.
  - This affects `CONFIG_CHANNELS`, scan commands, and the web UI's Wi-Fi channel field. The node now ignores channels it can't use.
- A device scan with no channel list now sweeps the share this node got from a channel split.
- Headless now replies `FAILED` when it can't start a scan. Before, it replied `STARTED`.
- An interrupted scheduled scan on Headless now resumes.
- `VIBSCAN_SET` now refuses a packet capture with no duration, which never captured anything.
- Stable no longer accepts the CSI command aliases, because only Beta and C5 have CSI.

### Scans and storage

- Device scans kept only 200 Wi-Fi and 200 Bluetooth devices. They now have no fixed limit.
- Bluetooth kept 200 devices per scan window. It now keeps every device.
- Target scans kept 1,000 hits. Each target now gets one row, with no limit.
- Probe scans kept 100 devices, and the probe database kept 500. Neither has a fixed limit now.
- Deauth detection stopped counting at 2,000 attacks. It now counts every one.
- The randomized MAC tracer stopped at 128 sessions. It now has no fixed limit.
- The device database held 2,000 devices. It now has no fixed limit.
- The SD card now holds every device. Memory holds only the devices from the current scan.
  - The device and probe databases are `/devicedb.bin` and `/probedb.bin`. Older files are converted on the first start.
  - A device that returns in a later scan gets its counts back from the SD card.
  - The device total is an estimate. It can read about 1% low at 200,000 devices.
  - When memory runs low, the randomized MAC tracer moves its oldest sessions to the SD card instead of skipping new ones.
- The baseline stores every device on the SD card. The **SD Device Storage** setting is gone.
- If a record can't be written to the SD card, the node counts it. The count shows on the System page, as `NotSaved:` in `SUMMARY`, and as `NS=` in `SCAN_DONE`. The web UI also shows a warning.
- A device that returns during a baseline is now read back from the SD card, instead of being counted as new.
- Saves now write to a temporary file first, so a power cut can't corrupt them.
- The system log now rolls over to `/antihunter_old.log` when it reaches 1 MB.
- Device scans now add devices to the device database even with mesh off.
- Saving a target list that is too large now reports an error.
- Without a working SD card, scans no longer run far past their set time.
- Every setting change now saves to the SD card at once and survives a reboot.
  - This fixes Sentinel starting again at boot after you turned it off.
- `FACTORY_RESET:CONFIG` now also removes the settings file from the SD card.
- If the board's built-in memory is wiped, the node now rebuilds its Sentinel settings from the SD card.

### Sentinel and detectors

- Sentinel no longer reports your own nodes' access points and mesh radios as threats.
- Nodes using the default network name no longer flag each other as evil twins.
- An access point that reboots is no longer reported as an evil twin.
- `EAPOL_BAIT` now needs two disconnects before it fires. One ordinary disconnect no longer raises the alert.
- Wi-Fi interference detection never alerted. It now alerts when a channel's noise floor rises.
- During a beacon flood, the detector queue now keeps room for handshake frames.
- A flood of fake PMKID sources can no longer use up the node's memory.
- 16 missing detector cards are back on the Sentinel tab.
- The raw `/detect` page updates again.
- The Karma and handshake cards now show real counts.
- Every incident type is now logged once, including alerts from other nodes.
- Sentinel age columns no longer show hundreds of thousands of hours.
- The tracer now links addresses only on evidence from the device itself, not on signal strength and timing.
- The tracer no longer hangs the node when a scan stops early.

### Stability

- With Sentinel on, the node could reboot at the end of a scan that used Bluetooth. It was rare: 2 times in 28 bench runs.
  - The node now stops Bluetooth before Sentinel resumes. It passed 40 scans in a row without a reboot.
- Battery saver no longer freezes the node by turning off Bluetooth while a scan still uses it.
- Battery saver now lowers the CPU clock to 80 MHz to save power.
- Battery saver no longer sends false GPS lost and GPS locked alerts.
- Starting Bluetooth no longer leaks memory.
- The task that receives mesh messages now has twice the memory for its stack, so it can't run out.
- A wrong-key lockout no longer starts again by itself after 24.8 days of uptime.
- Stable and Beta no longer reset with a stack error during boot.
- Headless with Sentinel on no longer fails every Wi-Fi scan.
- A failed triangulation setup on Headless no longer leaves the node stuck.

### Triangulation

- A distance calibration is no longer overwritten when the next triangulation starts.
- Stopping a triangulation while it waits for other nodes now cancels it.
- Helper nodes no longer wait 30 seconds for a stop message that never comes.
- Headless coordinators on Beta and C5 now wait for the other nodes' reports before working out a position.
- A **Peer link** status replaces the misleading "Clock Sync" line in triangulation results.
- Fake node names can no longer fill up the triangulation timing table.
- On Full, a single-node `TRIANGULATE_START` now accepts a tracer ID as the target.

### Web UI and data

- Times now show in the node's local time zone, which it sets from GPS.
- System log lines now show the time zone after the time.
- At midnight UTC, the clock no longer jumps back a day.
- The Data tab's baseline view no longer always shows 0 devices.
- Vendor names are now short brand names, such as Sony or Nokia.
- Apple and Microsoft Bluetooth devices are now labeled correctly.
- The results list now scrolls inside its own pane instead of the whole page.
- Privacy mode now also hides names and addresses on the Data tab.
- This node no longer appears twice in node lists.
- On Beta and C5, Full now reports an error when a scan can't start.

### C5 (Experimental)

- With **Band** set to 2.4 GHz, scans also swept 5 GHz, timed out, and found no networks. They now sweep only 2.4 GHz.
- Scans no longer fail to start when the air is busy with Wi-Fi traffic.
- Headless no longer drops the 5 GHz channels after its first scan.
- The boot log no longer shows a memory allocation error.
- C5 builds use Arduino core 3.3.12, which fixes a memory overwrite when Bluetooth starts.
- Building the C5 firmware now needs PlatformIO Core 6.2.0 or later.
- The firmware now resets the Wi-Fi hardware at every boot, so state left from before a USB reset can't corrupt memory.

### New in Stable

These fixes come to Stable in this release.

- With mesh turned off, the node no longer sends mesh messages.
- The drone scan no longer frees its queue while the radio still uses it.
- Frame counters no longer lose counts.
- A slow mesh send no longer holds up the GPS clock sync.
- Headless now updates its drone results every second during a scan, as Full does.
  - Mesh alerts are unchanged: one `DRONE` alert per drone, and `DRONE_LOST` after 2 minutes without a sighting.
- The Full access point now sends beacons with the old 802.11b rates off.
- Each scan mode in the Full web UI now shows a short description.
- The boot log now shows the build ID and the free SD card space.

### Flashers

- Both flashers sent auto-erase timings 1,000 times too short, which could make auto-erase wipe within a second of a trigger.
  - **If you set those timings with a flasher, set them again under Danger zone.**
- The web flasher's custom scan timings now apply. Choose them under **RF Preset** → **Custom**.
- A comma-separated target list in either flasher now becomes separate targets.
- The web flasher now sends Sentinel settings to Stable nodes too.

## Removed

- HTTP routes that nothing used. Use `/scan`, `/stop`, and `/results` instead.
- The route that reloaded the vendor (OUI) list, and the LittleFS library.
- The Bluetooth attack detector, which no build ever included.

## For developers

- Full stores its web page gzip-compressed, which saves about 300 KB of flash.
- CI runs host tests for the device table, the classifier, CSI, and MeshCore.
- The `[HEAP]` serial line shows the free stack of the mesh receive task.

## Firmware size

Full builds are smaller because the web page is compressed. Headless builds are larger because of the new features.

| Build | v1.0.4 | v1.0.5 | Change | App partition used |
|---|---|---|---|---|
| Stable full | 2,601,872 B | 2,418,672 B | -183,200 B | 77.8% -> 72.4% |
| Beta full | 2,787,152 B | 2,482,496 B | -304,656 B | 83.4% -> 74.3% |
| C5 full | 3,141,952 B | 2,850,192 B | -291,760 B | 74.9% -> 68.0% |
| Stable headless | 1,897,584 B | 2,048,640 B | +151,056 B | 56.8% -> 61.3% |
| Beta headless | 1,966,272 B | 2,099,472 B | +133,200 B | 58.8% -> 62.8% |
| C5 headless | 2,321,776 B | 2,475,600 B | +153,824 B | 55.4% -> 59.0% |

C5 sizes exclude the 64 KiB bootloader and partition table.

## Upgrade

Flashing keeps your settings, erase key, and SD files unless you check **Erase device**. After flashing, read your erase key as described in [Before you upgrade](#before-you-upgrade-write-down-your-erase-key).

Each build is on the release page with a `SHA256SUMS` file to check your downloads.

| | Stable | Beta | Experimental (C5) |
|---|---|---|---|
| Web flasher channel | Stable | Beta | Experimental, ESP32-C5 |
| Flasher script channel | 1 | 2 | 3 |
| Branch | `main` | `beta` | `feat/c5` |
| PlatformIO, Full | `AntiHunter-full` | `AntiHunter-full` | `AntiHunter-c5-full` |
| PlatformIO, Headless | `AntiHunter-headless` | `AntiHunter-headless` | `AntiHunter-c5-headless` |

Web flasher: open [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge.

Flasher script (needs Python 3, esptool, and pyserial):

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

PlatformIO (`-t upload` keeps your settings and the SD card):

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git   # or -b beta, or -b feat/c5
cd AntiHunter
pio run -e AntiHunter-full -t upload        # Full, with the web UI
pio run -e AntiHunter-headless -t upload    # Headless, mesh and USB only
```

On C5, use the `AntiHunter-c5-full` and `AntiHunter-c5-headless` environments.
