# AntiHunter v1.0.5

This release shows your erase key at flash, adds Sentinel to Stable, and removes scan limits.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.5 | ESP32-S3 | v1.0.4 (2026-10-04) |
| Beta | v1.0.5-beta1 | ESP32-S3 | v1.0.4-beta1 (2026-10-04) |
| Experimental | v1.0.5-c5exp1 | XIAO ESP32-C5 | v1.0.4-c5exp1 (2026-10-04) |

## Highlights

- Flashing shows your erase key. Write it down; every remote wipe needs it.
- Sentinel is in Stable. It stays off until you start it.
- Scans no longer stop at a fixed device count. They run until memory is low.
- Headless can schedule scans, watch a baseline, and command other nodes from USB.
- Scans can hear Bluetooth 5 long range, which some drones use for Remote ID.
- The web UI has a new Settings area, a login, and cleaner results.

## Before you upgrade: the erase key

The erase key is the password that authorizes a wipe. This applies to every channel.

- The node makes a key on first start. Every flash method shows it.
- The node prints the key at each boot until you change it.
- A normal reflash keeps your key and does not show it again.
- Lost it? Reflash with **Erase device** checked to get a new one.
- After that reflash, settings return from SD; access point and web passwords reset.
- Change the key in the web UI or with `CONFIG_ERASE_PSK:<new>:<current>`.
- A key is 8 to 64 characters and can't contain `:`.
- The access point password no longer works as the erase key.

Mesh wipe commands now use a one-time answer instead of the key:

1. Send `ERASE_REQUEST`. The node replies with a token.
2. Answer with the first 8 hex characters of HMAC-SHA256(token, erase key).
3. **Erase Answer** on the web flasher page works this out for you.

- This covers `ERASE_FORCE`, `ERASE_CANCEL`, `AUTOERASE_ENABLE`, `AUTOERASE_DISABLE`, and `FACTORY_RESET`.
- A recorded command can't be replayed.
- The node answers one `ERASE_REQUEST` every 20 seconds.
- A token allows one try and expires after 300 seconds.
- Five wrong answers lock erase commands for 10 minutes, on web and mesh.
- The key never goes to the SD card. Logs show it as `***`.

## New

### Mesh and Headless

- Most mesh commands have short aliases, such as `SS` for `SCAN_START` and `X` for `STOP`.
- Command names, node IDs, and `@ALL` are no longer case-sensitive.
- The [mesh command reference](https://github.com/lukeswitz/AntiHunter/blob/main/docs/mesh-commands.md) lists every alias.
- `SUMMARY` replies with scan state, device, target, and hit counts, incidents, campaign, and uptime.
- Full `STATUS` now ends with the last reset reason, like Headless.
- Device scans pack several devices into each mesh message.
- Full's Schedule dialog can schedule a scan on another mesh node.
- `DEVICE_SCAN_START` takes an optional channel list. A split scan sweeps only its channels.
- Headless can schedule scans and watch a baseline, like Full.
- Full sends a baseline summary over the mesh when a baseline ends, like Headless.
- `FLEET_SEND:<node> <command>` on USB sends a command to another node.
- With it, a Headless node on a laptop can command every node it hears.
- `FLEET` on Headless USB prints the mesh roster as JSON, like Full.
- Campaigns tag a node's logs with a name, so you can pull one survey out.
- Use `CAMPAIGN_START:<name>`, `CAMPAIGN_STOP`, and `CAMPAIGN_STATUS`. Campaigns survive a reboot.
- `scripts/campaign_report.py` summarizes a copied Headless SD card by campaign or date.
- Clearing probe, baseline, tracer, and Sentinel data now works over the mesh.
- `PCAP_AUTO` caps Sentinel's capture space. Defaults: 512 MB used, 256 MB kept free.
- `DETECT_COUNTS` sends Sentinel's tracker counts over the mesh.
- Headless results show security, target hits, range, signal trend, and probed networks.
- Beta and C5 can use a MeshCore radio instead of Meshtastic.
- Switch with `MESHCORE_ON` or `MESHCORE_OFF` on USB, or the Full web switch.
- With MeshCore on, `meshcore-cli` on the node's USB port reaches the radio.
- Split MeshCore replies end each continued part with ` +`.
- See [MeshCore radio setup](https://github.com/lukeswitz/AntiHunter/wiki/MeshCore-radio-setup) on the wiki.

### Bluetooth

- `BLE_LONGRANGE:1` adds Bluetooth 5 long range to scans. It's off by default.
- Long range costs listening time: 25 devices per window on, 31 off.
- `BLE_CLASSIFY:0` turns off the Bluetooth classifier to save processing. It's on by default.
- The classifier now reads every data block in an advertisement, not just the first.

### Web UI

- The System tab has one menu for Diagnostics, Fleet, and all settings.
- Full now asks for a login. User `admin`; password is the access point password.
- Set a separate web password under **Settings** → **Access point** → **Web login**.
- **Set RTC from this browser's clock** sets the node's clock.
- Paper dark is the new default theme.
- Results show Wi-Fi security and list target hits first.
- One sort menu works on every results list.
- The Data tab adds a campaign picker, date filters, and summary tiles.
- The Data tab can start and stop a campaign on several nodes at once.
- The Sentinel tab adds a Privacy button and a **Mesh Radios Nearby** card.
- **Clear All Events** on the Sentinel tab clears the mesh command log.
- The web flasher adds **LoRa Mesh Radios** and **Interference Baseline** settings.
- **Split across nodes** moved to the Scan tab, under Schedule.
- The baseline button is now **Compare from now**.
- Help text and messages are shorter. Bloom Gossip is now Baseline Sharing.
- Confirm prompts open inside the page and work from the keyboard.
- Full shows the terms of use once and remembers your answer on SD.

### Detection

- `CALIBRATE:<mac>:<meters>` calibrates distance from a device at a measured distance.
- The calibration saves to SD and survives reboots and Erase-device flashes.
- Sentinel can spot nearby Meshtastic and MeshCore radios. Turn it on with `GROUP:devices:on`.
- `RADIO_KNOWN_ADD` stops your own radios from raising alerts.
- Sentinel alerts when a Wi-Fi channel's noise floor jumps.
- `jam_baseline`, off by default, alerts when a busy channel goes silent.
- A new Pwnagotchi card. Sightings also count on the Deauth Flood and PMKID cards.
- Target results show **Getting closer** or **Moving away**. A Movement switch hides them.
- Malformed Bluetooth alerts record the advert bytes.
- Each Sentinel incident now records what triggered it.
- The target list accepts tracer IDs such as `T-00A3`.
- Vibration alerts record the pulse count and time since the last alert.
- Packet captures include the radiotap MCS field for 802.11n frames.

## Fixed

### Security and privacy

- The node uses random Wi-Fi and Bluetooth addresses from boot, not factory ones.
- Karma bait probes use a new random address and name each time.
- The web UI refuses requests from other websites.
- The web UI no longer sends the access point password to your browser.
- The access point password is no longer saved to SD.
- Over-the-air names can no longer inject a mesh command or HTML.

### Mesh commands

- A command runs only when addressed with `@<NODE>` or `@ALL`.
- Before, any unaddressed line ran, including others' Meshtastic messages.
- A command runs only when its name matches exactly.
- Invalid scan commands now reply `INVALID` instead of staying silent or scanning anyway.
- `SENTINEL_MODE` and `ATTACKER_TRILAT` reject invalid values instead of changing the setting.
- `SENTINEL_STATUS` shows Sentinel as on while a scan pauses it.
- `LIST_SCAN_DONE` and `BASELINE_DONE` report the real number of alerts sent.
- `CAMPAIGN_START` refuses bad names instead of shortening them.
- Mesh `CONFIG_TARGETS` separates entries with `|`.
- Turning off every attack response follow-up now turns attack response off.
- Bursts of replies no longer lose lines on Meshtastic radios.
- USB, mesh, and scheduled commands run one at a time.
- USB commands no longer get lost or merged with earlier ones.
- STOP cancels a pending attack response.
- `ERASE_FORCE` replies when the wipe finishes, fails, or is already running.
- `FACTORY_RESET` reports success or failure over the mesh before rebooting.
- A huge channel range no longer hangs the node. Ranges are 1 to 255.
- A device scan with no channel list now uses this node's assigned share.
- Headless replies `FAILED` when it can't start a scan, instead of `STARTED`.
- An interrupted Headless scheduled scan now resumes.
- `VIBSCAN_SET` refuses a packet capture with no duration.
- Stable drops the CSI command aliases, since only Beta and C5 have CSI.

### Scans and storage

- Device scans kept only 200 Wi-Fi and 200 Bluetooth devices. Now there's no limit.
- Bluetooth kept 200 devices per window. It now keeps them all.
- Target scans kept 1,000 hits. Now each target gets one row, with no limit.
- Probe scans kept 100 devices; the probe database kept 500. Neither has a limit.
- Deauth detection stopped at 2,000 attacks. It now counts every one.
- The randomized MAC tracer stopped at 128 sessions. It now has no limit.
- The device database held 2,000 devices. It now has no limit.
- Below 512 KB of free PSRAM, probe and tracer scans pause adding entries.
- The baseline **SD Device Storage** setting now actually limits devices stored on SD.
- A returning baseline device is read back from SD, not counted as new.
- Saves write to a temporary file first, so power loss can't corrupt them.
- The system log now rolls over at 1 MB to `/antihunter_old.log`.
- Device scans now add devices to the database even with mesh off.
- Saving a target list that is too large now reports an error.
- Without a working SD card, scans no longer run far past their set time.
- Every setting change now saves to SD and survives a reboot.
- That fixes Sentinel starting again after you turned it off.
- `FACTORY_RESET:CONFIG` now removes the settings file from SD too.
- After a memory wipe, the node rebuilds Sentinel settings from SD.

### Sentinel and detectors

- Sentinel no longer reports your own nodes' access points and radios as threats.
- With the default network name, nodes no longer flag each other as evil twins.
- A rebooted access point is no longer reported as an evil twin.
- `EAPOL_BAIT` now needs two disconnects before it fires.
- Wi-Fi interference detection never alerted. It now alerts on a noise floor rise.
- In a beacon flood, the detector queue now keeps room for handshake frames.
- A flood of spoofed PMKID sources can no longer exhaust memory.
- 16 missing detector cards are back on the Sentinel tab.
- The raw `/detect` page updates again.
- Karma and handshake counts now show real numbers.
- Every incident type is now logged once, including alerts from other nodes.
- Sentinel age columns no longer show hundreds of thousands of hours.
- The tracer links addresses only on device evidence, not signal strength and timing.
- The tracer no longer hangs the node when a scan stops early.

### Stability

- The node no longer crashes at the end of a scan with Sentinel on.
- Battery saver no longer freezes the node by stopping Bluetooth mid-use.
- Battery saver now lowers the CPU clock to 80 MHz.
- Battery saver no longer sends false GPS lost and locked alerts.
- Starting Bluetooth no longer leaks memory.
- The mesh receive task has twice the stack, so it can't run out.
- A wrong-key lockout no longer restarts itself after 24.8 days of uptime.
- Stable and Beta no longer reset with a stack error during boot.
- Headless with Sentinel on no longer fails every Wi-Fi scan.
- A failed Headless triangulation setup no longer leaves the node stuck.

### Triangulation

- A distance calibration is no longer overwritten when the next run starts.
- Stopping a run while waiting for nodes now cancels it.
- Helper nodes no longer wait 30 seconds for a stop that never comes.
- Beta and C5 Headless coordinators now wait for the other nodes' reports.
- A **Peer link** status replaces the misleading "Clock Sync" line.
- Spoofed node names can no longer grow the triangulation timing table.
- On Full, a single-node `TRIANGULATE_START` now accepts a tracer ID target.

### Web UI and data

- Times show in the node's local time zone, set from GPS.
- System log lines show the time zone after the time.
- At midnight UTC the clock no longer jumps back a day.
- The Data tab baseline view no longer always shows 0 devices.
- Vendor names are short brand names, such as Sony or Nokia.
- Apple and Microsoft Bluetooth devices are labeled correctly.
- The results list scrolls inside its own pane.
- Privacy mode now hides names and addresses on the Data tab.
- This node no longer appears twice in node lists.
- On Beta and C5, Full reports an error when a scan can't start.

### C5 (Experimental)

- With **Band** at 2.4 GHz, scans no longer sweep 5 GHz and find nothing.
- Scans no longer fail to start under heavy radio traffic.
- Headless scans no longer drop the 5 GHz channels.
- The boot log no longer shows a memory allocation error.
- C5 builds use Arduino core 3.3.12, fixing a memory overwrite at Bluetooth start.
- Building the C5 needs PlatformIO Core 6.2.0 or later.
- The Wi-Fi hardware now resets at every boot.

### New in Stable

These fixes come to Stable in this release.

- With mesh off, the node no longer sends mesh messages.
- The drone scan no longer frees its queue while the radio still uses it.
- Frame counters no longer lose counts.
- A slow mesh send no longer holds up the GPS clock sync.
- Headless drone results refresh every second, like Full.
- The Full access point sends beacons with 802.11b rates off.
- Each scan mode in the Full web UI shows a short description.
- The boot log shows the build ID and free SD space.

### Flashers

- Both flashers sent auto-erase timings 1,000 times too short.
- That could make auto-erase wipe within a second of a trigger.
- **If you set those timings with a flasher, set them again under Danger zone.**
- The web flasher's custom scan timings now apply, via **RF Preset** → **Custom**.
- A comma-separated target list now becomes separate targets.
- The web flasher sends Sentinel settings on Stable too.

## Removed

- Unused HTTP routes. Use `/scan`, `/stop`, and `/results` instead.
- The OUI reload route and the LittleFS library.
- The Bluetooth attack detector, which no build ever included.

## For developers

- Full stores its web page gzip-compressed, saving about 300 KB.
- CI runs host tests for the device table, classifier, CSI, and MeshCore.
- The `[HEAP]` serial line shows the mesh receive task's free stack.

## Firmware size

Full builds shrank because the web page is compressed. Headless grew with new features.

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

Flashing keeps settings, the erase key, and SD files unless you check **Erase device**.

After flashing, use **Show my erase key** and write the key down.

Each build is on the release page with a `SHA256SUMS` file to check downloads.

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

PlatformIO (`-t upload` keeps settings and the SD card):

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git   # or -b beta, or -b feat/c5
cd AntiHunter
pio run -e AntiHunter-full -t upload        # Full, with the web UI
pio run -e AntiHunter-headless -t upload    # Headless, mesh and USB only
```

On C5, use the `AntiHunter-c5-full` and `AntiHunter-c5-headless` environments.
