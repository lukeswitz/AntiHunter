# AntiHunter v1.0.5

Erase key shown at flash, Sentinel in Stable, scan scheduler and baseline watch in Headless, a reworked Settings area and results page, and fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.5 | ESP32-S3 | v1.0.4 (2026-10-04) |
| Beta | v1.0.5-beta1 | ESP32-S3 | v1.0.4-beta1 (2026-10-04) |
| Experimental | v1.0.5-c5exp1 | XIAO ESP32-C5 | v1.0.4-c5exp1 (2026-10-04) |

Stable now builds with Sentinel (`AH_SENTINEL=1`). It includes the Sentinel tab, Always-On, detector cards, incidents, and the Sentinel mesh commands. Sentinel stays off until you start it.

## Erase key (all channels; read before upgrading)

- **The node makes an erase key on first start** and every flash method shows it: Web Flasher step 2 (**Show my erase key**), `flashAntihunter.sh`, and `pio run -t upload`. The node also prints it in a banner at each boot until you change it. Full shows it in **Danger zone**. Write it down.
- **A normal reflash keeps the key.** A key you set yourself is kept and not shown. A key set on an earlier version is kept.
- **Lost key:** reflash with **Erase device** checked. The node makes and shows a new key. Settings come back from the SD card; the AP password and web password go back to their defaults.
- **Change the key** with the current key: in the web UI, or with `CONFIG_ERASE_PSK:<new>:<current>`. A key you set is 8 to 64 characters with no `:`.
- The AP password no longer works as the erase key.
- **Erase Answer** on the web flasher page turns a token and your key into the answer in your browser, without `openssl`.
- **Erase over mesh.** `ERASE_FORCE`, `ERASE_CANCEL`, `AUTOERASE_ENABLE`, `AUTOERASE_DISABLE`, and `FACTORY_RESET` take an answer, not the key. Send `ERASE_REQUEST`, and the node replies with a token. Answer with the first 8 hex characters of the HMAC-SHA256 of that token, keyed with the erase key. A captured command cannot be replayed. `CONFIG_ERASE_PSK` takes the current key, and so does the web UI.
- **Limits.** A node answers one `ERASE_REQUEST` per 20 seconds. Each token allows one attempt and expires after 300 seconds. Five wrong keys or answers lock erase commands for 10 minutes, on the web and over mesh.
- **Storage.** The key lives in the node's built-in memory only, never in the SD config. Serial logs and `/mesh_cmd.jsonl` show keys and answers as `***`.

## New

**Headless and mesh**
- Headless gains the `SCHED_ADD`, `SCHED_LIST`, and `SCHED_DEL` scheduler and `BASELINE_WATCH`, matching Full.
- Full and Headless: `PCAP_AUTO[:<budgetMB>,<floorMB>]` limits captures that Sentinel starts. `budgetMB` is the total size they may use (default 512 MB). `floorMB` is the free SD space to keep (default 256 MB).
- Full and Headless: `DETECT_COUNTS` replies with the Sentinel tracker counts: Karma candidates and confirmed, Pwnagotchi, handshakes, hunts, and mesh peers.
- Full and Headless: `CAMPAIGN_START:<name>`, `CAMPAIGN_STOP`, and `CAMPAIGN_STATUS`. While a campaign runs, SD log lines carry `[C:<name>]`. Start and stop times go to `/campaigns.csv`. The active campaign survives a reboot. Mesh `STATUS` adds `Camp:<name>`.
- `BLE_CLASSIFY:0|1` turns the BLE classifier off or on. Off skips advertisement parsing during scans. It is on by default, and the setting persists. The Scan tab **Classify BLE devices** switch and the Data tab checkbox do the same. On Headless, list and device scan results carry `C=<class>`.
- `/api/fleet/send` accepts the campaign commands and `BLE_CLASSIFY:`.
- `scripts/campaign_report.py <sd_dir> [--list] [--campaign NAME] [--from ..] [--to ..]` summarizes a copied SD card per file, for Headless nodes.

**Web UI**
- System tab: one **Settings** area replaces the settings cards. A menu on the left (tabs on a phone) selects the section: **Scanning**, **Node & mesh**, **Access point**, **Sensors & power**, **Storage**, **Appearance**, **Danger zone**. Switches apply at once. Number fields under **Node & mesh** save when you leave them.
- System tab: **Set RTC from this browser's clock** sets the node's clock.
- Full: the web UI asks for a login (HTTP Digest, user `admin`). The password is the AP password until you set a web password under System tab → **Settings** → **Access point** → **Web login**, or with `webPass` in the flasher config. Turn the login off in the same place, or with `"webAuth":false` in the flasher config. Changing either in the web UI needs the current web password. Neither can be changed over mesh. Scheduled scans are not affected.
- Theme: Paper dark is the new default. Blue dark and Light remain under **Settings** → **Appearance**. In Paper dark, the default accent colors are coral for STOP and the wipe buttons and lime for the Sentinel banners. A chosen accent scheme overrides them.
- Detection tab: **Clear Session** zeroes the shown counts and keeps the logs. New: a Privacy button, **Clear All Events** for the mesh command log, a Pwnagotchi card, Karma bait on/off, hunt cooldown, and a link to the raw `/detect` logs.
- Scan tab: the split device scan moved here from the Fleet card. It is **Split across nodes** under Schedule when Device Discovery is selected.
- Scan tab, Target card: Targets and Allow list sit above the scan options. Trend badges read Steady and Measuring. A Movement toggle sits in the Forever/Triangulate row.
- Baseline: the button is now **Compare from now**. It appears only after the baseline is built and the node is monitoring.
- Results: Wi-Fi rows show the advertised auth. The firmware marks target hits and lists them first. One sorter serves all result lists and offers only the options that apply. Collapsed sections stay closed. The toolbar is a full-width bar.
- Data tab: a campaign picker, a From/To date filter for every dataset, and a summary row (rows, time span, unique MACs, top 5 values). Date filtering needs the clock to be set. Without it, only system log lines match a campaign.
- Campaigns: one Data tab panel starts and stops a campaign on this node and on checked mesh nodes. A REC badge shows in the header. **Export campaign** saves it. Rows in the `.jsonl` files carry `campaign` and filter by it.

**Detection and capture**
- The target list accepts hex tracer IDs (`T-00A3`).
- PCAP files carry the radiotap MCS field for HT frames.
- The BLE classifier reads every manufacturer, service-data, and service-UUID block in an advertisement and its scan response, not only the first.

## Fixed

**Privacy and network**
- Full and Headless set random Wi-Fi STA, SoftAP, and BLE addresses at every boot, before the radios start. Before, active Wi-Fi scans and BLE scans sent the factory MACs.
- Karma bait probes use a new random source MAC, sequence number, and SSID for each probe. Before, every bait probe came from one fixed source MAC and its SSID contained the node ID.
- The web UI sends no CORS headers. It refuses requests (`403`) when `Host` is not the node's IP, `Sec-Fetch-Site` is cross-site, or `Origin` does not match. Another site's page cannot read from the node or send it commands, and DNS rebinding is blocked.
- `GET /wifi-config` no longer returns the AP password. Leaving the password field empty keeps the current one. The AP password is no longer written to the SD config.
- Web erase endpoints compare the key in constant time and share the five-failure lockout.
- Over-the-air SSIDs and Remote ID values with control characters can no longer split a mesh line into a second command.
- Over-the-air SSIDs are JSON-escaped in every detector log.

**Mesh commands**
- A command runs only on a line addressed `@<NODE>` or `@ALL`. Before, an unaddressed line (`STATUS` on USB serial, or any Meshtastic text from a non-node sender) ran as a command.
- A command name must match exactly or be followed by `:`. Before, `INCIDENTS_CLEAR`, `INCIDENTS`, `SD_REPAIR`, `PCAP_LIMITS`, `DETECT_CFG_GET`, `ERASE_CANCEL`, `AUTOERASE_ENABLE`, `AUTOERASE_DISABLE`, and `BATTERY_SAVER_START` ran on any line that started with the name (`BATTERY_SAVER_STARTX` started battery saver), and any `CAMPAIGN_` line got a campaign status reply.
- `SCAN_START`, `DEVICE_SCAN_START`, `RANDOMIZATION_START`, and `PROBE_START` reply `<name>_ACK:INVALID` when the radio value is out of range or a field is missing. Before, the node sent no reply and the command looked lost.
- `CAMPAIGN_START` replies `CAMPAIGN_ACK:INVALID` when the name has characters outside `A-Z a-z 0-9 - _`. Before, it dropped the bad characters and started a campaign under the shortened name.
- `CONFIG_TARGETS` over mesh splits entries on `|`, because mesh text has no newlines.
- Stable no longer has the mesh aliases `CIM`, `CIE`, `CIC`, `CIQ`, `CIJ`, and `CIR`. They map to CSI commands, which only Beta and Experimental have.
- `DETECT_CFG_GET` no longer lists `mesh_guard` twice. `CONFIG_NODEID` no longer prints debug lines.
- Commands from USB, mesh, and the scheduler run one at a time.
- USB serial input is read by one task only. Before, a list scan also read it and could corrupt memory.
- Headless replies `<name>_ACK:FAILED` and stops when a scan task cannot be created. Before, it reported `STARTED` while nothing ran.
- Headless `SUMMARY` reports `Dev:<count>` from the device database, matching Full.
- Headless `VIBSCAN_SET` reads the interrupt field, and an interrupted scheduled scan resumes.
- `VIBSCAN_SET` mode 8 (pcap) with a duration of 0 never captured. The node now refuses it.
- STOP (web and mesh) cancels a pending attack response. Before, a response armed while a scan ran started its capture after STOP, up to 15 minutes later.
- `TRIANGULATE_STOP` sent while the initiator waits for node ACKs cancels the run and stops the child nodes. Before, the node acknowledged the stop, then sent the cycle start and scanned for the full duration, and a new `TRIANGULATE_START` was refused until it finished.
- Mesh `ERASE_FORCE` runs the wipe on its own task under the same busy guard as the web wipe. It replies `ERASE_ACK:COMPLETE` or `FAILED` when done, and `BUSY` if a wipe is running.
- A channel range such as `1..2147483647` (mesh or web) hung the node. Ranges are now limited to 1-255.
- A Device Scan started with no channel list sweeps this node's share from Reassign or `CHAN_ASSIGN`. Before, the assignment had no effect.
- Mesh-fed Remote ID claim and channel assignment tables are capped.

**Detectors, results, and storage**
- Detection tab: 14 detector cards (RID, recon, Karma, hunts, handshake, probe graph, TSF, beacon forge, PMKID forge, EAPOL bait, probe flood, assoc sleep, jamming, mesh guard, TOF) were missing from the page while their refresh code still ran.
- `/api/pwnagotchi` returned invalid JSON for a real Pwnagotchi. The beacon text is now escaped there and in the detector tables.
- Auto-erase counts vibrations within the detection window and triggers at the configured count.
- Vibration alerts during the auto-erase setup period had no rate limit. They now follow the same limit as other vibration alerts, one every 3 seconds.
- Battery saver now lowers the CPU clock to 80 MHz and restores 240 MHz on exit. Before, the clock never changed.
- Saving a target list larger than the built-in memory holds reports an error (`507`, `CONFIG_ACK:TARGETS:FAILED`). Before, it reported success.
- The target list saves when you leave the field. The block list saves in privacy mode.
- Privacy mode redacts device-scan names and full MACs in the Data tab.
- List scan lines carry a range estimate and always highlight hits. Target tokens accept any MAC separator.
- The class table counts device rows only.
- BLE classes: Apple Nearby Info read the activity state from the wrong half of the byte and the Wi-Fi flag from the wrong bit. Labels are now `Nearby-<state>`; before, an active iPhone showed as `iPhone-Idle`. Apple types 0x09, 0x0A, 0x0D, 0x0E, and 0x0F now read AirPlay-Target, AirPlay-Source, Tethering-Target, Tethering-Source, and Nearby-Action.
- BLE classes: Microsoft beacons carry the MS-CDP device type (`CDP-WinDesktop`, `CDP-iPhone`, ...) and the Swift Pair mode (`SwiftPair-LE|BREDR|Dual`). Before, every CDP beacon showed as `MS-XboxOne`. Service data 0xFE2C reads `FastPair`.
- The Data tab search keeps the selected sort column.
- Split scan, Schedule **Run on**, and the campaign node list listed this node twice, as "This node" and by its node ID.
- The node keeps settings in two places: its built-in memory and the SD card. If the built-in memory is wiped, the node now rebuilds the detector settings and the start-Sentinel-at-boot flag from the SD card. The erase key and the web password are the exception. They stay in the built-in memory and are never written to the card.
- A node with no campaign or schedule saved no longer logs an error line at boot.

**Build and release**
- Full: the web page is gzip-compressed at build time and served with `Content-Encoding: gzip`. The Stable page shrinks from 451,990 B to 101,321 B, and the full image is 307,096 B smaller.
- Removed `POST /api/oui/reload` and the LittleFS library. They loaded `/oui_cat.bin`, which no build or tool produces, into a table that nothing read.
- Stable and Beta (S3): a boot could reset with `Stack canary watchpoint triggered (ipc1)` while installing the GPIO interrupt service. The IPC task stack is now 2048 bytes (was 1024). The S3 builds compile the Arduino ESP-IDF libraries with this setting.
- The boot banner and web footer show v1.0.5.

**Flashers**
- The web flasher and `flashAntihunter.sh` took erase delay, erase cooldown, detection window, setup delay, and vibration scan cooldown in seconds but sent them as milliseconds. A node set up with either tool got timings 1000 times too short, so auto-erase could arm and wipe within a second of a trigger. Both now convert seconds to milliseconds. `flashAntihunter.sh -c` sent these values even with auto-erase off. If you used either tool's settings, flash again with them, or set the values under System → Settings → **Danger zone**.
- The web flasher's four scan timing fields never applied, because the flasher had no Custom preset. **RF Preset** now has **Custom**, which uses them.
- A comma-separated target list from either flasher became one invalid entry. The flashers now send one entry per line.
- The web flasher sends Sentinel settings on the Stable channel too.

## Firmware size

App image size compared with the v1.0.4 release bins. Full builds shrink because the web page is stored gzip-compressed. Headless builds grew because of features added since v1.0.4.

| Build | v1.0.4 | v1.0.5 | Change | App partition used |
|---|---|---|---|---|
| Stable full | 2,601,872 B | 2,386,592 B | -215,280 B | 77.8% -> 71.4% |
| Beta full | 2,787,152 B | 2,444,224 B | -342,928 B | 83.4% -> 73.1% |
| C5 full | 3,141,952 B | 2,789,392 B | -352,560 B | 74.9% -> 66.5% |
| Stable headless | 1,897,584 B | 1,956,800 B | +59,216 B | 56.8% -> 58.5% |
| Beta headless | 1,966,272 B | 2,011,424 B | +45,152 B | 58.8% -> 60.2% |
| C5 headless | 2,321,776 B | 2,366,048 B | +44,272 B | 55.4% -> 56.4% |

C5 sizes exclude the 64 KiB bootloader and partition table in `.factory.bin`.

## Upgrade

A flash keeps settings, the erase key, and SD card files unless you check **Erase device** in the web flasher. After flashing, use **Show my erase key** (step 2) and write the key down.

All three builds attach to the one v1.0.5 release as `antihunter-<full|headless>-<version>.bin` (C5 uses `.factory.bin`), with `bootloader`, `partitions`, and `SHA256SUMS` per version. Check a download with `shasum -a 256`.

| | Stable | Beta | Experimental (C5) |
|---|---|---|---|
| Web flasher channel | Stable | Beta | Experimental — ESP32-C5 |
| Script channel | 1 | 2 | 3 |
| Branch | `main` | `beta` | `feat/c5` |
| PlatformIO full | `AntiHunter-full` | `AntiHunter-full` | `AntiHunter-c5-full` |
| PlatformIO mesh-only | `AntiHunter-headless` | `AntiHunter-headless` | `AntiHunter-c5-headless` |

**Web flasher.** Open [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge. Pick the channel, then Full or Headless.

**Flasher script** (needs Python 3, esptool, and pyserial). It is the same on every branch. `-c` sets device settings and `-l` lists firmware.

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

**PlatformIO.** `-t upload` keeps settings and the SD card.

Stable:

```bash
git clone -b main https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload        # web UI
pio run -e AntiHunter-headless -t upload    # mesh only
```

Beta:

```bash
git clone -b beta https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload
pio run -e AntiHunter-headless -t upload
```

Experimental (C5):

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload
pio run -e AntiHunter-c5-headless -t upload
```
