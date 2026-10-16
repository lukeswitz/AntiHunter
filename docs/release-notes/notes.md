# AntiHunter v1.0.5

User-set erase key, Sentinel in Stable, headless scheduler and baseline watch, Sentinel detector cards and mesh commands back, results UI rework, fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.5 | ESP32-S3 | v1.0.4 (2026-10-04) |
| Beta | v1.0.5-beta1 | ESP32-S3 | v1.0.4-beta1 (2026-10-04) |
| Experimental | v1.0.5-c5exp1 | XIAO ESP32-C5 | v1.0.4-c5exp1 (2026-10-04) |

Stable now builds with Sentinel (`AH_SENTINEL=1`): the Sentinel tab, Always-On, detector cards, incidents and the Sentinel mesh commands. Sentinel stays off until started.

## Erase key (all channels; read before upgrading)

- A wipe needs an erase key you set: web UI, flasher `CONFIG` `erasePSK`, or `CONFIG_ERASE_PSK:<new>:<current>`. Until then erase commands reply `ERASE_ACK:SET_KEY_FIRST`.
- Full: the AP password serves as `<current>` for setting the key, once the AP password is no longer the default. Headless: no key until set in the flasher.
- Over mesh, `ERASE_FORCE`, `ERASE_CANCEL`, `AUTOERASE_ENABLE`, `AUTOERASE_DISABLE` and `FACTORY_RESET` take a one-time answer to an `ERASE_REQUEST` token (the first 8 hex characters of HMAC-SHA256 of the token keyed with the erase key), not the key. A captured command can't be replayed. `CONFIG_ERASE_PSK` takes the current key. The web UI takes the key.
- One `ERASE_REQUEST` per 20 s; each token takes one attempt and expires after 300 s. 5 wrong keys or answers lock erase commands for 10 min, on the web and over mesh.
- Keys are 8-64 characters, no `:`. Boot no longer prints the key. A flasher-set key goes to NVS only and is stripped from the SD config. Keys and answers show as `***` in serial logs and `/mesh_cmd.jsonl`.

## New

- Headless: `SCHED_ADD`, `SCHED_LIST`, `SCHED_DEL` scan scheduler and `BASELINE_WATCH`, same as Full.
- Mesh, Full and headless: `PCAP_AUTO[:<budgetMB>,<floorMB>]` sets auto-capture limits.
- Mesh, Full and headless: `DETECT_COUNTS`.
- Detection tab: Clear Session (zeroes the shown counts, keeps logs); Privacy button; Clear All Events for the mesh command log; Pwnagotchi card; Karma bait on/off; hunt cooldown; link to the raw `/detect` logs.
- System tab: set the RTC from the browser's clock.
- Results: WiFi rows show the advertised auth; target hits are marked by the firmware and listed first; one sorter for all result lists, and the sort menu lists only options that apply; collapsed sections stay closed.
- Target card: Targets and Allow list above the scan options; trend badges Steady and Measuring; Movement toggle in the Forever/Triangulate row.
- Results toolbar is a full-width bar with a mobile grid layout.
- Watchlist accepts hex tracer IDs (`T-00A3`).
- PCAP files carry the radiotap MCS field for HT frames.
- Campaigns, Full and headless: `CAMPAIGN_START:<name>`, `CAMPAIGN_STOP`, `CAMPAIGN_STATUS`. While a campaign runs, SD log lines carry `[C:<name>]`. Start and stop times go to `/campaigns.csv`. The active campaign survives a reboot.
- Data tab: campaign picker, From/To date filter for every dataset, Start/Stop campaign, and a summary row (rows, time span, unique MACs, top 5 values). Date filtering needs the RTC; without it only system log lines match a campaign.
- BLE classifier on/off: Data tab checkbox or mesh `BLE_CLASSIFY:0|1`. Off skips advertisement parsing during scans. On by default; the setting persists.
- BLE classifier, headless: list and device scan results carry `C=<class>`; mesh `BLE_CLASSIFY:0|1`.
- BLE classifier reads every manufacturer, service-data and service-UUID block in an advertisement plus scan response, not only the first.
- Campaign UX: one Data tab panel starts/stops on this node and checked mesh nodes; header REC badge; Export campaign; jsonl rows carry `campaign` and filter by it; mesh `STATUS` adds `Camp:<name>`.
- `/api/fleet/send` accepts `CAMPAIGN_START:`, `CAMPAIGN_STOP`, `CAMPAIGN_STATUS`, `BLE_CLASSIFY:`.
- `scripts/campaign_report.py <sd_dir> [--list] [--campaign NAME] [--from ..] [--to ..]` summarizes a copied SD card per file, for headless nodes.

## Fixed

- STOP (web and mesh) cancels a pending attack response. Before, a response armed while a scan ran started its capture after STOP, up to 15 min later.
- Detection tab: 14 detector cards (RID, recon, Karma, hunts, handshake, probe graph, TSF, beacon forge, PMKID forge, EAPOL bait, probe flood, assoc sleep, jamming, mesh guard, TOF) were missing from the page while their refresh code still ran.
- `/api/pwnagotchi` returned invalid JSON for a real pwnagotchi; the beacon text is now escaped there and in detector tables.
- Battery saver now lowers the CPU clock to 80 MHz (restores 240 MHz on exit). Before, the clock never changed.
- `CONFIG_TARGETS` over mesh splits on `|`; mesh text has no newlines.
- Auto-erase counts vibrations within the detection window and triggers at the configured count.
- Targets list saves on blur; the block list saves in privacy mode.
- Privacy mode redacts device-scan names and full MACs in the Data tab.
- List scan lines carry a range estimate and always highlight hits; target tokens accept any MAC separator.
- Class table counts device rows only.
- BLE classes: Apple Nearby Info read the activity state from the wrong half of the byte and the Wi-Fi flag from the wrong bit; labels are now `Nearby-<state>`. Before, an active iPhone showed as `iPhone-Idle`. Apple types 0x09, 0x0A, 0x0D, 0x0E, 0x0F now read AirPlay-Target, AirPlay-Source, Tethering-Target, Tethering-Source, Nearby-Action.
- BLE classes: Microsoft beacons are labeled by MS-CDP device type (`CDP-WinDesktop`, `CDP-iPhone`, ...) and Swift Pair mode (`SwiftPair-LE|BREDR|Dual`). Before, every CDP beacon showed as `MS-XboxOne`. Service data 0xFE2C reads `FastPair`.
- Data tab search keeps the selected sort column.
- Full: the web page is gzip-compressed at build time and served with `Content-Encoding: gzip` (Stable page 451,990 B to 101,321 B). The full image is 307,096 B smaller.
- Removed `POST /api/oui/reload` and the LittleFS library. It loaded `/oui_cat.bin`, which no build or tool produces, into a table nothing read.
- Web: no CORS headers; requests are refused (`403`) when `Host` is not the node's IP, `Sec-Fetch-Site` is cross-site, or `Origin` doesn't match. Another site's page can't read from the node or send it commands, and DNS rebinding is blocked.
- Web: `GET /wifi-config` no longer returns the AP password; leaving the password field empty keeps the current one. The AP password is no longer written to the SD config.
- Web erase endpoints compare the key in constant time and share the 5-failure lockout.
- Over-the-air SSIDs and Remote ID values with control characters can no longer split a mesh line into a second command.
- OTA SSIDs are JSON-escaped in every detector log.
- A channel range such as `1..2147483647` (mesh or web) hung the node; ranges are clamped to 1-255.
- USB serial input is read by one task only. Before, a list scan read it too and could corrupt memory.
- Commands from USB, mesh and the scheduler run one at a time.
- Mesh `ERASE_FORCE` runs the wipe on its own task under the same busy guard as the web wipe, and replies `ERASE_ACK:COMPLETE` or `FAILED` when done, `BUSY` if a wipe is running.
- `VIBSCAN_SET` mode 8 (pcap) with duration 0 never captured; it is now refused.
- Headless `VIBSCAN_SET` reads the interrupt field, and an interrupted scheduled scan resumes.
- Saving a target list larger than NVS holds reports an error (`507`, `CONFIG_ACK:TARGETS:FAILED`) instead of success.
- Mesh-fed Remote ID claim and channel assignment tables are capped.
- A Device Scan started with no channel list sweeps this node's share from Reassign / `CHAN_ASSIGN`. Before, the assignment had no effect.
- Boot banner and web footer show v1.0.5.
- `TRIANGULATE_STOP` sent while the initiator waits for node ACKs cancels the run and stops the child nodes. Before, the node acknowledged the stop, then sent the cycle start and scanned for the full duration, and a new `TRIANGULATE_START` was refused until it finished.
- Stable and Beta (S3): a boot could reset with `Stack canary watchpoint triggered (ipc1)` while installing the GPIO interrupt service. The IPC task stack is 2048 bytes (was 1024); the S3 builds compile the Arduino ESP-IDF libraries with this setting.
- Stable: the mesh aliases `CIM`, `CIE`, `CIC`, `CIQ`, `CIJ`, `CIR` are removed. They map to CSI commands, which only Beta and Experimental have.

## Firmware size

App image size against the v1.0.4 release bins. Full builds shrink because the web page is stored gzip-compressed; headless builds grew from features added since v1.0.4.

| Build | v1.0.4 | v1.0.5 | Change | App partition used |
|---|---|---|---|---|
| Stable full | 2,601,872 B | 2,372,912 B | -228,960 B | 77.8% -> 71.0% |
| Beta full | 2,787,152 B | 2,430,688 B | -356,464 B | 83.4% -> 72.7% |
| C5 full | 3,141,952 B | 2,774,416 B | -367,536 B | 74.9% -> 66.1% |
| Stable headless | 1,897,584 B | 1,955,232 B | +57,648 B | 56.8% -> 58.5% |
| Beta headless | 1,966,272 B | 2,009,104 B | +42,832 B | 58.8% -> 60.1% |
| C5 headless | 2,321,776 B | 2,363,648 B | +41,872 B | 55.4% -> 56.4% |

C5 sizes exclude the 64 KiB bootloader and partition table in `.factory.bin`.

## Upgrade

Settings and SD card files survive a flash. Erase commands stay refused until you set an erase key (see above).

All three builds attach to the one v1.0.5 release.
Per channel: `antihunter-<full|headless>-<version>.bin`; C5 uses `.factory.bin`.
Also `bootloader`, `partitions` and `SHA256SUMS` per version.
Builds are reproducible; verify with `shasum -a 256`.

| | Stable | Beta | Experimental (C5) |
|---|---|---|---|
| Web flasher channel | Stable | Beta | Experimental — ESP32-C5 |
| Script channel | 1 | 2 | 3 |
| Branch | `main` | `beta` | `feat/c5` |
| PlatformIO full | `AntiHunter-full` | `AntiHunter-full` | `AntiHunter-c5-full` |
| PlatformIO mesh-only | `AntiHunter-headless` | `AntiHunter-headless` | `AntiHunter-c5-headless` |

**Web flasher**: [lukeswitz.github.io/AntiHunter](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge.
Pick the channel, then Full or Headless.

**Flasher script** (Python 3, esptool, pyserial), same on every branch:

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh
```

`-c` sets device settings; `-l` lists firmware.

**PlatformIO**: `-t upload` keeps settings and the SD card.

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
