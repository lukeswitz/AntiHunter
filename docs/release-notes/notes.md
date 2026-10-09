# AntiHunter v1.0.5

User-set erase key, headless scheduler and baseline watch, Sentinel detector cards and mesh commands back, results UI rework, fixes.

| Channel | Version | Board | Previous |
|---|---|---|---|
| Stable | v1.0.5 | ESP32-S3 | v1.0.4 (2026-10-04) |
| Beta | v1.0.5-beta1 | ESP32-S3 | v1.0.4-beta1 (2026-10-04) |
| Experimental | v1.0.5-c5exp1 | XIAO ESP32-C5 | v1.0.4-c5exp1 (2026-10-04) |

Items marked **(Beta/C5)** need Sentinel, which Stable builds without (`AH_SENTINEL=0`).

## Erase key (all channels; read before upgrading)

- A wipe needs an erase key you set: web UI, flasher `CONFIG` `erasePSK`, or `CONFIG_ERASE_PSK:<new>:<current>`. Until then erase commands reply `ERASE_ACK:SET_KEY_FIRST`.
- Full: the AP password serves as `<current>` for setting the key, once the AP password is no longer the default. Headless: no key until set in the flasher.
- `ERASE_FORCE`, `ERASE_CANCEL`, `AUTOERASE_*` and `CONFIG_ERASE_PSK` take the key directly. HMAC token answers still work for scripts and C2; each token is valid for one answer.
- One `ERASE_REQUEST` per 20 s. 5 wrong keys lock erase commands for 10 min.
- Keys are 8-64 characters, no `:`. Boot no longer prints the key. A flasher-set key goes to NVS only and is stripped from the SD config.

## New

- Headless: `SCHED_ADD`, `SCHED_LIST`, `SCHED_DEL` scan scheduler and `BASELINE_WATCH`, same as Full.
- Mesh, Full and headless: `STATUS_BOOT:` line after `STATUS` with reset reason, previous uptime, restored results, SD mount failures and write retries.
- Mesh, Full and headless: `PCAP_AUTO[:<budgetMB>,<floorMB>]` sets auto-capture limits; `PCAP_DELETE_ALL` deletes every capture on the SD card.
- Mesh, Full and headless **(Beta/C5)**: `DETECT_JSON:<karma|pg|tsf|hshk|pwna|tof|hunts|pcap|pcaps>`, `DETECT_CLEAR:<name>`, `DETECT_COUNTS`, `DETECT_VERBOSE:ON|OFF`, `TOF_PING[:<node>]`, `KARMA_ON`/`KARMA_OFF`, `HUNT_COOLDOWN:<ms>`, `QUORUM:<type>,<n>`, `ATTACK_RESPONSE_CANCEL`.
- Detection tab **(Beta/C5)**: Pwnagotchi card; Karma bait on/off; hunt cooldown; verbose detector logging; quorum setting; pending attack response with Cancel; link to the raw `/detect` logs.
- System tab: set the RTC from the browser's clock.
- Results: WiFi rows show the advertised auth; target hits are marked by the firmware and listed first; one sorter for all result lists, and the sort menu lists only options that apply; collapsed sections stay closed.
- Target card: Targets and Allow list above the scan options; trend badges Steady and Measuring; Movement toggle in the Forever/Triangulate row.
- Results toolbar is a full-width bar with a mobile grid layout.
- Watchlist accepts hex tracer IDs (`T-00A3`).
- PCAP files carry the radiotap MCS field for HT frames.

## Fixed

- **(Beta/C5)** STOP (web and mesh) cancels a pending attack response. Before, a response armed while a scan ran started its capture after STOP, up to 15 min later.
- **(Beta/C5)** Detection tab: 14 detector cards (RID, recon, Karma, hunts, handshake, probe graph, TSF, beacon forge, PMKID forge, EAPOL bait, probe flood, assoc sleep, jamming, mesh guard, TOF) were missing from the page while their refresh code still ran.
- **(Beta/C5)** `/api/pwnagotchi` returned invalid JSON for a real pwnagotchi; the beacon text is now escaped there and in detector tables.
- Battery saver now lowers the CPU clock to 80 MHz (restores 240 MHz on exit). Before, the clock never changed.
- Headless: boot forensics (previous uptime, restored results) reach the mesh again.
- `CONFIG_TARGETS` over mesh splits on `|`; mesh text has no newlines.
- Auto-erase counts vibrations within the detection window and triggers at the configured count.
- Targets list saves on blur; the block list saves in privacy mode.
- Privacy mode redacts device-scan names and full MACs in the Data tab.
- List scan lines carry a range estimate and always highlight hits; target tokens accept any MAC separator.
- Class table counts device rows only.

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
