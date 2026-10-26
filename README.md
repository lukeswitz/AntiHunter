<p align="center">
  <img src="https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO/blob/main/TopREADMElogo.png?raw=true" alt="AntiHunter Command Center Logo" width="320" />
</p>

<div align="center">

[![Stable](https://img.shields.io/github/v/release/lukeswitz/AntiHunter?filter=!*-beta*&label=stable&color=2ea44f)](https://github.com/lukeswitz/AntiHunter/releases/latest)
[![Beta](https://img.shields.io/github/v/tag/lukeswitz/AntiHunter?filter=*-beta*&label=beta&color=orange)](https://github.com/lukeswitz/AntiHunter/releases)
[![C5](https://img.shields.io/github/v/tag/lukeswitz/AntiHunter?filter=*-c5exp*&label=c5&color=purple)](https://github.com/lukeswitz/AntiHunter/releases)

[![AntiHunter Discord](https://img.shields.io/badge/AntiHunter-Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/AYFzUurfmh)</br>

[![Code Quality](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/lint.yml)
[![PlatformIO CI](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/platformio.yml)
[![CodeQL](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/AntiHunter/actions/workflows/github-code-scanning/codeql)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/AntiHunter)](https://github.com/lukeswitz/AntiHunter/tree/main/Antihunter)

</div>


<div align="center">
  <h3 align="center">DIGI Detection Node Firmware</h3>
  <h4><a href="https://lectronz.com/stores/antihunter">Get one</a> • <a href="https://lukeswitz.github.io/AntiHunter/">Flash from your browser</a> • <a href="#quick-start">Quick start</a> • <a href="#hardware">DIY</a> • <a href="docs/README.md">Docs</a></h4>
  
  <strong>Companion C2: <a href="https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO">Command Center</a></strong>

  <a href="https://lectronz.com/stores/antihunter" alt="I sell on Lectronz"><img src="https://lectronz-images.b-cdn.net/static/badges/i-sell-on-lectronz-small.png" /></a>
  
  [Website](https://rootdowndigital.com/antihunter)  • [Privacy Policy](https://rootdowndigital.com/privacy)


</div>

---

## What is AntiHunter?

AntiHunter is detection firmware for the DIGI node, an ESP32 board with a Meshtastic LoRa radio. It watches Wi-Fi, Bluetooth, and a vibration sensor. It reports watchlist devices, new or missing devices, drones, attacks, jamming, and tampering, and saves everything to SD.

You control a node from its web UI, or by sending text commands from any Meshtastic radio on your channel. It needs no internet and runs on battery. Several nodes can work together to locate a device, and the [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO) shows a whole fleet on one map.

<p align="center">
  <img width="430" alt="AntiHunter node" src="docs/img/ah-hero.png" />
</p>

<p align="center"><i>Featured in Seeed Studio <a href="https://www.seeedstudio.com/blog/2026/01/29/best-xiao-projects/">Best 20 XIAO Projects in 2025</a>.</i></p>

> [!TIP]
> **New to AntiHunter?** [Start Here](docs/README.md) covers setup order and troubleshooting.

---

## What it detects

**(Beta)** features are in the Beta firmware only. **(experimental)** features may give wrong results.

### Find devices

- **[Target scan](#target-scan)** – Alerts when it hears a MAC, vendor, or network name on your watchlist.
- **[Device discovery](#recon-device-discovery)** – Lists nearby Wi-Fi access points and Bluetooth devices.
- **[Probe request scanner](#recon-probe-request-scanner)** – Shows which network names each phone or laptop is looking for.
- **[Randomized MAC tracer](#recon-randomized-mac-tracer-experimental)** (experimental) – Links a phone's changing MAC addresses back to one device.
- **[Drone Remote ID](#recon-drone-remote-id)** – Reads drone ID, position, flight data, and the operator's location.
- **[Triangulation](#locate-triangulation-experimental)** (experimental) – Three or more nodes with GPS estimate where a device is.

### Watch an area

- **[Baseline anomaly](#detection-baseline-anomaly)** – Learns which devices belong, then reports new, missing, returning, and moving ones.
- **[CSI motion](#detection-csi-motion-beta)** (Beta) – Detects people moving nearby, even through walls, from changes in Wi-Fi signals.
- **[Tamper alert](#field-controls)** – Starts a scan or sends an alert when someone moves the node.

### Detect attacks

- **[Sentinel](#detection-sentinel)** – Runs in the background and reports Wi-Fi attacks such as deauth floods, evil twins, and handshake capture. It names the tool when it recognizes one.
- **[Wi-Fi interference](#detection-sentinel)** – Alerts when a channel's noise level jumps, a sign of jamming.
- **[Attack devices](#detection-sentinel)** – Finds Pwnagotchis and Meshtastic or MeshCore radios nearby.
- **[Deauth detection](#detection-deauth)** – Logs every deauth frame and flags floods.

### Capture and respond

- **[Packet capture](#capture-packet-capture)** – Saves Wi-Fi or Bluetooth traffic to SD as a file Wireshark opens.
- **[Scheduled scans](#field-controls)** – Runs a scan at a set time, once or every day.
- **[Secure wipe](#secure-data-destruction)** – Erases the node's data on command, or automatically if someone tampers with it.

---

## Table of Contents

1. [Quick start](#quick-start)
2. [Sending commands](#sending-a-command-over-mesh)
3. [Features](#features)
4. [Using a node](#using-a-node)
5. [Mesh networking](#mesh-networking)
6. [Hardware](#hardware)
7. [Build & flash](#build--flash)
8. [Reference](#reference)
9. [Legal](#license)

---

## Quick start

The [Operator's Guide](docs/AntiHunter-Operators-Guide.pdf) covers each step in more detail. The [Assembly Manual](hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf) covers building the hardware.

1. **Attach all three antennas** before you power on.
2. **Flash the firmware** from the [Web Flasher](https://lukeswitz.github.io/AntiHunter/) in Chrome or Edge on a desktop. Pick **Full** (with web UI) or **Headless** (mesh and serial only). See [Full vs Headless](#full-vs-headless).
3. **Connect.** For Full, join the `Antihunter` Wi-Fi network (password `antihunt3r123`), open http://192.168.4.1, and log in as `admin` with the same password. For Headless, open a serial monitor at 115200 baud.
4. **Set the radio's LoRa region.** Without it, the radio never transmits. See [Radio setup](#radio-setup).
5. <a id="before-you-deploy"></a>**Lock it down.** Every unit ships with the same published defaults, so change them:
   - Change the access point name and password under System → Settings → **Access point**.
   - Set the node ID in the web UI, or with `CONFIG_NODEID` over mesh.
   - Make your own encrypted Meshtastic channel primary and turn off the public one.
   - Write down the erase key the flasher shows. See [Secure data destruction](#secure-data-destruction).
6. **Run a scan.** Scan only where you have permission. See the [legal disclaimer](#legal-disclaimer).

---

## Sending a command over mesh

Send a text message from any Meshtastic radio on the node's channel. It has up to three parts separated by `:`: who it is for, the command, and its values.

```
@ALL DEVICE_SCAN_START:2:300
│    │                 │ └─ how long, in seconds (up to 86400), or FOREVER
│    │                 └─── which radio: 0 Wi-Fi, 1 Bluetooth, 2 both
│    └───────────────────── the command, or its short alias (DS)
└────────────────────────── who: @ALL for every node, @AH01 for one node
```

`@ALL STOP` stops every running scan. These short aliases work in place of the full command:

| Command | Alias | Command | Alias | Command | Alias |
|---|---|---|---|---|---|
| `SCAN_START` | `SS` | `DRONE_START` | `DR` | `PCAP_START` | `PCS` |
| `DEVICE_SCAN_START` | `DS` | `DEAUTH_START` | `DA` | `TRIANGULATE_START` | `TS` |
| `PROBE_START` | `PS` | `SENTINEL_ON` / `_OFF` | `SE1` / `SE0` | `VIBSCAN_SET` | `VSS` |
| `RANDOMIZATION_START` | `RS` | `CSI_MOTION_START` (Beta) | `CIM` | `SCHED_ADD` | `SA` |
| `BASELINE_START` | `BLS` | `STATUS` | `ST` | `STOP` | `X` |

Two settings apply to most scans. The node ignores devices weaker than −95 dBm, which you can change with `@ALL CONFIG_RSSI:-80`. Scans that hop channels use channels 1-11, which you can change with `@ALL CONFIG_CHANNELS:1,6,11`.

The [mesh command reference](docs/mesh-commands.md) lists every command, value, and reply.

---

## Features

Each feature starts from the web UI or with a mesh command. They follow the order of the list in [What it detects](#what-it-detects).

### Target scan

The node alerts in the web UI and over the mesh when it hears a device on your watchlist. A watchlist entry can be a full MAC, a vendor prefix (the first three bytes of a MAC), a tracer ID (`T-xxxx`), or a network name.

<p align="center">
  <img width="880" alt="Target Scan" src="docs/img/target-scan.jpg" />
</p>

**Start:** add entries under **Targets**, then go to Scan tab → Target Scan → **Start Scan**.

**Over mesh:** `@ALL CONFIG_TARGETS:AA:BB:CC:DD:EE:FF|T-00A3|MyNetwork` sets the watchlist. Then `@ALL SCAN_START:2:300:1..11` scans for 300 seconds on channels 1 to 11. The channel value is required.

The scan skips devices on the [allowlist](#field-controls). Each target sends at most one mesh alert every 30 seconds, unless its signal changes by 5 dB or the node moves.

---

### Recon: Device discovery

The node lists up to 200 nearby access points and 200 Bluetooth devices, with MAC, network name, signal, and channel.

<img width="880" alt="Mesh scan results" src="docs/img/mesh-screenshot.jpg" />

**Start:** Scan tab → Device Discovery → **Start Scan**. Tick **Capture Probes** to also collect probe requests.

**Over mesh:** `@ALL DEVICE_SCAN_START:2:300:+PROBE`. The `+PROBE` part is optional.

Several nodes can share one scan with **Split across nodes**. See [Field controls](#field-controls).

---

### Recon: Probe request scanner

Phones and laptops send probe requests that name the Wi-Fi networks they want to join. This scanner records the names each device asks for.

<p align="center">
  <img width="880" alt="Probe Request Scanner" src="docs/img/probe-scanner.jpg" />
</p>

**Start:** Scan tab → Probe Request Scanner → **Start Scan**.

**Over mesh:** `@ALL PROBE_START:2:300`. By default the node sends only watchlist devices to the mesh. Add `:+ALL` to send every probe it hears.

A `~` before a name means no network answered that probe.

---

### Recon: Randomized MAC tracer (experimental)

Phones change their MAC address to avoid tracking. The tracer groups MACs that behave alike into one device with an ID such as `T-00A3`. You can use that ID in a target scan or triangulation. It tracks up to 256 devices.

<p align="center">
  <img width="880" alt="Randomized MAC Tracer" src="docs/img/randomization.jpg" />
</p>

**Start:** Scan tab → Randomized MAC Tracer → **Start Scan**. Over mesh, send `@ALL RANDOMIZATION_START:2:300`.

---

### Recon: Drone Remote ID

The node reads drone Remote ID broadcasts in the FAA, EASA, and French formats. It reports the drone ID, the operator's location, and flight data to the mesh and to `/drones.jsonl` on SD.

<p align="center">
  <img width="880" alt="Drone RID Detection" src="docs/img/drone-rid.jpg" />
</p>

**Start:** Scan tab → Drone RID Detection → **Start Scan**. Over mesh, send `@ALL DRONE_START:300`.

It listens for Wi-Fi Remote ID on channel 6. It reads Bluetooth 4 broadcasts, not Bluetooth 5 long range.

---

### Locate: Triangulation (experimental)

Several nodes listen for the same device and record its signal strength and their own GPS position. With three or more nodes that have a GPS fix, the mesh estimates where the device is.

**Start:** send `@AH01 TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60` to one node. That node runs the hunt with every other node on the mesh for 60 seconds. You can use a tracer ID (`T-xxxx`) instead of a MAC.

`@AH01 TRIANGULATE_RESULTS` returns the coordinates, the estimated error in meters, and a map link.

<details>
<summary>RF environment and calibration</summary>

Add an environment number after the duration, such as `TRIANGULATE_START:AA:BB:CC:DD:EE:FF:60:3`. It sets how fast signal fades with distance.

| Value | Environment | Use for |
|---|---|---|
| `0` | Open Sky | Clear line of sight |
| `1` | Suburban | Light foliage, scattered buildings |
| `2` | Indoor (default) | Typical rooms, some walls |
| `3` | Indoor Dense | Offices, many partitions |
| `4` | Industrial | Heavy obstruction, machinery |

For better accuracy, calibrate each node. Put a Wi-Fi access point or Bluetooth device a measured distance away, then send `@AH01 CALIBRATE:AA:BB:CC:DD:EE:FF:5` for 5 meters. The node listens for 30 seconds and keeps the result. Send `@AH01 CALIBRATE_RESET` after you move the node.

</details>

---

### Detection: Baseline anomaly

The node learns which devices are normally around, then reports devices that are new, gone, back again, or moving closer or away.

<p align="center">
<img width="880" alt="Baseline Anomaly Detection" src="docs/img/baseline.jpg" />
</p>

**Start:** Scan tab → Baseline Anomaly Sniffer → pick the learning time → **Start Scan**.

**Over mesh:** `@ALL BASELINE_START:300` learns for 5 minutes, then monitors for 300 seconds. `@ALL BASELINE_STATUS` reports progress.

Once learning ends, the **Compare from now** button (or `@ALL BASELINE_WATCH`) splits the results at the moment you press it. Devices heard only after are **New**, devices heard only before are **Gone**, and devices whose signal changed by 20 dB are **Moving**. With an SD card, the baseline survives a reboot.

| Setting | What it does | Default | Range |
|---|---|---|---|
| RSSI | Ignores devices weaker than this | −70 dBm | −40 to −80 |
| Baseline | How long it learns | 5 min | 5, 10, 15 min |
| Marked Absent | Seconds unseen before a device counts as gone | 120 | 30-600 |
| Seen Reappear | Seconds after going missing that a return is reported | 300 | 60-1800 |
| RSSI Variation | Signal change that counts as moving | 20 dB | 5-50 |

---

### Detection: CSI motion (Beta)

The node alerts when something moves nearby, even through walls. Wi-Fi signals bounce around a room, and a moving person changes how they bounce. It needs ongoing Wi-Fi traffic, and it detects movement, not a person standing still.

<p align="center">
  <img width="880" alt="CSI Motion" src="https://github.com/user-attachments/assets/3a8dbabf-d626-4daf-9eee-ce2789e026ce" />
</p>

**Start:** Scan tab → CSI Motion Detection → **Start Scan**. Over mesh, `@ALL CSI_MOTION_START:0:FOREVER` runs until `@ALL STOP`.

| Sensitivity | Behavior |
|---|---|
| **Low** (default) | Fewest false alarms. Two devices must see the movement |
| **Medium** | Two devices, or one device seeing a strong change |
| **High** | Alerts sooner. Expect false alarms |

If it alerts in an empty room, turn on **Per-packet score to serial**, note the highest `sig` value, and set **Trigger level** slightly above it.

> [!WARNING]
> If you turn off **Listen only, never transmit**, the node sends Wi-Fi probe requests when traffic is low. Anyone nearby can see them.

---

### Detection: Sentinel

Sentinel watches for attacks in the background while no other scan runs. It detects Wi-Fi attacks, Wi-Fi interference, disruption of the node's Meshtastic channel, Pwnagotchis, and Meshtastic and MeshCore radios. When it recognizes the attack tool, it names it: Marauder, MDK4, ESP Deauther, aireplay-ng, bettercap, hcxdumptool, Bruce, or Pwnagotchi.

<p align="center">
  <img width="880" alt="Sentinel" src="docs/img/sentinel.jpg" />
</p>

**Start:** Sentinel tab → **Start Sentinel**. Over mesh, send `@ALL SENTINEL_ON`.

| Command | What it does |
|---|---|
| `@ALL SENTINEL_ON` / `SENTINEL_OFF` | Starts or stops Sentinel |
| `@ALL SENTINEL_BOOT:1` | Starts Sentinel at every power-on |
| `@ALL SENTINEL_MODE:scan` | Watches all channels. `defend` watches only the node's own channel. Headless needs `scan` |
| `@ALL GROUP:dos:on` | Turns a detector group on or off: `dos`, `rogue`, `recon`, `physical`, `mesh`, `devices`, or `all` |
| `@AH01 DETECT_CFG:{"meshradio":true}` | Changes one detector setting |

These Sentinel options are off until you turn them on:
- **Attack response** triangulates, captures packets, or starts a scan after a confirmed attack.
- **Karma bait** sends one probe request every 8 seconds to lure fake access points. It is the only detector that transmits.
- **Meshtastic / MeshCore** detection adds a Bluetooth scan. It also finds your own radios, so add them to the allowlist.
- **Interference Baseline** alerts when a busy channel suddenly goes silent in `defend` mode.

**Wi-Fi Interference** is on by default. It alerts when a channel's noise level jumps 8 dB. If you move the node, turn it off and on so it relearns the noise level.

Every detection records what triggered it, on serial and in the incident log, so you can check it.

<details>
<summary>Detector groups and test coverage</summary>

| Group | Detectors |
|---|---|
| **DoS** | Deauth flood, deauth forge, broadcast deauth, AP-targeted deauth, beacon flood, auth flood, assoc-sleep, SAE DoS |
| **Rogue AP** | Evil twin, OWE abuse, Karma / MANA |
| **Recon** | PMKID harvest, probe flood, forced handshake |
| **Physical** | FragAttacks, two-channel twin, Wi-Fi interference, interference baseline |
| **Mesh disruption** | Self-spoof, channel flood, command audit |
| **Devices** | Pwnagotchi, Meshtastic, MeshCore |

- **Confirmed on hardware:** deauth flood, deauth forge, AP-targeted deauth, beacon flood, auth flood, assoc-sleep, SAE DoS, karma, evil twin, probe flood, forced handshake, Meshtastic radios.
- **Experimental:** OWE abuse, PMKID harvest, FragAttacks, two-channel twin, Wi-Fi interference, interference baseline, mesh disruption, MeshCore radios.
- **Tested against:** airgeddon, aireplay-ng, bettercap, wifite, mdk4, angryoxide, eaphammer, hostapd-mana, wifipumpkin3, hcxdumptool, and common ESP32 attack firmware.

The [mesh command reference](docs/mesh-commands.md#sentinel) lists every Sentinel command and alert.

</details>

---

### Detection: Deauth

Deauth frames knock devices off Wi-Fi. The node alerts on any broadcast deauth and on 10 deauths to one device within 10 seconds. It flags a `DEAUTH_FLOOD` at 20 deauths from one source within 10 seconds. An attacker can fake the source address.

**Start:** Scan tab → Deauth Detection → **Start Scan**. Over mesh, send `@ALL DEAUTH_START:300`.

---

### Capture: Packet capture

The node saves traffic to SD as a pcap file that Wireshark opens.

<p align="center">
  <img width="880" alt="Packet capture" src="docs/img/pcap.jpg" />
</p>

**Start:** Scan tab → Packet Capture → **Start Capture**. Over mesh, `@ALL PCAP_START:0:300:0:CH1,6,11` captures Wi-Fi for 300 seconds on channels 1, 6, and 11. `@ALL PCAP_STOP` stops it.

| Value | Meaning |
|---|---|
| Radio | `0` Wi-Fi, `1` Bluetooth |
| Duration | Seconds. Required |
| Band | `0` 2.4 GHz, `1` 5 GHz, `2` both. 5 GHz needs the C5 board |
| Channels | Optional, such as `CH1,6,11` |

> [!WARNING]
> Stop a capture before you cut power, or the end of the file may be lost.

---

## Using a node

### Full vs Headless

Both builds run the same detectors. Full adds a Wi-Fi access point with the web UI and an [HTTP API](docs/api-reference.md). Headless has no access point, so it is harder to spot.

| | Full | Headless |
|---|---|---|
| Control | Web UI, API, serial, mesh | Serial, mesh |
| Results | Results tab and `/last_results.txt` on SD | `/last_results.txt` on SD |
| Scheduled scans | Yes | Yes, once the clock is set |
| Radio footprint | Access point beacons, unless hidden | None |

### Web UI

The web UI has five tabs: **Scan**, **Results**, **System**, **Data**, and **Sentinel**. On the Scan tab, pick a scan, the radio, and a duration, then select **Start Scan**.

<p align="center">
<img width="880" alt="AntiHunter Scan tab" src="docs/img/scan-tab.jpg" />
</p>

<details>
<summary>System tab</summary>

<p align="center">
  <img width="880" alt="System tab" src="docs/img/system-tab.jpg" />
</p>

| Section | What it holds |
|---|---|
| **Diagnostics** | Uptime, memory, SD, GPS, clock, and sensors |
| **Fleet** | Nodes and radios heard on the mesh |
| Settings → **Scanning** | Signal filter, RF environment, scan profile, channels |
| Settings → **Node & mesh** | Node ID, mesh, heartbeat, repeat filter |
| Settings → **Access point** | Network name, password, web login |
| Settings → **Sensors & power** | Vibration alert and scan, Battery Saver |
| Settings → **Storage** | SD status and repair |
| Settings → **Danger zone** | Erase key, Wipe now, auto-erase, factory reset |

</details>

### Field controls

| Control | What it does | Where |
|---|---|---|
| **Allowlist** | Devices that Target Scan and Baseline ignore | Scan tab → **Allow list** |
| **Privacy Mode** | Hides MACs, network names, and GPS on screen for screenshots. Saved files still contain them | **Privacy** button |
| **Vibration trigger** | Starts a scan when the node is moved | System → Settings → **Sensors & power**, or `VIBSCAN_SET` |
| **Scheduled scans** | Runs up to 8 scans at set times, once or repeating | Scan tab → **Schedule this scan**, or `SCHED_ADD` |
| **Split across nodes** | Shares one device scan across several nodes, by radio or by channel | Scan tab → Device Discovery |
| **Campaigns** | Tags all logs between start and stop with a name, for export | Data tab, or `CAMPAIGN_START:site-a` and `CAMPAIGN_STOP` |
| **BLE classifier** | Labels Bluetooth devices by type, such as `AirPods`. On by default | Scan tab, or `BLE_CLASSIFY:0` / `1` |
| **Battery Saver** | Stops scanning and sends only a heartbeat | System → Settings → **Sensors & power**, or `BATTERY_SAVER_START:10` |

**Vibration trigger over mesh:** `@AH01 VIBSCAN_SET:1:2:60:300`

| Value | Meaning |
|------|-------|
| `1` | `1` on, `0` off |
| `2` | Scan to run: `1` discovery, `2` probe, `3` MAC tracer, `4` target, `5` drone, `6` deauth, `7` baseline, `8` packet capture |
| `60` | Scan length in seconds. `0` runs until `STOP` |
| `300` | Optional. Seconds before it can trigger again, 5 to 86400 |

**Scheduled scan over mesh:** `@AH01 SCHED_ADD:2026-10-07T21:00|86400|/scan|mode=2&secs=600` runs a 10-minute target scan every day at 21:00.

| Value | Meaning |
|------|-------|
| `2026-10-07T21:00` | First start, in the node's local time |
| `86400` | Seconds between runs. `0` runs once. Minimum 600 |
| `/scan` | `/scan` target scan, `/sniffer` device discovery, `/drone` drone detection |
| `mode=2&secs=600` | Radio (`0` Wi-Fi, `1` Bluetooth, `2` both) and run length |

`@AH01 SCHED_LIST` lists the schedule, and `@AH01 SCHED_DEL:1` deletes entry 1.

### Secure data destruction

The node can erase its settings and SD files on command, or when someone moves it while auto-erase is on. It needs an SD card. A wipe can't be undone.

Every wipe needs the **erase key**. The node makes one on first start, and the flasher shows it. **Write it down.** If you flash with **Erase device** on, the node makes a new key. Change the key under System → Settings → **Danger zone**.

To wipe:
- **Web UI:** enter the key under **Erase key** and press **Wipe now**.
- **Mesh:** send `@AH01 ERASE_REQUEST`. Paste the token it returns and your key into **Erase Answer** on the [Web Flasher page](https://lukeswitz.github.io/AntiHunter/), then send `@AH01 ERASE_FORCE:<answer>` within 5 minutes. Your key never goes over the radio.

**Auto-erase on tamper** is off by default. Five wrong keys lock erase commands for 10 minutes. The [mesh command reference](docs/mesh-commands.md#erase) has every erase command.

---

## Mesh networking

The mesh is optional, and a node works fully on its own. With a mesh, you control nodes by text message from any Meshtastic app on the node's channel. Replies and alerts come back on the same channel.

Node IDs are 2 to 5 letters or digits. Keep the radio's short name different from the node ID.

### Radio setup

The radio needs the **Serial** module on, mode **TEXTMSG**, baud **115200**, and your board's pins: `19 RX / 20 TX` on Heltec V3, `10 RX / 9 TX` on T114. It also needs a LoRa region. Soldered Core and Assembled radios ship with serial set but no region.

Set it up in the [Meshtastic app](https://meshtastic.org/docs/software/) or with the script:

```bash
pip3 install 'meshtastic[cli]' pyserial
python3 scripts/meshtastic_config.py --serial on --region US
```

### Other Meshtastic clients

Commands and alerts are ordinary Meshtastic text messages, so any client works, including [ATAK](https://meshtastic.org/docs/software/integrations/integrations-atak-plugin/) and [MQTT](https://meshtastic.org/docs/software/integrations/mqtt/).

### Reaching a node you cannot hear

Nodes between you and a distant node relay your messages, [3 hops by default and 7 at most](https://meshtastic.org/docs/configuration/radio/lora/). A radio set to the `ROUTER` or `REPEATER` role extends range further.

### Cross-scan dedup

To save airtime, the node does not resend a device it sent in the last 5 minutes. Change it with `@ALL CONFIG_DEDUP_TTL:<seconds>` (0 to 3600). Alerts are always sent.

---

## Hardware

Buy a node from the [store](https://lectronz.com/stores/antihunter), or build one from the parts below.

<img width="600" height="600" alt="AntiHunter hardware" src="https://github.com/user-attachments/assets/57cae988-b5cf-480e-a076-9bf7f3b1ded8" />

> [!IMPORTANT]
> Use a regulated 5 V supply. Unregulated batteries cause voltage instability.

### Deployment steps by tier

No tier ships with AntiHunter installed. Flash it yourself ([Quick start](#quick-start), step 2).

| Tier | What ships | What you supply |
|---|---|---|
| **Bare PCB** ([note](docs/note-tier4-bare-pcb.pdf)) | One empty board | All parts ([BOM](hw/Prototype_STL_Files/BOM-Links.md)), soldering, radio setup, a FAT32 SD card |
| **Soldered Core PCB** ([note](docs/note-tier3-populated-pcb.pdf)) | Board with all parts soldered, 8 GB card, radio configured, whip antennas | 5 V power, optional enclosure and antennas |
| **Parts Kit** ([note](docs/note-tier2-parts-kit.pdf)) | Every part, loose, except the GPS antenna and batteries | Assembly, radio setup, two 18650 cells, GPS antenna |
| **Assembled** ([note](docs/note-tier1-assembled.pdf)) | Built and tested, with card, GPS antenna, and configured radio | Two 18650 cells |

### Core components

- **Seeed XIAO ESP32-S3** (8 MB flash or more), or **XIAO ESP32-C5** for 2.4 and 5 GHz ([C5 page](docs/ESP32-C5.md), testing)
- **Meshtastic board:** Heltec V3.2 (recommended) or T114
- **GPS, SD card, vibration sensor, and real-time clock**

The [assembly manual](hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf), [bill of materials](hw/Prototype_STL_Files/BOM-Links.md), and [enclosure STL files](hw/Prototype_STL_Files) cover the build.

<details>
<summary>Pinout (XIAO ESP32-S3)</summary>

| Function | GPIO |
|----------|------|
| Vibration sensor (SW-420) | 2 |
| Clock SDA (DS3231) | 3 |
| Clock SCL (DS3231) | 6 |
| GPS RX | 44 |
| GPS TX (unused) | 43 |
| SD CS | 1 |
| SD SCK | 7 |
| SD MISO | 8 |
| SD MOSI | 9 |
| Mesh RX | 4 |
| Mesh TX | 5 |

</details>

### Node types

| | Board | Sensor | Status |
|---|---|---|---|
| **DIGI** | ESP32-S3 | Wi-Fi and Bluetooth, 2.4 GHz | Stable |
| **[DIGI C5](docs/ESP32-C5.md)** | ESP32-C5 | Wi-Fi and Bluetooth, 2.4 and 5 GHz | Testing |
| **[RadarNode](docs/RADARNODE.md)** | ESP32-C5 | 24 GHz radar, then a Wi-Fi and Bluetooth sweep | Experimental |

<p align="center">
  <img width="880" alt="System Architecture" src="docs/img/architecture.png" />
</p>

---

## Build & flash

The [Web Flasher](https://lukeswitz.github.io/AntiHunter/) is the easiest way. You can also use the script or build from source.

### CLI flash

```bash
curl -fsSL -o flashAntihunter.sh https://raw.githubusercontent.com/lukeswitz/AntiHunter/main/Dist/flashAntihunter.sh
chmod +x flashAntihunter.sh
./flashAntihunter.sh        # -e erases first, -c sets device parameters, -l lists firmware
```

### Build from source

You need PlatformIO, Git, and a USB cable.

```bash
git clone https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-full -t upload        # Full: web UI on its own access point
pio run -e AntiHunter-headless -t upload    # Headless: serial and mesh only
pio device monitor -e AntiHunter-full       # serial output
```

The first build downloads about 6 GB of tools. The ESP32-C5 builds are on the `feat/c5` branch.

---

## Configuration

### RF scan presets

Pick a preset under System → Settings → **Scanning**. It sets how long the node listens on each channel and how often it scans.

| Preset | Time per channel | Wi-Fi scan every | Bluetooth scan every | Signal floor |
|--------|----------------|---------------|--------------|----------------|
| Relaxed | 300 ms | 5 s | 6 s | −80 dBm |
| Balanced (default) | 160 ms | 3 s | 4 s | −95 dBm |
| Aggressive | 110 ms | 1.5 s | 2 s | −100 dBm |

---

## Reference

- [Start Here](docs/README.md): setup order and troubleshooting
- [Operator's Guide](docs/AntiHunter-Operators-Guide.pdf): unboxing to deployment, with a printable quick-reference card
- [Mesh commands](docs/mesh-commands.md): every command, value, and alert
- [API reference](docs/api-reference.md): the Full firmware's HTTP endpoints

## Contributing

Ask questions and share builds in [Discussions](https://github.com/lukeswitz/AntiHunter/discussions) or on [Discord](https://discord.gg/AYFzUurfmh). Report bugs in [Issues](https://github.com/lukeswitz/AntiHunter/issues). Pull requests are welcome.

## Acknowledgments

Original concept and hardware design by @TheRealSirHaXalot.

This project includes code from [opendroneid-core-c](https://github.com/opendroneid/opendroneid-core-c), licensed under the Apache License 2.0. Copyright © Intel Corporation and OpenDroneID contributors

## License

Firmware: [GNU Affero General Public License v3.0](LICENSE). Hardware and documentation: as stated in their files.

## Legal disclaimer

<details>
<summary>Full Disclaimer</summary>

```
# Legal Disclaimer

AntiHunter ("AH", the "Project") comprises open-source firmware, source code, hardware designs, and associated documentation distributed for lawful, authorized defensive use only. You may operate the Project solely on infrastructure, networks, devices, radio spectrum, and datasets that you own or for which you hold explicit, written permission to assess. By downloading, compiling, flashing, assembling, energizing, or otherwise using the Project you agree to the following conditions:

- **Authorization & intent.** Use is limited to security research, blue-team training, regulatory-compliant monitoring, event security, network auditing, and other defensive activities. Offensive operations, targeted surveillance, stalking, harassment, or tracking of individuals without their informed consent are strictly prohibited. Detection, correlation, and triangulation capabilities are provided to characterize an environment you are authorized to assess, not to identify or follow persons.

- **Radio & telecommunications compliance.** You are responsible for abiding by every jurisdictional regulation governing radio frequency use, including FCC Part 15 and Part 97, CE/RED, Ofcom, and equivalent national rules; LoRa/ISM band allocations, power limits, and duty-cycle restrictions; and any licensing conditions applicable to your operating class. LoRa firmware is region-locked (868 MHz EU / 915 MHz US / 923 MHz Asia); operating a build outside its intended regulatory region may be unlawful. You must not use the Project to cause harmful interference or to interfere with authorized radio communications.

- **Interception & wiretap law.** Passive reception of radio emissions is regulated separately from network access in many jurisdictions. Depending on your location and the mode in use, capturing, storing, decoding, or disclosing frame contents, payloads, or identifiers may implicate the U.S. Wiretap Act (18 U.S.C. § 2511), the Electronic Communications Privacy Act, state two-party-consent statutes, the UK Investigatory Powers Act, or equivalent law. Determine the lawfulness of each capture mode in your jurisdiction before enabling it.

- **Privacy & data protection.** MAC addresses, device identifiers, probe request contents, BLE advertisements, and Remote ID broadcasts may constitute personal data under GDPR, UK GDPR, CCPA/CPRA, ePrivacy, and similar regimes. Collect telemetry only with a lawful basis. Obtain consent where required, minimize collection, apply retention and destruction schedules that match applicable law, and honor data-subject rights. The maintainers do not process, receive, or host your data.

- **Drone Remote ID.** Reception of broadcast Remote ID is permitted in most jurisdictions, but using Remote ID data to locate, approach, confront, or interfere with an aircraft or its operator may violate aviation, harassment, or anti-stalking law, including 18 U.S.C. § 32. Remote ID reception is not an authorization to act on what you receive.

- **Computer misuse laws.** Scanning, probing, or accessing third-party networks without permission may violate the Computer Fraud and Abuse Act, the UK Computer Misuse Act, EU Directive 2013/40, or similar statutes. Always obtain written authorization before interfacing with systems you do not control.

- **Export & sanctions.** You must ensure distribution and use complies with the U.S. EAR (including controls applicable to cryptographic and telemetry functionality), EU dual-use regulations, applicable sanctions regimes, and any contractual restrictions. The maintainers make no export classification representations and grant no export approvals.

- **Hardware, assembly & safety.** Kits, bare PCBs, and assembled units are supplied for use by persons competent in electronics assembly and operation. You are responsible for correct assembly, soldering, ESD control, antenna selection and attachment, and supply of regulated 5 V power. Operating the transceiver without a properly matched antenna may damage the hardware. Lithium cells are not supplied; sourcing, protection circuitry, charging, storage, transport, and disposal of any battery are your responsibility and carry fire and injury risk. The hardware is not certified for, and must not be used in, life-safety, medical, aviation, automotive, industrial-control, or other applications where failure could result in death, injury, or environmental damage. It is not a substitute for a certified security, alarm, or life-safety system, and detection results are advisory only, subject to false positives and false negatives.

- **Units, kits, and builds supplied by the maintainers.** These terms apply in full to units the maintainers assembled, kits and bare boards they shipped, firmware flashed with tools they published, and builds produced by following their documentation, BOM, wiring diagrams, or flashing instructions. Assembly, sale, or instruction by the maintainers creates no warranty, no certification, no fitness-for-purpose representation, and no assumption of responsibility for how a unit is later configured, deployed, or used. Once the unit is in your hands, operation and compliance are yours alone. Flashing the firmware - by the web flasher, the shell script, or any other means - is acceptance of these terms.

- **Experimental features.** Modes designated beta or experimental - including Sentinel, Triangulation, and MAC Randomization Correlation - are unvalidated, may produce inaccurate or misleading output, and must not be relied upon for operational, evidentiary, investigative, or safety decisions.

- **Operational safeguards.** Run the Project on hardened, access-controlled infrastructure. You are responsible for segregation of duties, credential management, network isolation of nodes and mesh links, and preventing unauthorized access to captured telemetry or command functions.

- **Forks and modifications.** The firmware is licensed under the GNU Affero General Public License v3.0; hardware and documentation are licensed as stated in their respective files. If you fork, redistribute, modify, manufacture, or resell the Project, you are solely responsible for supporting your derivative work, for its regulatory compliance and certification, and for any representations you make about it. The original authors and contributors are not liable for defects or legal issues introduced by third-party changes, packaging, integrations, or manufacture.

## No Warranty / Limitation of Liability

THE PROJECT - INCLUDING SOFTWARE, FIRMWARE, HARDWARE DESIGNS, AND DOCUMENTATION - IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, DETECTION EFFICACY, OR UNINTERRUPTED OPERATION. THIS DISCLAIMER SUPPLEMENTS AND DOES NOT LIMIT THE WARRANTY DISCLAIMER AND LIABILITY LIMITATION SET OUT IN SECTIONS 15 THROUGH 17 OF THE GNU AFFERO GENERAL PUBLIC LICENSE V3.0.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE AUTHORS, DEVELOPERS, MAINTAINERS, AND CONTRIBUTORS SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES (INCLUDING, WITHOUT LIMITATION, LOSS OF DATA, PROFITS, GOODWILL, EQUIPMENT, OR BUSINESS INTERRUPTION, OR DAMAGES ARISING FROM FAILURE TO DETECT, FALSE DETECTION, OR REGULATORY ENFORCEMENT ACTION) ARISING FROM OR RELATED TO YOUR USE OF THE PROJECT, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. WHERE LIABILITY CANNOT BE FULLY DISCLAIMED, TOTAL AGGREGATE LIABILITY SHALL NOT EXCEED THE GREATER OF (A) THE AMOUNT PAID, IF ANY, FOR THE COPY OR UNIT THAT GAVE RISE TO THE CLAIM OR (B) USD $0.

NOTHING IN THIS DISCLAIMER EXCLUDES OR LIMITS LIABILITY THAT CANNOT LAWFULLY BE EXCLUDED OR LIMITED, INCLUDING LIABILITY FOR DEATH OR PERSONAL INJURY CAUSED BY NEGLIGENCE, FOR FRAUD, OR ANY NON-EXCLUDABLE STATUTORY CONSUMER RIGHTS. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OF IMPLIED WARRANTIES OR THE LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO SOME OF THE ABOVE MAY NOT APPLY TO YOU.

## Responsibility for Compliance

You alone are responsible for ensuring your build, deployment, and operation comply with all applicable laws, regulations, licenses, permits, equipment authorizations, organizational policies, and third-party rights. No advice or information, whether oral or written, obtained from the Project, its maintainers, or its community channels creates any warranty or obligation not expressly stated in this disclaimer. Continued use signifies your agreement to indemnify and hold harmless the authors, developers, maintainers, and contributors from claims arising out of or related to your activities with the Project.

If you do not agree to these terms, do not build, flash, assemble, deploy, or operate AntiHunter.
```

</details>
