# Start Here

- **[README](../README.md)**: features, settings, mesh, hardware, build.
- **[Operator's Guide](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html)** ([PDF](AntiHunter-Operators-Guide.pdf)): the node from the box to the field.
- **[Assembly Manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)**: soldering, SD card preparation, connectors, printed enclosure.
- **Tier notes**, the sheet in the box:
  - [Tier 1 Assembled](note-tier1-assembled.pdf)
  - [Tier 2 Parts Kit](note-tier2-parts-kit.pdf)
  - [Tier 3 Populated PCB](note-tier3-populated-pcb.pdf)
  - [Tier 4 Bare PCB](note-tier4-bare-pcb.pdf)

---

## Before you power anything

1. **Use regulated 5 V only.** Power the board from USB, a bench supply, a DC-DC regulator, or the UPS board. Unregulated input permanently damages the modules. Below 4.5 V the board is unstable.
2. **Never power the LoRa radio without its antenna.** Transmitting into an open port can destroy the radio's power amplifier. Fit the antenna, or the U.FL pigtail, first.
3. **Plug in one USB cable at a time.** The ESP32 and the radio share the board's power rails. With both cables plugged in, one board feeds current back into the other.

Flashing needs a **data** USB-C cable and Chrome or Edge on a desktop. Charge-only cables cannot flash, and other browsers cannot open serial ports.

---

## Pick your path

No tier comes with AntiHunter installed. You flash it yourself.

### Assembled or Soldered Core PCB

The Meshtastic radio is already flashed and configured. The ESP32 is not.

1. Fit the antennas ([Operator's Guide §3](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s3)).
2. Flash AntiHunter with the [web flasher](https://lukeswitz.github.io/AntiHunter/). Choose **Full** first.
3. Change the access point name and password.
4. Set the LoRa region, a pairing pin, and an encrypted channel ([Radio Setup](https://github.com/lukeswitz/AntiHunter/wiki/Meshtastic-radio-setup)).
5. Continue at [Setup order](#setup-order-for-a-new-node).

### Parts Kit or Bare PCB

Nothing is soldered and nothing is flashed.

1. Check the box against [what each tier includes](https://github.com/lukeswitz/AntiHunter/wiki/Choose-your-hardware).
2. Bare PCB only: buy the parts from the [BOM](../hw/Prototype_STL_Files/BOM-Links.md).
3. Solder the board with the [assembly manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf).
4. Print an [enclosure](../hw/Prototype_STL_Files/README.md) if you want one.
5. Flash Meshtastic onto the radio at [flasher.meshtastic.org](https://flasher.meshtastic.org). Then turn the Serial module on, set mode **TEXTMSG**, baud **115200**, and pins `19 RX / 20 TX` (Heltec V3) or `10 RX / 9 TX` (T114). [`meshtastic_config.py`](../scripts/meshtastic_config.py) sets all of this.
6. Continue at [Setup order](#setup-order-for-a-new-node).

### Bare XIAO ESP32-S3, no PCB

The firmware expects the full module set: LoRa radio, GPS, clock, SD reader, and vibration sensor. Wire them to the same pins as the PCB. The pinout is in [Operator's Guide Appendix A](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#appendix-a) and [Hardware](../README.md#hardware).

### Build from source

The PlatformIO environments are under [Build from source](../README.md#build-from-source). Read [CONTRIBUTING](../CONTRIBUTING.md) and the [CLA](../CLA.md) before you open a pull request.

### Several nodes

Give each node its own ID and put all of them on the same encrypted channel. Nodes relay for each other, 3 hops by default ([reaching a node you cannot hear](https://github.com/lukeswitz/AntiHunter/wiki/Meshtastic-radio-setup#reaching-a-node-you-cannot-hear)). The [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO) collects all nodes in one view. Its install steps are in [Operator's Guide §13](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s13).

---

## Setup order for a new node

| # | Step | Where |
|---|------|-------|
| 1 | Fit the antennas: 2.4 GHz on the XIAO, LoRa on the radio, GPS on the GPS module. | [§3](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s3) |
| 2 | Flash AntiHunter. Choose Full first. | [Web flasher](https://lukeswitz.github.io/AntiHunter/), [flasher script](../README.md#flash-from-the-command-line) |
| 3 | Change the access point name and password. The defaults are published in this repository. | Web UI: System tab → **Settings** → **Access point** |
| 4 | Set the radio's LoRa region. Until you do, the radio receives but never transmits. | [Radio Setup](https://github.com/lukeswitz/AntiHunter/wiki/Meshtastic-radio-setup) |
| 5 | Create your own encrypted channel, make it primary, and turn off the public channel. | [Radio Setup](https://github.com/lukeswitz/AntiHunter/wiki/Meshtastic-radio-setup) |
| 6 | Set the node ID. The node starts every message it sends with this ID. | Web UI, or `@AH01 CONFIG_NODEID:GATE1` ([§10.1](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s10-1)) |
| 7 | Set the clock. The CLI flasher and the web flasher's **Connect & Configure** button set it. GPS keeps it in sync afterward. | None needed |
| 8 | Confirm the SD card mounts and the GPS gets a fix outdoors. | [§7](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s7) |
| 9 | Tune the vibration trimpot in place, on the real mount. | [§12.2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s12-2) |
| 10 | Send `@ALL STATUS` over the mesh and confirm the node answers. | [Mesh Commands](mesh-commands.md) |
| 11 | Seal the node and deploy it. | [§14](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s14) |

---

## Decisions

| Question | Answer |
|---|---|
| **Full or Headless?** | Both builds run the same detectors, scan engine, and mesh commands. Full adds a Wi-Fi access point with the web UI and API. The access point is visible unless **Hidden network** is on. Headless has no access point and is controlled by serial and mesh only. Start with Full. Use Headless where the node must stay quiet. [Details](https://github.com/lukeswitz/AntiHunter/wiki/Full-or-Headless) |
| **Stable or Beta?** | Use Stable (`main`) in the field. Beta (`beta`) gets new features first. See the [release notes](release-notes/notes.md). |
| **S3 or C5?** | The ESP32-S3 is the stable board. The [ESP32-C5](ESP32-C5.md) fits the same pads and adds 5 GHz. It is under the flasher's Experimental channel while it is in testing. [RadarNode](RADARNODE.md) adds a 24 GHz radar to the same mesh. |
| **Do I need the Meshtastic radio?** | Not to scan. Without it, you control a node from its own access point or over USB serial, standing next to it. With it, you send commands to every node in mesh range and receive detections from them. |
| **Which SD card?** | Use FAT32. A card of 32 GB or more is not recommended. Every tier except Bare PCB includes an 8 GB card. |
| **How do I update?** | Run the flasher again on the same channel and leave **Erase device** unchecked. Settings stay on the node and on the SD card. The access point password, web password, and erase key stay on the node only. Read the release notes first. |

---

## Ten commands to know

Send these as text messages from any Meshtastic client on your channel. Each line starts with `@` and either a node ID or `@ALL`:

| Part | Meaning |
|---|---|
| `@ALL` | Every node on the channel runs the command. |
| `@AH01` | Only the node with ID `AH01` runs it. |

Every node that runs a command replies with its node ID and a result such as `SCAN_ACK:STARTED`. `BUSY` means the radio is already in use. `INVALID` means the node rejected the values.

| Command | What it does | Values |
|---|---|---|
| `@ALL STATUS` | Each node reports its state. Use it to see which nodes answer. | None |
| `@ALL STOP` | Stops every running scan. | None |
| `@AH01 CONFIG_NODEID:GATE1` | Renames a node. | `GATE1` is the new ID: 2 to 5 letters or digits. |
| `@ALL CONFIG_TARGETS:AA:BB:CC\|MyNetwork` | Replaces the watchlist that the target scan looks for. | Separate entries with `\|`. An entry is a full MAC address, the first three bytes of one (a vendor prefix, like `AA:BB:CC`), or a Wi-Fi network name. |
| `@ALL SCAN_START:2:600:1..11` | Starts a target scan. The node alerts when it hears a watchlist entry. | `2` is the radio: `0` Wi-Fi, `1` Bluetooth LE, `2` both. `600` is the run time in seconds (0 to 86400; `0` runs until `STOP`). `1..11` is the Wi-Fi channels: a range (`1..11`) or a list (`1,6,11`). The channel field is required. Put `FOREVER` in its place to run until `STOP` on the default channels 1 to 11. |
| `@ALL DEVICE_SCAN_START:2:300` | Lists every access point and Bluetooth LE device the node hears. | `2` is the radio, as above. `300` is the run time in seconds. |
| `@ALL BASELINE_START:900` | Learns which devices are normally present, then reports new, missing, returning, and moved devices. | `900` is the monitoring time in seconds after learning (60 to 86400). Learning time is a separate setting, 300 seconds by default, set in the web UI or the web flasher. |
| `@ALL SENTINEL_ON` | Starts Sentinel, which detects Wi-Fi attacks, interference, attack devices, and LoRa mesh radios. | None. `SENTINEL_OFF` turns it off. |
| `@ALL DRONE_START:0` | Starts the drone Remote ID scan. | `0` runs until `STOP`. Any other number is the run time in seconds. |
| `@AH01 BATTERY_SAVER_START:10` | Stops scanning and lowers the CPU clock. The mesh stays on. | `10` is the minutes between heartbeat messages (1 to 30, default 5). `BATTERY_SAVER_STOP` ends it. |

Most commands also have a short alias, such as `SS` for `SCAN_START`. [Mesh Commands](mesh-commands.md) lists every command, value, reply, and alias. To control a node over HTTP instead, see the [API Reference](api-reference.md).

---

## Something is wrong

| Symptom | Usual cause | Fix |
|---|---|---|
| The `Antihunter` Wi-Fi network does not appear. | Headless is flashed, you changed the network name, or **Hidden network** is on. | Check over serial which build is running. Flash Full if you need the web UI. |
| The web UI does not load. | Your device is not on the node's access point, or the browser forced https. | Join the access point and open `http://192.168.4.1` exactly. Log in as `admin`. |
| Flashing fails, or no serial port appears. | You used a charge-only cable, another program holds the port, both USB ports are plugged in, or the browser is not Chrome or Edge. | Use a data cable, close other serial tools, unplug the radio, and use Chrome or Edge. |
| The SD card is not detected. | It is not FAT32, it is 32 GB or larger, or it is not seated. | Reformat it as FAT32, or use a card under 32 GB. |
| There is no GPS fix. | The antenna is disconnected, or the node has no view of the sky. | Check the U.FL or SMA connector and go outdoors. |
| Nothing arrives over the mesh. | The radio has no region and is receive-only, the Serial module is off, the pins are wrong, or the nodes use different channels or keys. | Run [`meshtastic_config.py`](../scripts/meshtastic_config.py) and print the settings. Every node needs the same channel and key. |
| A node receives commands but never answers. | Its radio has no region, so it cannot transmit. | Set the region. |
| A node scans until you stop it. | The scan started with `FOREVER` or a duration of `0`. | Send `@ALL STOP`, or select Stop in the web UI. |
| Settings are gone after flashing. | **Erase device** was checked, and the SD card had no saved config. | Configure the node again. It also has a new erase key: use **Show my erase key** and write it down. |
| Lost the erase key. | | Reflash with **Erase device** checked, then **Show my erase key**. Settings come back from the SD card; the AP password and web password go back to their defaults. |
| Vibration alerts never stop. | The trimpot is too sensitive, or the mount resonates. | Retune in place ([§12.2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s12-2)) and pad the mount. |
| Detections have no coordinates. | The GPS had no valid fix at that moment. | None. The node attaches a position only when the fix is valid. |

The full symptom table, the factory reset, and what to include in a bug report are in [§15](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s15). For help, use [Discussions](https://github.com/lukeswitz/AntiHunter/discussions) or [Discord](https://discord.gg/AYFzUurfmh). Remove coordinates and MAC addresses from anything you paste.

---

## Everything else

### Hardware

- [Assembly manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf) (PDF)
- [BOM links](../hw/Prototype_STL_Files/BOM-Links.md): every part with a buy link
- [Enclosures and STLs](../hw/Prototype_STL_Files/README.md)
- [Welcome letter](../hw/Prototype_STL_Files/ahwelcome.txt)
- [What each tier includes](https://github.com/lukeswitz/AntiHunter/wiki/Choose-your-hardware)
- Tier notes (PDF):
  - [Tier 1 Assembled](note-tier1-assembled.pdf)
  - [Tier 2 Parts Kit](note-tier2-parts-kit.pdf)
  - [Tier 3 Populated PCB](note-tier3-populated-pcb.pdf)
  - [Tier 4 Bare PCB](note-tier4-bare-pcb.pdf)

### Firmware

- [Web flasher](https://lukeswitz.github.io/AntiHunter/): flash from Chrome or Edge on a desktop
- [CLI flasher](../Dist/flashAntihunter.sh): flash from a terminal
- [Build from source](../README.md#build-from-source)
- [Releases](https://github.com/lukeswitz/AntiHunter/releases) and [release notes](release-notes/notes.md)

### Operating

- [What it detects](../README.md#what-it-detects): every feature, with a link to its wiki page
- [Scan presets](https://github.com/lukeswitz/AntiHunter/wiki/Settings)
- [Web UI](https://github.com/lukeswitz/AntiHunter/wiki/Web-UI-tour)
- [Secure wipe](https://github.com/lukeswitz/AntiHunter/wiki/Secure-wipe)
- [Mesh radio](https://github.com/lukeswitz/AntiHunter/wiki/Meshtastic-radio-setup)
- [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO)

### Scripts

- [`meshtastic_config.py`](../scripts/meshtastic_config.py) sets the radio's screen, LED, pairing pin, serial module, and region.

### Project

- Help: [Discord](https://discord.gg/AYFzUurfmh) and [Discussions](https://github.com/lukeswitz/AntiHunter/discussions)
- Buy: [store](https://lectronz.com/stores/antihunter) and [website](https://rootdowndigital.com/antihunter)
- Contribute: [contributing](../CONTRIBUTING.md), [CLA](../CLA.md), and the [security policy](../SECURITY.md)
- Legal: [license](../LICENSE) and the [legal disclaimer](../README.md#legal-disclaimer)
