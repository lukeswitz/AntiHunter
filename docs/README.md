# Start Here
- **[Read the Documentation](https://github.com/lukeswitz/AntiHunter/tree/main)** - everything there is to know about this project
- **[Operator's Guide](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html)** — the node, from the box to the field. [PDF](AntiHunter-Operators-Guide.pdf)
- **[Assembly Manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)** — soldering, SD card prep, connectors, printed enclosure

---

## Before you power anything

1. **Regulated 5 V only.** USB, a bench supply, a DC-DC regulator or the UPS board. Unregulated input permanently damages the modules, and under 4.5 V is unstable.
2. **Never power the LoRa radio without its antenna.** Transmitting into an open port can kill the PA. Fit the antenna or the U.FL pigtail first.
3. **One USB cable at a time.** The ESP32 and the radio share the PCB rails; with both plugged in, one back-feeds the other.

Flashing needs a **data** USB-C cable and Chrome or Edge on a desktop. Charge-only cables will not flash. Other browsers cannot talk to serial ports.

---

## Pick your path

### Assembled node or Populated PCB

The radio is already flashed and serial-configured. You do not redo that.

1. Fit the antennas — [§2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s2)
2. Flash AntiHunter, Full to start with — [web flasher](https://lukeswitz.github.io/AntiHunter/)
3. Change the AP credentials
4. Set your LoRa region, pairing pin and encrypted channel — [Radio Setup](../README.md#radio-setup)
5. Carry on at [Setup order](#setup-order-for-a-new-node)

### Parts Kit or Bare PCB

Nothing is soldered, nothing is flashed.

1. Check the box against [what your tier ships](../README.md#deployment-steps-by-tier)
2. Bare PCB only: source the parts — [BOM](../hw/Prototype_STL_Files/BOM-Links.md)
3. Solder it — [assembly manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf)
4. Print an [enclosure](../hw/Prototype_STL_Files/README.md) if you want one
5. Flash Meshtastic on the radio at [flasher.meshtastic.org](https://flasher.meshtastic.org), then set SERIAL enabled, TEXTMSG, 115200, pins 19RX/20TX on Heltec V3 or 10RX/9TX on T114. [`meshtastic_config.py`](../scripts/meshtastic_config.py) does all of it
6. Carry on at [Setup order](#setup-order-for-a-new-node)

---

### Bare XIAO ESP32-S3, no PCB

The firmware expects the full module set: LoRa radio, GPS, RTC, SD reader, vibration sensor. Breadboard them to the same pins if you are not using the PCB.

Pinout: [Appendix A](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#appendix-a), or [Hardware](../README.md#hardware). Parts: [BOM](../hw/Prototype_STL_Files/BOM-Links.md).

### Building from source

PlatformIO environments: [Build & Flash](../README.md#build-from-source). Read [CONTRIBUTING](../CONTRIBUTING.md) and the [CLA](../CLA.md) before a PR.

---

### Several nodes

Give every node its own ID and put them all on the same encrypted channel. They relay for each other, 3 hops by default — [reaching a node you cannot hear](../README.md#reaching-a-node-you-cannot-hear). Aggregate the fleet with the [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO) — install steps in [§12](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s12).

---

## Setup order for a new node

| # | Step | Where |
|---|------|-------|
| 1 | Fit the antennas — 2.4 GHz to the XIAO, LoRa to the radio, GPS to the GPS module | [§2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s2) |
| 2 | Flash AntiHunter, Full to start with | [Web flasher](https://lukeswitz.github.io/AntiHunter/) · [CLI](../README.md#cli-flash) |
| 3 | Change the AP credentials — the defaults are published in this repo | RF Settings in the web UI |
| 4 | Set the radio's LoRa region — it ships UNSET and receives without ever transmitting | [Radio Setup](../README.md#radio-setup) |
| 5 | Create your own encrypted channel, make it primary, disable the public one | [Radio Setup](../README.md#radio-setup) |
| 6 | Set the node ID — it prefixes every mesh message the node sends. The clock needs nothing: the RTC is set at flash time and disciplined by GPS | Web UI, or `@AH01 CONFIG_NODEID:GATE1` · [§8.2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s8-2) |
| 7 | Confirm the SD card mounts and GPS gets a fix outdoors | [§4](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s4) |
| 8 | Tune the vibration trimpot in place, on the real mount | [§10.2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s10-2) |
| 9 | Verify `@NODEID STATUS` answers over the mesh | [Mesh Commands](../README.md#mesh-commands) |
| 10 | Seal and deploy | [§13](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s13) |

---

## Decisions

| Question | Answer |
|---|---|
| **Full or Headless?** | Same detectors, same scan engine, same mesh commands. Full hosts the WiFi AP with the web UI and API, and beacons continuously. Headless is serial and mesh only, never beacons. Start on Full, reflash to Headless before a quiet deployment. [Details](../README.md#full-vs-headless) |
| **Stable or Beta?** | Stable (`main`) for field deployments. Beta (`beta`) for new features first, Sentinel among them. [Stable notes](release-notes/notes-stable.md) · [Beta notes](release-notes/notes-beta.md) |
| **S3 or C5?** | ESP32-S3 is the shipping build. The [ESP32-C5](https://github.com/lukeswitz/AntiHunter/blob/beta/docs/ESP32-C5.md) is a drop-in on the same pads and adds 5 GHz, under the flasher's Experimental channel while it is in testing. [RadarNode](https://github.com/lukeswitz/AntiHunter/blob/beta/docs/RADARNODE.md) pairs a 24 GHz radar with the same mesh. |
| **Do I need the Meshtastic radio?** | Not for scanning. Without it, you control one node from its own AP or over serial, standing next to it. With it, you send commands and get detections over LoRa from anywhere in mesh range, across as many nodes as you deploy. |
| **Which SD card?** | FAT32, under 32 GB. Every tier except Bare PCB ships with an 8 GB card fitted. |
| **How do I update?** | Re-run the flasher on the same channel with *Erase Device* unticked. Settings are in NVS and mirrored to the SD card, so they survive. Read the release notes first. |

---

## Ten commands to know

Send these as text messages from any Meshtastic client on your channel.

```
@ALL STATUS                        which nodes answer
@ALL STOP                          stop everything
@AH01 CONFIG_NODEID:GATE1          name a node
@ALL CONFIG_TARGETS:AA:BB:CC|MyWiFi   set the watchlist
@ALL SCAN_START:2:600:1..11        watchlist scan, 10 minutes
@ALL DEVICE_SCAN_START:2:300       survey everything nearby
@ALL BASELINE_START:900            learn the site's normal devices
@ALL SENTINEL_ON                   attacker-tool detection (Beta)
@ALL DRONE_START:0                 drone watch until stopped
@AH01 BATTERY_SAVER_START:10       idle, mesh stays up
```

Every command, every reply label: [Mesh Commands](../README.md#mesh-commands). Over HTTP instead: [API Reference](../README.md#api-reference).

---

## Something is wrong

| Symptom | Usual cause | Fix |
|---|---|---|
| No `Antihunter` WiFi network | Headless is flashed, or the AP name and password were changed | Check over serial which build is running. Reflash Full if you need the UI |
| Web UI will not load | Not on the node's own AP, or the browser forced https | Join the AP, open `http://192.168.4.1` exactly |
| Flashing fails, or no serial port appears | Charge-only cable, a serial monitor holding the port, both USB ports connected, or the wrong browser | Data cable, close other serial tools, unplug the radio, use Chrome or Edge |
| SD card not detected | Not FAT32, 32 GB or larger, or not seated | Reformat FAT32 on a card under 32 GB |
| No GPS fix | Antenna not connected, or no sky view | Check the U.FL or SMA, go outdoors, give it time. The module runs hot while searching |
| Nothing arrives over the mesh | Region UNSET so the radio is receive-only, serial module off, wrong pins, or nodes on different channels or keys | Re-run [`meshtastic_config.py`](../scripts/meshtastic_config.py) and print the settings. Every node needs the same channel and key |
| A node hears commands but never answers | Its region is unset, so it cannot transmit | Set its region |
| Node scans forever | A scan was started with `:FOREVER` or duration 0 | `@ALL STOP`, or Stop in the UI |
| Settings gone after flashing | *Erase Device* was ticked | Reconfigure. NVS mirrors to SD and self-heals, but a deliberate erase clears it |
| Constant vibration alerts | Trimpot too sensitive, or a resonant mount | Retune in place ([§10.2](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s10-2)), pad the mount |
| Detections with no coordinates | No valid GPS fix at that moment | Expected. Position is attached only when the fix is valid |

Full symptom table, factory reset and what to include in a bug report: [§14](https://lukeswitz.github.io/AntiHunter/operators-guide/operators-guide.html#s14). Then [Discussions](https://github.com/lukeswitz/AntiHunter/discussions) or [Discord](https://discord.gg/AYFzUurfmh). Scrub coordinates and MAC addresses from anything you paste.

---

## Everything else

**Hardware** — [assembly manual](../hw/Prototype_STL_Files/Antihunter-DIGINODE-AssemblyManual.pdf) · [BOM links](../hw/Prototype_STL_Files/BOM-Links.md) · [enclosures and STLs](../hw/Prototype_STL_Files/README.md) · [welcome letter](../hw/Prototype_STL_Files/ahwelcome.txt) · [what each tier ships](../README.md#deployment-steps-by-tier)

**Firmware** — [web flasher](https://lukeswitz.github.io/AntiHunter/) · [CLI flasher](../Dist/flashAntihunter.sh) · [build from source](../README.md#build-from-source) · [releases](https://github.com/lukeswitz/AntiHunter/releases) · [stable notes](release-notes/notes-stable.md) · [beta notes](release-notes/notes-beta.md)

**Operating** — [what it detects](../README.md#what-it-detects) · [scan presets](../README.md#rf-scan-presets) · [field controls](../README.md#field-controls) · [secure data destruction](../README.md#secure-data-destruction) · [mesh networking](../README.md#mesh-networking) · [Command Center](https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO)

**Scripts** — [`meshtastic_config.py`](../scripts/meshtastic_config.py) hardens a radio: screen, LED, pairing pin, serial module, region

**Project** — [Discord](https://discord.gg/AYFzUurfmh) · [Discussions](https://github.com/lukeswitz/AntiHunter/discussions) · [store](https://lectronz.com/stores/antihunter) · [website](https://rootdowndigital.com/antihunter) · [contributing](../CONTRIBUTING.md) · [CLA](../CLA.md) · [security policy](../SECURITY.md) · [license](../LICENSE) · [legal disclaimer](../README.md#legal-disclaimer)
