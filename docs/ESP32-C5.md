# ESP32-C5 DIGI Node

> [!WARNING]
> **Testing phase.** Breadboard the C5 and test it before you solder anything. A C5 soldered into a PCB can only go back to stable firmware by desoldering it and fitting an ESP32-S3. The C5 build is on the web flasher's **Experimental** channel; the S3 build on `main` is the stable one.

The XIAO ESP32-C5 replaces the XIAO ESP32-S3 on the same AntiHunter PCB: same footprint, same peripherals, same mesh. Its radio is 802.11ax on 2.4 GHz **and** 5 GHz, plus BLE. The S3 is 2.4 GHz only.

Every S3 feature runs on the C5: target scan, device scanner, probe scanner, baseline, deauth detection, Sentinel, drone RID, CSI motion, packet capture, triangulation, mesh, SD, GPS, vibration wipe. This page covers only what differs.

- [Bands and channels](#bands-and-channels)
- [Pinout](#pinout)
- [Build & Flash](#build--flash)
- [Known limits](#known-limits)

---

## Bands and channels

The node has one radio, so it works on one band at a time. Pick the band and it scans only the channels in that band.

| Band | Setting | Scans |
|---|---|---|
| 2.4 GHz | `0` | channels 1–14 |
| 5 GHz | `1` | channels above 14 |
| both | `2` | everything on your channel list |

The default is `2` (both). Bands `1` and `2` add 36/40/44/48/149/153/157/161/165 if your
channel list has no 5 GHz channel. Band `2` also adds 1/6/11 if it has no 2.4 GHz channel.
Band `0` adds nothing; if the list has no 2.4 GHz channel it scans the whole list. Edit the
list under System → Settings → Scanning.

Change it in the web interface under System → Settings → Scanning (the Band row appears only on C5 hardware),
or over mesh with `@<NODE> CONFIG_BAND:<0|1|2>`. Stop any running scan first. The setting is
remembered across reboots.

---

## Pinout

Same pads as the S3 node, different GPIO numbers. No wiring change on an assembled PCB.

| Function | Pad | C5 GPIO | S3 GPIO |
|---|---|---|---|
| Mesh UART RX← | D3 | 7 | 4 |
| Mesh UART TX→ | D4 | 23 | 5 |
| Vibration sensor | D1 | 0 | 2 |
| RTC SDA | D2 | 25 | 3 |
| RTC SCL | D5 | 24 | 6 |
| GPS TX→ | D6 | 11 | 43 |
| GPS RX← | D7 | 12 | 44 |
| SD CS | D0 | 1 | 1 |
| SD SCK | D8 | 8 | 7 |
| SD MISO | D9 | 9 | 8 |
| SD MOSI | D10 | 10 | 9 |

---

## Build & Flash

**Web flasher**: [open it](https://lukeswitz.github.io/AntiHunter/), choose the **Experimental — XIAO ESP32-C5** channel, pick Full or Headless, check the acknowledgment box, then Connect & Flash.

**From source:**

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload        # web UI build
pio run -e AntiHunter-c5-headless -t upload    # serial + mesh only
```

Board `seeed_xiao_esp32c5`, partitions `Dist/partitions_c5.csv`, platform pioarduino. Post-flash setup is the same as the S3 node.

---

## Known limits

- 5 GHz is for scanning only. The node's own Wi-Fi access point stays on 2.4 GHz.
- Changing band briefly restarts that access point, so a browser connected to the node reconnects.

### Motion detection on a C5

**In testing.** In the same room, a C5 separates movement from background less cleanly than an S3. Use an S3 where detection matters.

The C5 default trigger level is 0.020; the S3 Beta build's is 0.140. Don't copy a value between them: the C5 reads a higher idle level, so an S3 value silences a C5 and a C5 value floods an S3.

Set the trigger from the room: watch the score with the room empty, then with someone walking, and set it between the two with `@AH01 CSI_CFG:SENSITIVITY=<value>`. If they overlap, move the node. `@AH01 CSI_RECAL` clears the value you set and returns to the default.

Chip-level detail and open Espressif issues: [C5 firmware notes](ESP32-C5-firmware-notes.md).
