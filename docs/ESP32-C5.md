# ESP32-C5 DIGI Node

> [!WARNING]
> **Testing phase.** Breadboard the C5 and test it before you solder anything. A C5 soldered into a PCB can go back to stable firmware only if you desolder it and fit an ESP32-S3. The C5 build is on the web flasher's **Experimental** channel. The S3 build on `main` is the stable one.

The XIAO ESP32-C5 replaces the XIAO ESP32-S3 on the same AntiHunter PCB, with the same footprint, peripherals and mesh. Its radio is 802.11ax on 2.4 GHz **and** 5 GHz, plus BLE. The S3 radio is 2.4 GHz only.

The C5 build has the S3 build's features: target scan, device scanner, probe scanner, baseline, deauth detection, Sentinel, drone RID, CSI motion, packet capture, triangulation, mesh, SD, GPS and vibration wipe. This page covers only what differs.

- [Bands and channels](#bands-and-channels)
- [Pinout](#pinout)
- [Build & Flash](#build--flash)
- [Known limits](#known-limits)

---

## Bands and channels

The node has one radio, so it works on one band at a time. The band setting decides which channels from your channel list the node scans.

| Band | Setting | Scans |
|---|---|---|
| 2.4 GHz | `0` | Channels 1-14 |
| 5 GHz | `1` | Channels above 14 |
| Both | `2` | Every channel on your list |

The default is `2`. The node edits your channel list when the list lacks a channel in the selected band:

- Band `1` or `2`: if the list has no 5 GHz channel, the node adds 36, 40, 44, 48, 149, 153, 157, 161 and 165.
- Band `2`: if the list has no 2.4 GHz channel, the node adds 1, 6 and 11.
- Band `0`: the node adds nothing. If the list has no 2.4 GHz channel, it scans the whole list.

Edit the list under System → Settings → Scanning.

Change the band in either place:

- **Web UI:** System → Settings → **Scanning** → **Band**, then **Save**. The Band row appears only on C5 hardware. Stop any running scan first, or the node refuses the change.
- **Mesh:** `@<NODE> CONFIG_BAND:<0|1|2>`. The node replies `CONFIG_ACK:BAND:<n>`, or `CONFIG_ACK:BAND:INVALID` for any other value.

The node keeps the setting across reboots.

---

## Pinout

The pads are the same as on the S3 node. Only the GPIO numbers differ, so an assembled PCB needs no wiring change.

| Function | Pad | C5 GPIO | S3 GPIO |
|---|---|---|---|
| Mesh UART RX | D3 | 7 | 4 |
| Mesh UART TX | D4 | 23 | 5 |
| Vibration sensor | D1 | 0 | 2 |
| RTC SDA | D2 | 25 | 3 |
| RTC SCL | D5 | 24 | 6 |
| GPS TX | D6 | 11 | 43 |
| GPS RX | D7 | 12 | 44 |
| SD CS | D0 | 1 | 1 |
| SD SCK | D8 | 8 | 7 |
| SD MISO | D9 | 9 | 8 |
| SD MOSI | D10 | 10 | 9 |

---

## Build & Flash

**Web flasher.** [Open it](https://lukeswitz.github.io/AntiHunter/), then:

1. Choose the **Experimental — XIAO ESP32-C5** channel.
2. Pick Full or Headless.
3. Check the acknowledgment box.
4. Select **Connect & Flash**.

**From source:**

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload        # web UI build
pio run -e AntiHunter-c5-headless -t upload    # serial + mesh only
```

The build uses board `seeed_xiao_esp32c5`, partition table `Dist/partitions_c5.csv` and the pioarduino platform. Setup after flashing is the same as for the S3 node.

---

## Known limits

- 5 GHz is for scanning only. The node's own Wi-Fi access point stays on channel 6 (2.4 GHz).
- Changing the band applies a new Wi-Fi country setting, which can drop clients connected to the access point. Reconnect the browser if that happens.

### Motion detection on a C5

**In testing.** In the same room, a C5 separates movement from background less cleanly than an S3. Use an S3 where detection matters.

The C5 default trigger level is 0.020. The S3 Beta build's is 0.140. Do not copy a value between them. C5 scores run lower than S3 scores, so an S3 value silences a C5 and a C5 value floods an S3.

To set the trigger for a room:

1. Watch the score with the room empty, then with someone walking.
2. Set the trigger between the two scores: `@AH01 CSI_CFG:SENSITIVITY=<value>`.
3. If the two scores overlap, move the node.

`SENSITIVITY` takes a number from 0.005 to 20, or `LOW`, `MEDIUM` or `HIGH`. The three words also set the trigger to 0.070, 0.070 and 0.056, and they set how long motion must last and how many links must agree. `@AH01 CSI_RECAL` clears the value you set and returns to the default.

Chip-level detail and open Espressif issues: [C5 firmware notes](ESP32-C5-firmware-notes.md).
