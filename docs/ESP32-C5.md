# ESP32-C5 DIGI Node

> [!WARNING]
> **Testing phase.** Breadboard the C5 and test it before you solder anything — a C5 soldered into a PCB can only be put back on stable firmware by desoldering it and fitting an ESP32-S3 in its place. The C5 build ships through the web flasher's **Experimental** channel; the S3 build on `main`/`beta` is the stable one.

The XIAO ESP32-C5 is a drop-in replacement for the XIAO ESP32-S3 on the same AntiHunter PCB — same footprint, same peripherals, same mesh. It adds dual-band WiFi: the C5 radio is 802.11ax on 2.4 GHz **and** 5 GHz, plus BLE. The S3 is 2.4 GHz only.

Everything the S3 node does — target scan, device scanner, probe scanner, baseline, deauth detection, Sentinel, drone RID, CSI motion, packet capture, triangulation, mesh, SD, GPS, vibration wipe — runs on the C5. The rest of this page covers only what differs.

- [Bands and channels](#bands-and-channels)
- [Pinout](#pinout)
- [Build & Flash](#build--flash)
- [Known limits](#known-limits)

---

## Bands and channels

One radio, one band at a time. The band setting filters the configured channel list into the hop list.

| Mode | Value | Hop list |
|---|---|---|
| 2.4 GHz | `0` | configured channels 1–14 only |
| 5 GHz | `1` | configured channels above 14 only |
| 2.4 + 5 GHz | `2` | the whole configured list |

Selecting a 5 GHz mode appends `36, 40, 44, 48, 149, 153, 157, 161, 165` to the saved channel list if it holds no 5 GHz channel; mode `2` likewise adds `1, 6, 11` if it holds no 2.4 GHz channel. Set the list itself in RF Settings (default `1..11`).

Set it three ways:

- **Web UI** — RF Settings, *Band* selector. The row only appears on C5 hardware.
- **Mesh** — `@<NODE> CONFIG_BAND:<0|1|2>`, replies `CONFIG_ACK:BAND:<mode>` or `CONFIG_ACK:BAND:INVALID`.
- **API** — `POST /rf-config` with `bandMode=<0|1|2>`. `POST /config` also accepts `bandMode`, but requires `channels` and `targets` in the same request. Both return `409` while a scan is running — stop it first.

The value persists to NVS. On the full build the 5 GHz channels are scanned in short dwells between AP beacons so the web UI client stays associated.

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

**Web flasher** — [open it](https://lukeswitz.github.io/AntiHunter/), choose the **Experimental — XIAO ESP32-C5** channel, pick Full or Headless, tick the acknowledgement, then Connect & Flash.

**From source:**

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload        # web UI build
pio run -e AntiHunter-c5-headless -t upload    # serial + mesh only
```

Board `seeed_xiao_esp32c5`, partitions `Dist/partitions_c5.csv`, platform pioarduino. Post-flash setup is identical to the S3 node.

---

## Known limits

- Experimental channel only — not covered by the stable release cadence.
- 5 GHz is scan-only. The SoftAP stays on 2.4 GHz.
- Band changes rewrite the regulatory domain, which restarts the AP beacon; associated web UI clients reconnect.

### CSI motion detection: the C5 ingests more than the S3

The S3 is dual-core Xtensa LX7, the C5 single-core RISC-V. That cuts the other way from CSI:

| | ESP32-S3 | ESP32-C5 |
|---|---|---|
| cores | 2 | 1 |
| WiFi and BLE scanning, mesh, web UI | more headroom - scan callbacks and the server do not share a core | everything shares one core |
| CSI ingest rate | reference | ~3x the S3, measured same channel same intervals |
| CSI measurement noise | reference | 7-57x lower |
| 802.11n frames seen | almost none | hundreds per 15s |
| release channel | stable | experimental |

Run scanning on S3 nodes, put a C5 where sensing matters most.

Both boards run the same detector. It watches how much the WiFi signal shifts around,
reported as `sig` in the status line, and alerts when that crosses the trigger you set
with `CSI_CFG` (0.050 until you change it).

Each board needs its own trigger. What counts as a quiet room depends on the channel
the node picked and which access points it can hear, and those differ between two
nodes sitting in the same house. Two here settled on 0.080 for the S3 on ch1 and 0.045
for the C5 on ch6, both confirmed against a walk-in.

The C5 does not behave identically to the S3, and the difference is physical rather
than a fault. Measured on one C5 and one S3 in the same room, on the same channel,
from the same transmitters:

- the C5's CSI carries 7-57x less measurement noise for the same signal variance
- it ingests roughly 3x the CSI records per second

So it resolves weaker movement. Over a 50 minute run with an operator moving in and
out, the C5 opened episodes 22-88s earlier and held them longer.

A 16 hour side-by-side run measured the relationship as containment, not agreement.
Comparing per-minute area state, the C5 flagged 194 of the 200 minutes the S3 called
moving (97%), and flagged a further 235 minutes the S3 called quiet. Agreement 0.585
against a chance rate of 0.426, Cohen's kappa 0.278. On the minutes only the C5
flagged, the S3's own statistic was elevated too - median 0.0357 against its 0.0203
when both were quiet - so it was seeing the same disturbance and falling short of the
gate, not missing it entirely. Both boards read the same floor across the sleeping
hours (C5 0.0176, S3 0.0203), which is what rules out a noise difference as the cause.
Occupants were present and still, not absent, so this is a quiet floor rather than a
true empty-building control.

Expect from a C5 node, relative to an S3 in the same room:

| | S3 | C5 |
|---|---|---|
| motion onset | reference | up to ~90s earlier |
| episode length | reference | longer |
| weak or distant movement | often missed | usually detected |

Neither is wrong. Set each board's trigger from its own idle distribution with
`CSI_CFG:<value>:5000:3:0`; the value persists in NVS and `CSI_RECAL` clears it
back to the compiled default. Send it after the mesh task is up, roughly 15s past
`Hardware initialized` - a command sent during boot is dropped silently.

The C5 is harder to set a trigger for than the S3, and it is not the channel. Measured
with both boards on ch1 in the same room over the same 20 minutes:

| | quietest reading | loudest reading | average |
|---|---|---|---|
| S3 | 0.0250 | 0.4007 | 0.0883 |
| C5 | 0.0112 | 0.9758 | 0.1168 |

The C5 reads lower when the room is still and spikes far higher, so its quiet and its
moving overlap more than the S3's do. Set it too low and it sticks on - a C5 at 0.080
stayed in one alert for 384 seconds and then showed nothing when someone walked in,
because it was already alerting. Set it too high and it misses - the same node at 0.170
peaked at 0.2216 when someone moved, dropped back the next reading, and never held the
12 seconds an area alert needs.

Get it from the room, not from a guess. Watch `sig` with nobody in the space and note
the highest value. Watch it again while someone walks around. Put the trigger between
the two. If the two overlap, move the node or its antenna - no number will work.

Open upstream issues on C5/C61 CSI, none of which currently has a fix:

- [esp-idf#18982](https://github.com/espressif/esp-idf/issues/18982) - the 106-byte
  L-LTF buffer does not match the documented two-signed-bytes-per-subcarrier layout.
  Does not apply at `lltf_bit_mode = 1`, which is what this firmware sets.
- [esp-idf#18493](https://github.com/espressif/esp-idf/issues/18493) - CSI IQ buffer
  static on 5 GHz. 2.4 GHz is unaffected; CSI here runs on 2.4 GHz.
- [esp-idf#18118](https://github.com/espressif/esp-idf/issues/18118) - 11g PPDUs return
  unchanging CSI on HE-MAC parts, traced to the closed PHY blob.
  `acquire_csi_force_lltf = 1` is the documented workaround; this firmware sets it to 0,
  because forcing it collapsed the capture to a single distinct payload on this node
  (measured 2026-09-09: 887 packets, 22 transmitters, 1 distinct 106-byte payload).
- [esp-idf#14271](https://github.com/espressif/esp-idf/issues/14271) - HT-LTF subcarrier
  order differs from the S3 on HE parts. This is reached: a ch6 capture measured 2.71M
  106-byte L-LTF and 454k 114-byte HT-LTF records, so roughly 14% of traffic arrives as
  HT-LTF. It is contained rather than fixed - each link locks to the first payload
  length it sees and rejects the other format, so a link's scorer never mixes the two
  layouts. The counter is reported as `fmtdrop` in the status line.
- [esp-csi#258](https://github.com/espressif/esp-csi/issues/258) - Espressif publishes a
  chip CSI ranking of `C5 > C6 > C3 ~= S3 > ESP32` and has not said what it measures.

#### Why the C5 ingests more

Measured on ch6, same room, same 15s intervals, no SoftAP client on either board:

| per 15s | DSSS | legacy 11g | HT |
|---|---|---|---|
| S3 | 5983-7279 | 1129 | 3-12 |
| C5 | 5983 | 3020 | 194-666 |

The S3 hears more DSSS, so both radios are getting the same air. Ruled out by measurement:
receiver sensitivity (the gap is widest on the strongest frames), STA and AP bandwidth,
the `esp_wifi_set_protocol` bits (`0x07`, 11N on), the promiscuous filter, and
misclassification (`sig_mode==0` frames all read `aggregation=0`, `mcs=0`). Matches
[esp-idf#736](https://github.com/espressif/esp-idf/issues/736), closed on the grounds that no
11n was in the air - here a C5 12 cm away was decoding hundreds per 15s.

Channel-specific, not a chip verdict: on ch1 the same S3 decoded 10120 HT frames, 15.7% of
its OFDM against the C5's 33.6% on ch6. Why ch6 starved it is unexplained. Let the survey
pick the channel.

### SD card does not survive a reset without power removal

> [!WARNING]
> Stop a capture before cutting power or resetting the node. FAT has no power-fail
> protection, so an interruption mid-write can leave the SD card unreadable until it is
> reformatted, and the node then runs with no storage at all. `SD_REPAIR:ON` lets a node
> rebuild its own card, which recovers most cases but not all, and erases the card.

A reset that leaves the SD card powered can leave the card unmountable until power is physically removed. Seen after flashing and after USB-serial resets, which report `rst:0x15 (USB_UART_HPSYS)` in the ROM banner. It does not happen on every such reset.

```
Initializing SD card...
[SD] C5: SPI2 bus clock ungated
[  3404][E][sd_diskio.cpp:810] sdcard_mount(): f_mount failed: (1) A hard error occurred in the low level disk I/O layer
[SD] FAILED
```

The periodic remount then fails for the rest of the session and the node runs with no SD: no logging, no baseline, no capture, config from NVS only. Unplugging and repowering clears it.

Any reboot that keeps the card powered is exposed, including a panic and an OTA restart. Plan for a node that reboots in the field to come back without its card.

No firmware workaround has been found.

Upstream issues covering the same failure on other targets. None is specific to the ESP32-C5, and no C5 issue has been filed:

- [esp-idf#14000](https://github.com/espressif/esp-idf/issues/14000) - mounting an SPI-mode card after a restart fails because the card holds state from before the reset.
- [esp-idf#10294](https://github.com/espressif/esp-idf/issues/10294) - SD fails to mount a second time, host init failed.
- [esp-idf#15535](https://github.com/espressif/esp-idf/issues/15535) - SDSPI example failing on ESP32-S3.
- [arduino-esp32#9218](https://github.com/espressif/arduino-esp32/issues/9218) - the SD library does not force SPI mode before activating the card.

### CSI stops updating and only a power cycle clears it

After hours of continuous CSI capture the C5 PHY latches its channel-estimate buffer. Packets keep arriving and every metadata field stays correct - `records` climbs at the normal rate, `rejected` stays flat, `rx_channel_estimate_info_vld` stays set, RSSI and source MAC vary per frame - but the IQ bytes in `wifi_csi_info_t.buf` stop changing.

Every link then reads a constant score, `scoreVar` decays to zero, and `csiExpireLinks` drops the link as flat. New links rebuild and die the same way at roughly 500 packets, so detection stops with `links=0 pairs=0` and the event counter frozen.

Measured on AH94, 2026-09-09: 1505 packets from 18 transmitters spanning -95 to -18 dBm produced 2 distinct 106-byte payloads, and those two were one byte sequence at two alignments. A working node in the same room on the same channel produced a distinct payload per packet.

The onset is gradual, roughly 90 seconds, visible in the status line as `acf` climbing toward 1.0 while `sig` collapses:

```
00:10:48  acf=0.748..0.823  sig=0.0956
00:11:18  acf=0.772..0.848  sig=0.0054
00:11:48  acf=0.850..0.850  sig=0.0001
00:12:19  links=0           sig=0.0000
```

Nothing in firmware clears it. Tested and ruled out on hardware, each as a single-variable A/B: `acquire_csi_force_lltf=1`, `acquire_csi_legacy=0` (HT-only), a different channel, `bandMode=0`, `esp_phy_erase_cal_data_in_nvs()`, CSI stop/start, a full reflash, and an RTS reset. Unplugging the node for ten seconds restores a distinct payload per packet immediately.

The RF block keeps the latched state across any reset that leaves it powered, and `esp_phy_init.h:157` states PHY and RF enabling is driven only by the WiFi start path, so there is no application-level call that power-cycles it.

Upstream issues covering the same failure. Both are closed as resolved internally with no published cause or workaround:

- [esp-idf#18493](https://github.com/espressif/esp-idf/issues/18493) - ESP32-C5, `wifi_csi_info_t.buf` never changes while metadata updates normally.
- [esp-idf#18118](https://github.com/espressif/esp-idf/issues/18118) - ESP32-C61, constant CSI on 802.11g frames, traced by the reporter to a commit in the esp-phy-lib blob. Its `acquire_csi_force_lltf` workaround does not work on the C5.

### CSI field reference

The decoder relies on four documented properties of the C5 CSI path. Source:
[ESP-IDF v5.5.3, Wi-Fi Driver, ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi.html).

- "Each item is stored as two bytes: imaginary part followed by real part." `csiAmplitudesLen`
  reads `buf[k*2]` as imaginary and `buf[k*2+1]` as real.
- "If `first_word_invalid` of `wifi_csi_info_t` is true, it means that the first four bytes
  of CSI data is invalid due to a hardware limitation in ESP32-C5." The decoder skips two
  complex words, four bytes, when the flag is set.
- "If `rx_channel_estimate_info_vld` of `rx_ctrl` field is 1, indicates that the CSI data is
  valid; otherwise, the CSI data is invalid." Counted per packet as `ce=<valid>/<invalid>`
  in the status line; `csiRequireCeVld` gates on it.
- `lltf_bit_mode`, `esp_wifi_he_types.h:63`: "LLTF bit width mode for I/Q components,
  0 : 12-bit, 1 : 8-bit, default : 12-bit". `csiArmCsi` sets 1, so the int8 pair decode
  matches what the radio is asked for. `csiWord12` in `csi_metric.h` is the 12-bit decoder,
  retained and unused while this stays at 1.

`CSIR` raw dump lines end with `,L<len>,F<0|1>` - the packet's `ev.len` and `first_word_invalid`.
Without them a capture cannot be decoded correctly, because the values are dumped as a fixed
114-byte buffer while only `len` bytes are valid.
