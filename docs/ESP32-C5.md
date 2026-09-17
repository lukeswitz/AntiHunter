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

The node has one radio, so it works on one band at a time. Pick the band and it scans only the channels in that band.

| Band | Setting | Scans |
|---|---|---|
| 2.4 GHz | `0` | channels 1–14 |
| 5 GHz | `1` | channels above 14 |
| both | `2` | everything on your channel list |

If your channel list has nothing in the band you pick, the node adds the usual channels for
that band itself. Edit the list under RF Settings.

Change it in the web interface under RF Settings (the Band row appears only on C5 hardware),
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

- Experimental build — it does not follow the stable release schedule.
- **Motion sensing can stall after hours of continuous running** and only a power cycle clears it. The chip's radio stops producing fresh signal data while everything else looks normal, so the node reports no movement rather than reporting a fault. Nothing in firmware recovers it.
- 5 GHz is for scanning only. The node's own WiFi access point stays on 2.4 GHz.
- Changing band briefly restarts that access point, so a browser connected to the node reconnects.

### Motion detection on a C5

The S3 has two processor cores, the C5 one, so the S3 has more room to run scanning, mesh
and the web interface at once. The C5 takes in noticeably more raw signal data per second
and sees far more modern WiFi traffic, which suits motion sensing.

Put S3 nodes where you want heavy scanning, and a C5 where sensing matters most.

Both board types use the same detection maths and the same default sensitivity. Sitting side
by side on one channel they settle at the same background level, so a C5 needs no special
tuning.

To set sensitivity: watch the readings with the room empty, watch them again with someone
walking around, and put the setting between the two. If the two overlap, no setting will
work — move the node or its antenna. The value is saved on the node; `CSI_RECAL` restores
the default.

---

## Firmware notes

Developer reference. Chip-level detail, open bugs in Espressif's own code, and the exact
fields the firmware reads. Nothing below is needed to set up or run a node.

### Open upstream issues

Open bugs in Espressif's CSI support on C5/C61, none with a fix:

- [esp-idf#18982](https://github.com/espressif/esp-idf/issues/18982) - the 106-byte
  L-LTF buffer does not match the documented two-signed-bytes-per-subcarrier layout.
  This firmware reads the documented layout: 53 subcarriers, one signed byte per component.
- [esp-idf#18493](https://github.com/espressif/esp-idf/issues/18493) - CSI IQ buffer
  static on 5 GHz. 2.4 GHz is unaffected; CSI here runs on 2.4 GHz.
- [esp-idf#18118](https://github.com/espressif/esp-idf/issues/18118) - 11g PPDUs return
  unchanging CSI on HE-MAC parts, traced to the closed PHY blob.
  `acquire_csi_force_lltf = 1` is the documented workaround. A capture on 2026-09-09
  collapsed to one distinct 106-byte payload over 887 packets and 22 transmitters, so
  this firmware ran with it off; it is now on, which restricts CSI to L-LTF and keeps a
  link's payload length constant. A 300-packet capture on 2026-09-16 held per-subcarrier
  variation of 0.72 to 1.54, so the payloads differ.
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
- `lltf_bit_mode`, `esp_wifi_he_types.h:63`: "0 : 12-bit, 1 : 8-bit, default : 12-bit".
  `csiArmCsi` sets 0 but the decode reads int8 pairs. Harmless so far — the payload is 106
  bytes either way, too small for 12-bit across 53 subcarriers — but the request should be 1.
  `csiWord12` is the 12-bit decoder, retained and unused.

`CSIR` raw dump lines end with `,L<len>,F<0|1>` - the packet's `ev.len` and `first_word_invalid`.
Without them a capture cannot be decoded correctly, because the values are dumped as a fixed
114-byte buffer while only `len` bytes are valid.
