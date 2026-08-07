# ESP32-C5 DIGI Node

> [!WARNING]
> **Testing phase.** The C5 build is not in the web flasher and has no release binaries. Build it from the `feat/c5` branch. The S3 build on `main`/`beta` is the stable one.

The XIAO ESP32-C5 is a drop-in replacement for the XIAO ESP32-S3 on the same AntiHunter PCB — same footprint, same peripherals, same mesh. It adds dual-band WiFi: the C5 radio is 802.11ax on 2.4 GHz **and** 5 GHz, plus BLE. The S3 is 2.4 GHz only.

Everything the S3 node does — target scan, device scanner, probe scanner, baseline, deauth detection, Sentinel, drone RID, triangulation, mesh, SD, GPS, vibration wipe — runs on the C5. The rest of this page covers only what differs.

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
- **API** — `POST /api/config` with `bandMode=<0|1|2>`.

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

```bash
git clone -b feat/c5 https://github.com/lukeswitz/AntiHunter.git
cd AntiHunter
pio run -e AntiHunter-c5-full -t upload        # web UI build
pio run -e AntiHunter-c5-headless -t upload    # serial + mesh only
```

Board `seeed_xiao_esp32c5`, partitions `Dist/partitions_c5.csv`, platform pioarduino. Post-flash setup is identical to the S3 node.

---

## Known limits

- No web-flasher entry and no release binaries — source builds only.
- 5 GHz is scan-only. The SoftAP stays on 2.4 GHz.
- Band changes rewrite the regulatory domain, which restarts the AP beacon; associated web UI clients reconnect.
