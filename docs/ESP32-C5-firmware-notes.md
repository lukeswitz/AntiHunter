# ESP32-C5 Firmware Notes

[Back to the C5 page](ESP32-C5.md)

Developer reference: chip-level detail, open bugs in Espressif's code, and the fields the firmware reads. You do not need it to set up or run a node.

## Open upstream issues

These are Espressif CSI issues on the C5 and C61. Issues #18982, #14271 and esp-csi#258 are open. Issue #18118 was closed on 2026-02-26 as fixed by commit aa097c8e. Issue #18493 was closed on 2026-04-23 as a hardware limit.

- [esp-idf#18982](https://github.com/espressif/esp-idf/issues/18982): the 106-byte L-LTF buffer does not match the documented layout of two signed bytes per subcarrier. A capture on channel 6 with `acquire_csi_force_lltf = 1` gave 611 raw records. In every 4-byte group, bytes 1 and 3 stay in 0-15 (16497 and 15886 samples, no exceptions), while bytes 0 and 2 span the signed range. The buffer holds 12-bit words in 2-byte containers, 26 complex subcarriers in all. `csiAmplitudesLen` decodes it that way through `csiWord12`.
- [esp-idf#18493](https://github.com/espressif/esp-idf/issues/18493): the CSI IQ buffer stays static on 5 GHz. 2.4 GHz is unaffected, and this firmware runs CSI on 2.4 GHz.
- [esp-idf#18118](https://github.com/espressif/esp-idf/issues/18118): 11g PPDUs return unchanging CSI on HE-MAC parts, traced to the closed PHY blob. The documented workaround is `acquire_csi_force_lltf = 1`. A capture on 2026-09-09 collapsed to one distinct 106-byte payload over 887 packets from 22 transmitters, so the firmware ran with the workaround off. It is now on (`CSI_FORCE_LLTF` is 1), which limits CSI to L-LTF and keeps a link's payload length constant. A 300-packet capture on 2026-09-16 held per-subcarrier variation of 0.72 to 1.54, so the payloads differ.
- [esp-idf#14271](https://github.com/espressif/esp-idf/issues/14271): the HT-LTF subcarrier order differs from the S3 on HE parts. A channel 6 capture held 2.71M 106-byte L-LTF records and 454k 114-byte HT-LTF records, so about 14% of traffic arrives as HT-LTF. Each link locks to the first payload length it sees and rejects the other format, so a link's scorer never mixes the two layouts. The status line reports the rejected count as `fmtdrop`.
- [esp-csi#258](https://github.com/espressif/esp-csi/issues/258): Espressif publishes a chip CSI ranking of `C5 > C6 > C3 ~= S3 > ESP32` and has not said what it measures.

### Why the C5 ingests more

Measured on channel 6 in the same room, over the same 15 s intervals, with no SoftAP client on either board:

| Frames per 15 s | DSSS | Legacy 11g | HT |
|---|---|---|---|
| S3 | 5983-7279 | 1129 | 3-12 |
| C5 | 5983 | 3020 | 194-666 |

The S3 hears more DSSS, so both radios get the same air. These causes were ruled out by measurement:

- Receiver sensitivity (the gap is widest on the strongest frames).
- STA and AP bandwidth.
- The `esp_wifi_set_protocol` bits (`0x07`, 11N on).
- The promiscuous filter.
- Misclassification (`sig_mode==0` frames all read `aggregation=0`, `mcs=0`).

The result matches [esp-idf#736](https://github.com/espressif/esp-idf/issues/736), which was closed on the grounds that no 11n traffic was in the air. Here a C5 12 cm away decoded hundreds of HT frames per 15 s.

The gap depends on the channel. On channel 1 the same S3 decoded 10120 HT frames, 15.7% of its OFDM, against the C5's 33.6% on channel 6. Why channel 6 starved the S3 is unexplained. Let the channel survey pick the channel.

## CSI field reference

The decoder relies on documented properties of the C5 CSI path. Source: [ESP-IDF v5.5.3, Wi-Fi Driver, ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi.html).

- "Each item is stored as two bytes: imaginary part followed by real part." For that layout, `csiAmplitudesLen` reads `buf[k*2]` as imaginary and `buf[k*2+1]` as real. The measured C5 L-LTF payload does not match it and takes the 12-bit path (see esp-idf#18982 above).
- "If `first_word_invalid` of `wifi_csi_info_t` is true, it means that the first four bytes of CSI data is invalid due to a hardware limitation in ESP32-C5." When the flag is set, the decoder skips the first four bytes. That is one 4-byte subcarrier on the 106-byte L-LTF path and two 2-byte subcarriers otherwise.
- "If `rx_channel_estimate_info_vld` of `rx_ctrl` field is 1, indicates that the CSI data is valid; otherwise, the CSI data is invalid." The status line counts valid and invalid packets as `ce=<valid>/<invalid>`. The `csiRequireCeVld` setting drops packets whose flag is 0.
- `val_scale_cfg` (`esp_wifi_he_types.h:61`, "value 0-8") is set to 0. This is open. The C5 reads far quieter than the S3 on the same channel and trigger: over 30 minutes, 1.6% of samples crossed the line against 21.7%. The field has no documented meaning and is untested.
- `lltf_bit_mode` (`esp_wifi_he_types.h:63`, "0 : 12-bit, 1 : 8-bit, default : 12-bit"): `csiArmCsi` sets 0. The 106-byte L-LTF payload is 12-bit words in 2-byte containers, and `csiAmplitudesLen` decodes it with `csiWord12` (26 subcarriers). Other buffer lengths use the int8-pair path.

`CSIR` raw dump lines end with `,L<len>,F<0|1>`: the packet's `ev.len` and `first_word_invalid`. Without them you cannot decode a capture correctly, because the dump writes every packet as a fixed 114-byte buffer while only `len` bytes are valid.
