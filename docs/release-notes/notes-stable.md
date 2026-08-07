# AntiHunter v1.0.1 (stable)

Stable channel · Previous release v1.0.0 (2026-08-05)

## What's Changed

### Full FW

- Data explorer: show all found devices
- Fixed possible WiFi channel pin in some scans
- Fixed stop button/scan behavior when ending a task
- Probe results: Broadcast group opens by default
- Probe Devices: real Type column, new Ch column

### Headless FW

- Fix USB serial commands being eaten by loop
- Fix potential stuck scan and dropped STOP

### Both

- Labels devices BLE/WiFi in probe and randomization scans
- New vendor lookup database in results and data explorer
- Device names no longer land in the Vendor column
- Probe scan now captures BLE
- STOP responds in under a second, was up to 60s
- Sentinel pin mode no longer drops AP clients
- Fixed empty first BLE scan window

### Experimental

On the Experimental flasher channel, for testing:

- ESP32-C5 full and headless: dual-band 2.4/5 GHz, band set at flash time or with `CONFIG_BAND`
- RadarNode C5: HLK-LD2451 radar. No serial config on this build.
- Breadboard the C5 first. Desoldering is the only way back to an S3.

### Docs and tooling

- `scripts/meshtastic_config.py` configures the mesh radio
- ESP32-C5 page, node-types table
- BOM: 8GB and FAT32 SD cards work
