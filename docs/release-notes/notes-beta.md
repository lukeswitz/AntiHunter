# AntiHunter v1.0.3-beta1 (beta)

Beta channel · Previous release v1.0.2-beta1 (2026-08-07)

## What's Changed

### New

- **CSI motion detection** (full + headless): device-free WiFi motion sensing on the WiDetect ACF statistic, per-area movement strength, on-device whole-session heatmap, throttled mesh alerts.
- **Fleet roster** (full, System tab): live roster of mesh nodes and radios, a card for this node, per-node mode/uptime/temp/hits/GPS, collapsible, privacy redaction of coordinates and names.
- **Hidden SoftAP mode** (full): run the web UI on a non-broadcast SSID.
- **Accent colour picker** (full, System tab): choose the UI accent colour.
- **Data Explorer privacy toggle** (full): redact MACs, SSIDs and coordinates in the Data tab.

### Both FW

- Baseline no longer panics under low heap: the SD write path is heap-guarded and baseline BLE/history caches are capped to internal RAM.
- BLE result vector is bounded in every scan mode.
- Mesh enable now persists across reboot.
- Mesh TX can be cancelled without killing the running scan.
- Failed task creation is reported instead of silently wedging the node.
- Mesh sender names with emoji no longer drop the command.

### Headless FW

- CSI motion detection runs at full parity with Full.

### Full FW

- Fleet: this node shows as its own card; a node's own transport radio no longer appears under Other Mesh Radios.
- Frozen results pane fixed; results flicker removed and alert hues tuned.
- Theme toggle stays in the mobile scan header.
- `FLEET` serial command dumps the fleet roster as JSON.

### Flasher

- C5 experimental channel carries the same CSI, Fleet and fixes for testing.

### Docs & Kit

- Operator's guide and per-tier welcome notes refreshed; BOM corrections (JST terminals, USB-C 5V, fan screws, optional battery fuse).
