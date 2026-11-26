#!/bin/bash
set -e

STABLE_BRANCH="main"
STABLE_VERSION="v1.0.5"
BETA_BRANCH="beta"
BETA_VERSION="v1.0.5-beta1"
# ESP32-C5 beta builds and the experimental RadarNode. Served from main/Dist until the C5 branches are published.
C5_BRANCH="main"
C5_VERSION="v1.0.5-c5exp1"
RADAR_BRANCH="main"
RADAR_VERSION="v0.1.0-radarexp2"

FIRMWARE_OPTIONS=()
IS_C5=false
CONFIG_FILE=""
trap 'rm -f "$CONFIG_FILE"' EXIT

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

in_range() {
    [[ "$1" =~ ^-?[0-9]+$ ]] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

ask_range() {
    local prompt=$1 lo=$2 hi=$3 def=$4 v
    while true; do
        read -p "$prompt, $lo-$hi [default: $def]: " v
        v=${v:-$def}
        if in_range "$v" "$lo" "$hi"; then printf '%s' "$v"; return; fi
        echo "Enter a number from $lo to $hi." >&2
    done
}

add_opt() {
    local prompt=$1 lo=$2 hi=$3 key=$4 scale=$5 def=${6:-} v
    while true; do
        read -p "$prompt, $lo to $hi${def:+ [default: $def]}: " v
        v=${v:-$def}
        if [ -z "$v" ]; then return 0; fi
        if in_range "$v" "$lo" "$hi"; then
            EXTRA_JSON="$EXTRA_JSON,\"$key\":$((v * scale))"
            return 0
        fi
        echo "Enter a number from $lo to $hi, or leave it empty."
    done
}

select_channel() {
    if [ ${#FIRMWARE_OPTIONS[@]} -gt 0 ]; then
        return
    fi
    local branch version label
    echo "Release channel:"
    echo "  1. Stable ($STABLE_VERSION) - ESP32-S3, tested, recommended"
    echo "  2. Beta ($BETA_VERSION) - ESP32-S3, newest features, may be unstable"
    echo "  3. Beta - XIAO ESP32-C5 (2.4 + 5GHz), newest features, may be unstable. Also the experimental RadarNode."
    echo ""
    while true; do
        read -p "Select channel (1-3) [default: 1]: " ch
        ch=${ch:-1}
        case "$ch" in
            1) branch="$STABLE_BRANCH"; version="$STABLE_VERSION"; label="Stable"; break ;;
            2) branch="$BETA_BRANCH"; version="$BETA_VERSION"; label="Beta"; break ;;
            3) IS_C5=true; break ;;
            *) echo "Invalid selection. Enter 1, 2 or 3." ;;
        esac
    done

    if [ "$IS_C5" = true ]; then
        echo ""
        echo "Breadboard the C5 and test it before you solder anything. A C5 soldered into a"
        echo "PCB can only be put back on stable firmware by desoldering it and fitting an"
        echo "ESP32-S3 in its place."
        echo ""
        echo "These builds are not on the stable release track and are still being tested on"
        echo "hardware."
        read -p "Continue? (y/N): " ack
        case "$ack" in
            [Yy]*) ;;
            *) echo "Canceled."; exit 0 ;;
        esac
        local c5base="https://github.com/lukeswitz/AntiHunter/raw/refs/heads/$C5_BRANCH/Dist"
        local rbase="https://github.com/lukeswitz/AntiHunter/raw/refs/heads/$RADAR_BRANCH/Dist"
        FIRMWARE_OPTIONS=(
            "AntiHunter AP (With WiFi AP) - $C5_VERSION C5:$c5base/antihunter-c5-full-$C5_VERSION.factory.bin"
            "AntiHunter Headless - (Mesh only) $C5_VERSION C5:$c5base/antihunter-c5-headless-$C5_VERSION.factory.bin"
            "RadarNode (24GHz radar) - $RADAR_VERSION C5:$rbase/radarnode-c5-$RADAR_VERSION.factory.bin"
        )
        echo ""
        return
    fi

    local base="https://github.com/lukeswitz/AntiHunter/raw/refs/heads/$branch/Dist"
    FIRMWARE_OPTIONS=(
        "AntiHunter AP (With WiFi AP) - $version $label:$base/antihunter-full-$version.bin"
        "AntiHunter Headless - (Mesh only) $version $label:$base/antihunter-headless-$version.bin"
    )
    echo ""
}

CUSTOM_BIN=""
CONFIG_MODE=false
NO_FLASH=false
EXTRA_JSON=""
IS_HEADLESS=false
IS_RADAR=false
FACTORY_MODE=false
ERASE_FLASH=false

MONITOR_SPEED=115200
UPLOAD_SPEED=230400
ESP32_PORT=""

show_help() {
    cat << EOF
Usage: $0 [OPTION]
Flash firmware to ESP32 devices.

Options:
  -f, --file FILE    Path to custom .bin file to flash
  -c, --configure    Configure device parameters during flash
  -n, --no-flash     Configure a node that is already flashed, without flashing
  -e, --erase        Erase flash memory before flashing (optional)
  -h, --help         Display this help message and exit
  -l, --list         List available firmware options and exit

S3 builds ship bootloader + partitions + app and are written at 0x0/0x8000/0x10000.
C5 builds ship a single .factory.bin written at 0x0; a custom .bin ending
in .factory.bin is treated the same way. Use --erase to perform full flash erase first.

Requires esptool and pyserial. Install them with your system package manager.
EOF
}

find_serial_devices() {
    local devices=""

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        devices=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true)
        if [ -z "$devices" ] && [ -d "/dev/serial/by-id" ]; then
            devices=$(ls /dev/serial/by-id/* 2>/dev/null || true)
        fi
        if [ -z "$devices" ] && [ -d "/dev/serial/by-path" ]; then
            devices=$(ls /dev/serial/by-path/* 2>/dev/null || true)
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        devices=$(ls /dev/cu.* 2>/dev/null | grep -i -E 'usb|serial|usbmodem' || true)
    fi

    echo "$devices"
}

collect_configuration() {
    echo ""
    echo "==================================================="
    echo "Device Configuration Setup"
    echo "==================================================="
    echo ""

    while true; do
        read -p "Node ID (2-5 alphanumeric characters, leave empty for auto): " NODE_ID

        if [ -z "$NODE_ID" ]; then
            echo "Using auto-generated node ID"
            break
        fi

        NODE_ID=$(echo "$NODE_ID" | tr '[:lower:]' '[:upper:]')

        if [ ${#NODE_ID} -lt 2 ] || [ ${#NODE_ID} -gt 5 ]; then
            echo "Node ID must be 2-5 characters"
            echo "You entered: $NODE_ID (length ${#NODE_ID})"
            echo "Examples: AB (2 chars), A1C (3 chars), XYZ99 (5 chars)"
            continue
        fi

        if [[ ! "$NODE_ID" =~ ^[A-Z0-9]+$ ]]; then
            echo "Only alphanumeric characters (A-Z, 0-9) allowed"
            echo "Examples: AB ✓, A1C ✓, XYZ99 ✓, AB-1 ✗, A_BC ✗"
            continue
        fi

        echo "✓ Valid node ID: $NODE_ID"
        break
    done

    echo ""
    echo "Scan Mode:"
    echo "  0 - WiFi only"
    echo "  1 - BLE only"
    echo "  2 - Both WiFi and BLE"
    read -p "Select scan mode (0-2) [default: 2]: " SCAN_MODE
    SCAN_MODE=${SCAN_MODE:-2}
    read -p "BLE long range (Bluetooth 5)? Normal BLE gets less listening time (y/N): " BLE_LR_ON
    if [[ "$BLE_LR_ON" =~ ^[Yy]$ ]]; then BLE_LONG_RANGE="true"; else BLE_LONG_RANGE="false"; fi

    echo ""
    local ch_default="1..11"
    [ "$IS_C5" = true ] && ch_default="1,6,11"
    read -p "WiFi channels (comma-separated or range like 1..11) [default: $ch_default]: " CHANNELS
    CHANNELS=${CHANNELS:-"$ch_default"}

    BAND_JSON=""
    if [ "$IS_C5" = true ]; then
        echo ""
        echo "Band: 0 = 2.4GHz, 1 = 5GHz, 2 = both"
        read -p "Band [default: 0]: " BAND_MODE
        BAND_MODE=${BAND_MODE:-0}
        case "$BAND_MODE" in
            0|1|2) BAND_JSON=",\"bandMode\":$BAND_MODE" ;;
            *) echo "Invalid band, using firmware default."; BAND_JSON="" ;;
        esac
    fi

    echo ""
    read -p "Mesh send interval in milliseconds [default: 3000]: " MESH_INTERVAL
    MESH_INTERVAL=${MESH_INTERVAL:-3000}

    echo ""
    read -p "Target MAC addresses (comma-separated, leave empty for none): " TARGETS

    echo ""
    echo "RF Preset:"
    echo "  0 - Relaxed (low power)"
    echo "  1 - Balanced"
    echo "  2 - Aggressive (fast detection)"
    echo "  3 - Custom (you set the four scan timings)"
    read -p "Select RF preset (0-3) [default: 1]: " RF_PRESET
    RF_PRESET=${RF_PRESET:-1}
    if [ "$RF_PRESET" = "3" ]; then
        add_opt "Wi-Fi channel dwell in ms" 110 300 wifiChannelTime 1 160
        add_opt "Wi-Fi scan interval in ms" 1000 10000 wifiScanInterval 1 3000
        add_opt "BLE scan interval in ms" 1000 10000 bleScanInterval 1 4000
        add_opt "BLE scan duration in ms" 1000 5000 bleScanDuration 1 2000
    fi

    echo ""
    read -p "Mesh enabled? (Y/n): " MESH_ON
    if [[ "$MESH_ON" =~ ^[Nn]$ ]]; then MESH_ENABLED="false"; else MESH_ENABLED="true"; fi
    read -p "Mesh dedup TTL in seconds, 0 = off [default: 300]: " MESH_DEDUP_TTL
    MESH_DEDUP_TTL=${MESH_DEDUP_TTL:-300}
    read -p "Session dedup - send only devices not already sent this session? (y/N): " SESS_DEDUP
    if [[ "$SESS_DEDUP" =~ ^[Yy]$ ]]; then MESH_SESS_DEDUP="true"; else MESH_SESS_DEDUP="false"; fi
    read -p "Status heartbeat over mesh? (y/N): " HB_ON
    if [[ "$HB_ON" =~ ^[Yy]$ ]]; then
        HB_ENABLED="true"
        read -p "Heartbeat interval in minutes [default: 30]: " HB_INTERVAL
        HB_INTERVAL=${HB_INTERVAL:-30}
    else
        HB_ENABLED="false"
        HB_INTERVAL=30
    fi

    echo ""
    read -p "Vibration sensor alerts? (Y/n): " VIB_ON
    if [[ "$VIB_ON" =~ ^[Nn]$ ]]; then VIB_ENABLED="false"; else VIB_ENABLED="true"; fi
    read -p "Start a scan when the node is bumped? (y/N): " VIBSCAN_ON
    if [[ "$VIBSCAN_ON" =~ ^[Yy]$ ]]; then
        VIBSCAN_ENABLED="true"
        echo "  1 - Device discovery   2 - Probe requests   3 - Randomized MAC tracer"
        echo "  4 - Target scan        5 - Drone RID        6 - Deauth detection"
        echo "  7 - Baseline anomaly   8 - Packet capture to SD"
        read -p "Scan to run (1-8) [default: 1]: " VIBSCAN_MODE
        VIBSCAN_MODE=${VIBSCAN_MODE:-1}
        read -p "Duration in seconds, 0 = until stopped [default: 60]: " VIBSCAN_DURATION
        VIBSCAN_DURATION=${VIBSCAN_DURATION:-60}
        read -p "Cooldown in seconds [default: 60]: " VIBSCAN_COOLDOWN
        VIBSCAN_COOLDOWN=${VIBSCAN_COOLDOWN:-60}
    else
        VIBSCAN_ENABLED="false"
        VIBSCAN_MODE=0
        VIBSCAN_DURATION=60
        VIBSCAN_COOLDOWN=60
    fi

    echo ""
    read -p "Rebuild an unmountable SD card automatically? Rebuilding erases it. (y/N): " SD_REPAIR_ON
    if [[ "$SD_REPAIR_ON" =~ ^[Yy]$ ]]; then SD_AUTO_REPAIR="true"; else SD_AUTO_REPAIR="false"; fi
    read -p "Packet capture file cap in MB, 8-300 [default: 100]: " PCAP_MAX_MB
    PCAP_MAX_MB=${PCAP_MAX_MB:-100}

    echo ""
    read -p "Baseline RAM cache size [default: 400]: " BASELINE_RAM
    BASELINE_RAM=${BASELINE_RAM:-400}

    if [ "$IS_HEADLESS" = false ]; then
        echo ""
        echo "WiFi Access Point Configuration:"
        read -p "WiFi SSID [default: Antihunter]: " AP_SSID
        AP_SSID=${AP_SSID:-"Antihunter"}

        read -p "WiFi Password (min 8 chars, empty keeps the firmware default antihunt3r123): " AP_PASS
        while [ -n "$AP_PASS" ] && [ ${#AP_PASS} -lt 8 ]; do
            read -p "Too short. WiFi Password (min 8 chars, empty keeps the default): " AP_PASS
        done
        read -p "AP security: 0 = WPA2/WPA3, 1 = WPA2 only [default: 0]: " AP_AUTH
        AP_AUTH=${AP_AUTH:-0}
        read -p "Hide the AP name (stops the beacon, not access control)? (y/N): " AP_HIDDEN_ON
        if [[ "$AP_HIDDEN_ON" =~ ^[Yy]$ ]]; then AP_HIDDEN="true"; else AP_HIDDEN="false"; fi

        read -p "Require a web UI login (user admin)? (y/N): " WEB_AUTH_ON
        if [[ "$WEB_AUTH_ON" =~ ^[Yy]$ ]]; then WEB_AUTH="true"; else WEB_AUTH="false"; fi
        WEB_PASS=""
        if [ "$WEB_AUTH" = true ]; then
            read -p "Web UI password (8-63 chars, no ':', empty uses the WiFi password): " WEB_PASS
            while [ -n "$WEB_PASS" ] && { [ ${#WEB_PASS} -lt 8 ] || [ ${#WEB_PASS} -gt 63 ] || [[ "$WEB_PASS" == *:* ]]; }; do
                read -p "Needs 8-63 chars, no ':'. Web UI password (empty uses the WiFi password): " WEB_PASS
            done
        fi

        AP_SSID_JSON=",\"apSsid\":\"$(json_escape "$AP_SSID")\",\"apAuth\":$AP_AUTH,\"apHidden\":$AP_HIDDEN,\"webAuth\":$WEB_AUTH"
        if [ -n "$AP_PASS" ]; then
            AP_SSID_JSON="$AP_SSID_JSON,\"apPass\":\"$(json_escape "$AP_PASS")\""
        fi
        if [ -n "$WEB_PASS" ]; then
            AP_SSID_JSON="$AP_SSID_JSON,\"webPass\":\"$(json_escape "$WEB_PASS")\""
        fi
    else
        AP_SSID_JSON=""
    fi

    echo ""
    echo "Auto-Erase Configuration:"
    read -p "Enable auto-erase? (y/N): " AUTO_ERASE_ENABLED
    if [[ "$AUTO_ERASE_ENABLED" =~ ^[Yy]$ ]]; then
        AUTO_ERASE_ENABLED="true"
        AUTO_ERASE_DELAY=$(ask_range "Erase countdown in seconds" 10 300 30)
        AUTO_ERASE_COOLDOWN=$(ask_range "Trigger cooldown in seconds" 300 3600 300)
        VIBRATIONS_REQUIRED=$(ask_range "Vibrations required" 2 5 3)
        DETECTION_WINDOW=$(ask_range "Detection window in seconds" 10 60 20)
        SETUP_DELAY=$(ask_range "Setup period in seconds" 30 600 120)
    else
        AUTO_ERASE_ENABLED="false"
        AUTO_ERASE_DELAY=30
        AUTO_ERASE_COOLDOWN=300
        VIBRATIONS_REQUIRED=3
        DETECTION_WINDOW=20
        SETUP_DELAY=120
    fi

    echo ""
    read -p "Erase key (8-64 chars, no ':', empty keeps the node's key): " ERASE_KEY
    while [ -n "$ERASE_KEY" ] && { [ ${#ERASE_KEY} -lt 8 ] || [ ${#ERASE_KEY} -gt 64 ] || [[ "$ERASE_KEY" == *:* ]]; }; do
        read -p "Needs 8-64 chars, no ':'. Erase key (empty keeps the node's key): " ERASE_KEY
    done
    if [ -n "$ERASE_KEY" ]; then EXTRA_JSON="$EXTRA_JSON,\"erasePSK\":\"$(json_escape "$ERASE_KEY")\""; fi

    read -p "Start Sentinel on boot? (y/N): " SENT_BOOT
    if [[ "$SENT_BOOT" =~ ^[Yy]$ ]]; then EXTRA_JSON="$EXTRA_JSON,\"sentinelBoot\":true"; fi

    echo ""
    read -p "More settings: scan timing, baseline alerts, detectors? (y/N): " MORE_ON
    if [[ "$MORE_ON" =~ ^[Yy]$ ]]; then
        echo "Leave a line empty to keep the node's value."
        add_opt "Signal filter in dBm" -100 -10 globalRssiThreshold 1
        add_opt "Baseline signal filter in dBm" -100 -10 baselineRssiThreshold 1
        add_opt "Baseline learning time in seconds" 60 3600 baselineDuration 1
        add_opt "Marked absent after seconds" 30 600 absenceThreshold 1
        add_opt "Reappearance window in seconds" 60 1800 reappearanceWindow 1
        add_opt "Signal change in dB" 5 50 rssiChangeDelta 1
        if [ "$VIBSCAN_ENABLED" = "true" ]; then
            read -p "Let the vibration scan interrupt a scheduled scan? (y/N): " VIB_PRE
            if [[ "$VIB_PRE" =~ ^[Yy]$ ]]; then EXTRA_JSON="$EXTRA_JSON,\"vibScanPreempt\":true"; fi
        fi
        if [ "$IS_HEADLESS" = false ]; then
            read -p "Keep the access point joinable during scans? (Y/n): " AP_REACH
            if [[ "$AP_REACH" =~ ^[Nn]$ ]]; then EXTRA_JSON="$EXTRA_JSON,\"apReach\":false"; fi
        fi
        local det_json=""
        read -p "Sentinel radio mode: 0 = defend one channel, 1 = scan all channels (empty keeps it): " SENT_SCAN
        case "$SENT_SCAN" in
            0) det_json="\"sentinel_scan\":false" ;;
            1) det_json="\"sentinel_scan\":true" ;;
        esac
        echo "Detector settings as key=value pairs, comma-separated. Keys are the DETECT_CFG"
        echo "keys in docs/mesh-commands.md, values are true, false or a number."
        read -p "Detector settings (empty for none): " DET_PAIRS
        local pair key val
        IFS=',' read -ra DET_LIST <<< "$DET_PAIRS"
        for pair in "${DET_LIST[@]}"; do
            pair="${pair// /}"
            [ -z "$pair" ] && continue
            key="${pair%%=*}"
            val="${pair#*=}"
            if [[ "$key" =~ ^[a-z0-9_]+$ ]] && [[ "$val" =~ ^(true|false|-?[0-9]+)$ ]]; then
                det_json="${det_json:+$det_json,}\"$key\":$val"
            else
                echo "Skipped '$pair': use key=true, key=false or key=number."
            fi
        done
        if [ -n "$det_json" ]; then EXTRA_JSON="$EXTRA_JSON,\"detectors\":{$det_json}"; fi
    fi

    local targets_json
    targets_json=$(json_escape "$TARGETS")
    targets_json=${targets_json//,/\\n}
    CONFIG_FILE=$(umask 077; mktemp "${TMPDIR:-/tmp}/antihunter_config.XXXXXX")
    cat > "$CONFIG_FILE" <<EOF
{"nodeId":"$(json_escape "$NODE_ID")","scanMode":$SCAN_MODE,"bleLongRange":$BLE_LONG_RANGE,"channels":"$(json_escape "$CHANNELS")"${BAND_JSON},"meshInterval":$MESH_INTERVAL,"meshEnabled":$MESH_ENABLED,"meshDedupTtl":$MESH_DEDUP_TTL,"meshSessDedup":$MESH_SESS_DEDUP,"hbEnabled":$HB_ENABLED,"hbInterval":$HB_INTERVAL,"vibEnabled":$VIB_ENABLED,"vibScanEnabled":$VIBSCAN_ENABLED,"vibScanMode":$VIBSCAN_MODE,"vibScanDuration":$VIBSCAN_DURATION,"vibScanCooldown":$((VIBSCAN_COOLDOWN * 1000)),"sdAutoRepair":$SD_AUTO_REPAIR,"pcapMaxFileMB":$PCAP_MAX_MB,"targets":"${targets_json}","rfPreset":$RF_PRESET,"baselineRamSize":$BASELINE_RAM${AP_SSID_JSON},"autoEraseEnabled":$AUTO_ERASE_ENABLED,"autoEraseDelay":$((AUTO_ERASE_DELAY * 1000)),"autoEraseCooldown":$((AUTO_ERASE_COOLDOWN * 1000)),"vibrationsRequired":$VIBRATIONS_REQUIRED,"detectionWindow":$((DETECTION_WINDOW * 1000)),"setupDelay":$((SETUP_DELAY * 1000))${EXTRA_JSON}}
EOF

    echo ""
    echo "Configuration prepared"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            CUSTOM_BIN="$2"
            shift
            shift
            ;;
        -c|--configure)
            CONFIG_MODE=true
            shift
            ;;
        -n|--no-flash)
            CONFIG_MODE=true
            NO_FLASH=true
            shift
            ;;
        -e|--erase)
            ERASE_FLASH=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            select_channel
            echo "Available firmware options:"
            for option in "${FIRMWARE_OPTIONS[@]}"; do
                echo "  ${option%%:*}"
            done
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

clear

cat <<'BANNER'
▄▖  ▗ ▘▖▖    ▗     
▌▌▛▌▜▘▌▙▌▌▌▛▌▜▘█▌▛▘
▛▌▌▌▐▖▌▌▌▙▌▌▌▐▖▙▖▌
BANNER

cat <<'DISCLAIMER'

LEGAL DISCLAIMER
AntiHunter is for lawful, authorized defensive use only. Use it only on networks,
devices and radio spectrum you own or have written permission to assess.
- You follow every radio rule where you operate, including your LoRa region.
- Capturing or storing radio data can be regulated by wiretap and privacy law.
  Check the law before you turn a capture mode on.
- No targeted surveillance, stalking, or tracking people without their consent.
- The maintainers are not liable for how you use it.
Full text: https://github.com/lukeswitz/AntiHunter/blob/main/docs/legal-disclaimer.md

DISCLAIMER
read -r -p "Type yes to accept and continue: " LEGAL_ACK
if [ "$(printf '%s' "$LEGAL_ACK" | tr '[:upper:]' '[:lower:]')" != "yes" ]; then
    echo "Not accepted. Nothing was flashed."
    exit 1
fi

PYTHON_CMD=python3
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD=python
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python (python3 or python) not found. Please install Python."
        exit 1
    fi
fi

install_hint() {
    echo "ERROR: esptool and pyserial are required."
    echo ""
    if command -v apt &>/dev/null; then
        echo "  sudo apt install esptool python3-serial"
    elif command -v dnf &>/dev/null; then
        echo "  sudo dnf install esptool python3-pyserial"
    elif command -v pacman &>/dev/null; then
        echo "  sudo pacman -S esptool python-pyserial"
    elif command -v brew &>/dev/null; then
        echo "  brew install esptool"
    else
        echo "  Install esptool and pyserial with your package manager."
    fi
    exit 1
}

ESPTOOL_CMD=""
for candidate in esptool esptool.py; do
    if command -v "$candidate" &>/dev/null; then
        ESPTOOL_CMD="$candidate"
        break
    fi
done
[ -z "$ESPTOOL_CMD" ] && install_hint

$PYTHON_CMD -c "import serial" &>/dev/null || install_hint

echo ""
echo "====================================="
echo "Unified for multiple ESP32S3 configs"
echo "====================================="

if [ "$NO_FLASH" = true ]; then
    read -p "Firmware on the node: 1 = Full, 2 = Headless [default: 1]: " nf_build
    [ "$nf_build" = "2" ] && IS_HEADLESS=true
    read -p "Board: 1 = ESP32-S3, 2 = XIAO ESP32-C5 [default: 1]: " nf_board
    [ "$nf_board" = "2" ] && IS_C5=true
    firmware_choice="Configure only"
elif [ -n "$CUSTOM_BIN" ]; then
    if [ ! -f "$CUSTOM_BIN" ]; then
        echo "Error: Custom file '$CUSTOM_BIN' not found."
        exit 1
    fi
    FIRMWARE_FILE="$CUSTOM_BIN"
    firmware_choice="Custom firmware: $(basename "$CUSTOM_BIN")"

    if [[ "$CUSTOM_BIN" == *"headless"* ]]; then
        IS_HEADLESS=true
    fi

    if [[ "$CUSTOM_BIN" == *.factory.bin ]]; then
        FACTORY_MODE=true
    else
        CUSTOM_DIR=$(dirname "$CUSTOM_BIN")
        BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
        PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"

        if [ ! -f "$BOOTLOADER_FILE" ] || [ ! -f "$PARTITIONS_FILE" ]; then
            echo "ERROR: Custom firmware requires bootloader.bin and partitions.bin in same directory"
            exit 1
        fi
    fi
else
    select_channel
    declare -a options_array
    for i in "${!FIRMWARE_OPTIONS[@]}"; do
        echo "$((i+1)). ${FIRMWARE_OPTIONS[$i]%%:*}"
        options_array[i]="${FIRMWARE_OPTIONS[$i]%%:*}"
    done
    echo "$((${#FIRMWARE_OPTIONS[@]}+1)). Custom .bin file"
    echo ""

    while true; do
        read -p "Select option (1-$((${#FIRMWARE_OPTIONS[@]}+1))): " choice

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $((${#FIRMWARE_OPTIONS[@]}+1)) ]; then
            if [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
                firmware_choice="${options_array[$((choice-1))]}"

                if [[ "$firmware_choice" == *"Headless"* ]]; then
                    IS_HEADLESS=true
                fi
                if [[ "$firmware_choice" == *"RadarNode"* ]]; then
                    IS_RADAR=true
                fi

                for option in "${FIRMWARE_OPTIONS[@]}"; do
                    if [[ "$option" == "$firmware_choice:"* ]]; then
                        FIRMWARE_URL="${option#*:}"
                        FIRMWARE_FILE=$(basename "$FIRMWARE_URL")
                        break
                    fi
                done

                echo ""
                echo "Downloading $firmware_choice firmware..."
                curl -fLo "$FIRMWARE_FILE" "$FIRMWARE_URL" || { echo "Error downloading firmware. Please check the URL and your connection."; exit 1; }

                # A factory image already carries bootloader + partitions + app at their offsets.
                if [[ "$FIRMWARE_URL" == *.factory.bin ]]; then
                    FACTORY_MODE=true
                else

                FIRMWARE_DIR=$(dirname "$FIRMWARE_URL")
                BOOTLOADER_URL="$FIRMWARE_DIR/bootloader.bin"
                PARTITIONS_URL="$FIRMWARE_DIR/partitions.bin"
                BOOTLOADER_FILE="bootloader.bin"
                PARTITIONS_FILE="partitions.bin"

                echo "Downloading bootloader..."
                curl -fLo "$BOOTLOADER_FILE" "$BOOTLOADER_URL" || { echo "ERROR: Failed to download bootloader.bin"; exit 1; }

                echo "Downloading partitions..."
                curl -fLo "$PARTITIONS_FILE" "$PARTITIONS_URL" || { echo "ERROR: Failed to download partitions.bin"; exit 1; }
                fi

            else
                read -p "Enter path to custom .bin file: " custom_file
                if [ ! -f "$custom_file" ]; then
                    echo "Error: File '$custom_file' not found."
                    exit 1
                fi
                FIRMWARE_FILE="$custom_file"
                firmware_choice="Custom firmware: $(basename "$custom_file")"

                if [[ "$custom_file" == *"headless"* ]]; then
                    IS_HEADLESS=true
                fi

                if [[ "$custom_file" == *.factory.bin ]]; then
                    FACTORY_MODE=true
                else
                    CUSTOM_DIR=$(dirname "$custom_file")
                    BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
                    PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"

                    if [ ! -f "$BOOTLOADER_FILE" ] || [ ! -f "$PARTITIONS_FILE" ]; then
                        echo "ERROR: Custom firmware requires bootloader.bin and partitions.bin in same directory"
                        exit 1
                    fi
                fi
            fi
            break
        else
            echo "Invalid selection. Please enter a number between 1 and $((${#FIRMWARE_OPTIONS[@]}+1))."
        fi
    done
fi

echo ""
echo "Searching for USB serial devices..."
serial_devices=$(find_serial_devices)

if [ -z "$serial_devices" ]; then
    echo "ERROR: No USB serial devices found."
    echo "Please check your connection and try again."
    exit 1
fi

echo ""
echo "==================================================="
echo "Found USB serial devices:"
echo "==================================================="
device_array=($serial_devices)
for i in "${!device_array[@]}"; do
    echo "$((i+1)). ${device_array[$i]}"
done
echo ""

while true; do
    read -p "Select USB serial device number (1-${#device_array[@]}): " device_choice

    if [[ "$device_choice" =~ ^[0-9]+$ ]] && [ "$device_choice" -ge 1 ] && [ "$device_choice" -le "${#device_array[@]}" ]; then
        ESP32_PORT="${device_array[$((device_choice-1))]}"
        echo ""
        echo "Selected USB serial device: $ESP32_PORT"
        break
    else
        echo "Invalid selection. Please enter a number between 1 and ${#device_array[@]}."
    fi
done

# RadarNode has no serial config protocol; it is configured from its own web UI.
if [ "$CONFIG_MODE" = true ] && [ "$IS_RADAR" = true ]; then
    echo ""
    echo "NOTE: RadarNode has no serial configuration. Configure it at http://192.168.4.1 after flashing."
    CONFIG_MODE=false
fi

if [ "$CONFIG_MODE" = true ]; then
    collect_configuration
fi

CHIP_ARG="auto"
[ "$IS_C5" = true ] && CHIP_ARG="esp32c5"

if [ "$ERASE_FLASH" = true ] && [ "$NO_FLASH" != true ]; then
    echo ""
    echo "==================================================="
    echo "Erasing flash memory..."
    echo "==================================================="
    $ESPTOOL_CMD \
        --chip "$CHIP_ARG" \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        erase_flash
    echo "Flash erase complete."
fi

echo ""
if [ "$NO_FLASH" = true ]; then
    echo "Restarting the node..."
    $ESPTOOL_CMD \
        --chip "$CHIP_ARG" \
        --port "$ESP32_PORT" \
        --before default_reset \
        --after hard_reset \
        chip_id
elif [ "$FACTORY_MODE" = true ]; then
    echo "Flashing factory image (bootloader + partitions + app) at 0x0..."
    $ESPTOOL_CMD \
        --chip "$CHIP_ARG" \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        --before default_reset \
        --after hard_reset \
        write_flash -z \
        --flash-size detect \
        0x0 "$FIRMWARE_FILE"
else
    echo "Flashing complete firmware (bootloader + partitions + app)..."
    $ESPTOOL_CMD \
        --chip "$CHIP_ARG" \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        --before default_reset \
        --after hard_reset \
        write_flash -z \
        --flash-size detect \
        0x0 "$BOOTLOADER_FILE" \
        0x8000 "$PARTITIONS_FILE" \
        0x10000 "$FIRMWARE_FILE"
fi

if [ "$NO_FLASH" != true ]; then
    echo ""
    echo "==================================================="
    echo "Firmware flashing complete!"
    echo "==================================================="
fi

echo ""
echo "Device initialization..."
sleep 3

if [ "$CONFIG_MODE" = true ]; then
    echo ""
    echo "Sending configuration to device..."

    $PYTHON_CMD -c "
import serial
import time
import sys

try:
    ser = serial.Serial('$ESP32_PORT', 115200, timeout=5)
    time.sleep(3)

    ser.write(b'RECONFIG\n')
    ser.flush()
    time.sleep(0.5)

    print('[CONFIG] Waiting for device ready...')
    start = time.time()
    ready = False

    while time.time() - start < 35:
        if ser.in_waiting:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            print('[DEVICE]', line)
            if 'INITIAL CONFIGURATION MODE' in line:
                ready = True
                break
        time.sleep(0.1)

    if not ready:
        print('[CONFIG] Device not in config mode - may already be configured')
        ser.close()
        sys.exit(0)

    time.sleep(0.5)
    config_cmd = 'CONFIG:' + ''.join(open('$CONFIG_FILE', encoding='utf-8').read().splitlines()) + chr(10)
    ser.write(config_cmd.encode())
    ser.flush()
    print('[CONFIG] Configuration sent')

    time.sleep(1)
    while ser.in_waiting:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        print('[DEVICE]', line)

    ser.close()
    print('[CONFIG] Configuration complete')

except Exception as e:
    print('[CONFIG] Error:', e)
    sys.exit(1)
" || echo "[CONFIG] Warning: Config send may have failed"

    rm -f "$CONFIG_FILE"

    echo ""
    echo "Waiting for device reboot..."
    sleep 8
fi

echo ""
echo "Setting RTC time..."

echo "Fetching time from NTP..."
NTP_EPOCH=$($PYTHON_CMD -c "
import socket, struct
try:
  c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  c.settimeout(3)
  c.sendto(b'\x1b' + 47 * b'\x00', ('pool.ntp.org', 123))
  d, _ = c.recvfrom(1024)
  t = struct.unpack('!12I', d)[10] - 2208988800
  print(t)
except:
  print(0)
" 2>/dev/null)

if [ "$NTP_EPOCH" -gt 0 ] 2>/dev/null; then
  EPOCH=$NTP_EPOCH
  echo "✓ NTP time: $(date -u -d @$EPOCH '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -r $EPOCH -u '+%Y-%m-%d %H:%M:%S UTC')"
else
  EPOCH=$(date +%s)
  echo "✗ NTP failed, using system time: $(date -u -d @$EPOCH '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -r $EPOCH -u '+%Y-%m-%d %H:%M:%S UTC')"
fi

$PYTHON_CMD -c "
import serial
import time
try:
  ser = serial.Serial('$ESP32_PORT', 115200, timeout=2)
  time.sleep(1)

  ser.reset_input_buffer()

  ser.write(b'SETTIME:$EPOCH\n')
  ser.flush()
  time.sleep(0.5)

  while ser.in_waiting:
    line = ser.readline().decode('utf-8', errors='ignore').strip()
    if 'RTC' in line or 'OK' in line:
      print(line)
      break

  ser.close()
  print('[RTC] Time command sent')
except Exception as e:
  print('[RTC] Failed:', e)
" 2>/dev/null

echo ""
echo "Waiting for the node to report its erase key (up to 90 s)..."
$PYTHON_CMD -c "
import serial, time, re
try:
  ser = serial.Serial('$ESP32_PORT', 115200, timeout=1)
  start = time.time()
  found = False
  while time.time() - start < 90:
    line = ser.readline().decode('utf-8', errors='ignore').strip()
    m = re.search(r'\[ERASE\] Erase key: (\S+) \(generated', line)
    if m:
      print('')
      print('===================================================')
      print('  ERASE KEY:  ' + m.group(1))
      print('  WRITE THIS DOWN. You need it to wipe this node.')
      print('  LOST IT? Reflash with erase (-e) for a new key.')
      print('===================================================')
      found = True
      break
    if '[ERASE] Erase key: set by you' in line:
      print('[ERASE] The node keeps the erase key you set earlier.')
      print('[ERASE] Lost it? Run this script again with -e for a new key.')
      found = True
      break
  ser.close()
  if not found:
    print('[ERASE] No key line seen. Open a serial monitor at 115200 and reboot the node to see it.')
except Exception as e:
  print('[ERASE] Could not read the key:', e)
" 2>/dev/null

if [ -z "$CUSTOM_BIN" ] && [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
  rm -f "$FIRMWARE_FILE"
  rm -f "bootloader.bin"
  rm -f "partitions.bin"
fi

echo ""
echo "Done."