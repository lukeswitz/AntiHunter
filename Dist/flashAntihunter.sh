#!/bin/bash
set -e

# Variables
ESPTOOL_REPO="https://github.com/alphafox02/esptool"
FIRMWARE_OPTIONS=(
    "AntiHunter Full - v0.6.8 Beta :https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/ah_beta_v06_9_full.bin"
    "AntiHunter Headless - v0.6.8 Beta:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/ah_beta_v06_9_headless.bin"
)
ESPTOOL_DIR="esptool"
CUSTOM_BIN=""
ERASE_FLASH=false
CONFIG_MODE=false

# PlatformIO Config Values
MONITOR_SPEED=115200
UPLOAD_SPEED=230400
ESP32_PORT=""

show_help() {
    cat << EOF
Usage: $0 [OPTION]
Flash firmware to ESP32 devices.

Options:
  -f, --file FILE    Path to custom .bin file to flash
  -e, --erase        Erase flash before flashing (default: no)
  -c, --configure    Configure device parameters during flash
  -h, --help         Display this help message and exit
  -l, --list         List available firmware options and exit

Without options, the script will run in interactive mode.
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
        read -p "Node ID (AH + 1-3 digits, leave empty for auto): " NODE_ID
        
        if [ -z "$NODE_ID" ]; then
            echo "Using auto-generated node ID"
            break
        fi
        
        NODE_ID=$(echo "$NODE_ID" | tr '[:lower:]' '[:upper:]')
        
        if [[ ! "$NODE_ID" =~ ^AH ]]; then
            echo "Node ID must start with 'AH' prefix"
            echo "Example: AH1, AH42, AH999"
            continue
        fi
        
        NODE_ID_SUFFIX="${NODE_ID:2}"
        
        if [ ${#NODE_ID_SUFFIX} -lt 1 ] || [ ${#NODE_ID_SUFFIX} -gt 3 ]; then
            echo "Node ID must have 1-3 digits after 'AH' (total 3-5 chars)"
            echo "You entered: $NODE_ID (length ${#NODE_ID})"
            echo "Example: AH1 (3 chars), AH42 (4 chars), AH999 (5 chars)"
            continue
        fi
        
        if [[ ! "$NODE_ID_SUFFIX" =~ ^[0-9]+$ ]]; then
            echo "Characters after 'AH' must be digits only (0-9)"
            echo "Invalid characters detected in: $NODE_ID_SUFFIX"
            echo "Example: AH1 ✓, AH42 ✓, AH999 ✓, AHAB ✗, AH-1 ✗"
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
    
    echo ""
    read -p "WiFi channels (comma-separated or range like 1..11) [default: 1,6,11]: " CHANNELS
    CHANNELS=${CHANNELS:-"1,6,11"}
    
    echo ""
    read -p "Mesh send interval in milliseconds [default: 3000]: " MESH_INTERVAL
    MESH_INTERVAL=${MESH_INTERVAL:-3000}
    
    echo ""
    read -p "Target MAC addresses (comma-separated, leave empty for none): " TARGETS
    
    echo ""
    echo "RF Preset:"
    echo "  0 - Balanced"
    echo "  1 - Fast scan"
    echo "  2 - Deep scan"
    read -p "Select RF preset (0-2) [default: 0]: " RF_PRESET
    RF_PRESET=${RF_PRESET:-0}
    
    echo ""
    read -p "Baseline RAM cache size [default: 400]: " BASELINE_RAM
    BASELINE_RAM=${BASELINE_RAM:-400}
    
    read -p "Baseline SD max devices [default: 50000]: " BASELINE_SD
    BASELINE_SD=${BASELINE_SD:-50000}
    
    cat > /tmp/antihunter_config.json <<EOF
{"nodeId":"$NODE_ID","scanMode":$SCAN_MODE,"channels":"$CHANNELS","meshInterval":$MESH_INTERVAL,"maclist":"$TARGETS","rfPreset":$RF_PRESET,"baselineRamSize":$BASELINE_RAM,"baselineSdMax":$BASELINE_SD}
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
        -e|--erase)
            ERASE_FLASH=true
            shift
            ;;
        -c|--configure)
            CONFIG_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
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

PYTHON_CMD=python3
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD=python
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python (python3 or python) not found. Please install Python."
        exit 1
    fi
fi

if command -v esptool &>/dev/null; then
    ESPTOOL_CMD="esptool"
elif command -v esptool.py &>/dev/null; then
    ESPTOOL_CMD="esptool.py"
else
    if [ ! -f "$ESPTOOL_DIR/esptool.py" ]; then
        echo "Cloning esptool repository..."
        git clone "$ESPTOOL_REPO" "$ESPTOOL_DIR"
    fi
    ESPTOOL_CMD="$PYTHON_CMD $ESPTOOL_DIR/esptool.py"
fi

echo ""
echo "====================================="
echo "Unified for multiple ESP32S3 configs"
echo "====================================="

if [ -n "$CUSTOM_BIN" ]; then
    if [ ! -f "$CUSTOM_BIN" ]; then
        echo "Error: Custom file '$CUSTOM_BIN' not found."
        exit 1
    fi
    FIRMWARE_FILE="$CUSTOM_BIN"
    firmware_choice="Custom firmware: $(basename "$CUSTOM_BIN")"
else
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
                
                FIRMWARE_DIR=$(dirname "$FIRMWARE_URL")
                BOOTLOADER_URL="$FIRMWARE_DIR/bootloader.bin"
                PARTITIONS_URL="$FIRMWARE_DIR/partitions.bin"
                BOOTLOADER_FILE="bootloader.bin"
                PARTITIONS_FILE="partitions.bin"
                
                echo "Downloading bootloader..."
                if curl -fLo "$BOOTLOADER_FILE" "$BOOTLOADER_URL" 2>/dev/null; then
                    echo "Bootloader downloaded successfully."
                else
                    echo "Warning: Could not download bootloader.bin from $BOOTLOADER_URL"
                    BOOTLOADER_FILE=""
                fi
                
                echo "Downloading partitions..."
                if curl -fLo "$PARTITIONS_FILE" "$PARTITIONS_URL" 2>/dev/null; then
                    echo "Partitions downloaded successfully."
                else
                    echo "Warning: Could not download partitions.bin from $PARTITIONS_URL"
                    PARTITIONS_FILE=""
                fi
                
            else
                read -p "Enter path to custom .bin file: " custom_file
                if [ ! -f "$custom_file" ]; then
                    echo "Error: File '$custom_file' not found."
                    exit 1
                fi
                FIRMWARE_FILE="$custom_file"
                firmware_choice="Custom firmware: $(basename "$custom_file")"
                
                CUSTOM_DIR=$(dirname "$custom_file")
                BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
                PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"
                
                if [ ! -f "$BOOTLOADER_FILE" ]; then
                    BOOTLOADER_FILE=""
                fi
                
                if [ ! -f "$PARTITIONS_FILE" ]; then
                    PARTITIONS_FILE=""
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

if [ "$CONFIG_MODE" = true ]; then
    collect_configuration
fi

if [ "$ERASE_FLASH" = false ]; then
    echo ""
    read -p "Erase flash before flashing? (y/N): " erase_response
    if [[ "$erase_response" =~ ^[Yy]$ ]]; then
        ERASE_FLASH=true
    fi
fi

if [ "$ERASE_FLASH" = true ]; then
    echo ""
    echo "==================================================="
    echo "Erasing flash memory..."
    echo "==================================================="
    $ESPTOOL_CMD \
        --chip auto \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        erase-flash
    echo "Flash erase complete."
    echo ""
    
    if [ -z "$BOOTLOADER_FILE" ] || [ ! -f "$BOOTLOADER_FILE" ]; then
        echo "Bootloader required after flash erase."
        read -p "Enter path to bootloader.bin: " bootloader_path
        if [ -f "$bootloader_path" ]; then
            BOOTLOADER_FILE="$bootloader_path"
        else
            echo "ERROR: Bootloader file not found. Cannot proceed after erase."
            exit 1
        fi
    fi
    
    if [ -z "$PARTITIONS_FILE" ] || [ ! -f "$PARTITIONS_FILE" ]; then
        echo "Partition table required after flash erase."
        read -p "Enter path to partitions.bin: " partitions_path
        if [ -f "$partitions_path" ]; then
            PARTITIONS_FILE="$partitions_path"
        else
            echo "ERROR: Partition file not found. Cannot proceed after erase."
            exit 1
        fi
    fi
fi

echo ""
if [ "$ERASE_FLASH" = true ] && [ -n "$BOOTLOADER_FILE" ] && [ -n "$PARTITIONS_FILE" ]; then
    echo "Flashing complete firmware (bootloader + partitions + app)..."
    $ESPTOOL_CMD \
        --chip auto \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        --before default-reset \
        --after hard-reset \
        write-flash -z \
        --flash-size detect \
        0x0 "$BOOTLOADER_FILE" \
        0x8000 "$PARTITIONS_FILE" \
        0x10000 "$FIRMWARE_FILE"
else
    echo "Flashing application firmware only to 0x10000..."
    $ESPTOOL_CMD \
        --chip auto \
        --port "$ESP32_PORT" \
        --baud "$UPLOAD_SPEED" \
        --before default-reset \
        --after hard-reset \
        write-flash -z \
        --flash-size detect \
        0x10000 "$FIRMWARE_FILE"
fi

echo ""
echo "==================================================="
echo "Firmware flashing complete!"
echo "==================================================="

echo ""
echo "Device initialization..."
sleep 3

if [ "$CONFIG_MODE" = true ]; then
    echo ""
    echo "Sending configuration to device..."
    
    CONFIG_JSON_COMPACT=$(cat /tmp/antihunter_config.json | tr -d '\n' | tr -d ' ')
    
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
    config_cmd = 'CONFIG:$CONFIG_JSON_COMPACT\n'
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

    rm -f /tmp/antihunter_config.json
    
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
  
  # Clear buffer
  ser.reset_input_buffer()
  
  ser.write(b'SETTIME:$EPOCH\n')
  ser.flush()
  time.sleep(0.5)
  
  # Read until we get actual RTC response
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

if [ -z "$CUSTOM_BIN" ] && [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
  rm -f "$FIRMWARE_FILE"
  [ -n "$BOOTLOADER_FILE" ] && rm -f "bootloader.bin"
  [ -n "$PARTITIONS_FILE" ] && rm -f "partitions.bin"
fi

echo ""
echo "Done."