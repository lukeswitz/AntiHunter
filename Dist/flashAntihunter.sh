#!/bin/bash
set -e

ESPTOOL_REPO="https://github.com/alphafox02/esptool"
FIRMWARE_OPTIONS=(
    "AntiHunter Full - v0.6.8 Beta :https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/ah_beta_v06_9_full.bin"
    "AntiHunter Headless - v0.6.8 Beta:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/ah_beta_v06_9_headless.bin"
)
ESPTOOL_DIR="esptool"
CUSTOM_BIN=""
CONFIG_MODE=false
IS_HEADLESS=false

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
  -h, --help         Display this help message and exit
  -l, --list         List available firmware options and exit

Script always performs full erase and flashes bootloader + partitions + app.
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
    
    if [ "$IS_HEADLESS" = false ]; then
        echo ""
        echo "WiFi Access Point Configuration:"
        read -p "WiFi SSID [default: Antihunter]: " AP_SSID
        AP_SSID=${AP_SSID:-"Antihunter"}
        
        read -p "WiFi Password (min 8 chars, empty for default): " AP_PASS
        if [ -z "$AP_PASS" ]; then
            AP_PASS="antihunter"
        fi
        
        AP_SSID_JSON=",\"apSsid\":\"$AP_SSID\",\"apPass\":\"$AP_PASS\""
    else
        AP_SSID_JSON=""
    fi
    
    echo ""
    echo "Auto-Erase Configuration:"
    read -p "Enable auto-erase? (y/N): " AUTO_ERASE_ENABLED
    if [[ "$AUTO_ERASE_ENABLED" =~ ^[Yy]$ ]]; then
        AUTO_ERASE_ENABLED="true"
        read -p "Auto-erase delay in seconds [default: 300]: " AUTO_ERASE_DELAY
        AUTO_ERASE_DELAY=${AUTO_ERASE_DELAY:-300}
        
        read -p "Auto-erase cooldown in seconds [default: 600]: " AUTO_ERASE_COOLDOWN
        AUTO_ERASE_COOLDOWN=${AUTO_ERASE_COOLDOWN:-600}
        
        read -p "Vibrations required [default: 3]: " VIBRATIONS_REQUIRED
        VIBRATIONS_REQUIRED=${VIBRATIONS_REQUIRED:-3}
        
        read -p "Detection window in seconds [default: 10]: " DETECTION_WINDOW
        DETECTION_WINDOW=${DETECTION_WINDOW:-10}
        
        read -p "Setup delay in seconds [default: 60]: " SETUP_DELAY
        SETUP_DELAY=${SETUP_DELAY:-60}
    else
        AUTO_ERASE_ENABLED="false"
        AUTO_ERASE_DELAY=300
        AUTO_ERASE_COOLDOWN=600
        VIBRATIONS_REQUIRED=3
        DETECTION_WINDOW=10
        SETUP_DELAY=60
    fi
    
    cat > /tmp/antihunter_config.json <<EOF
{"nodeId":"$NODE_ID","scanMode":$SCAN_MODE,"channels":"$CHANNELS","meshInterval":$MESH_INTERVAL,"targets":"$TARGETS","rfPreset":$RF_PRESET,"wifiChannelTime":120,"wifiScanInterval":4000,"bleScanInterval":2000,"bleScanDuration":2000,"baselineRamSize":$BASELINE_RAM,"baselineSdMax":$BASELINE_SD${AP_SSID_JSON},"autoEraseEnabled":$AUTO_ERASE_ENABLED,"autoEraseDelay":$AUTO_ERASE_DELAY,"autoEraseCooldown":$AUTO_ERASE_COOLDOWN,"vibrationsRequired":$VIBRATIONS_REQUIRED,"detectionWindow":$DETECTION_WINDOW,"setupDelay":$SETUP_DELAY}
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
    
    if [[ "$CUSTOM_BIN" == *"headless"* ]]; then
        IS_HEADLESS=true
    fi
    
    CUSTOM_DIR=$(dirname "$CUSTOM_BIN")
    BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
    PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"
    
    if [ ! -f "$BOOTLOADER_FILE" ] || [ ! -f "$PARTITIONS_FILE" ]; then
        echo "ERROR: Custom firmware requires bootloader.bin and partitions.bin in same directory"
        exit 1
    fi
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
                
                if [[ "$firmware_choice" == *"Headless"* ]]; then
                    IS_HEADLESS=true
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
                
                FIRMWARE_DIR=$(dirname "$FIRMWARE_URL")
                BOOTLOADER_URL="$FIRMWARE_DIR/bootloader.bin"
                PARTITIONS_URL="$FIRMWARE_DIR/partitions.bin"
                BOOTLOADER_FILE="bootloader.bin"
                PARTITIONS_FILE="partitions.bin"
                
                echo "Downloading bootloader..."
                curl -fLo "$BOOTLOADER_FILE" "$BOOTLOADER_URL" || { echo "ERROR: Failed to download bootloader.bin"; exit 1; }
                
                echo "Downloading partitions..."
                curl -fLo "$PARTITIONS_FILE" "$PARTITIONS_URL" || { echo "ERROR: Failed to download partitions.bin"; exit 1; }
                
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
                
                CUSTOM_DIR=$(dirname "$custom_file")
                BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
                PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"
                
                if [ ! -f "$BOOTLOADER_FILE" ] || [ ! -f "$PARTITIONS_FILE" ]; then
                    echo "ERROR: Custom firmware requires bootloader.bin and partitions.bin in same directory"
                    exit 1
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

if [ -z "$CUSTOM_BIN" ] && [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
  rm -f "$FIRMWARE_FILE"
  rm -f "bootloader.bin"
  rm -f "partitions.bin"
fi

echo ""
echo "Done."