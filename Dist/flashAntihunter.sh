#!/bin/bash
set -e

# Variables
ESPTOOL_REPO="https://github.com/alphafox02/esptool"
FIRMWARE_OPTIONS=(
    "AntiHunter - v3:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_s3_v3.bin"
    "AntiHunter Mesh - v4:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_proto_v4.bin"
)
ESPTOOL_DIR="esptool"

# PlatformIO Config Values
MONITOR_SPEED=115200
UPLOAD_SPEED=115200
ESP32_PORT=""

# Function to find serial devices
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

clear

cat <<'BANNER'
▄▖  ▗ ▘▖▖    ▗     
▌▌▛▌▜▘▌▙▌▌▌▛▌▜▘█▌▛▘
▛▌▌▌▐▖▌▌▌▙▌▌▌▐▖▙▖▌ 
BANNER

# Check for esptool.py system-wide or clone if missing
if command -v esptool.py &>/dev/null; then
    ESPTOOL_CMD="esptool.py"
else
    if [ ! -f "$ESPTOOL_DIR/esptool.py" ]; then
        echo "Cloning esptool repository..."
        git clone "$ESPTOOL_REPO" "$ESPTOOL_DIR"
    fi
    ESPTOOL_CMD="$PYTHON_CMD $ESPTOOL_DIR/esptool.py"
fi

echo ""
echo "============================"
echo "Available firmware options:"
echo "============================"

declare -a options_array
for i in "${!FIRMWARE_OPTIONS[@]}"; do
    echo "$((i+1)). ${FIRMWARE_OPTIONS[$i]%%:*}"
    options_array[i]="${FIRMWARE_OPTIONS[$i]%%:*}"
done
echo ""

while true; do
    read -p "Select number to flash (1-${#FIRMWARE_OPTIONS[@]}): " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
        firmware_choice="${options_array[$((choice-1))]}"

        for option in "${FIRMWARE_OPTIONS[@]}"; do
            if [[ "$option" == "$firmware_choice:"* ]]; then
                FIRMWARE_URL="${option#*:}"
                FIRMWARE_FILE=$(basename "$FIRMWARE_URL")
                break
            fi
        done

        echo ""
        echo "Downloading fresh $firmware_choice firmware..."
        curl -fLo "$FIRMWARE_FILE" "$FIRMWARE_URL" || { echo "Error downloading firmware. Please check the URL and your connection."; exit 1; }

        break
    else
        echo "Invalid selection. Please enter a number between 1 and ${#FIRMWARE_OPTIONS[@]}."
    fi
done

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

echo ""
echo "Flashing $firmware_choice firmware to the device..."
PYTHON_CMD=python3
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD=python
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python (python3 or python) not found. Please install Python."
        exit 1
    fi
fi

$ESPTOOL_CMD \
    --chip auto \
    --port "$ESP32_PORT" \
    --baud "$UPLOAD_SPEED" \
    --before default_reset \
    --after hard_reset \
    write_flash -z \
    --flash_mode dio \
    --flash_freq 80m \
    --flash_size detect \
    0x10000 "$FIRMWARE_FILE"

echo ""
echo "==================================================="
echo "Firmware flashing complete!"
echo "==================================================="

cd ..
rm -f "$FIRMWARE_FILE"

echo "Done."
