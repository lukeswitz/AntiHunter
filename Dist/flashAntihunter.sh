#!/bin/bash
set -e

# Variables
ESPTOOL_REPO="https://github.com/alphafox02/esptool"
FIRMWARE_OPTIONS=(
    "AntiHunter - v6:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_v6.bin"
)
ESPTOOL_DIR="esptool"
CUSTOM_BIN=""

# PlatformIO Config Values
MONITOR_SPEED=115200
UPLOAD_SPEED=115200
ESP32_PORT=""

# Function to display help
show_help() {
    cat << EOF
Usage: $0 [OPTION]
Flash firmware to ESP32 devices.

Options:
  -f, --file FILE    Path to custom .bin file to flash
  -h, --help         Display this help message and exit
  -l, --list         List available firmware options and exit

Without options, the script will run in interactive mode.
EOF
}

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

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            CUSTOM_BIN="$2"
            shift
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

# Ensure Python command is set
PYTHON_CMD=python3
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD=python
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python (python3 or python) not found. Please install Python."
        exit 1
    fi
fi

# Check for esptool system-wide or clone if missing
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

# Handle custom bin file
if [ -n "$CUSTOM_BIN" ]; then
    if [ ! -f "$CUSTOM_BIN" ]; then
        echo "Error: Custom file '$CUSTOM_BIN' not found."
        exit 1
    fi
    FIRMWARE_FILE="$CUSTOM_BIN"
    firmware_choice="Custom firmware: $(basename "$CUSTOM_BIN")"
else
    # Interactive firmware selection
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
                
                # Download bootloader and partitions from same directory
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
                # Custom file selection
                read -p "Enter path to custom .bin file: " custom_file
                if [ ! -f "$custom_file" ]; then
                    echo "Error: File '$custom_file' not found."
                    exit 1
                fi
                FIRMWARE_FILE="$custom_file"
                firmware_choice="Custom firmware: $(basename "$custom_file")"
                
                # Look for bootloader and partitions in same directory
                CUSTOM_DIR=$(dirname "$custom_file")
                BOOTLOADER_FILE="$CUSTOM_DIR/bootloader.bin"
                PARTITIONS_FILE="$CUSTOM_DIR/partitions.bin"
                
                if [ ! -f "$BOOTLOADER_FILE" ]; then
                    echo "Warning: bootloader.bin not found in $CUSTOM_DIR"
                    BOOTLOADER_FILE=""
                fi
                
                if [ ! -f "$PARTITIONS_FILE" ]; then
                    echo "Warning: partitions.bin not found in $CUSTOM_DIR"
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

echo ""
if [ -n "$BOOTLOADER_FILE" ] && [ -n "$PARTITIONS_FILE" ]; then
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
    echo "WARNING: Bootloader and/or partition table not found - flashing app only."
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

# Delete downloads
if [ -z "$CUSTOM_BIN" ] && [ "$choice" -le "${#FIRMWARE_OPTIONS[@]}" ]; then
    rm -f "$FIRMWARE_FILE"
    [ -n "$BOOTLOADER_FILE" ] && rm -f "bootloader.bin"
    [ -n "$PARTITIONS_FILE" ] && rm -f "partitions.bin"
fi

echo "Done."