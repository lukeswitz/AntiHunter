#!/bin/bash
set -euo pipefail

# Banner
cat <<'BANNER'
░█▀█░█▀█░▀█▀░▀█▀░█░█░█░█░█▀█░▀█▀░█▀▀░█▀▄
░█▀█░█░█░░█░░░█░░█▀█░█░█░█░█░░█░░█▀▀░█▀▄
░▀░▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀
BANNER
echo

# URLs to flash
FIRMWARES=(
  "AntiHunter S3 Mesh v1:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_s3_mesh_v1.bin"
  "AntiHunter S3 v1:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_s3_v1.bin"
)

UPLOAD_SPEED=115200

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

# Python + esptool discovery
PYTHON_CMD=python3
command -v python3 >/dev/null 2>&1 || PYTHON_CMD=python
if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
  echo "ERROR: Python not found (python3/python)." >&2
  exit 1
fi

if command -v esptool.py >/dev/null 2>&1; then
  ESPTOOL_CMD="esptool.py"
else
  # Try module form if esptool.py isn't on PATH
  if "$PYTHON_CMD" -m esptool --help >/dev/null 2>&1; then
    ESPTOOL_CMD="$PYTHON_CMD -m esptool"
  else
    echo "ERROR: esptool not found. Install with:" >&2
    echo "  $PYTHON_CMD -m pip install esptool" >&2
    exit 1
  fi
fi

echo "Select firmware to flash:"
select opt in "${FIRMWARES[@]}"; do
  if [[ -n "$opt" ]]; then
    FIRMWARE_NAME="${opt%%:*}"
    FIRMWARE_URL="${opt#*:}"
    break
  else
    echo "Invalid selection."
  fi
done

FIRMWARE_FILE=$(basename "$FIRMWARE_URL")
echo "Downloading $FIRMWARE_NAME..."
curl -fL --retry 3 -o "$FIRMWARE_FILE" "$FIRMWARE_URL"

echo "Searching for USB serial devices..."
serial_devices=$(find_serial_devices)
if [ -z "$serial_devices" ]; then
  echo "ERROR: No USB serial devices found."
  exit 1
fi

echo "Found USB serial devices:"
mapfile -t device_array < <(printf "%s\n" $serial_devices)
for i in "${!device_array[@]}"; do
  echo "$((i+1)). ${device_array[$i]}"
done

while true; do
  read -r -p "Select device (1-${#device_array[@]}): " device_choice
  if [[ "$device_choice" =~ ^[0-9]+$ ]] && [ "$device_choice" -ge 1 ] && [ "$device_choice" -le "${#device_array[@]}" ]; then
    ESP32_PORT="${device_array[$((device_choice-1))]}"
    break
  else
    echo "Invalid selection."
  fi
done

echo "Flashing $FIRMWARE_NAME to $ESP32_PORT..."
# Typical single-app offset for ESP32 images is 0x10000
# Keep DIO/80m/detect consistent with common ESP32-S3 modules
eval $ESPTOOL_CMD \
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

echo "Done."