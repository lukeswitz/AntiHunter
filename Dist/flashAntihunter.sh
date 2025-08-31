#!/bin/bash
set -euo pipefail

cat <<'BANNER'
░█▀█░█▀█░▀█▀░▀█▀░█░█░█░█░█▀█░▀█▀░█▀▀░█▀▄
░█▀█░█░█░░█░░░█░░█▀█░█░█░█░█░░█░░█▀▀░█▀▄
░▀░▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀
BANNER
echo "AntiHunter Flasher"
echo "=================="

FIRMWARES=(
  "AntiHunter S3 Mesh v2:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_s3_mesh_v2.bin"
  "AntiHunter S3 v1:https://github.com/lukeswitz/AntiHunter/raw/refs/heads/main/Dist/antihunter_s3_v1.bin"
)

# Detect OS
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macos"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "linux"  
  else
    echo "windows"
  fi
}

OS=$(detect_os)
echo "OS: $OS"

# Install deps
case "$OS" in
  linux)
    if ! command -v python3 >/dev/null; then
      sudo apt-get update && sudo apt-get install -y python3 python3-pip curl
    fi
    ;;
  macos)  
    if ! command -v brew >/dev/null; then
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || eval "$(/usr/local/bin/brew shellenv)"
    fi
    if ! command -v python3 >/dev/null; then
      brew install python
    fi
    ;;
esac

# Install esptool
if ! python3 -m esptool --help >/dev/null 2>&1; then
  python3 -m pip install --user esptool
fi

# Find devices
find_devices() {
  case "$OS" in
    linux) ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true ;;
    macos) ls /dev/cu.* 2>/dev/null | grep -E 'usb|serial' || true ;;
  esac  
}

# Select firmware
echo "Select firmware:"
select opt in "${FIRMWARES[@]}"; do
  FIRMWARE_NAME="${opt%%:*}"
  FIRMWARE_URL="${opt#*:}"
  break
done

# Download
FIRMWARE_FILE=$(basename "$FIRMWARE_URL")
curl -fL -o "$FIRMWARE_FILE" "$FIRMWARE_URL"

# Find devices and create array using bash 3.2 compatible method
devices=$(find_devices)
if [ -z "$devices" ]; then
  echo "No devices found"
  exit 1
fi

echo "Devices:"
# Use bash 3.2 compatible array creation
device_array=()
i=1
while IFS= read -r device; do
  echo "$i. $device"
  device_array[i]="$device"
  i=$((i+1))
done < <(echo "$devices")
device_count=$((i-1))

# Select device
read -p "Select device number: " choice
if [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$device_count" ]]; then
  PORT="${device_array[$choice]}"
else
  echo "Invalid choice"
  exit 1
fi

# Flash
echo "Flashing to $PORT..."
python3 -m esptool \
  --chip auto \
  --port "$PORT" \
  --baud 115200 \
  --before default_reset \
  --after hard_reset \
  write_flash -z \
  --flash_mode dio \
  --flash_freq 80m \
  --flash_size detect \
  0x10000 "$FIRMWARE_FILE"

echo "Done!"
rm -f "$FIRMWARE_FILE"