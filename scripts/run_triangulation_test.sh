#!/bin/bash

# Quick triangulation test runner
# Usage: ./run_triangulation_test.sh

set -e

echo "============================================"
echo "AntiHunter Triangulation Test Runner"
echo "============================================"
echo ""

# Check for pyserial
if ! python3 -c "import serial" 2>/dev/null; then
    echo "ERROR: pyserial not installed"
    echo "Install with: pip3 install pyserial"
    exit 1
fi

# Detect OS and list ports
echo "Detecting serial ports..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    PORTS=$(ls /dev/tty.usb* /dev/cu.usb* 2>/dev/null || true)
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    PORTS=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true)
else
    # Windows/Other
    PORTS=$(ls /dev/ttyS* 2>/dev/null || true)
fi

if [ -z "$PORTS" ]; then
    echo "ERROR: No serial ports detected"
    echo "Please connect your AntiHunter nodes via USB"
    exit 1
fi

echo "Available ports:"
echo "$PORTS" | nl
echo ""

# Get coordinator port
read -p "Enter coordinator port number (e.g., 1): " COORD_NUM
COORDINATOR=$(echo "$PORTS" | sed -n "${COORD_NUM}p")

if [ -z "$COORDINATOR" ]; then
    echo "ERROR: Invalid port selection"
    exit 1
fi

echo "Coordinator: $COORDINATOR"
echo ""

# Get child node ports
echo "Available remaining ports:"
echo "$PORTS" | grep -v "$COORDINATOR" | nl
echo ""

read -p "How many child nodes to test? (1-10): " NODE_COUNT

CHILD_NODES=()
for i in $(seq 1 $NODE_COUNT); do
    read -p "Enter child node $i port number: " NODE_NUM
    NODE_PORT=$(echo "$PORTS" | sed -n "${NODE_NUM}p")

    if [ -z "$NODE_PORT" ]; then
        echo "ERROR: Invalid port selection"
        exit 1
    fi

    CHILD_NODES+=("$NODE_PORT")
    echo "Child node $i: $NODE_PORT"
done

echo ""

# Get test parameters
read -p "Target MAC address (e.g., AA:BB:CC:DD:EE:FF): " TARGET_MAC
read -p "Test duration in seconds (default: 90): " DURATION
DURATION=${DURATION:-90}

# Build nodes parameter
NODES_PARAM=$(IFS=,; echo "${CHILD_NODES[*]}")

echo ""
echo "============================================"
echo "Test Configuration"
echo "============================================"
echo "Coordinator:   $COORDINATOR"
echo "Child Nodes:   $NODES_PARAM"
echo "Target MAC:    $TARGET_MAC"
echo "Duration:      ${DURATION}s"
echo "============================================"
echo ""

read -p "Start test? (y/n): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Test cancelled"
    exit 0
fi

echo ""
echo "Starting test monitoring..."
echo "Open another terminal and run:"
echo "  python3 test_mesh_commands.py $COORDINATOR $TARGET_MAC $DURATION"
echo ""
echo "Or manually send via serial console:"
echo "  TRIANGULATE_START:$TARGET_MAC:$DURATION"
echo ""

# Run the test
python3 test_triangulation_flow.py \
    --coordinator "$COORDINATOR" \
    --nodes "$NODES_PARAM" \
    --duration "$DURATION"

exit $?
