#!/usr/bin/env python3
"""
Mesh Command Test Script for AntiHunter
Tests mesh communication, message length limits, and rate limiting.
"""
import serial
import time
import argparse
import sys
from typing import Optional

MAX_MESH_SIZE = 200

class MeshTester:
    def __init__(self, port: str, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self.ser: Optional[serial.Serial] = None

    def connect(self) -> bool:
        """Connect to the device."""
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
            time.sleep(2)  # Wait for device to be ready
            print(f"[✓] Connected to {self.port} at {self.baudrate} baud")
            return True
        except Exception as e:
            print(f"[✗] Failed to connect: {e}")
            return False

    def disconnect(self):
        """Disconnect from the device."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("[✓] Disconnected")

    def send_command(self, command: str, wait_time: float = 0.5) -> list:
        """Send a command and return responses."""
        if not self.ser or not self.ser.is_open:
            print("[✗] Not connected")
            return []

        # Check message length
        cmd_len = len(command)
        if cmd_len > MAX_MESH_SIZE:
            print(f"[!] WARNING: Command length {cmd_len} exceeds MAX_MESH_SIZE ({MAX_MESH_SIZE})")

        try:
            # Send command
            self.ser.write(f"{command}\n".encode())
            self.ser.flush()
            print(f"[→] Sent ({cmd_len} chars): {command}")

            # Wait and collect responses
            time.sleep(wait_time)
            responses = []
            while self.ser.in_waiting:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    responses.append(line)
                    print(f"[←] {line}")

            return responses
        except Exception as e:
            print(f"[✗] Error sending command: {e}")
            return []

    def test_basic_commands(self):
        """Test basic mesh commands."""
        print("\n" + "="*60)
        print("TESTING BASIC COMMANDS")
        print("="*60)

        tests = [
            ("STATUS", "Get device status"),
            ("BASELINE_STATUS", "Get baseline status"),
            ("VIBRATION_STATUS", "Get vibration status"),
        ]

        for cmd, desc in tests:
            print(f"\n--- {desc} ---")
            self.send_command(cmd, wait_time=1.0)
            time.sleep(0.5)

    def test_config_commands(self):
        """Test configuration commands."""
        print("\n" + "="*60)
        print("TESTING CONFIG COMMANDS")
        print("="*60)

        tests = [
            ("CONFIG_NODEID:TEST", "Set Node ID to 'TEST'"),
            ("CONFIG_CHANNELS:1,6,11", "Set channels to 1,6,11"),
            ("CONFIG_RSSI:-75", "Set RSSI threshold to -75"),
        ]

        for cmd, desc in tests:
            print(f"\n--- {desc} ---")
            self.send_command(cmd, wait_time=1.0)
            time.sleep(0.5)

    def test_scan_commands(self):
        """Test scan start/stop commands."""
        print("\n" + "="*60)
        print("TESTING SCAN COMMANDS")
        print("="*60)

        tests = [
            ("SCAN_START:0:10:1,6,11", "Start WiFi scan for 10s"),
            ("STATUS", "Check status during scan"),
        ]

        for cmd, desc in tests:
            print(f"\n--- {desc} ---")
            self.send_command(cmd, wait_time=1.0)
            time.sleep(0.5)

        print("\n--- Wait 3 seconds ---")
        time.sleep(3)

        print("\n--- Stop scan ---")
        self.send_command("STOP", wait_time=1.0)

    def test_message_length_limits(self):
        """Test message length boundaries."""
        print("\n" + "="*60)
        print("TESTING MESSAGE LENGTH LIMITS")
        print("="*60)

        # Test at exactly MAX_MESH_SIZE
        base_cmd = "CONFIG_NODEID:"
        # Calculate how many chars we need to reach exactly 200
        padding_needed = MAX_MESH_SIZE - len(base_cmd)

        tests = [
            (MAX_MESH_SIZE - 10, "10 chars under limit"),
            (MAX_MESH_SIZE - 1, "1 char under limit"),
            (MAX_MESH_SIZE, "Exactly at limit (200)"),
            (MAX_MESH_SIZE + 1, "1 char over limit (should be rejected)"),
            (MAX_MESH_SIZE + 10, "10 chars over limit (should be rejected)"),
        ]

        for target_len, desc in tests:
            padding = target_len - len(base_cmd)
            if padding < 1:
                padding = 1
            test_cmd = base_cmd + "A" * min(padding, 5)  # Keep it valid (max 5 char node ID)
            # Pad with comment to reach target length
            if len(test_cmd) < target_len:
                # Can't actually test this cleanly without breaking command format
                # So we'll use a different approach - send raw padding
                test_cmd = "STATUS" + " " * (target_len - 6)

            print(f"\n--- {desc} (length: {len(test_cmd)}) ---")
            self.send_command(test_cmd, wait_time=0.5)
            time.sleep(0.3)

    def test_rate_limiting(self):
        """Test rate limiting (200 chars per second)."""
        print("\n" + "="*60)
        print("TESTING RATE LIMITING")
        print("="*60)

        print("\n--- Sending 5 STATUS commands rapidly ---")
        print("(Rate limiter allows 200 tokens/sec, STATUS is ~6 chars + 2 for newline)")

        start_time = time.time()
        for i in range(5):
            responses = self.send_command("STATUS", wait_time=0.1)
            # Look for rate limit messages
            for resp in responses:
                if "Rate limit" in resp:
                    print(f"[!] Rate limit triggered on command {i+1}")

        elapsed = time.time() - start_time
        print(f"\n[i] Completed 5 commands in {elapsed:.2f}s")

    def test_triangulation(self):
        """Test triangulation commands."""
        print("\n" + "="*60)
        print("TESTING TRIANGULATION COMMANDS")
        print("="*60)

        # Test with a fake MAC address
        test_mac = "AA:BB:CC:DD:EE:FF"
        duration = 5

        print(f"\n--- Start triangulation for {test_mac} ({duration}s) ---")
        self.send_command(f"TRIANGULATE_START:{test_mac}:{duration}", wait_time=1.0)

        time.sleep(2)

        print("\n--- Check status during triangulation ---")
        self.send_command("STATUS", wait_time=0.5)

        time.sleep(1)

        print("\n--- Stop triangulation ---")
        self.send_command("TRIANGULATE_STOP", wait_time=0.5)

    def test_targeted_commands(self):
        """Test targeted commands with @NodeID prefix."""
        print("\n" + "="*60)
        print("TESTING TARGETED COMMANDS")
        print("="*60)

        tests = [
            ("@ALL STATUS", "Broadcast STATUS to all nodes"),
            ("@TEST STATUS", "Send STATUS to node 'TEST'"),
        ]

        for cmd, desc in tests:
            print(f"\n--- {desc} ---")
            self.send_command(cmd, wait_time=1.0)
            time.sleep(0.5)

    def monitor_mode(self, duration: int = 60):
        """Monitor incoming messages for a duration."""
        print("\n" + "="*60)
        print(f"MONITOR MODE ({duration} seconds)")
        print("="*60)
        print("Listening for incoming mesh messages...\n")

        end_time = time.time() + duration
        try:
            while time.time() < end_time:
                if self.ser and self.ser.in_waiting:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        timestamp = time.strftime("%H:%M:%S")
                        print(f"[{timestamp}] {line}")
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Monitor interrupted by user")

def main():
    parser = argparse.ArgumentParser(
        description="Test AntiHunter mesh commands and limits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  python test_mesh_commands.py /dev/cu.usbserial-0001 --all

  # Run specific tests
  python test_mesh_commands.py /dev/cu.usbserial-0001 --basic --config

  # Monitor incoming messages
  python test_mesh_commands.py /dev/cu.usbserial-0001 --monitor 30

  # Send a single custom command
  python test_mesh_commands.py /dev/cu.usbserial-0001 --command "STATUS"
        """
    )

    parser.add_argument('port', help='Serial port (e.g., /dev/cu.usbserial-0001 or COM3)')
    parser.add_argument('--baudrate', type=int, default=115200, help='Baud rate (default: 115200)')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--basic', action='store_true', help='Test basic commands')
    parser.add_argument('--config', action='store_true', help='Test config commands')
    parser.add_argument('--scan', action='store_true', help='Test scan commands')
    parser.add_argument('--limits', action='store_true', help='Test message length limits')
    parser.add_argument('--rate', action='store_true', help='Test rate limiting')
    parser.add_argument('--triangulation', action='store_true', help='Test triangulation commands')
    parser.add_argument('--targeted', action='store_true', help='Test targeted commands')
    parser.add_argument('--monitor', type=int, metavar='SECONDS', help='Monitor mode for N seconds')
    parser.add_argument('--command', type=str, metavar='CMD', help='Send a single custom command')

    args = parser.parse_args()

    # Create tester instance
    tester = MeshTester(args.port, args.baudrate)

    if not tester.connect():
        sys.exit(1)

    try:
        # Handle monitor mode
        if args.monitor:
            tester.monitor_mode(args.monitor)
            return

        # Handle single command
        if args.command:
            tester.send_command(args.command, wait_time=1.0)
            return

        # Run tests
        run_any = False

        if args.all or args.basic:
            tester.test_basic_commands()
            run_any = True

        if args.all or args.config:
            tester.test_config_commands()
            run_any = True

        if args.all or args.scan:
            tester.test_scan_commands()
            run_any = True

        if args.all or args.limits:
            tester.test_message_length_limits()
            run_any = True

        if args.all or args.rate:
            tester.test_rate_limiting()
            run_any = True

        if args.all or args.triangulation:
            tester.test_triangulation()
            run_any = True

        if args.all or args.targeted:
            tester.test_targeted_commands()
            run_any = True

        if not run_any:
            print("[!] No tests specified. Use --help for options.")
            print("[!] Try: --all for all tests, or --basic for a quick check")

    finally:
        tester.disconnect()
        print("\n[✓] Test session complete")

if __name__ == "__main__":
    main()
