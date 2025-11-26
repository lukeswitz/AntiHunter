#!/usr/bin/env python3
"""
Mesh Command Test Script for AntiHunter
Tests mesh communication respecting Meshtastic airtime and buffer constraints.
"""
import serial
import time
import argparse
import sys
import math
from typing import Optional, Tuple

MAX_MESH_SIZE = 200

class MeshtasticAirtimeCalculator:
    """Calculate LoRa airtime for Meshtastic messages."""
    
    def __init__(self, sf=11, bw=250000, cr=5):
        self.sf = sf
        self.bw = bw
        self.cr = cr
        
    def calculate_airtime(self, payload_bytes: int) -> float:
        """
        Calculate LoRa packet airtime in milliseconds.
        Based on Semtech AN1200.13 calculations.
        """
        t_sym = (2 ** self.sf) / self.bw * 1000
        
        preamble_symbols = 8
        t_preamble = (preamble_symbols + 4.25) * t_sym
        
        payload_symbols_numerator = 8 * payload_bytes - 4 * self.sf + 28 + 16
        payload_symbols_denominator = 4 * self.sf
        payload_symbols = 8 + max(
            math.ceil(payload_symbols_numerator / payload_symbols_denominator) * self.cr,
            0
        )
        
        t_payload = payload_symbols * t_sym
        t_packet = t_preamble + t_payload
        
        return t_packet
    
    def calculate_safe_interval(self, message_length: int) -> float:
        """
        Calculate safe transmission interval accounting for:
        - Message airtime
        - CSMA/CA backoff
        - Mesh rebroadcast window
        """
        overhead = 30
        total_bytes = message_length + overhead
        airtime_ms = self.calculate_airtime(total_bytes)
        
        csma_backoff = 500
        rebroadcast_window = 2000
        safety_margin = 500
        
        safe_interval_ms = airtime_ms + csma_backoff + rebroadcast_window + safety_margin
        
        return safe_interval_ms / 1000.0


class MeshTester:
    def __init__(self, port: str, baudrate: int = 115200, sf: int = 11, bw: int = 250000):
        self.port = port
        self.baudrate = baudrate
        self.ser: Optional[serial.Serial] = None
        self.airtime_calc = MeshtasticAirtimeCalculator(sf=sf, bw=bw)
        self.messages_sent = 0
        self.messages_failed = 0

    def connect(self) -> bool:
        """Connect to the device."""
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
            time.sleep(2)
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
            print(f"\n[STATS] Messages sent: {self.messages_sent}, Failed: {self.messages_failed}")

    def send_command(self, command: str, respect_airtime: bool = True) -> Tuple[list, bool]:
        """
        Send a command and return responses.
        
        Args:
            command: Command string to send
            respect_airtime: If True, wait for safe airtime interval
            
        Returns:
            Tuple of (responses list, success boolean)
        """
        if not self.ser or not self.ser.is_open:
            print("[✗] Not connected")
            return [], False

        cmd_len = len(command)
        if cmd_len > MAX_MESH_SIZE:
            print(f"[✗] Command length {cmd_len} exceeds MAX_MESH_SIZE ({MAX_MESH_SIZE})")
            self.messages_failed += 1
            return [], False

        try:
            if respect_airtime:
                safe_interval = self.airtime_calc.calculate_safe_interval(cmd_len)
                airtime = self.airtime_calc.calculate_airtime(cmd_len + 30)
                print(f"[i] Message: {cmd_len} bytes, Airtime: {airtime:.0f}ms, Safe interval: {safe_interval:.1f}s")
            
            self.ser.write(f"{command}\n".encode())
            self.ser.flush()
            print(f"[↑] Sent ({cmd_len} chars): {command}")
            self.messages_sent += 1

            initial_wait = 0.5
            time.sleep(initial_wait)
            
            responses = []
            while self.ser.in_waiting:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    responses.append(line)
                    print(f"[↓] {line}")

            if respect_airtime:
                remaining_wait = max(0, safe_interval - initial_wait)
                if remaining_wait > 0:
                    print(f"[i] Waiting {remaining_wait:.1f}s for mesh to settle...")
                    time.sleep(remaining_wait)
            
            return responses, True
            
        except Exception as e:
            print(f"[✗] Error sending command: {e}")
            self.messages_failed += 1
            return [], False

    def test_basic_commands(self):
        """Test basic mesh commands with proper airtime spacing."""
        print("\n" + "="*60)
        print("TESTING BASIC COMMANDS (with airtime respect)")
        print("="*60)

        tests = [
            ("STATUS", "Get device status"),
            ("BASELINE_STATUS", "Get baseline status"),
            ("VIBRATION_STATUS", "Get vibration status"),
        ]

        for cmd, desc in tests:
            print(f"\n--- {desc} ---")
            self.send_command(cmd, respect_airtime=True)

    def test_message_length_limits(self):
        """Test message length limits without flooding."""
        print("\n" + "="*60)
        print("TESTING MESSAGE LENGTH LIMITS")
        print("="*60)

        tests = [
            (50, "Short message (50 chars)"),
            (100, "Medium message (100 chars)"),
            (150, "Long message (150 chars)"),
            (190, "Near limit (190 chars)"),
            (200, "At limit (200 chars)"),
        ]

        for target_len, desc in tests:
            test_msg = "T" * target_len
            print(f"\n--- {desc} ---")
            responses, success = self.send_command(test_msg, respect_airtime=True)
            
            if success:
                has_warning = any("240 char" in r or "Invalid" in r for r in responses)
                if has_warning:
                    print("[!] Device reported message handling issue")

    def test_rate_limiting_realistic(self):
        """Test rate limiting with realistic intervals."""
        print("\n" + "="*60)
        print("TESTING REALISTIC RATE LIMITING")
        print("="*60)

        print("\n--- Sending 5 STATUS commands with safe intervals ---")
        print("(Each message waits for mesh to settle before next)")

        start_time = time.time()
        success_count = 0
        
        for i in range(5):
            print(f"\n[Message {i+1}/5]")
            responses, success = self.send_command("STATUS", respect_airtime=True)
            if success:
                success_count += 1
            
            for resp in responses:
                if "Rate limit" in resp:
                    print(f"[!] Rate limit triggered on command {i+1}")

        elapsed = time.time() - start_time
        print(f"\n[✓] Completed {success_count}/5 commands in {elapsed:.1f}s")
        print(f"[i] Average interval: {elapsed/5:.1f}s per message")

    def test_burst_vs_spaced(self):
        """Compare burst sending vs properly spaced sending."""
        print("\n" + "="*60)
        print("COMPARING BURST vs SPACED TRANSMISSION")
        print("="*60)

        print("\n--- BURST MODE (no airtime respect) ---")
        print("Sending 3 rapid messages...")
        burst_start = time.time()
        burst_fails = 0
        
        for i in range(3):
            responses, success = self.send_command(f"TEST_BURST_{i}", respect_airtime=False)
            if not success:
                burst_fails += 1
            time.sleep(0.5)
        
        burst_time = time.time() - burst_start
        print(f"[i] Burst completed in {burst_time:.1f}s, {burst_fails} failures")

        print("\n--- SPACED MODE (airtime respected) ---")
        print("Sending 3 properly spaced messages...")
        spaced_start = time.time()
        spaced_fails = 0
        
        for i in range(3):
            responses, success = self.send_command(f"TEST_SPACED_{i}", respect_airtime=True)
            if not success:
                spaced_fails += 1
        
        spaced_time = time.time() - spaced_start
        print(f"[i] Spaced completed in {spaced_time:.1f}s, {spaced_fails} failures")
        
        print("\n[COMPARISON]")
        print(f"  Burst:  {burst_time:.1f}s, {burst_fails} failures")
        print(f"  Spaced: {spaced_time:.1f}s, {spaced_fails} failures")
        print(f"  Time overhead: {spaced_time - burst_time:.1f}s for reliable delivery")

    def test_buffer_recovery(self):
        """Test Serial1 buffer recovery after heavy load."""
        print("\n" + "="*60)
        print("TESTING BUFFER RECOVERY")
        print("="*60)

        print("\n--- Phase 1: Light load (baseline) ---")
        responses, _ = self.send_command("STATUS", respect_airtime=True)
        baseline_healthy = not any("buffer" in r.lower() for r in responses)
        print(f"[i] Baseline buffer state: {'healthy' if baseline_healthy else 'issues detected'}")

        print("\n--- Phase 2: Wait for buffer to settle ---")
        print("Waiting 10 seconds for any queued mesh activity to complete...")
        time.sleep(10)

        print("\n--- Phase 3: Test after recovery ---")
        responses, _ = self.send_command("STATUS", respect_airtime=True)
        recovered = not any("buffer" in r.lower() for r in responses)
        print(f"[i] Post-recovery state: {'healthy' if recovered else 'still issues'}")

    def monitor_mode(self, duration: int = 60):
        """Monitor incoming messages for a duration."""
        print("\n" + "="*60)
        print(f"MONITOR MODE ({duration} seconds)")
        print("="*60)
        print("Listening for incoming mesh messages...\n")

        message_count = 0
        end_time = time.time() + duration
        
        try:
            while time.time() < end_time:
                if self.ser and self.ser.in_waiting:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        timestamp = time.strftime("%H:%M:%S")
                        print(f"[{timestamp}] {line}")
                        message_count += 1
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Monitor interrupted by user")
        
        print(f"\n[✓] Received {message_count} messages in {duration}s")


def main():
    parser = argparse.ArgumentParser(
        description="Test mesh commands with Meshtastic airtime constraints"
    )
    parser.add_argument("port", help="Serial port (e.g., /dev/cu.usbserial-0001)")
    parser.add_argument("--baudrate", type=int, default=115200, help="Baud rate")
    parser.add_argument("--sf", type=int, default=11, choices=range(7, 13),
                       help="Spreading factor (7-12, default: 11)")
    parser.add_argument("--bw", type=int, default=250000, 
                       choices=[125000, 250000, 500000],
                       help="Bandwidth in Hz (default: 250000)")
    
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--basic", action="store_true", help="Test basic commands")
    parser.add_argument("--limits", action="store_true", help="Test message length limits")
    parser.add_argument("--rate", action="store_true", help="Test realistic rate limiting")
    parser.add_argument("--burst", action="store_true", help="Compare burst vs spaced")
    parser.add_argument("--buffer", action="store_true", help="Test buffer recovery")
    parser.add_argument("--monitor", type=int, metavar="SECONDS",
                       help="Monitor mode for N seconds")
    parser.add_argument("--command", type=str, help="Send a single command")

    args = parser.parse_args()

    tester = MeshTester(args.port, args.baudrate, args.sf, args.bw)

    if not tester.connect():
        return 1

    try:
        print(f"\n[CONFIG] SF={args.sf}, BW={args.bw/1000:.0f}kHz")
        print(f"[INFO] Meshtastic requires ~3-5s between messages for reliable mesh operation")
        print()

        if args.command:
            tester.send_command(args.command, respect_airtime=True)
        elif args.monitor is not None:
            tester.monitor_mode(args.monitor)
        else:
            run_all = args.all or not (args.basic or args.limits or args.rate or args.burst or args.buffer)
            
            if run_all or args.basic:
                tester.test_basic_commands()
            
            if run_all or args.limits:
                tester.test_message_length_limits()
            
            if run_all or args.rate:
                tester.test_rate_limiting_realistic()
            
            if run_all or args.burst:
                tester.test_burst_vs_spaced()
            
            if run_all or args.buffer:
                tester.test_buffer_recovery()

    except KeyboardInterrupt:
        print("\n[!] Tests interrupted by user")
    finally:
        tester.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())