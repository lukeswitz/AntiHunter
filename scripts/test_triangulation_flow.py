#!/usr/bin/env python3
"""
Triangulation Slot Coordination Test Script

This script monitors serial output from multiple AntiHunter nodes during triangulation
and validates that the GPS-synchronized slot timing fixes are working correctly.

Usage:
    python3 test_triangulation_flow.py --coordinator /dev/ttyUSB0 --nodes /dev/ttyUSB1,/dev/ttyUSB2,/dev/ttyUSB3

Requirements:
    pip3 install pyserial
"""

import argparse
import re
import serial
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ANSI color codes for output
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class TriangulationTest:
    def __init__(self, coordinator_port: str, node_ports: List[str], baud: int = 115200):
        self.coordinator_port = coordinator_port
        self.node_ports = node_ports
        self.baud = baud

        # Test state
        self.coordinator_serial = None
        self.node_serials = []
        self.running = False
        self.test_start_time = None

        # Data collection
        self.cycle_start_times = {}  # node_id -> cycle_start_ms
        self.acks_received = []
        self.target_data_messages = []  # (timestamp, node_id, message)
        self.heartbeats = defaultdict(list)  # node_id -> [timestamps]
        self.stop_received = {}  # node_id -> timestamp
        self.coordinator_timeout = None
        self.silent_warnings = []

        # Validation results
        self.results = {
            'gps_sync': False,
            'cycle_broadcast': False,
            'acks_received': False,
            'slot_coordination': False,
            'no_collisions': False,
            'heartbeats_ok': False,
            'adaptive_timeout': False,
            'all_nodes_reported': False,
        }

    def open_serial_ports(self):
        """Open serial connections to all nodes."""
        try:
            print(f"{Color.CYAN}Opening serial ports...{Color.RESET}")

            # Coordinator
            self.coordinator_serial = serial.Serial(
                self.coordinator_port,
                self.baud,
                timeout=1
            )
            time.sleep(2)  # Let port stabilize
            print(f"{Color.GREEN}✓ Coordinator: {self.coordinator_port}{Color.RESET}")

            # Child nodes
            for i, port in enumerate(self.node_ports):
                ser = serial.Serial(port, self.baud, timeout=1)
                time.sleep(2)
                self.node_serials.append(ser)
                print(f"{Color.GREEN}✓ Node {i+1}: {port}{Color.RESET}")

            return True
        except Exception as e:
            print(f"{Color.RED}✗ Failed to open serial ports: {e}{Color.RESET}")
            return False

    def close_serial_ports(self):
        """Close all serial connections."""
        if self.coordinator_serial:
            self.coordinator_serial.close()
        for ser in self.node_serials:
            ser.close()

    def read_coordinator_logs(self):
        """Thread function to read coordinator serial output."""
        print(f"{Color.BLUE}[COORDINATOR] Monitoring started{Color.RESET}")

        while self.running:
            try:
                if self.coordinator_serial.in_waiting:
                    line = self.coordinator_serial.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        self.parse_coordinator_line(line)
                        print(f"{Color.WHITE}[COORD] {line}{Color.RESET}")
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"{Color.RED}[COORD ERROR] {e}{Color.RESET}")
                time.sleep(0.1)

    def read_node_logs(self, node_index: int):
        """Thread function to read child node serial output."""
        node_name = f"NODE{node_index+1}"
        print(f"{Color.MAGENTA}[{node_name}] Monitoring started{Color.RESET}")

        while self.running:
            try:
                ser = self.node_serials[node_index]
                if ser.in_waiting:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        self.parse_node_line(node_name, line)
                        print(f"{Color.CYAN}[{node_name}] {line}{Color.RESET}")
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"{Color.RED}[{node_name} ERROR] {e}{Color.RESET}")
                time.sleep(0.1)

    def parse_coordinator_line(self, line: str):
        """Parse coordinator log lines and extract test data."""
        timestamp = time.time() - self.test_start_time

        # Check for cycle start broadcast
        match = re.search(r'Cycle start broadcast: (\d+) ms \(GPS-synced\)', line)
        if match:
            self.cycle_start_times['COORDINATOR'] = int(match.group(1))
            self.results['cycle_broadcast'] = True
            print(f"{Color.GREEN}✓ Cycle start broadcast detected: {match.group(1)} ms{Color.RESET}")

        # Check for ACKs received
        match = re.search(r'ACK received from (\w+)', line)
        if match:
            node_id = match.group(1)
            self.acks_received.append((timestamp, node_id))
            print(f"{Color.GREEN}✓ ACK from {node_id} at T+{timestamp:.1f}s{Color.RESET}")

        # Check for T_D messages
        if 'T_D:' in line:
            # Extract node ID from message format "NODE1: T_D: ..."
            match = re.search(r'(\w+): T_D:', line)
            if match:
                node_id = match.group(1)
                self.target_data_messages.append((timestamp, node_id, line))

        # Check for heartbeats
        match = re.search(r'(\w+): TRI_HEARTBEAT', line)
        if match:
            node_id = match.group(1)
            self.heartbeats[node_id].append(timestamp)

        # Check for adaptive timeout calculation
        match = re.search(r'ADAPTIVE_TIMEOUT.*Total=(\d+)ms', line)
        if match:
            self.coordinator_timeout = int(match.group(1))
            self.results['adaptive_timeout'] = True
            print(f"{Color.GREEN}✓ Adaptive timeout calculated: {match.group(1)} ms{Color.RESET}")

        # Check for silent node warnings
        if 'WARNING: Node' in line and 'silent for' in line:
            self.silent_warnings.append((timestamp, line))
            print(f"{Color.YELLOW}⚠ Silent node warning: {line}{Color.RESET}")

        # Check if all nodes reported
        match = re.search(r'All (\d+) nodes reported', line)
        if match:
            self.results['all_nodes_reported'] = True
            print(f"{Color.GREEN}✓ All {match.group(1)} nodes reported!{Color.RESET}")

    def parse_node_line(self, node_id: str, line: str):
        """Parse child node log lines and extract test data."""
        timestamp = time.time() - self.test_start_time

        # Check for cycle start received
        match = re.search(r'TRI_CYCLE_START received: (\d+) ms', line)
        if match:
            self.cycle_start_times[node_id] = int(match.group(1))
            print(f"{Color.GREEN}✓ {node_id} received cycle start: {match.group(1)} ms{Color.RESET}")

        # Check for GPS-corrected slot initialization
        match = re.search(r'Initialized cycle start at syncedMs=(\d+)', line)
        if match:
            synced_ms = int(match.group(1))
            print(f"{Color.GREEN}✓ {node_id} initialized slot at syncedMs={synced_ms}{Color.RESET}")

        # Check for STOP command received
        if 'TRIANGULATE_STOP received' in line:
            self.stop_received[node_id] = timestamp
            print(f"{Color.GREEN}✓ {node_id} received STOP at T+{timestamp:.1f}s{Color.RESET}")

    def validate_gps_sync(self) -> Tuple[bool, str]:
        """Validate that all nodes are using GPS-synchronized time."""
        if not self.cycle_start_times:
            return False, "No cycle start times detected - GPS sync may not be working"

        # All nodes should have received the same cycle start time
        cycle_times = list(self.cycle_start_times.values())
        if len(set(cycle_times)) > 1:
            return False, f"Nodes have different cycle start times: {self.cycle_start_times}"

        return True, f"All nodes synchronized to cycle start: {cycle_times[0]} ms"

    def validate_slot_coordination(self) -> Tuple[bool, str]:
        """Validate that T_D messages arrive in proper slot order."""
        if len(self.target_data_messages) < 6:  # Need at least 2 full cycles
            return False, f"Not enough T_D messages ({len(self.target_data_messages)}) - need at least 6 for validation"

        # Group messages by node
        node_messages = defaultdict(list)
        for ts, node_id, msg in self.target_data_messages:
            node_messages[node_id].append(ts)

        # Check if messages from each node are regularly spaced
        num_nodes = len(node_messages)
        if num_nodes == 0:
            return False, "No T_D messages from any nodes"

        # Expected slot duration based on node count
        expected_slot_duration = {
            2: 3.0, 3: 3.0,  # 3000ms
            4: 2.5, 5: 2.5, 6: 2.5,  # 2500ms
            7: 2.0, 8: 2.0, 9: 2.0, 10: 2.0  # 2000ms
        }
        expected_duration = expected_slot_duration.get(num_nodes, 3.0)
        expected_cycle = expected_duration * num_nodes

        # Check spacing between messages from same node
        issues = []
        for node_id, timestamps in node_messages.items():
            if len(timestamps) < 2:
                continue

            # Calculate intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)

            # Should be close to full cycle duration
            if abs(avg_interval - expected_cycle) > 1.0:  # 1 second tolerance
                issues.append(f"{node_id}: avg interval {avg_interval:.1f}s (expected ~{expected_cycle:.1f}s)")

        if issues:
            return False, f"Slot timing issues: {'; '.join(issues)}"

        return True, f"Slot coordination working: {num_nodes} nodes with ~{expected_cycle:.1f}s cycle"

    def validate_no_collisions(self) -> Tuple[bool, str]:
        """Validate that no message collisions occurred."""
        if len(self.target_data_messages) < 3:
            return False, "Not enough messages to validate collisions"

        # Sort messages by timestamp
        sorted_messages = sorted(self.target_data_messages, key=lambda x: x[0])

        # Check for messages arriving within 100ms of each other (collision)
        collisions = []
        for i in range(len(sorted_messages) - 1):
            ts1, node1, _ = sorted_messages[i]
            ts2, node2, _ = sorted_messages[i+1]

            if ts2 - ts1 < 0.1 and node1 != node2:  # Same node can send multiple in quick succession
                collisions.append(f"T+{ts1:.1f}s: {node1} and {node2} within {(ts2-ts1)*1000:.0f}ms")

        if collisions:
            return False, f"Detected {len(collisions)} collisions: {'; '.join(collisions[:3])}"

        return True, f"No collisions detected in {len(sorted_messages)} messages"

    def validate_heartbeats(self) -> Tuple[bool, str]:
        """Validate that heartbeats are sent regularly."""
        if not self.heartbeats:
            return False, "No heartbeats detected from any nodes"

        issues = []
        for node_id, timestamps in self.heartbeats.items():
            if len(timestamps) < 2:
                issues.append(f"{node_id}: only {len(timestamps)} heartbeat(s)")
                continue

            # Check intervals (should be ~10 seconds)
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)

            if abs(avg_interval - 10.0) > 2.0:  # 2 second tolerance
                issues.append(f"{node_id}: avg {avg_interval:.1f}s (expected ~10s)")

        if issues:
            return False, f"Heartbeat issues: {'; '.join(issues)}"

        total_heartbeats = sum(len(ts) for ts in self.heartbeats.values())
        return True, f"{len(self.heartbeats)} nodes sent {total_heartbeats} heartbeats (~10s intervals)"

    def run_test(self, duration: int = 90):
        """Run the triangulation test for specified duration."""
        print(f"\n{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}Triangulation Slot Coordination Test{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}\n")

        if not self.open_serial_ports():
            return False

        print(f"\n{Color.YELLOW}Starting test for {duration} seconds...{Color.RESET}\n")
        print(f"{Color.YELLOW}You must manually start triangulation on the coordinator!{Color.RESET}")
        print(f"{Color.YELLOW}Command: TRIANGULATE_START:<MAC>:{duration}{Color.RESET}\n")

        # Start monitoring threads
        self.running = True
        self.test_start_time = time.time()

        coordinator_thread = threading.Thread(target=self.read_coordinator_logs, daemon=True)
        coordinator_thread.start()

        node_threads = []
        for i in range(len(self.node_serials)):
            thread = threading.Thread(target=self.read_node_logs, args=(i,), daemon=True)
            thread.start()
            node_threads.append(thread)

        # Wait for test duration
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Test interrupted by user{Color.RESET}")

        # Stop monitoring
        self.running = False
        time.sleep(1)

        # Run validation
        self.validate_results()

        # Close ports
        self.close_serial_ports()

        return self.print_results()

    def validate_results(self):
        """Run all validation checks."""
        print(f"\n{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}Validation Results{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}\n")

        # GPS Sync
        self.results['gps_sync'], msg = self.validate_gps_sync()
        self._print_result('GPS Synchronization', self.results['gps_sync'], msg)

        # ACKs
        expected_acks = len(self.node_ports)
        self.results['acks_received'] = len(self.acks_received) >= expected_acks
        msg = f"{len(self.acks_received)}/{expected_acks} ACKs received"
        self._print_result('TRI_START_ACK Received', self.results['acks_received'], msg)

        # Slot Coordination
        self.results['slot_coordination'], msg = self.validate_slot_coordination()
        self._print_result('Slot Coordination', self.results['slot_coordination'], msg)

        # No Collisions
        self.results['no_collisions'], msg = self.validate_no_collisions()
        self._print_result('No Message Collisions', self.results['no_collisions'], msg)

        # Heartbeats
        self.results['heartbeats_ok'], msg = self.validate_heartbeats()
        self._print_result('Heartbeat Mechanism', self.results['heartbeats_ok'], msg)

    def _print_result(self, test_name: str, passed: bool, details: str):
        """Print a single test result."""
        status = f"{Color.GREEN}✓ PASS{Color.RESET}" if passed else f"{Color.RED}✗ FAIL{Color.RESET}"
        print(f"{status} {Color.BOLD}{test_name}{Color.RESET}")
        print(f"     {details}\n")

    def print_results(self) -> bool:
        """Print final test summary."""
        print(f"\n{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}Test Summary{Color.RESET}")
        print(f"{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}\n")

        passed_count = sum(1 for v in self.results.values() if v)
        total_count = len(self.results)

        print(f"Tests Passed: {Color.BOLD}{passed_count}/{total_count}{Color.RESET}")
        print(f"Tests Failed: {Color.BOLD}{total_count - passed_count}/{total_count}{Color.RESET}\n")

        print(f"Data Collected:")
        print(f"  - Cycle start times: {len(self.cycle_start_times)}")
        print(f"  - ACKs received: {len(self.acks_received)}")
        print(f"  - T_D messages: {len(self.target_data_messages)}")
        print(f"  - Heartbeats: {sum(len(ts) for ts in self.heartbeats.values())}")
        print(f"  - Silent warnings: {len(self.silent_warnings)}")

        if self.coordinator_timeout:
            print(f"  - Adaptive timeout: {self.coordinator_timeout} ms")
        print()

        all_passed = all(self.results.values())

        if all_passed:
            print(f"{Color.BOLD}{Color.GREEN}{'='*60}{Color.RESET}")
            print(f"{Color.BOLD}{Color.GREEN}ALL TESTS PASSED - Triangulation fixes are working!{Color.RESET}")
            print(f"{Color.BOLD}{Color.GREEN}{'='*60}{Color.RESET}\n")
        else:
            print(f"{Color.BOLD}{Color.RED}{'='*60}{Color.RESET}")
            print(f"{Color.BOLD}{Color.RED}SOME TESTS FAILED - Review logs above{Color.RESET}")
            print(f"{Color.BOLD}{Color.RED}{'='*60}{Color.RESET}\n")

            print(f"{Color.YELLOW}Failed tests:{Color.RESET}")
            for test_name, passed in self.results.items():
                if not passed:
                    print(f"  - {test_name}")
            print()

        return all_passed

def main():
    parser = argparse.ArgumentParser(
        description='Test AntiHunter triangulation slot coordination',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Test with coordinator and 2 child nodes
  python3 test_triangulation_flow.py --coordinator /dev/ttyUSB0 --nodes /dev/ttyUSB1,/dev/ttyUSB2

  # Test with coordinator and 3 child nodes, 120 second duration
  python3 test_triangulation_flow.py --coordinator /dev/ttyUSB0 --nodes /dev/ttyUSB1,/dev/ttyUSB2,/dev/ttyUSB3 --duration 120

  # Use different baud rate
  python3 test_triangulation_flow.py --coordinator /dev/ttyUSB0 --nodes /dev/ttyUSB1,/dev/ttyUSB2 --baud 9600
        '''
    )

    parser.add_argument('--coordinator', required=True, help='Serial port for coordinator node')
    parser.add_argument('--nodes', required=True, help='Comma-separated serial ports for child nodes')
    parser.add_argument('--duration', type=int, default=90, help='Test duration in seconds (default: 90)')
    parser.add_argument('--baud', type=int, default=115200, help='Baud rate (default: 115200)')

    args = parser.parse_args()

    node_ports = [port.strip() for port in args.nodes.split(',')]

    print(f"{Color.CYAN}Configuration:{Color.RESET}")
    print(f"  Coordinator: {args.coordinator}")
    print(f"  Child nodes: {', '.join(node_ports)}")
    print(f"  Duration: {args.duration}s")
    print(f"  Baud rate: {args.baud}")
    print()

    tester = TriangulationTest(args.coordinator, node_ports, args.baud)
    success = tester.run_test(args.duration)

    exit(0 if success else 1)

if __name__ == '__main__':
    main()
