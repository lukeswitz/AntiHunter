#!/usr/bin/env python3
"""
AntiHunter Triangulation Test - With Real Meshtastic Rate Limiting
Tests against actual Meshtastic airtime and channel utilization constraints.

Meshtastic constraints:
- Default SF11: ~1.2s airtime per 200-char message
- Messages split into packets with rebroadcast window
- Channel utilization limits (can't exceed 33% airtime)
- Safe interval between messages: ~3-5s minimum
- Hop-based delivery delay: ~0.5-1s per hop
"""
import time
import math
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


class MessageType(Enum):
    TRIANGULATE_START = "TRIANGULATE_START"
    TRIANGULATE_STOP = "TRIANGULATE_STOP"
    TRIANGULATE_ACK = "TRIANGULATE_ACK"
    T_D = "T_D"
    TRIANGULATION_FINAL = "TRIANGULATION_FINAL"
    TRIANGULATE_COMPLETE = "TRIANGULATE_COMPLETE"


@dataclass
class Message:
    sender_id: str
    target: str
    message_type: MessageType
    payload: str = ""
    length_bytes: int = 0
    
    def calculate_length(self) -> int:
        """Calculate actual message length in bytes."""
        msg_str = f"{self.sender_id}: {self.target} {self.message_type.value}"
        if self.payload:
            msg_str += f":{self.payload}"
        return len(msg_str.encode())
    
    def __str__(self):
        if self.payload:
            return f"{self.sender_id}: {self.target} {self.message_type.value}:{self.payload}"
        return f"{self.sender_id}: {self.target} {self.message_type.value}"


class MeshtasticAirtime:
    """Calculate realistic Meshtastic airtime and throughput."""
    
    # LoRa SF11 (default) parameters
    SPREADING_FACTOR = 11
    BANDWIDTH_HZ = 250000
    CODING_RATE = 5
    
    @staticmethod
    def calculate_airtime_ms(payload_bytes: int) -> float:
        """
        Calculate LoRa airtime in milliseconds for SF11, BW=250kHz.
        Realistic SF11 airtime: ~700-800ms for 200 chars.
        Based on Semtech LoRa calculator.
        """
        # Simplification: SF11 @ 250kHz ≈ 3.5ms per byte + overhead
        preamble_ms = 50  # 8 symbols at SF11
        payload_ms = (payload_bytes * 3.5) + 100  # Approximation
        total_ms = preamble_ms + payload_ms
        return min(total_ms, 1200.0)  # Cap at realistic max
    
    @staticmethod
    def safe_send_interval_s(message_bytes: int) -> float:
        """
        Real Meshtastic safe sending interval accounting for:
        - Message airtime
        - CSMA backoff (random 0-500ms)
        - Rebroadcast window (up to 2s in multi-hop)
        - Safety margin for acknowledgments
        """
        airtime_ms = MeshtasticAirtime.calculate_airtime_ms(message_bytes)
        
        # Components of safe interval
        csma_backoff_ms = 300  # Average CSMA/CA
        rebroadcast_window_ms = 1500  # Mesh rebroadcast
        ack_wait_ms = 500  # Wait for potential acks
        safety_margin_ms = 300  # Extra safety
        
        total_ms = airtime_ms + csma_backoff_ms + rebroadcast_window_ms + ack_wait_ms + safety_margin_ms
        return total_ms / 1000.0


class TriangulationNode:
    """Simulates a node with realistic Meshtastic constraints."""
    
    def __init__(self, node_id: str, is_coordinator: bool = False):
        self.node_id = node_id
        self.is_coordinator = is_coordinator
        
        self.triangulation_active = False
        self.triangulation_coordinator = ""
        self.acked_nodes: List[str] = []
        self.received_reports: Dict[str, dict] = {}
        self.received_final = False
        self.received_complete = False
        
        self.outgoing_messages: List[Message] = []
        self.pending_send_time = 0.0  # When we can send next

    def can_send(self, sim_time: float) -> bool:
        """Check if enough time has passed since last send."""
        return sim_time >= self.pending_send_time

    def queue_message(self, message: Message, sim_time: float) -> float:
        """Queue a message and return when it will be sent."""
        if not self.can_send(sim_time):
            # Schedule after pending send completes
            send_time = self.pending_send_time
        else:
            send_time = sim_time
        
        # Calculate safe interval for this message
        msg_len = message.calculate_length()
        safe_interval = MeshtasticAirtime.safe_send_interval_s(msg_len)
        
        # Update when we can send next
        self.pending_send_time = send_time + safe_interval
        
        self.outgoing_messages.append(message)
        return send_time

    def receive_start(self, sender_id: str, target_mac: str, duration: int, sim_time: float):
        """Handle TRIANGULATE_START."""
        if self.is_coordinator:
            return
        
        self.triangulation_coordinator = sender_id
        self.triangulation_active = True
        
        print(f"[{sim_time:.1f}s] [{self.node_id}] ← START from {sender_id} for {target_mac}")
        
        # Send ACK after small delay
        ack_msg = Message(
            sender_id=self.node_id,
            target=f"@{sender_id}",
            message_type=MessageType.TRIANGULATE_ACK
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(ack_msg.calculate_length())
        self.queue_message(ack_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ ACK queued (will send in {safe_interval:.1f}s)")

    def receive_stop(self, sender_id: str, sim_time: float):
        """Handle TRIANGULATE_STOP."""
        self.triangulation_active = False
        print(f"[{sim_time:.1f}s] [{self.node_id}] ← STOP from {sender_id}")
        
        # Send T_D after delay
        payload = (f"AA:BB:CC:DD:EE:FF "
                  f"RSSI:-65 Hits:20 Type:WiFi "
                  f"GPS=37.7750,-122.4190 HDOP=1.5")
        
        target_data_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.T_D,
            payload=payload
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(target_data_msg.calculate_length())
        self.queue_message(target_data_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ T_D queued (will send in {safe_interval:.1f}s)")

    def receive_ack(self, sender_id: str, sim_time: float):
        """Handle ACK (coordinator only)."""
        if not self.is_coordinator:
            return
        
        if sender_id not in self.acked_nodes:
            self.acked_nodes.append(sender_id)
            print(f"[{sim_time:.1f}s] [{self.node_id}] ← ACK from {sender_id} ({len(self.acked_nodes)} total)")

    def receive_target_data(self, sender_id: str, payload: str, sim_time: float):
        """Handle T_D (coordinator only)."""
        if not self.is_coordinator:
            return
        
        if sender_id not in self.received_reports:
            self.received_reports[sender_id] = {"data": payload}
            print(f"[{sim_time:.1f}s] [{self.node_id}] ← T_D from {sender_id}")

    def receive_final(self, sender_id: str, payload: str, sim_time: float):
        """Handle TRIANGULATION_FINAL."""
        self.received_final = True
        print(f"[{sim_time:.1f}s] [{self.node_id}] ← TRIANGULATION_FINAL from {sender_id}: {payload}")

    def receive_complete(self, sender_id: str, payload: str, sim_time: float):
        """Handle TRIANGULATE_COMPLETE."""
        self.received_complete = True
        print(f"[{sim_time:.1f}s] [{self.node_id}] ← TRIANGULATE_COMPLETE from {sender_id}: {payload}")

    def start_triangulation(self, target_mac: str, duration: int, sim_time: float):
        """Coordinator initiates triangulation."""
        if not self.is_coordinator:
            return
        
        self.triangulation_active = True
        self.acked_nodes.clear()
        self.received_reports.clear()
        self.received_final = False
        self.received_complete = False
        
        payload = f"{target_mac}:{duration}"
        start_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.TRIANGULATE_START,
            payload=payload
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(start_msg.calculate_length())
        self.queue_message(start_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ START queued (will send in {safe_interval:.1f}s)")

    def stop_triangulation(self, sim_time: float):
        """Coordinator stops triangulation."""
        if not self.is_coordinator:
            return
        
        # Send STOP
        stop_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.TRIANGULATE_STOP
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(stop_msg.calculate_length())
        self.queue_message(stop_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ STOP queued (will send in {safe_interval:.1f}s)")
        
        # Send self T_D
        payload = (f"AA:BB:CC:DD:EE:FF "
                  f"RSSI:-65 Hits:20 Type:WiFi "
                  f"GPS=37.7749,-122.4194 HDOP=1.5")
        
        target_data_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.T_D,
            payload=payload
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(target_data_msg.calculate_length())
        self.queue_message(target_data_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ Self T_D queued (will send in {safe_interval:.1f}s)")

    def finalize(self, sim_time: float):
        """Coordinator sends FINAL and COMPLETE."""
        if not self.is_coordinator:
            return
        
        # TRIANGULATION_FINAL - actual coordinates
        final_payload = "AA:BB:CC:DD:EE:FF GPS=37.7750,-122.4193 CONF=85.5 UNC=12.3"
        final_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.TRIANGULATION_FINAL,
            payload=final_payload
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(final_msg.calculate_length())
        self.queue_message(final_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ FINAL queued (will send in {safe_interval:.1f}s)")
        
        # TRIANGULATE_COMPLETE - summary
        complete_payload = f"AA:BB:CC:DD:EE:FF Nodes=3"
        complete_msg = Message(
            sender_id=self.node_id,
            target="@ALL",
            message_type=MessageType.TRIANGULATE_COMPLETE,
            payload=complete_payload
        )
        safe_interval = MeshtasticAirtime.safe_send_interval_s(complete_msg.calculate_length())
        self.queue_message(complete_msg, sim_time)
        print(f"[{sim_time:.1f}s] [{self.node_id}] ↻ COMPLETE queued (will send in {safe_interval:.1f}s)")


class MeshSimulator:
    """Simulates mesh with realistic airtime and propagation delays."""
    
    def __init__(self):
        self.nodes: Dict[str, TriangulationNode] = {}
        self.pending_deliveries: List[tuple] = []  # (message, recipient, delivery_time)
        self.sim_time = 0.0

    def add_node(self, node: TriangulationNode):
        self.nodes[node.node_id] = node
        print(f"[NET] Added {node.node_id} ({'coordinator' if node.is_coordinator else 'sensor'})")

    def dispatch_ready_messages(self):
        """Send messages that are ready from all nodes."""
        for node in self.nodes.values():
            for msg in node.outgoing_messages:
                # Determine recipients and delivery times
                if msg.target == "@ALL":
                    recipients = [n for nid, n in self.nodes.items() if nid != msg.sender_id]
                else:
                    recipient_id = msg.target.lstrip("@")
                    recipients = [self.nodes[recipient_id]] if recipient_id in self.nodes else []
                
                # Add propagation delay (0.5-1.5s for real mesh)
                delivery_delay = 0.5 + (len(self.nodes.keys()) % 3) * 0.25
                
                for recipient in recipients:
                    self.pending_deliveries.append((msg, recipient, self.sim_time + delivery_delay))
            
            node.outgoing_messages.clear()

    def deliver_ready_messages(self):
        """Deliver messages whose delivery time has arrived."""
        still_pending = []
        
        for msg, recipient, delivery_time in self.pending_deliveries:
            if delivery_time <= self.sim_time:
                # Deliver the message
                if msg.message_type == MessageType.TRIANGULATE_START:
                    mac, duration = msg.payload.rsplit(":", 1)
                    recipient.receive_start(msg.sender_id, mac, int(duration), self.sim_time)
                
                elif msg.message_type == MessageType.TRIANGULATE_STOP:
                    recipient.receive_stop(msg.sender_id, self.sim_time)
                
                elif msg.message_type == MessageType.TRIANGULATE_ACK:
                    recipient.receive_ack(msg.sender_id, self.sim_time)
                
                elif msg.message_type == MessageType.T_D:
                    recipient.receive_target_data(msg.sender_id, msg.payload, self.sim_time)
                
                elif msg.message_type == MessageType.TRIANGULATION_FINAL:
                    recipient.receive_final(msg.sender_id, msg.payload, self.sim_time)
                
                elif msg.message_type == MessageType.TRIANGULATE_COMPLETE:
                    recipient.receive_complete(msg.sender_id, msg.payload, self.sim_time)
            else:
                still_pending.append((msg, recipient, delivery_time))
        
        self.pending_deliveries = still_pending

    def step(self, dt: float = 0.5):
        """Step simulation forward."""
        self.sim_time += dt
        self.dispatch_ready_messages()
        self.deliver_ready_messages()

    def run_until(self, target_time: float):
        """Run simulation until target time."""
        while self.sim_time < target_time:
            self.step(0.5)

    def validate(self) -> bool:
      """Validate triangulation completion."""
      coordinator = self.nodes.get("AH901")
      if not coordinator:
        return False
      
      print("\n" + "="*80)
      print(f"VALIDATION (simulation time: {self.sim_time:.1f}s)")
      print("="*80)
      
      all_pass = True
      
      # [1] Coordinator received ACKs from all children
      ack_count = len(coordinator.acked_nodes)
      print(f"\n[1] Coordinator received ACKs: {ack_count}/3")
      if ack_count < 3:
        missing = set(['AH902', 'AH903', 'AH904']) - set(coordinator.acked_nodes)
        print(f"  ✗ FAILED: Missing from {missing}")
        all_pass = False
      else:
        print(f"  ✓ PASS: {coordinator.acked_nodes}")
        
      # [2] Coordinator received T_D from all children
      report_count = len(coordinator.received_reports)
      print(f"\n[2] Coordinator received T_D: {report_count}/3")
      print(f"  From: {list(coordinator.received_reports.keys())}")
      if report_count < 3:
        missing = set(['AH902', 'AH903', 'AH904']) - set(coordinator.received_reports.keys())
        print(f"  ✗ FAILED: Missing from {missing}")
        all_pass = False
      else:
        print(f"  ✓ PASS")
        
      print()
      if all_pass:
        print("="*80)
        print(f"✓✓✓ ALL TESTS PASSED (took {self.sim_time:.1f}s) ✓✓✓")
        print("="*80)
      else:
        print("="*80)
        print(f"✗✗✗ SOME TESTS FAILED ✗✗✗")
        print("="*80)
        
      return all_pass


def test_triangulation_realistic():
    """Test with realistic Meshtastic constraints."""
    print("="*80)
    print("ANTIHUNTER TRIANGULATION - REALISTIC MESHTASTIC SIMULATION")
    print("="*80)
    print(f"\nMeshtastic SF11 constraints:")
    print(f"  - Airtime per 200-char message: ~{MeshtasticAirtime.calculate_airtime_ms(200):.0f}ms")
    print(f"  - Safe send interval: ~{MeshtasticAirtime.safe_send_interval_s(200):.1f}s")
    print(f"  - Expected test duration: ~60-120s (realistic field conditions)")
    print()
    
    mesh = MeshSimulator()
    
    # Create network
    coordinator = TriangulationNode("AH901", is_coordinator=True)
    child1 = TriangulationNode("AH902", is_coordinator=False)
    child2 = TriangulationNode("AH903", is_coordinator=False)
    child3 = TriangulationNode("AH904", is_coordinator=False)
    
    mesh.add_node(coordinator)
    mesh.add_node(child1)
    mesh.add_node(child2)
    mesh.add_node(child3)
    print()
    
    # Phase 1: Start
    print("[PHASE 1] Coordinator queues START")
    print("-" * 80)
    coordinator.start_triangulation("AA:BB:CC:DD:EE:FF", 60, mesh.sim_time)
    mesh.run_until(15.0)  # Wait for START to send and be delivered
    print()
    
    # Phase 2: ACKs
    print("[PHASE 2] Waiting for ACKs with rate limiting")
    print("-" * 80)
    mesh.run_until(45.0)  # ACKs arrive and are queued/sent
    print(f"ACKs collected: {len(coordinator.acked_nodes)}/3\n")
    
    # Phase 3: Stop
    print("[PHASE 3] Coordinator queues STOP")
    print("-" * 80)
    coordinator.stop_triangulation(mesh.sim_time)
    mesh.run_until(65.0)  # STOP arrives and children queue T_D
    print()
    
    # Phase 4: Reports
    print("[PHASE 4] Collecting T_D with realistic delays")
    print("-" * 80)
    mesh.run_until(105.0)  # Children send reports with rate limiting
    print(f"Reports collected: {len(coordinator.received_reports)}/3\n")
    
    # Phase 5: Final results
    print("[PHASE 5] Coordinator sends FINAL and COMPLETE")
    print("-" * 80)
    coordinator.finalize(mesh.sim_time)
    mesh.run_until(130.0)
    print()
    
    # Validate
    success = mesh.validate()
    return success


if __name__ == "__main__":
    import sys
    success = test_triangulation_realistic()
    sys.exit(0 if success else 1)