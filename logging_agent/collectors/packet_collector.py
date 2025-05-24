"""
Packet Capture Collector

This module captures network packets using Scapy and provides
them in a standardized format for analysis.
"""

import logging
import socket
import threading
import time
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import json

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCollector:
    """Collects network packets using packet capture."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Packet Collector.
        
        Args:
            config: Configuration dictionary for packet capture
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available - packet capture disabled")
            self.enabled = False
            return
            
        self.enabled = config.get('enabled', False)
        self.interface = config.get('interface', 'auto')
        self.filter_expression = config.get('filter', '')
        self.max_packets = config.get('max_packets', 50)
        
        self._capture_thread = None
        self._stop_capture = False
        self._captured_packets = []
        self._capture_lock = threading.Lock()
        
        # Auto-detect interface if needed
        if self.interface == 'auto':
            self.interface = self._get_default_interface()
            
    def _get_default_interface(self) -> Optional[str]:
        """
        Get the default network interface for packet capture.
        
        Returns:
            Default interface name or None if not found
        """
        try:
            interfaces = get_if_list()
            
            # Filter out loopback and virtual interfaces
            real_interfaces = [
                iface for iface in interfaces 
                if not iface.startswith(('lo', 'Loopback', 'VMware', 'VirtualBox'))
            ]
            
            if real_interfaces:
                default_iface = real_interfaces[0]
                self.logger.info(f"Auto-selected interface: {default_iface}")
                return default_iface
            else:
                self.logger.warning("No suitable network interface found")
                return None
                
        except Exception as e:
            self.logger.error(f"Error detecting default interface: {e}")
            return None
            
    def start_capture(self) -> bool:
        """
        Start packet capture in a background thread.
        
        Returns:
            True if capture started successfully, False otherwise
        """
        if not self.enabled or not SCAPY_AVAILABLE:
            self.logger.info("Packet capture is disabled")
            return False
            
        if not self.interface:
            self.logger.error("No network interface specified for packet capture")
            return False
            
        if self._capture_thread and self._capture_thread.is_alive():
            self.logger.warning("Packet capture is already running")
            return True
            
        try:
            self._stop_capture = False
            self._capture_thread = threading.Thread(
                target=self._capture_packets,
                daemon=True
            )
            self._capture_thread.start()
            
            self.logger.info(f"Started packet capture on interface {self.interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting packet capture: {e}")
            return False
            
    def stop_capture(self) -> None:
        """Stop packet capture."""
        if self._capture_thread and self._capture_thread.is_alive():
            self._stop_capture = True
            self._capture_thread.join(timeout=5)
            self.logger.info("Stopped packet capture")
            
    def _capture_packets(self) -> None:
        """Main packet capture loop (runs in background thread)."""
        try:
            # Configure Scapy to be less verbose
            conf.verb = 0
            
            self.logger.info(
                f"Starting packet capture on {self.interface} "
                f"with filter: '{self.filter_expression}'"
            )
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.filter_expression,
                prn=self._process_packet,
                stop_filter=lambda x: self._stop_capture,
                store=False  # Don't store packets in memory
            )
            
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            
    def _process_packet(self, packet) -> None:
        """
        Process a captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            with self._capture_lock:
                # Limit the number of stored packets
                if len(self._captured_packets) >= self.max_packets:
                    self._captured_packets.pop(0)  # Remove oldest packet
                    
                # Parse and store the packet
                parsed_packet = self._parse_packet(packet)
                if parsed_packet:
                    self._captured_packets.append(parsed_packet)
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            
    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Parse a packet into a standardized format.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Parsed packet dictionary or None
        """
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'source': 'PacketCapture',
                'source_type': 'network',
                'host': socket.gethostname(),
                'log_level': 'info',
                'message': '',
                'packet_size': len(packet),
                'additional_fields': {
                    'interface': self.interface,
                    'protocols': []
                }
            }
            
            # Parse Ethernet layer
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info['additional_fields']['ethernet'] = {
                    'src_mac': eth.src,
                    'dst_mac': eth.dst,
                    'type': eth.type
                }
                packet_info['additional_fields']['protocols'].append('Ethernet')
                
            # Parse IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['additional_fields']['ip'] = {
                    'version': ip.version,
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'protocol': ip.proto,
                    'ttl': ip.ttl,
                    'length': ip.len
                }
                packet_info['additional_fields']['protocols'].append('IP')
                
                # Build message
                packet_info['message'] = f"IP packet: {ip.src} -> {ip.dst}"
                
                # Parse transport layer
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_info['additional_fields']['tcp'] = {
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'seq': tcp.seq,
                        'ack': tcp.ack,
                        'flags': tcp.flags,
                        'window': tcp.window
                    }
                    packet_info['additional_fields']['protocols'].append('TCP')
                    packet_info['message'] += f" TCP {tcp.sport}->{tcp.dport}"
                    
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info['additional_fields']['udp'] = {
                        'src_port': udp.sport,
                        'dst_port': udp.dport,
                        'length': udp.len
                    }
                    packet_info['additional_fields']['protocols'].append('UDP')
                    packet_info['message'] += f" UDP {udp.sport}->{udp.dport}"
                    
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    packet_info['additional_fields']['icmp'] = {
                        'type': icmp.type,
                        'code': icmp.code
                    }
                    packet_info['additional_fields']['protocols'].append('ICMP')
                    packet_info['message'] += f" ICMP type:{icmp.type} code:{icmp.code}"
                    
            # Add packet summary if no specific message was created
            if not packet_info['message']:
                packet_info['message'] = packet.summary()
                
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            return None
            
    def collect_logs(self) -> List[Dict[str, Any]]:
        """
        Collect captured packets as log entries.
        
        Returns:
            List of packet log entries
        """
        if not self.enabled or not SCAPY_AVAILABLE:
            return []
            
        with self._capture_lock:
            # Return a copy of captured packets and clear the buffer
            packets = self._captured_packets.copy()
            self._captured_packets.clear()
            return packets
            
    def get_capture_stats(self) -> Dict[str, Any]:
        """
        Get packet capture statistics.
        
        Returns:
            Dictionary containing capture statistics
        """
        stats = {
            'enabled': self.enabled,
            'interface': self.interface,
            'filter': self.filter_expression,
            'captured_packets': 0,
            'capture_active': False
        }
        
        if self.enabled and SCAPY_AVAILABLE:
            with self._capture_lock:
                stats['captured_packets'] = len(self._captured_packets)
                
            stats['capture_active'] = (
                self._capture_thread is not None and 
                self._capture_thread.is_alive()
            )
            
        return stats
        
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            return get_if_list()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []
            
    def test_interface(self, interface: str) -> bool:
        """
        Test if an interface is available for packet capture.
        
        Args:
            interface: Interface name to test
            
        Returns:
            True if interface is available, False otherwise
        """
        if not SCAPY_AVAILABLE:
            return False
            
        try:
            available_interfaces = get_if_list()
            return interface in available_interfaces
        except Exception as e:
            self.logger.error(f"Error testing interface {interface}: {e}")
            return False
            
    def set_filter(self, filter_expression: str) -> bool:
        """
        Set a new packet filter expression.
        
        Args:
            filter_expression: BPF filter expression
            
        Returns:
            True if filter was set successfully, False otherwise
        """
        try:
            # Validate filter by attempting to compile it
            # Note: This is a basic validation, actual validation would require
            # platform-specific BPF compilation
            self.filter_expression = filter_expression
            self.logger.info(f"Set packet filter: {filter_expression}")
            return True
        except Exception as e:
            self.logger.error(f"Error setting filter: {e}")
            return False


class MockPacketCollector:
    """Mock packet collector for when Scapy is not available."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = False
        self.logger.warning("Scapy not available - using mock packet collector")
        
    def start_capture(self) -> bool:
        return False
        
    def stop_capture(self) -> None:
        pass
        
    def collect_logs(self) -> List[Dict[str, Any]]:
        return []
        
    def get_capture_stats(self) -> Dict[str, Any]:
        return {
            'enabled': False,
            'interface': None,
            'filter': '',
            'captured_packets': 0,
            'capture_active': False,
            'error': 'Scapy not available'
        }
        
    def get_available_interfaces(self) -> List[str]:
        return []
        
    def test_interface(self, interface: str) -> bool:
        return False
        
    def set_filter(self, filter_expression: str) -> bool:
        return False


# Factory function to create appropriate collector
def create_packet_collector(config: Dict[str, Any]) -> 'PacketCollector':
    """
    Create a packet collector instance.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        PacketCollector or MockPacketCollector instance
    """
    if SCAPY_AVAILABLE:
        return PacketCollector(config)
    else:
        return MockPacketCollector(config)
