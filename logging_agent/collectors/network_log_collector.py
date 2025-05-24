"""
Network Log Collector

This module collects network-related logs including connection attempts,
network interface changes, and basic network statistics.
"""

import logging
import psutil
import socket
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


class NetworkLogCollector:
    """Collects network-related logs and statistics."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Network Log Collector.
        
        Args:
            config: Configuration dictionary for network log collection
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.include_connections = config.get('include_connections', True)
        self.include_interface_changes = config.get('include_interface_changes', True)
        
        # Store previous state for change detection
        self._previous_connections = set()
        self._previous_interfaces = {}
        self._previous_stats = {}
        
        # Initialize baseline
        self._initialize_baseline()
        
    def _initialize_baseline(self) -> None:
        """Initialize baseline network state for change detection."""
        try:
            if self.include_connections:
                self._previous_connections = set(self._get_connection_tuples())
                
            if self.include_interface_changes:
                self._previous_interfaces = self._get_interface_info()
                self._previous_stats = self._get_interface_stats()
                
        except Exception as e:
            self.logger.error(f"Error initializing network baseline: {e}")
            
    def collect_logs(self) -> List[Dict[str, Any]]:
        """
        Collect network logs including connections and interface changes.
        
        Returns:
            List of collected network log entries
        """
        logs = []
        
        try:
            if self.include_connections:
                connection_logs = self._collect_connection_logs()
                logs.extend(connection_logs)
                
            if self.include_interface_changes:
                interface_logs = self._collect_interface_logs()
                logs.extend(interface_logs)
                
        except Exception as e:
            self.logger.error(f"Error collecting network logs: {e}")
            
        return logs
        
    def _collect_connection_logs(self) -> List[Dict[str, Any]]:
        """
        Collect network connection logs by detecting changes.
        
        Returns:
            List of connection log entries
        """
        logs = []
        
        try:
            current_connections = set(self._get_connection_tuples())
            
            # Detect new connections
            new_connections = current_connections - self._previous_connections
            for conn_tuple in new_connections:
                log_entry = self._create_connection_log(conn_tuple, "new_connection")
                if log_entry:
                    logs.append(log_entry)
                    
            # Detect closed connections
            closed_connections = self._previous_connections - current_connections
            for conn_tuple in closed_connections:
                log_entry = self._create_connection_log(conn_tuple, "connection_closed")
                if log_entry:
                    logs.append(log_entry)
                    
            # Update previous state
            self._previous_connections = current_connections
            
        except Exception as e:
            self.logger.error(f"Error collecting connection logs: {e}")
            
        return logs
        
    def _collect_interface_logs(self) -> List[Dict[str, Any]]:
        """
        Collect network interface logs by detecting changes.
        
        Returns:
            List of interface log entries
        """
        logs = []
        
        try:
            current_interfaces = self._get_interface_info()
            current_stats = self._get_interface_stats()
            
            # Detect interface changes
            for interface, info in current_interfaces.items():
                if interface not in self._previous_interfaces:
                    # New interface
                    log_entry = self._create_interface_log(interface, info, "interface_added")
                    if log_entry:
                        logs.append(log_entry)
                elif info != self._previous_interfaces[interface]:
                    # Interface changed
                    log_entry = self._create_interface_log(interface, info, "interface_changed")
                    if log_entry:
                        logs.append(log_entry)
                        
            # Detect removed interfaces
            for interface in self._previous_interfaces:
                if interface not in current_interfaces:
                    log_entry = self._create_interface_log(
                        interface, 
                        self._previous_interfaces[interface], 
                        "interface_removed"
                    )
                    if log_entry:
                        logs.append(log_entry)
                        
            # Detect significant traffic changes
            traffic_logs = self._detect_traffic_changes(current_stats)
            logs.extend(traffic_logs)
            
            # Update previous state
            self._previous_interfaces = current_interfaces
            self._previous_stats = current_stats
            
        except Exception as e:
            self.logger.error(f"Error collecting interface logs: {e}")
            
        return logs
        
    def _get_connection_tuples(self) -> List[tuple]:
        """
        Get current network connections as tuples for comparison.
        
        Returns:
            List of connection tuples
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    conn_tuple = (
                        conn.family,
                        conn.type,
                        conn.laddr.ip if conn.laddr else None,
                        conn.laddr.port if conn.laddr else None,
                        conn.raddr.ip if conn.raddr else None,
                        conn.raddr.port if conn.raddr else None,
                        conn.pid
                    )
                    connections.append(conn_tuple)
                    
        except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
            self.logger.debug(f"Access denied getting connections: {e}")
        except Exception as e:
            self.logger.error(f"Error getting connections: {e}")
            
        return connections
        
    def _get_interface_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get current network interface information.
        
        Returns:
            Dictionary of interface information
        """
        interfaces = {}
        
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface, addr_list in addrs.items():
                interface_info = {
                    'addresses': [],
                    'is_up': stats.get(interface, {}).isup if interface in stats else False,
                    'duplex': stats.get(interface, {}).duplex if interface in stats else None,
                    'speed': stats.get(interface, {}).speed if interface in stats else None,
                    'mtu': stats.get(interface, {}).mtu if interface in stats else None
                }
                
                for addr in addr_list:
                    addr_info = {
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                    
                interfaces[interface] = interface_info
                
        except Exception as e:
            self.logger.error(f"Error getting interface info: {e}")
            
        return interfaces
        
    def _get_interface_stats(self) -> Dict[str, Dict[str, int]]:
        """
        Get current network interface statistics.
        
        Returns:
            Dictionary of interface statistics
        """
        stats = {}
        
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            
            for interface, counters in io_counters.items():
                stats[interface] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout
                }
                
        except Exception as e:
            self.logger.error(f"Error getting interface stats: {e}")
            
        return stats
        
    def _create_connection_log(self, conn_tuple: tuple, event_type: str) -> Optional[Dict[str, Any]]:
        """
        Create a log entry for a network connection event.
        
        Args:
            conn_tuple: Connection tuple
            event_type: Type of connection event
            
        Returns:
            Log entry dictionary or None
        """
        try:
            family, conn_type, local_ip, local_port, remote_ip, remote_port, pid = conn_tuple
            
            # Get process information if available
            process_name = None
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'source': 'NetworkConnections',
                'source_type': 'network',
                'host': socket.gethostname(),
                'log_level': 'info',
                'message': f"{event_type}: {local_ip}:{local_port} -> {remote_ip}:{remote_port}",
                'event_type': event_type,
                'additional_fields': {
                    'connection_family': socket.AddressFamily(family).name,
                    'connection_type': socket.SocketKind(conn_type).name,
                    'local_address': local_ip,
                    'local_port': local_port,
                    'remote_address': remote_ip,
                    'remote_port': remote_port,
                    'process_id': pid,
                    'process_name': process_name
                }
            }
            
            return log_entry
            
        except Exception as e:
            self.logger.error(f"Error creating connection log: {e}")
            return None
            
    def _create_interface_log(
        self, 
        interface: str, 
        info: Dict[str, Any], 
        event_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Create a log entry for a network interface event.
        
        Args:
            interface: Interface name
            info: Interface information
            event_type: Type of interface event
            
        Returns:
            Log entry dictionary or None
        """
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'source': 'NetworkInterfaces',
                'source_type': 'network',
                'host': socket.gethostname(),
                'log_level': 'info',
                'message': f"{event_type}: {interface}",
                'event_type': event_type,
                'additional_fields': {
                    'interface_name': interface,
                    'interface_info': info
                }
            }
            
            return log_entry
            
        except Exception as e:
            self.logger.error(f"Error creating interface log: {e}")
            return None
            
    def _detect_traffic_changes(self, current_stats: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
        """
        Detect significant traffic changes on network interfaces.
        
        Args:
            current_stats: Current interface statistics
            
        Returns:
            List of traffic change log entries
        """
        logs = []
        
        try:
            for interface, stats in current_stats.items():
                if interface in self._previous_stats:
                    prev_stats = self._previous_stats[interface]
                    
                    # Calculate traffic deltas
                    bytes_sent_delta = stats['bytes_sent'] - prev_stats['bytes_sent']
                    bytes_recv_delta = stats['bytes_recv'] - prev_stats['bytes_recv']
                    
                    # Check for significant traffic (> 10MB in collection interval)
                    threshold = 10 * 1024 * 1024  # 10MB
                    
                    if bytes_sent_delta > threshold or bytes_recv_delta > threshold:
                        log_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'source': 'NetworkTraffic',
                            'source_type': 'network',
                            'host': socket.gethostname(),
                            'log_level': 'info',
                            'message': f"High traffic on {interface}: "
                                     f"Sent: {bytes_sent_delta/1024/1024:.2f}MB, "
                                     f"Received: {bytes_recv_delta/1024/1024:.2f}MB",
                            'event_type': 'high_traffic',
                            'additional_fields': {
                                'interface_name': interface,
                                'bytes_sent_delta': bytes_sent_delta,
                                'bytes_recv_delta': bytes_recv_delta,
                                'current_stats': stats,
                                'previous_stats': prev_stats
                            }
                        }
                        logs.append(log_entry)
                        
        except Exception as e:
            self.logger.error(f"Error detecting traffic changes: {e}")
            
        return logs
        
    def get_network_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current network state.
        
        Returns:
            Dictionary containing network summary information
        """
        summary = {
            'active_connections': 0,
            'listening_ports': [],
            'interfaces': {},
            'total_traffic': {'sent': 0, 'received': 0}
        }
        
        try:
            # Count active connections
            connections = psutil.net_connections(kind='inet')
            summary['active_connections'] = len([
                c for c in connections if c.status == psutil.CONN_ESTABLISHED
            ])
            
            # Get listening ports
            listening = [
                c.laddr.port for c in connections 
                if c.status == psutil.CONN_LISTEN and c.laddr
            ]
            summary['listening_ports'] = sorted(set(listening))
            
            # Get interface information
            summary['interfaces'] = self._get_interface_info()
            
            # Calculate total traffic
            stats = psutil.net_io_counters()
            summary['total_traffic'] = {
                'sent': stats.bytes_sent,
                'received': stats.bytes_recv
            }
            
        except Exception as e:
            self.logger.error(f"Error generating network summary: {e}")
            
        return summary
