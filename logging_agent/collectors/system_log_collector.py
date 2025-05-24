"""
System Log Collector

This module collects Windows System logs including hardware changes,
driver failures, and system events.
"""

import logging
import win32evtlog
import win32api
import psutil
from typing import List, Dict, Any, Optional
from datetime import datetime
from .event_log_collector import EventLogCollector


class SystemLogCollector(EventLogCollector):
    """Specialized collector for Windows System logs."""
    
    # System event IDs of interest
    SYSTEM_EVENT_IDS = {
        # System startup/shutdown
        6005: "Event log service started",
        6006: "Event log service stopped",
        6008: "Unexpected shutdown",
        6009: "System startup",
        6013: "System uptime",
        
        # Hardware events
        10: "Hardware configuration changed",
        20: "Plug and Play device installed",
        24: "Device driver loaded",
        25: "Device driver unloaded",
        
        # Driver events
        7000: "Service failed to start",
        7001: "Service depends on failed service",
        7009: "Service timeout",
        7011: "Service timeout (transaction)",
        7023: "Service terminated with error",
        7024: "Service terminated unexpectedly",
        7026: "Boot-start or system-start driver failed",
        7031: "Service crashed and was restarted",
        7032: "Service recovery action taken",
        7034: "Service crashed unexpectedly",
        
        # Disk events
        51: "Disk error",
        52: "Disk warning",
        98: "Disk performance degraded",
        129: "Reset to device",
        
        # Memory events
        2019: "Memory resource exhaustion",
        2020: "Memory allocation failure",
        
        # Power events
        1: "System power event",
        42: "System entering sleep",
        107: "System resumed from sleep",
        
        # Time events
        1: "System time changed",
        37: "Time service synchronization",
        
        # Network events
        4201: "Network adapter disabled",
        4202: "Network adapter enabled",
        
        # Security events
        4608: "Windows starting up",
        4609: "Windows shutting down"
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the System Log Collector.
        
        Args:
            config: Configuration dictionary for system log collection
        """
        # Set up system-specific sources
        system_config = config.copy()
        system_config['sources'] = ['System']
        
        super().__init__(system_config)
        
        self.include_hardware = config.get('include_hardware', True)
        self.include_drivers = config.get('include_drivers', True)
        self.include_services = config.get('include_services', True)
        
        # Build filter based on configuration
        self.event_id_filter = self._build_event_filter()
        
    def _build_event_filter(self) -> set:
        """
        Build event ID filter based on configuration.
        
        Returns:
            Set of event IDs to collect
        """
        event_ids = set()
        
        # Always include critical system events
        critical_events = {6005, 6006, 6008, 6009, 6013, 4608, 4609}
        event_ids.update(critical_events)
        
        if self.include_hardware:
            hardware_events = {10, 20, 24, 25, 51, 52, 98, 129, 2019, 2020}
            event_ids.update(hardware_events)
            
        if self.include_drivers:
            driver_events = {7026, 24, 25}
            event_ids.update(driver_events)
            
        if self.include_services:
            service_events = {7000, 7001, 7009, 7011, 7023, 7024, 7031, 7032, 7034}
            event_ids.update(service_events)
            
        # Power and time events
        power_time_events = {1, 42, 107, 37}
        event_ids.update(power_time_events)
        
        # Network events
        network_events = {4201, 4202}
        event_ids.update(network_events)
        
        return event_ids
        
    def _parse_event(self, event, source: str) -> Optional[Dict[str, Any]]:
        """
        Parse a system event with enhanced system-specific information.
        
        Args:
            event: Windows event object
            source: Source name of the event log
            
        Returns:
            Parsed system log entry or None if parsing fails
        """
        # Get base event information
        log_entry = super()._parse_event(event, source)
        if not log_entry:
            return None
            
        event_id = event.EventID & 0xFFFF
        
        # Filter events based on configuration
        if self.event_id_filter and event_id not in self.event_id_filter:
            return None
            
        # Add system-specific information
        log_entry['source_type'] = 'system'
        log_entry['event_description'] = self.SYSTEM_EVENT_IDS.get(
            event_id, "System event"
        )
        
        # Parse system-specific fields
        system_fields = self._parse_system_fields(event)
        if system_fields:
            log_entry['additional_fields'].update(system_fields)
            
        # Add system information
        log_entry['additional_fields']['system_info'] = self._get_system_info()
        
        # Categorize the event
        log_entry['system_category'] = self._categorize_system_event(event_id)
        
        # Set appropriate log level based on event type
        log_entry['log_level'] = self._get_system_log_level(event_id)
        
        return log_entry
        
    def _parse_system_fields(self, event) -> Dict[str, Any]:
        """
        Parse system-specific fields from the event.
        
        Args:
            event: Windows event object
            
        Returns:
            Dictionary of system-specific fields
        """
        fields = {}
        event_id = event.EventID & 0xFFFF
        
        try:
            if event.StringInserts:
                inserts = event.StringInserts
                
                if event_id in [7000, 7001, 7023, 7024, 7031, 7032, 7034]:  # Service events
                    fields.update(self._parse_service_event(inserts))
                elif event_id in [24, 25, 7026]:  # Driver events
                    fields.update(self._parse_driver_event(inserts))
                elif event_id in [51, 52, 98, 129]:  # Disk events
                    fields.update(self._parse_disk_event(inserts))
                elif event_id in [10, 20]:  # Hardware events
                    fields.update(self._parse_hardware_event(inserts))
                elif event_id == 6013:  # Uptime event
                    fields.update(self._parse_uptime_event(inserts))
                    
        except Exception as e:
            self.logger.warning(f"Error parsing system fields for event {event_id}: {e}")
            
        return fields
        
    def _parse_service_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse service-related event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['service_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['service_error'] = inserts[1] if len(inserts) > 1 else ""
                fields['service_exit_code'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing service event fields: {e}")
            
        return fields
        
    def _parse_driver_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse driver-related event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['driver_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['driver_path'] = inserts[1] if len(inserts) > 1 else ""
                fields['driver_version'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing driver event fields: {e}")
            
        return fields
        
    def _parse_disk_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse disk-related event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['device_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['error_code'] = inserts[1] if len(inserts) > 1 else ""
                fields['error_description'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing disk event fields: {e}")
            
        return fields
        
    def _parse_hardware_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse hardware-related event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['device_id'] = inserts[0] if len(inserts) > 0 else ""
                fields['device_description'] = inserts[1] if len(inserts) > 1 else ""
                fields['device_status'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing hardware event fields: {e}")
            
        return fields
        
    def _parse_uptime_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse system uptime event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                uptime_seconds = int(inserts[0]) if inserts[0].isdigit() else 0
                fields['uptime_seconds'] = uptime_seconds
                fields['uptime_days'] = uptime_seconds // 86400
                fields['uptime_hours'] = (uptime_seconds % 86400) // 3600
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing uptime event fields: {e}")
            
        return fields
        
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Get current system information.
        
        Returns:
            Dictionary containing system information
        """
        system_info = {}
        
        try:
            # CPU information
            system_info['cpu_count'] = psutil.cpu_count()
            system_info['cpu_percent'] = psutil.cpu_percent(interval=1)
            
            # Memory information
            memory = psutil.virtual_memory()
            system_info['memory_total'] = memory.total
            system_info['memory_available'] = memory.available
            system_info['memory_percent'] = memory.percent
            
            # Disk information
            disk = psutil.disk_usage('/')
            system_info['disk_total'] = disk.total
            system_info['disk_free'] = disk.free
            system_info['disk_percent'] = (disk.used / disk.total) * 100
            
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            system_info['boot_time'] = boot_time.isoformat()
            
            # Load average (if available)
            try:
                system_info['load_average'] = psutil.getloadavg()
            except AttributeError:
                # Not available on Windows
                pass
                
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            
        return system_info
        
    def _categorize_system_event(self, event_id: int) -> str:
        """
        Categorize system events into logical groups.
        
        Args:
            event_id: Windows system event ID
            
        Returns:
            Category string
        """
        if event_id in [6005, 6006, 6008, 6009, 6013, 4608, 4609]:
            return "system_lifecycle"
        elif event_id in [10, 20, 24, 25]:
            return "hardware"
        elif event_id in [7000, 7001, 7009, 7011, 7023, 7024, 7031, 7032, 7034]:
            return "service"
        elif event_id in [51, 52, 98, 129]:
            return "disk"
        elif event_id in [2019, 2020]:
            return "memory"
        elif event_id in [1, 42, 107]:
            return "power"
        elif event_id in [37]:
            return "time"
        elif event_id in [4201, 4202]:
            return "network"
        else:
            return "other"
            
    def _get_system_log_level(self, event_id: int) -> str:
        """
        Get appropriate log level for system events.
        
        Args:
            event_id: Windows system event ID
            
        Returns:
            Log level string
        """
        # Critical system events
        critical_events = {6008, 7000, 7023, 7024, 7026, 7031, 7034, 51, 2019, 2020}
        
        # Warning events
        warning_events = {7001, 7009, 7011, 7032, 52, 98, 129}
        
        if event_id in critical_events:
            return "error"
        elif event_id in warning_events:
            return "warning"
        else:
            return "info"
            
    def get_system_summary(self) -> Dict[str, int]:
        """
        Get a summary of system events by category.
        
        Returns:
            Dictionary with event counts by category
        """
        summary = {
            "system_lifecycle": 0,
            "hardware": 0,
            "service": 0,
            "disk": 0,
            "memory": 0,
            "power": 0,
            "time": 0,
            "network": 0,
            "other": 0
        }
        
        try:
            logs = self.collect_logs()
            for log in logs:
                category = log.get('system_category', 'other')
                summary[category] = summary.get(category, 0) + 1
                
        except Exception as e:
            self.logger.error(f"Error generating system summary: {e}")
            
        return summary
        
    def get_system_health(self) -> Dict[str, Any]:
        """
        Get current system health metrics.
        
        Returns:
            Dictionary containing system health information
        """
        health = {
            'status': 'healthy',
            'issues': [],
            'metrics': {}
        }
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            health['metrics']['cpu_percent'] = cpu_percent
            if cpu_percent > 90:
                health['issues'].append('High CPU usage')
                health['status'] = 'warning'
                
            # Memory usage
            memory = psutil.virtual_memory()
            health['metrics']['memory_percent'] = memory.percent
            if memory.percent > 90:
                health['issues'].append('High memory usage')
                health['status'] = 'warning'
                
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            health['metrics']['disk_percent'] = disk_percent
            if disk_percent > 90:
                health['issues'].append('High disk usage')
                health['status'] = 'warning'
                
            # Check for recent critical events
            recent_logs = self.collect_logs()
            critical_count = len([
                log for log in recent_logs 
                if log.get('log_level') == 'error'
            ])
            
            health['metrics']['recent_critical_events'] = critical_count
            if critical_count > 5:
                health['issues'].append('Multiple critical system events')
                health['status'] = 'critical'
                
            if health['issues']:
                health['status'] = 'critical' if 'critical' in str(health['issues']) else 'warning'
                
        except Exception as e:
            self.logger.error(f"Error getting system health: {e}")
            health['status'] = 'unknown'
            health['issues'].append(f'Error checking system health: {e}')
            
        return health
