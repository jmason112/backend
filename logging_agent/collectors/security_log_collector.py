"""
Windows Security Log Collector

This module specifically collects Windows Security logs including
authentication events, policy changes, and privilege use.
"""

import logging
import win32evtlog
import win32api
import win32security
from typing import List, Dict, Any, Optional
from datetime import datetime
from .event_log_collector import EventLogCollector


class SecurityLogCollector(EventLogCollector):
    """Specialized collector for Windows Security logs."""
    
    # Security event IDs of interest
    SECURITY_EVENT_IDS = {
        # Authentication events
        4624: "Successful logon",
        4625: "Failed logon",
        4634: "Logoff",
        4647: "User initiated logoff",
        4648: "Logon using explicit credentials",
        4672: "Special privileges assigned to new logon",
        
        # Account management
        4720: "User account created",
        4722: "User account enabled",
        4723: "User account password change attempted",
        4724: "User account password reset attempted",
        4725: "User account disabled",
        4726: "User account deleted",
        4738: "User account changed",
        4740: "User account locked out",
        4767: "User account unlocked",
        
        # Policy changes
        4719: "System audit policy changed",
        4739: "Domain policy changed",
        4817: "Audit settings on object changed",
        
        # Privilege use
        4673: "Privileged service called",
        4674: "Operation attempted on privileged object",
        
        # Process and object access
        4688: "New process created",
        4689: "Process terminated",
        4656: "Handle to object requested",
        4658: "Handle to object closed",
        4663: "Attempt to access object",
        
        # System events
        4608: "Windows starting up",
        4609: "Windows shutting down",
        4616: "System time changed",
        4697: "Service installed",
        
        # Logon/Logoff events
        4800: "Workstation locked",
        4801: "Workstation unlocked",
        4802: "Screen saver invoked",
        4803: "Screen saver dismissed"
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Security Log Collector.
        
        Args:
            config: Configuration dictionary for security log collection
        """
        # Override sources to focus on Security log
        security_config = config.copy()
        security_config['sources'] = ['Security']
        
        super().__init__(security_config)
        
        self.include_authentication = config.get('include_authentication', True)
        self.include_policy_changes = config.get('include_policy_changes', True)
        self.include_privilege_use = config.get('include_privilege_use', True)
        
        # Build filter based on configuration
        self.event_id_filter = self._build_event_filter()
        
    def _build_event_filter(self) -> set:
        """
        Build event ID filter based on configuration.
        
        Returns:
            Set of event IDs to collect
        """
        event_ids = set()
        
        if self.include_authentication:
            # Authentication and account management events
            auth_events = {4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4723, 
                          4724, 4725, 4726, 4738, 4740, 4767, 4800, 4801, 4802, 4803}
            event_ids.update(auth_events)
            
        if self.include_policy_changes:
            # Policy change events
            policy_events = {4719, 4739, 4817}
            event_ids.update(policy_events)
            
        if self.include_privilege_use:
            # Privilege use events
            privilege_events = {4673, 4674}
            event_ids.update(privilege_events)
            
        # Always include critical system events
        system_events = {4608, 4609, 4616, 4697, 4688, 4689}
        event_ids.update(system_events)
        
        return event_ids
        
    def _parse_event(self, event, source: str) -> Optional[Dict[str, Any]]:
        """
        Parse a security event with enhanced security-specific information.
        
        Args:
            event: Windows event object
            source: Source name of the event log
            
        Returns:
            Parsed security log entry or None if parsing fails
        """
        # Get base event information
        log_entry = super()._parse_event(event, source)
        if not log_entry:
            return None
            
        event_id = event.EventID & 0xFFFF
        
        # Filter events based on configuration
        if self.event_id_filter and event_id not in self.event_id_filter:
            return None
            
        # Add security-specific information
        log_entry['source_type'] = 'security'
        log_entry['event_description'] = self.SECURITY_EVENT_IDS.get(
            event_id, "Unknown security event"
        )
        
        # Parse security-specific fields
        security_fields = self._parse_security_fields(event)
        if security_fields:
            log_entry['additional_fields'].update(security_fields)
            
        # Categorize the event
        log_entry['security_category'] = self._categorize_security_event(event_id)
        
        # Set appropriate log level based on event type
        log_entry['log_level'] = self._get_security_log_level(event_id)
        
        return log_entry
        
    def _parse_security_fields(self, event) -> Dict[str, Any]:
        """
        Parse security-specific fields from the event.
        
        Args:
            event: Windows event object
            
        Returns:
            Dictionary of security-specific fields
        """
        fields = {}
        event_id = event.EventID & 0xFFFF
        
        try:
            # Parse string inserts based on event type
            if event.StringInserts:
                inserts = event.StringInserts
                
                if event_id in [4624, 4625]:  # Logon events
                    fields.update(self._parse_logon_event(inserts, event_id))
                elif event_id in [4720, 4722, 4725, 4726]:  # Account management
                    fields.update(self._parse_account_event(inserts))
                elif event_id == 4688:  # Process creation
                    fields.update(self._parse_process_event(inserts))
                elif event_id in [4719, 4739]:  # Policy changes
                    fields.update(self._parse_policy_event(inserts))
                    
        except Exception as e:
            self.logger.warning(f"Error parsing security fields for event {event_id}: {e}")
            
        return fields
        
    def _parse_logon_event(self, inserts: List[str], event_id: int) -> Dict[str, Any]:
        """Parse logon/logoff event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 8:
                fields['target_user_name'] = inserts[5] if len(inserts) > 5 else ""
                fields['target_domain_name'] = inserts[6] if len(inserts) > 6 else ""
                fields['logon_type'] = inserts[8] if len(inserts) > 8 else ""
                fields['authentication_package'] = inserts[10] if len(inserts) > 10 else ""
                fields['workstation_name'] = inserts[11] if len(inserts) > 11 else ""
                fields['source_network_address'] = inserts[18] if len(inserts) > 18 else ""
                fields['source_port'] = inserts[19] if len(inserts) > 19 else ""
                
                # Map logon type to description
                logon_types = {
                    "2": "Interactive",
                    "3": "Network",
                    "4": "Batch",
                    "5": "Service",
                    "7": "Unlock",
                    "8": "NetworkCleartext",
                    "9": "NewCredentials",
                    "10": "RemoteInteractive",
                    "11": "CachedInteractive"
                }
                
                logon_type_desc = logon_types.get(fields.get('logon_type', ''), 'Unknown')
                fields['logon_type_description'] = logon_type_desc
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing logon event fields: {e}")
            
        return fields
        
    def _parse_account_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse account management event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 4:
                fields['target_account_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['target_account_domain'] = inserts[1] if len(inserts) > 1 else ""
                fields['subject_account_name'] = inserts[4] if len(inserts) > 4 else ""
                fields['subject_account_domain'] = inserts[5] if len(inserts) > 5 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing account event fields: {e}")
            
        return fields
        
    def _parse_process_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse process creation event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 6:
                fields['process_name'] = inserts[5] if len(inserts) > 5 else ""
                fields['process_id'] = inserts[4] if len(inserts) > 4 else ""
                fields['command_line'] = inserts[8] if len(inserts) > 8 else ""
                fields['parent_process_name'] = inserts[13] if len(inserts) > 13 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing process event fields: {e}")
            
        return fields
        
    def _parse_policy_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse policy change event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 2:
                fields['policy_category'] = inserts[0] if len(inserts) > 0 else ""
                fields['policy_changes'] = inserts[1] if len(inserts) > 1 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing policy event fields: {e}")
            
        return fields
        
    def _categorize_security_event(self, event_id: int) -> str:
        """
        Categorize security events into logical groups.
        
        Args:
            event_id: Windows security event ID
            
        Returns:
            Category string
        """
        if event_id in [4624, 4625, 4634, 4647, 4648, 4800, 4801, 4802, 4803]:
            return "authentication"
        elif event_id in [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767]:
            return "account_management"
        elif event_id in [4719, 4739, 4817]:
            return "policy_change"
        elif event_id in [4673, 4674]:
            return "privilege_use"
        elif event_id in [4688, 4689]:
            return "process_tracking"
        elif event_id in [4656, 4658, 4663]:
            return "object_access"
        elif event_id in [4608, 4609, 4616, 4697]:
            return "system"
        else:
            return "other"
            
    def _get_security_log_level(self, event_id: int) -> str:
        """
        Get appropriate log level for security events.
        
        Args:
            event_id: Windows security event ID
            
        Returns:
            Log level string
        """
        # Critical security events
        critical_events = {4625, 4740, 4625}  # Failed logons, lockouts
        
        # Warning events
        warning_events = {4672, 4673, 4674, 4719, 4739}  # Privilege use, policy changes
        
        if event_id in critical_events:
            return "warning"
        elif event_id in warning_events:
            return "warning"
        else:
            return "info"
            
    def get_security_summary(self) -> Dict[str, int]:
        """
        Get a summary of security events by category.
        
        Returns:
            Dictionary with event counts by category
        """
        summary = {
            "authentication": 0,
            "account_management": 0,
            "policy_change": 0,
            "privilege_use": 0,
            "process_tracking": 0,
            "object_access": 0,
            "system": 0,
            "other": 0
        }
        
        try:
            logs = self.collect_logs()
            for log in logs:
                category = log.get('security_category', 'other')
                summary[category] = summary.get(category, 0) + 1
                
        except Exception as e:
            self.logger.error(f"Error generating security summary: {e}")
            
        return summary
