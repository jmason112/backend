"""
Application Log Collector

This module collects Windows Application logs and other application-specific
log sources with enhanced parsing capabilities.
"""

import logging
import win32evtlog
import win32api
from typing import List, Dict, Any, Optional
from datetime import datetime
from .event_log_collector import EventLogCollector


class ApplicationLogCollector(EventLogCollector):
    """Specialized collector for Windows Application logs."""
    
    # Common application event IDs of interest
    APPLICATION_EVENT_IDS = {
        # Application errors
        1000: "Application Error",
        1001: "Windows Error Reporting",
        1002: "Application Hang",
        
        # Service events
        7034: "Service crashed unexpectedly",
        7035: "Service sent a control",
        7036: "Service entered running/stopped state",
        
        # Windows Update events
        19: "Windows Update installation started",
        20: "Windows Update installation succeeded",
        21: "Windows Update installation failed",
        
        # MSI Installer events
        1033: "MSI installation started",
        1034: "MSI installation completed",
        1035: "MSI installation failed",
        
        # .NET Runtime events
        1026: ".NET Runtime error",
        
        # Application-specific events
        100: "Application started",
        101: "Application stopped",
        102: "Application configuration changed"
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Application Log Collector.
        
        Args:
            config: Configuration dictionary for application log collection
        """
        # Set up application-specific sources
        app_config = config.copy()
        app_sources = config.get('sources', ['Application'])
        
        # Add Microsoft-Windows-* sources if configured
        if any('Microsoft-Windows-' in source for source in app_sources):
            # Get available Microsoft Windows sources
            available_sources = self._get_microsoft_sources()
            app_sources.extend(available_sources)
            
        app_config['sources'] = list(set(app_sources))  # Remove duplicates
        
        super().__init__(app_config)
        
    def _get_microsoft_sources(self) -> List[str]:
        """
        Get available Microsoft-Windows-* event log sources.
        
        Returns:
            List of Microsoft Windows event log sources
        """
        sources = []
        
        try:
            import winreg
            
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\EventLog"
            )
            
            i = 0
            while True:
                try:
                    source_name = winreg.EnumKey(key, i)
                    if source_name.startswith('Microsoft-Windows-'):
                        sources.append(source_name)
                    i += 1
                except WindowsError:
                    break
                    
            winreg.CloseKey(key)
            
            # Limit to most important sources to avoid overwhelming
            important_sources = [
                'Microsoft-Windows-Application-Experience',
                'Microsoft-Windows-ApplicationHost',
                'Microsoft-Windows-Kernel-General',
                'Microsoft-Windows-Security-Auditing',
                'Microsoft-Windows-TaskScheduler',
                'Microsoft-Windows-WindowsUpdateClient'
            ]
            
            # Return intersection of available and important sources
            return [s for s in sources if s in important_sources]
            
        except Exception as e:
            self.logger.error(f"Error getting Microsoft sources: {e}")
            return []
            
    def _parse_event(self, event, source: str) -> Optional[Dict[str, Any]]:
        """
        Parse an application event with enhanced application-specific information.
        
        Args:
            event: Windows event object
            source: Source name of the event log
            
        Returns:
            Parsed application log entry or None if parsing fails
        """
        # Get base event information
        log_entry = super()._parse_event(event, source)
        if not log_entry:
            return None
            
        event_id = event.EventID & 0xFFFF
        
        # Add application-specific information
        log_entry['source_type'] = 'application'
        log_entry['event_description'] = self.APPLICATION_EVENT_IDS.get(
            event_id, "Application event"
        )
        
        # Parse application-specific fields
        app_fields = self._parse_application_fields(event, source)
        if app_fields:
            log_entry['additional_fields'].update(app_fields)
            
        # Categorize the event
        log_entry['application_category'] = self._categorize_application_event(event_id, source)
        
        # Set appropriate log level based on event type and ID
        log_entry['log_level'] = self._get_application_log_level(event_id, event.EventType)
        
        return log_entry
        
    def _parse_application_fields(self, event, source: str) -> Dict[str, Any]:
        """
        Parse application-specific fields from the event.
        
        Args:
            event: Windows event object
            source: Source name
            
        Returns:
            Dictionary of application-specific fields
        """
        fields = {}
        event_id = event.EventID & 0xFFFF
        
        try:
            if event.StringInserts:
                inserts = event.StringInserts
                
                if event_id in [1000, 1002]:  # Application errors/hangs
                    fields.update(self._parse_application_error(inserts))
                elif event_id in [7034, 7035, 7036]:  # Service events
                    fields.update(self._parse_service_event(inserts))
                elif event_id in [19, 20, 21]:  # Windows Update events
                    fields.update(self._parse_update_event(inserts))
                elif event_id in [1033, 1034, 1035]:  # MSI events
                    fields.update(self._parse_msi_event(inserts))
                elif event_id == 1026:  # .NET Runtime error
                    fields.update(self._parse_dotnet_error(inserts))
                    
            # Add source-specific parsing
            if source.startswith('Microsoft-Windows-'):
                fields.update(self._parse_microsoft_event(event, source))
                
        except Exception as e:
            self.logger.warning(f"Error parsing application fields for event {event_id}: {e}")
            
        return fields
        
    def _parse_application_error(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse application error event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 4:
                fields['application_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['application_version'] = inserts[1] if len(inserts) > 1 else ""
                fields['module_name'] = inserts[2] if len(inserts) > 2 else ""
                fields['module_version'] = inserts[3] if len(inserts) > 3 else ""
                fields['exception_code'] = inserts[4] if len(inserts) > 4 else ""
                fields['fault_offset'] = inserts[5] if len(inserts) > 5 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing application error fields: {e}")
            
        return fields
        
    def _parse_service_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse service event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['service_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['service_state'] = inserts[1] if len(inserts) > 1 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing service event fields: {e}")
            
        return fields
        
    def _parse_update_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse Windows Update event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['update_title'] = inserts[0] if len(inserts) > 0 else ""
                fields['update_id'] = inserts[1] if len(inserts) > 1 else ""
                fields['result_code'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing update event fields: {e}")
            
        return fields
        
    def _parse_msi_event(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse MSI installer event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['product_name'] = inserts[0] if len(inserts) > 0 else ""
                fields['product_version'] = inserts[1] if len(inserts) > 1 else ""
                fields['installation_result'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing MSI event fields: {e}")
            
        return fields
        
    def _parse_dotnet_error(self, inserts: List[str]) -> Dict[str, Any]:
        """Parse .NET Runtime error event fields."""
        fields = {}
        
        try:
            if len(inserts) >= 1:
                fields['application_domain'] = inserts[0] if len(inserts) > 0 else ""
                fields['exception_type'] = inserts[1] if len(inserts) > 1 else ""
                fields['exception_message'] = inserts[2] if len(inserts) > 2 else ""
                
        except (IndexError, ValueError) as e:
            self.logger.debug(f"Error parsing .NET error fields: {e}")
            
        return fields
        
    def _parse_microsoft_event(self, event, source: str) -> Dict[str, Any]:
        """Parse Microsoft-Windows-* specific events."""
        fields = {}
        
        try:
            fields['microsoft_source'] = source
            
            # Add source-specific parsing based on the source name
            if 'TaskScheduler' in source:
                fields['event_category'] = 'task_scheduler'
            elif 'WindowsUpdateClient' in source:
                fields['event_category'] = 'windows_update'
            elif 'Application-Experience' in source:
                fields['event_category'] = 'application_experience'
            elif 'Kernel-General' in source:
                fields['event_category'] = 'kernel'
                
        except Exception as e:
            self.logger.debug(f"Error parsing Microsoft event fields: {e}")
            
        return fields
        
    def _categorize_application_event(self, event_id: int, source: str) -> str:
        """
        Categorize application events into logical groups.
        
        Args:
            event_id: Windows application event ID
            source: Event source name
            
        Returns:
            Category string
        """
        if event_id in [1000, 1001, 1002, 1026]:
            return "application_error"
        elif event_id in [7034, 7035, 7036]:
            return "service_management"
        elif event_id in [19, 20, 21]:
            return "windows_update"
        elif event_id in [1033, 1034, 1035]:
            return "software_installation"
        elif event_id in [100, 101, 102]:
            return "application_lifecycle"
        elif source.startswith('Microsoft-Windows-'):
            return "microsoft_component"
        else:
            return "general_application"
            
    def _get_application_log_level(self, event_id: int, event_type: int) -> str:
        """
        Get appropriate log level for application events.
        
        Args:
            event_id: Windows application event ID
            event_type: Windows event type
            
        Returns:
            Log level string
        """
        # Critical application events
        critical_events = {1000, 1002, 7034, 21, 1035, 1026}  # Errors, crashes, failures
        
        # Warning events
        warning_events = {1001, 7035, 1033}  # Warnings, service controls, installations
        
        if event_id in critical_events:
            return "error"
        elif event_id in warning_events:
            return "warning"
        else:
            # Use base class logic for standard event types
            return super()._get_event_level(event_type)
            
    def get_application_summary(self) -> Dict[str, int]:
        """
        Get a summary of application events by category.
        
        Returns:
            Dictionary with event counts by category
        """
        summary = {
            "application_error": 0,
            "service_management": 0,
            "windows_update": 0,
            "software_installation": 0,
            "application_lifecycle": 0,
            "microsoft_component": 0,
            "general_application": 0
        }
        
        try:
            logs = self.collect_logs()
            for log in logs:
                category = log.get('application_category', 'general_application')
                summary[category] = summary.get(category, 0) + 1
                
        except Exception as e:
            self.logger.error(f"Error generating application summary: {e}")
            
        return summary
