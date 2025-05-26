"""
Windows Event Log Collector

This module collects Windows Event Logs using the Windows API
and provides them in a standardized format for processing.
"""

import logging
import win32evtlog
import win32api
import win32con
import win32security
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


class EventLogCollector:
    """Collects Windows Event Logs from various sources."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Event Log Collector.

        Args:
            config: Configuration dictionary for event log collection
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.sources = config.get('sources', ['System', 'Application', 'Security'])
        self.max_records = config.get('max_records', 100)
        self.server = None  # Local machine

    def collect_logs(self) -> List[Dict[str, Any]]:
        """
        Collect event logs from all configured sources.

        Returns:
            List of collected log entries
        """
        all_logs = []

        for source in self.sources:
            try:
                logs = self._collect_from_source(source)
                all_logs.extend(logs)
                self.logger.debug(f"Collected {len(logs)} logs from {source}")
            except Exception as e:
                self.logger.error(f"Error collecting logs from {source}: {e}")

        return all_logs

    def _collect_from_source(self, source: str) -> List[Dict[str, Any]]:
        """
        Collect logs from a specific event log source.

        Args:
            source: Name of the event log source

        Returns:
            List of log entries from the source
        """
        logs = []

        try:
            # Check if this is a wildcard source that needs expansion
            if '*' in source:
                expanded_sources = self._expand_wildcard_source(source)
                for expanded_source in expanded_sources:
                    logs.extend(self._collect_from_single_source(expanded_source))
                return logs
            else:
                return self._collect_from_single_source(source)

        except Exception as e:
            self.logger.error(f"Error collecting from source {source}: {e}")

        return logs

    def _collect_from_single_source(self, source: str) -> List[Dict[str, Any]]:
        """
        Collect logs from a single, specific event log source.

        Args:
            source: Name of the event log source

        Returns:
            List of log entries from the source
        """
        logs = []

        try:
            # Check for Security log privilege requirements
            if source.lower() == 'security':
                if not self._check_security_privilege():
                    self.logger.warning(f"Insufficient privileges to access {source} event log. Run as administrator to access Security logs.")
                    return logs

            # Open the event log
            handle = win32evtlog.OpenEventLog(self.server, source)

            # Get the total number of records
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)

            if total_records == 0:
                win32evtlog.CloseEventLog(handle)
                return logs

            # Read events using sequential read (more reliable than seek)
            events = win32evtlog.ReadEventLog(
                handle,
                win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                0
            )

            # Limit to max_records most recent events
            event_count = 0
            for event in events:
                if event_count >= self.max_records:
                    break

                try:
                    log_entry = self._parse_event(event, source)
                    if log_entry:
                        logs.append(log_entry)
                        event_count += 1
                except Exception as e:
                    self.logger.warning(f"Error parsing event from {source}: {e}")

            win32evtlog.CloseEventLog(handle)

        except Exception as e:
            self.logger.error(f"Error accessing event log {source}: {e}")

        return logs

    def _parse_event(self, event, source: str) -> Optional[Dict[str, Any]]:
        """
        Parse a Windows event into a standardized format.

        Args:
            event: Windows event object
            source: Source name of the event log

        Returns:
            Parsed log entry or None if parsing fails
        """
        try:
            # Convert Windows timestamp to datetime
            timestamp = datetime.fromtimestamp(event.TimeGenerated.timestamp())

            # Get event level
            level = self._get_event_level(event.EventType)

            # Get event message
            message = self._get_event_message(event, source)

            # Create standardized log entry
            log_entry = {
                'timestamp': timestamp.isoformat(),
                'source': source,
                'source_type': 'event',
                'host': win32api.GetComputerName(),
                'log_level': level,
                'message': message,
                'event_id': event.EventID & 0xFFFF,  # Remove severity bits
                'event_category': event.EventCategory,
                'event_type': event.EventType,
                'source_name': event.SourceName,
                'user_sid': self._get_user_sid(event),
                'additional_fields': {
                    'record_number': event.RecordNumber,
                    'computer_name': event.ComputerName,
                    'string_inserts': event.StringInserts,
                    'data': event.Data.hex() if event.Data else None
                }
            }

            return log_entry

        except Exception as e:
            self.logger.error(f"Error parsing event: {e}")
            return None

    def _get_event_level(self, event_type: int) -> str:
        """
        Convert Windows event type to standard log level.

        Args:
            event_type: Windows event type constant

        Returns:
            Standard log level string
        """
        level_map = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'error',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'warning',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'info',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'info',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'warning'
        }

        return level_map.get(event_type, 'info')

    def _get_event_message(self, event, source: str) -> str:
        """
        Get the formatted message for an event.

        Args:
            event: Windows event object
            source: Source name of the event log

        Returns:
            Formatted event message
        """
        try:
            # Try to get the formatted message
            message = win32evtlogutil.SafeFormatMessage(event, source)
            if message:
                return message.strip()
        except:
            pass

        # Fallback to basic information
        message_parts = []

        if event.SourceName:
            message_parts.append(f"Source: {event.SourceName}")

        if event.EventID:
            message_parts.append(f"Event ID: {event.EventID & 0xFFFF}")

        if event.StringInserts:
            message_parts.append(f"Data: {', '.join(event.StringInserts)}")

        return ' | '.join(message_parts) if message_parts else "No message available"

    def _get_user_sid(self, event) -> Optional[str]:
        """
        Get the user SID from an event.

        Args:
            event: Windows event object

        Returns:
            User SID string or None
        """
        try:
            if event.Sid:
                return win32security.ConvertSidToStringSid(event.Sid)
        except:
            pass
        return None

    def get_available_sources(self) -> List[str]:
        """
        Get list of available event log sources on the system.

        Returns:
            List of available event log source names
        """
        sources = []

        try:
            # Get list of event logs from registry
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\EventLog"
            )

            i = 0
            while True:
                try:
                    source_name = winreg.EnumKey(key, i)
                    sources.append(source_name)
                    i += 1
                except WindowsError:
                    break

            winreg.CloseKey(key)

        except Exception as e:
            self.logger.error(f"Error getting available sources: {e}")
            # Return default sources if registry access fails
            sources = ['System', 'Application', 'Security']

        return sources

    def test_access(self) -> Dict[str, bool]:
        """
        Test access to configured event log sources.

        Returns:
            Dictionary mapping source names to access status
        """
        access_status = {}

        for source in self.sources:
            try:
                handle = win32evtlog.OpenEventLog(self.server, source)
                win32evtlog.CloseEventLog(handle)
                access_status[source] = True
                self.logger.debug(f"Access test successful for {source}")
            except Exception as e:
                access_status[source] = False
                self.logger.warning(f"Access test failed for {source}: {e}")

        return access_status

    def _expand_wildcard_source(self, wildcard_source: str) -> List[str]:
        """
        Expand wildcard event log sources to actual log names.

        Args:
            wildcard_source: Source pattern with wildcards (e.g., "Microsoft-Windows-*")

        Returns:
            List of actual event log source names matching the pattern
        """
        expanded_sources = []

        try:
            # Get all available sources
            all_sources = self.get_available_sources()

            # Convert wildcard pattern to regex
            import re
            pattern = wildcard_source.replace('*', '.*').replace('?', '.')
            regex = re.compile(pattern, re.IGNORECASE)

            # Find matching sources
            for source in all_sources:
                if regex.match(source):
                    expanded_sources.append(source)

            if not expanded_sources:
                self.logger.warning(f"No event logs found matching pattern: {wildcard_source}")
            else:
                self.logger.debug(f"Expanded {wildcard_source} to {len(expanded_sources)} sources")

        except Exception as e:
            self.logger.error(f"Error expanding wildcard source {wildcard_source}: {e}")

        return expanded_sources

    def _check_security_privilege(self) -> bool:
        """
        Check if the current process has privileges to access Security event logs.

        Returns:
            True if Security log access is available, False otherwise
        """
        try:
            # Try to open the Security log to test access
            handle = win32evtlog.OpenEventLog(self.server, 'Security')
            win32evtlog.CloseEventLog(handle)
            return True
        except Exception as e:
            # Check if it's a privilege error
            if "1314" in str(e) or "privilege" in str(e).lower():
                return False
            # For other errors, assume no access
            return False


# Import win32evtlogutil if available
try:
    import win32evtlogutil
except ImportError:
    # Create a minimal replacement if not available
    class win32evtlogutil:
        @staticmethod
        def SafeFormatMessage(event, source):
            return None
