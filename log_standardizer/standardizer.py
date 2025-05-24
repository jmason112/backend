"""
Log Standardizer

This module provides the main LogStandardizer class that converts
raw logs from various sources into a standardized JSON format.
"""

import logging
import json
import socket
from typing import Dict, Any, Optional, List
from datetime import datetime
import copy


class LogStandardizer:
    """Standardizes logs from various sources into a consistent JSON format."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Log Standardizer.
        
        Args:
            config: Configuration dictionary for standardization
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration options
        self.output_format = config.get('output_format', 'json')
        self.include_raw_data = config.get('include_raw_data', False)
        self.timestamp_format = config.get('timestamp_format', 'iso8601')
        self.add_hostname = config.get('add_hostname', True)
        self.add_source_metadata = config.get('add_source_metadata', True)
        
        # Get hostname once
        self.hostname = socket.gethostname() if self.add_hostname else None
        
        # Standard schema template
        self.standard_schema = {
            'timestamp': None,
            'source': None,
            'source_type': None,
            'host': self.hostname,
            'log_level': 'info',
            'message': None,
            'raw_data': None,
            'additional_fields': {}
        }
        
    def standardize_log(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Standardize a raw log entry into the standard format.
        
        Args:
            raw_log: Raw log entry from a collector
            
        Returns:
            Standardized log entry or None if standardization fails
        """
        try:
            # Create a copy of the standard schema
            standardized_log = copy.deepcopy(self.standard_schema)
            
            # Map fields from raw log to standardized format
            self._map_standard_fields(raw_log, standardized_log)
            
            # Add metadata if configured
            if self.add_source_metadata:
                self._add_source_metadata(raw_log, standardized_log)
                
            # Include raw data if configured
            if self.include_raw_data:
                standardized_log['raw_data'] = copy.deepcopy(raw_log)
                
            # Validate the standardized log
            if self._validate_log(standardized_log):
                return standardized_log
            else:
                self.logger.warning("Log validation failed")
                return None
                
        except Exception as e:
            self.logger.error(f"Error standardizing log: {e}")
            return None
            
    def _map_standard_fields(self, raw_log: Dict[str, Any], standardized_log: Dict[str, Any]) -> None:
        """
        Map fields from raw log to standardized format.
        
        Args:
            raw_log: Raw log entry
            standardized_log: Standardized log entry to populate
        """
        # Timestamp
        timestamp = raw_log.get('timestamp')
        if timestamp:
            standardized_log['timestamp'] = self._normalize_timestamp(timestamp)
        else:
            standardized_log['timestamp'] = datetime.now().isoformat()
            
        # Source information
        standardized_log['source'] = raw_log.get('source', 'unknown')
        standardized_log['source_type'] = raw_log.get('source_type', 'unknown')
        
        # Host information
        if self.add_hostname:
            standardized_log['host'] = raw_log.get('host', self.hostname)
            
        # Log level
        log_level = raw_log.get('log_level', 'info')
        standardized_log['log_level'] = self._normalize_log_level(log_level)
        
        # Message
        standardized_log['message'] = raw_log.get('message', '')
        
        # Additional fields
        additional_fields = raw_log.get('additional_fields', {})
        if additional_fields:
            standardized_log['additional_fields'] = copy.deepcopy(additional_fields)
            
        # Copy other relevant fields
        for field in ['event_id', 'event_category', 'event_type', 'event_description']:
            if field in raw_log:
                standardized_log['additional_fields'][field] = raw_log[field]
                
    def _add_source_metadata(self, raw_log: Dict[str, Any], standardized_log: Dict[str, Any]) -> None:
        """
        Add source metadata to the standardized log.
        
        Args:
            raw_log: Raw log entry
            standardized_log: Standardized log entry to populate
        """
        metadata = {
            'collection_time': datetime.now().isoformat(),
            'agent_version': '1.0.0',  # Could be made configurable
            'standardizer_version': '1.0.0'
        }
        
        # Add source-specific metadata
        source_type = raw_log.get('source_type', 'unknown')
        
        if source_type == 'event':
            metadata['windows_event_log'] = True
            metadata['event_log_source'] = raw_log.get('source')
        elif source_type == 'security':
            metadata['security_log'] = True
            metadata['security_category'] = raw_log.get('security_category')
        elif source_type == 'application':
            metadata['application_log'] = True
            metadata['application_category'] = raw_log.get('application_category')
        elif source_type == 'system':
            metadata['system_log'] = True
            metadata['system_category'] = raw_log.get('system_category')
        elif source_type == 'network':
            metadata['network_log'] = True
            metadata['network_source'] = raw_log.get('source')
            
        standardized_log['additional_fields']['metadata'] = metadata
        
    def _normalize_timestamp(self, timestamp: str) -> str:
        """
        Normalize timestamp to the configured format.
        
        Args:
            timestamp: Input timestamp string
            
        Returns:
            Normalized timestamp string
        """
        try:
            # Try to parse the timestamp
            if isinstance(timestamp, str):
                # Handle various timestamp formats
                for fmt in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', 
                           '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    # If no format matches, try ISO format parsing
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                # Assume it's already a datetime object
                dt = timestamp
                
            # Return in ISO 8601 format
            if self.timestamp_format == 'iso8601':
                return dt.isoformat()
            else:
                # Could add other formats here
                return dt.isoformat()
                
        except Exception as e:
            self.logger.warning(f"Error normalizing timestamp '{timestamp}': {e}")
            return datetime.now().isoformat()
            
    def _normalize_log_level(self, log_level: str) -> str:
        """
        Normalize log level to standard values.
        
        Args:
            log_level: Input log level
            
        Returns:
            Normalized log level
        """
        if not log_level:
            return 'info'
            
        level = log_level.lower().strip()
        
        # Map various level names to standard levels
        level_mapping = {
            'debug': 'debug',
            'info': 'info',
            'information': 'info',
            'warn': 'warning',
            'warning': 'warning',
            'error': 'error',
            'err': 'error',
            'critical': 'critical',
            'crit': 'critical',
            'fatal': 'critical',
            'emergency': 'critical',
            'alert': 'critical'
        }
        
        return level_mapping.get(level, 'info')
        
    def _validate_log(self, log: Dict[str, Any]) -> bool:
        """
        Validate that a log entry meets the standard schema requirements.
        
        Args:
            log: Log entry to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['timestamp', 'source', 'source_type', 'log_level', 'message']
        
        for field in required_fields:
            if field not in log or log[field] is None:
                self.logger.warning(f"Missing required field: {field}")
                return False
                
        # Validate timestamp format
        try:
            datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            self.logger.warning(f"Invalid timestamp format: {log['timestamp']}")
            return False
            
        # Validate log level
        valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
        if log['log_level'] not in valid_levels:
            self.logger.warning(f"Invalid log level: {log['log_level']}")
            return False
            
        return True
        
    def standardize_batch(self, raw_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Standardize a batch of raw log entries.
        
        Args:
            raw_logs: List of raw log entries
            
        Returns:
            List of standardized log entries
        """
        standardized_logs = []
        
        for raw_log in raw_logs:
            try:
                standardized_log = self.standardize_log(raw_log)
                if standardized_log:
                    standardized_logs.append(standardized_log)
            except Exception as e:
                self.logger.error(f"Error standardizing log in batch: {e}")
                
        return standardized_logs
        
    def get_schema(self) -> Dict[str, Any]:
        """
        Get the current standardization schema.
        
        Returns:
            Dictionary representing the schema
        """
        return {
            'version': '1.0.0',
            'format': self.output_format,
            'fields': {
                'timestamp': {
                    'type': 'string',
                    'format': 'iso8601',
                    'required': True,
                    'description': 'Log entry timestamp in ISO 8601 format'
                },
                'source': {
                    'type': 'string',
                    'required': True,
                    'description': 'Log source identifier'
                },
                'source_type': {
                    'type': 'string',
                    'required': True,
                    'enum': ['event', 'security', 'application', 'system', 'network'],
                    'description': 'Type of log source'
                },
                'host': {
                    'type': 'string',
                    'required': False,
                    'description': 'Hostname where the log was generated'
                },
                'log_level': {
                    'type': 'string',
                    'required': True,
                    'enum': ['debug', 'info', 'warning', 'error', 'critical'],
                    'description': 'Log severity level'
                },
                'message': {
                    'type': 'string',
                    'required': True,
                    'description': 'Log message content'
                },
                'raw_data': {
                    'type': 'object',
                    'required': False,
                    'description': 'Original raw log data (if enabled)'
                },
                'additional_fields': {
                    'type': 'object',
                    'required': False,
                    'description': 'Source-specific additional fields'
                }
            }
        }
        
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get standardization statistics.
        
        Returns:
            Dictionary containing statistics
        """
        # This would be enhanced with actual statistics tracking
        return {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'validation_errors': 0,
            'schema_version': '1.0.0'
        }
