"""
Unit tests for log standardization.
"""

import unittest
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from log_standardizer.standardizer import LogStandardizer


class TestLogStandardizer(unittest.TestCase):
    """Test cases for LogStandardizer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'output_format': 'json',
            'include_raw_data': False,
            'timestamp_format': 'iso8601',
            'add_hostname': True,
            'add_source_metadata': True
        }
        self.standardizer = LogStandardizer(self.config)

    def test_standardize_event_log(self):
        """Test standardizing an event log entry."""
        raw_log = {
            'timestamp': '2024-01-15T10:30:00',
            'source': 'System',
            'source_type': 'event',
            'host': 'TEST-PC',
            'log_level': 'info',
            'message': 'System startup completed',
            'event_id': 6005,
            'additional_fields': {
                'record_number': 12345,
                'computer_name': 'TEST-PC'
            }
        }

        standardized = self.standardizer.standardize_log(raw_log)

        self.assertIsNotNone(standardized)
        self.assertEqual(standardized['source'], 'System')
        self.assertEqual(standardized['source_type'], 'event')
        self.assertEqual(standardized['log_level'], 'info')
        self.assertEqual(standardized['message'], 'System startup completed')
        self.assertIn('metadata', standardized['additional_fields'])

    def test_standardize_security_log(self):
        """Test standardizing a security log entry."""
        raw_log = {
            'timestamp': '2024-01-15T10:30:00',
            'source': 'Security',
            'source_type': 'security',
            'host': 'TEST-PC',
            'log_level': 'warning',
            'message': 'Failed logon attempt',
            'event_id': 4625,
            'security_category': 'authentication',
            'additional_fields': {
                'target_user_name': 'testuser',
                'logon_type': '3'
            }
        }

        standardized = self.standardizer.standardize_log(raw_log)

        self.assertIsNotNone(standardized)
        self.assertEqual(standardized['source_type'], 'security')
        self.assertEqual(standardized['log_level'], 'warning')
        # Security category is stored in metadata
        self.assertIn('metadata', standardized['additional_fields'])
        self.assertEqual(standardized['additional_fields']['metadata']['security_category'], 'authentication')

    def test_normalize_timestamp(self):
        """Test timestamp normalization."""
        # Test various timestamp formats
        timestamps = [
            '2024-01-15T10:30:00',
            '2024-01-15 10:30:00',
            '2024-01-15T10:30:00.123456',
            '2024-01-15T10:30:00Z'
        ]

        for ts in timestamps:
            normalized = self.standardizer._normalize_timestamp(ts)
            self.assertIsInstance(normalized, str)
            # Should be able to parse back to datetime
            datetime.fromisoformat(normalized.replace('Z', '+00:00'))

    def test_normalize_log_level(self):
        """Test log level normalization."""
        test_cases = [
            ('DEBUG', 'debug'),
            ('Info', 'info'),
            ('WARN', 'warning'),
            ('ERROR', 'error'),
            ('CRITICAL', 'critical'),
            ('unknown', 'info')  # Default case
        ]

        for input_level, expected in test_cases:
            normalized = self.standardizer._normalize_log_level(input_level)
            self.assertEqual(normalized, expected)

    def test_validate_log(self):
        """Test log validation."""
        # Valid log
        valid_log = {
            'timestamp': '2024-01-15T10:30:00',
            'source': 'System',
            'source_type': 'event',
            'log_level': 'info',
            'message': 'Test message',
            'additional_fields': {}
        }

        self.assertTrue(self.standardizer._validate_log(valid_log))

        # Invalid log - missing required field
        invalid_log = {
            'timestamp': '2024-01-15T10:30:00',
            'source': 'System',
            # Missing source_type
            'log_level': 'info',
            'message': 'Test message'
        }

        self.assertFalse(self.standardizer._validate_log(invalid_log))

        # Invalid log - bad timestamp
        invalid_timestamp_log = {
            'timestamp': 'invalid-timestamp',
            'source': 'System',
            'source_type': 'event',
            'log_level': 'info',
            'message': 'Test message'
        }

        self.assertFalse(self.standardizer._validate_log(invalid_timestamp_log))

    def test_standardize_batch(self):
        """Test batch standardization."""
        raw_logs = [
            {
                'timestamp': '2024-01-15T10:30:00',
                'source': 'System',
                'source_type': 'event',
                'log_level': 'info',
                'message': 'Message 1'
            },
            {
                'timestamp': '2024-01-15T10:31:00',
                'source': 'Application',
                'source_type': 'application',
                'log_level': 'error',
                'message': 'Message 2'
            }
        ]

        standardized_logs = self.standardizer.standardize_batch(raw_logs)

        self.assertEqual(len(standardized_logs), 2)
        self.assertEqual(standardized_logs[0]['source'], 'System')
        self.assertEqual(standardized_logs[1]['source'], 'Application')

    def test_include_raw_data(self):
        """Test including raw data in standardized logs."""
        config_with_raw = self.config.copy()
        config_with_raw['include_raw_data'] = True

        standardizer = LogStandardizer(config_with_raw)

        raw_log = {
            'timestamp': '2024-01-15T10:30:00',
            'source': 'System',
            'source_type': 'event',
            'log_level': 'info',
            'message': 'Test message'
        }

        standardized = standardizer.standardize_log(raw_log)

        self.assertIsNotNone(standardized['raw_data'])
        self.assertEqual(standardized['raw_data'], raw_log)

    def test_get_schema(self):
        """Test getting the standardization schema."""
        schema = self.standardizer.get_schema()

        self.assertIn('version', schema)
        self.assertIn('fields', schema)
        self.assertIn('timestamp', schema['fields'])
        self.assertIn('source', schema['fields'])
        self.assertIn('message', schema['fields'])


if __name__ == '__main__':
    unittest.main()
