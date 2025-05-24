"""
Unit tests for configuration management.
"""

import unittest
import tempfile
import os
import yaml
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import ConfigManager


class TestConfigManager(unittest.TestCase):
    """Test cases for ConfigManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_config = {
            'general': {
                'service_name': 'TestService',
                'log_level': 'INFO',
                'buffer_size': 1000,
                'processing_interval': 5
            },
            'collection': {
                'event_logs': {
                    'enabled': True,
                    'sources': ['System', 'Application']
                }
            },
            'standardization': {
                'output_format': 'json',
                'include_raw_data': False
            },
            'output': {
                'file': {
                    'enabled': True,
                    'path': 'logs/test.json'
                }
            }
        }
        
    def test_load_valid_config(self):
        """Test loading a valid configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.test_config, f)
            config_path = f.name
            
        try:
            config_manager = ConfigManager(config_path)
            loaded_config = config_manager.load_config()
            
            self.assertEqual(loaded_config['general']['service_name'], 'TestService')
            self.assertEqual(loaded_config['general']['log_level'], 'INFO')
            
        finally:
            os.unlink(config_path)
            
    def test_get_config_value(self):
        """Test getting configuration values using dot notation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.test_config, f)
            config_path = f.name
            
        try:
            config_manager = ConfigManager(config_path)
            config_manager.load_config()
            
            # Test getting nested values
            self.assertEqual(config_manager.get('general.service_name'), 'TestService')
            self.assertEqual(config_manager.get('general.buffer_size'), 1000)
            self.assertEqual(config_manager.get('collection.event_logs.enabled'), True)
            
            # Test default values
            self.assertEqual(config_manager.get('nonexistent.key', 'default'), 'default')
            
        finally:
            os.unlink(config_path)
            
    def test_set_config_value(self):
        """Test setting configuration values using dot notation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.test_config, f)
            config_path = f.name
            
        try:
            config_manager = ConfigManager(config_path)
            config_manager.load_config()
            
            # Test setting existing value
            config_manager.set('general.log_level', 'DEBUG')
            self.assertEqual(config_manager.get('general.log_level'), 'DEBUG')
            
            # Test setting new nested value
            config_manager.set('new.nested.value', 'test')
            self.assertEqual(config_manager.get('new.nested.value'), 'test')
            
        finally:
            os.unlink(config_path)
            
    def test_get_log_sources(self):
        """Test getting enabled log sources."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.test_config, f)
            config_path = f.name
            
        try:
            config_manager = ConfigManager(config_path)
            config_manager.load_config()
            
            sources = config_manager.get_log_sources()
            
            self.assertTrue(sources['event_logs'])
            self.assertFalse(sources.get('security_logs', False))
            
        finally:
            os.unlink(config_path)
            
    def test_invalid_config_file(self):
        """Test handling of invalid configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name
            
        try:
            config_manager = ConfigManager(config_path)
            
            with self.assertRaises(yaml.YAMLError):
                config_manager.load_config()
                
        finally:
            os.unlink(config_path)
            
    def test_missing_config_file(self):
        """Test handling of missing configuration file."""
        config_manager = ConfigManager('nonexistent_config.yaml')
        
        with self.assertRaises(FileNotFoundError):
            config_manager.load_config()


if __name__ == '__main__':
    unittest.main()
