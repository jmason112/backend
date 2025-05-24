"""
Configuration Manager for Python Logging Agent

This module handles loading and managing configuration settings
from YAML files with validation and default value support.
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """Manages configuration loading and validation for the logging agent."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses default.
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        current_dir = Path(__file__).parent
        return str(current_dir / "default_config.yaml")
        
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from the YAML file.
        
        Returns:
            Dictionary containing the configuration settings.
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        try:
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self.config = yaml.safe_load(file)
                
            self._validate_config()
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return self.config
            
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_path}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML configuration: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error loading configuration: {e}")
            raise
            
    def _validate_config(self) -> None:
        """Validate the loaded configuration."""
        required_sections = ['general', 'collection', 'standardization', 'output']
        
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")
                
        # Validate general settings
        general = self.config.get('general', {})
        if 'service_name' not in general:
            raise ValueError("Missing required setting: general.service_name")
            
        # Validate log levels
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = general.get('log_level', 'INFO')
        if log_level not in valid_log_levels:
            raise ValueError(f"Invalid log level: {log_level}")
            
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation (e.g., 'general.log_level')
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        config_ref = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]
            
        # Set the value
        config_ref[keys[-1]] = value
        
    def save_config(self, path: Optional[str] = None) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            path: Path to save the configuration. If None, uses current config_path.
        """
        save_path = path or self.config_path
        
        try:
            with open(save_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, indent=2)
            self.logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            raise
            
    def reload_config(self) -> Dict[str, Any]:
        """
        Reload configuration from the file.
        
        Returns:
            Updated configuration dictionary
        """
        return self.load_config()
        
    def get_log_sources(self) -> Dict[str, bool]:
        """
        Get enabled log sources from configuration.
        
        Returns:
            Dictionary mapping log source names to their enabled status
        """
        collection = self.config.get('collection', {})
        sources = {}
        
        for source_type in ['event_logs', 'security_logs', 'application_logs', 
                           'system_logs', 'network_logs', 'packet_capture']:
            source_config = collection.get(source_type, {})
            sources[source_type] = source_config.get('enabled', False)
            
        return sources
        
    def get_output_config(self) -> Dict[str, Any]:
        """
        Get output configuration settings.
        
        Returns:
            Dictionary containing output configuration
        """
        return self.config.get('output', {})
        
    def get_performance_config(self) -> Dict[str, Any]:
        """
        Get performance configuration settings.
        
        Returns:
            Dictionary containing performance configuration
        """
        return self.config.get('performance', {})
