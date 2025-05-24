"""
Logging utilities for Python Logging Agent

This module provides centralized logging configuration and utilities
for the entire logging agent system.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional
import colorlog


class LoggerSetup:
    """Handles logging configuration for the application."""
    
    @staticmethod
    def setup_logging(
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        console_output: bool = True,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5
    ) -> logging.Logger:
        """
        Set up logging configuration for the application.
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file. If None, only console logging is used.
            console_output: Whether to output logs to console
            max_file_size: Maximum size of log file before rotation
            backup_count: Number of backup files to keep
            
        Returns:
            Configured logger instance
        """
        # Convert string level to logging constant
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Create logger
        logger = logging.getLogger()
        logger.setLevel(numeric_level)
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        
        # Add console handler if requested
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(numeric_level)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        # Add file handler if log file is specified
        if log_file:
            # Create log directory if it doesn't exist
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    @staticmethod
    def setup_error_logging(error_log_path: str) -> logging.Logger:
        """
        Set up separate error logging for the application.
        
        Args:
            error_log_path: Path to the error log file
            
        Returns:
            Error logger instance
        """
        error_logger = logging.getLogger('error_logger')
        error_logger.setLevel(logging.ERROR)
        
        # Create error log directory if it doesn't exist
        error_log_dir = Path(error_log_path).parent
        error_log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create error file handler
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_path,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        
        error_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s\n'
            'Exception: %(exc_info)s\n',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        error_handler.setFormatter(error_formatter)
        error_logger.addHandler(error_handler)
        
        return error_logger
    
    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """
        Get a logger instance with the specified name.
        
        Args:
            name: Logger name (typically __name__)
            
        Returns:
            Logger instance
        """
        return logging.getLogger(name)


class PerformanceLogger:
    """Utility class for performance monitoring and logging."""
    
    def __init__(self, logger: logging.Logger):
        """
        Initialize performance logger.
        
        Args:
            logger: Logger instance to use for performance logs
        """
        self.logger = logger
        
    def log_memory_usage(self, component: str) -> None:
        """
        Log current memory usage for a component.
        
        Args:
            component: Name of the component being monitored
        """
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            self.logger.debug(
                f"Memory usage for {component}: {memory_mb:.2f} MB"
            )
        except ImportError:
            self.logger.warning("psutil not available for memory monitoring")
        except Exception as e:
            self.logger.error(f"Error monitoring memory usage: {e}")
            
    def log_cpu_usage(self, component: str) -> None:
        """
        Log current CPU usage for a component.
        
        Args:
            component: Name of the component being monitored
        """
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            
            self.logger.debug(
                f"CPU usage for {component}: {cpu_percent:.2f}%"
            )
        except ImportError:
            self.logger.warning("psutil not available for CPU monitoring")
        except Exception as e:
            self.logger.error(f"Error monitoring CPU usage: {e}")


class AuditLogger:
    """Utility class for audit logging of important events."""
    
    def __init__(self, audit_log_path: str):
        """
        Initialize audit logger.
        
        Args:
            audit_log_path: Path to the audit log file
        """
        self.audit_logger = logging.getLogger('audit_logger')
        self.audit_logger.setLevel(logging.INFO)
        
        # Create audit log directory if it doesn't exist
        audit_log_dir = Path(audit_log_path).parent
        audit_log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create audit file handler
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        
    def log_service_start(self) -> None:
        """Log service start event."""
        self.audit_logger.info("Python Logging Agent service started")
        
    def log_service_stop(self) -> None:
        """Log service stop event."""
        self.audit_logger.info("Python Logging Agent service stopped")
        
    def log_config_change(self, config_path: str) -> None:
        """Log configuration change event."""
        self.audit_logger.info(f"Configuration changed: {config_path}")
        
    def log_error_recovery(self, error_type: str, component: str) -> None:
        """Log error recovery event."""
        self.audit_logger.info(
            f"Error recovery successful - Type: {error_type}, Component: {component}"
        )
