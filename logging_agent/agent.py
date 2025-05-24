"""
Main Logging Agent

This module contains the main LoggingAgent class that coordinates
all log collection activities and manages the overall agent lifecycle.
"""

import logging
import threading
import time
import signal
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

from config.config_manager import ConfigManager
from utils.logger import LoggerSetup, PerformanceLogger, AuditLogger
from utils.buffer import TimedBuffer
from .collectors.event_log_collector import EventLogCollector
from .collectors.security_log_collector import SecurityLogCollector
from .collectors.application_log_collector import ApplicationLogCollector
from .collectors.system_log_collector import SystemLogCollector
from .collectors.network_log_collector import NetworkLogCollector
from .collectors.packet_collector import create_packet_collector


class LoggingAgent:
    """Main logging agent that coordinates all log collection activities."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Logging Agent.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = ConfigManager(config_path)
        self.config = {}
        self.logger = None
        self.performance_logger = None
        self.audit_logger = None
        
        # Collectors
        self.collectors = {}
        
        # Threading and control
        self._running = False
        self._collection_thread = None
        self._stop_event = threading.Event()
        
        # Buffer for collected logs
        self._log_buffer = None
        
        # Statistics
        self.stats = {
            'start_time': None,
            'logs_collected': 0,
            'logs_processed': 0,
            'errors': 0,
            'last_collection': None
        }
        
        # Initialize the agent
        self._initialize()
        
    def _initialize(self) -> None:
        """Initialize the agent with configuration and logging."""
        try:
            # Load configuration
            self.config = self.config_manager.load_config()
            
            # Set up logging
            self._setup_logging()
            
            # Set up audit logging
            error_log_path = self.config.get('error_handling', {}).get(
                'error_log_path', 'logs/agent_errors.log'
            )
            self.audit_logger = AuditLogger('logs/audit.log')
            
            # Set up performance monitoring
            self.performance_logger = PerformanceLogger(self.logger)
            
            # Initialize log buffer
            self._setup_buffer()
            
            # Initialize collectors
            self._initialize_collectors()
            
            # Set up signal handlers
            self._setup_signal_handlers()
            
            self.logger.info("Logging Agent initialized successfully")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error initializing agent: {e}")
            else:
                print(f"Error initializing agent: {e}")
            raise
            
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        general_config = self.config.get('general', {})
        error_config = self.config.get('error_handling', {})
        
        log_level = general_config.get('log_level', 'INFO')
        error_log_path = error_config.get('error_log_path', 'logs/agent_errors.log')
        
        # Set up main logger
        self.logger = LoggerSetup.setup_logging(
            log_level=log_level,
            log_file='logs/agent.log',
            console_output=True
        )
        
        # Set up error logger
        LoggerSetup.setup_error_logging(error_log_path)
        
    def _setup_buffer(self) -> None:
        """Set up the log buffer with configuration."""
        general_config = self.config.get('general', {})
        buffer_size = general_config.get('buffer_size', 1000)
        processing_interval = general_config.get('processing_interval', 5)
        
        # Create timed buffer that automatically processes logs
        self._log_buffer = TimedBuffer(
            max_size=buffer_size,
            flush_interval=processing_interval,
            flush_handler=self._process_buffered_logs
        )
        
    def _initialize_collectors(self) -> None:
        """Initialize all configured log collectors."""
        collection_config = self.config.get('collection', {})
        
        try:
            # Event Log Collector
            if collection_config.get('event_logs', {}).get('enabled', False):
                self.collectors['event_logs'] = EventLogCollector(
                    collection_config['event_logs']
                )
                self.logger.info("Event Log Collector initialized")
                
            # Security Log Collector
            if collection_config.get('security_logs', {}).get('enabled', False):
                self.collectors['security_logs'] = SecurityLogCollector(
                    collection_config['security_logs']
                )
                self.logger.info("Security Log Collector initialized")
                
            # Application Log Collector
            if collection_config.get('application_logs', {}).get('enabled', False):
                self.collectors['application_logs'] = ApplicationLogCollector(
                    collection_config['application_logs']
                )
                self.logger.info("Application Log Collector initialized")
                
            # System Log Collector
            if collection_config.get('system_logs', {}).get('enabled', False):
                self.collectors['system_logs'] = SystemLogCollector(
                    collection_config['system_logs']
                )
                self.logger.info("System Log Collector initialized")
                
            # Network Log Collector
            if collection_config.get('network_logs', {}).get('enabled', False):
                self.collectors['network_logs'] = NetworkLogCollector(
                    collection_config['network_logs']
                )
                self.logger.info("Network Log Collector initialized")
                
            # Packet Collector
            if collection_config.get('packet_capture', {}).get('enabled', False):
                self.collectors['packet_capture'] = create_packet_collector(
                    collection_config['packet_capture']
                )
                self.logger.info("Packet Collector initialized")
                
        except Exception as e:
            self.logger.error(f"Error initializing collectors: {e}")
            raise
            
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down...")
            self.stop()
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    def start(self) -> bool:
        """
        Start the logging agent.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self._running:
            self.logger.warning("Agent is already running")
            return True
            
        try:
            self._running = True
            self._stop_event.clear()
            self.stats['start_time'] = datetime.now()
            
            # Start packet capture if enabled
            packet_collector = self.collectors.get('packet_capture')
            if packet_collector:
                packet_collector.start_capture()
                
            # Start main collection thread
            self._collection_thread = threading.Thread(
                target=self._collection_loop,
                daemon=True
            )
            self._collection_thread.start()
            
            self.logger.info("Logging Agent started successfully")
            self.audit_logger.log_service_start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting agent: {e}")
            self._running = False
            return False
            
    def stop(self) -> None:
        """Stop the logging agent."""
        if not self._running:
            self.logger.info("Agent is not running")
            return
            
        try:
            self.logger.info("Stopping Logging Agent...")
            
            # Signal stop
            self._running = False
            self._stop_event.set()
            
            # Stop packet capture
            packet_collector = self.collectors.get('packet_capture')
            if packet_collector:
                packet_collector.stop_capture()
                
            # Wait for collection thread to finish
            if self._collection_thread and self._collection_thread.is_alive():
                self._collection_thread.join(timeout=10)
                
            # Process any remaining buffered logs
            if self._log_buffer:
                self._log_buffer.manual_flush()
                self._log_buffer.stop()
                
            self.logger.info("Logging Agent stopped successfully")
            self.audit_logger.log_service_stop()
            
        except Exception as e:
            self.logger.error(f"Error stopping agent: {e}")
            
    def _collection_loop(self) -> None:
        """Main collection loop that runs in a separate thread."""
        processing_interval = self.config.get('general', {}).get('processing_interval', 5)
        
        while self._running and not self._stop_event.is_set():
            try:
                start_time = time.time()
                
                # Collect logs from all enabled collectors
                self._collect_all_logs()
                
                # Update statistics
                self.stats['last_collection'] = datetime.now()
                
                # Performance monitoring
                self.performance_logger.log_memory_usage("LoggingAgent")
                
                # Calculate sleep time
                elapsed = time.time() - start_time
                sleep_time = max(0, processing_interval - elapsed)
                
                # Wait for next collection cycle or stop signal
                if sleep_time > 0:
                    self._stop_event.wait(sleep_time)
                    
            except Exception as e:
                self.logger.error(f"Error in collection loop: {e}")
                self.stats['errors'] += 1
                
                # Wait before retrying
                self._stop_event.wait(5)
                
    def _collect_all_logs(self) -> None:
        """Collect logs from all enabled collectors."""
        total_collected = 0
        
        for collector_name, collector in self.collectors.items():
            try:
                logs = collector.collect_logs()
                
                if logs:
                    # Add logs to buffer
                    for log in logs:
                        self._log_buffer.add(log)
                        
                    total_collected += len(logs)
                    self.logger.debug(
                        f"Collected {len(logs)} logs from {collector_name}"
                    )
                    
            except Exception as e:
                self.logger.error(f"Error collecting from {collector_name}: {e}")
                self.stats['errors'] += 1
                
        if total_collected > 0:
            self.stats['logs_collected'] += total_collected
            self.logger.debug(f"Total logs collected this cycle: {total_collected}")
            
    def _process_buffered_logs(self, logs: List[Dict[str, Any]]) -> None:
        """
        Process buffered logs (called by TimedBuffer).
        
        Args:
            logs: List of log entries to process
        """
        try:
            if not logs:
                return
                
            # Import here to avoid circular imports
            from log_standardizer.standardizer import LogStandardizer
            
            # Create standardizer
            standardizer = LogStandardizer(self.config.get('standardization', {}))
            
            # Standardize logs
            standardized_logs = []
            for log in logs:
                try:
                    standardized_log = standardizer.standardize_log(log)
                    if standardized_log:
                        standardized_logs.append(standardized_log)
                except Exception as e:
                    self.logger.error(f"Error standardizing log: {e}")
                    
            # Output standardized logs
            if standardized_logs:
                self._output_logs(standardized_logs)
                self.stats['logs_processed'] += len(standardized_logs)
                
        except Exception as e:
            self.logger.error(f"Error processing buffered logs: {e}")
            
    def _output_logs(self, logs: List[Dict[str, Any]]) -> None:
        """
        Output logs to configured destinations.
        
        Args:
            logs: List of standardized log entries
        """
        output_config = self.config.get('output', {})
        
        try:
            # File output
            if output_config.get('file', {}).get('enabled', False):
                self._output_to_file(logs, output_config['file'])
                
            # Console output
            if output_config.get('console', {}).get('enabled', False):
                self._output_to_console(logs)
                
        except Exception as e:
            self.logger.error(f"Error outputting logs: {e}")
            
    def _output_to_file(self, logs: List[Dict[str, Any]], file_config: Dict[str, Any]) -> None:
        """Output logs to file."""
        import json
        from pathlib import Path
        
        file_path = file_config.get('path', 'logs/standardized_logs.json')
        
        # Create directory if it doesn't exist
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Append logs to file
        with open(file_path, 'a', encoding='utf-8') as f:
            for log in logs:
                f.write(json.dumps(log, ensure_ascii=False) + '\n')
                
    def _output_to_console(self, logs: List[Dict[str, Any]]) -> None:
        """Output logs to console."""
        import json
        
        for log in logs:
            print(json.dumps(log, ensure_ascii=False, indent=2))
            
    def get_status(self) -> Dict[str, Any]:
        """
        Get current agent status.
        
        Returns:
            Dictionary containing agent status information
        """
        status = {
            'running': self._running,
            'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
            'uptime_seconds': None,
            'collectors': {},
            'statistics': self.stats.copy(),
            'buffer_size': self._log_buffer.size() if self._log_buffer else 0,
            'configuration': {
                'log_level': self.config.get('general', {}).get('log_level'),
                'processing_interval': self.config.get('general', {}).get('processing_interval'),
                'enabled_collectors': list(self.collectors.keys())
            }
        }
        
        # Calculate uptime
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            status['uptime_seconds'] = int(uptime.total_seconds())
            
        # Get collector status
        for name, collector in self.collectors.items():
            try:
                if hasattr(collector, 'get_capture_stats'):
                    status['collectors'][name] = collector.get_capture_stats()
                elif hasattr(collector, 'test_access'):
                    status['collectors'][name] = collector.test_access()
                else:
                    status['collectors'][name] = {'status': 'active'}
            except Exception as e:
                status['collectors'][name] = {'status': 'error', 'error': str(e)}
                
        return status
        
    def reload_config(self) -> bool:
        """
        Reload configuration from file.
        
        Returns:
            True if reload was successful, False otherwise
        """
        try:
            old_config = self.config.copy()
            self.config = self.config_manager.reload_config()
            
            self.logger.info("Configuration reloaded successfully")
            self.audit_logger.log_config_change(self.config_manager.config_path)
            
            # Note: Full reconfiguration would require stopping and restarting
            # For now, just log the change
            self.logger.warning("Configuration changed - restart required for full effect")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error reloading configuration: {e}")
            return False
