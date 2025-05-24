#!/usr/bin/env python3
"""
Python Logging Agent - Main Entry Point

This is the main entry point for the Python Logging Agent system.
It provides command-line interface for running the agent in various modes.
"""

import sys
import os
import argparse
import signal
import time
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from logging_agent.agent import LoggingAgent
from service.windows_service import (
    install_service, remove_service, start_service, stop_service,
    get_service_status, run_service_debug, PYWIN32_AVAILABLE
)
from config.config_manager import ConfigManager
from utils.logger import LoggerSetup


def run_console_mode(config_path=None):
    """
    Run the agent in console mode for testing and development.
    
    Args:
        config_path: Path to configuration file
    """
    print("Python Logging Agent - Console Mode")
    print("=" * 50)
    
    try:
        # Initialize the agent
        print("Initializing logging agent...")
        agent = LoggingAgent(config_path)
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            print(f"\nReceived signal {signum}, shutting down...")
            agent.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start the agent
        print("Starting logging agent...")
        if agent.start():
            print("Logging agent started successfully!")
            print("Press Ctrl+C to stop the agent")
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(1)
                    
                    # Print status every 60 seconds
                    if int(time.time()) % 60 == 0:
                        status = agent.get_status()
                        print(f"Status: Running | Logs collected: {status['statistics']['logs_collected']} | "
                              f"Logs processed: {status['statistics']['logs_processed']} | "
                              f"Buffer size: {status['buffer_size']}")
                        
            except KeyboardInterrupt:
                print("\nShutdown requested by user")
                
        else:
            print("Failed to start logging agent")
            return 1
            
    except Exception as e:
        print(f"Error running agent: {e}")
        return 1
    finally:
        print("Logging agent stopped")
        
    return 0


def run_test_mode(config_path=None):
    """
    Run the agent in test mode to verify configuration and collectors.
    
    Args:
        config_path: Path to configuration file
    """
    print("Python Logging Agent - Test Mode")
    print("=" * 50)
    
    try:
        # Test configuration loading
        print("Testing configuration...")
        config_manager = ConfigManager(config_path)
        config = config_manager.load_config()
        print("✓ Configuration loaded successfully")
        
        # Initialize the agent
        print("Testing agent initialization...")
        agent = LoggingAgent(config_path)
        print("✓ Agent initialized successfully")
        
        # Test collectors
        print("Testing collectors...")
        status = agent.get_status()
        
        for collector_name, collector_status in status['collectors'].items():
            if 'error' in collector_status:
                print(f"✗ {collector_name}: {collector_status['error']}")
            else:
                print(f"✓ {collector_name}: OK")
                
        # Test log collection (brief)
        print("Testing log collection...")
        if agent.start():
            time.sleep(5)  # Collect for 5 seconds
            agent.stop()
            
            final_status = agent.get_status()
            logs_collected = final_status['statistics']['logs_collected']
            print(f"✓ Collected {logs_collected} logs in test run")
        else:
            print("✗ Failed to start agent for testing")
            
        print("\nTest completed successfully!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return 1


def show_status(config_path=None):
    """
    Show current agent status.
    
    Args:
        config_path: Path to configuration file
    """
    print("Python Logging Agent - Status")
    print("=" * 50)
    
    try:
        # Try to get service status first
        if PYWIN32_AVAILABLE:
            service_status = get_service_status()
            if service_status:
                print(f"Service Status: {service_status}")
                
        # Try to connect to running agent (this would require IPC in a real implementation)
        print("Note: Detailed status requires the agent to be running in console mode")
        
    except Exception as e:
        print(f"Error getting status: {e}")
        return 1
        
    return 0


def validate_config(config_path=None):
    """
    Validate the configuration file.
    
    Args:
        config_path: Path to configuration file
    """
    print("Python Logging Agent - Configuration Validation")
    print("=" * 50)
    
    try:
        config_manager = ConfigManager(config_path)
        config = config_manager.load_config()
        
        print("✓ Configuration file is valid")
        print(f"✓ Service name: {config.get('general', {}).get('service_name')}")
        print(f"✓ Log level: {config.get('general', {}).get('log_level')}")
        
        # Show enabled collectors
        enabled_sources = config_manager.get_log_sources()
        print("\nEnabled log sources:")
        for source, enabled in enabled_sources.items():
            status = "✓" if enabled else "✗"
            print(f"  {status} {source}")
            
        return 0
        
    except Exception as e:
        print(f"✗ Configuration validation failed: {e}")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Python Logging Agent - Cybersecurity Log Collection and Standardization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py console                    # Run in console mode
  python main.py test                       # Test configuration and collectors
  python main.py service install           # Install Windows service
  python main.py service start             # Start Windows service
  python main.py validate-config           # Validate configuration file
        """
    )
    
    parser.add_argument(
        'mode',
        choices=['console', 'test', 'service', 'status', 'validate-config'],
        help='Operation mode'
    )
    
    parser.add_argument(
        'service_action',
        nargs='?',
        choices=['install', 'remove', 'start', 'stop', 'status', 'debug'],
        help='Service action (when mode is "service")'
    )
    
    parser.add_argument(
        '--config',
        '-c',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set up basic logging if verbose
    if args.verbose:
        LoggerSetup.setup_logging(log_level='DEBUG', console_output=True)
    
    # Handle different modes
    if args.mode == 'console':
        return run_console_mode(args.config)
        
    elif args.mode == 'test':
        return run_test_mode(args.config)
        
    elif args.mode == 'service':
        if not args.service_action:
            print("Service action required. Use: install, remove, start, stop, status, or debug")
            return 1
            
        if not PYWIN32_AVAILABLE:
            print("Error: pywin32 is required for Windows service functionality")
            print("Install with: pip install pywin32")
            return 1
            
        if args.service_action == 'install':
            return 0 if install_service() else 1
        elif args.service_action == 'remove':
            return 0 if remove_service() else 1
        elif args.service_action == 'start':
            return 0 if start_service() else 1
        elif args.service_action == 'stop':
            return 0 if stop_service() else 1
        elif args.service_action == 'status':
            return 0 if get_service_status() else 1
        elif args.service_action == 'debug':
            return 0 if run_service_debug() else 1
            
    elif args.mode == 'status':
        return show_status(args.config)
        
    elif args.mode == 'validate-config':
        return validate_config(args.config)
        
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
