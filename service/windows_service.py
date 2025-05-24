"""
Windows Service Implementation

This module provides Windows service functionality for the Python Logging Agent
using the pywin32 library.
"""

import logging
import sys
import os
import time
from pathlib import Path

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


class PythonLoggingAgentService:
    """Windows service wrapper for the Python Logging Agent."""
    
    # Service configuration
    _svc_name_ = "PythonLoggingAgent"
    _svc_display_name_ = "Python Logging Agent"
    _svc_description_ = "Collects and standardizes Windows logs for security monitoring"
    
    def __init__(self, args=None):
        """Initialize the service."""
        if not PYWIN32_AVAILABLE:
            raise ImportError("pywin32 is required for Windows service functionality")
            
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None
        self.logger = None
        
    def SvcStop(self):
        """Handle service stop request."""
        try:
            if self.logger:
                self.logger.info("Service stop requested")
            
            # Signal the service to stop
            win32event.SetEvent(self.hWaitStop)
            
            # Stop the agent
            if self.agent:
                self.agent.stop()
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error stopping service: {e}")
            
    def SvcDoRun(self):
        """Main service execution method."""
        try:
            # Log service start
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            
            # Set up logging for the service
            self._setup_service_logging()
            
            # Initialize and start the agent
            self._start_agent()
            
            # Wait for stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
            # Log service stop
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, '')
            )
            
        except Exception as e:
            # Log error
            servicemanager.LogErrorMsg(f"Service error: {e}")
            if self.logger:
                self.logger.error(f"Service execution error: {e}")
                
    def _setup_service_logging(self):
        """Set up logging for the service."""
        try:
            # Create logs directory
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            # Set up basic logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler('logs/service.log'),
                    logging.StreamHandler()
                ]
            )
            
            self.logger = logging.getLogger(__name__)
            self.logger.info("Service logging initialized")
            
        except Exception as e:
            servicemanager.LogErrorMsg(f"Error setting up service logging: {e}")
            
    def _start_agent(self):
        """Initialize and start the logging agent."""
        try:
            # Import here to avoid circular imports
            from logging_agent.agent import LoggingAgent
            
            # Initialize the agent
            self.agent = LoggingAgent()
            
            # Start the agent
            if self.agent.start():
                self.logger.info("Logging agent started successfully")
            else:
                raise Exception("Failed to start logging agent")
                
        except Exception as e:
            self.logger.error(f"Error starting agent: {e}")
            raise


# Make the service class compatible with win32serviceutil
if PYWIN32_AVAILABLE:
    class PythonLoggingAgentServiceWin32(win32serviceutil.ServiceFramework, PythonLoggingAgentService):
        """Windows service class that inherits from ServiceFramework."""
        pass
else:
    PythonLoggingAgentServiceWin32 = None


def install_service():
    """Install the Windows service."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return False
        
    try:
        win32serviceutil.InstallService(
            PythonLoggingAgentServiceWin32,
            PythonLoggingAgentService._svc_name_,
            PythonLoggingAgentService._svc_display_name_,
            description=PythonLoggingAgentService._svc_description_
        )
        print(f"Service '{PythonLoggingAgentService._svc_display_name_}' installed successfully")
        return True
        
    except Exception as e:
        print(f"Error installing service: {e}")
        return False


def remove_service():
    """Remove the Windows service."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return False
        
    try:
        win32serviceutil.RemoveService(PythonLoggingAgentService._svc_name_)
        print(f"Service '{PythonLoggingAgentService._svc_display_name_}' removed successfully")
        return True
        
    except Exception as e:
        print(f"Error removing service: {e}")
        return False


def start_service():
    """Start the Windows service."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return False
        
    try:
        win32serviceutil.StartService(PythonLoggingAgentService._svc_name_)
        print(f"Service '{PythonLoggingAgentService._svc_display_name_}' started successfully")
        return True
        
    except Exception as e:
        print(f"Error starting service: {e}")
        return False


def stop_service():
    """Stop the Windows service."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return False
        
    try:
        win32serviceutil.StopService(PythonLoggingAgentService._svc_name_)
        print(f"Service '{PythonLoggingAgentService._svc_display_name_}' stopped successfully")
        return True
        
    except Exception as e:
        print(f"Error stopping service: {e}")
        return False


def get_service_status():
    """Get the current service status."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return None
        
    try:
        status = win32serviceutil.QueryServiceStatus(PythonLoggingAgentService._svc_name_)
        
        status_map = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Start Pending",
            win32service.SERVICE_STOP_PENDING: "Stop Pending",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
            win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
            win32service.SERVICE_PAUSED: "Paused"
        }
        
        current_state = status_map.get(status[1], "Unknown")
        print(f"Service '{PythonLoggingAgentService._svc_display_name_}' status: {current_state}")
        return current_state
        
    except Exception as e:
        print(f"Error getting service status: {e}")
        return None


def run_service_debug():
    """Run the service in debug mode (console)."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service functionality")
        return False
        
    try:
        # Set debug flag
        win32serviceutil.HandleCommandLine(
            PythonLoggingAgentServiceWin32,
            argv=['', 'debug']
        )
        return True
        
    except Exception as e:
        print(f"Error running service in debug mode: {e}")
        return False


def main():
    """Main entry point for service management."""
    if len(sys.argv) == 1:
        # No arguments - try to start as service
        if PYWIN32_AVAILABLE:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(PythonLoggingAgentServiceWin32)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            print("Error: pywin32 is required for Windows service functionality")
    else:
        # Handle command line arguments
        command = sys.argv[1].lower()
        
        if command == 'install':
            install_service()
        elif command == 'remove':
            remove_service()
        elif command == 'start':
            start_service()
        elif command == 'stop':
            stop_service()
        elif command == 'status':
            get_service_status()
        elif command == 'debug':
            run_service_debug()
        else:
            print("Usage: python windows_service.py [install|remove|start|stop|status|debug]")


if __name__ == '__main__':
    main()
