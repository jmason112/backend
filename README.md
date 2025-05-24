# Python Logging Agent

A comprehensive Python-based cybersecurity agent for collecting and standardizing Windows logs. This system provides automated log collection from various Windows sources and converts them into a standardized JSON format suitable for SIEM systems and security analysis.

## Features

### Log Collection
- **Windows Event Logs**: System, Application, Security logs
- **Security Logs**: Authentication events, policy changes, privilege use
- **Application Logs**: Application errors, service events, Windows Update logs
- **System Logs**: Hardware changes, driver failures, system events
- **Network Logs**: Connection attempts, interface changes, traffic monitoring
- **Packet Capture**: Network packet analysis using Scapy (optional)

### Log Standardization
- **JSON Format**: Converts all logs to standardized JSON format
- **Consistent Schema**: Unified schema across all log types
- **Metadata Enhancement**: Adds source metadata and timestamps
- **Field Normalization**: Standardizes field names and values

### Deployment Options
- **Console Mode**: Interactive mode for testing and development
- **Windows Service**: Background service for production deployment
- **Configurable**: YAML-based configuration with runtime reconfiguration

## Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 or Windows Server 2016/2019/2022
- Administrator privileges (for some log sources and service installation)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional Dependencies
For Windows service functionality:
```bash
pip install pywin32
```

For packet capture functionality:
```bash
pip install scapy
```

## Quick Start

### 1. Configuration
Copy and customize the default configuration:
```bash
cp config/default_config.yaml config/config.yaml
```

Edit `config/config.yaml` to enable desired log sources and configure output settings.

### 2. Test the Configuration
```bash
python main.py test
```

### 3. Run in Console Mode
```bash
python main.py console
```

### 4. Install as Windows Service
```bash
python main.py service install
python main.py service start
```

## Configuration

The agent uses YAML configuration files. Key sections include:

### General Settings
```yaml
general:
  service_name: "PythonLoggingAgent"
  log_level: "INFO"
  buffer_size: 1000
  processing_interval: 5
```

### Log Collection
```yaml
collection:
  event_logs:
    enabled: true
    sources: ["System", "Application", "Security"]
    max_records: 100
    
  security_logs:
    enabled: true
    include_authentication: true
    include_policy_changes: true
    
  packet_capture:
    enabled: false
    interface: "auto"
    filter: ""
```

### Output Configuration
```yaml
output:
  file:
    enabled: true
    path: "logs/standardized_logs.json"
    rotation:
      enabled: true
      max_size: "100MB"
      backup_count: 5
```

## Usage Examples

### Console Mode
```bash
# Run with default configuration
python main.py console

# Run with custom configuration
python main.py console --config custom_config.yaml

# Run with verbose output
python main.py console --verbose
```

### Service Management
```bash
# Install service
python main.py service install

# Start service
python main.py service start

# Check service status
python main.py service status

# Stop service
python main.py service stop

# Remove service
python main.py service remove

# Debug service (run in console with service configuration)
python main.py service debug
```

### Testing and Validation
```bash
# Test configuration and collectors
python main.py test

# Validate configuration file
python main.py validate-config

# Check agent status
python main.py status
```

## Log Format

The agent standardizes all logs into a consistent JSON format:

```json
{
  "timestamp": "2024-01-15T10:30:00.123456",
  "source": "System",
  "source_type": "event",
  "host": "COMPUTER-NAME",
  "log_level": "info",
  "message": "System startup completed",
  "additional_fields": {
    "event_id": 6005,
    "event_category": 0,
    "record_number": 12345,
    "metadata": {
      "collection_time": "2024-01-15T10:30:01.000000",
      "agent_version": "1.0.0",
      "windows_event_log": true
    }
  }
}
```

## Architecture

The system consists of two main components:

### Logging Agent
- Collects logs from various Windows sources
- Manages collection frequency and buffering
- Runs as a Windows service or console application

### Log Standardizer
- Converts raw logs to standardized JSON format
- Applies consistent schema and field normalization
- Handles error cases and malformed logs

## Security Considerations

- **Permissions**: Requires appropriate permissions to access log sources
- **Data Handling**: Sensitive information filtering capabilities
- **Network Security**: Packet capture requires elevated privileges
- **Log Rotation**: Automatic log rotation to prevent disk space issues

## Performance

- **Low Resource Usage**: Optimized for minimal CPU and memory footprint
- **Configurable Limits**: Adjustable buffer sizes and collection intervals
- **Efficient Processing**: Batch processing and buffering mechanisms
- **Monitoring**: Built-in performance monitoring and statistics

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the agent runs with appropriate privileges
2. **Service Won't Start**: Check the Windows Event Log for error details
3. **No Logs Collected**: Verify log source access and configuration
4. **High Resource Usage**: Adjust buffer sizes and collection intervals

### Log Files
- Agent logs: `logs/agent.log`
- Error logs: `logs/agent_errors.log`
- Audit logs: `logs/audit.log`
- Service logs: Windows Event Log

### Debug Mode
Run the service in debug mode for detailed troubleshooting:
```bash
python main.py service debug
```

## Development

### Running Tests
```bash
python -m pytest tests/
```

### Code Structure
```
├── config/                 # Configuration management
├── logging_agent/          # Main agent code
│   └── collectors/         # Log collectors
├── log_standardizer/       # Log standardization
│   └── parsers/           # Format-specific parsers
├── service/               # Windows service support
├── utils/                 # Utility modules
└── tests/                 # Unit tests
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the troubleshooting section
- Review the configuration documentation
- Submit issues on the project repository

## Changelog

### Version 1.0.0
- Initial release
- Windows Event Log collection
- Security log analysis
- Application and system log support
- Network monitoring capabilities
- JSON standardization
- Windows service support
- Comprehensive configuration system
