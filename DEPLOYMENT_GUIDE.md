# Python Logging Agent - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Python Logging Agent in various environments.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016/2019/2022
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum
- **Disk Space**: 100MB for installation + additional space for logs
- **Permissions**: Administrator privileges for full functionality

### Recommended Requirements
- **RAM**: 8GB or higher
- **CPU**: Multi-core processor
- **Disk Space**: 1GB+ for log storage
- **Network**: Stable network connection for remote log shipping

## Installation Methods

### Method 1: Quick Installation (Recommended)

1. **Download and Extract**
   ```bash
   # Extract the agent files to desired location
   # Example: C:\PythonLoggingAgent\
   ```

2. **Run Installation Script**
   ```bash
   # Run as Administrator
   install.bat
   ```

3. **Verify Installation**
   ```bash
   python main.py validate-config
   python main.py test
   ```

### Method 2: Manual Installation

1. **Install Python Dependencies**
   ```bash
   pip install --user -r requirements.txt
   ```

2. **Create Log Directories**
   ```bash
   mkdir logs
   ```

3. **Test Configuration**
   ```bash
   python main.py validate-config
   ```

## Configuration

### Basic Configuration

1. **Copy Default Configuration**
   ```bash
   copy config\default_config.yaml config\config.yaml
   ```

2. **Edit Configuration File**
   Edit `config/config.yaml` to customize:
   - Log sources to collect
   - Output destinations
   - Collection intervals
   - Performance settings

### Key Configuration Sections

#### Log Sources
```yaml
collection:
  event_logs:
    enabled: true
    sources: ["System", "Application"]
  
  security_logs:
    enabled: true
    include_authentication: true
  
  network_logs:
    enabled: true
    include_connections: true
```

#### Output Settings
```yaml
output:
  file:
    enabled: true
    path: "logs/standardized_logs.json"
    rotation:
      enabled: true
      max_size: "100MB"
```

## Deployment Scenarios

### Scenario 1: Development/Testing

**Purpose**: Testing and development environment

**Deployment**:
```bash
# Run in console mode
python main.py console

# Or run tests
python main.py test
```

**Configuration**: Use default settings with console output enabled

### Scenario 2: Production Server

**Purpose**: Production log collection as Windows service

**Deployment**:
```bash
# Install as Windows service (run as Administrator)
python main.py service install

# Start the service
python main.py service start

# Check service status
python main.py service status
```

**Configuration**: 
- Disable console output
- Enable file output with rotation
- Set appropriate log levels
- Configure performance limits

### Scenario 3: Workstation Monitoring

**Purpose**: Individual workstation monitoring

**Deployment**:
```bash
# Install service with limited permissions
python main.py service install

# Configure for workstation use
# Edit config.yaml to reduce resource usage
```

**Configuration**:
- Reduce buffer sizes
- Increase collection intervals
- Focus on security and application logs

## Security Considerations

### Permissions

1. **Service Account**: Create dedicated service account
2. **Log Access**: Ensure access to required log sources
3. **File Permissions**: Secure log output directories
4. **Network**: Configure firewall rules if needed

### Security Best Practices

1. **Principle of Least Privilege**: Run with minimum required permissions
2. **Log Encryption**: Consider encrypting log files at rest
3. **Network Security**: Use secure protocols for log shipping
4. **Access Control**: Restrict access to configuration files

## Monitoring and Maintenance

### Health Monitoring

1. **Service Status**
   ```bash
   python main.py service status
   ```

2. **Log File Monitoring**
   - Check `logs/agent.log` for operational status
   - Monitor `logs/agent_errors.log` for errors
   - Review `logs/audit.log` for security events

3. **Performance Monitoring**
   - Monitor CPU and memory usage
   - Check disk space for log storage
   - Review collection statistics

### Maintenance Tasks

#### Daily
- Check service status
- Monitor error logs
- Verify log collection

#### Weekly
- Review log file sizes
- Check disk space
- Analyze performance metrics

#### Monthly
- Update configuration if needed
- Review security logs
- Plan capacity upgrades

### Log Rotation

The agent automatically rotates logs based on configuration:

```yaml
output:
  file:
    rotation:
      enabled: true
      max_size: "100MB"
      backup_count: 5
```

### Backup and Recovery

1. **Configuration Backup**
   ```bash
   # Backup configuration
   copy config\config.yaml config\config.yaml.backup
   ```

2. **Log Backup**
   - Implement regular backup of log files
   - Consider automated backup scripts
   - Test recovery procedures

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   - Check Windows Event Log
   - Verify Python installation
   - Check file permissions

2. **No Logs Collected**
   - Verify log source access
   - Check configuration settings
   - Review error logs

3. **High Resource Usage**
   - Reduce buffer sizes
   - Increase collection intervals
   - Limit log sources

4. **Permission Errors**
   - Run as Administrator
   - Check service account permissions
   - Verify log source access

### Debug Mode

Run the service in debug mode for troubleshooting:
```bash
python main.py service debug
```

### Log Analysis

Check the following log files:
- `logs/agent.log` - General operation
- `logs/agent_errors.log` - Error details
- `logs/audit.log` - Security events
- Windows Event Log - Service events

## Performance Tuning

### Resource Optimization

1. **Memory Usage**
   ```yaml
   general:
     buffer_size: 500  # Reduce for lower memory usage
   
   performance:
     max_memory_mb: 128  # Set memory limit
   ```

2. **CPU Usage**
   ```yaml
   general:
     processing_interval: 10  # Increase for lower CPU usage
   
   performance:
     max_cpu_percent: 5  # Set CPU limit
   ```

3. **Disk I/O**
   ```yaml
   output:
     file:
       rotation:
         max_size: "50MB"  # Smaller files for better I/O
   ```

### Scaling Considerations

- **Multiple Agents**: Deploy multiple agents for different log types
- **Load Balancing**: Distribute collection across multiple systems
- **Centralized Storage**: Use network storage for log aggregation

## Integration with SIEM Systems

### Splunk Integration
```bash
# Configure Splunk Universal Forwarder to monitor:
# logs/standardized_logs.json
```

### ELK Stack Integration
```bash
# Configure Filebeat to ship logs to Elasticsearch
# Use the JSON format for easy parsing
```

### Custom Integration
- Use the standardized JSON format
- Implement custom log shippers
- Configure API endpoints for real-time streaming

## Support and Documentation

### Getting Help
1. Check the troubleshooting section
2. Review log files for errors
3. Consult the README.md for detailed information
4. Submit issues to the project repository

### Additional Resources
- Configuration reference
- API documentation
- Best practices guide
- Security hardening guide
