# AWS CloudWatch Monitor - Dynamic Multi-Resource Edition

A powerful, terminal-based monitoring application for AWS RDS instances and CloudWatch logs with dynamic resource discovery, tabbed interface, and real-time configuration reloading.

## 🚀 Features

### Core Monitoring

- **Real-time RDS Metrics**: CPU utilization, database connections, read/write IOPS, memory usage
- **CloudWatch Logs Streaming**: Live log viewing with intelligent color-coded log levels
- **Multi-Resource Support**: Monitor multiple RDS instances and log groups simultaneously
- **Tabbed Interface**: Easy navigation between different resources

### Dynamic Capabilities

- **Auto-Discovery**: Automatically discover RDS instances and log groups based on tags and patterns
- **Hot Configuration Reload**: Changes to config.json are automatically detected and applied
- **Dynamic Resource Addition**: New resources are discovered and added without restart
- **Flexible Thresholds**: Per-metric configurable warning and critical thresholds

### User Experience

- **Responsive UI**: Split-pane interface with keyboard navigation
- **Color-coded Status**: Visual indicators for metric health and log levels
- **Real-time Updates**: Configurable refresh intervals for different data types
- **Graceful Shutdown**: Proper cleanup and signal handling

## 🎯 Major Improvements Made

### 1. Dynamic Multi-Resource Architecture

- **Before**: Single hardcoded RDS instance and log group
- **After**: Support for unlimited RDS instances and log groups with tabbed interface
- **Benefits**: Monitor entire AWS infrastructure from one application

### 2. Auto-Discovery System

- **Before**: Manual configuration of each resource
- **After**: Automatic discovery based on tags, patterns, and AWS API calls
- **Benefits**: Zero-configuration monitoring of new resources

### 3. Configuration-Driven Everything

- **Before**: Hardcoded values scattered throughout code
- **After**: Comprehensive JSON configuration with hot-reloading
- **Benefits**: Runtime configuration changes without restart

### 4. Advanced UI with Tabs

- **Before**: Single static view
- **After**: Dynamic tabbed interface with resource-specific views
- **Benefits**: Efficient monitoring of multiple resources

### 5. Intelligent Resource Management

- **Before**: Static resource list
- **After**: Dynamic resource discovery and management
- **Benefits**: Automatically adapts to infrastructure changes

## 📋 Configuration

The application uses a comprehensive `config.json` file:

```json
{
  "autoDiscovery": {
    "enabled": true,
    "rdsInstances": {
      "enabled": true,
      "tags": {
        "Environment": ["prod", "staging"],
        "Application": ["web", "api"]
      }
    },
    "logGroups": {
      "enabled": true,
      "patterns": ["/aws/lambda/*", "/aws/rds/*", "/aws/ecs/*"]
    }
  },
  "resources": {
    "rdsInstances": [
      {
        "identifier": "my-prod-db",
        "displayName": "Production DB",
        "region": "us-east-1",
        "enabled": true
      }
    ],
    "logGroups": [
      {
        "name": "/aws/lambda/my-function",
        "displayName": "Lambda Logs",
        "region": "us-east-1",
        "enabled": true
      }
    ]
  },
  "intervals": {
    "metricsUpdateSeconds": 30,
    "logsUpdateSeconds": 5,
    "discoveryIntervalMinutes": 15,
    "configReloadSeconds": 60
  }
}
```

### 🔧 Configuration Sections

#### Auto-Discovery

| Setting                              | Description                           | Default |
| ------------------------------------ | ------------------------------------- | ------- |
| `autoDiscovery.enabled`              | Enable automatic resource discovery   | `true`  |
| `autoDiscovery.rdsInstances.enabled` | Auto-discover RDS instances           | `true`  |
| `autoDiscovery.rdsInstances.tags`    | Tag-based filtering for RDS discovery | `{}`    |
| `autoDiscovery.logGroups.enabled`    | Auto-discover log groups              | `true`  |
| `autoDiscovery.logGroups.patterns`   | Patterns for log group discovery      | `[]`    |

#### Manual Resources

| Setting                    | Description                       |
| -------------------------- | --------------------------------- |
| `resources.rdsInstances[]` | Manually configured RDS instances |
| `resources.logGroups[]`    | Manually configured log groups    |

#### Timing Configuration

| Setting                              | Description                 | Default |
| ------------------------------------ | --------------------------- | ------- |
| `intervals.metricsUpdateSeconds`     | Metrics refresh interval    | `30`    |
| `intervals.logsUpdateSeconds`        | Logs refresh interval       | `5`     |
| `intervals.discoveryIntervalMinutes` | Resource discovery interval | `15`    |
| `intervals.configReloadSeconds`      | Configuration reload check  | `60`    |

#### Thresholds

| Setting                           | Description                   | Default |
| --------------------------------- | ----------------------------- | ------- |
| `thresholds.cpu.warning`          | CPU warning threshold (%)     | `50.0`  |
| `thresholds.cpu.critical`         | CPU critical threshold (%)    | `80.0`  |
| `thresholds.connections.warning`  | Connection warning threshold  | `50.0`  |
| `thresholds.connections.critical` | Connection critical threshold | `100.0` |

## 🚀 Usage

### Prerequisites

1. **AWS Credentials**: Configured via AWS CLI, environment variables, or IAM roles
2. **AWS Permissions**: CloudWatch, RDS, and CloudWatch Logs read access
3. **Go 1.24+**: For building the application

### Quick Start

```bash
# Clone or download the application files
# Ensure you have main.go and config.json

# Build the application
go build -o aws-monitor main.go

# Run with default configuration
./aws-monitor

# Run with custom configuration
./aws-monitor /path/to/custom-config.json
```

### First Run Setup

1. **Configure AWS credentials**:

   ```bash
   aws configure
   # or set environment variables
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. **Customize config.json**:

   - Add your RDS instance identifiers
   - Add your log group names
   - Configure auto-discovery patterns
   - Set appropriate thresholds

3. **Run the application**:
   ```bash
   ./aws-monitor
   ```

### 🎮 Keyboard Controls

| Key             | Action                     |
| --------------- | -------------------------- |
| `q` or `Ctrl+C` | Quit application           |
| `r` or `F5`     | Manual refresh current tab |
| `Tab` or `→`    | Next tab                   |
| `←`             | Previous tab               |
| `↑/↓`           | Scroll logs up/down        |
| `PgUp/PgDn`     | Page through logs          |

### 🔍 Auto-Discovery Examples

#### RDS Instance Discovery by Tags

```json
{
  "autoDiscovery": {
    "rdsInstances": {
      "enabled": true,
      "tags": {
        "Environment": ["production", "staging"],
        "Team": ["backend", "data"]
      }
    }
  }
}
```

#### Log Group Discovery by Patterns

```json
{
  "autoDiscovery": {
    "logGroups": {
      "enabled": true,
      "patterns": ["/aws/lambda/prod-*", "/aws/ecs/my-cluster/*", "/aws/rds/instance/*/error"]
    }
  }
}
```

## 🏗️ Architecture

### Dynamic Resource Management

```
Config File → Auto-Discovery → Resource Tabs → Background Workers → UI Updates
     ↓              ↓              ↓              ↓              ↓
Hot Reload → AWS APIs → Tab Manager → Data Fetchers → View Renderer
```

### Core Components

1. **Configuration Manager**: Hot-reloading JSON configuration
2. **Resource Discovery**: AWS API-based resource discovery
3. **Tab Manager**: Dynamic tab creation and management
4. **Background Workers**: Concurrent data fetching for all resources
5. **UI Renderer**: Responsive terminal interface with gocui

### Data Flow

1. **Initialization**: Load config → Discover resources → Create tabs
2. **Runtime**: Background workers fetch data → Update tab buffers → Render UI
3. **Discovery**: Periodic resource discovery → Add new tabs → Update UI
4. **Configuration**: File watcher → Reload config → Reinitialize resources

## 🔧 Advanced Configuration

### Custom Metrics

Add new RDS metrics to monitor:

```json
{
  "metrics": [
    {
      "name": "FreeableMemory",
      "namespace": "AWS/RDS",
      "unit": "bytes",
      "format": "%.0f"
    },
    {
      "name": "SwapUsage",
      "namespace": "AWS/RDS",
      "unit": "bytes",
      "format": "%.0f"
    }
  ]
}
```

### Environment-Specific Configurations

**Production Config** (`config-prod.json`):

```json
{
  "intervals": {
    "metricsUpdateSeconds": 15,
    "logsUpdateSeconds": 2,
    "discoveryIntervalMinutes": 5
  },
  "thresholds": {
    "cpu": { "warning": 70.0, "critical": 90.0 }
  }
}
```

**Development Config** (`config-dev.json`):

```json
{
  "intervals": {
    "metricsUpdateSeconds": 60,
    "logsUpdateSeconds": 10,
    "discoveryIntervalMinutes": 30
  },
  "autoDiscovery": {
    "enabled": false
  }
}
```

### Multi-Region Support

Configure resources across regions:

```json
{
  "resources": {
    "rdsInstances": [
      {
        "identifier": "us-east-db",
        "region": "us-east-1",
        "displayName": "East Coast DB"
      },
      {
        "identifier": "us-west-db",
        "region": "us-west-2",
        "displayName": "West Coast DB"
      }
    ]
  }
}
```

## 🔐 AWS Permissions

### Minimum Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricStatistics",
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups",
        "rds:DescribeDBInstances",
        "rds:ListTagsForResource"
      ],
      "Resource": "*"
    }
  ]
}
```

### Enhanced Permissions (for full auto-discovery)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["cloudwatch:*", "logs:*", "rds:Describe*", "rds:List*", "tag:GetResources"],
      "Resource": "*"
    }
  ]
}
```

## 🐛 Troubleshooting

### Common Issues

1. **No resources discovered**

   - Check AWS credentials and permissions
   - Verify tag filters and patterns in config
   - Check AWS region configuration

2. **Configuration not reloading**

   - Ensure config file is writable
   - Check file modification timestamps
   - Verify JSON syntax

3. **Metrics not updating**

   - Verify RDS instance identifiers
   - Check CloudWatch permissions
   - Ensure instances are in correct region

4. **Logs not streaming**
   - Verify log group names and permissions
   - Check log group regions
   - Ensure logs exist in specified time range

### Debug Mode

Enable detailed logging:

```bash
export AWS_SDK_LOAD_CONFIG=1
export AWS_LOG_LEVEL=debug
./aws-monitor
```

### Performance Tuning

For large numbers of resources:

```json
{
  "intervals": {
    "metricsUpdateSeconds": 60,
    "logsUpdateSeconds": 10,
    "discoveryIntervalMinutes": 30
  },
  "bufferSize": 500
}
```

## 🚀 Future Enhancements

- **Multi-region auto-discovery**
- **Custom dashboard layouts**
- **Alerting and notifications**
- **Export capabilities (CSV, JSON)**
- **Plugin system for custom metrics**
- **Web interface option**

## 📄 License

This project is licensed under the MIT License.

---

**Dynamic AWS CloudWatch Monitor** - Monitor your entire AWS infrastructure with zero configuration! 🎯
