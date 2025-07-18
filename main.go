package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/charmbracelet/log"
	"github.com/jroimartin/gocui"
)

// Configuration holds all application configuration
type Configuration struct {
	AutoDiscovery       AutoDiscoveryConfig `json:"autoDiscovery"`
	Resources           ResourcesConfig     `json:"resources"`
	BufferSize          int                 `json:"bufferSize"`
	Intervals           Intervals           `json:"intervals"`
	MetricPeriodSeconds int32               `json:"metricPeriodSeconds"`
	Thresholds          Thresholds          `json:"thresholds"`
	Metrics             []MetricInfo        `json:"metrics"`
	Logging             LoggingConfig       `json:"logging"`
	UI                  UIConfig            `json:"ui"`
}

// LoggingConfig defines logging configuration
type LoggingConfig struct {
	Level   string        `json:"level"`
	Format  string        `json:"format"`
	Output  string        `json:"output"`
	File    FileConfig    `json:"file"`
	Console ConsoleConfig `json:"console"`
}

// FileConfig defines file logging configuration
type FileConfig struct {
	Path       string `json:"path"`
	MaxSize    string `json:"maxSize"`
	MaxBackups int    `json:"maxBackups"`
	Compress   bool   `json:"compress"`
}

// ConsoleConfig defines console logging configuration
type ConsoleConfig struct {
	Enabled  bool `json:"enabled"`
	Colorize bool `json:"colorize"`
}

// AutoDiscoveryConfig defines auto-discovery settings
type AutoDiscoveryConfig struct {
	Enabled      bool                    `json:"enabled"`
	RDSInstances RDSDiscoveryConfig      `json:"rdsInstances"`
	LogGroups    LogGroupDiscoveryConfig `json:"logGroups"`
}

// RDSDiscoveryConfig defines RDS auto-discovery settings
type RDSDiscoveryConfig struct {
	Enabled bool              `json:"enabled"`
	Tags    map[string][]string `json:"tags"`
}

// LogGroupDiscoveryConfig defines log group auto-discovery settings
type LogGroupDiscoveryConfig struct {
	Enabled  bool     `json:"enabled"`
	Patterns []string `json:"patterns"`
}

// ResourcesConfig holds manually configured resources
type ResourcesConfig struct {
	RDSInstances []RDSInstanceConfig `json:"rdsInstances"`
	LogGroups    []LogGroupConfig    `json:"logGroups"`
}

// RDSInstanceConfig represents an RDS instance configuration
type RDSInstanceConfig struct {
	Identifier  string `json:"identifier"`
	DisplayName string `json:"displayName"`
	Region      string `json:"region"`
	Enabled     bool   `json:"enabled"`
}

// LogGroupConfig represents a log group configuration
type LogGroupConfig struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Region      string `json:"region"`
	Enabled     bool   `json:"enabled"`
}

// Intervals defines timing configuration
type Intervals struct {
	MetricsUpdateSeconds     int `json:"metricsUpdateSeconds"`
	LogsUpdateSeconds        int `json:"logsUpdateSeconds"`
	MetricLookbackMinutes    int `json:"metricLookbackMinutes"`
	DiscoveryIntervalMinutes int `json:"discoveryIntervalMinutes"`
	ConfigReloadSeconds      int `json:"configReloadSeconds"`
}

// Thresholds defines warning and critical thresholds for metrics
type Thresholds struct {
	CPU struct {
		Warning  float64 `json:"warning"`
		Critical float64 `json:"critical"`
	} `json:"cpu"`
	Connections struct {
		Warning  float64 `json:"warning"`
		Critical float64 `json:"critical"`
	} `json:"connections"`
	IOPS struct {
		Warning  float64 `json:"warning"`
		Critical float64 `json:"critical"`
	} `json:"iops"`
}

// MetricInfo represents a CloudWatch metric with its configuration
type MetricInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Unit      string `json:"unit"`
	Format    string `json:"format"`
}

// UIConfig holds UI-related configuration
type UIConfig struct {
	Colors struct {
		Enabled bool   `json:"enabled"`
		Theme   string `json:"theme"`
	} `json:"colors"`
	RefreshKeys []string `json:"refreshKeys"`
	QuitKeys    []string `json:"quitKeys"`
	Navigation  struct {
		NextTab    []string `json:"nextTab"`
		PrevTab    []string `json:"prevTab"`
		SwitchView []string `json:"switchView"`
	} `json:"navigation"`
	Layout struct {
		ShowTabs   bool    `json:"showTabs"`
		ShowStatus bool    `json:"showStatus"`
		SplitRatio float64 `json:"splitRatio"`
	} `json:"layout"`
}

// ResourceTab represents a tab for monitoring a specific resource
type ResourceTab struct {
	ID          string
	DisplayName string
	Type        string // "rds" or "logs"
	Resource    interface{} // RDSInstanceConfig or LogGroupConfig
	LogBuffer   []LogEvent
	LogOffset   int
	LastToken   *string
	Active      bool
}

// LogEvent represents a formatted log event
type LogEvent struct {
	Timestamp time.Time
	Message   string
	Formatted string
}

// AWSClients holds all AWS service clients
type AWSClients struct {
	RDS            *rds.Client
	CloudWatch     *cloudwatch.Client
	CloudWatchLogs *cloudwatchlogs.Client
}

// MonitoringApp represents the main application
type MonitoringApp struct {
	config         *Configuration
	clients        *AWSClients
	gui            *gocui.Gui
	tabs           []*ResourceTab
	currentTab     int
	ctx            context.Context
	cancel         context.CancelFunc
	configFile     string
	lastConfigMod  time.Time
	logger         *log.Logger
}

// Color constants for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
	ColorLink   = "\033[4;36m" // Underlined cyan for links
)

// LinkableResource represents a resource that can be linked to AWS Console
type LinkableResource struct {
	Name     string
	URL      string
	StartPos int
	EndPos   int
}

// LoadConfiguration loads configuration from a JSON file
func LoadConfiguration(filename string) (*Configuration, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	var config Configuration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", filename, err)
	}

	return &config, nil
}

// GetMetricsInterval returns the metrics update interval as a duration
func (c *Configuration) GetMetricsInterval() time.Duration {
	return time.Duration(c.Intervals.MetricsUpdateSeconds) * time.Second
}

// GetLogsInterval returns the logs update interval as a duration
func (c *Configuration) GetLogsInterval() time.Duration {
	return time.Duration(c.Intervals.LogsUpdateSeconds) * time.Second
}

// GetMetricLookback returns the metric lookback time as a duration
func (c *Configuration) GetMetricLookback() time.Duration {
	return time.Duration(c.Intervals.MetricLookbackMinutes) * time.Minute
}

// GetDiscoveryInterval returns the discovery interval as a duration
func (c *Configuration) GetDiscoveryInterval() time.Duration {
	return time.Duration(c.Intervals.DiscoveryIntervalMinutes) * time.Minute
}

// GetConfigReloadInterval returns the config reload interval as a duration
func (c *Configuration) GetConfigReloadInterval() time.Duration {
	return time.Duration(c.Intervals.ConfigReloadSeconds) * time.Second
}

// initializeLogger sets up the Charm.sh logger based on configuration
func initializeLogger(config *Configuration) (*log.Logger, error) {
	var output *os.File
	var err error

	// Configure output
	switch strings.ToLower(config.Logging.Output) {
	case "file":
		if config.Logging.File.Path != "" {
			output, err = os.OpenFile(config.Logging.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				return nil, fmt.Errorf("failed to open log file: %w", err)
			}
		} else {
			output = os.Stdout
		}
	default:
		output = os.Stdout
	}

	logger := log.NewWithOptions(output, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      "2006-01-02 15:04:05",
	})

	// Set log level
	switch strings.ToLower(config.Logging.Level) {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info":
		logger.SetLevel(log.InfoLevel)
	case "warn", "warning":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	default:
		logger.SetLevel(log.InfoLevel)
	}

	return logger, nil
}

// NewAWSClients initializes AWS service clients
func NewAWSClients(ctx context.Context) (*AWSClients, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSClients{
		RDS:            rds.NewFromConfig(cfg),
		CloudWatch:     cloudwatch.NewFromConfig(cfg),
		CloudWatchLogs: cloudwatchlogs.NewFromConfig(cfg),
	}, nil
}

// NewMonitoringApp creates a new monitoring application instance
func NewMonitoringApp(configFile string) (*MonitoringApp, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	config, err := LoadConfiguration(configFile)
	if err != nil {
		cancel()
		return nil, err
	}

	// Initialize logger
	logger, err := initializeLogger(config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	clients, err := NewAWSClients(ctx)
	if err != nil {
		cancel()
		return nil, err
	}

	gui, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create GUI: %w", err)
	}

	// Get config file modification time
	stat, _ := os.Stat(configFile)
	var lastMod time.Time
	if stat != nil {
		lastMod = stat.ModTime()
	}

	app := &MonitoringApp{
		config:        config,
		clients:       clients,
		gui:           gui,
		tabs:          make([]*ResourceTab, 0),
		currentTab:    0,
		ctx:           ctx,
		cancel:        cancel,
		configFile:    configFile,
		lastConfigMod: lastMod,
		logger:        logger,
	}

	// Initialize tabs from configuration
	if err := app.initializeTabs(); err != nil {
		cancel()
		return nil, err
	}

	return app, nil
}

// initializeTabs creates tabs for all configured resources
func (app *MonitoringApp) initializeTabs() error {
	app.tabs = make([]*ResourceTab, 0)

	// Add single consolidated databases tab if any RDS instances exist
	enabledRDSInstances := make([]RDSInstanceConfig, 0)
	for _, rds := range app.config.Resources.RDSInstances {
		if rds.Enabled {
			enabledRDSInstances = append(enabledRDSInstances, rds)
		}
	}

	if len(enabledRDSInstances) > 0 {
		tab := &ResourceTab{
			ID:          "databases",
			DisplayName: "Databases",
			Type:        "databases",
			Resource:    enabledRDSInstances, // Store all RDS instances
			LogBuffer:   make([]LogEvent, 0, app.config.BufferSize),
			LogOffset:   0,
			Active:      true, // Databases tab is active by default
		}
		app.tabs = append(app.tabs, tab)
	}

	// Add log group tabs
	for _, lg := range app.config.Resources.LogGroups {
		if lg.Enabled {
			tab := &ResourceTab{
				ID:          fmt.Sprintf("logs-%s", strings.ReplaceAll(lg.Name, "/", "-")),
				DisplayName: lg.DisplayName,
				Type:        "logs",
				Resource:    lg,
				LogBuffer:   make([]LogEvent, 0, app.config.BufferSize),
				LogOffset:   0,
				Active:      len(app.tabs) == 0, // First tab is active if no databases tab
			}
			app.tabs = append(app.tabs, tab)
		}
	}

	if len(app.tabs) == 0 {
		return fmt.Errorf("no enabled resources found in configuration")
	}

	return nil
}

// discoverResources automatically discovers AWS resources based on configuration
func (app *MonitoringApp) discoverResources() error {
	if !app.config.AutoDiscovery.Enabled {
		return nil
	}

	var newTabs []*ResourceTab

	// Discover RDS instances and add to consolidated databases tab
	if app.config.AutoDiscovery.RDSInstances.Enabled {
		instances, err := app.discoverRDSInstances()
		if err != nil {
			app.logger.Error("Failed to discover RDS instances", "error", err)
		} else {
			// Find the databases tab
			var databasesTab *ResourceTab
			for _, tab := range app.tabs {
				if tab.Type == "databases" {
					databasesTab = tab
					break
				}
			}

			// If no databases tab exists, create one
			if databasesTab == nil {
				databasesTab = &ResourceTab{
					ID:          "databases",
					DisplayName: "Databases",
					Type:        "databases",
					Resource:    make([]RDSInstanceConfig, 0),
					LogBuffer:   make([]LogEvent, 0, app.config.BufferSize),
					LogOffset:   0,
				}
				app.tabs = append([]*ResourceTab{databasesTab}, app.tabs...)
			}

			// Add new instances to the databases tab
			existingInstances, ok := databasesTab.Resource.([]RDSInstanceConfig)
			if !ok {
				existingInstances = make([]RDSInstanceConfig, 0)
			}

			for _, instance := range instances {
				// Check if instance already exists
				exists := false
				for _, existing := range existingInstances {
					if existing.Identifier == instance.Identifier {
						exists = true
						break
					}
				}

				if !exists {
					existingInstances = append(existingInstances, instance)
				}
			}

			databasesTab.Resource = existingInstances
		}
	}

	// Discover log groups
	if app.config.AutoDiscovery.LogGroups.Enabled {
		logGroups, err := app.discoverLogGroups()
		if err != nil {
			app.logger.Error("Failed to discover log groups", "error", err)
		} else {
			for _, lg := range logGroups {
				// Check if tab already exists
				exists := false
				for _, tab := range app.tabs {
					if tab.Type == "logs" {
						if lgConfig, ok := tab.Resource.(LogGroupConfig); ok {
							if lgConfig.Name == lg.Name {
								exists = true
								break
							}
						}
					}
				}

				if !exists {
					tab := &ResourceTab{
						ID:          fmt.Sprintf("logs-%s", strings.ReplaceAll(lg.Name, "/", "-")),
						DisplayName: lg.DisplayName,
						Type:        "logs",
						Resource:    lg,
						LogBuffer:   make([]LogEvent, 0, app.config.BufferSize),
						LogOffset:   0,
					}
					newTabs = append(newTabs, tab)
				}
			}
		}
	}

	// Add new tabs
	app.tabs = append(app.tabs, newTabs...)

	return nil
}

// discoverRDSInstances discovers RDS instances based on tags
func (app *MonitoringApp) discoverRDSInstances() ([]RDSInstanceConfig, error) {
	input := &rds.DescribeDBInstancesInput{}
	
	result, err := app.clients.RDS.DescribeDBInstances(app.ctx, input)
	if err != nil {
		return nil, err
	}

	var instances []RDSInstanceConfig
	for _, db := range result.DBInstances {
		// Check if instance matches tag criteria
		if app.matchesRDSTags(db) {
			instance := RDSInstanceConfig{
				Identifier:  aws.ToString(db.DBInstanceIdentifier),
				DisplayName: aws.ToString(db.DBInstanceIdentifier),
				Region:      "us-east-1", // Default region, could be made dynamic
				Enabled:     true,
			}
			instances = append(instances, instance)
		}
	}

	return instances, nil
}

// matchesRDSTags checks if an RDS instance matches the configured tag criteria
func (app *MonitoringApp) matchesRDSTags(db rdsTypes.DBInstance) bool {
	if len(app.config.AutoDiscovery.RDSInstances.Tags) == 0 {
		return true // No tag filtering, include all
	}

	// Get tags for the instance
	input := &rds.ListTagsForResourceInput{
		ResourceName: db.DBInstanceArn,
	}
	
	result, err := app.clients.RDS.ListTagsForResource(app.ctx, input)
	if err != nil {
		return false
	}

	// Check if instance has matching tags
	for tagKey, tagValues := range app.config.AutoDiscovery.RDSInstances.Tags {
		for _, tag := range result.TagList {
			if aws.ToString(tag.Key) == tagKey {
				for _, value := range tagValues {
					if aws.ToString(tag.Value) == value {
						return true
					}
				}
			}
		}
	}

	return false
}

// discoverLogGroups discovers log groups based on patterns
func (app *MonitoringApp) discoverLogGroups() ([]LogGroupConfig, error) {
	var logGroups []LogGroupConfig

	for _, pattern := range app.config.AutoDiscovery.LogGroups.Patterns {
		input := &cloudwatchlogs.DescribeLogGroupsInput{
			LogGroupNamePrefix: aws.String(strings.TrimSuffix(pattern, "*")),
		}

		result, err := app.clients.CloudWatchLogs.DescribeLogGroups(app.ctx, input)
		if err != nil {
			continue
		}

		for _, lg := range result.LogGroups {
			logGroup := LogGroupConfig{
				Name:        aws.ToString(lg.LogGroupName),
				DisplayName: aws.ToString(lg.LogGroupName),
				Region:      "us-east-1", // Default region
				Enabled:     true,
			}
			logGroups = append(logGroups, logGroup)
		}
	}

	return logGroups, nil
}

// reloadConfiguration reloads the configuration file if it has been modified
func (app *MonitoringApp) reloadConfiguration() error {
	stat, err := os.Stat(app.configFile)
	if err != nil {
		return err
	}

	if stat.ModTime().After(app.lastConfigMod) {
		newConfig, err := LoadConfiguration(app.configFile)
		if err != nil {
			return err
		}

		app.config = newConfig
		app.lastConfigMod = stat.ModTime()
		
		// Reinitialize tabs
		return app.initializeTabs()
	}

	return nil
}

// getCurrentTab returns the currently active tab
func (app *MonitoringApp) getCurrentTab() *ResourceTab {
	if len(app.tabs) == 0 || app.currentTab >= len(app.tabs) {
		return nil
	}
	return app.tabs[app.currentTab]
}

// nextTab switches to the next tab
func (app *MonitoringApp) nextTab() {
	if len(app.tabs) > 1 {
		app.currentTab = (app.currentTab + 1) % len(app.tabs)
	}
}

// prevTab switches to the previous tab
func (app *MonitoringApp) prevTab() {
	if len(app.tabs) > 1 {
		app.currentTab = (app.currentTab - 1 + len(app.tabs)) % len(app.tabs)
	}
}

// generateRDSConsoleURL creates a URL to the AWS Console for an RDS instance
func (app *MonitoringApp) generateRDSConsoleURL(rdsConfig RDSInstanceConfig) string {
	return fmt.Sprintf("https://console.aws.amazon.com/rds/home?region=%s#database:id=%s", 
		rdsConfig.Region, rdsConfig.Identifier)
}

// generateLogGroupConsoleURL creates a URL to the AWS Console for a CloudWatch Log Group
func (app *MonitoringApp) generateLogGroupConsoleURL(lgConfig LogGroupConfig) string {
	encodedName := url.QueryEscape(lgConfig.Name)
	return fmt.Sprintf("https://console.aws.amazon.com/cloudwatch/home?region=%s#logsV2:log-groups/log-group/%s", 
		lgConfig.Region, encodedName)
}

// openURL opens a URL in the default browser
func (app *MonitoringApp) openURL(urlToOpen string) error {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", urlToOpen)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", urlToOpen)
	default: // Linux and others
		cmd = exec.Command("xdg-open", urlToOpen)
	}
	
	app.logger.Debug("Opening URL in browser", "url", urlToOpen)
	return cmd.Start()
}

// FetchRDSMetrics retrieves and formats RDS metrics for the current tab
func (app *MonitoringApp) FetchRDSMetrics() string {
	tab := app.getCurrentTab()
	if tab == nil || tab.Type != "databases" {
		return "No databases selected"
	}

	rdsInstances, ok := tab.Resource.([]RDSInstanceConfig)
	if !ok {
		return "Invalid databases configuration"
	}

	if len(rdsInstances) == 0 {
		return "No RDS instances configured"
	}

	var sb strings.Builder
	
	sb.WriteString(app.colorize(ColorCyan, fmt.Sprintf("Database Metrics (%d instances)", len(rdsInstances))))
	sb.WriteString("\n\n")

	for i, rdsConfig := range rdsInstances {
		if i > 0 {
			sb.WriteString("\n")
		}
		
		// Make the database name clickable
		dbNameStr := fmt.Sprintf("=== %s (%s) ===", rdsConfig.DisplayName, rdsConfig.Identifier)
		sb.WriteString(app.colorize(ColorBold+ColorLink, dbNameStr))
		sb.WriteString(" [click to open in AWS Console]")
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("%-20s | %-15s | %-10s | %s\n", "Metric", "Value", "Status", "Unit"))
		sb.WriteString(strings.Repeat("-", 65) + "\n")

		for _, metric := range app.config.Metrics {
			value, err := app.getLatestMetricValue(metric.Name, rdsConfig.Identifier)
			if err != nil {
				sb.WriteString(fmt.Sprintf("%-20s | %-15s | %s | %s\n",
					metric.Name, "N/A", app.colorize(ColorRed, "Error"), metric.Unit))
				continue
			}

			coloredValue, status := app.colorizeMetric(metric.Name, value)
			
			sb.WriteString(fmt.Sprintf("%-20s | %-15s | %-10s | %s\n",
				metric.Name, coloredValue, status, metric.Unit))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(app.colorize(ColorBlue, fmt.Sprintf("Last updated: %s", time.Now().Format("15:04:05"))))
	sb.WriteString("\n")
	sb.WriteString(app.colorize(ColorPurple, "Tab/←→: Switch tabs | r: Refresh | q: Quit | Click: Open in AWS Console"))
	
	return sb.String()
}

// colorize applies color to text if colors are enabled
func (app *MonitoringApp) colorize(color, text string) string {
	if !app.config.UI.Colors.Enabled {
		return text
	}
	return fmt.Sprintf("%s%s%s", color, text, ColorReset)
}

// colorizeMetric applies color coding based on metric thresholds
func (app *MonitoringApp) colorizeMetric(metricName string, value float64) (string, string) {
	var color string
	var status string
	var critical, warning float64

	switch metricName {
	case "CPUUtilization":
		critical = app.config.Thresholds.CPU.Critical
		warning = app.config.Thresholds.CPU.Warning
	case "DatabaseConnections":
		critical = app.config.Thresholds.Connections.Critical
		warning = app.config.Thresholds.Connections.Warning
	case "ReadIOPS", "WriteIOPS":
		critical = app.config.Thresholds.IOPS.Critical
		warning = app.config.Thresholds.IOPS.Warning
	default:
		return fmt.Sprintf("%.2f", value), "Unknown"
	}

	if value >= critical {
		color = ColorRed
		status = "Critical"
	} else if value >= warning {
		color = ColorYellow
		status = "Warning"
	} else {
		color = ColorGreen
		status = "OK"
	}

	// Find the appropriate metric config for formatting
	var format string = "%.2f"
	for _, metric := range app.config.Metrics {
		if metric.Name == metricName {
			format = metric.Format
			break
		}
	}

	coloredValue := app.colorize(color, fmt.Sprintf(format, value))
	coloredStatus := app.colorize(color, status)
	
	return coloredValue, coloredStatus
}

// getLatestMetricValue retrieves the latest value for a specific metric
func (app *MonitoringApp) getLatestMetricValue(metricName, dbInstance string) (float64, error) {
	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String(metricName),
		Dimensions: []cwTypes.Dimension{{
			Name:  aws.String("DBInstanceIdentifier"),
			Value: aws.String(dbInstance),
		}},
		StartTime:  aws.Time(time.Now().Add(-app.config.GetMetricLookback())),
		EndTime:    aws.Time(time.Now()),
		Period:     aws.Int32(app.config.MetricPeriodSeconds),
		Statistics: []cwTypes.Statistic{cwTypes.StatisticAverage},
	}

	result, err := app.clients.CloudWatch.GetMetricStatistics(app.ctx, input)
	if err != nil {
		return 0, fmt.Errorf("failed to get metric %s: %w", metricName, err)
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no datapoints found for metric %s", metricName)
	}

	// Find the latest datapoint
	latest := result.Datapoints[0]
	for _, dp := range result.Datapoints {
		if dp.Timestamp.After(*latest.Timestamp) {
			latest = dp
		}
	}

	return *latest.Average, nil
}

// FetchLogEvents retrieves new log events for the current tab
func (app *MonitoringApp) FetchLogEvents() error {
	tab := app.getCurrentTab()
	if tab == nil {
		return fmt.Errorf("no active tab")
	}

	if tab.Type == "logs" {
		return app.fetchLogEventsForTab(tab)
	}

	return nil
}

// fetchLogEventsForTab retrieves log events for a specific tab
func (app *MonitoringApp) fetchLogEventsForTab(tab *ResourceTab) error {
	lgConfig, ok := tab.Resource.(LogGroupConfig)
	if !ok {
		return fmt.Errorf("invalid log group configuration")
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(lgConfig.Name),
		NextToken:    tab.LastToken,
		StartTime:    aws.Int64(time.Now().Add(-1 * time.Hour).UnixMilli()),
	}

	output, err := app.clients.CloudWatchLogs.FilterLogEvents(app.ctx, input)
	if err != nil {
		errorEvent := LogEvent{
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("Error fetching logs: %v", err),
			Formatted: fmt.Sprintf("[%s] %s: %v", 
				time.Now().Format("15:04:05"), 
				app.colorize(ColorRed, "ERROR"), err),
		}
		app.addLogEventToTab(tab, errorEvent)
		return err
	}

	for _, event := range output.Events {
		logEvent := LogEvent{
			Timestamp: time.UnixMilli(*event.Timestamp),
			Message:   aws.ToString(event.Message),
		}
		logEvent.Formatted = app.formatLogEvent(logEvent)
		app.addLogEventToTab(tab, logEvent)
	}

	tab.LastToken = output.NextToken
	return nil
}

// formatLogEvent formats a log event with timestamp and optional highlighting
func (app *MonitoringApp) formatLogEvent(event LogEvent) string {
	timestamp := event.Timestamp.Format("15:04:05")
	message := event.Message

	// Add color coding for different log levels
	upperMessage := strings.ToUpper(message)
	if strings.Contains(upperMessage, "ERROR") || strings.Contains(upperMessage, "FATAL") {
		return fmt.Sprintf("[%s] %s", timestamp, app.colorize(ColorRed, message))
	} else if strings.Contains(upperMessage, "WARN") {
		return fmt.Sprintf("[%s] %s", timestamp, app.colorize(ColorYellow, message))
	} else if strings.Contains(upperMessage, "INFO") {
		return fmt.Sprintf("[%s] %s", timestamp, app.colorize(ColorGreen, message))
	} else if strings.Contains(upperMessage, "DEBUG") {
		return fmt.Sprintf("[%s] %s", timestamp, app.colorize(ColorBlue, message))
	}
	
	return fmt.Sprintf("[%s] %s", timestamp, message)
}

// addLogEventToTab adds a new log event to a specific tab's buffer
func (app *MonitoringApp) addLogEventToTab(tab *ResourceTab, event LogEvent) {
	tab.LogBuffer = append(tab.LogBuffer, event)
	if len(tab.LogBuffer) > app.config.BufferSize {
		tab.LogBuffer = tab.LogBuffer[1:]
	}
}

// updateMetricsView refreshes the metrics display
func (app *MonitoringApp) updateMetricsView() {
	app.gui.Update(func(gui *gocui.Gui) error {
		if v, err := gui.View("metrics"); err == nil {
			v.Clear()
			fmt.Fprint(v, app.FetchRDSMetrics())
		}
		return nil
	})
}

// updateLogsView refreshes the logs display
func (app *MonitoringApp) updateLogsView() {
	app.gui.Update(func(gui *gocui.Gui) error {
		if v, err := gui.View("logs"); err == nil {
			v.Clear()
			tab := app.getCurrentTab()
			if tab != nil {
				_, height := v.Size()
				
				start := tab.LogOffset
				if start < 0 {
					start = 0
				}
				
				end := start + height - 1
				if end > len(tab.LogBuffer) {
					end = len(tab.LogBuffer)
				}
				
				for i := start; i < end && i < len(tab.LogBuffer); i++ {
					fmt.Fprintln(v, tab.LogBuffer[i].Formatted)
				}
				
				// Show scroll indicator
				if len(tab.LogBuffer) > height-1 {
					scrollInfo := fmt.Sprintf(" [%d/%d] ", start+1, len(tab.LogBuffer))
					if v.Title != "" {
						parts := strings.Split(v.Title, " [")
						baseTitle := parts[0]
						
						// Add clickable indicator for log groups
						if tab.Type == "logs" {
							if lgConfig, ok := tab.Resource.(LogGroupConfig); ok {
								baseTitle = fmt.Sprintf(" CloudWatch Logs - %s ", 
									app.colorize(ColorLink, lgConfig.DisplayName))
								baseTitle += " [click to open in AWS Console]"
							}
						}
						
						v.Title = baseTitle + app.colorize(ColorCyan, scrollInfo)
					}
				}
			}
		}
		return nil
	})
}

// updateTabBar refreshes the tab bar display
func (app *MonitoringApp) updateTabBar() {
	app.gui.Update(func(gui *gocui.Gui) error {
		if v, err := gui.View("tabs"); err == nil {
			v.Clear()
			
			var tabNames []string
			for i, tab := range app.tabs {
				name := tab.DisplayName
				if i == app.currentTab {
					name = app.colorize(ColorBold+ColorCyan, fmt.Sprintf("[%s]", name))
				} else {
					name = fmt.Sprintf(" %s ", name)
				}
				tabNames = append(tabNames, name)
			}
			
			fmt.Fprint(v, strings.Join(tabNames, " | "))
		}
		return nil
	})
}

// layout defines the GUI layout
func (app *MonitoringApp) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	
	tabHeight := 0
	if app.config.UI.Layout.ShowTabs && len(app.tabs) > 1 {
		tabHeight = 2
		// Tab bar
		if v, err := g.SetView("tabs", 0, 0, maxX-1, tabHeight); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Frame = true
			v.Title = " Tabs "
		}
	}
	
	tab := app.getCurrentTab()
	if tab == nil {
		return nil
	}
	
	splitX := int(float64(maxX) * app.config.UI.Layout.SplitRatio)
	
	if tab.Type == "databases" {
		// Metrics view (left side)
		if v, err := g.SetView("metrics", 0, tabHeight, splitX-1, maxY-1); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Title = fmt.Sprintf(" %s ", tab.DisplayName)
			v.Wrap = true
			v.Frame = true
		}
		
		// Logs view (right side) - placeholder for database logs if needed
		if v, err := g.SetView("logs", splitX, tabHeight, maxX-1, maxY-1); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Title = " Database Logs (if available) "
			v.Wrap = true
			v.Frame = true
		}
	} else if tab.Type == "logs" {
		// Full width logs view for log groups
		if v, err := g.SetView("logs", 0, tabHeight, maxX-1, maxY-1); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Title = fmt.Sprintf(" CloudWatch Logs - %s ", tab.DisplayName)
			v.Wrap = true
			v.Frame = true
			v.Autoscroll = false
		}
	}
	
	return nil
}

// setupKeybindings configures keyboard shortcuts based on configuration
func (app *MonitoringApp) setupKeybindings() error {
	// Quit application - support multiple keys from config
	for _, key := range app.config.UI.QuitKeys {
		switch key {
		case "Ctrl+C":
			if err := app.gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, app.quit); err != nil {
				return err
			}
		case "q":
			if err := app.gui.SetKeybinding("", 'q', gocui.ModNone, app.quit); err != nil {
				return err
			}
		}
	}
	
	// Refresh - support multiple keys from config
	for _, key := range app.config.UI.RefreshKeys {
		switch key {
		case "r":
			if err := app.gui.SetKeybinding("", 'r', gocui.ModNone, app.refresh); err != nil {
				return err
			}
		case "F5":
			if err := app.gui.SetKeybinding("", gocui.KeyF5, gocui.ModNone, app.refresh); err != nil {
				return err
			}
		}
	}
	
	// Tab navigation - simplified to basic keys
	if err := app.gui.SetKeybinding("", gocui.KeyTab, gocui.ModNone, app.nextTabHandler); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("", gocui.KeyArrowRight, gocui.ModNone, app.nextTabHandler); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("", gocui.KeyArrowLeft, gocui.ModNone, app.prevTabHandler); err != nil {
		return err
	}
	
	// Log navigation
	if err := app.gui.SetKeybinding("logs", gocui.KeyArrowUp, gocui.ModNone, app.scrollLogsUp); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("logs", gocui.KeyArrowDown, gocui.ModNone, app.scrollLogsDown); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("logs", gocui.KeyPgup, gocui.ModNone, app.pageLogsUp); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("logs", gocui.KeyPgdn, gocui.ModNone, app.pageLogsDown); err != nil {
		return err
	}
	
	// Mouse click handlers for opening resources in AWS Console
	if err := app.gui.SetKeybinding("metrics", gocui.MouseLeft, gocui.ModNone, app.handleMetricsClick); err != nil {
		return err
	}
	if err := app.gui.SetKeybinding("logs", gocui.MouseLeft, gocui.ModNone, app.handleLogsClick); err != nil {
		return err
	}
	
	return nil
}

// handleMetricsClick handles mouse clicks in the metrics view
func (app *MonitoringApp) handleMetricsClick(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab == nil || tab.Type != "databases" {
		return nil
	}
	
	// Get mouse position
	_, cy := v.Cursor()
	line, err := v.Line(cy)
	if err != nil {
		return nil
	}
	
	// Check if the line contains a database header
	if strings.Contains(line, "===") && strings.Contains(line, "[click to open in AWS Console]") {
		rdsInstances, ok := tab.Resource.([]RDSInstanceConfig)
		if !ok {
			return nil
		}
		
		// Find which database was clicked
		for _, rdsConfig := range rdsInstances {
			if strings.Contains(line, rdsConfig.DisplayName) && strings.Contains(line, rdsConfig.Identifier) {
				url := app.generateRDSConsoleURL(rdsConfig)
				app.logger.Info("Opening RDS instance in AWS Console", 
					"instance", rdsConfig.Identifier, 
					"url", url)
				return app.openURL(url)
			}
		}
	}
	
	return nil
}

// handleLogsClick handles mouse clicks in the logs view
func (app *MonitoringApp) handleLogsClick(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab == nil {
		return nil
	}
	
	// Check if the title was clicked (approximate)
	_, cy := v.Cursor()
	if cy == 0 && tab.Type == "logs" {
		if lgConfig, ok := tab.Resource.(LogGroupConfig); ok {
			url := app.generateLogGroupConsoleURL(lgConfig)
			app.logger.Info("Opening Log Group in AWS Console", 
				"logGroup", lgConfig.Name, 
				"url", url)
			return app.openURL(url)
		}
	}
	
	return nil
}

// Event handlers
func (app *MonitoringApp) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (app *MonitoringApp) nextTabHandler(g *gocui.Gui, v *gocui.View) error {
	app.nextTab()
	app.updateTabBar()
	app.updateMetricsView()
	app.updateLogsView()
	return nil
}

func (app *MonitoringApp) prevTabHandler(g *gocui.Gui, v *gocui.View) error {
	app.prevTab()
	app.updateTabBar()
	app.updateMetricsView()
	app.updateLogsView()
	return nil
}

func (app *MonitoringApp) scrollLogsUp(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab != nil {
		tab.LogOffset--
		if tab.LogOffset < 0 {
			tab.LogOffset = 0
		}
		app.updateLogsView()
	}
	return nil
}

func (app *MonitoringApp) scrollLogsDown(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab != nil {
		if v, err := app.gui.View("logs"); err == nil {
			_, height := v.Size()
			tab.LogOffset++
			maxOffset := len(tab.LogBuffer) - (height - 1)
			if maxOffset < 0 {
				maxOffset = 0
			}
			if tab.LogOffset > maxOffset {
				tab.LogOffset = maxOffset
			}
		}
		app.updateLogsView()
	}
	return nil
}

func (app *MonitoringApp) pageLogsUp(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab != nil {
		if v, err := app.gui.View("logs"); err == nil {
			_, height := v.Size()
			tab.LogOffset -= height - 1
			if tab.LogOffset < 0 {
				tab.LogOffset = 0
			}
		}
		app.updateLogsView()
	}
	return nil
}

func (app *MonitoringApp) pageLogsDown(g *gocui.Gui, v *gocui.View) error {
	tab := app.getCurrentTab()
	if tab != nil {
		if v, err := app.gui.View("logs"); err == nil {
			_, height := v.Size()
			tab.LogOffset += height - 1
			maxOffset := len(tab.LogBuffer) - (height - 1)
			if maxOffset < 0 {
				maxOffset = 0
			}
			if tab.LogOffset > maxOffset {
				tab.LogOffset = maxOffset
			}
		}
		app.updateLogsView()
	}
	return nil
}

func (app *MonitoringApp) refresh(g *gocui.Gui, v *gocui.View) error {
	go func() {
		app.updateMetricsView()
		app.FetchLogEvents()
		app.updateLogsView()
	}()
	return nil
}

// startBackgroundTasks starts the periodic update goroutines
func (app *MonitoringApp) startBackgroundTasks() {
	// Metrics updater
	go func() {
		ticker := time.NewTicker(app.config.GetMetricsInterval())
		defer ticker.Stop()
		
		for {
			select {
			case <-app.ctx.Done():
				return
			case <-ticker.C:
				app.updateMetricsView()
			}
		}
	}()
	
	// Logs updater
	go func() {
		ticker := time.NewTicker(app.config.GetLogsInterval())
		defer ticker.Stop()
		
		for {
			select {
			case <-app.ctx.Done():
				return
			case <-ticker.C:
				// Fetch logs for all log group tabs
				for _, tab := range app.tabs {
					if tab.Type == "logs" {
						app.fetchLogEventsForTab(tab)
					}
				}
				app.updateLogsView()
			}
		}
	}()
	
	// Resource discovery updater
	if app.config.AutoDiscovery.Enabled {
		go func() {
			ticker := time.NewTicker(app.config.GetDiscoveryInterval())
			defer ticker.Stop()
			
			for {
				select {
				case <-app.ctx.Done():
					return
				case <-ticker.C:
					if err := app.discoverResources(); err != nil {
						app.logger.Error("Resource discovery error", "error", err)
					}
					app.updateTabBar()
				}
			}
		}()
	}
	
	// Configuration reload updater
	go func() {
		ticker := time.NewTicker(app.config.GetConfigReloadInterval())
		defer ticker.Stop()
		
		for {
			select {
			case <-app.ctx.Done():
				return
			case <-ticker.C:
				if err := app.reloadConfiguration(); err != nil {
					app.logger.Error("Config reload error", "error", err)
				}
			}
		}
	}()
}

// Run starts the monitoring application
func (app *MonitoringApp) Run() error {
	defer app.gui.Close()
	defer app.cancel()
	
	app.gui.SetManagerFunc(app.layout)
	
	if err := app.setupKeybindings(); err != nil {
		return fmt.Errorf("failed to setup keybindings: %w", err)
	}
	
	// Initial resource discovery
	if app.config.AutoDiscovery.Enabled {
		if err := app.discoverResources(); err != nil {
			app.logger.Error("Initial resource discovery failed", "error", err)
		}
	}
	
	// Initial data fetch
	app.updateTabBar()
	app.updateMetricsView()
	app.FetchLogEvents()
	app.updateLogsView()
	
	// Start background tasks
	app.startBackgroundTasks()
	
	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		app.cancel()
		app.gui.Update(func(g *gocui.Gui) error {
			return gocui.ErrQuit
		})
	}()
	
	// Run the main loop
	if err := app.gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		return fmt.Errorf("GUI error: %w", err)
	}
	
	return nil
}

func main() {
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	
	// Create a temporary logger for startup
	tempLogger := log.NewWithOptions(os.Stdout, log.Options{
		ReportCaller:    false,
		ReportTimestamp: true,
		TimeFormat:      "2006-01-02 15:04:05",
	})
	
	app, err := NewMonitoringApp(configFile)
	if err != nil {
		tempLogger.Fatal("Failed to create monitoring app", "error", err)
	}
	
	app.logger.Info("Starting AWS CloudWatch Monitor",
		"config", configFile,
		"rds_instances", len(app.config.Resources.RDSInstances),
		"log_groups", len(app.config.Resources.LogGroups),
		"total_tabs", len(app.tabs))
	
	if err := app.Run(); err != nil {
		app.logger.Fatal("Application error", "error", err)
	}
}
