// SPDX-License-Identifier: MIT
package logging

import (
	"io"
	"log/slog"
	"os"
)

// LogOption represents a logging configuration option
type LogOption func(*logConfig)

// Internal config struct (not exported)
type logConfig struct {
	logger               *slog.Logger
	processOutput        bool
	managementProto      bool
	lifecycle            bool
	processOutputLevel   slog.Level
	managementProtoLevel slog.Level
	lifecycleLevel       slog.Level
}

// defaultLogConfig returns sensible defaults
func defaultLogConfig() *logConfig {
	return &logConfig{
		logger:               nil, // Will create default stderr logger
		processOutput:        false,
		managementProto:      false,
		lifecycle:            true, // Important events should be visible by default
		processOutputLevel:   slog.LevelDebug,
		managementProtoLevel: slog.LevelDebug,
		lifecycleLevel:       slog.LevelInfo,
	}
}

// WithLogger sets a custom logger
func WithLogger(logger *slog.Logger) LogOption {
	return func(c *logConfig) {
		c.logger = logger
	}
}

// WithProcessOutput enables logging of OpenVPN process stdout/stderr
func WithProcessOutput() LogOption {
	return func(c *logConfig) {
		c.processOutput = true
	}
}

// WithManagementProtocol enables logging of raw management interface messages
func WithManagementProtocol() LogOption {
	return func(c *logConfig) {
		c.managementProto = true
	}
}

// WithLifecycleLogging explicitly enables lifecycle event logging (enabled by default)
func WithLifecycleLogging() LogOption {
	return func(c *logConfig) {
		c.lifecycle = true
	}
}

// WithProcessOutputLevel sets the log level for process output
func WithProcessOutputLevel(level slog.Level) LogOption {
	return func(c *logConfig) {
		c.processOutputLevel = level
	}
}

// WithManagementProtocolLevel sets the log level for management protocol messages
func WithManagementProtocolLevel(level slog.Level) LogOption {
	return func(c *logConfig) {
		c.managementProtoLevel = level
	}
}

// WithLifecycleLevel sets the log level for lifecycle events
func WithLifecycleLevel(level slog.Level) LogOption {
	return func(c *logConfig) {
		c.lifecycleLevel = level
	}
}

// Preset option combinations

// WithSilentLogging disables all logging
func WithSilentLogging() LogOption {
	return func(c *logConfig) {
		c.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		c.processOutput = false
		c.managementProto = false
		c.lifecycle = false
	}
}

// WithVerboseLogging enables all logging categories
func WithVerboseLogging() LogOption {
	return func(c *logConfig) {
		c.processOutput = true
		c.managementProto = true
		c.lifecycle = true
	}
}

// buildLogConfig applies options to create a final config
func buildLogConfig(opts []LogOption) *logConfig {
	config := defaultLogConfig()

	for _, opt := range opts {
		opt(config)
	}

	// If no logger was provided, create a default one
	if config.logger == nil {
		config.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}

	return config
}
