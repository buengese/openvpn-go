// SPDX-License-Identifier: MIT
package logging

import (
	"context"
)

// Logger provides categorized logging for the OpenVPN library
type Logger struct {
	config *logConfig
}

// NewLogger creates a logger with the given options
func NewLogger(opts ...LogOption) *Logger {
	return &Logger{
		config: buildLogConfig(opts),
	}
}

// LogProcessOutput logs output from the OpenVPN process
func (l *Logger) LogProcessOutput(ctx context.Context, message string, args ...any) {
	if l.config.processOutput {
		l.config.logger.Log(ctx, l.config.processOutputLevel, message, args...)
	}
}

// LogManagementProto logs raw management interface protocol messages
func (l *Logger) LogManagementProto(ctx context.Context, message string, args ...any) {
	if l.config.managementProto {
		l.config.logger.Log(ctx, l.config.managementProtoLevel, message, args...)
	}
}

// LogLifecycle logs important lifecycle events (connection, state changes, etc.)
func (l *Logger) LogLifecycle(ctx context.Context, message string, args ...any) {
	if l.config.lifecycle {
		l.config.logger.Log(ctx, l.config.lifecycleLevel, message, args...)
	}
}

// LogError logs error messages (always enabled)
func (l *Logger) LogError(message string, args ...any) {
	l.config.logger.Error(message, args...)
}
