// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package logging

import (
	"context"
	"io"
	"log/slog"
)

type contextKey struct{}

var loggerKey = contextKey{}

// FromContext returns a logger from context, or a no-op logger if none exists.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return noopLogger()
}

// ToContext adds a logger to the context.
func ToContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// noopLogger returns a logger that discards all output.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
