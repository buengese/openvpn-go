// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package logging

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

//nolint:gochecknoglobals // Globals are ok for logging imho.
var (
	once   sync.Once
	logger zerolog.Logger
)

// GetLogger returns a logger instance.
func GetLogger() *zerolog.Logger {
	once.Do(func() {
		zerolog.TimeFieldFormat = time.RFC3339Nano
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack //nolint:reassign // Same here.

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}

		logger = zerolog.New(output).
			Level(zerolog.TraceLevel).
			With().
			Timestamp().
			Logger()

		zerolog.DefaultContextLogger = &logger
	})
	return &logger
}
