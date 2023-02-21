package logging

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

const (
	// FileMaxSize is the maximum size of the log file in MB.
	FileMaxSize = 5
	// FileMaxAge is the maximum age of the log file in days.
	FileMaxAge = 14
)

//nolint:gochecknoglobals // Globals are ok for logging imho.
var (
	once   sync.Once
	logger zerolog.Logger
)

func Setup() {
	once.Do(func() {
		zerolog.TimeFieldFormat = time.RFC3339Nano
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack //nolint:reassign // Same here.

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		}

		logger = zerolog.New(output).
			Level(zerolog.DebugLevel).
			With().
			Timestamp().
			Logger()

		zerolog.DefaultContextLogger = &logger
	})
}
