// Package logging configures a process-wide zerolog logger.
package logging

import (
	"os"
	"time"

	"blocky/internal/config"
	"github.com/rs/zerolog"
)

// New builds a zerolog.Logger from config. Format is json or console; level is the
// usual zerolog levels (debug|info|warn|error|fatal).
func New(cfg config.Config) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	var out zerolog.Logger
	if cfg.LogFormat == "console" {
		out = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	} else {
		out = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}
	return out.Level(level)
}
