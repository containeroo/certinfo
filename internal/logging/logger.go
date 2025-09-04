package logging

import (
	"io"
	"log/slog"
)

// SetupLogger configures and returns a slog logger with a text handler.
// Use handler options (level, etc.) to control verbosity.
func SetupLogger(output io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{
		Level: level,
	}))
}
