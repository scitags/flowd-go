package types

import "log/slog"

type LogLevel slog.Level

const (
	LevelTrace = slog.Level(slog.LevelDebug - 1)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)
