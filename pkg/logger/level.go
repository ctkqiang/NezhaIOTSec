package logger

import (
	"fmt"
	"strings"
)

type Level uint8

const (
	LevelAlways Level = iota
	LevelError
	LevelWarning
	LevelInfo
	LevelDebug
	LevelVerbose
)

const (
	MinLevel = LevelAlways
	MaxLevel = LevelVerbose
)

func (l Level) String() string {
	switch l {
	case LevelAlways:
		return "always"
	case LevelError:
		return "error"
	case LevelWarning:
		return "warning"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	case LevelVerbose:
		return "verbose"
	default:
		return fmt.Sprintf("level(%d)", uint8(l))
	}
}

func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "always":
		return LevelAlways, nil
	case "1", "error", "err":
		return LevelError, nil
	case "2", "warning", "warn":
		return LevelWarning, nil
	case "3", "info":
		return LevelInfo, nil
	case "4", "debug":
		return LevelDebug, nil
	case "5", "verbose", "all":
		return LevelVerbose, nil
	default:
		return LevelAlways, fmt.Errorf("logger: invalid level %q, must be between 0 and 5", s)
	}
}

func (l Level) Valid() bool {
	return l <= MaxLevel
}

func (l Level) Enabled(threshold Level) bool {
	return l == LevelAlways || l <= threshold
}
