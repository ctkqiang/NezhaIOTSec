package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
)

const (
	prefixBad     = "[-]"
	prefixGood    = "[+]"
	prefixStatus  = "[*]"
	prefixWarning = "[!]"
	prefixDebug   = "[D]"
	prefixVerbose = "[V]"
)

type Logger struct {
	mu        sync.Mutex
	out       io.Writer
	errOut    io.Writer
	level     atomic.Int32
	color     atomic.Bool
	timestamp atomic.Bool
}

func New(out, errOut io.Writer) *Logger {
	l := &Logger{out: out, errOut: errOut}
	l.level.Store(int32(LevelVerbose))
	l.color.Store(isTerminal(out))
	return l
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (l *Logger) Level() Level {
	return Level(l.level.Load())
}

func (l *Logger) SetLevel(level Level) {
	if !level.Valid() {
		level = MaxLevel
	}
	l.level.Store(int32(level))
}

func (l *Logger) Enabled(level Level) bool {
	return level.Enabled(l.Level())
}

func (l *Logger) Color() bool {
	return l.color.Load()
}

func (l *Logger) SetColor(enabled bool) {
	l.color.Store(enabled)
}

func (l *Logger) SetTimestamp(enabled bool) {
	l.timestamp.Store(enabled)
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

func (l *Logger) SetErrorOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errOut = w
}

func (l *Logger) emit(errOut bool, level Level, color, prefix, msg string) {
	if !level.Enabled(l.Level()) {
		return
	}

	var b strings.Builder
	if l.timestamp.Load() {
		b.WriteString(time.Now().Format("[2006-01-02 15:04:05] "))
	}
	colored := l.color.Load() && color != ""
	if colored {
		b.WriteString(ansiBold)
		b.WriteString(color)
	}
	if prefix != "" {
		b.WriteString(prefix)
	}
	if colored {
		b.WriteString(ansiReset)
	}
	if prefix != "" {
		b.WriteString(" ")
	}
	b.WriteString(msg)
	b.WriteString("\n")

	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.out
	if errOut {
		w = l.errOut
	}
	fmt.Fprint(w, b.String())
}

func sprintf(format string, args []any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

func (l *Logger) PrintError(format string, args ...any) {
	l.emit(true, LevelError, ansiRed, prefixBad, sprintf(format, args))
}

func (l *Logger) PrintBad(format string, args ...any) {
	l.emit(true, LevelError, ansiRed, prefixBad, sprintf(format, args))
}

func (l *Logger) PrintWarning(format string, args ...any) {
	l.emit(false, LevelWarning, ansiYellow, prefixWarning, sprintf(format, args))
}

func (l *Logger) PrintStatus(format string, args ...any) {
	l.emit(false, LevelInfo, ansiBlue, prefixStatus, sprintf(format, args))
}

func (l *Logger) PrintGood(format string, args ...any) {
	l.emit(false, LevelAlways, ansiGreen, prefixGood, sprintf(format, args))
}

func (l *Logger) PrintDebug(format string, args ...any) {
	l.emit(false, LevelDebug, ansiCyan, prefixDebug, sprintf(format, args))
}

func (l *Logger) PrintVerbose(format string, args ...any) {
	l.emit(false, LevelVerbose, ansiMagenta, prefixVerbose, sprintf(format, args))
}

func (l *Logger) PrintLine(format string, args ...any) {
	l.emit(false, LevelAlways, "", "", sprintf(format, args))
}

func (l *Logger) PrintRaw(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.out, msg)
}

func (l *Logger) Log(level Level, format string, args ...any) {
	switch level {
	case LevelError:
		l.PrintError(format, args...)
	case LevelWarning:
		l.PrintWarning(format, args...)
	case LevelInfo:
		l.PrintStatus(format, args...)
	case LevelDebug:
		l.PrintDebug(format, args...)
	case LevelVerbose:
		l.PrintVerbose(format, args...)
	default:
		l.PrintLine(format, args...)
	}
}

var std = New(os.Stdout, os.Stderr)

func Default() *Logger {
	return std
}

func SetLevel(level Level) {
	std.SetLevel(level)
}

func GetLevel() Level {
	return std.Level()
}

func SetOutput(w io.Writer) {
	std.SetOutput(w)
}

func SetErrorOutput(w io.Writer) {
	std.SetErrorOutput(w)
}

func Color() bool {
	return std.Color()
}

func SetColor(enabled bool) {
	std.SetColor(enabled)
}

func SetTimestamp(enabled bool) {
	std.SetTimestamp(enabled)
}

func PrintError(format string, args ...any) {
	std.PrintError(format, args...)
}

func PrintBad(format string, args ...any) {
	std.PrintBad(format, args...)
}

func PrintWarning(format string, args ...any) {
	std.PrintWarning(format, args...)
}

func PrintStatus(format string, args ...any) {
	std.PrintStatus(format, args...)
}

func PrintGood(format string, args ...any) {
	std.PrintGood(format, args...)
}

func PrintDebug(format string, args ...any) {
	std.PrintDebug(format, args...)
}

func PrintVerbose(format string, args ...any) {
	std.PrintVerbose(format, args...)
}

func PrintLine(format string, args ...any) {
	std.PrintLine(format, args...)
}

func PrintRaw(msg string) {
	std.PrintRaw(msg)
}

func Log(level Level, format string, args ...any) {
	std.Log(level, format, args...)
}
