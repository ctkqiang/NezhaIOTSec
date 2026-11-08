package test

import (
	"testing"

	"nezha_iot_sec/pkg/logger"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  logger.Level
		fail  bool
	}{
		{"0", logger.LevelAlways, false},
		{"1", logger.LevelError, false},
		{"2", logger.LevelWarning, false},
		{"3", logger.LevelInfo, false},
		{"4", logger.LevelDebug, false},
		{"5", logger.LevelVerbose, false},
		{"always", logger.LevelAlways, false},
		{"ERROR", logger.LevelError, false},
		{"err", logger.LevelError, false},
		{"warn", logger.LevelWarning, false},
		{" info ", logger.LevelInfo, false},
		{"all", logger.LevelVerbose, false},
		{"", 0, true},
		{"6", 0, true},
		{"loud", 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got, err := logger.ParseLevel(tc.input)

			if tc.fail {
				if err == nil {
					t.Fatalf("ParseLevel(%q) expected error, got %v", tc.input, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseLevel(%q) unexpected error: %v", tc.input, err)
			}

			if got != tc.want {
				t.Fatalf("ParseLevel(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	t.Parallel()

	names := map[logger.Level]string{
		logger.LevelAlways:  "always",
		logger.LevelError:   "error",
		logger.LevelWarning: "warning",
		logger.LevelInfo:    "info",
		logger.LevelDebug:   "debug",
		logger.LevelVerbose: "verbose",
	}

	for level, want := range names {
		if got := level.String(); got != want {
			t.Fatalf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}

	if got := logger.Level(200).String(); got != "level(200)" {
		t.Fatalf("out of range String() = %q", got)
	}
}

func TestLevelEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		level     logger.Level
		threshold logger.Level
		want      bool
	}{
		{logger.LevelAlways, logger.LevelAlways, true},
		{logger.LevelError, logger.LevelAlways, false},
		{logger.LevelError, logger.LevelError, true},
		{logger.LevelInfo, logger.LevelWarning, false},
		{logger.LevelInfo, logger.LevelInfo, true},
		{logger.LevelVerbose, logger.LevelVerbose, true},
		{logger.LevelWarning, logger.LevelVerbose, true},
	}

	for _, tc := range cases {
		if got := tc.level.Enabled(tc.threshold); got != tc.want {
			t.Fatalf("Level(%s).Enabled(%s) = %v, want %v",
				tc.level, tc.threshold, got, tc.want)
		}
	}
}

func TestLevelValid(t *testing.T) {
	t.Parallel()

	if !logger.LevelVerbose.Valid() {
		t.Fatal("verbose must be valid")
	}

	if logger.Level(6).Valid() {
		t.Fatal("level 6 must be invalid")
	}

	if logger.MinLevel != logger.LevelAlways || logger.MaxLevel != logger.LevelVerbose {
		t.Fatalf("unexpected level bounds: %v..%v", logger.MinLevel, logger.MaxLevel)
	}
}
