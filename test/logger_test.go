package test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"nezha_iot_sec/pkg/logger"
)

func newBufferedLogger() (*logger.Logger, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer

	l := logger.New(&out, &errOut)
	l.SetColor(false)
	l.SetLevel(logger.LevelVerbose)

	return l, &out, &errOut
}

func TestLoggerPrefixes(t *testing.T) {
	t.Parallel()

	l, out, errOut := newBufferedLogger()

	l.PrintGood("good")
	l.PrintStatus("status")
	l.PrintWarning("warning")
	l.PrintDebug("debug")
	l.PrintVerbose("verbose")
	l.PrintLine("plain")
	l.PrintError("error")
	l.PrintBad("bad")

	stdout := out.String()
	stderr := errOut.String()

	expectations := map[string]string{
		"[+] good\n":    stdout,
		"[*] status\n":  stdout,
		"[!] warning\n": stdout,
		"[D] debug\n":   stdout,
		"[V] verbose\n": stdout,
		"plain\n":       stdout,
		"[-] error\n":   stderr,
		"[-] bad\n":     stderr,
	}

	for want, haystack := range expectations {
		if !strings.Contains(haystack, want) {
			t.Fatalf("missing %q in output:\n%s", want, haystack)
		}
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	t.Parallel()

	l, out, _ := newBufferedLogger()
	l.SetLevel(logger.LevelError)

	l.PrintStatus("should vanish")
	l.PrintDebug("should vanish too")
	l.PrintGood("must survive")
	l.PrintError("also survives")

	text := out.String()

	if strings.Contains(text, "should vanish") {
		t.Fatalf("filtered message leaked: %s", text)
	}

	if !strings.Contains(text, "must survive") {
		t.Fatalf("always level message was dropped: %s", text)
	}
}

func TestLoggerColorToggle(t *testing.T) {
	t.Parallel()

	l, out, _ := newBufferedLogger()

	l.SetColor(true)
	l.PrintStatus("with colour")

	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected ansi escape, got %q", out.String())
	}

	out.Reset()
	l.SetColor(false)
	l.PrintStatus("no colour")

	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("unexpected ansi escape: %q", out.String())
	}

	if l.Color() {
		t.Fatal("Color() must report false after SetColor(false)")
	}
}

func TestLoggerTimestamp(t *testing.T) {
	t.Parallel()

	l, out, _ := newBufferedLogger()
	l.SetTimestamp(true)
	l.PrintGood("stamped")

	if !regexp.MustCompile(`^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] `).MatchString(out.String()) {
		t.Fatalf("timestamp prefix missing: %q", out.String())
	}
}

func TestLoggerFormatting(t *testing.T) {
	t.Parallel()

	l, out, _ := newBufferedLogger()

	l.PrintStatus("host %s port %d", "10.0.0.1", 502)

	if !strings.Contains(out.String(), "host 10.0.0.1 port 502") {
		t.Fatalf("arguments were not interpolated: %q", out.String())
	}
}

func TestLoggerRawOutput(t *testing.T) {
	t.Parallel()

	l, out, _ := newBufferedLogger()
	l.PrintRaw("raw-without-newline")

	if out.String() != "raw-without-newline" {
		t.Fatalf("PrintRaw wrote %q", out.String())
	}
}

func TestLoggerLogDispatch(t *testing.T) {
	t.Parallel()

	l, out, errOut := newBufferedLogger()

	l.Log(logger.LevelDebug, "dispatched")
	l.Log(logger.LevelError, "dispatched-error")

	if !strings.Contains(out.String(), "[D] dispatched") {
		t.Fatalf("debug dispatch failed: %q", out.String())
	}

	if !strings.Contains(errOut.String(), "[-] dispatched-error") {
		t.Fatalf("error dispatch failed: %q", errOut.String())
	}
}
