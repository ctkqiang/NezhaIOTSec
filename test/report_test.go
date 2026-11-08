package test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/report"
)

func findingsFixture() []model.Finding {
	return []model.Finding{
		{
			IP:       "10.0.0.1",
			Port:     502,
			Service:  "Modbus-TCP",
			Severity: model.SeverityHigh,
			Detail:   "Modbus PLC Confirmed (FC 0x2B device identification)",
			MAC:      "aa:bb:cc:dd:ee:01",
			FoundAt:  time.Now().UTC(),
		},
		{
			IP:       "10.0.0.2",
			Port:     1883,
			Service:  "MQTT",
			Severity: model.SeverityCritical,
			Detail:   "CRITICAL: Unauthenticated MQTT Broker Access Allowed",
			FoundAt:  time.Now().UTC(),
		},
	}
}

func TestDisplayWidth(t *testing.T) {
	t.Parallel()

	cases := map[string]int{
		"":      0,
		"abc":   3,
		"IP 地址": 7,
		"服务":    4,
		"日本語":   6,
		"a中b":   4,
	}

	for input, want := range cases {
		if got := report.DisplayWidth(input); got != want {
			t.Fatalf("DisplayWidth(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestPadRight(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		width int
		want  string
	}{
		{"ab", 4, "ab  "},
		{"中", 4, "中  "},
		{"abcd", 2, "abcd"},
		{"", 3, "   "},
	}

	for _, tc := range cases {
		if got := report.PadRight(tc.input, tc.width); got != tc.want {
			t.Fatalf("PadRight(%q, %d) = %q, want %q", tc.input, tc.width, got, tc.want)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	if err := report.Render(&buffer, nil, report.Options{}); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if buffer.Len() != 0 {
		t.Fatalf("empty input wrote %q", buffer.String())
	}
}

func TestRenderTable(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	if err := report.Render(&buffer, findingsFixture(), report.Options{ShowMAC: true}); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	table := buffer.String()

	for _, want := range []string{
		"IP 地址",
		"服务",
		"严重性",
		"MAC",
		"Modbus-TCP",
		"MQTT",
		"critical",
		"aa:bb:cc:dd:ee:01",
		"CRITICAL: Unauthenticated MQTT Broker Access Allowed",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("rendered table is missing %q:\n%s", want, table)
		}
	}

	if strings.Contains(table, "\x1b[") {
		t.Fatalf("colour must stay off when disabled:\n%s", table)
	}

	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected blank line + header + rule + 2 rows, got %d lines:\n%s",
			len(lines), table)
	}
}

func TestRenderColour(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	if err := report.Render(&buffer, findingsFixture(), report.Options{Color: true}); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	table := buffer.String()

	if !strings.Contains(table, "\x1b[33m") {
		t.Fatalf("high severity should be yellow:\n%s", table)
	}

	if !strings.Contains(table, "\x1b[31m") {
		t.Fatalf("critical severity should be red:\n%s", table)
	}

	if strings.Contains(table, "aa:bb:cc") {
		t.Fatalf("mac must be hidden when ShowMAC is false:\n%s", table)
	}
}

func TestRenderJSON(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	if err := report.RenderJSON(&buffer, findingsFixture()); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buffer.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines, got %d:\n%s", len(lines), buffer.String())
	}

	for i, line := range lines {
		var decoded model.Finding
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line %d is not valid json: %v", i, err)
		}

		if decoded.IP == "" {
			t.Fatalf("line %d lost the ip", i)
		}
	}

	if !strings.Contains(buffer.String(), `"severity":"critical"`) {
		t.Fatalf("severity must marshal as a name:\n%s", buffer.String())
	}
}
