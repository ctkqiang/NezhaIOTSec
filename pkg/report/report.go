package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"nezha_iot_sec/pkg/model"
)

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"

	headerIP       = "IP 地址"
	headerService  = "服务"
	headerSeverity = "严重性"
	headerDetail   = "详情"
	headerMAC      = "MAC"

	columnGap = "  "
	rowIndent = "  "
)

type Options struct {
	Color   bool
	ShowMAC bool
}

func Render(w io.Writer, findings []model.Finding, opts Options) error {
	if len(findings) == 0 {
		return nil
	}

	headers := []string{headerIP, headerService, headerSeverity}
	widths := []int{
		DisplayWidth(headerIP),
		DisplayWidth(headerService),
		DisplayWidth(headerSeverity),
	}

	if opts.ShowMAC {
		headers = append(headers, headerMAC)
		widths = append(widths, DisplayWidth(headerMAC))
	}

	for _, finding := range findings {
		widths[0] = max(widths[0], DisplayWidth(finding.IP))
		widths[1] = max(widths[1], DisplayWidth(finding.Service))
		widths[2] = max(widths[2], DisplayWidth(finding.Severity.String()))
		if opts.ShowMAC {
			widths[len(widths)-1] = max(widths[len(widths)-1], DisplayWidth(finding.MAC))
		}
	}

	var b strings.Builder
	b.WriteString("\n")
	writeRow(&b, paddedCells(headers, widths))
	writeRule(&b, widths)

	for _, finding := range findings {
		cells := []string{finding.IP, finding.Service, finding.Severity.String()}
		if opts.ShowMAC {
			cells = append(cells, finding.MAC)
		}

		padded := paddedCells(cells, widths)
		padded[2] = colorize(padded[2], finding.Severity, opts.Color)
		padded = append(padded, finding.Detail)

		writeRow(&b, padded)
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("report: write table: %w", err)
	}

	return nil
}

func RenderJSON(w io.Writer, findings []model.Finding) error {
	encoder := json.NewEncoder(w)

	for _, finding := range findings {
		if err := encoder.Encode(finding); err != nil {
			return fmt.Errorf("report: encode finding: %w", err)
		}
	}

	return nil
}

func paddedCells(cells []string, widths []int) []string {
	padded := make([]string, len(cells))

	for i, cell := range cells {
		padded[i] = PadRight(cell, widths[i])
	}

	return padded
}

func writeRow(b *strings.Builder, cells []string) {
	b.WriteString(rowIndent)

	for i, cell := range cells {
		if i > 0 {
			b.WriteString(columnGap)
		}

		b.WriteString(cell)
	}

	b.WriteString("\n")
}

func writeRule(b *strings.Builder, widths []int) {
	b.WriteString(rowIndent)

	for i, width := range widths {
		if i > 0 {
			b.WriteString(columnGap)
		}

		b.WriteString(strings.Repeat("─", width))
	}

	b.WriteString(columnGap)
	b.WriteString(strings.Repeat("─", DisplayWidth(headerDetail)))
	b.WriteString("\n")
}

func colorize(cell string, severity model.Severity, enabled bool) string {
	if !enabled {
		return cell
	}

	colour := ""

	switch severity {
	case model.SeverityCritical:
		colour = ansiRed
	case model.SeverityHigh:
		colour = ansiYellow
	default:
		colour = ansiCyan
	}

	return colour + cell + ansiReset
}

func DisplayWidth(s string) int {
	width := 0

	for _, r := range s {
		if IsWide(r) {
			width += 2
			continue
		}

		width++
	}

	return width
}

func IsWide(r rune) bool {
	return r >= 0x1100 && (r <= 0x115f ||
		r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x20000 && r <= 0x2fffd) ||
		(r >= 0x30000 && r <= 0x3fffd))
}

func PadRight(s string, width int) string {
	if gap := width - DisplayWidth(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}

	return s
}
