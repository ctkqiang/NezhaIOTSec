package model

import (
	"encoding/json"
	"fmt"
	"time"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("model: severity must be a string: %w", err)
	}

	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}

	*s = parsed
	return nil
}

func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "", "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("model: invalid severity %q", s)
	}
}

type Finding struct {
	IP       string    `json:"ip"`
	Port     int       `json:"port"`
	Service  string    `json:"service"`
	Severity Severity  `json:"severity"`
	Detail   string    `json:"detail"`
	MAC      string    `json:"mac,omitempty"`
	FoundAt  time.Time `json:"found_at"`
}
