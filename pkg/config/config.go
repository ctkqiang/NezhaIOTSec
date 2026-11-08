package config

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"nezha_iot_sec/pkg/logger"
)

type CryptoKeyMode string

const (
	CryptoKeyEphemeral  CryptoKeyMode = "ephemeral"
	CryptoKeyPassphrase CryptoKeyMode = "passphrase"
)

const (
	DefaultBridgeAddr = "127.0.0.1:7788"
	DefaultPorts      = "502,1883,80,554,47808"
	defaultWorkers    = 150
	maxWorkers        = 512
	maxProbeTimeout   = 10 * time.Second
	passphraseEnv     = "NEZHA_PASSPHRASE"
)

type Config struct {
	CIDR        string
	ARPOnly     bool
	Ports       []int
	Workers     int
	Timeout     time.Duration
	PortTimeout time.Duration

	Serve      bool
	BridgeAddr string
	BridgeOff  bool

	CryptoKeyMode CryptoKeyMode
	Passphrase    string
	EncryptWire   bool

	JSON     bool
	LogLevel logger.Level
	NoColor  bool
	Version  bool
}

func Parse(args []string, getenv func(string) string) (Config, error) {
	fs := flag.NewFlagSet("nezhaiot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		cidr        = fs.String("cidr", "", "target cidr, empty means auto-detect from the active interface")
		arpOnly     = fs.Bool("arp-only", false, "scan only hosts present in the kernel neighbor table")
		portsText   = fs.String("ports", DefaultPorts, "comma separated tcp ports")
		workers     = fs.Int("workers", defaultWorkers, "concurrent workers, clamped to 1..512")
		timeout     = fs.Duration("timeout", 300*time.Millisecond, "per probe timeout")
		portTimeout = fs.Duration("port-timeout", 200*time.Millisecond, "per generic tcp port timeout")
		serve       = fs.Bool("serve", false, "wait for bridge commands instead of scanning at startup")
		bridgeAddr  = fs.String("bridge-addr", DefaultBridgeAddr, "loopback address for the bridge")
		bridgeOff   = fs.Bool("bridge-off", false, "disable the loopback bridge")
		keyMode     = fs.String("crypto-key", string(CryptoKeyEphemeral), "key source: ephemeral or passphrase")
		passphrase  = fs.String("crypto-pass", "", "passphrase for -crypto-key=passphrase")
		wire        = fs.Bool("crypto-wire", true, "encrypt bridge payloads")
		jsonOut     = fs.Bool("json", false, "print findings as ndjson")
		levelText   = fs.String("loglevel", "info", "log level 0..5 or error/warning/info/debug/verbose")
		noColor     = fs.Bool("no-color", false, "disable ansi colour")
		version     = fs.Bool("version", false, "print version and exit")
	)

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("config: parse flags: %w", err)
	}

	cfg := Config{
		CIDR:        strings.TrimSpace(*cidr),
		ARPOnly:     *arpOnly,
		Workers:     clamp(*workers, 1, maxWorkers),
		Timeout:     *timeout,
		PortTimeout: *portTimeout,
		Serve:       *serve,
		BridgeAddr:  strings.TrimSpace(*bridgeAddr),
		BridgeOff:   *bridgeOff,
		EncryptWire: *wire,
		JSON:        *jsonOut,
		NoColor:     *noColor,
		Version:     *version,
	}

	ports, err := parsePorts(*portsText)
	if err != nil {
		return Config{}, err
	}
	cfg.Ports = ports

	mode, err := parseKeyMode(*keyMode)
	if err != nil {
		return Config{}, err
	}
	cfg.CryptoKeyMode = mode

	level, err := logger.ParseLevel(*levelText)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	cfg.LogLevel = level

	if cfg.Version {
		return cfg, nil
	}

	if cfg.CIDR != "" {
		if _, _, err := net.ParseCIDR(cfg.CIDR); err != nil {
			return Config{}, fmt.Errorf("config: invalid cidr %q: %w", cfg.CIDR, err)
		}
	}

	if cfg.Timeout <= 0 || cfg.Timeout > maxProbeTimeout {
		return Config{}, fmt.Errorf("config: timeout must be between 1ns and %s", maxProbeTimeout)
	}

	if cfg.PortTimeout <= 0 || cfg.PortTimeout > maxProbeTimeout {
		return Config{}, fmt.Errorf("config: port timeout must be between 1ns and %s", maxProbeTimeout)
	}

	if cfg.ARPOnly && cfg.CIDR != "" {
		return Config{}, fmt.Errorf("config: -arp-only and -cidr are mutually exclusive")
	}

	if !cfg.BridgeOff {
		if err := requireLoopback(cfg.BridgeAddr); err != nil {
			return Config{}, err
		}
	}

	if cfg.CryptoKeyMode == CryptoKeyPassphrase {
		cfg.Passphrase = firstNonEmpty(*passphrase, getenv(passphraseEnv))
		if cfg.Passphrase == "" {
			return Config{}, fmt.Errorf("config: -crypto-key=passphrase requires -crypto-pass or %s", passphraseEnv)
		}
	}

	return cfg, nil
}

func parsePorts(text string) ([]int, error) {
	fields := strings.Split(text, ",")
	ports := make([]int, 0, len(fields))
	seen := make(map[int]struct{}, len(fields))

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		port, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("config: invalid port %q", field)
		}

		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("config: port %d out of range", port)
		}

		if _, ok := seen[port]; ok {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("config: at least one port is required")
	}

	return ports, nil
}

func parseKeyMode(text string) (CryptoKeyMode, error) {
	switch CryptoKeyMode(strings.ToLower(strings.TrimSpace(text))) {
	case CryptoKeyEphemeral:
		return CryptoKeyEphemeral, nil
	case CryptoKeyPassphrase:
		return CryptoKeyPassphrase, nil
	default:
		return "", fmt.Errorf("config: invalid key mode %q, want ephemeral or passphrase", text)
	}
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: invalid bridge address %q: %w", addr, err)
	}

	if strings.EqualFold(host, "localhost") {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("config: bridge must bind to loopback, got %q", addr)
	}

	return nil
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}

	if value > high {
		return high
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
