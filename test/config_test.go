package test

import (
	"testing"
	"time"

	"nezha_iot_sec/pkg/config"
	"nezha_iot_sec/pkg/logger"
)

func noEnv(string) string {
	return ""
}

func mapEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := config.Parse(nil, noEnv)
	if err != nil {
		t.Fatalf("Parse(nil) failed: %v", err)
	}

	if cfg.CIDR != "" || cfg.ARPOnly {
		t.Fatalf("unexpected target defaults: cidr=%q arpOnly=%v", cfg.CIDR, cfg.ARPOnly)
	}

	if cfg.Workers != 150 {
		t.Fatalf("Workers = %d, want 150", cfg.Workers)
	}

	if cfg.Timeout != 300*time.Millisecond {
		t.Fatalf("Timeout = %s, want 300ms", cfg.Timeout)
	}

	if cfg.PortTimeout != 200*time.Millisecond {
		t.Fatalf("PortTimeout = %s, want 200ms", cfg.PortTimeout)
	}

	if cfg.BridgeAddr != config.DefaultBridgeAddr {
		t.Fatalf("BridgeAddr = %q", cfg.BridgeAddr)
	}

	if cfg.CryptoKeyMode != config.CryptoKeyEphemeral {
		t.Fatalf("CryptoKeyMode = %q", cfg.CryptoKeyMode)
	}

	if !cfg.EncryptWire {
		t.Fatal("wire encryption must be enabled by default")
	}

	if cfg.LogLevel != logger.LevelInfo {
		t.Fatalf("LogLevel = %v, want info", cfg.LogLevel)
	}

	want := []int{502, 1883, 80, 554, 47808}
	if len(cfg.Ports) != len(want) {
		t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
	}

	for i := range want {
		if cfg.Ports[i] != want[i] {
			t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
		}
	}
}

func TestConfigPorts(t *testing.T) {
	t.Parallel()

	cfg, err := config.Parse([]string{"-ports", " 443, 80 ,443,8080 "}, noEnv)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	want := []int{443, 80, 8080}
	if len(cfg.Ports) != len(want) {
		t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
	}

	for i := range want {
		if cfg.Ports[i] != want[i] {
			t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
		}
	}

	for _, bad := range [][]string{
		{"-ports", "0"},
		{"-ports", "65536"},
		{"-ports", "eighty"},
		{"-ports", " , , "},
	} {
		if _, err := config.Parse(bad, noEnv); err == nil {
			t.Fatalf("Parse(%v) expected error", bad)
		}
	}
}

func TestConfigWorkersClamp(t *testing.T) {
	t.Parallel()

	cases := map[string]int{
		"-workers=0":    1,
		"-workers=-9":   1,
		"-workers=9999": 512,
		"-workers=32":   32,
	}

	for arg, want := range cases {
		cfg, err := config.Parse([]string{arg}, noEnv)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", arg, err)
		}

		if cfg.Workers != want {
			t.Fatalf("Parse(%q).Workers = %d, want %d", arg, cfg.Workers, want)
		}
	}
}

func TestConfigTimeoutBounds(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"-timeout", "0s"},
		{"-timeout", "11s"},
		{"-port-timeout", "-1s"},
		{"-port-timeout", "30s"},
	} {
		if _, err := config.Parse(args, noEnv); err == nil {
			t.Fatalf("Parse(%v) expected error", args)
		}
	}
}

func TestConfigTargetExclusivity(t *testing.T) {
	t.Parallel()

	if _, err := config.Parse([]string{"-arp-only", "-cidr", "192.168.1.0/24"}, noEnv); err == nil {
		t.Fatal("-arp-only with -cidr must be rejected")
	}

	if _, err := config.Parse([]string{"-cidr", "not-a-cidr"}, noEnv); err == nil {
		t.Fatal("invalid cidr must be rejected")
	}
}

func TestConfigBridgeLoopback(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"127.0.0.1:7788", "localhost:7788", "[::1]:7788"} {
		if _, err := config.Parse([]string{"-bridge-addr", addr}, noEnv); err != nil {
			t.Fatalf("Parse(-bridge-addr=%q) failed: %v", addr, err)
		}
	}

	for _, addr := range []string{"0.0.0.0:7788", "192.168.1.10:7788", "no-port"} {
		if _, err := config.Parse([]string{"-bridge-addr", addr}, noEnv); err == nil {
			t.Fatalf("Parse(-bridge-addr=%q) must fail", addr)
		}
	}

	if _, err := config.Parse([]string{"-bridge-addr", "0.0.0.0:7788", "-bridge-off"}, noEnv); err != nil {
		t.Fatalf("bridge-off must skip loopback validation: %v", err)
	}
}

func TestConfigPassphrase(t *testing.T) {
	t.Parallel()

	if _, err := config.Parse([]string{"-crypto-key", "passphrase"}, noEnv); err == nil {
		t.Fatal("passphrase mode without a secret must fail")
	}

	cfg, err := config.Parse([]string{"-crypto-key", "passphrase", "-crypto-pass", "s3cret"}, noEnv)
	if err != nil {
		t.Fatalf("Parse with explicit passphrase failed: %v", err)
	}

	if cfg.Passphrase != "s3cret" {
		t.Fatalf("Passphrase = %q", cfg.Passphrase)
	}

	cfg, err = config.Parse(
		[]string{"-crypto-key", "passphrase"},
		mapEnv(map[string]string{"NEZHA_PASSPHRASE": "from-env"}),
	)
	if err != nil {
		t.Fatalf("Parse with env passphrase failed: %v", err)
	}

	if cfg.Passphrase != "from-env" {
		t.Fatalf("Passphrase = %q, want from-env", cfg.Passphrase)
	}

	if _, err := config.Parse([]string{"-crypto-key", "rot13"}, noEnv); err == nil {
		t.Fatal("unknown key mode must fail")
	}
}

func TestConfigVersionShortCircuit(t *testing.T) {
	t.Parallel()

	if _, err := config.Parse([]string{"-version", "-ports", "0"}, noEnv); err == nil {
		t.Fatal("ports are validated before the version short circuit")
	}

	cfg, err := config.Parse([]string{"-version", "-cidr", "definitely-not-a-cidr"}, noEnv)
	if err != nil {
		t.Fatalf("-version must skip target validation: %v", err)
	}

	if !cfg.Version {
		t.Fatal("Version flag was not propagated")
	}
}

func TestConfigInvalidLogLevel(t *testing.T) {
	t.Parallel()

	if _, err := config.Parse([]string{"-loglevel", "screaming"}, noEnv); err == nil {
		t.Fatal("unknown log level must fail")
	}

	cfg, err := config.Parse([]string{"-loglevel", "debug", "-no-color", "-json"}, noEnv)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if cfg.LogLevel != logger.LevelDebug || !cfg.NoColor || !cfg.JSON {
		t.Fatalf("flags not propagated: %+v", cfg)
	}
}
