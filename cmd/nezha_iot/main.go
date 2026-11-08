package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nezha_iot_sec/pkg/bridge"
	"nezha_iot_sec/pkg/config"
	"nezha_iot_sec/pkg/logger"
	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/netlink"
	"nezha_iot_sec/pkg/probes"
	"nezha_iot_sec/pkg/report"
	"nezha_iot_sec/pkg/scan"
	"nezha_iot_sec/pkg/vault"
)

const (
	appName    = "哪吒网络安全物联网 · NezhaIOTSec"
	appVersion = "1.0.0"
	ruleWidth  = 62
)

func main() {
	if err := run(); err != nil {
		logger.PrintError("%v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}

	logger.SetLevel(cfg.LogLevel)
	if cfg.NoColor {
		logger.SetColor(false)
	}

	if cfg.Version {
		logger.PrintLine("%s %s", appName, appVersion)
		return nil
	}

	key, err := resolveKey(cfg)
	if err != nil {
		return err
	}
	defer wipe(key)

	store, err := vault.New(key)
	if err != nil {
		return err
	}
	defer store.Close()

	scanner := &scan.Scanner{
		Prober:    probes.Default{},
		Neighbors: netlink.DumpNeighbors,
		Logger:    logger.Default(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(cfg)

	if !cfg.Serve {
		if err := runOnce(ctx, cfg, scanner, store); err != nil {
			return err
		}
	}

	if ctx.Err() != nil {
		return nil
	}

	if cfg.BridgeOff {
		if cfg.Serve {
			logger.PrintWarning("-serve 依赖 bridge，但 -bridge-off 已启用，未启动任何监听")
		}
		return nil
	}

	return serveBridge(ctx, cfg, key, store, scanner)
}

func resolveKey(cfg config.Config) ([]byte, error) {
	if cfg.CryptoKeyMode == config.CryptoKeyPassphrase {
		return vault.PassphraseKey(cfg.Passphrase)
	}

	return vault.EphemeralKey()
}

func runOnce(ctx context.Context, cfg config.Config, scanner *scan.Scanner, store *vault.Vault) error {
	started := time.Now()

	findings, err := scanner.Scan(ctx, scan.Request{
		CIDR:        cfg.CIDR,
		ARPOnly:     cfg.ARPOnly,
		Ports:       cfg.Ports,
		Workers:     cfg.Workers,
		Timeout:     cfg.Timeout,
		PortTimeout: cfg.PortTimeout,
	})
	if err != nil {
		return err
	}

	elapsed := time.Since(started).Round(time.Millisecond)

	logger.PrintLine("")

	if len(findings) == 0 {
		logger.PrintWarning("扫描完成，耗时 %s，未发现活跃物联网服务", elapsed)
		return nil
	}

	logger.PrintGood("扫描完成，耗时 %s，发现 %d 个活跃物联网服务", elapsed, len(findings))

	if !cfg.BridgeOff {
		for _, finding := range findings {
			if err := store.Add(finding); err != nil {
				return err
			}
		}
	}

	if cfg.JSON {
		return report.RenderJSON(os.Stdout, findings)
	}

	return report.Render(os.Stdout, findings, report.Options{
		Color:   logger.Color(),
		ShowMAC: hasMAC(findings),
	})
}

func serveBridge(ctx context.Context, cfg config.Config, key []byte, store *vault.Vault, scanner *scan.Scanner) error {
	server, err := bridge.New(bridge.Config{
		Addr:        cfg.BridgeAddr,
		Key:         key,
		KeyMode:     cfg.CryptoKeyMode,
		EncryptWire: cfg.EncryptWire,
		Vault:       store,
		Scanner:     scanner,
		Logger:      logger.Default(),
		Defaults: scan.Request{
			Ports:       cfg.Ports,
			Workers:     cfg.Workers,
			Timeout:     cfg.Timeout,
			PortTimeout: cfg.PortTimeout,
		},
	})
	if err != nil {
		return err
	}

	logger.PrintGood("Bridge 已监听 %s（协议 v%d）", server.Addr(), bridge.ProtocolVersion)
	logger.PrintStatus("等待 Flutter 操作端接入，Ctrl+C 退出")

	if err := server.Serve(ctx); err != nil {
		return err
	}

	logger.PrintStatus("Bridge 已关闭")
	return nil
}

func printBanner(cfg config.Config) {
	logger.PrintLine("")
	logger.PrintLine(strings.Repeat("─", ruleWidth))
	logger.PrintLine("  " + appName + "  v" + appVersion)
	logger.PrintLine(strings.Repeat("─", ruleWidth))
	logger.PrintStatus("目标范围: %s", targetDescription(cfg))
	logger.PrintStatus("扫描端口: %s", joinPorts(cfg.Ports))
	logger.PrintStatus("工作池: %d goroutines，单探针超时 %s", cfg.Workers, cfg.Timeout)
	logger.PrintStatus("加密模式: %s，链路加密: %s", cfg.CryptoKeyMode, onOff(cfg.EncryptWire))
	logger.PrintWarning("仅可在已获得书面授权的网络中使用")
	logger.PrintLine("")
}

func targetDescription(cfg config.Config) string {
	if cfg.ARPOnly {
		return "内核邻居表（ARP）"
	}

	if cfg.CIDR != "" {
		return cfg.CIDR
	}

	return "自动探测（主接口网段 + 邻居表优先）"
}

func hasMAC(findings []model.Finding) bool {
	for _, finding := range findings {
		if finding.MAC != "" {
			return true
		}
	}

	return false
}

func onOff(enabled bool) string {
	if enabled {
		return "开启"
	}

	return "关闭"
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))

	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}

	return strings.Join(parts, ", ")
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
