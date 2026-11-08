package scan

import (
	"context"
	"errors"
	"time"

	"nezha_iot_sec/pkg/engine"
	"nezha_iot_sec/pkg/logger"
	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/netlink"
	"nezha_iot_sec/pkg/netutil"
)

type Request struct {
	CIDR        string
	ARPOnly     bool
	Ports       []int
	Workers     int
	Timeout     time.Duration
	PortTimeout time.Duration
	OnFinding   func(model.Finding)
}

type Scanner struct {
	Prober    engine.Prober
	Neighbors func() ([]netlink.Neighbor, error)
	Logger    *logger.Logger
}

func (s *Scanner) Scan(ctx context.Context, req Request) ([]model.Finding, error) {
	log := s.logger()
	neighbors := s.resolveNeighbors(log)

	targets, err := BuildTargets(req.CIDR, req.ARPOnly, neighbors, netutil.DefaultHostLimit)
	if err != nil {
		return nil, err
	}

	if len(targets) == 0 {
		log.PrintWarning("没有可扫描的目标，请检查邻居表或 -cidr 参数")
		return nil, nil
	}

	log.PrintStatus("启动有界工作池，%d 个目标，单探针超时 %s", len(targets), req.Timeout)

	findings := engine.RunSweep(ctx, targets, engine.Options{
		Workers:     req.Workers,
		Timeout:     req.Timeout,
		PortTimeout: req.PortTimeout,
		Ports:       req.Ports,
		Prober:      s.Prober,
		OnFinding:   req.OnFinding,
	})

	enrich(findings, neighbors)
	return findings, nil
}

func BuildTargets(cidr string, arpOnly bool, neighbors []netlink.Neighbor, limit int) ([]string, error) {
	arpHosts := make([]string, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if neighbor.IP == "" {
			continue
		}
		arpHosts = append(arpHosts, neighbor.IP)
	}

	if arpOnly {
		return netutil.MergeHosts(arpHosts, nil), nil
	}

	resolved := cidr
	if resolved == "" {
		cidrs, err := netutil.LocalCIDRs()
		if err != nil {
			return nil, err
		}
		resolved = cidrs[0]
	}

	hosts, err := netutil.HostsInCIDR(resolved, limit)
	if err != nil {
		return nil, err
	}

	inside := make([]string, 0, len(arpHosts))
	for _, host := range arpHosts {
		if netutil.Contains(resolved, host) {
			inside = append(inside, host)
		}
	}

	return netutil.MergeHosts(inside, hosts), nil
}

func (s *Scanner) resolveNeighbors(log *logger.Logger) []netlink.Neighbor {
	if s.Neighbors == nil {
		return nil
	}

	neighbors, err := s.Neighbors()
	if err != nil {
		if errors.Is(err, netlink.ErrUnsupported) {
			log.PrintStatus("当前平台不支持内核邻居表读取，回退到网段扫描")
			return nil
		}

		log.PrintWarning("内核邻居表读取失败，回退到网段扫描: %v", err)
		return nil
	}

	log.PrintDebug("内核邻居表返回 %d 个条目", len(neighbors))
	return neighbors
}

func (s *Scanner) logger() *logger.Logger {
	if s.Logger != nil {
		return s.Logger
	}

	return logger.Default()
}

func enrich(findings []model.Finding, neighbors []netlink.Neighbor) {
	if len(neighbors) == 0 {
		return
	}

	byIP := make(map[string]string, len(neighbors))
	for _, neighbor := range neighbors {
		byIP[neighbor.IP] = neighbor.MAC
	}

	for i := range findings {
		if mac, ok := byIP[findings[i].IP]; ok {
			findings[i].MAC = mac
		}
	}
}
