package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/probes"
)

const (
	defaultWorkers    = 150
	defaultTimeout    = 300 * time.Millisecond
	defaultPortWindow = 200 * time.Millisecond
	dedicatedProbes   = 3
)

var dedicatedPorts = map[int]struct{}{
	502:   {},
	1883:  {},
	47808: {},
}

type Prober interface {
	Modbus(ip string, timeout time.Duration) (model.Finding, bool)
	MQTT(ip string, timeout time.Duration) (model.Finding, bool)
	BACnet(ip string, timeout time.Duration) (model.Finding, bool)
}

type Options struct {
	Workers     int
	Timeout     time.Duration
	PortTimeout time.Duration
	Ports       []int
	Prober      Prober
	OnFinding   func(model.Finding)
}

func RunSweep(ctx context.Context, ips []string, opts Options) []model.Finding {
	if len(ips) == 0 {
		return nil
	}

	opts = normalizedOptions(opts)
	genericPorts := genericPortsOf(opts.Ports)

	// capacity must cover every probe per host, otherwise workers block on send while the collector waits
	capacity := len(ips) * (dedicatedProbes + len(genericPorts))

	jobs := make(chan string, len(ips))
	results := make(chan model.Finding, capacity)

	workerCount := opts.Workers
	if workerCount > len(ips) {
		workerCount = len(ips)
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					return
				}
				sweepHost(ctx, ip, opts, genericPorts, results)
			}
		}()
	}

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		jobs <- ip
	}
	close(jobs)

	wg.Wait()
	close(results)

	findings := make([]model.Finding, 0, capacity)
	for finding := range results {
		findings = append(findings, finding)
	}

	sortFindings(findings)
	return findings
}

func sweepHost(ctx context.Context, ip string, opts Options, genericPorts []int, results chan<- model.Finding) {
	if finding, ok := opts.Prober.Modbus(ip, opts.Timeout); ok {
		emit(finding, results, opts.OnFinding)
	}

	if ctx.Err() != nil {
		return
	}

	if finding, ok := opts.Prober.MQTT(ip, opts.Timeout); ok {
		emit(finding, results, opts.OnFinding)
	}

	if ctx.Err() != nil {
		return
	}

	if finding, ok := opts.Prober.BACnet(ip, opts.Timeout); ok {
		emit(finding, results, opts.OnFinding)
	}

	for _, port := range genericPorts {
		if ctx.Err() != nil {
			return
		}

		if finding, ok := dialPort(ip, port, opts.PortTimeout); ok {
			emit(finding, results, opts.OnFinding)
		}
	}
}

func emit(finding model.Finding, results chan<- model.Finding, onFinding func(model.Finding)) {
	if onFinding != nil {
		onFinding(finding)
	}

	results <- finding
}

func dialPort(ip string, port int, timeout time.Duration) (model.Finding, bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return model.Finding{}, false
	}
	_ = conn.Close()

	return model.Finding{
		IP:       ip,
		Port:     port,
		Service:  fmt.Sprintf("Port-%d", port),
		Severity: model.SeverityInfo,
		Detail:   "Open",
		FoundAt:  time.Now(),
	}, true
}

func normalizedOptions(opts Options) Options {
	if opts.Workers < 1 {
		opts.Workers = defaultWorkers
	}

	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	if opts.PortTimeout <= 0 {
		opts.PortTimeout = defaultPortWindow
	}

	if opts.Prober == nil {
		opts.Prober = probes.Default{}
	}

	return opts
}

func genericPortsOf(ports []int) []int {
	generic := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, dedicated := dedicatedPorts[port]; dedicated {
			continue
		}
		generic = append(generic, port)
	}

	return generic
}

func sortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].IP != findings[j].IP {
			return findings[i].IP < findings[j].IP
		}

		if findings[i].Port != findings[j].Port {
			return findings[i].Port < findings[j].Port
		}

		return findings[i].Service < findings[j].Service
	})
}
