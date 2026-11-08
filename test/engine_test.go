package test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"nezha_iot_sec/pkg/engine"
	"nezha_iot_sec/pkg/model"
)

type stubProber struct {
	modbus bool
	mqtt   bool
	bacnet bool
}

func (p stubProber) Modbus(ip string, _ time.Duration) (model.Finding, bool) {
	if !p.modbus {
		return model.Finding{}, false
	}

	return model.Finding{IP: ip, Port: 502, Service: "Modbus-TCP", Severity: model.SeverityHigh}, true
}

func (p stubProber) MQTT(ip string, _ time.Duration) (model.Finding, bool) {
	if !p.mqtt {
		return model.Finding{}, false
	}

	return model.Finding{IP: ip, Port: 1883, Service: "MQTT", Severity: model.SeverityCritical}, true
}

func (p stubProber) BACnet(ip string, _ time.Duration) (model.Finding, bool) {
	if !p.bacnet {
		return model.Finding{}, false
	}

	return model.Finding{IP: ip, Port: 47808, Service: "BACnet/IP", Severity: model.SeverityHigh}, true
}

func TestRunSweepProducesSortedFindings(t *testing.T) {
	t.Parallel()

	ips := []string{"10.0.0.2", "10.0.0.1"}

	findings := engine.RunSweep(context.Background(), ips, engine.Options{
		Workers: 4,
		Prober:  stubProber{modbus: true, mqtt: true},
	})

	want := []struct {
		ip   string
		port int
	}{
		{"10.0.0.1", 502},
		{"10.0.0.1", 1883},
		{"10.0.0.2", 502},
		{"10.0.0.2", 1883},
	}

	if len(findings) != len(want) {
		t.Fatalf("RunSweep returned %d findings, want %d: %+v", len(findings), len(want), findings)
	}

	for i, expected := range want {
		if findings[i].IP != expected.ip || findings[i].Port != expected.port {
			t.Fatalf("finding %d = %s:%d, want %s:%d",
				i, findings[i].IP, findings[i].Port, expected.ip, expected.port)
		}
	}
}

func TestRunSweepOnFindingCallback(t *testing.T) {
	t.Parallel()

	var seen atomic.Int64

	findings := engine.RunSweep(context.Background(), []string{"10.0.0.1"}, engine.Options{
		Workers: 1,
		Prober:  stubProber{modbus: true, mqtt: true, bacnet: true},
		OnFinding: func(model.Finding) {
			seen.Add(1)
		},
	})

	if int64(len(findings)) != seen.Load() {
		t.Fatalf("callback fired %d times for %d findings", seen.Load(), len(findings))
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 dedicated findings, got %d", len(findings))
	}
}

func TestRunSweepEmptyInput(t *testing.T) {
	t.Parallel()

	if findings := engine.RunSweep(context.Background(), nil, engine.Options{}); findings != nil {
		t.Fatalf("empty input must return nil, got %+v", findings)
	}
}

func TestRunSweepHonoursCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := engine.RunSweep(ctx, []string{"10.0.0.1", "10.0.0.2"}, engine.Options{
		Workers: 2,
		Prober:  stubProber{modbus: true},
	})

	if len(findings) != 0 {
		t.Fatalf("cancelled sweep produced %d findings", len(findings))
	}
}

func TestRunSweepGenericPorts(t *testing.T) {
	t.Parallel()

	listener, err := listenLoopback()
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	port := listenerPort(t, listener.Addr().String())

	findings := engine.RunSweep(context.Background(), []string{"127.0.0.1"}, engine.Options{
		Workers:     1,
		PortTimeout: time.Second,
		Ports:       []int{port, 502, 1883, 47808},
		Prober:      stubProber{},
	})

	if len(findings) != 1 {
		t.Fatalf("expected one generic finding, got %+v", findings)
	}

	if findings[0].Port != port {
		t.Fatalf("generic finding port = %d, want %d", findings[0].Port, port)
	}

	if findings[0].Service != "Port-"+itoa(port) {
		t.Fatalf("Service = %q", findings[0].Service)
	}
}

func TestRunSweepWorkerClamp(t *testing.T) {
	t.Parallel()

	findings := engine.RunSweep(context.Background(), []string{"10.0.0.1"}, engine.Options{
		Workers: 1000,
		Prober:  stubProber{modbus: true},
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
}
