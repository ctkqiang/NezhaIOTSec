package test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"nezha_iot_sec/pkg/logger"
	"nezha_iot_sec/pkg/netlink"
	"nezha_iot_sec/pkg/scan"
)

func TestBuildTargetsARPOnly(t *testing.T) {
	t.Parallel()

	neighbors := []netlink.Neighbor{
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:01"},
		{IP: "", MAC: "aa:bb:cc:dd:ee:02"},
		{IP: "10.0.0.6", MAC: "aa:bb:cc:dd:ee:03"},
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:01"},
	}

	hosts, err := scan.BuildTargets("", true, neighbors, 100)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	want := []string{"10.0.0.5", "10.0.0.6"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}

	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("hosts = %v, want %v", hosts, want)
		}
	}
}

func TestBuildTargetsPrefersNeighboursInsideCIDR(t *testing.T) {
	t.Parallel()

	neighbors := []netlink.Neighbor{
		{IP: "192.168.1.2", MAC: "aa:bb:cc:dd:ee:01"},
		{IP: "10.9.9.9", MAC: "aa:bb:cc:dd:ee:02"},
	}

	hosts, err := scan.BuildTargets("192.168.1.0/30", false, neighbors, 100)
	if err != nil {
		t.Fatalf("BuildTargets failed: %v", err)
	}

	want := []string{"192.168.1.2", "192.168.1.1"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}

	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("hosts = %v, want %v", hosts, want)
		}
	}
}

func TestBuildTargetsRejectsOversizedCIDR(t *testing.T) {
	t.Parallel()

	if _, err := scan.BuildTargets("10.0.0.0/8", false, nil, 1024); err == nil {
		t.Fatal("an oversized cidr must be rejected")
	}
}

func TestScannerEnrichesMAC(t *testing.T) {
	t.Parallel()

	scanner := &scan.Scanner{
		Prober: stubProber{modbus: true},
		Neighbors: func() ([]netlink.Neighbor, error) {
			return []netlink.Neighbor{{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:01"}}, nil
		},
		Logger: quietLogger(),
	}

	findings, err := scanner.Scan(context.Background(), scan.Request{
		ARPOnly:     true,
		Ports:       []int{502},
		Workers:     2,
		Timeout:     time.Second,
		PortTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}

	if findings[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("MAC = %q", findings[0].MAC)
	}
}

func TestScannerFallsBackWhenNeighboursFail(t *testing.T) {
	t.Parallel()

	scanner := &scan.Scanner{
		Prober: stubProber{},
		Neighbors: func() ([]netlink.Neighbor, error) {
			return nil, errors.New("netlink denied by selinux")
		},
		Logger: quietLogger(),
	}

	findings, err := scanner.Scan(context.Background(), scan.Request{
		CIDR:        "127.0.0.1/32",
		Ports:       []int{502},
		Workers:     1,
		Timeout:     time.Second,
		PortTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Scan must survive a neighbour failure: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("stub prober produced findings: %+v", findings)
	}
}

func TestScannerWithoutNeighboursSource(t *testing.T) {
	t.Parallel()

	scanner := &scan.Scanner{Prober: stubProber{}, Logger: quietLogger()}

	findings, err := scanner.Scan(context.Background(), scan.Request{
		ARPOnly: true,
		Ports:   []int{502},
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected no targets, got %+v", findings)
	}
}

func quietLogger() *logger.Logger {
	var out, errOut bytes.Buffer

	l := logger.New(&out, &errOut)
	l.SetColor(false)

	return l
}
