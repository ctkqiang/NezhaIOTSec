package test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"nezha_iot_sec/pkg/netlink"
)

func TestDumpNeighbors(t *testing.T) {
	t.Parallel()

	neighbors, err := netlink.DumpNeighbors()

	if runtime.GOOS != "linux" {
		if !errors.Is(err, netlink.ErrUnsupported) {
			t.Fatalf("expected ErrUnsupported on %s, got %v", runtime.GOOS, err)
		}

		if neighbors != nil {
			t.Fatalf("expected no neighbours on %s, got %v", runtime.GOOS, neighbors)
		}

		return
	}

	if err != nil {
		t.Skipf("kernel neighbour dump unavailable in this sandbox: %v", err)
	}

	for _, neighbor := range neighbors {
		if neighbor.IP == "" {
			t.Fatal("kernel returned a neighbour without an ip")
		}

		if strings.Count(neighbor.MAC, ":") != 5 {
			t.Fatalf("unexpected mac %q for %s", neighbor.MAC, neighbor.IP)
		}
	}
}

func TestErrUnsupportedMessage(t *testing.T) {
	t.Parallel()

	if netlink.ErrUnsupported == nil {
		t.Fatal("ErrUnsupported must be a sentinel error")
	}

	if !strings.Contains(netlink.ErrUnsupported.Error(), "netlink") {
		t.Fatalf("sentinel error lacks context: %q", netlink.ErrUnsupported.Error())
	}
}
