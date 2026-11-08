package test

import (
	"testing"

	"nezha_iot_sec/pkg/netutil"
)

func TestHostsInCIDR(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		cidr      string
		limit     int
		wantLen   int
		wantFirst string
		wantLast  string
		fail      bool
	}{
		{
			name:      "slash24",
			cidr:      "192.168.1.0/24",
			wantLen:   254,
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.254",
		},
		{
			name:      "slash30",
			cidr:      "10.0.0.0/30",
			wantLen:   2,
			wantFirst: "10.0.0.1",
			wantLast:  "10.0.0.2",
		},
		{
			name:      "slash31 keeps both ends",
			cidr:      "10.0.0.0/31",
			wantLen:   2,
			wantFirst: "10.0.0.0",
			wantLast:  "10.0.0.1",
		},
		{
			name:      "slash32 single host",
			cidr:      "10.0.0.5/32",
			wantLen:   1,
			wantFirst: "10.0.0.5",
			wantLast:  "10.0.0.5",
		},
		{
			name:  "limit exceeded",
			cidr:  "10.0.0.0/16",
			limit: 100,
			fail:  true,
		},
		{
			name: "invalid cidr",
			cidr: "192.168.1.0",
			fail: true,
		},
		{
			name: "ipv6 rejected",
			cidr: "::1/128",
			fail: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hosts, err := netutil.HostsInCIDR(tc.cidr, tc.limit)

			if tc.fail {
				if err == nil {
					t.Fatalf("HostsInCIDR(%q) expected error, got %d hosts", tc.cidr, len(hosts))
				}
				return
			}

			if err != nil {
				t.Fatalf("HostsInCIDR(%q) failed: %v", tc.cidr, err)
			}

			if len(hosts) != tc.wantLen {
				t.Fatalf("HostsInCIDR(%q) returned %d hosts, want %d", tc.cidr, len(hosts), tc.wantLen)
			}

			if hosts[0] != tc.wantFirst || hosts[len(hosts)-1] != tc.wantLast {
				t.Fatalf("HostsInCIDR(%q) spans %s..%s, want %s..%s",
					tc.cidr, hosts[0], hosts[len(hosts)-1], tc.wantFirst, tc.wantLast)
			}
		})
	}
}

func TestMergeHosts(t *testing.T) {
	t.Parallel()

	merged := netutil.MergeHosts(
		[]string{"10.0.0.9", "10.0.0.1"},
		[]string{"10.0.0.1", "", "10.0.0.2", "10.0.0.9"},
	)

	want := []string{"10.0.0.9", "10.0.0.1", "10.0.0.2"}
	if len(merged) != len(want) {
		t.Fatalf("MergeHosts = %v, want %v", merged, want)
	}

	for i := range want {
		if merged[i] != want[i] {
			t.Fatalf("MergeHosts = %v, want %v", merged, want)
		}
	}

	if got := netutil.MergeHosts(nil, nil); len(got) != 0 {
		t.Fatalf("MergeHosts(nil, nil) = %v", got)
	}
}

func TestContains(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.42", true},
		{"192.168.1.0/24", "192.168.2.42", false},
		{"192.168.1.0/24", "not-an-ip", false},
		{"broken", "192.168.1.42", false},
		{"10.0.0.0/8", "10.255.255.255", true},
	}

	for _, tc := range cases {
		if got := netutil.Contains(tc.cidr, tc.ip); got != tc.want {
			t.Fatalf("Contains(%q, %q) = %v, want %v", tc.cidr, tc.ip, got, tc.want)
		}
	}
}

func TestLocalCIDRs(t *testing.T) {
	t.Parallel()

	cidrs, err := netutil.LocalCIDRs()
	if err != nil {
		t.Skipf("no active ipv4 interface in this environment: %v", err)
	}

	if len(cidrs) == 0 {
		t.Fatal("LocalCIDRs returned no entries without an error")
	}

	for _, cidr := range cidrs {
		hosts, err := netutil.HostsInCIDR(cidr, netutil.DefaultHostLimit)
		if err != nil {
			t.Fatalf("HostsInCIDR(%q) failed: %v", cidr, err)
		}

		if len(hosts) == 0 {
			t.Fatalf("HostsInCIDR(%q) returned no hosts", cidr)
		}
	}
}
