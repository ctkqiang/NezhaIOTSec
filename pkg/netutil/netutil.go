package netutil

import (
	"fmt"
	"net"
)

const DefaultHostLimit = 65536

func LocalCIDRs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("netutil: list interfaces: %w", err)
	}

	var cidrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			cidr, ok := ipv4CIDR(ipNet)
			if !ok {
				continue
			}

			if containsString(cidrs, cidr) {
				continue
			}

			cidrs = append(cidrs, cidr)
		}
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("netutil: no active ipv4 interface found")
	}

	return cidrs, nil
}

func HostsInCIDR(cidr string, limit int) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("netutil: parse cidr %q: %w", cidr, err)
	}

	base, ok := ipv4Network(network)
	if !ok {
		return nil, fmt.Errorf("netutil: cidr %q is not an ipv4 network", cidr)
	}

	if limit <= 0 {
		limit = DefaultHostLimit
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("netutil: cidr %q is not an ipv4 network", cidr)
	}

	total := uint64(1) << uint(32-ones)
	usable := total
	if ones < 31 {
		usable = total - 2
	}

	if usable > uint64(limit) {
		return nil, fmt.Errorf("netutil: cidr %q expands to %d hosts, above the %d host limit", cidr, usable, limit)
	}

	start := base
	if ones < 31 {
		start = base + 1
	}

	hosts := make([]string, 0, usable)
	for i := uint64(0); i < usable; i++ {
		hosts = append(hosts, ipv4String(start+uint32(i)))
	}

	return hosts, nil
}

func MergeHosts(primary, extra []string) []string {
	seen := make(map[string]struct{}, len(primary)+len(extra))
	merged := make([]string, 0, len(primary)+len(extra))

	for _, group := range [][]string{primary, extra} {
		for _, host := range group {
			if host == "" {
				continue
			}

			if _, ok := seen[host]; ok {
				continue
			}

			seen[host] = struct{}{}
			merged = append(merged, host)
		}
	}

	return merged
}

func Contains(cidr, ip string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	return network.Contains(parsed)
}

func ipv4CIDR(ipNet *net.IPNet) (string, bool) {
	ip4 := ipNet.IP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
		return "", false
	}

	mask := ipNet.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}

	if len(mask) != net.IPv4len {
		return "", false
	}

	return (&net.IPNet{IP: ip4.Mask(mask), Mask: mask}).String(), true
}

func ipv4Network(network *net.IPNet) (uint32, bool) {
	ip4 := network.IP.To4()
	if ip4 == nil {
		return 0, false
	}

	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), true
}

func ipv4String(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}
