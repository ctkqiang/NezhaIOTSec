package netlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
)

const (
	ndmStateOffset = 8
	nudIncomplete  = 0x01
	nudFailed      = 0x20
)

var payloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		return &buf
	},
}

func DumpNeighbors() ([]Neighbor, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket failed: %w", err)
	}
	defer syscall.Close(fd)

	req, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("netlinkRIB failed: %w", err)
	}

	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink sendto failed: %w", err)
	}

	bufPtr := payloadPool.Get().(*[]byte)
	defer payloadPool.Put(bufPtr)
	buf := *bufPtr

	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("netlink recvfrom failed: %w", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("netlink parse failed: %w", err)
	}

	var discovered []Neighbor
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}

		if skippedNeighbor(m.Data) {
			continue
		}

		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}

		var (
			ip  net.IP
			mac net.HardwareAddr
		)

		for _, attr := range attrs {
			switch attr.Attr.Type {
			case 0x01:
				ip = net.IP(attr.Value)
			case 0x02:
				mac = net.HardwareAddr(attr.Value)
			}
		}

		if ip == nil || len(mac) != 6 {
			continue
		}

		discovered = append(discovered, Neighbor{IP: ip.String(), MAC: mac.String()})
	}

	return discovered, nil
}

// skippedNeighbor drops entries that never resolved, so stale rows cannot become scan targets
func skippedNeighbor(data []byte) bool {
	if len(data) < ndmStateOffset+2 {
		return true
	}

	state := binary.LittleEndian.Uint16(data[ndmStateOffset : ndmStateOffset+2])
	return state == nudIncomplete || state == nudFailed
}
