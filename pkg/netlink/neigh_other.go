//go:build !linux

package netlink

func DumpNeighbors() ([]Neighbor, error) {
	return nil, ErrUnsupported
}
