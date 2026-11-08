package netlink

import "errors"

var ErrUnsupported = errors.New("netlink: kernel neighbor dump is not supported on this platform")

type Neighbor struct {
	IP  string
	MAC string
}
