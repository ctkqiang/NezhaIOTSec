package probes

import (
	"bytes"
	"net"
	"strconv"
	"time"

	"nezha_iot_sec/pkg/model"
)

const (
	bacnetPort    = 47808
	bacnetApdu    = 0x10
	bacnetBVLC    = 0x81
	bacnetBVLCTyp = 0x0A
)

var bacnetWhoIs = []byte{0x81, 0x0A, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08}

func ProbeBACnet(ip string, timeout time.Duration) (model.Finding, bool) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(bacnetPort)), timeout)
	if err != nil {
		return model.Finding{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(bacnetWhoIs); err != nil {
		return model.Finding{}, false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return model.Finding{}, false
	}

	if buf[0] != bacnetBVLC || buf[1] != bacnetBVLCTyp {
		return model.Finding{}, false
	}

	if !bytes.Contains(buf[4:n], []byte{bacnetApdu}) {
		return model.Finding{}, false
	}

	return model.Finding{
		IP:       ip,
		Port:     bacnetPort,
		Service:  "BACnet/IP",
		Severity: model.SeverityHigh,
		Detail:   "BACnet Device Confirmed (I-Am)",
		FoundAt:  time.Now(),
	}, true
}
