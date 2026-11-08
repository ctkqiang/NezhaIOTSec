package probes

import (
	"net"
	"time"

	"nezha_iot_sec/pkg/model"
)

const (
	modbusPort = 502
	modbusFC   = 0x2B
)

var modbusRequest = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, modbusFC, 0x0E, 0x01, 0x00}

func ProbeModbus(target string, timeout time.Duration) (model.Finding, bool) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return model.Finding{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(modbusRequest); err != nil {
		return model.Finding{}, false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return model.Finding{}, false
	}

	if buf[7] != modbusFC {
		return model.Finding{}, false
	}

	host, port, ok := splitTarget(target, modbusPort)
	if !ok {
		return model.Finding{}, false
	}

	return model.Finding{
		IP:       host,
		Port:     port,
		Service:  "Modbus-TCP",
		Severity: model.SeverityHigh,
		Detail:   "Modbus PLC Confirmed (FC 0x2B device identification)",
		FoundAt:  time.Now(),
	}, true
}

func ProbeModbusPLC(ip string, timeout time.Duration) (model.Finding, bool) {
	return ProbeModbus(net.JoinHostPort(ip, "502"), timeout)
}
