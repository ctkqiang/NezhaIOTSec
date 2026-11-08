package probes

import (
	"net"
	"strconv"
	"time"

	"nezha_iot_sec/pkg/model"
)

func splitTarget(target string, fallbackPort int) (string, int, bool) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, false
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		port = fallbackPort
	}

	return host, port, true
}

type Default struct{}

func (Default) Modbus(ip string, timeout time.Duration) (model.Finding, bool) {
	return ProbeModbusPLC(ip, timeout)
}

func (Default) MQTT(ip string, timeout time.Duration) (model.Finding, bool) {
	return ProbeMQTTBroker(ip, timeout)
}

func (Default) BACnet(ip string, timeout time.Duration) (model.Finding, bool) {
	return ProbeBACnet(ip, timeout)
}
