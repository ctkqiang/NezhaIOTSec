package probes

import (
	"net"
	"time"

	"nezha_iot_sec/pkg/model"
)

const mqttPort = 1883

var mqttConnect = []byte{
	0x10, 0x0E,
	0x00, 0x04, 'M', 'Q', 'T', 'T',
	0x04,
	0x02,
	0x00, 0x3C,
	0x00, 0x02, 'n', 'z',
}

func ProbeMQTT(target string, timeout time.Duration) (model.Finding, bool) {
	host, port, ok := splitTarget(target, mqttPort)
	if !ok {
		return model.Finding{}, false
	}

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return model.Finding{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(mqttConnect); err != nil {
		return model.Finding{}, false
	}

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return model.Finding{}, false
	}

	if buf[0] != 0x20 {
		return model.Finding{}, false
	}

	if buf[3] == 0x00 {
		return model.Finding{
			IP:       host,
			Port:     port,
			Service:  "MQTT",
			Severity: model.SeverityCritical,
			Detail:   "CRITICAL: Unauthenticated MQTT Broker Access Allowed",
			FoundAt:  time.Now(),
		}, true
	}

	return model.Finding{
		IP:       host,
		Port:     port,
		Service:  "MQTT",
		Severity: model.SeverityInfo,
		Detail:   "MQTT Broker requires authentication",
		FoundAt:  time.Now(),
	}, true
}

func ProbeMQTTBroker(ip string, timeout time.Duration) (model.Finding, bool) {
	return ProbeMQTT(net.JoinHostPort(ip, "1883"), timeout)
}
