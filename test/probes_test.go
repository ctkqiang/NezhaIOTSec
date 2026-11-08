package test

import (
	"net"
	"testing"
	"time"

	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/probes"
)

const probeTimeout = 2 * time.Second

func tcpResponder(t *testing.T, reply []byte) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err != nil {
			return
		}

		_, _ = conn.Write(reply)
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

func udpResponder(port int, reply []byte) (func(), bool) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return func() {}, false
	}

	go func() {
		buf := make([]byte, 512)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			return
		}

		_, _ = conn.WriteToUDP(reply, from)
	}()

	return func() { _ = conn.Close() }, true
}

func TestProbeModbusConfirmed(t *testing.T) {
	t.Parallel()

	reply := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00}
	addr, stop := tcpResponder(t, reply)
	defer stop()

	finding, ok := probes.ProbeModbus(addr, probeTimeout)
	if !ok {
		t.Fatal("expected a modbus finding")
	}

	if finding.Service != "Modbus-TCP" {
		t.Fatalf("Service = %q", finding.Service)
	}

	if finding.Severity != model.SeverityHigh {
		t.Fatalf("Severity = %v", finding.Severity)
	}

	if finding.IP != "127.0.0.1" {
		t.Fatalf("IP = %q", finding.IP)
	}

	if finding.FoundAt.IsZero() {
		t.Fatal("FoundAt was not stamped")
	}
}

func TestProbeModbusRejectsForeignFunctionCode(t *testing.T) {
	t.Parallel()

	reply := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00}
	addr, stop := tcpResponder(t, reply)
	defer stop()

	if _, ok := probes.ProbeModbus(addr, probeTimeout); ok {
		t.Fatal("function code 0x03 must not be reported as a modbus plc")
	}
}

func TestProbeModbusClosedPort(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	addr := listener.Addr().String()
	_ = listener.Close()

	if _, ok := probes.ProbeModbus(addr, 200*time.Millisecond); ok {
		t.Fatal("closed port must not yield a finding")
	}
}

func TestProbeMQTTAnonymous(t *testing.T) {
	t.Parallel()

	addr, stop := tcpResponder(t, []byte{0x20, 0x02, 0x00, 0x00})
	defer stop()

	finding, ok := probes.ProbeMQTT(addr, probeTimeout)
	if !ok {
		t.Fatal("expected an mqtt finding")
	}

	if finding.Severity != model.SeverityCritical {
		t.Fatalf("anonymous broker must be critical, got %v", finding.Severity)
	}

	if finding.Service != "MQTT" {
		t.Fatalf("Service = %q", finding.Service)
	}
}

func TestProbeMQTTAuthenticated(t *testing.T) {
	t.Parallel()

	addr, stop := tcpResponder(t, []byte{0x20, 0x02, 0x00, 0x05})
	defer stop()

	finding, ok := probes.ProbeMQTT(addr, probeTimeout)
	if !ok {
		t.Fatal("expected an mqtt finding")
	}

	if finding.Severity != model.SeverityInfo {
		t.Fatalf("authenticated broker must be info, got %v", finding.Severity)
	}
}

func TestProbeMQTTRejectsNonConnack(t *testing.T) {
	t.Parallel()

	addr, stop := tcpResponder(t, []byte{0x30, 0x02, 0x00, 0x00})
	defer stop()

	if _, ok := probes.ProbeMQTT(addr, probeTimeout); ok {
		t.Fatal("a publish frame must not be treated as a connack")
	}
}

func TestProbeBACnetConfirmed(t *testing.T) {
	stop, ok := udpResponder(47808, []byte{0x81, 0x0A, 0x00, 0x08, 0x01, 0x10})
	if !ok {
		t.Skip("udp/47808 is already in use")
	}
	defer stop()

	finding, found := probes.ProbeBACnet("127.0.0.1", probeTimeout)
	if !found {
		t.Fatal("expected a bacnet finding")
	}

	if finding.Service != "BACnet/IP" {
		t.Fatalf("Service = %q", finding.Service)
	}

	if finding.Port != 47808 {
		t.Fatalf("Port = %d", finding.Port)
	}
}

func TestProbeBACnetRejectsForeignBVLC(t *testing.T) {
	stop, ok := udpResponder(47808, []byte{0x82, 0x0A, 0x00, 0x08, 0x01, 0x10})
	if !ok {
		t.Skip("udp/47808 is already in use")
	}
	defer stop()

	if _, found := probes.ProbeBACnet("127.0.0.1", probeTimeout); found {
		t.Fatal("unexpected bvlc type must not be reported")
	}
}

func TestDefaultProberWiring(t *testing.T) {
	t.Parallel()

	addr, stop := tcpResponder(t, []byte{0x20, 0x02, 0x00, 0x00})
	defer stop()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split failed: %v", err)
	}

	if port == "" {
		t.Fatal("ephemeral port was not resolved")
	}

	finding, ok := probes.ProbeMQTT(addr, probeTimeout)
	if !ok || finding.Port == 0 {
		t.Fatalf("probe did not report the negotiated port: %+v", finding)
	}
}
