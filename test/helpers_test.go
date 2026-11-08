package test

import (
	"net"
	"strconv"
	"testing"
)

func listenLoopback() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func listenerPort(t *testing.T, addr string) int {
	t.Helper()

	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port %q: %v", portText, err)
	}

	return port
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
