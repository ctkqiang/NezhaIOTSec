package test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"nezha_iot_sec/pkg/bridge"
	"nezha_iot_sec/pkg/config"
	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/scan"
	"nezha_iot_sec/pkg/vault"
)

const bridgeDeadline = 3 * time.Second

type stubScanner struct {
	findings []model.Finding
}

func (s stubScanner) Scan(_ context.Context, req scan.Request) ([]model.Finding, error) {
	if req.OnFinding != nil {
		for _, finding := range s.findings {
			req.OnFinding(finding)
		}
	}

	return s.findings, nil
}

type frame struct {
	Type     string `json:"type"`
	Protocol int    `json:"protocol"`
	App      string `json:"app"`
	KeyMode  string `json:"key_mode"`
	Wire     string `json:"wire"`
	KeyB64   string `json:"key_b64"`
	Seq      int    `json:"seq"`
	Payload  string `json:"payload"`
	Cipher   bool   `json:"cipher"`
	Count    int    `json:"count"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func startBridge(t *testing.T, findings []model.Finding, encrypt bool) (string, func()) {
	t.Helper()

	key, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("vault.New failed: %v", err)
	}

	server, err := bridge.New(bridge.Config{
		Addr:        "127.0.0.1:0",
		Key:         key,
		KeyMode:     config.CryptoKeyEphemeral,
		EncryptWire: encrypt,
		Vault:       store,
		Scanner:     stubScanner{findings: findings},
		Logger:      quietLogger(),
		Defaults: scan.Request{
			Ports:       []int{502, 1883, 47808},
			Workers:     2,
			Timeout:     time.Second,
			PortTimeout: time.Second,
		},
	})
	if err != nil {
		t.Fatalf("bridge.New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- server.Serve(ctx)
	}()

	stop := func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("bridge shutdown error: %v", err)
			}
		case <-time.After(bridgeDeadline):
			t.Error("bridge did not shut down after cancellation")
		}

		store.Close()
	}

	return server.Addr(), stop
}

func dialBridge(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, bridgeDeadline)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}

	return conn, bufio.NewReaderSize(conn, 64*1024)
}

func sendFrame(t *testing.T, conn net.Conn, payload any) {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readFrame(t *testing.T, conn net.Conn, reader *bufio.Reader) frame {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(bridgeDeadline))

	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	var decoded frame
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("decode frame %q: %v", line, err)
	}

	return decoded
}

func bridgeFindings() []model.Finding {
	return []model.Finding{
		{
			IP:       "10.0.0.1",
			Port:     502,
			Service:  "Modbus-TCP",
			Severity: model.SeverityHigh,
			Detail:   "Modbus PLC Confirmed (FC 0x2B device identification)",
			FoundAt:  time.Now().UTC(),
		},
		{
			IP:       "10.0.0.2",
			Port:     1883,
			Service:  "MQTT",
			Severity: model.SeverityCritical,
			Detail:   "CRITICAL: Unauthenticated MQTT Broker Access Allowed",
			FoundAt:  time.Now().UTC(),
		},
	}
}

func TestBridgeHandshakeScanAndResults(t *testing.T) {
	t.Parallel()

	findings := bridgeFindings()

	addr, stop := startBridge(t, findings, false)
	defer stop()

	conn, reader := dialBridge(t, addr)
	defer conn.Close()

	sendFrame(t, conn, map[string]any{"type": "hello", "protocol": bridge.ProtocolVersion})
	welcome := readFrame(t, conn, reader)

	if welcome.Type != "welcome" {
		t.Fatalf("first frame = %+v, want welcome", welcome)
	}

	if welcome.Protocol != bridge.ProtocolVersion {
		t.Fatalf("welcome protocol = %d", welcome.Protocol)
	}

	if welcome.App != "nezhaiot" {
		t.Fatalf("welcome app = %q", welcome.App)
	}

	if welcome.Wire != "plain" {
		t.Fatalf("welcome wire = %q", welcome.Wire)
	}

	if welcome.KeyB64 == "" {
		t.Fatal("ephemeral mode must publish the session key in the welcome frame")
	}

	sendFrame(t, conn, map[string]any{"type": "scan.start", "protocol": bridge.ProtocolVersion})

	streamed := 0
	for {
		next := readFrame(t, conn, reader)

		if next.Type == "finding" {
			streamed++

			if next.Seq != streamed {
				t.Fatalf("finding seq = %d, want %d", next.Seq, streamed)
			}

			var decoded model.Finding
			if err := json.Unmarshal([]byte(next.Payload), &decoded); err != nil {
				t.Fatalf("finding payload is not json: %v", err)
			}
			continue
		}

		if next.Type == "scan.done" {
			if next.Count != len(findings) {
				t.Fatalf("scan.done count = %d, want %d", next.Count, len(findings))
			}
			break
		}

		t.Fatalf("unexpected frame during scan: %+v", next)
	}

	if streamed != len(findings) {
		t.Fatalf("streamed %d findings, want %d", streamed, len(findings))
	}

	sendFrame(t, conn, map[string]any{"type": "results"})
	results := readFrame(t, conn, reader)

	if results.Type != "results" {
		t.Fatalf("results frame = %+v", results)
	}

	if results.Count != len(findings) {
		t.Fatalf("results count = %d, want %d", results.Count, len(findings))
	}

	if results.Cipher {
		t.Fatal("wire encryption is disabled, payload must stay plain")
	}

	var decoded []model.Finding
	if err := json.Unmarshal([]byte(results.Payload), &decoded); err != nil {
		t.Fatalf("results payload is not json: %v", err)
	}

	if len(decoded) != len(findings) {
		t.Fatalf("decoded %d findings, want %d", len(decoded), len(findings))
	}

	sendFrame(t, conn, map[string]any{"type": "ping"})
	if pong := readFrame(t, conn, reader); pong.Type != "pong" {
		t.Fatalf("ping reply = %+v", pong)
	}
}

func TestBridgeEncryptedWire(t *testing.T) {
	t.Parallel()

	findings := bridgeFindings()

	addr, stop := startBridge(t, findings, true)
	defer stop()

	conn, reader := dialBridge(t, addr)
	defer conn.Close()

	sendFrame(t, conn, map[string]any{"type": "hello", "protocol": bridge.ProtocolVersion})
	welcome := readFrame(t, conn, reader)

	if welcome.Wire != "aead" {
		t.Fatalf("welcome wire = %q, want aead", welcome.Wire)
	}

	key, err := base64.StdEncoding.DecodeString(welcome.KeyB64)
	if err != nil {
		t.Fatalf("session key is not base64: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("session key is unusable: %v", err)
	}
	defer store.Close()

	sendFrame(t, conn, map[string]any{"type": "scan.start", "protocol": bridge.ProtocolVersion})

	for {
		next := readFrame(t, conn, reader)

		if next.Type == "finding" {
			if !next.Cipher {
				t.Fatal("encrypted mode must flag streamed findings as ciphertext")
			}

			sealed, err := base64.StdEncoding.DecodeString(next.Payload)
			if err != nil {
				t.Fatalf("finding payload is not base64: %v", err)
			}

			plain, err := store.Open(sealed, vault.AAD("finding"))
			if err != nil {
				t.Fatalf("finding cannot be decrypted: %v", err)
			}

			var decoded model.Finding
			if err := json.Unmarshal(plain, &decoded); err != nil {
				t.Fatalf("decrypted finding is not json: %v", err)
			}

			continue
		}

		if next.Type == "scan.done" {
			break
		}

		t.Fatalf("unexpected frame during scan: %+v", next)
	}

	sendFrame(t, conn, map[string]any{"type": "results"})
	results := readFrame(t, conn, reader)

	if !results.Cipher {
		t.Fatal("results must be ciphertext when wire encryption is on")
	}

	sealed, err := base64.StdEncoding.DecodeString(results.Payload)
	if err != nil {
		t.Fatalf("results payload is not base64: %v", err)
	}

	plain, err := store.Open(sealed, vault.AAD("results"))
	if err != nil {
		t.Fatalf("results cannot be decrypted: %v", err)
	}

	var decoded []model.Finding
	if err := json.Unmarshal(plain, &decoded); err != nil {
		t.Fatalf("decrypted results are not json: %v", err)
	}

	if len(decoded) != len(findings) {
		t.Fatalf("decrypted %d findings, want %d", len(decoded), len(findings))
	}
}

func TestBridgeRejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	addr, stop := startBridge(t, nil, false)
	defer stop()

	conn, reader := dialBridge(t, addr)
	defer conn.Close()

	sendFrame(t, conn, map[string]any{"type": "hello", "protocol": bridge.ProtocolVersion + 1})
	reply := readFrame(t, conn, reader)

	if reply.Type != "error" || reply.Code != "unsupported_protocol" {
		t.Fatalf("reply = %+v, want unsupported_protocol", reply)
	}
}

func TestBridgeRejectsMalformedAndUnknownFrames(t *testing.T) {
	t.Parallel()

	addr, stop := startBridge(t, nil, false)
	defer stop()

	conn, reader := dialBridge(t, addr)
	defer conn.Close()

	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if reply := readFrame(t, conn, reader); reply.Type != "error" || reply.Code != "bad_request" {
		t.Fatalf("malformed frame reply = %+v", reply)
	}

	sendFrame(t, conn, map[string]any{"type": "teleport"})
	if reply := readFrame(t, conn, reader); reply.Type != "error" || reply.Code != "bad_request" {
		t.Fatalf("unknown frame reply = %+v", reply)
	}
}

func TestBridgeStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	addr, stop := startBridge(t, nil, false)

	conn, err := net.DialTimeout("tcp", addr, bridgeDeadline)
	if err != nil {
		stop()
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	stop()

	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
}
