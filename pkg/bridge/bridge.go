package bridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"nezha_iot_sec/pkg/config"
	"nezha_iot_sec/pkg/logger"
	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/scan"
	"nezha_iot_sec/pkg/vault"
)

const (
	ProtocolVersion = 1

	typeHello      = "hello"
	typeWelcome    = "welcome"
	typeScanStart  = "scan.start"
	typeScanDone   = "scan.done"
	typeScanCancel = "scan.cancel"
	typeResults    = "results"
	typeFinding    = "finding"
	typePing       = "ping"
	typePong       = "pong"
	typeError      = "error"
	typeShutdown   = "shutdown"

	codeBadRequest       = "bad_request"
	codeUnsupportedProto = "unsupported_protocol"
	codeScanInProgress   = "scan_in_progress"
	codeScanFailed       = "scan_failed"
	codeResultsFailed    = "results_failed"

	idleTimeout  = 30 * time.Second
	writeTimeout = 5 * time.Second
)

type Scanner interface {
	Scan(ctx context.Context, req scan.Request) ([]model.Finding, error)
}

type Config struct {
	Addr        string
	Key         []byte
	KeyMode     config.CryptoKeyMode
	EncryptWire bool
	Vault       *vault.Vault
	Scanner     Scanner
	Logger      *logger.Logger
	Defaults    scan.Request
}

type Server struct {
	cfg      Config
	listener net.Listener
	log      *logger.Logger

	lifecycle sync.Mutex
	cancel    context.CancelFunc
	running   bool

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

type inbound struct {
	Type     string `json:"type"`
	Protocol int    `json:"protocol"`
	CIDR     string `json:"cidr"`
	Ports    []int  `json:"ports"`
	ARPOnly  bool   `json:"arp_only"`
}

type outbound struct {
	Type      string `json:"type"`
	Protocol  int    `json:"protocol,omitempty"`
	App       string `json:"app,omitempty"`
	KeyMode   string `json:"key_mode,omitempty"`
	Wire      string `json:"wire,omitempty"`
	KeyB64    string `json:"key_b64,omitempty"`
	Seq       int    `json:"seq,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Cipher    bool   `json:"cipher,omitempty"`
	Count     int    `json:"count,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Cancelled bool   `json:"cancelled,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	TS        string `json:"ts,omitempty"`
}

func New(cfg Config) (*Server, error) {
	if cfg.Scanner == nil {
		return nil, fmt.Errorf("bridge: scanner is required")
	}

	if cfg.Vault == nil {
		return nil, fmt.Errorf("bridge: vault is required")
	}

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("bridge: listen on %s: %w", cfg.Addr, err)
	}

	log := cfg.Logger
	if log == nil {
		log = logger.Default()
	}

	return &Server{
		cfg:      cfg,
		listener: listener,
		log:      log,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) Serve(ctx context.Context) error {
	defer s.listener.Close()

	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
		s.closeConns()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}

			return fmt.Errorf("bridge: accept: %w", err)
		}

		s.track(conn)
		s.wg.Add(1)

		go func() {
			defer s.wg.Done()
			defer s.untrack(conn)
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReaderSize(conn, 64*1024)
	encoder := json.NewEncoder(conn)
	writer := &sync.Mutex{}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))

		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}

		var frame inbound
		if err := json.Unmarshal(line, &frame); err != nil {
			s.write(conn, encoder, outbound{Type: typeError, Code: codeBadRequest, Message: "malformed json frame"})
			continue
		}

		switch frame.Type {
		case typeHello:
			if err := s.handleHello(conn, encoder, frame); err != nil {
				return
			}
		case typePing:
			s.write(conn, encoder, outbound{Type: typePong, TS: time.Now().UTC().Format(time.RFC3339)})
		case typeScanStart:
			s.handleScanStart(ctx, conn, encoder, writer, frame)
		case typeScanCancel:
			s.cancelScan()
		case typeResults:
			s.handleResults(conn, encoder)
		case typeShutdown:
			return
		default:
			s.write(conn, encoder, outbound{Type: typeError, Code: codeBadRequest, Message: "unknown frame type"})
		}
	}
}

func (s *Server) handleHello(conn net.Conn, encoder *json.Encoder, frame inbound) error {
	if frame.Protocol != ProtocolVersion {
		_ = s.write(conn, encoder, outbound{
			Type:    typeError,
			Code:    codeUnsupportedProto,
			Message: fmt.Sprintf("bridge speaks protocol %d", ProtocolVersion),
		})

		return errors.New("bridge: unsupported protocol")
	}

	welcome := outbound{
		Type:     typeWelcome,
		Protocol: ProtocolVersion,
		App:      "nezhaiot",
		KeyMode:  string(s.cfg.KeyMode),
		Wire:     "plain",
	}

	if s.cfg.EncryptWire {
		welcome.Wire = "aead"
	}

	if s.cfg.KeyMode == config.CryptoKeyEphemeral && len(s.cfg.Key) == 32 {
		welcome.KeyB64 = base64.StdEncoding.EncodeToString(s.cfg.Key)
	}

	return s.write(conn, encoder, welcome)
}

func (s *Server) handleScanStart(ctx context.Context, conn net.Conn, encoder *json.Encoder, writer *sync.Mutex, frame inbound) {
	if !s.beginScan() {
		s.write(conn, encoder, outbound{Type: typeError, Code: codeScanInProgress, Message: "a scan is already running"})
		return
	}
	defer s.endScan()

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.lifecycle.Lock()
	s.cancel = cancel
	s.lifecycle.Unlock()

	seq := 0
	started := time.Now()

	req := s.cfg.Defaults
	req.CIDR = frame.CIDR
	req.ARPOnly = frame.ARPOnly
	if len(frame.Ports) > 0 {
		req.Ports = frame.Ports
	}
	req.OnFinding = func(finding model.Finding) {
		if err := s.cfg.Vault.Add(finding); err != nil {
			s.log.PrintWarning("结果入库失败: %v", err)
		}

		writer.Lock()
		defer writer.Unlock()

		seq++
		if err := s.streamFinding(conn, encoder, seq, finding); err != nil {
			return
		}
	}

	findings, err := s.cfg.Scanner.Scan(scanCtx, req)
	elapsed := time.Since(started)

	if err != nil {
		s.write(conn, encoder, outbound{Type: typeError, Code: codeScanFailed, Message: err.Error()})
		return
	}

	s.write(conn, encoder, outbound{
		Type:      typeScanDone,
		Count:     len(findings),
		ElapsedMS: elapsed.Milliseconds(),
		Cancelled: scanCtx.Err() != nil,
	})
}

func (s *Server) handleResults(conn net.Conn, encoder *json.Encoder) {
	findings, err := s.cfg.Vault.Snapshot()
	if err != nil {
		s.write(conn, encoder, outbound{Type: typeError, Code: codeResultsFailed, Message: err.Error()})
		return
	}

	plain, err := json.Marshal(findings)
	if err != nil {
		s.write(conn, encoder, outbound{Type: typeError, Code: codeResultsFailed, Message: err.Error()})
		return
	}

	frame := outbound{Type: typeResults, Count: len(findings), Payload: string(plain)}

	if s.cfg.EncryptWire {
		sealed, err := s.cfg.Vault.Seal(plain, vault.AAD("results"))
		if err != nil {
			s.write(conn, encoder, outbound{Type: typeError, Code: codeResultsFailed, Message: err.Error()})
			return
		}

		frame.Payload = base64.StdEncoding.EncodeToString(sealed)
		frame.Cipher = true
	}

	s.write(conn, encoder, frame)
}

func (s *Server) streamFinding(conn net.Conn, encoder *json.Encoder, seq int, finding model.Finding) error {
	frame := outbound{Type: typeFinding, Seq: seq}

	plain, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("bridge: encode finding: %w", err)
	}

	frame.Payload = string(plain)

	if s.cfg.EncryptWire {
		sealed, err := s.cfg.Vault.Seal(plain, vault.AAD("finding"))
		if err != nil {
			return err
		}

		frame.Payload = base64.StdEncoding.EncodeToString(sealed)
		frame.Cipher = true
	}

	return s.write(conn, encoder, frame)
}

func (s *Server) write(conn net.Conn, encoder *json.Encoder, frame outbound) error {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	if err := encoder.Encode(frame); err != nil {
		return fmt.Errorf("bridge: write frame: %w", err)
	}

	return nil
}

func (s *Server) beginScan() bool {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	if s.running {
		return false
	}

	s.running = true
	return true
}

func (s *Server) endScan() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	s.running = false
	s.cancel = nil
}

func (s *Server) cancelScan() {
	s.lifecycle.Lock()
	cancel := s.cancel
	s.lifecycle.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (s *Server) track(conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	s.conns[conn] = struct{}{}
}

func (s *Server) untrack(conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	delete(s.conns, conn)
}

func (s *Server) closeConns() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	for conn := range s.conns {
		_ = conn.Close()
	}
}
