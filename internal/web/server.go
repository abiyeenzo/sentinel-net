package web

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/baseline"
	"github.com/abiyeenzo/sentinel-net/internal/netscope"
	"github.com/abiyeenzo/sentinel-net/internal/osint"
	"github.com/abiyeenzo/sentinel-net/internal/profiles"
	"github.com/abiyeenzo/sentinel-net/internal/report"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
)

//go:embed static/index.html
var dashboardHTML []byte

//go:embed static/logo.svg
var logoSVG []byte

const maxRequestBodyBytes = 2 << 20 // 2 MiB

// Server hosts the local Sentinel Net HTTP & Desktop GUI console.
type Server struct {
	version     string
	desktopMode bool
	mu          sync.Mutex
	active      map[string]context.CancelFunc
	lastBeat    time.Time
	doneOnce    sync.Once
	doneCh      chan struct{}
	httpSrv     *http.Server
	ln          net.Listener
}

type scanRequest struct {
	Authorized  bool            `json:"authorized"`
	Target      string          `json:"target"`
	Profile     string          `json:"profile"`
	Ports       string          `json:"ports"`
	MaxPorts    int             `json:"maxPorts"`
	TimeoutMs   int             `json:"timeoutMs"`
	Concurrency int             `json:"concurrency"`
	Retries     int             `json:"retries"`
	DelayMs     int             `json:"delayMs"`
	Banner      bool            `json:"banner"`
	TLS         bool            `json:"tls"`
	HTTP        bool            `json:"http"`
	Vuln        bool            `json:"vuln"`
	CVEOnline   bool            `json:"cveOnline"`
	OSINT       bool            `json:"osint"`
	ResolveDNS  bool            `json:"resolveDns"`
	Baseline    *scanner.Report `json:"baseline"`
}

type osintRequest struct {
	Query      string `json:"query"`
	ActiveWeb  bool   `json:"activeWeb"`
	Authorized bool   `json:"authorized"`
	TimeoutMs  int    `json:"timeoutMs"`
}

type cancelRequest struct {
	ScanID string `json:"scanId"`
}

type exportRequest struct {
	Format string          `json:"format"`
	Report *scanner.Report `json:"report"`
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON request body")
	}
	return nil
}

// Start binds and starts the HTTP audit console on addr (e.g. "127.0.0.1:3000").
func Start(addr, version string) (*Server, error) {
	return StartWithOptions(addr, version, false)
}

// StartDesktop starts the local GUI backend in desktop lifecycle mode.
func StartDesktop(addr, version string) (*Server, error) {
	return StartWithOptions(addr, version, true)
}

// StartWithOptions binds and starts the server with optional desktop window lifecycle management.
func StartWithOptions(addr, version string, desktopMode bool) (*Server, error) {
	if version == "" {
		version = "1.0.0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s := &Server{
		version:     version,
		desktopMode: desktopMode,
		active:      make(map[string]context.CancelFunc),
		lastBeat:    time.Now(),
		doneCh:      make(chan struct{}),
		ln:          ln,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/logo.svg", s.handleLogo)
	mux.HandleFunc("/favicon.ico", s.handleLogo)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/scan/cancel", s.handleCancel)
	mux.HandleFunc("/api/osint", s.handleOSINT)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/window-closed", s.handleWindowClosed)

	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = s.httpSrv.Serve(ln)
	}()

	return s, nil
}

// Addr returns the bound TCP address of the running server.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Done closes when a desktop window session ends.
func (s *Server) Done() <-chan struct{} {
	return s.doneCh
}

func (s *Server) signalDone() {
	s.doneOnce.Do(func() {
		close(s.doneCh)
	})
}

// Close gracefully shuts down the server and cancels any in-flight scans.
func (s *Server) Close(ctx context.Context) error {
	s.signalDone()
	s.mu.Lock()
	for id, cancel := range s.active {
		cancel()
		delete(s.active, id)
	}
	s.mu.Unlock()
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(logoSVG)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	activeCount := len(s.active)
	s.lastBeat = time.Now()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     s.version,
		"desktopMode": s.desktopMode,
		"activeScans": activeCount,
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	s.lastBeat = time.Now()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleWindowClosed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.desktopMode {
		closedAt := time.Now()
		go func() {
			time.Sleep(2500 * time.Millisecond)
			s.mu.Lock()
			reconnected := s.lastBeat.After(closedAt)
			s.mu.Unlock()
			if !reconnected {
				s.signalDone()
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ifaces, err := netscope.ListLocalInterfaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": ifaces})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles.All()})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body cancelRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	cancel, ok := s.active[body.ScanID]
	if ok {
		delete(s.active, body.ScanID)
	}
	s.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"cancelled": false, "error": "active scan not found"})
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": true})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req scanRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !req.Authorized {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "explicit authorization required: confirm authorization only for assets you are permitted to scan",
		})
		return
	}

	// Normalize space-separated Nmap-style target lists into comma-separated tokens
	normTarget := strings.Join(strings.Fields(strings.ReplaceAll(req.Target, ",", " ")), ",")
	resolvedTargets, err := netscope.ResolveTargets(r.Context(), normTarget, netscope.ResolveOptions{
		ResolveDNS: req.ResolveDNS || req.OSINT,
		MaxHosts:   netscope.DefaultMaxHosts,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	profileName := strings.TrimSpace(req.Profile)
	portsSpec := strings.TrimSpace(req.Ports)
	maxPorts := req.MaxPorts
	if portsSpec == "-" {
		portsSpec = "1-4096"
		if maxPorts < netscope.HardMaxPorts {
			maxPorts = netscope.HardMaxPorts
		}
	}
	if portsSpec == "" && profileName == "" {
		profileName = "top100"
	}
	if maxPorts <= 0 {
		maxPorts = netscope.DefaultMaxPorts
		if strings.Contains(portsSpec, "-") {
			maxPorts = netscope.HardMaxPorts
		}
	}

	ports, err := netscope.ResolvePortSelection(portsSpec, profileName, maxPorts)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 1000 * time.Millisecond
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = 24
	}

	scanID := randomID()
	scanCtx, cancel := context.WithCancel(r.Context())
	s.mu.Lock()
	s.active[scanID] = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.active, scanID)
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	var writeMu sync.Mutex
	sendEvent := func(v any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		raw, mErr := json.Marshal(v)
		if mErr != nil {
			return
		}
		_, _ = w.Write(append(raw, '\n'))
		if flusher != nil {
			flusher.Flush()
		}
	}

	sendEvent(map[string]any{
		"type":       "started",
		"scanId":     scanID,
		"hostsCount": len(resolvedTargets),
		"portsCount": len(ports),
	})

	rep, err := scanner.ScanNetwork(scanCtx, scanner.NetworkOptions{
		Targets:     resolvedTargets,
		Ports:       ports,
		Profile:     profileName,
		Version:     s.version,
		Timeout:     timeout,
		Concurrency: conc,
		Retries:     req.Retries,
		Delay:       time.Duration(req.DelayMs) * time.Millisecond,
		Banner:      req.Banner,
		TLS:         req.TLS,
		HTTP:        req.HTTP,
		Vuln:        req.Vuln,
		CVEOnline:   req.CVEOnline,
		OSINT:       req.OSINT,
		OnProgress: func(ev scanner.ProgressEvent) {
			sendEvent(map[string]any{
				"type":    "progress",
				"target":  ev.Target,
				"port":    ev.Port,
				"state":   ev.State,
				"percent": ev.Percent,
			})
		},
	})
	if err != nil {
		sendEvent(map[string]any{"type": "error", "error": err.Error()})
		return
	}

	if req.Baseline != nil {
		drift := baseline.Compare(req.Baseline, rep)
		rep.Drift = drift
	}

	sendEvent(map[string]any{
		"type":       "complete",
		"report":     rep,
		"nmapOutput": report.FormatNmap(rep, false),
	})
}

func (s *Server) handleOSINT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req osintRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	q := strings.TrimSpace(req.Query)
	if q == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing OSINT target domain or IP"})
		return
	}
	if req.ActiveWeb && !req.Authorized && q != "127.0.0.1" && q != "::1" && !strings.EqualFold(q, "localhost") {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "active web surface inspection requires explicit authorization checkbox",
		})
		return
	}
	timeout := 6 * time.Second
	if req.TimeoutMs >= 1000 && req.TimeoutMs <= 20000 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	oRep, err := osint.Run(r.Context(), q, osint.Options{
		Timeout:   timeout,
		ActiveWeb: req.ActiveWeb,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"osint":       oRep,
		"tableOutput": report.FormatOSINTTable(oRep, false),
	})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req exportRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Report == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing report payload"})
		return
	}
	fmtName := strings.ToLower(strings.TrimSpace(req.Format))
	if fmtName == "" {
		fmtName = "json"
	}
	rendered, err := report.Format(req.Report, report.Options{Format: fmtName})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	contentType := "text/plain; charset=utf-8"
	ext := "txt"
	switch fmtName {
	case "html":
		contentType = "text/html; charset=utf-8"
		ext = "html"
	case "json":
		contentType = "application/json; charset=utf-8"
		ext = "json"
	case "sarif":
		contentType = "application/sarif+json; charset=utf-8"
		ext = "sarif"
	case "markdown", "md":
		contentType = "text/markdown; charset=utf-8"
		ext = "md"
	case "csv":
		contentType = "text/csv; charset=utf-8"
		ext = "csv"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\"sentinel-net-audit."+ext+"\"")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(rendered))
}
