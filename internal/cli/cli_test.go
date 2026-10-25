package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/report"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
	"github.com/abiyeenzo/sentinel-net/internal/web"
)

func bufferIO() (IO, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	return IO{Stdout: out, Stderr: errBuf, StdoutTTY: false, StderrTTY: false}, out, errBuf
}

func TestCLIGuardrailsScansFormatsAndDriftGate(t *testing.T) {
	ctx := context.Background()

	// Refuses scan without --authorized
	ioCfg, _, errBuf := bufferIO()
	if code := Run(ctx, []string{"--target", "127.0.0.1", "--ports", "80"}, ioCfg); code != 2 {
		t.Fatalf("expected exit code 2 without --authorized, got %d (stderr=%s)", code, errBuf.String())
	}

	// Version and Help
	ioCfg, out, _ := bufferIO()
	if code := Run(ctx, []string{"--version"}, ioCfg); code != 0 || !strings.Contains(out.String(), "sentinel-net v") {
		t.Fatalf("unexpected --version result: code=%d out=%q", code, out.String())
	}

	ioCfg, out, _ = bufferIO()
	if code := Run(ctx, []string{"--help"}, ioCfg); code != 0 || !strings.Contains(out.String(), "USAGE:") {
		t.Fatalf("unexpected --help result: code=%d", code)
	}

	// Real TCP listener + banner + baseline + HTML + drift policy gate
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen1: %v", err)
	}
	defer ln1.Close()
	go func() {
		for {
			c, err := ln1.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.7\r\n"))
			_ = c.Close()
		}
	}()

	openPort := ln1.Addr().(*net.TCPAddr).Port
	tmpDir := t.TempDir()
	baseFile := filepath.Join(tmpDir, "base.json")
	htmlFile := filepath.Join(tmpDir, "audit.html")

	ioCfg, out, errBuf = bufferIO()
	code := Run(ctx, []string{
		"scan",
		"--target", "127.0.0.1",
		"--ports", strconv.Itoa(openPort),
		"--banner",
		"--authorized",
		"--save-baseline", baseFile,
		"--report-html", htmlFile,
	}, ioCfg)
	if code != 0 {
		t.Fatalf("expected scan code 0, got %d (stderr=%s)", code, errBuf.String())
	}

	var parsed scanner.Report
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid scan JSON: %v", err)
	}
	if parsed.Summary.OpenPorts != 1 || parsed.Observations[0].Inspection == nil || parsed.Observations[0].Inspection.Banner != "SSH-2.0-OpenSSH_9.7" {
		t.Fatalf("unexpected scan observation: %+v", parsed.Observations)
	}
	if st, err := os.Stat(htmlFile); err != nil || st.Size() < 800 {
		t.Fatalf("expected non-empty HTML report, err=%v", err)
	}

	// Verify table, sarif, markdown and csv formatters
	for _, fmtName := range []string{"table", "sarif", "markdown", "csv"} {
		rendered, err := report.Format(&parsed, report.Options{Format: fmtName})
		if err != nil || len(rendered) == 0 {
			t.Fatalf("report format %q failed: %v", fmtName, err)
		}
	}

	// Open a second port and assert --fail-on-drift exits with code 3
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port2 := ln2.Addr().(*net.TCPAddr).Port

	ioCfg, _, errBuf = bufferIO()
	driftCode := Run(ctx, []string{
		"scan",
		"--target", "127.0.0.1",
		"--ports", strconv.Itoa(openPort) + "," + strconv.Itoa(port2),
		"--authorized",
		"--compare", baseFile,
		"--fail-on-drift",
	}, ioCfg)
	if driftCode != 3 {
		t.Fatalf("expected exit code 3 on drift gate, got %d (stderr=%s)", driftCode, errBuf.String())
	}
}

func TestWebConsoleServerEndpoints(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	targetPort := ln.Addr().(*net.TCPAddr).Port

	srv, err := web.Start("127.0.0.1:0", "1.0.0")
	if err != nil {
		t.Fatalf("web.Start failed: %v", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Close(shutCtx)
	}()

	baseURL := "http://" + srv.Addr()

	// Root UI
	resp, err := http.Get(baseURL + "/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET / failed: %v", err)
	}
	_ = resp.Body.Close()

	// Embedded SVG logo
	logoResp, err := http.Get(baseURL + "/logo.svg")
	if err != nil || logoResp.StatusCode != 200 {
		t.Fatalf("GET /logo.svg failed: %v", err)
	}
	if !strings.Contains(logoResp.Header.Get("Content-Type"), "image/svg+xml") {
		t.Fatalf("unexpected logo content-type: %s", logoResp.Header.Get("Content-Type"))
	}
	_ = logoResp.Body.Close()

	// Unauthorized scan returns 400
	unauthResp, err := http.Post(baseURL+"/api/scan", "application/json",
		strings.NewReader(`{"authorized":false,"target":"127.0.0.1","ports":"80"}`))
	if err != nil || unauthResp.StatusCode != 400 {
		t.Fatalf("expected 400 for unauthorized scan, got %v, err=%v", unauthResp, err)
	}
	_ = unauthResp.Body.Close()

	// Authorized streaming scan returns started + complete
	scanPayload := `{"authorized":true,"target":"127.0.0.1","ports":"` + strconv.Itoa(targetPort) + `","timeoutMs":500,"concurrency":4}`
	scanResp, err := http.Post(baseURL+"/api/scan", "application/json", strings.NewReader(scanPayload))
	if err != nil || scanResp.StatusCode != 200 {
		t.Fatalf("POST /api/scan failed: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(scanResp.Body)
	_ = scanResp.Body.Close()
	if !strings.Contains(buf.String(), `"type":"complete"`) || !strings.Contains(buf.String(), `"nmapOutput"`) {
		t.Fatalf("expected complete NDJSON event with nmapOutput, got %s", buf.String())
	}
}

func TestNmapStyleCLIAndMultiOutput(t *testing.T) {
	ctx := context.Background()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.8\r\n"))
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Compact Nmap syntax: -sV -T4 -p<port> --nmap <target> -y
	ioCfg, out, errBuf := bufferIO()
	code := Run(ctx, []string{
		"-sV",
		"-T4",
		"-p" + strconv.Itoa(openPort),
		"--nmap",
		"127.0.0.1",
		"-y",
	}, ioCfg)
	if code != 0 {
		t.Fatalf("expected exit 0 on Nmap shorthand, got %d (stderr=%s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Sentinel Net scan report for 127.0.0.1") ||
		!strings.Contains(out.String(), "|_ banner: SSH-2.0-OpenSSH_9.8") {
		t.Fatalf("unexpected Nmap formatted output:\n%s", out.String())
	}

	// -oA writes .txt, .json, .html, and .sarif simultaneously
	tmpDir := t.TempDir()
	prefix := filepath.Join(tmpDir, "audit-all")
	ioCfg, _, errBuf = bufferIO()
	code = Run(ctx, []string{
		"-A",
		"--top-ports", "5",
		"127.0.0.1",
		"-oA", prefix,
		"-y",
	}, ioCfg)
	if code != 0 {
		t.Fatalf("expected exit 0 on -oA, got %d (stderr=%s)", code, errBuf.String())
	}
	for _, ext := range []string{".txt", ".json", ".html", ".sarif"} {
		st, statErr := os.Stat(prefix + ext)
		if statErr != nil || st.Size() == 0 {
			t.Fatalf("expected non-empty %s file, err=%v", prefix+ext, statErr)
		}
	}
}
