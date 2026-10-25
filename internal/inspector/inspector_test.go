package inspector

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/services"
)

func TestSanitizeAndGrabBanner(t *testing.T) {
	raw := "\x1b[31mSSH-2.0-OpenSSH_9.8_Test\x1b[0m\x07\r\n"
	clean := services.SanitizeText(raw, 120)
	if strings.Contains(clean, "\x1b") || clean != "SSH-2.0-OpenSSH_9.8_Test" {
		t.Fatalf("unexpected sanitized banner: %q", clean)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(raw))
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	banner, err := GrabBanner(context.Background(), "127.0.0.1", port, 800*time.Millisecond)
	if err != nil || banner != "SSH-2.0-OpenSSH_9.8_Test" {
		t.Fatalf("unexpected banner=%q, err=%v", banner, err)
	}
}

func TestInspectHTTPAndTLS(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.27.1")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	tlsInfo, err := InspectTLS(context.Background(), host, port, "", time.Second)
	if err != nil || tlsInfo == nil || !tlsInfo.Established || tlsInfo.Certificate == nil {
		t.Fatalf("expected established TLS info, got %+v, err=%v", tlsInfo, err)
	}
	if tlsInfo.Authorized {
		t.Fatalf("expected httptest self-signed cert to report Authorized=false")
	}

	httpInfo, err := InspectHTTP(context.Background(), host, port, true, "", time.Second)
	if err != nil || httpInfo == nil || httpInfo.StatusCode != 200 || httpInfo.Server != "nginx/1.27.1" {
		t.Fatalf("unexpected HTTP inspection result: %+v, err=%v", httpInfo, err)
	}
	if len(httpInfo.MissingSecurityHeaders) == 0 {
		t.Fatal("expected missing HSTS/CSP headers to be detected")
	}
}
