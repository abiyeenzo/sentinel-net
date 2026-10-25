package inspector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/services"
)

// CertificateInfo holds parsed X.509 certificate metadata.
type CertificateInfo struct {
	SubjectCN         string `json:"subjectCN,omitempty"`
	IssuerCN          string `json:"issuerCN,omitempty"`
	SubjectAltName    string `json:"subjectAltName,omitempty"`
	ValidFrom         string `json:"validFrom,omitempty"`
	ValidTo           string `json:"validTo,omitempty"`
	DaysRemaining     int    `json:"daysRemaining"`
	Expired           bool   `json:"expired"`
	ExpiringSoon      bool   `json:"expiringSoon"`
	SelfSigned        bool   `json:"selfSigned"`
	FingerprintSHA256 string `json:"fingerprint256,omitempty"`
	SerialNumber      string `json:"serialNumber,omitempty"`
}

// CipherInfo describes the negotiated TLS cipher suite.
type CipherInfo struct {
	Name string `json:"name"`
}

// TLSInfo holds TLS handshake and certificate audit observations.
type TLSInfo struct {
	Established        bool             `json:"established"`
	Protocol           string           `json:"protocol"`
	Cipher             *CipherInfo      `json:"cipher,omitempty"`
	Authorized         bool             `json:"authorized"`
	AuthorizationError string           `json:"authorizationError,omitempty"`
	Certificate        *CertificateInfo `json:"certificate,omitempty"`
}

// SecurityHeaders captures defensive HTTP response headers.
type SecurityHeaders struct {
	StrictTransportSecurity string `json:"strictTransportSecurity,omitempty"`
	ContentSecurityPolicy   string `json:"contentSecurityPolicy,omitempty"`
	XFrameOptions           string `json:"xFrameOptions,omitempty"`
	XContentTypeOptions     string `json:"xContentTypeOptions,omitempty"`
	ReferrerPolicy          string `json:"referrerPolicy,omitempty"`
	PermissionsPolicy       string `json:"permissionsPolicy,omitempty"`
}

// HTTPInfo holds read-only HTTP HEAD response observations.
type HTTPInfo struct {
	Scheme                 string          `json:"scheme"`
	StatusCode             int             `json:"statusCode"`
	StatusMessage          string          `json:"statusMessage,omitempty"`
	Server                 string          `json:"server,omitempty"`
	PoweredBy              string          `json:"poweredBy,omitempty"`
	Location               string          `json:"location,omitempty"`
	ContentType            string          `json:"contentType,omitempty"`
	SecurityHeaders        SecurityHeaders `json:"securityHeaders"`
	MissingSecurityHeaders []string        `json:"missingSecurityHeaders,omitempty"`
}

// Result aggregates optional passive protocol metadata for an open TCP port.
type Result struct {
	Banner string    `json:"banner,omitempty"`
	TLS    *TLSInfo  `json:"tls,omitempty"`
	HTTP   *HTTPInfo `json:"http,omitempty"`
}

// Options controls which non-intrusive protocol checks run on open ports.
type Options struct {
	Banner     bool
	TLS        bool
	HTTP       bool
	ServerName string
	Timeout    time.Duration
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func formatFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// GrabBanner reads up to maxBytes of an initial server greeting without sending application data.
func GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	if timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", nil
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	var collected bytes.Buffer

	for collected.Len() < 512 {
		n, readErr := conn.Read(buf[:512-collected.Len()])
		if n > 0 {
			chunk := buf[:n]
			collected.Write(chunk)
			if bytes.IndexByte(chunk, '\n') >= 0 {
				break
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			break
		}
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}
	return services.SanitizeText(collected.String(), 240), nil
}

// InspectTLS performs a read-only TLS handshake and inspects the leaf X.509 certificate.
func InspectTLS(ctx context.Context, host string, port int, serverName string, timeout time.Duration) (*TLSInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	sni := strings.TrimSpace(serverName)
	if sni != "" {
		if _, err := netip.ParseAddr(sni); err == nil {
			sni = ""
		}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // Intentional: read metadata from self-signed/expired certs and verify separately below.
		MinVersion:         tls.VersionTLS10,
	}
	if sni != "" {
		tlsCfg.ServerName = sni
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    tlsCfg,
	}
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil
	}
	state := tlsConn.ConnectionState()

	info := &TLSInfo{
		Established: true,
		Protocol:    tlsVersionName(state.Version),
		Cipher:      &CipherInfo{Name: tls.CipherSuiteName(state.CipherSuite)},
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, ic := range state.PeerCertificates[1:] {
			intermediates.AddCert(ic)
		}
		verifyDNS := sni
		if verifyDNS == "" {
			verifyDNS = host
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{
			DNSName:       verifyDNS,
			Intermediates: intermediates,
		})
		if verifyErr == nil {
			info.Authorized = true
		} else {
			info.Authorized = false
			info.AuthorizationError = services.SanitizeText(verifyErr.Error(), 140)
		}

		daysRemaining := int(math.Floor(time.Until(leaf.NotAfter).Hours() / 24.0))
		selfSigned := bytes.Equal(leaf.RawIssuer, leaf.RawSubject)

		var sans []string
		for _, d := range leaf.DNSNames {
			sans = append(sans, "DNS:"+d)
		}
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, "IP:"+ip.String())
		}

		subject := leaf.Subject.CommonName
		if subject == "" && len(leaf.Subject.Organization) > 0 {
			subject = leaf.Subject.Organization[0]
		}
		issuer := leaf.Issuer.CommonName
		if issuer == "" && len(leaf.Issuer.Organization) > 0 {
			issuer = leaf.Issuer.Organization[0]
		}

		info.Certificate = &CertificateInfo{
			SubjectCN:         services.SanitizeText(subject, 120),
			IssuerCN:          services.SanitizeText(issuer, 120),
			SubjectAltName:    services.SanitizeText(strings.Join(sans, ", "), 240),
			ValidFrom:         leaf.NotBefore.UTC().Format(time.RFC3339),
			ValidTo:           leaf.NotAfter.UTC().Format(time.RFC3339),
			DaysRemaining:     daysRemaining,
			Expired:           time.Now().After(leaf.NotAfter),
			ExpiringSoon:      !time.Now().After(leaf.NotAfter) && daysRemaining <= 30,
			SelfSigned:        selfSigned,
			FingerprintSHA256: formatFingerprint(leaf.Raw),
			SerialNumber:      strings.ToUpper(leaf.SerialNumber.Text(16)),
		}
	}

	return info, nil
}

// InspectHTTP sends a safe HEAD / request and audits defensive HTTP headers.
func InspectHTTP(ctx context.Context, host string, port int, useTLS bool, serverName string, timeout time.Duration) (*HTTPInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	urlStr := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, urlStr, nil)
	if err != nil {
		return nil, nil
	}
	if serverName != "" {
		req.Host = net.JoinHostPort(serverName, strconv.Itoa(port))
	}
	req.Header.Set("User-Agent", "SentinelNet/1.0 (Authorized-Audit)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if serverName != "" {
		if _, parseErr := netip.ParseAddr(serverName); parseErr != nil {
			tlsCfg.ServerName = serverName
		}
	}

	tr := &http.Transport{
		DisableKeepAlives:     true,
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: timeout,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
	}()

	h := resp.Header
	sec := SecurityHeaders{
		StrictTransportSecurity: services.SanitizeText(h.Get("Strict-Transport-Security"), 160),
		ContentSecurityPolicy:   services.SanitizeText(h.Get("Content-Security-Policy"), 160),
		XFrameOptions:           services.SanitizeText(h.Get("X-Frame-Options"), 80),
		XContentTypeOptions:     services.SanitizeText(h.Get("X-Content-Type-Options"), 80),
		ReferrerPolicy:          services.SanitizeText(h.Get("Referrer-Policy"), 80),
		PermissionsPolicy:       services.SanitizeText(h.Get("Permissions-Policy"), 120),
	}

	var missing []string
	if useTLS && sec.StrictTransportSecurity == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if sec.ContentSecurityPolicy == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if sec.XContentTypeOptions == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if sec.XFrameOptions == "" && !strings.Contains(strings.ToLower(sec.ContentSecurityPolicy), "frame-ancestors") {
		missing = append(missing, "X-Frame-Options")
	}

	return &HTTPInfo{
		Scheme:                 scheme,
		StatusCode:             resp.StatusCode,
		StatusMessage:          services.SanitizeText(resp.Status, 64),
		Server:                 services.SanitizeText(h.Get("Server"), 120),
		PoweredBy:              services.SanitizeText(h.Get("X-Powered-By"), 120),
		Location:               services.SanitizeText(h.Get("Location"), 180),
		ContentType:            services.SanitizeText(h.Get("Content-Type"), 100),
		SecurityHeaders:        sec,
		MissingSecurityHeaders: missing,
	}, nil
}

func isCommonTLSPort(port int) bool {
	switch port {
	case 443, 465, 636, 853, 902, 990, 993, 995, 2376, 3269, 3389, 5001, 5986, 6380, 6443, 8006, 8443, 8883, 9443, 10250:
		return true
	default:
		return false
	}
}

// InspectPort runs the requested non-intrusive checks on an open TCP port.
func InspectPort(ctx context.Context, host string, port int, opts Options) (*Result, error) {
	if !opts.Banner && !opts.TLS && !opts.HTTP {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hint, _ := services.LookupPort(port)
	out := &Result{}

	if opts.TLS && (hint.TLSCandidate || hint.Encrypted || isCommonTLSPort(port)) {
		tlsInfo, err := InspectTLS(ctx, host, port, opts.ServerName, opts.Timeout)
		if err != nil {
			return nil, err
		}
		if tlsInfo != nil {
			out.TLS = tlsInfo
		}
	}

	if opts.HTTP && (hint.HTTPCandidate || (out.TLS != nil && out.TLS.Established && hint.Category == "web")) {
		useTLS := (out.TLS != nil && out.TLS.Established) || hint.TLSCandidate
		if useTLS && out.TLS == nil && opts.TLS {
			tlsInfo, err := InspectTLS(ctx, host, port, opts.ServerName, opts.Timeout)
			if err != nil {
				return nil, err
			}
			out.TLS = tlsInfo
		}
		httpInfo, err := InspectHTTP(ctx, host, port, useTLS, opts.ServerName, opts.Timeout)
		if err != nil {
			return nil, err
		}
		if httpInfo != nil {
			out.HTTP = httpInfo
		}
	}

	if opts.Banner && out.TLS == nil && out.HTTP == nil {
		banner, err := GrabBanner(ctx, host, port, opts.Timeout)
		if err != nil {
			return nil, err
		}
		if banner != "" {
			out.Banner = banner
		}
	}

	if out.Banner == "" && out.TLS == nil && out.HTTP == nil {
		return nil, nil
	}
	return out, nil
}
