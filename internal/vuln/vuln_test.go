package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/services"
)

func TestCompareVersionAndBannerCVECorrelation(t *testing.T) {
	if CompareVersion("9.2p1", "9.8p1") >= 0 {
		t.Fatalf("expected 9.2p1 < 9.8p1")
	}
	if CompareVersion("9.8p1", "9.8p1") != 0 {
		t.Fatalf("expected 9.8p1 == 9.8p1")
	}
	if CompareVersion("1.0.1f", "1.0.1g") >= 0 {
		t.Fatalf("expected 1.0.1f < 1.0.1g")
	}
	if CompareVersion("2.4.52", "2.4.51") <= 0 {
		t.Fatalf("expected 2.4.52 > 2.4.51")
	}

	// OpenSSH 9.2p1 on Ubuntu triggers CVE-2024-6387 + CVE-2023-48795 + CVE-2023-38408 with distro caveat
	sshMatches := MatchPort(
		"10.0.0.5",
		22,
		services.ServiceInfo{ID: "ssh", Label: "SSH"},
		&inspector.Result{Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
	)
	foundRegreSSHion := false
	for _, m := range sshMatches {
		if m.CVE == "CVE-2024-6387" {
			foundRegreSSHion = true
			if !strings.Contains(m.AffectedScope, "9.8p1") {
				t.Fatalf("expected scope mentioning 9.8p1, got %q", m.AffectedScope)
			}
			if m.NVDURL != "https://nvd.nist.gov/vuln/detail/CVE-2024-6387" {
				t.Fatalf("unexpected NVD URL: %s", m.NVDURL)
			}
			if m.BackportCaveat == "" {
				t.Fatalf("expected Debian backport caveat")
			}
		}
	}
	if !foundRegreSSHion {
		t.Fatalf("expected CVE-2024-6387 on OpenSSH 9.2p1, got %+v", sshMatches)
	}

	// Patched OpenSSH 9.8p1 does NOT trigger CVE-2024-6387
	patchedMatches := MatchPort(
		"10.0.0.6",
		22,
		services.ServiceInfo{ID: "ssh", Label: "SSH"},
		&inspector.Result{Banner: "SSH-2.0-OpenSSH_9.8p1"},
	)
	if len(patchedMatches) != 0 {
		t.Fatalf("expected 0 CVEs on OpenSSH 9.8p1, got %+v", patchedMatches)
	}

	// Apache 2.4.49 + TLSv1.0 triggers CVE-2021-41773 and CVE-2011-3389
	webMatches := MatchPort(
		"10.0.0.8",
		443,
		services.ServiceInfo{ID: "https", Label: "HTTPS"},
		&inspector.Result{
			TLS:  &inspector.TLSInfo{Established: true, Protocol: "TLSv1.0"},
			HTTP: &inspector.HTTPInfo{StatusCode: 200, Server: "Apache/2.4.49 (Unix) OpenSSL/1.0.1f"},
		},
	)
	cves := make(map[string]bool)
	for _, m := range webMatches {
		cves[m.CVE] = true
	}
	for _, expected := range []string{"CVE-2021-41773", "CVE-2014-0160", "CVE-2011-3389"} {
		if !cves[expected] {
			t.Fatalf("expected %s in matches, got %v", expected, cves)
		}
	}
}

func TestLookupOnlineNVDWithMockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2025-99999",
					"descriptions": [{"lang": "en", "value": "Test online NVD advisory entry."}],
					"metrics": {
						"cvssMetricV31": [{
							"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}
						}]
					},
					"weaknesses": [{"description": [{"value": "CWE-79"}]}]
				}
			}]
		}`))
	}))
	defer srv.Close()

	insp := &inspector.Result{HTTP: &inspector.HTTPInfo{StatusCode: 200, Server: "nginx/1.26.0"}}
	svc := services.ServiceInfo{ID: "http", Label: "HTTP"}
	merged := LookupOnlineNVD(context.Background(), "127.0.0.1", 80, svc, insp, nil, OnlineOptions{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if len(merged) != 1 || merged[0].CVE != "CVE-2025-99999" || merged[0].CVSS != 8.8 {
		t.Fatalf("unexpected online NVD result: %+v", merged)
	}
}
