package baseline

import (
	"testing"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/risk"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
	"github.com/abiyeenzo/sentinel-net/internal/services"
)

func TestRiskRulesAndBaselineDrift(t *testing.T) {
	obs := []risk.PortInput{
		{
			Port:      23,
			State:     "open",
			LatencyMs: 1.2,
			Service:   services.ServiceInfo{ID: "telnet", Label: "Telnet", Category: "remote-access"},
		},
		{
			Port:      2375,
			State:     "open",
			LatencyMs: 0.8,
			Service:   services.ServiceInfo{ID: "docker", Label: "Docker API", Category: "containers"},
		},
		{
			Port:      6379,
			State:     "open",
			LatencyMs: 0.9,
			Service:   services.ServiceInfo{ID: "redis", Label: "Redis", Category: "database"},
		},
		{
			Port:      443,
			State:     "open",
			LatencyMs: 2.1,
			Service:   services.ServiceInfo{ID: "https", Label: "HTTPS", Category: "web", Encrypted: true},
			Inspection: &inspector.Result{
				TLS: &inspector.TLSInfo{
					Established: true,
					Protocol:    "TLSv1.0",
					Authorized:  false,
					Certificate: &inspector.CertificateInfo{
						SubjectCN:     "expired.local",
						ValidTo:       "2024-01-01T00:00:00Z",
						DaysRemaining: -200,
						Expired:       true,
						SelfSigned:    true,
					},
				},
			},
		},
	}

	eval := risk.EvaluateHost("10.0.0.15", obs)
	if eval.Grade != "F" || eval.Level != "critical" {
		t.Fatalf("expected critical F posture, got grade=%s level=%s score=%d", eval.Grade, eval.Level, eval.Score)
	}

	repA := &scanner.Report{
		StartedAt: "2026-10-25T10:00:00Z",
		Risk:      risk.ScanSummary{Score: 95, Grade: "A+"},
		Hosts: []scanner.HostReport{
			{
				Target: "192.168.1.10",
				Observations: []scanner.Observation{
					{
						Port:    22,
						State:   "open",
						Service: services.ServiceInfo{ID: "ssh", Label: "SSH"},
						Inspection: &inspector.Result{
							TLS: &inspector.TLSInfo{Certificate: &inspector.CertificateInfo{FingerprintSHA256: "AA:11"}},
						},
					},
					{Port: 80, State: "open", Service: services.ServiceInfo{ID: "http", Label: "HTTP"}},
					{Port: 6379, State: "closed", Service: services.ServiceInfo{ID: "redis", Label: "Redis"}},
				},
			},
		},
	}

	snap, err := CreateSnapshot(repA)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	ok, err := Verify(snap)
	if err != nil || !ok {
		t.Fatalf("expected snapshot integrity verification to succeed, ok=%v err=%v", ok, err)
	}

	// Tamper check
	snap.Hosts[0].Observations[2].State = "open"
	ok, _ = Verify(snap)
	if ok {
		t.Fatal("expected tampered snapshot verification to fail")
	}
	snap.Hosts[0].Observations[2].State = "closed"

	repB := &scanner.Report{
		StartedAt: "2026-10-25T11:00:00Z",
		Risk:      risk.ScanSummary{Score: 72, Grade: "C"},
		Hosts: []scanner.HostReport{
			{
				Target: "192.168.1.10",
				Observations: []scanner.Observation{
					{
						Port:    22,
						State:   "open",
						Service: services.ServiceInfo{ID: "ssh", Label: "SSH"},
						Inspection: &inspector.Result{
							TLS: &inspector.TLSInfo{Certificate: &inspector.CertificateInfo{FingerprintSHA256: "BB:22"}},
						},
					},
					{Port: 80, State: "closed", Service: services.ServiceInfo{ID: "http", Label: "HTTP"}},
					{Port: 6379, State: "open", Service: services.ServiceInfo{ID: "redis", Label: "Redis"}},
				},
			},
		},
	}

	drift := Compare(&snap.Report, repB)
	if !drift.HasDrift || !drift.HasCriticalDrift {
		t.Fatalf("expected critical drift, got %+v", drift)
	}
	if len(drift.NewlyOpened) != 1 || drift.NewlyOpened[0].Port != 6379 {
		t.Fatalf("unexpected newlyOpened: %+v", drift.NewlyOpened)
	}
	if len(drift.NewlyClosed) != 1 || drift.NewlyClosed[0].Port != 80 {
		t.Fatalf("unexpected newlyClosed: %+v", drift.NewlyClosed)
	}
	if len(drift.ServiceChanges) != 1 || drift.ServiceChanges[0].Kind != "tls-certificate" {
		t.Fatalf("unexpected serviceChanges: %+v", drift.ServiceChanges)
	}
}
