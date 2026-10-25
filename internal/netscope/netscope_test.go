package netscope

import (
	"context"
	"testing"
)

func TestParseTargetAndScopes(t *testing.T) {
	v4, err := ParseTarget("127.0.0.1")
	if err != nil || v4.String() != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %v, err=%v", v4, err)
	}
	if got := ClassifyScope(v4); got != "loopback" {
		t.Fatalf("expected loopback scope, got %q", got)
	}

	v6, err := ParseTarget("::1")
	if err != nil || v6.String() != "::1" {
		t.Fatalf("expected ::1, got %v, err=%v", v6, err)
	}
	if got := ClassifyScope(v6); got != "loopback" {
		t.Fatalf("expected loopback scope, got %q", got)
	}

	priv, err := ParseTarget("192.168.10.25")
	if err != nil || ClassifyScope(priv) != "private" {
		t.Fatalf("expected private scope, got %v, err=%v", priv, err)
	}

	invalidInputs := []string{
		"localhost",
		"10.0.0.0/24",
		" 127.0.0.1",
		"",
		"224.0.0.1",
		"0.0.0.0",
		"255.255.255.255",
	}
	for _, in := range invalidInputs {
		if _, err := ParseTarget(in); err == nil {
			t.Errorf("expected %q to fail ParseTarget", in)
		}
	}
}

func TestExpandCIDRAndRanges(t *testing.T) {
	s32, err := ExpandCIDR("192.168.1.9/32", 256)
	if err != nil || len(s32) != 1 || s32[0].String() != "192.168.1.9" {
		t.Fatalf("unexpected /32 expansion: %v, err=%v", s32, err)
	}

	s31, err := ExpandCIDR("192.168.1.4/31", 256)
	if err != nil || len(s31) != 2 {
		t.Fatalf("unexpected /31 expansion: %v, err=%v", s31, err)
	}

	s24, err := ExpandCIDR("10.0.8.0/24", 256)
	if err != nil || len(s24) != 254 || s24[0].String() != "10.0.8.1" || s24[253].String() != "10.0.8.254" {
		t.Fatalf("unexpected /24 expansion: len=%d, err=%v", len(s24), err)
	}

	if _, err := ExpandCIDR("10.0.0.0/16", 256); err == nil {
		t.Fatal("expected /16 CIDR to be rejected")
	}
	if _, err := ExpandCIDR("10.0.0.0/24", 32); err == nil {
		t.Fatal("expected /24 CIDR to fail when maxHosts=32")
	}

	rng, err := ExpandRange("10.0.0.10-13", 256)
	if err != nil || len(rng) != 4 || rng[3].String() != "10.0.0.13" {
		t.Fatalf("unexpected shorthand range: %v, err=%v", rng, err)
	}
	if _, err := ExpandRange("10.0.0.20-10.0.0.5", 256); err == nil {
		t.Fatal("expected inverted range to fail")
	}
}

func TestResolveTargetsAndPorts(t *testing.T) {
	ctx := context.Background()
	if _, err := ResolveTargets(ctx, "host.internal", ResolveOptions{ResolveDNS: false}); err == nil {
		t.Fatal("expected hostname without ResolveDNS to fail")
	}

	resolved, err := ResolveTargets(ctx, "host.internal,127.0.0.1", ResolveOptions{
		ResolveDNS: true,
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"10.1.2.3"}, nil
		},
	})
	if err != nil || len(resolved) != 2 || resolved[0].IP != "10.1.2.3" || resolved[0].Hostname != "host.internal" {
		t.Fatalf("unexpected resolved targets: %+v, err=%v", resolved, err)
	}

	ports, err := ParsePorts("22,80,8000-8002", 64, true)
	if err != nil || len(ports) != 5 || ports[4] != 8002 {
		t.Fatalf("unexpected ports: %v, err=%v", ports, err)
	}

	badSpecs := []string{"0", "65536", "80,80", "90-80", "1;id", " 80"}
	for _, spec := range badSpecs {
		if _, err := ParsePorts(spec, 64, true); err == nil {
			t.Errorf("expected invalid port spec %q to fail", spec)
		}
	}

	merged, err := ResolvePortSelection("9999", "iot", 256)
	if err != nil || len(merged) < 10 {
		t.Fatalf("unexpected merged profile ports: %v, err=%v", merged, err)
	}

	ifaces, err := ListLocalInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Fatalf("expected at least one local interface, err=%v", err)
	}
}
