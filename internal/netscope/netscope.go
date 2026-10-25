package netscope

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/abiyeenzo/sentinel-net/internal/profiles"
)

const (
	HardMaxHosts    = 1024
	DefaultMaxHosts = 256
	HardMaxPorts    = 4096
	DefaultMaxPorts = 1024
)

// TargetHost represents a validated unicast scan target.
type TargetHost struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Scope    string `json:"scope"`
}

// InterfaceInfo describes a local network interface address.
type InterfaceInfo struct {
	Interface           string `json:"interface"`
	Family              string `json:"family"`
	Address             string `json:"address"`
	CIDR                string `json:"cidr,omitempty"`
	SuggestedScanTarget string `json:"suggestedScanTarget"`
	MAC                 string `json:"mac,omitempty"`
	Internal            bool   `json:"internal"`
	Scope               string `json:"scope"`
}

// ResolveOptions configures target resolution and safety bounds.
type ResolveOptions struct {
	ResolveDNS bool
	MaxHosts   int
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

var (
	cgnatPrefix  = netip.MustParsePrefix("100.64.0.0/10")
	docV4a       = netip.MustParsePrefix("192.0.2.0/24")
	docV4b       = netip.MustParsePrefix("198.51.100.0/24")
	docV4c       = netip.MustParsePrefix("203.0.113.0/24")
	docV6        = netip.MustParsePrefix("2001:db8::/32")
	hostnameRE   = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	shortRangeRE = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$`)
)

// ClassifyScope returns the address scope of a parsed IP.
func ClassifyScope(addr netip.Addr) string {
	if !addr.IsValid() {
		return "invalid"
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return "loopback"
	}
	if addr.IsMulticast() {
		return "multicast"
	}
	if addr.IsUnspecified() {
		return "reserved"
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 || b[0] >= 240 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) {
			return "reserved"
		}
		if cgnatPrefix.Contains(addr) {
			return "carrier-nat"
		}
		if docV4a.Contains(addr) || docV4b.Contains(addr) || docV4c.Contains(addr) {
			return "documentation"
		}
	} else if docV6.Contains(addr) {
		return "documentation"
	}
	if addr.IsLinkLocalUnicast() {
		return "link-local"
	}
	if addr.IsPrivate() {
		return "private"
	}
	return "public"
}

// ParseTarget validates a single literal IPv4 or IPv6 unicast address.
func ParseTarget(value string) (netip.Addr, error) {
	if value == "" || len(value) > 45 || strings.TrimSpace(value) != value {
		return netip.Addr{}, errors.New("target must be one literal IPv4 or IPv6 address")
	}
	if strings.Contains(value, "%") {
		return netip.Addr{}, errors.New("zone identifiers are not supported in literal targets")
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, errors.New("target must be a literal IPv4 or IPv6 address; hostnames and ranges require --resolve or CIDR/range syntax")
	}
	addr = addr.Unmap()
	scope := ClassifyScope(addr)
	if scope == "multicast" || scope == "reserved" {
		return netip.Addr{}, fmt.Errorf("target IP %q is %s and cannot be scanned over unicast TCP", value, scope)
	}
	return addr, nil
}

func ipv4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// ExpandCIDR expands a bounded IPv4 CIDR block (/22 to /32) into unicast addresses.
func ExpandCIDR(cidr string, maxHosts int) ([]netip.Addr, error) {
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 CIDR notation %q", cidr)
	}
	bits := prefix.Bits()
	if bits < 22 || bits > 32 {
		return nil, errors.New("IPv4 CIDR prefix must be between /22 and /32 to enforce bounded scanning")
	}

	masked := prefix.Masked()
	base := ipv4ToUint32(masked.Addr())

	if bits == 32 {
		addr, err := ParseTarget(prefix.Addr().String())
		if err != nil {
			return nil, err
		}
		return []netip.Addr{addr}, nil
	}
	// RFC 3021 point-to-point /31 links have two usable host addresses.
	if bits == 31 {
		a0, err := ParseTarget(uint32ToIPv4(base).String())
		if err != nil {
			return nil, err
		}
		a1, err := ParseTarget(uint32ToIPv4(base + 1).String())
		if err != nil {
			return nil, err
		}
		return []netip.Addr{a0, a1}, nil
	}

	total := 1 << (32 - bits)
	usable := total - 2
	if usable > maxHosts {
		return nil, fmt.Errorf("CIDR %q expands to %d hosts, exceeding max-hosts (%d)", cidr, usable, maxHosts)
	}

	out := make([]netip.Addr, 0, usable)
	for i := 1; i <= usable; i++ {
		ip := uint32ToIPv4(base + uint32(i))
		valid, err := ParseTarget(ip.String())
		if err != nil {
			return nil, err
		}
		out = append(out, valid)
	}
	return out, nil
}

// ExpandRange expands bounded IPv4 ranges like "10.0.0.1-10.0.0.20" or "10.0.0.1-20".
func ExpandRange(expr string, maxHosts int) ([]netip.Addr, error) {
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}
	var startStr, endStr string
	if m := shortRangeRE.FindStringSubmatch(expr); m != nil {
		startStr = m[1] + m[2]
		endStr = m[1] + m[3]
	} else if parts := strings.Split(expr, "-"); len(parts) == 2 {
		startStr = parts[0]
		endStr = parts[1]
	} else {
		return nil, fmt.Errorf("invalid IPv4 range %q", expr)
	}

	startAddr, err := netip.ParseAddr(startStr)
	if err != nil || !startAddr.Is4() {
		return nil, fmt.Errorf("invalid range start IPv4 %q", startStr)
	}
	endAddr, err := netip.ParseAddr(endStr)
	if err != nil || !endAddr.Is4() {
		return nil, fmt.Errorf("invalid range end IPv4 %q", endStr)
	}

	startInt := ipv4ToUint32(startAddr)
	endInt := ipv4ToUint32(endAddr)
	if endInt < startInt {
		return nil, fmt.Errorf("inverted IPv4 range %q: end precedes start", expr)
	}
	count := int(endInt - startInt + 1)
	if count > maxHosts {
		return nil, fmt.Errorf("IPv4 range %q contains %d hosts, exceeding max-hosts (%d)", expr, count, maxHosts)
	}

	out := make([]netip.Addr, 0, count)
	for cur := startInt; cur <= endInt; cur++ {
		valid, err := ParseTarget(uint32ToIPv4(cur).String())
		if err != nil {
			return nil, err
		}
		out = append(out, valid)
	}
	return out, nil
}

func isNumericRangeToken(s string) bool {
	if !strings.Contains(s, "-") {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// ResolveTargets parses and expands a comma/whitespace-separated target list.
func ResolveTargets(ctx context.Context, input string, opts ResolveOptions) ([]TargetHost, error) {
	maxHosts := opts.MaxHosts
	if maxHosts == 0 {
		maxHosts = DefaultMaxHosts
	}
	if maxHosts < 1 || maxHosts > HardMaxHosts {
		return nil, fmt.Errorf("max-hosts must be between 1 and %d", HardMaxHosts)
	}

	tokens := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(tokens) == 0 {
		return nil, errors.New("at least one target IP, CIDR or range is required")
	}

	lookup := opts.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}

	seen := make(map[string]struct{})
	var targets []TargetHost

	appendAddr := func(addr netip.Addr, hostname string) error {
		key := addr.String()
		if _, exists := seen[key]; exists {
			return nil
		}
		seen[key] = struct{}{}
		targets = append(targets, TargetHost{
			IP:       key,
			Hostname: hostname,
			Scope:    ClassifyScope(addr),
		})
		if len(targets) > maxHosts {
			return fmt.Errorf("target count exceeds max-hosts limit (%d)", maxHosts)
		}
		return nil
	}

	for _, tok := range tokens {
		if len(tok) > 253 {
			return nil, fmt.Errorf("target token too long: %q", tok[:32])
		}
		if addr, err := netip.ParseAddr(tok); err == nil {
			valid, err := ParseTarget(addr.Unmap().String())
			if err != nil {
				return nil, err
			}
			if err := appendAddr(valid, ""); err != nil {
				return nil, err
			}
			continue
		}
		if strings.Contains(tok, "/") {
			addrs, err := ExpandCIDR(tok, maxHosts)
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if err := appendAddr(a, ""); err != nil {
					return nil, err
				}
			}
			continue
		}
		if isNumericRangeToken(tok) {
			addrs, err := ExpandRange(tok, maxHosts)
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if err := appendAddr(a, ""); err != nil {
					return nil, err
				}
			}
			continue
		}

		if !opts.ResolveDNS {
			return nil, fmt.Errorf("target %q is not a literal IP, IPv4 CIDR (/22-/32), or IPv4 range (pass --resolve for DNS)", tok)
		}
		if !hostnameRE.MatchString(tok) {
			return nil, fmt.Errorf("invalid hostname %q", tok)
		}
		resolvedAddrs, err := lookup(ctx, tok)
		if err != nil || len(resolvedAddrs) == 0 {
			return nil, fmt.Errorf("failed to resolve hostname %q: %v", tok, err)
		}
		valid, err := ParseTarget(resolvedAddrs[0])
		if err != nil {
			return nil, err
		}
		if err := appendAddr(valid, tok); err != nil {
			return nil, err
		}
	}

	return targets, nil
}

// ParsePorts parses a comma-separated port list supporting ranges (e.g. "22,80,443,8000-8010").
func ParsePorts(spec string, maxPorts int, rejectDuplicates bool) ([]int, error) {
	if maxPorts == 0 {
		maxPorts = DefaultMaxPorts
	}
	if maxPorts < 1 || maxPorts > HardMaxPorts {
		return nil, fmt.Errorf("max-ports must be between 1 and %d", HardMaxPorts)
	}
	if spec == "" || len(spec) > 4096 || strings.TrimSpace(spec) != spec {
		return nil, fmt.Errorf("provide 1 to %d TCP ports or ranges (e.g. 22,80,443,8000-8010)", maxPorts)
	}

	segments := strings.Split(spec, ",")
	seen := make(map[int]struct{})
	var ports []int

	for _, seg := range segments {
		if seg == "" {
			return nil, errors.New("empty port segment in port specification")
		}
		if strings.Contains(seg, "-") {
			bounds := strings.Split(seg, "-")
			if len(bounds) != 2 || bounds[0] == "" || bounds[1] == "" {
				return nil, fmt.Errorf("invalid port range %q", seg)
			}
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || end < start {
				return nil, fmt.Errorf("invalid TCP port range %q (expected 1-65535 with start <= end)", seg)
			}
			for p := start; p <= end; p++ {
				if _, dup := seen[p]; dup {
					if rejectDuplicates {
						return nil, fmt.Errorf("overlapping TCP port %d in range %q", p, seg)
					}
					continue
				}
				seen[p] = struct{}{}
				ports = append(ports, p)
				if len(ports) > maxPorts {
					return nil, fmt.Errorf("port count exceeds max-ports limit (%d)", maxPorts)
				}
			}
		} else {
			for _, r := range seg {
				if r < '0' || r > '9' {
					return nil, fmt.Errorf("invalid port %q", seg)
				}
			}
			p, err := strconv.Atoi(seg)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %q out of valid TCP range (1-65535)", seg)
			}
			if _, dup := seen[p]; dup {
				if rejectDuplicates {
					return nil, fmt.Errorf("duplicate TCP port %d", p)
				}
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
			if len(ports) > maxPorts {
				return nil, fmt.Errorf("port count exceeds max-ports limit (%d)", maxPorts)
			}
		}
	}

	if len(ports) == 0 {
		return nil, errors.New("at least one valid TCP port is required")
	}
	return ports, nil
}

// ResolvePortSelection merges a named profile and/or custom port expression into a sorted, unique port slice.
func ResolvePortSelection(portsSpec, profileName string, maxPorts int) ([]int, error) {
	if maxPorts == 0 {
		maxPorts = DefaultMaxPorts
	}
	if maxPorts < 1 || maxPorts > HardMaxPorts {
		return nil, fmt.Errorf("max-ports must be between 1 and %d", HardMaxPorts)
	}

	combined := make(map[int]struct{})
	if strings.TrimSpace(profileName) != "" {
		prof, err := profiles.Get(profileName)
		if err != nil {
			return nil, err
		}
		for _, p := range prof.Ports {
			combined[p] = struct{}{}
		}
	}

	if strings.TrimSpace(portsSpec) != "" {
		rejectDups := strings.TrimSpace(profileName) == ""
		parsed, err := ParsePorts(strings.TrimSpace(portsSpec), maxPorts, rejectDups)
		if err != nil {
			return nil, err
		}
		for _, p := range parsed {
			combined[p] = struct{}{}
		}
	}

	if len(combined) == 0 {
		return nil, errors.New("specify --ports (e.g. 22,80,443) or --profile (quick, web, infra, database, containers, iot, top100)")
	}
	if len(combined) > maxPorts {
		return nil, fmt.Errorf("resolved port count (%d) exceeds max-ports limit (%d)", len(combined), maxPorts)
	}

	sorted := make([]int, 0, len(combined))
	for p := range combined {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)
	return sorted, nil
}

// ListLocalInterfaces enumerates active host network interfaces and unicast addresses.
func ListLocalInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []InterfaceInfo
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		mac := ""
		if len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
		}
		for _, rawAddr := range addrs {
			var ip net.IP
			var maskBits int
			switch v := rawAddr.(type) {
			case *net.IPNet:
				ip = v.IP
				ones, _ := v.Mask.Size()
				maskBits = ones
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			parsed = parsed.Unmap()
			family := "IPv6"
			if parsed.Is4() {
				family = "IPv4"
			}
			cidrStr := ""
			if maskBits > 0 {
				cidrStr = fmt.Sprintf("%s/%d", parsed.String(), maskBits)
			}
			suggested := parsed.String()
			if parsed.Is4() && !isLoopback && !parsed.IsLinkLocalUnicast() && maskBits > 0 {
				b := parsed.As4()
				if maskBits >= 24 {
					suggested = cidrStr
				} else {
					suggested = fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
				}
			}
			out = append(out, InterfaceInfo{
				Interface:           iface.Name,
				Family:              family,
				Address:             parsed.String(),
				CIDR:                cidrStr,
				SuggestedScanTarget: suggested,
				MAC:                 mac,
				Internal:            isLoopback || parsed.IsLoopback(),
				Scope:               ClassifyScope(parsed),
			})
		}
	}
	return out, nil
}
