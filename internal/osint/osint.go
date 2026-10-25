package osint

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/netscope"
	"github.com/abiyeenzo/sentinel-net/internal/services"
)

// DNSResolver abstracts DNS queries so unit tests can run offline deterministically.
type DNSResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Options configures an OSINT reconnaissance run.
type Options struct {
	Timeout      time.Duration
	ActiveWeb    bool   // Opt-in direct HTTP/TLS fetch of target title, security.txt, robots.txt
	WebTargetURL string // Optional override URL for testing active web surface
	CRTShBaseURL string // Defaults to https://crt.sh
	RDAPBaseURL  string // Defaults to https://rdap.org
	GeoIPBaseURL string // Defaults to https://ipwho.is
	HTTPClient   *http.Client
	Resolver     DNSResolver
	SkipCTLogs   bool
	SkipRDAP     bool
	SkipGeoIP    bool
}

// MXEntry represents one DNS mail exchange record.
type MXEntry struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// EmailPosture summarizes SPF and DMARC anti-spoofing posture on a domain.
type EmailPosture struct {
	SPFRecord     string `json:"spfRecord,omitempty"`
	SPFPolicy     string `json:"spfPolicy,omitempty"`
	DMARCRecord   string `json:"dmarcRecord,omitempty"`
	DMARCPolicy   string `json:"dmarcPolicy,omitempty"`
	MissingSPF    bool   `json:"missingSpf"`
	MissingDMARC  bool   `json:"missingDmarc"`
	PermissiveSPF bool   `json:"permissiveSpf"`
}

// DNSIntel holds passive DNS records, reverse PTR mappings, and SaaS provider clues.
type DNSIntel struct {
	A                 []string            `json:"a,omitempty"`
	AAAA              []string            `json:"aaaa,omitempty"`
	CNAME             string              `json:"cname,omitempty"`
	MX                []MXEntry           `json:"mx,omitempty"`
	NS                []string            `json:"ns,omitempty"`
	TXT               []string            `json:"txt,omitempty"`
	PTR               map[string][]string `json:"ptr,omitempty"`
	EmailSecurity     *EmailPosture       `json:"emailSecurity,omitempty"`
	DetectedProviders []string            `json:"detectedProviders,omitempty"`
}

// RDAPIntel holds WHOIS/RDAP ownership metadata for domains and IP blocks.
type RDAPIntel struct {
	DomainName    string            `json:"domainName,omitempty"`
	Registrar     string            `json:"registrar,omitempty"`
	Status        []string          `json:"status,omitempty"`
	DNSSECSigned  bool              `json:"dnssecSigned"`
	Events        map[string]string `json:"events,omitempty"`
	NetworkHandle string            `json:"networkHandle,omitempty"`
	NetworkName   string            `json:"networkName,omitempty"`
	IPRange       string            `json:"ipRange,omitempty"`
	Country       string            `json:"country,omitempty"`
	Organization  string            `json:"organization,omitempty"`
	AbuseContact  string            `json:"abuseContact,omitempty"`
}

// GeoASNIntel holds BGP ASN and geographic attribution for a public IP.
type GeoASNIntel struct {
	IP          string `json:"ip"`
	ASN         string `json:"asn,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Org         string `json:"org,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
}

// CTIntel summarizes Certificate Transparency subdomain and issuer intelligence.
type CTIntel struct {
	Source            string   `json:"source"`
	CertificatesCount int      `json:"certificatesCount"`
	Subdomains        []string `json:"subdomains,omitempty"`
	Issuers           []string `json:"issuers,omitempty"`
}

// SecurityTxtInfo holds parsed RFC 9116 /.well-known/security.txt fields.
type SecurityTxtInfo struct {
	Found      bool     `json:"found"`
	URL        string   `json:"url,omitempty"`
	Contacts   []string `json:"contacts,omitempty"`
	Expires    string   `json:"expires,omitempty"`
	Encryption []string `json:"encryption,omitempty"`
	Policy     string   `json:"policy,omitempty"`
}

// RobotsInfo summarizes /robots.txt directives.
type RobotsInfo struct {
	Found          bool     `json:"found"`
	Sitemaps       []string `json:"sitemaps,omitempty"`
	DisallowSample []string `json:"disallowSample,omitempty"`
}

// WebIntel holds passive/lightweight web surface metadata.
type WebIntel struct {
	URL                    string                     `json:"url"`
	FinalURL               string                     `json:"finalUrl,omitempty"`
	StatusCode             int                        `json:"statusCode"`
	Title                  string                     `json:"title,omitempty"`
	Server                 string                     `json:"server,omitempty"`
	PoweredBy              string                     `json:"poweredBy,omitempty"`
	Technologies           []string                   `json:"technologies,omitempty"`
	MissingSecurityHeaders []string                   `json:"missingSecurityHeaders,omitempty"`
	SecurityTxt            *SecurityTxtInfo           `json:"securityTxt,omitempty"`
	RobotsTxt              *RobotsInfo                `json:"robotsTxt,omitempty"`
	TLSCertificate         *inspector.CertificateInfo `json:"tlsCertificate,omitempty"`
}

// FindingNote highlights a defensive OSINT hygiene or surface exposure observation.
type FindingNote struct {
	Severity       string `json:"severity"` // "high" | "medium" | "low" | "info"
	Category       string `json:"category"`
	Title          string `json:"title"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

// Report aggregates all OSINT reconnaissance results for a target domain or IP.
type Report struct {
	Query        string        `json:"query"`
	TargetType   string        `json:"targetType"` // "domain" | "ip"
	Domain       string        `json:"domain,omitempty"`
	ApexDomain   string        `json:"apexDomain,omitempty"`
	IPs          []string      `json:"ips,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	StartedAt    string        `json:"startedAt"`
	FinishedAt   string        `json:"finishedAt"`
	DurationMs   float64       `json:"durationMs"`
	DNS          *DNSIntel     `json:"dns,omitempty"`
	RDAP         *RDAPIntel    `json:"rdap,omitempty"`
	GeoASN       *GeoASNIntel  `json:"geoAsn,omitempty"`
	CTLogs       *CTIntel      `json:"ctLogs,omitempty"`
	Web          *WebIntel     `json:"web,omitempty"`
	Observations []FindingNote `json:"observations,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

var (
	domainSyntaxRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	htmlTitleRE    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaGenRE      = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	sensitiveSubRE = regexp.MustCompile(`(?i)\b(dev|staging|stage|test|uat|preprod|admin|internal|vpn|git|gitlab|jenkins|grafana|kibana|backup|old|beta)\b`)
)

func normalizeQuery(raw string) (targetType, host, apex string, addr netip.Addr, err error) {
	q := strings.TrimSpace(raw)
	if q == "" {
		return "", "", "", netip.Addr{}, errors.New("empty OSINT target")
	}
	if strings.Contains(q, "://") {
		u, uErr := url.Parse(q)
		if uErr != nil || u.Hostname() == "" {
			return "", "", "", netip.Addr{}, fmt.Errorf("invalid URL target %q", raw)
		}
		q = u.Hostname()
	} else if h, _, splitErr := net.SplitHostPort(q); splitErr == nil && h != "" {
		q = h
	}
	q = strings.TrimSuffix(strings.ToLower(strings.Trim(q, "[]")), ".")

	if ip, ipErr := netip.ParseAddr(q); ipErr == nil {
		return "ip", ip.String(), "", ip, nil
	}
	if q == "localhost" {
		ip, _ := netip.ParseAddr("127.0.0.1")
		return "ip", "127.0.0.1", "", ip, nil
	}
	if !domainSyntaxRE.MatchString(q) {
		return "", "", "", netip.Addr{}, fmt.Errorf("invalid domain or IP address %q", raw)
	}
	return "domain", q, guessApexDomain(q), netip.Addr{}, nil
}

var twoLevelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "com.br": true, "com.cm": true, "co.za": true, "asso.fr": true, "gouv.fr": true,
}

func guessApexDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if twoLevelSuffixes[lastTwo] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return lastTwo
}

// Run executes passive OSINT collection (and optional lightweight web surface checks) for rawQuery.
func Run(ctx context.Context, rawQuery string, opts Options) (*Report, error) {
	tType, host, apex, parsedIP, err := normalizeQuery(rawQuery)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	crtBase := strings.TrimRight(opts.CRTShBaseURL, "/")
	if crtBase == "" {
		crtBase = "https://crt.sh"
	}
	rdapBase := strings.TrimRight(opts.RDAPBaseURL, "/")
	if rdapBase == "" {
		rdapBase = "https://rdap.org"
	}
	geoBase := strings.TrimRight(opts.GeoIPBaseURL, "/")
	if geoBase == "" {
		geoBase = "https://ipwho.is"
	}

	started := time.Now()
	rep := &Report{
		Query:      strings.TrimSpace(rawQuery),
		TargetType: tType,
		StartedAt:  started.UTC().Format(time.RFC3339),
		DNS:        &DNSIntel{PTR: make(map[string][]string)},
	}

	var warnMu sync.Mutex
	addWarn := func(msg string) {
		warnMu.Lock()
		rep.Warnings = append(rep.Warnings, msg)
		warnMu.Unlock()
	}

	// Step 1: DNS & IP resolution
	dnsCtx, cancelDNS := context.WithTimeout(ctx, timeout)
	if tType == "ip" {
		rep.IPs = []string{parsedIP.String()}
		rep.Scope = netscope.ClassifyScope(parsedIP)
		if names, pErr := resolver.LookupAddr(dnsCtx, parsedIP.String()); pErr == nil && len(names) > 0 {
			cleaned := cleanDomainList(names)
			rep.DNS.PTR[parsedIP.String()] = cleaned
			if len(cleaned) > 0 && domainSyntaxRE.MatchString(cleaned[0]) {
				rep.Domain = cleaned[0]
				rep.ApexDomain = guessApexDomain(cleaned[0])
			}
		}
	} else {
		rep.Domain = host
		rep.ApexDomain = apex
		collectDomainDNS(dnsCtx, resolver, host, apex, rep.DNS)
		for _, a := range rep.DNS.A {
			rep.IPs = append(rep.IPs, a)
		}
		for _, a6 := range rep.DNS.AAAA {
			rep.IPs = append(rep.IPs, a6)
		}
		if len(rep.IPs) > 0 {
			if firstIP, pErr := netip.ParseAddr(rep.IPs[0]); pErr == nil {
				rep.Scope = netscope.ClassifyScope(firstIP)
			}
			for _, ipStr := range rep.IPs {
				if names, pErr := resolver.LookupAddr(dnsCtx, ipStr); pErr == nil && len(names) > 0 {
					rep.DNS.PTR[ipStr] = cleanDomainList(names)
				}
			}
		}
	}
	cancelDNS()

	// Step 2: Parallel passive enrichments (CT Logs, RDAP, GeoASN, optional Web)
	var wg sync.WaitGroup

	if !opts.SkipCTLogs && rep.ApexDomain != "" {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ct, cErr := queryCRTSh(subCtx, httpClient, crtBase, dom)
			if cErr != nil {
				addWarn("CT logs (crt.sh): " + cErr.Error())
				return
			}
			rep.CTLogs = ct
		}(rep.ApexDomain)
	}

	if !opts.SkipRDAP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			rdap := &RDAPIntel{Events: make(map[string]string)}
			hasData := false

			if rep.ApexDomain != "" {
				if err := queryRDAPDomain(subCtx, httpClient, rdapBase, rep.ApexDomain, rdap); err != nil {
					addWarn("RDAP domain: " + err.Error())
				} else {
					hasData = true
				}
			}
			if len(rep.IPs) > 0 {
				if ipAddr, pErr := netip.ParseAddr(rep.IPs[0]); pErr == nil && netscope.ClassifyScope(ipAddr) == "public" || opts.RDAPBaseURL != "" {
					if err := queryRDAPIP(subCtx, httpClient, rdapBase, rep.IPs[0], rdap); err != nil {
						addWarn("RDAP IP: " + err.Error())
					} else {
						hasData = true
					}
				}
			}
			if hasData {
				rep.RDAP = rdap
			}
		}()
	}

	if !opts.SkipGeoIP && len(rep.IPs) > 0 {
		if ipAddr, pErr := netip.ParseAddr(rep.IPs[0]); pErr == nil && (netscope.ClassifyScope(ipAddr) == "public" || opts.GeoIPBaseURL != "") {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				subCtx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				geo, gErr := queryGeoASN(subCtx, httpClient, geoBase, ip)
				if gErr != nil {
					addWarn("Geo/ASN: " + gErr.Error())
					return
				}
				rep.GeoASN = geo
			}(rep.IPs[0])
		}
	}

	if opts.ActiveWeb {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			targetHost := rep.Domain
			if targetHost == "" && len(rep.IPs) > 0 {
				targetHost = rep.IPs[0]
			}
			webRes, wErr := inspectWebSurface(subCtx, targetHost, opts.WebTargetURL, timeout)
			if wErr != nil {
				addWarn("Web surface: " + wErr.Error())
				return
			}
			rep.Web = webRes
		}()
	}

	wg.Wait()

	rep.Observations = evaluateOSINTFindings(rep)
	finished := time.Now()
	rep.FinishedAt = finished.UTC().Format(time.RFC3339)
	rep.DurationMs = float64(finished.Sub(started).Microseconds()) / 1000.0
	return rep, nil
}

func cleanDomainList(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		if c == "" {
			continue
		}
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func collectDomainDNS(ctx context.Context, r DNSResolver, host, apex string, dst *DNSIntel) {
	if ips, err := r.LookupIPAddr(ctx, host); err == nil {
		seen4 := make(map[string]struct{})
		seen6 := make(map[string]struct{})
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip.IP); ok {
				au := a.Unmap()
				if au.Is4() {
					s := au.String()
					if _, dup := seen4[s]; !dup {
						seen4[s] = struct{}{}
						dst.A = append(dst.A, s)
					}
				} else {
					s := au.String()
					if _, dup := seen6[s]; !dup {
						seen6[s] = struct{}{}
						dst.AAAA = append(dst.AAAA, s)
					}
				}
			}
		}
		sort.Strings(dst.A)
		sort.Strings(dst.AAAA)
	}

	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
		if c != "" && c != host {
			dst.CNAME = c
		}
	}

	mailDomain := apex
	if mailDomain == "" {
		mailDomain = host
	}
	if mxs, err := r.LookupMX(ctx, mailDomain); err == nil {
		for _, m := range mxs {
			h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.Host)), ".")
			if h != "" {
				dst.MX = append(dst.MX, MXEntry{Host: h, Pref: m.Pref})
			}
		}
		sort.Slice(dst.MX, func(i, j int) bool {
			if dst.MX[i].Pref != dst.MX[j].Pref {
				return dst.MX[i].Pref < dst.MX[j].Pref
			}
			return dst.MX[i].Host < dst.MX[j].Host
		})
	}

	if nss, err := r.LookupNS(ctx, mailDomain); err == nil {
		var raw []string
		for _, n := range nss {
			raw = append(raw, n.Host)
		}
		dst.NS = cleanDomainList(raw)
	}

	if txts, err := r.LookupTXT(ctx, mailDomain); err == nil {
		for _, t := range txts {
			s := services.SanitizeText(t, 512)
			if s != "" {
				dst.TXT = append(dst.TXT, s)
			}
		}
		sort.Strings(dst.TXT)
	}

	// SPF & DMARC evaluation
	posture := &EmailPosture{MissingSPF: true, MissingDMARC: true}
	for _, txt := range dst.TXT {
		low := strings.ToLower(txt)
		if strings.HasPrefix(low, "v=spf1") {
			posture.MissingSPF = false
			posture.SPFRecord = txt
			switch {
			case strings.Contains(low, "+all"):
				posture.SPFPolicy = "+all (dangereux : tout serveur autorise)"
				posture.PermissiveSPF = true
			case strings.Contains(low, "?all"):
				posture.SPFPolicy = "?all (neutre)"
				posture.PermissiveSPF = true
			case strings.Contains(low, "~all"):
				posture.SPFPolicy = "~all (softfail)"
			case strings.Contains(low, "-all"):
				posture.SPFPolicy = "-all (strict reject)"
			default:
				posture.SPFPolicy = "personnalise"
			}
		}
	}

	if dmarcTxts, err := r.LookupTXT(ctx, "_dmarc."+mailDomain); err == nil {
		reDmarcP := regexp.MustCompile(`(?:^|[;\s])p\s*=\s*([a-z]+)`)
		reDmarcSP := regexp.MustCompile(`(?:^|[;\s])sp\s*=\s*([a-z]+)`)
		for _, dt := range dmarcTxts {
			clean := services.SanitizeText(dt, 512)
			low := strings.ToLower(clean)
			if strings.HasPrefix(low, "v=dmarc1") {
				posture.MissingDMARC = false
				posture.DMARCRecord = clean
				pVal := ""
				if m := reDmarcP.FindStringSubmatch(low); len(m) >= 2 {
					pVal = m[1]
				}
				spNote := ""
				if m := reDmarcSP.FindStringSubmatch(low); len(m) >= 2 && m[1] != pVal {
					spNote = fmt.Sprintf(", sp=%s", m[1])
				}
				switch pVal {
				case "reject":
					posture.DMARCPolicy = "reject (strict" + spNote + ")"
				case "quarantine":
					posture.DMARCPolicy = "quarantine" + spNote
				case "none":
					posture.DMARCPolicy = "none (surveillance seule" + spNote + ")"
				default:
					posture.DMARCPolicy = "present"
				}
				break
			}
		}
	}
	dst.EmailSecurity = posture
	dst.DetectedProviders = fingerprintDNSProviders(dst)
}

func fingerprintDNSProviders(d *DNSIntel) []string {
	var corpus strings.Builder
	corpus.WriteString(strings.ToLower(d.CNAME) + " ")
	for _, m := range d.MX {
		corpus.WriteString(m.Host + " ")
	}
	for _, n := range d.NS {
		corpus.WriteString(n + " ")
	}
	for _, t := range d.TXT {
		corpus.WriteString(strings.ToLower(t) + " ")
	}
	all := corpus.String()

	rules := []struct {
		needle string
		label  string
	}{
		{"google-site-verification", "Google Workspace / Cloud"},
		{"aspmx.l.google.com", "Google Workspace Mail"},
		{"google.com", "Google Infrastructure"},
		{"ms=", "Microsoft 365 / Entra"},
		{"protection.outlook.com", "Microsoft 365 Exchange Online"},
		{"cloudflare", "Cloudflare DNS / Edge"},
		{"amazonses", "AWS SES"},
		{"awsdns", "AWS Route 53"},
		{"cloudfront.net", "AWS CloudFront"},
		{"protonmail", "Proton Mail"},
		{"sendgrid", "Twilio SendGrid"},
		{"mailgun", "Mailgun"},
		{"spf.mandrillapp.com", "Mailchimp Mandrill"},
		{"atlassian-domain-verification", "Atlassian Cloud"},
		{"stripe-verification", "Stripe"},
		{"github-verification", "GitHub"},
		{"vercel", "Vercel"},
		{"netlify", "Netlify"},
		{"fastly", "Fastly CDN"},
		{"akamai", "Akamai Edge"},
		{"hubspot", "HubSpot"},
		{"zendesk", "Zendesk"},
	}

	seen := make(map[string]struct{})
	var out []string
	for _, r := range rules {
		if strings.Contains(all, r.needle) {
			if _, ok := seen[r.label]; !ok {
				seen[r.label] = struct{}{}
				out = append(out, r.label)
			}
		}
	}
	sort.Strings(out)
	return out
}

type crtShEntry struct {
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func queryCRTSh(ctx context.Context, client *http.Client, baseURL, domain string) (*CTIntel, error) {
	u := fmt.Sprintf("%s/?q=%s&output=json", baseURL, url.QueryEscape("%."+domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	raw, rErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	_ = resp.Body.Close()
	if rErr != nil {
		return nil, rErr
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, errors.New("unexpected crt.sh JSON payload")
	}

	subSeen := make(map[string]struct{})
	issuerSeen := make(map[string]struct{})
	suffix := "." + domain

	for _, e := range entries {
		if e.IssuerName != "" {
			iss := extractOrgFromDN(e.IssuerName)
			if iss != "" {
				issuerSeen[iss] = struct{}{}
			}
		}
		for _, candidate := range append(strings.Split(e.NameValue, "\n"), e.CommonName) {
			c := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(candidate)), "*.")
			c = strings.TrimSuffix(c, ".")
			if c == "" {
				continue
			}
			if (c == domain || strings.HasSuffix(c, suffix)) && domainSyntaxRE.MatchString(c) {
				subSeen[c] = struct{}{}
			}
		}
	}

	subs := make([]string, 0, len(subSeen))
	for s := range subSeen {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	if len(subs) > 200 {
		subs = subs[:200]
	}

	issuers := make([]string, 0, len(issuerSeen))
	for iss := range issuerSeen {
		issuers = append(issuers, iss)
	}
	sort.Strings(issuers)

	return &CTIntel{
		Source:            "crt.sh",
		CertificatesCount: len(entries),
		Subdomains:        subs,
		Issuers:           issuers,
	}, nil
}

func extractOrgFromDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "O") {
			return services.SanitizeText(strings.Trim(kv[1], `"`), 64)
		}
	}
	return services.SanitizeText(dn, 64)
}

type rdapDoc struct {
	Handle       string   `json:"handle"`
	LDHName      string   `json:"ldhName"`
	Name         string   `json:"name"`
	Country      string   `json:"country"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	Status       []string `json:"status"`
	SecureDNS    *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

func extractVCardField(vcard []any, propName string) string {
	if len(vcard) < 2 {
		return ""
	}
	rows, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, row := range rows {
		arr, ok := row.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		key, _ := arr[0].(string)
		if strings.EqualFold(key, propName) {
			if val, ok := arr[3].(string); ok && val != "" {
				return services.SanitizeText(val, 96)
			}
		}
	}
	return ""
}

func walkRDAPEntities(entities []rdapEntity, dst *RDAPIntel) {
	for _, ent := range entities {
		fn := extractVCardField(ent.VCardArray, "fn")
		email := extractVCardField(ent.VCardArray, "email")
		for _, role := range ent.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				if fn != "" && dst.Registrar == "" {
					dst.Registrar = fn
				}
			case "registrant", "administrative", "technical":
				if fn != "" && dst.Organization == "" {
					dst.Organization = fn
				}
			case "abuse":
				if email != "" && dst.AbuseContact == "" {
					dst.AbuseContact = email
				}
			}
		}
		if len(ent.Entities) > 0 {
			walkRDAPEntities(ent.Entities, dst)
		}
	}
}

func queryRDAPDomain(ctx context.Context, client *http.Client, baseURL, domain string, dst *RDAPIntel) error {
	doc, err := fetchRDAP(ctx, client, fmt.Sprintf("%s/domain/%s", baseURL, url.PathEscape(domain)))
	if err != nil {
		return err
	}
	dst.DomainName = strings.ToLower(doc.LDHName)
	dst.Status = doc.Status
	if doc.SecureDNS != nil {
		dst.DNSSECSigned = doc.SecureDNS.DelegationSigned
	}
	for _, ev := range doc.Events {
		if ev.EventAction != "" && ev.EventDate != "" {
			dst.Events[ev.EventAction] = ev.EventDate
		}
	}
	walkRDAPEntities(doc.Entities, dst)
	return nil
}

func queryRDAPIP(ctx context.Context, client *http.Client, baseURL, ip string, dst *RDAPIntel) error {
	doc, err := fetchRDAP(ctx, client, fmt.Sprintf("%s/ip/%s", baseURL, url.PathEscape(ip)))
	if err != nil {
		return err
	}
	if doc.Handle != "" {
		dst.NetworkHandle = doc.Handle
	}
	if doc.Name != "" {
		dst.NetworkName = doc.Name
	}
	if doc.StartAddress != "" && doc.EndAddress != "" {
		dst.IPRange = doc.StartAddress + " - " + doc.EndAddress
	}
	if doc.Country != "" {
		dst.Country = doc.Country
	}
	walkRDAPEntities(doc.Entities, dst)
	return nil
}

func fetchRDAP(ctx context.Context, client *http.Client, u string) (*rdapDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	raw, rErr := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	_ = resp.Body.Close()
	if rErr != nil {
		return nil, rErr
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc rdapDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("invalid RDAP JSON")
	}
	return &doc, nil
}

func queryGeoASN(ctx context.Context, client *http.Client, baseURL, ip string) (*GeoASNIntel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", baseURL, url.PathEscape(ip)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	raw, rErr := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	_ = resp.Body.Close()
	if rErr != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Success     *bool  `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return nil, errors.New("invalid GeoIP JSON")
	}
	if payload.Success != nil && !*payload.Success {
		return nil, errors.New("GeoIP lookup declined")
	}
	asnStr := ""
	if payload.Connection.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d", payload.Connection.ASN)
	}
	return &GeoASNIntel{
		IP:          ip,
		ASN:         asnStr,
		ISP:         services.SanitizeText(payload.Connection.ISP, 80),
		Org:         services.SanitizeText(payload.Connection.Org, 80),
		Country:     services.SanitizeText(payload.Country, 64),
		CountryCode: services.SanitizeText(payload.CountryCode, 8),
		Region:      services.SanitizeText(payload.Region, 64),
		City:        services.SanitizeText(payload.City, 64),
	}, nil
}

func inspectWebSurface(ctx context.Context, host, overrideURL string, timeout time.Duration) (*WebIntel, error) {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec // passive audit tool
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	var candidates []string
	if overrideURL != "" {
		candidates = []string{strings.TrimRight(overrideURL, "/")}
	} else {
		candidates = []string{"https://" + host, "http://" + host}
	}

	var base string
	var resp *http.Response
	var bodyBytes []byte
	for _, cand := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cand+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")
		r, dErr := client.Do(req)
		if dErr != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		_ = r.Body.Close()
		base = cand
		resp = r
		bodyBytes = b
		break
	}
	if resp == nil {
		return nil, errors.New("no HTTP/HTTPS response on standard web ports")
	}

	res := &WebIntel{
		URL:        base + "/",
		StatusCode: resp.StatusCode,
		Server:     services.SanitizeText(resp.Header.Get("Server"), 96),
		PoweredBy:  services.SanitizeText(resp.Header.Get("X-Powered-By"), 96),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		res.FinalURL = resp.Request.URL.String()
	}

	bodyStr := string(bodyBytes)
	if m := htmlTitleRE.FindStringSubmatch(bodyStr); len(m) >= 2 {
		res.Title = services.SanitizeText(html.UnescapeString(strings.TrimSpace(m[1])), 120)
	}

	// Missing defensive HTTP headers
	requiredHdrs := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
	}
	for _, hName := range requiredHdrs {
		if resp.Header.Get(hName) == "" {
			res.MissingSecurityHeaders = append(res.MissingSecurityHeaders, strings.ToLower(hName))
		}
	}

	// Passive technology fingerprinting
	techSeen := make(map[string]struct{})
	addTech := func(t string) {
		if t != "" {
			techSeen[t] = struct{}{}
		}
	}
	if res.Server != "" {
		addTech(res.Server)
	}
	if res.PoweredBy != "" {
		addTech(res.PoweredBy)
	}
	if m := metaGenRE.FindStringSubmatch(bodyStr); len(m) >= 2 {
		addTech(services.SanitizeText(m[1], 64))
	}
	if resp.Header.Get("CF-Ray") != "" {
		addTech("Cloudflare WAF/CDN")
	}
	if resp.Header.Get("X-Vercel-Id") != "" {
		addTech("Vercel")
	}
	if resp.Header.Get("X-Amz-Cf-Id") != "" {
		addTech("AWS CloudFront")
	}
	if strings.Contains(bodyStr, "/wp-content/") {
		addTech("WordPress")
	}
	if strings.Contains(bodyStr, "/_next/static/") {
		addTech("Next.js")
	}
	for t := range techSeen {
		res.Technologies = append(res.Technologies, t)
	}
	sort.Strings(res.Technologies)

	// TLS certificate inspection if HTTPS
	if strings.HasPrefix(base, "https://") && overrideURL == "" {
		if tlsInfo, tErr := inspector.InspectTLS(ctx, host, 443, host, timeout); tErr == nil && tlsInfo != nil && tlsInfo.Certificate != nil {
			res.TLSCertificate = tlsInfo.Certificate
		}
	}

	// RFC 9116 /.well-known/security.txt
	res.SecurityTxt = fetchSecurityTxt(ctx, client, base)
	// /robots.txt
	res.RobotsTxt = fetchRobotsTxt(ctx, client, base)

	return res, nil
}

func fetchSecurityTxt(ctx context.Context, client *http.Client, base string) *SecurityTxtInfo {
	for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/plain") {
			continue
		}
		info := &SecurityTxtInfo{Found: true, URL: base + path}
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			v := services.SanitizeText(strings.TrimSpace(kv[1]), 160)
			switch k {
			case "contact":
				info.Contacts = append(info.Contacts, v)
			case "expires":
				info.Expires = v
			case "encryption":
				info.Encryption = append(info.Encryption, v)
			case "policy":
				info.Policy = v
			}
		}
		if len(info.Contacts) > 0 || info.Expires != "" || info.Policy != "" {
			return info
		}
	}
	return &SecurityTxtInfo{Found: false}
}

func fetchRobotsTxt(ctx context.Context, client *http.Client, base string) *RobotsInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/robots.txt", nil)
	if err != nil {
		return &RobotsInfo{Found: false}
	}
	req.Header.Set("User-Agent", "Sentinel-Net-OSINT/1.2")
	resp, err := client.Do(req)
	if err != nil {
		return &RobotsInfo{Found: false}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/plain") {
		return &RobotsInfo{Found: false}
	}

	info := &RobotsInfo{Found: true}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := services.SanitizeText(strings.TrimSpace(kv[1]), 140)
		if v == "" {
			continue
		}
		if k == "sitemap" && len(info.Sitemaps) < 10 {
			info.Sitemaps = append(info.Sitemaps, v)
		} else if k == "disallow" && v != "/" && len(info.DisallowSample) < 15 {
			info.DisallowSample = append(info.DisallowSample, v)
		}
	}
	return info
}

func evaluateOSINTFindings(rep *Report) []FindingNote {
	var notes []FindingNote

	if rep.DNS != nil && rep.DNS.EmailSecurity != nil && rep.ApexDomain != "" {
		es := rep.DNS.EmailSecurity
		if es.PermissiveSPF {
			notes = append(notes, FindingNote{
				Severity:       "high",
				Category:       "email-spoofing",
				Title:          "Politique SPF permissive (+all / ?all)",
				Evidence:       es.SPFRecord,
				Recommendation: "Remplacer +all / ?all par ~all ou -all dans l'enregistrement TXT SPF du domaine.",
			})
		} else if es.MissingSPF && len(rep.DNS.MX) > 0 {
			notes = append(notes, FindingNote{
				Severity:       "medium",
				Category:       "email-spoofing",
				Title:          "Enregistrement SPF absent sur un domaine disposant de serveurs MX",
				Evidence:       fmt.Sprintf("Domaine %s (%d MX)", rep.ApexDomain, len(rep.DNS.MX)),
				Recommendation: "Publier un enregistrement TXT v=spf1 listant explicitement les serveurs d'envoi autorises.",
			})
		}

		if es.MissingDMARC && len(rep.DNS.MX) > 0 {
			notes = append(notes, FindingNote{
				Severity:       "medium",
				Category:       "email-spoofing",
				Title:          "Politique DMARC (_dmarc) absente",
				Evidence:       "_dmarc." + rep.ApexDomain + " introuvable",
				Recommendation: "Configurer un enregistrement TXT _dmarc avec p=quarantine ou p=reject pour bloquer l'usurpation d'identite.",
			})
		} else if strings.HasPrefix(es.DMARCPolicy, "none") {
			notes = append(notes, FindingNote{
				Severity:       "low",
				Category:       "email-spoofing",
				Title:          "DMARC en mode surveillance seule (p=none)",
				Evidence:       es.DMARCRecord,
				Recommendation: "Apres analyse des rapports RUA, faire evoluer la politique DMARC vers p=quarantine puis p=reject.",
			})
		}
	}

	if rep.RDAP != nil && rep.RDAP.DomainName != "" && !rep.RDAP.DNSSECSigned {
		notes = append(notes, FindingNote{
			Severity:       "low",
			Category:       "dns-integrity",
			Title:          "DNSSEC non active sur le domaine (delegationSigned=false)",
			Evidence:       rep.RDAP.DomainName,
			Recommendation: "Activer la signature DNSSEC aupres du bureau d'enregistrement et de l'hebergeur DNS.",
		})
	}

	if rep.CTLogs != nil && len(rep.CTLogs.Subdomains) > 0 {
		var sensitive []string
		for _, sub := range rep.CTLogs.Subdomains {
			if sensitiveSubRE.MatchString(sub) && len(sensitive) < 8 {
				sensitive = append(sensitive, sub)
			}
		}
		if len(sensitive) > 0 {
			notes = append(notes, FindingNote{
				Severity:       "medium",
				Category:       "attack-surface",
				Title:          "Sous-domaines d'administration ou de preproduction visibles dans les journaux CT",
				Evidence:       strings.Join(sensitive, ", "),
				Recommendation: "Verifier que ces environnements ne sont pas accessibles publiquement sans VPN ou authentification forte.",
			})
		}
	}

	if rep.Web != nil && rep.Web.SecurityTxt != nil && !rep.Web.SecurityTxt.Found {
		notes = append(notes, FindingNote{
			Severity:       "info",
			Category:       "vulnerability-disclosure",
			Title:          "Fichier /.well-known/security.txt absent (RFC 9116)",
			Evidence:       rep.Web.URL,
			Recommendation: "Publier un fichier /.well-known/security.txt indiquant le canal officiel de signalement de vulnerabilites.",
		})
	}

	return notes
}
