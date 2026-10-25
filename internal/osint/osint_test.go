package osint

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeDNS struct{}

func (fakeDNS) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}
func (fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	return "edge." + host + ".", nil
}
func (fakeDNS) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: "aspmx.l.google.com.", Pref: 10}}, nil
}
func (fakeDNS) LookupNS(_ context.Context, _ string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns1.cloudflare.com."}}, nil
}
func (fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if strings.HasPrefix(name, "_dmarc.") {
		return []string{"v=DMARC1; p=none; rua=mailto:sec@exemple.com"}, nil
	}
	return []string{
		"v=spf1 include:_spf.google.com ~all",
		"google-site-verification=123456",
	}, nil
}
func (fakeDNS) LookupAddr(_ context.Context, _ string) ([]string, error) {
	return []string{"web01.exemple.com."}, nil
}

func TestRunFullOSINTPipelineOffline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.URL.Query().Get("output") == "json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"exemple.com","name_value":"api.exemple.com\nstaging.exemple.com"}
			]`))
		case strings.HasPrefix(r.URL.Path, "/domain/"):
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"ldhName":"EXEMPLE.COM",
				"status":["client transfer prohibited"],
				"secureDNS":{"delegationSigned":false},
				"events":[{"eventAction":"registration","eventDate":"2020-01-15T00:00:00Z"}],
				"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar SAS"]]]}]
			}`))
		case strings.HasPrefix(r.URL.Path, "/ip/"):
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"handle":"NET-93-184-216-0",
				"name":"EDGE-NET",
				"country":"FR",
				"startAddress":"93.184.216.0",
				"endAddress":"93.184.216.255"
			}`))
		case r.URL.Path == "/93.184.216.34":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"country":"France","country_code":"FR","city":"Paris","connection":{"asn":15133,"org":"EdgeCast","isp":"EdgeCast"}}`))
		case r.URL.Path == "/.well-known/security.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Contact: mailto:security@exemple.com\nExpires: 2027-01-01T00:00:00Z\n"))
		case r.URL.Path == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin-portal\nSitemap: https://exemple.com/sitemap.xml\n"))
		default:
			w.Header().Set("Server", "nginx/1.26.0")
			w.Header().Set("CF-Ray", "89abc-CDG")
			_, _ = w.Write([]byte("<html><head><title>Portail Exemple</title></head><body>/wp-content/</body></html>"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rep, err := Run(context.Background(), "https://app.exemple.com:8443/login", Options{
		Timeout:      3 * time.Second,
		ActiveWeb:    true,
		WebTargetURL: srv.URL,
		CRTShBaseURL: srv.URL,
		RDAPBaseURL:  srv.URL,
		GeoIPBaseURL: srv.URL,
		HTTPClient:   srv.Client(),
		Resolver:     fakeDNS{},
	})
	if err != nil {
		t.Fatalf("OSINT Run failed: %v", err)
	}
	if rep.ApexDomain != "exemple.com" || len(rep.IPs) != 1 || rep.IPs[0] != "93.184.216.34" {
		t.Fatalf("unexpected domain/IP normalization: %+v", rep)
	}
	if rep.CTLogs == nil || len(rep.CTLogs.Subdomains) != 3 {
		t.Fatalf("expected 3 CT subdomains, got %+v", rep.CTLogs)
	}
	if rep.RDAP == nil || rep.RDAP.Registrar != "Example Registrar SAS" || rep.RDAP.NetworkName != "EDGE-NET" {
		t.Fatalf("unexpected RDAP result: %+v", rep.RDAP)
	}
	if rep.GeoASN == nil || rep.GeoASN.ASN != "AS15133" {
		t.Fatalf("unexpected GeoASN result: %+v", rep.GeoASN)
	}
	if rep.Web == nil || rep.Web.Title != "Portail Exemple" || !rep.Web.SecurityTxt.Found || !rep.Web.RobotsTxt.Found {
		t.Fatalf("unexpected Web OSINT result: %+v", rep.Web)
	}
	if len(rep.Observations) == 0 {
		t.Fatalf("expected OSINT posture observations (staging CT, p=none DMARC, unsigned DNSSEC)")
	}
}
