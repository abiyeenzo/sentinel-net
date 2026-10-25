package scanner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/netscope"
	"github.com/abiyeenzo/sentinel-net/internal/osint"
	"github.com/abiyeenzo/sentinel-net/internal/risk"
	"github.com/abiyeenzo/sentinel-net/internal/services"
	"github.com/abiyeenzo/sentinel-net/internal/vuln"
)

const (
	MaxConcurrency = 128
	MinTimeout     = 100 * time.Millisecond
	MaxTimeout     = 15 * time.Second
)

// ErrCancelled is returned whenever a scan is aborted via context cancellation.
var ErrCancelled = errors.New("scan cancelled")

// DialFunc abstracts TCP socket dialing so tests can simulate hanging or lossy links deterministically.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Observation describes the outcome of probing one TCP port on one target.
type Observation struct {
	Port            int                  `json:"port"`
	State           string               `json:"state"`
	Reason          string               `json:"reason"`
	LatencyMs       float64              `json:"latencyMs"`
	Attempts        int                  `json:"attempts"`
	Service         services.ServiceInfo `json:"service"`
	Inspection      *inspector.Result    `json:"inspection,omitempty"`
	Components      []vuln.Component     `json:"components,omitempty"`
	Vulnerabilities []vuln.AdvisoryMatch `json:"vulnerabilities,omitempty"`
}

// ProgressEvent is emitted after each port completes.
type ProgressEvent struct {
	Target          string      `json:"target"`
	Hostname        string      `json:"hostname,omitempty"`
	Port            int         `json:"port"`
	State           string      `json:"state"`
	Completed       int         `json:"completed"`
	Total           int         `json:"total"`
	GlobalCompleted int         `json:"globalCompleted"`
	GlobalTotal     int         `json:"globalTotal"`
	Percent         float64     `json:"percent"`
	Observation     Observation `json:"observation"`
}

// LatencyStats summarizes TCP handshake/RST round-trip times in milliseconds.
type LatencyStats struct {
	SampleCount int      `json:"sampleCount"`
	MinMs       *float64 `json:"minMs"`
	AvgMs       *float64 `json:"avgMs"`
	P95Ms       *float64 `json:"p95Ms"`
	MaxMs       *float64 `json:"maxMs"`
}

// PortCounts tracks state totals for a host.
type PortCounts struct {
	Total   int `json:"total"`
	Open    int `json:"open"`
	Closed  int `json:"closed"`
	Unknown int `json:"unknown"`
}

// HostRiskBrief embeds the host-level posture score inside a HostReport.
type HostRiskBrief struct {
	Score  int                 `json:"score"`
	Grade  string              `json:"grade"`
	Level  string              `json:"level"`
	Counts risk.SeverityCounts `json:"counts"`
}

// HostReport contains all observations and posture metrics for one scanned IP.
type HostReport struct {
	Target               string        `json:"target"`
	Hostname             string        `json:"hostname,omitempty"`
	Scope                string        `json:"scope"`
	DurationMs           float64       `json:"durationMs"`
	Counts               PortCounts    `json:"counts"`
	Latency              LatencyStats  `json:"latency"`
	Risk                 HostRiskBrief `json:"risk"`
	VulnerabilitiesCount int           `json:"vulnerabilitiesCount"`
	OSINT                *osint.Report `json:"osint,omitempty"`
	Observations         []Observation `json:"observations"`
}

// Summary aggregates metrics across all scanned hosts.
type Summary struct {
	HostsScanned       int          `json:"hostsScanned"`
	HostsWithOpenPorts int          `json:"hostsWithOpenPorts"`
	PortsPerHost       int          `json:"portsPerHost"`
	TotalProbes        int          `json:"totalProbes"`
	OpenPorts          int          `json:"openPorts"`
	ClosedPorts        int          `json:"closedPorts"`
	UnknownPorts       int          `json:"unknownPorts"`
	Vulnerabilities    int          `json:"vulnerabilities"`
	DurationMs         float64      `json:"durationMs"`
	Latency            LatencyStats `json:"latency"`
}

// ToolMeta identifies the scanner binary version in serialized reports.
type ToolMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InspectionFlags records which optional inspectors were active during the scan.
type InspectionFlags struct {
	Banner    bool `json:"banner"`
	TLS       bool `json:"tls"`
	HTTP      bool `json:"http"`
	Vuln      bool `json:"vuln"`
	CVEOnline bool `json:"cveOnline,omitempty"`
	OSINT     bool `json:"osint,omitempty"`
}

// ConfigSnapshot records the scan configuration inside a report.
type ConfigSnapshot struct {
	Profile         string          `json:"profile,omitempty"`
	PortsCount      int             `json:"portsCount"`
	Ports           []int           `json:"ports"`
	TimeoutMs       int             `json:"timeoutMs"`
	Concurrency     int             `json:"concurrency"`
	HostConcurrency int             `json:"hostConcurrency"`
	Retries         int             `json:"retries"`
	DelayMs         int             `json:"delayMs"`
	Inspection      InspectionFlags `json:"inspection"`
}

// Report is the top-level serialized audit report produced by ScanNetwork.
type Report struct {
	SchemaVersion   string               `json:"schemaVersion"`
	Tool            ToolMeta             `json:"tool"`
	StartedAt       string               `json:"startedAt"`
	FinishedAt      string               `json:"finishedAt"`
	Configuration   ConfigSnapshot       `json:"configuration"`
	Target          string               `json:"target,omitempty"`
	Observations    []Observation        `json:"observations,omitempty"`
	Summary         Summary              `json:"summary"`
	Risk            risk.ScanSummary     `json:"risk"`
	VulnSummary     vuln.Summary         `json:"vulnSummary"`
	Vulnerabilities []vuln.AdvisoryMatch `json:"vulnerabilities,omitempty"`
	Hosts           []HostReport         `json:"hosts"`
	OSINT           []*osint.Report      `json:"osint,omitempty"`
	Drift           any                  `json:"drift,omitempty"`
}

// TCPOptions configures a single-host TCP scan.
type TCPOptions struct {
	Target      string
	ServerName  string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	Retries     int
	Delay       time.Duration
	Inspect     bool
	Banner      bool
	TLS         bool
	HTTP        bool
	Vuln        bool
	CVEOnline   bool
	Dial        DialFunc
	OnProgress  func(ProgressEvent)
}

// NetworkOptions configures a multi-host network audit.
type NetworkOptions struct {
	Targets         []netscope.TargetHost
	Ports           []int
	Profile         string
	Version         string
	Timeout         time.Duration
	Concurrency     int
	HostConcurrency int
	Retries         int
	Delay           time.Duration
	Inspect         bool
	Banner          bool
	TLS             bool
	HTTP            bool
	Vuln            bool
	CVEOnline       bool
	OSINT           bool
	Dial            DialFunc
	OnProgress      func(ProgressEvent)
}

func roundMs(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/10.0) / 100.0
}

func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func classifyDialError(err error) (state, reason string) {
	if isConnRefused(err) {
		return "closed", "ECONNREFUSED"
	}
	if isTimeoutErr(err) {
		return "unknown", "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "network is unreachable"):
		return "unknown", "ENETUNREACH"
	case strings.Contains(msg, "no route to host") || strings.Contains(msg, "host is unreachable"):
		return "unknown", "EHOSTUNREACH"
	default:
		return "unknown", "network-error"
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
	case <-timer.C:
		return nil
	}
}

func singleProbe(ctx context.Context, host string, port int, timeout time.Duration, dial DialFunc) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, fmt.Errorf("%w: %v", ErrCancelled, err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	t0 := time.Now()
	conn, err := dial(probeCtx, "tcp", addr)
	elapsed := roundMs(time.Since(t0))

	if err != nil {
		// Parent context cancellation takes precedence over per-probe deadline.
		if ctx.Err() != nil {
			return Observation{}, fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
		}
		state, reason := classifyDialError(err)
		return Observation{
			Port:      port,
			State:     state,
			Reason:    reason,
			LatencyMs: elapsed,
		}, nil
	}

	_ = conn.Close()
	if ctx.Err() != nil {
		return Observation{}, fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
	}

	return Observation{
		Port:      port,
		State:     "open",
		Reason:    "tcp-connect",
		LatencyMs: elapsed,
	}, nil
}

// ScanTCP runs bounded concurrent TCP probes against a single literal IP address.
func ScanTCP(ctx context.Context, opts TCPOptions) ([]Observation, error) {
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 16
	}

	addr, err := netip.ParseAddr(opts.Target)
	if err != nil || strings.TrimSpace(opts.Target) != opts.Target {
		return nil, errors.New("target must be a literal IP address")
	}
	_ = addr

	if len(opts.Ports) < 1 || len(opts.Ports) > netscope.HardMaxPorts {
		return nil, fmt.Errorf("ports must contain 1 to %d unique TCP ports", netscope.HardMaxPorts)
	}
	seenPorts := make(map[int]struct{}, len(opts.Ports))
	for _, p := range opts.Ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid TCP port %d (must be 1-65535)", p)
		}
		if _, dup := seenPorts[p]; dup {
			return nil, fmt.Errorf("duplicate TCP port %d", p)
		}
		seenPorts[p] = struct{}{}
	}

	if opts.Timeout < MinTimeout || opts.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout must be between %s and %s", MinTimeout, MaxTimeout)
	}
	if opts.Concurrency < 1 || opts.Concurrency > MaxConcurrency {
		return nil, fmt.Errorf("concurrency must be between 1 and %d", MaxConcurrency)
	}
	if opts.Retries < 0 || opts.Retries > 3 {
		return nil, errors.New("retries must be between 0 and 3")
	}
	if opts.Delay < 0 || opts.Delay > 5*time.Second {
		return nil, errors.New("delay must be between 0 and 5s")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCancelled, err)
	}

	dial := opts.Dial
	if dial == nil {
		dial = func(dCtx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: opts.Timeout}
			return d.DialContext(dCtx, network, address)
		}
	}

	doBanner := opts.Inspect || opts.Banner || opts.Vuln
	doTLS := opts.Inspect || opts.TLS || opts.Vuln
	doHTTP := opts.Inspect || opts.HTTP || opts.Vuln

	results := make([]Observation, len(opts.Ports))
	var nextIdx atomic.Int64
	var completedCount atomic.Int64

	workerCount := opts.Concurrency
	if workerCount > len(opts.Ports) {
		workerCount = len(opts.Ports)
	}

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	setErr := func(e error) {
		errOnce.Do(func() {
			firstErr = e
		})
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := ctx.Err(); err != nil {
					setErr(fmt.Errorf("%w: %v", ErrCancelled, err))
					return
				}
				idx := int(nextIdx.Add(1) - 1)
				if idx >= len(opts.Ports) {
					return
				}

				if opts.Delay > 0 && idx > 0 {
					if err := sleepWithContext(ctx, opts.Delay); err != nil {
						setErr(err)
						return
					}
				}

				port := opts.Ports[idx]
				var obs Observation
				for attempt := 0; attempt <= opts.Retries; attempt++ {
					probeRes, probeErr := singleProbe(ctx, opts.Target, port, opts.Timeout, dial)
					if probeErr != nil {
						setErr(probeErr)
						return
					}
					probeRes.Attempts = attempt + 1
					obs = probeRes
					if obs.State != "unknown" || obs.Reason != "timeout" || attempt == opts.Retries {
						break
					}
				}

				var clues *services.Clues
				if obs.State == "open" && (doBanner || doTLS || doHTTP) {
					inspTimeout := opts.Timeout
					if inspTimeout < 1200*time.Millisecond {
						inspTimeout = 1200 * time.Millisecond
					}
					inspRes, inspErr := inspector.InspectPort(ctx, opts.Target, port, inspector.Options{
						Banner:     doBanner,
						TLS:        doTLS,
						HTTP:       doHTTP,
						ServerName: opts.ServerName,
						Timeout:    inspTimeout,
					})
					if inspErr != nil {
						if ctx.Err() != nil {
							setErr(fmt.Errorf("%w: %v", ErrCancelled, ctx.Err()))
							return
						}
					}
					if inspRes != nil {
						obs.Inspection = inspRes
						clues = &services.Clues{
							Banner:         inspRes.Banner,
							TLSEstablished: inspRes.TLS != nil && inspRes.TLS.Established,
						}
						if inspRes.HTTP != nil {
							clues.HTTPStatusCode = inspRes.HTTP.StatusCode
							clues.HTTPServer = inspRes.HTTP.Server
							clues.HTTPPoweredBy = inspRes.HTTP.PoweredBy
						}
					}
				}

				obs.Service = services.Identify(port, clues)
				if obs.State == "open" && obs.Inspection != nil {
					obs.Components = vuln.ExtractComponents(obs.Service, obs.Inspection)
					obs.Vulnerabilities = vuln.MatchPort(opts.Target, port, obs.Service, obs.Inspection)
					if opts.CVEOnline && len(obs.Components) > 0 {
						obs.Vulnerabilities = vuln.LookupOnlineNVD(ctx, opts.Target, port, obs.Service, obs.Inspection, obs.Vulnerabilities, vuln.OnlineOptions{})
					}
				}
				results[idx] = obs

				doneNow := int(completedCount.Add(1))
				if opts.OnProgress != nil {
					opts.OnProgress(ProgressEvent{
						Target:      opts.Target,
						Port:        port,
						State:       obs.State,
						Completed:   doneNow,
						Total:       len(opts.Ports),
						Observation: obs,
					})
				}
			}
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCancelled, err)
	}
	return results, nil
}

func computeLatencyStats(observations []Observation) LatencyStats {
	samples := make([]float64, 0, len(observations))
	for _, o := range observations {
		if o.State == "open" || o.State == "closed" {
			samples = append(samples, o.LatencyMs)
		}
	}
	if len(samples) == 0 {
		return LatencyStats{SampleCount: 0}
	}
	sort.Float64s(samples)
	sum := 0.0
	for _, v := range samples {
		sum += v
	}
	minVal := samples[0]
	maxVal := samples[len(samples)-1]
	avgVal := math.Round((sum/float64(len(samples)))*100) / 100
	p95Idx := int(math.Floor(float64(len(samples)) * 0.95))
	if p95Idx >= len(samples) {
		p95Idx = len(samples) - 1
	}
	p95Val := samples[p95Idx]

	return LatencyStats{
		SampleCount: len(samples),
		MinMs:       &minVal,
		AvgMs:       &avgVal,
		P95Ms:       &p95Val,
		MaxMs:       &maxVal,
	}
}

// ScanNetwork orchestrates bounded scanning, protocol inspection and risk scoring across 1..N hosts.
func ScanNetwork(ctx context.Context, opts NetworkOptions) (*Report, error) {
	if len(opts.Targets) == 0 {
		return nil, errors.New("at least one target host is required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 24
	}
	if opts.HostConcurrency == 0 {
		opts.HostConcurrency = 4
	}
	if opts.HostConcurrency < 1 || opts.HostConcurrency > 32 {
		return nil, errors.New("host concurrency must be between 1 and 32")
	}
	if opts.Version == "" {
		opts.Version = "1.0.0"
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCancelled, err)
	}

	startedAt := time.Now().UTC()
	totalProbes := len(opts.Targets) * len(opts.Ports)
	var globalCompleted atomic.Int64
	var progressMu sync.Mutex

	activeHosts := opts.HostConcurrency
	if activeHosts > len(opts.Targets) {
		activeHosts = len(opts.Targets)
	}
	perHostConc := opts.Concurrency / activeHosts
	if perHostConc < 1 {
		perHostConc = 1
	}
	if perHostConc > MaxConcurrency {
		perHostConc = MaxConcurrency
	}

	hostReports := make([]HostReport, len(opts.Targets))
	var nextHost atomic.Int64
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	for w := 0; w < activeHosts; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := ctx.Err(); err != nil {
					errOnce.Do(func() { firstErr = fmt.Errorf("%w: %v", ErrCancelled, err) })
					return
				}
				idx := int(nextHost.Add(1) - 1)
				if idx >= len(opts.Targets) {
					return
				}

				entry := opts.Targets[idx]
				hStart := time.Now()
				obs, err := ScanTCP(ctx, TCPOptions{
					Target:      entry.IP,
					ServerName:  entry.Hostname,
					Ports:       opts.Ports,
					Timeout:     opts.Timeout,
					Concurrency: perHostConc,
					Retries:     opts.Retries,
					Delay:       opts.Delay,
					Inspect:     opts.Inspect,
					Banner:      opts.Banner,
					TLS:         opts.TLS,
					HTTP:        opts.HTTP,
					Vuln:        opts.Vuln,
					CVEOnline:   opts.CVEOnline,
					Dial:        opts.Dial,
					OnProgress: func(ev ProgressEvent) {
						doneGlobal := int(globalCompleted.Add(1))
						if opts.OnProgress != nil {
							ev.Hostname = entry.Hostname
							ev.GlobalCompleted = doneGlobal
							ev.GlobalTotal = totalProbes
							ev.Percent = math.Round((float64(doneGlobal)/float64(totalProbes))*1000) / 10
							progressMu.Lock()
							opts.OnProgress(ev)
							progressMu.Unlock()
						}
					},
				})
				if err != nil {
					errOnce.Do(func() { firstErr = err })
					return
				}

				hDuration := roundMs(time.Since(hStart))
				var counts PortCounts
				counts.Total = len(obs)
				vulnTotal := 0
				portInputs := make([]risk.PortInput, 0, len(obs))
				for _, o := range obs {
					switch o.State {
					case "open":
						counts.Open++
					case "closed":
						counts.Closed++
					default:
						counts.Unknown++
					}
					vulnTotal += len(o.Vulnerabilities)
					portInputs = append(portInputs, risk.PortInput{
						Port:       o.Port,
						State:      o.State,
						LatencyMs:  o.LatencyMs,
						Service:    o.Service,
						Inspection: o.Inspection,
					})
				}

				hRisk := risk.EvaluateHost(entry.IP, portInputs)
				scope := entry.Scope
				if scope == "" {
					if a, parseErr := netip.ParseAddr(entry.IP); parseErr == nil {
						scope = netscope.ClassifyScope(a)
					}
				}

				hostReports[idx] = HostReport{
					Target:     entry.IP,
					Hostname:   entry.Hostname,
					Scope:      scope,
					DurationMs: hDuration,
					Counts:     counts,
					Latency:    computeLatencyStats(obs),
					Risk: HostRiskBrief{
						Score:  hRisk.Score,
						Grade:  hRisk.Grade,
						Level:  hRisk.Level,
						Counts: hRisk.Counts,
					},
					VulnerabilitiesCount: vulnTotal,
					Observations:         obs,
				}
			}
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	if opts.OSINT {
		osintCache := make(map[string]*osint.Report)
		for i := range hostReports {
			query := hostReports[i].Hostname
			if query == "" {
				query = hostReports[i].Target
			}
			if cached, ok := osintCache[query]; ok {
				hostReports[i].OSINT = cached
				continue
			}
			oRep, oErr := osint.Run(ctx, query, osint.Options{
				Timeout:   5 * time.Second,
				ActiveWeb: opts.Inspect || opts.HTTP,
			})
			if oErr == nil && oRep != nil {
				osintCache[query] = oRep
				hostReports[i].OSINT = oRep
			}
		}
	}

	finishedAt := time.Now().UTC()
	durationMs := roundMs(finishedAt.Sub(startedAt))

	allObs := make([]Observation, 0, totalProbes)
	var allVulns []vuln.AdvisoryMatch
	riskInputs := make([]risk.HostInput, 0, len(hostReports))
	var osintList []*osint.Report
	seenOSINT := make(map[*osint.Report]struct{})
	hostsWithOpen := 0
	openTotal, closedTotal, unknownTotal, vulnGlobalTotal := 0, 0, 0, 0

	for _, hr := range hostReports {
		if hr.Counts.Open > 0 {
			hostsWithOpen++
		}
		openTotal += hr.Counts.Open
		closedTotal += hr.Counts.Closed
		unknownTotal += hr.Counts.Unknown
		vulnGlobalTotal += hr.VulnerabilitiesCount
		if hr.OSINT != nil {
			if _, ok := seenOSINT[hr.OSINT]; !ok {
				seenOSINT[hr.OSINT] = struct{}{}
				osintList = append(osintList, hr.OSINT)
			}
		}
		allObs = append(allObs, hr.Observations...)

		pInputs := make([]risk.PortInput, 0, len(hr.Observations))
		for _, o := range hr.Observations {
			if len(o.Vulnerabilities) > 0 {
				allVulns = append(allVulns, o.Vulnerabilities...)
			}
			pInputs = append(pInputs, risk.PortInput{
				Port:       o.Port,
				State:      o.State,
				LatencyMs:  o.LatencyMs,
				Service:    o.Service,
				Inspection: o.Inspection,
			})
		}
		riskInputs = append(riskInputs, risk.HostInput{
			Target:       hr.Target,
			Observations: pInputs,
		})
	}

	rep := &Report{
		SchemaVersion: "1.0.0",
		Tool: ToolMeta{
			Name:    "sentinel-net",
			Version: opts.Version,
		},
		StartedAt:  startedAt.Format(time.RFC3339Nano),
		FinishedAt: finishedAt.Format(time.RFC3339Nano),
		Configuration: ConfigSnapshot{
			Profile:         opts.Profile,
			PortsCount:      len(opts.Ports),
			Ports:           opts.Ports,
			TimeoutMs:       int(opts.Timeout / time.Millisecond),
			Concurrency:     opts.Concurrency,
			HostConcurrency: opts.HostConcurrency,
			Retries:         opts.Retries,
			DelayMs:         int(opts.Delay / time.Millisecond),
			Inspection: InspectionFlags{
				Banner:    opts.Inspect || opts.Banner || opts.Vuln,
				TLS:       opts.Inspect || opts.TLS || opts.Vuln,
				HTTP:      opts.Inspect || opts.HTTP || opts.Vuln,
				Vuln:      opts.Inspect || opts.Banner || opts.TLS || opts.HTTP || opts.Vuln,
				CVEOnline: opts.CVEOnline,
				OSINT:     opts.OSINT,
			},
		},
		Summary: Summary{
			HostsScanned:       len(hostReports),
			HostsWithOpenPorts: hostsWithOpen,
			PortsPerHost:       len(opts.Ports),
			TotalProbes:        totalProbes,
			OpenPorts:          openTotal,
			ClosedPorts:        closedTotal,
			UnknownPorts:       unknownTotal,
			Vulnerabilities:    vulnGlobalTotal,
			DurationMs:         durationMs,
			Latency:            computeLatencyStats(allObs),
		},
		Risk:            risk.EvaluateScan(riskInputs),
		VulnSummary:     vuln.Summarize(allVulns, opts.CVEOnline),
		Vulnerabilities: allVulns,
		Hosts:           hostReports,
		OSINT:           osintList,
	}

	if len(hostReports) == 1 {
		rep.Target = hostReports[0].Target
		rep.Observations = hostReports[0].Observations
	}

	return rep, nil
}
