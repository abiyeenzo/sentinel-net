package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/scanner"
)

// Meta records when a baseline snapshot was created and its canonical SHA-256 digest.
type Meta struct {
	CreatedAt       string `json:"createdAt"`
	IntegritySHA256 string `json:"integritySha256"`
}

// Snapshot wraps a scanner.Report with an integrity seal.
type Snapshot struct {
	scanner.Report
	BaselineMeta *Meta `json:"baselineMeta,omitempty"`
}

// OpenedPort describes a port that transitioned into the open state.
type OpenedPort struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	PreviousState string `json:"previousState"`
	Service       string `json:"service"`
	Product       string `json:"product,omitempty"`
}

// ClosedPort describes a previously open port that is no longer open.
type ClosedPort struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	CurrentState    string `json:"currentState"`
	PreviousService string `json:"previousService"`
}

// ServiceChange describes a banner or TLS certificate change on a persistently open port.
type ServiceChange struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Kind   string `json:"kind"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// ScoreDelta captures how the posture score moved between two scans.
type ScoreDelta struct {
	PreviousScore int    `json:"previousScore"`
	CurrentScore  int    `json:"currentScore"`
	Delta         int    `json:"delta"`
	PreviousGrade string `json:"previousGrade"`
	CurrentGrade  string `json:"currentGrade"`
}

// DriftCounts summarizes drift item counts.
type DriftCounts struct {
	NewlyOpened    int `json:"newlyOpened"`
	NewlyClosed    int `json:"newlyClosed"`
	ServiceChanges int `json:"serviceChanges"`
	AddedHosts     int `json:"addedHosts"`
	RemovedHosts   int `json:"removedHosts"`
}

// DriftReport details inventory differences between a baseline and a current scan.
type DriftReport struct {
	ComparedAt        string          `json:"comparedAt"`
	BaselineStartedAt string          `json:"baselineStartedAt,omitempty"`
	CurrentStartedAt  string          `json:"currentStartedAt,omitempty"`
	HasDrift          bool            `json:"hasDrift"`
	HasCriticalDrift  bool            `json:"hasCriticalDrift"`
	Counts            DriftCounts     `json:"counts"`
	ScoreDelta        *ScoreDelta     `json:"scoreDelta,omitempty"`
	AddedHosts        []string        `json:"addedHosts"`
	RemovedHosts      []string        `json:"removedHosts"`
	NewlyOpened       []OpenedPort    `json:"newlyOpened"`
	NewlyClosed       []ClosedPort    `json:"newlyClosed"`
	ServiceChanges    []ServiceChange `json:"serviceChanges"`
}

type canonicalObs struct {
	Port           int    `json:"port"`
	State          string `json:"state"`
	ServiceID      string `json:"serviceId,omitempty"`
	Product        string `json:"product,omitempty"`
	Banner         string `json:"banner,omitempty"`
	TLSFingerprint string `json:"tlsFingerprint,omitempty"`
}

type canonicalHost struct {
	Target       string         `json:"target"`
	Observations []canonicalObs `json:"observations"`
}

func canonicalize(rep *scanner.Report) []canonicalHost {
	if rep == nil {
		return nil
	}
	srcHosts := rep.Hosts
	if len(srcHosts) == 0 && rep.Target != "" && len(rep.Observations) > 0 {
		srcHosts = []scanner.HostReport{{Target: rep.Target, Observations: rep.Observations}}
	}

	hosts := make([]canonicalHost, 0, len(srcHosts))
	for _, h := range srcHosts {
		obsList := make([]canonicalObs, 0, len(h.Observations))
		for _, o := range h.Observations {
			var banner, fp string
			if o.Inspection != nil {
				banner = o.Inspection.Banner
				if o.Inspection.TLS != nil && o.Inspection.TLS.Certificate != nil {
					fp = o.Inspection.TLS.Certificate.FingerprintSHA256
				}
			}
			obsList = append(obsList, canonicalObs{
				Port:           o.Port,
				State:          o.State,
				ServiceID:      o.Service.ID,
				Product:        o.Service.Product,
				Banner:         banner,
				TLSFingerprint: fp,
			})
		}
		sort.Slice(obsList, func(i, j int) bool { return obsList[i].Port < obsList[j].Port })
		hosts = append(hosts, canonicalHost{Target: h.Target, Observations: obsList})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Target < hosts[j].Target })
	return hosts
}

// ComputeDigest calculates the SHA-256 hex digest of a report's canonical host/port state.
func ComputeDigest(rep *scanner.Report) (string, error) {
	raw, err := json.Marshal(canonicalize(rep))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CreateSnapshot produces a sealed baseline snapshot from a scan report.
func CreateSnapshot(rep *scanner.Report) (*Snapshot, error) {
	if rep == nil {
		return nil, fmt.Errorf("nil scan report")
	}
	digest, err := ComputeDigest(rep)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Report: *rep,
		BaselineMeta: &Meta{
			CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
			IntegritySHA256: digest,
		},
	}, nil
}

// Verify checks whether a loaded Snapshot matches its recorded SHA-256 digest.
func Verify(snap *Snapshot) (bool, error) {
	if snap == nil || snap.BaselineMeta == nil || snap.BaselineMeta.IntegritySHA256 == "" {
		return false, nil
	}
	actual, err := ComputeDigest(&snap.Report)
	if err != nil {
		return false, err
	}
	return actual == snap.BaselineMeta.IntegritySHA256, nil
}

// SaveFile writes a signed baseline JSON snapshot to disk.
func SaveFile(path string, rep *scanner.Report) (*Snapshot, error) {
	snap, err := CreateSnapshot(rep)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return snap, nil
}

// LoadFile reads a baseline or scan JSON file from disk.
func LoadFile(path string, requireVerified bool) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("invalid JSON in %q: %w", path, err)
	}
	if snap.BaselineMeta != nil && snap.BaselineMeta.IntegritySHA256 != "" {
		ok, err := Verify(&snap)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("baseline integrity check failed for %q (digest mismatch)", path)
		}
	} else if requireVerified {
		return nil, fmt.Errorf("file %q does not contain a baseline integrity seal", path)
	}
	return &snap, nil
}

// Compare computes the drift report between a baseline report and a current report.
func Compare(baseRep, currRep *scanner.Report) DriftReport {
	prevHosts := canonicalize(baseRep)
	currHosts := canonicalize(currRep)

	prevMap := make(map[string]canonicalHost, len(prevHosts))
	for _, h := range prevHosts {
		prevMap[h.Target] = h
	}
	currMap := make(map[string]canonicalHost, len(currHosts))
	for _, h := range currHosts {
		currMap[h.Target] = h
	}

	addedHosts := make([]string, 0)
	removedHosts := make([]string, 0)
	newlyOpened := make([]OpenedPort, 0)
	newlyClosed := make([]ClosedPort, 0)
	serviceChanges := make([]ServiceChange, 0)

	for _, h := range currHosts {
		if _, ok := prevMap[h.Target]; !ok {
			addedHosts = append(addedHosts, h.Target)
		}
	}
	for _, h := range prevHosts {
		if _, ok := currMap[h.Target]; !ok {
			removedHosts = append(removedHosts, h.Target)
		}
	}

	for _, currHost := range currHosts {
		prevHost, hadHost := prevMap[currHost.Target]
		prevPorts := make(map[int]canonicalObs, len(prevHost.Observations))
		for _, o := range prevHost.Observations {
			prevPorts[o.Port] = o
		}
		currPorts := make(map[int]canonicalObs, len(currHost.Observations))
		for _, o := range currHost.Observations {
			currPorts[o.Port] = o
		}

		for _, currObs := range currHost.Observations {
			prevObs, hadPort := prevPorts[currObs.Port]
			wasOpen := hadPort && prevObs.State == "open"
			isOpen := currObs.State == "open"

			if !wasOpen && isOpen {
				prevState := "unscanned"
				if hadPort {
					prevState = prevObs.State
				}
				svcName := currObs.ServiceID
				if svcName == "" {
					svcName = fmt.Sprintf("TCP/%d", currObs.Port)
				}
				newlyOpened = append(newlyOpened, OpenedPort{
					Host:          currHost.Target,
					Port:          currObs.Port,
					PreviousState: prevState,
					Service:       svcName,
					Product:       currObs.Product,
				})
			} else if wasOpen && !isOpen {
				svcName := prevObs.ServiceID
				if svcName == "" {
					svcName = fmt.Sprintf("TCP/%d", currObs.Port)
				}
				newlyClosed = append(newlyClosed, ClosedPort{
					Host:            currHost.Target,
					Port:            currObs.Port,
					CurrentState:    currObs.State,
					PreviousService: svcName,
				})
			} else if wasOpen && isOpen {
				if prevObs.TLSFingerprint != "" && currObs.TLSFingerprint != "" && prevObs.TLSFingerprint != currObs.TLSFingerprint {
					serviceChanges = append(serviceChanges, ServiceChange{
						Host:   currHost.Target,
						Port:   currObs.Port,
						Kind:   "tls-certificate",
						Before: prevObs.TLSFingerprint,
						After:  currObs.TLSFingerprint,
					})
				} else {
					beforeBanner := prevObs.Product
					if beforeBanner == "" {
						beforeBanner = prevObs.Banner
					}
					afterBanner := currObs.Product
					if afterBanner == "" {
						afterBanner = currObs.Banner
					}
					if beforeBanner != "" && afterBanner != "" && beforeBanner != afterBanner {
						serviceChanges = append(serviceChanges, ServiceChange{
							Host:   currHost.Target,
							Port:   currObs.Port,
							Kind:   "service-banner",
							Before: beforeBanner,
							After:  afterBanner,
						})
					}
				}
			}
		}

		if hadHost {
			for _, prevObs := range prevHost.Observations {
				if _, stillScanned := currPorts[prevObs.Port]; !stillScanned && prevObs.State == "open" {
					svcName := prevObs.ServiceID
					if svcName == "" {
						svcName = fmt.Sprintf("TCP/%d", prevObs.Port)
					}
					newlyClosed = append(newlyClosed, ClosedPort{
						Host:            currHost.Target,
						Port:            prevObs.Port,
						CurrentState:    "not-scanned",
						PreviousService: svcName,
					})
				}
			}
		}
	}

	var delta *ScoreDelta
	if baseRep != nil && currRep != nil && baseRep.Risk.Grade != "" && currRep.Risk.Grade != "" {
		delta = &ScoreDelta{
			PreviousScore: baseRep.Risk.Score,
			CurrentScore:  currRep.Risk.Score,
			Delta:         currRep.Risk.Score - baseRep.Risk.Score,
			PreviousGrade: baseRep.Risk.Grade,
			CurrentGrade:  currRep.Risk.Grade,
		}
	}

	hasDrift := len(newlyOpened) > 0 || len(newlyClosed) > 0 || len(serviceChanges) > 0 || len(addedHosts) > 0 || len(removedHosts) > 0
	criticalDrift := len(newlyOpened) > 0
	for _, sc := range serviceChanges {
		if sc.Kind == "tls-certificate" {
			criticalDrift = true
			break
		}
	}

	var baseStart, currStart string
	if baseRep != nil {
		baseStart = baseRep.StartedAt
	}
	if currRep != nil {
		currStart = currRep.StartedAt
	}

	return DriftReport{
		ComparedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		BaselineStartedAt: baseStart,
		CurrentStartedAt:  currStart,
		HasDrift:          hasDrift,
		HasCriticalDrift:  criticalDrift,
		Counts: DriftCounts{
			NewlyOpened:    len(newlyOpened),
			NewlyClosed:    len(newlyClosed),
			ServiceChanges: len(serviceChanges),
			AddedHosts:     len(addedHosts),
			RemovedHosts:   len(removedHosts),
		},
		ScoreDelta:     delta,
		AddedHosts:     addedHosts,
		RemovedHosts:   removedHosts,
		NewlyOpened:    newlyOpened,
		NewlyClosed:    newlyClosed,
		ServiceChanges: serviceChanges,
	}
}
