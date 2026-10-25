package risk

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/services"
)

// RuleSpec documents a deterministic exposure rule.
type RuleSpec struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Severity         string `json:"severity"`
	Weight           int    `json:"weight"`
	ShortDescription string `json:"shortDescription"`
	Help             string `json:"help"`
}

// Finding represents one evidence-backed observation triggered on a host/port.
type Finding struct {
	RuleID            string `json:"ruleId"`
	Name              string `json:"name"`
	Severity          string `json:"severity"`
	Weight            int    `json:"weight"`
	Confidence        string `json:"confidence"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Service           string `json:"service"`
	Title             string `json:"title"`
	Evidence          string `json:"evidence"`
	Rationale         string `json:"rationale"`
	FalsePositiveNote string `json:"falsePositiveNote"`
	Remediation       string `json:"remediation"`
}

// SeverityCounts tracks finding totals per severity bucket.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// HostSummary captures the posture score and findings for one host.
type HostSummary struct {
	Host           string         `json:"host"`
	Score          int            `json:"score"`
	Grade          string         `json:"grade"`
	Level          string         `json:"level"`
	OpenPortsCount int            `json:"openPortsCount"`
	Counts         SeverityCounts `json:"counts"`
	Findings       []Finding      `json:"findings"`
}

// ScanSummary aggregates risk findings and posture scores across all scanned hosts.
type ScanSummary struct {
	Score              int            `json:"score"`
	Grade              string         `json:"grade"`
	Level              string         `json:"level"`
	Counts             SeverityCounts `json:"counts"`
	TotalFindings      int            `json:"totalFindings"`
	ActionableFindings int            `json:"actionableFindings"`
	Hosts              []HostSummary  `json:"hosts"`
	Findings           []Finding      `json:"findings"`
}

// PortInput is the minimal port observation structure consumed by the risk engine.
type PortInput struct {
	Port       int
	State      string
	LatencyMs  float64
	Service    services.ServiceInfo
	Inspection *inspector.Result
}

// HostInput groups a host address and its port observations for evaluation.
type HostInput struct {
	Target       string
	Observations []PortInput
}

var orderedRuleIDs = []string{
	"SN-CRIT-001", "SN-CRIT-002", "SN-CRIT-003",
	"SN-HIGH-001", "SN-HIGH-002", "SN-HIGH-003", "SN-HIGH-004", "SN-HIGH-005",
	"SN-MED-001", "SN-MED-002", "SN-MED-003", "SN-MED-004",
	"SN-LOW-001", "SN-LOW-002",
	"SN-INFO-001",
}

var rulesCatalog = map[string]RuleSpec{
	"SN-CRIT-001": {
		ID:               "SN-CRIT-001",
		Name:             "CleartextRemoteAdmin",
		Severity:         "critical",
		Weight:           30,
		ShortDescription: "Service d'administration distante en clair expose (Telnet / r-services)",
		Help:             "Desactiver Telnet/rlogin/rsh et imposer SSHv2 avec authentification par cle.",
	},
	"SN-CRIT-002": {
		ID:               "SN-CRIT-002",
		Name:             "ExposedContainerControlPlane",
		Severity:         "critical",
		Weight:           35,
		ShortDescription: "API de demon conteneur ou orchestrateur exposee sans TLS",
		Help:             "Ne jamais exposer Docker TCP (2375) ou Kubelet RO (10255) sur le reseau; exiger mTLS et filtrage pare-feu.",
	},
	"SN-CRIT-003": {
		ID:               "SN-CRIT-003",
		Name:             "ExpiredTLSCertificate",
		Severity:         "critical",
		Weight:           25,
		ShortDescription: "Certificat TLS X.509 expire sur un service actif",
		Help:             "Renouveler le certificat TLS et automatiser la rotation (ACME ou PKI interne).",
	},
	"SN-HIGH-001": {
		ID:               "SN-HIGH-001",
		Name:             "DirectDatabaseExposure",
		Severity:         "high",
		Weight:           20,
		ShortDescription: "Base de donnees, cache memoire ou moteur d'indexation directement joignable",
		Help:             "Lier le service a 127.0.0.1 ou un VLAN backend dedie, activer l'authentification forte et TLS.",
	},
	"SN-HIGH-002": {
		ID:               "SN-HIGH-002",
		Name:             "LateralMovementSurface",
		Severity:         "high",
		Weight:           18,
		ShortDescription: "Protocole de partage fichier ou RPC sensible aux mouvements lateraux expose",
		Help:             "Restreindre SMB/RPC/NFS/rsync aux sous-reseaux d'administration autorises et imposer la signature SMB.",
	},
	"SN-HIGH-003": {
		ID:               "SN-HIGH-003",
		Name:             "ExposedGraphicalOrOOBAdmin",
		Severity:         "high",
		Weight:           18,
		ShortDescription: "Interface d'administration graphique ou hors-bande exposee (RDP / VNC / IPMI / WinRM)",
		Help:             "Isoler RDP, VNC, IPMI et WinRM derriere un bastion VPN et activer NLA/MFA.",
	},
	"SN-HIGH-004": {
		ID:               "SN-HIGH-004",
		Name:             "ExposedIndustrialOrIoTProtocol",
		Severity:         "high",
		Weight:           18,
		ShortDescription: "Protocole industriel (OT/SCADA) ou IoT non chiffre accessible sur le reseau",
		Help:             "Cloisonner les equipements OT/IoT dans un sous-reseau dedie avec filtrage strict.",
	},
	"SN-HIGH-005": {
		ID:               "SN-HIGH-005",
		Name:             "DeprecatedTLSProtocol",
		Severity:         "high",
		Weight:           20,
		ShortDescription: "Protocole TLS obsolete negocie (TLS 1.0 ou TLS 1.1)",
		Help:             "Desactiver TLS 1.0 et TLS 1.1; imposer TLS 1.2 minimum et privilegier TLS 1.3.",
	},
	"SN-MED-001": {
		ID:               "SN-MED-001",
		Name:             "CleartextProtocolExposure",
		Severity:         "medium",
		Weight:           12,
		ShortDescription: "Protocole applicatif transmettant potentiellement des identifiants en clair",
		Help:             "Migrer vers SFTP/FTPS, IMAPS, POP3S, LDAPS ou imposer STARTTLS obligatoire.",
	},
	"SN-MED-002": {
		ID:               "SN-MED-002",
		Name:             "UntrustedOrSelfSignedTLS",
		Severity:         "medium",
		Weight:           10,
		ShortDescription: "Certificat TLS auto-signe ou chaine de certification non validee",
		Help:             "Deployer un certificat signe par une autorite reconnue ou installer la racine PKI interne.",
	},
	"SN-MED-003": {
		ID:               "SN-MED-003",
		Name:             "ExpiringSoonTLSCertificate",
		Severity:         "medium",
		Weight:           10,
		ShortDescription: "Certificat TLS arrivant a expiration sous 30 jours",
		Help:             "Planifier le renouvellement anticipe du certificat avant interruption de service.",
	},
	"SN-MED-004": {
		ID:               "SN-MED-004",
		Name:             "UnencryptedHTTPService",
		Severity:         "medium",
		Weight:           8,
		ShortDescription: "Service HTTP actif sans redirection automatique vers HTTPS",
		Help:             "Configurer une redirection permanente HTTP 301/308 vers HTTPS et activer HSTS.",
	},
	"SN-LOW-001": {
		ID:               "SN-LOW-001",
		Name:             "MissingHTTPSecurityHeaders",
		Severity:         "low",
		Weight:           5,
		ShortDescription: "En-tetes HTTP de securite absents",
		Help:             "Ajouter Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options et X-Frame-Options.",
	},
	"SN-LOW-002": {
		ID:               "SN-LOW-002",
		Name:             "VerboseServiceBanner",
		Severity:         "low",
		Weight:           4,
		ShortDescription: "Numero de version detaille expose dans les en-tetes ou bannieres",
		Help:             "Masquer les versions logicielles exactes (ex: server_tokens off, ServerTokens Prod).",
	},
	"SN-INFO-001": {
		ID:               "SN-INFO-001",
		Name:             "EncryptedServiceInventory",
		Severity:         "info",
		Weight:           0,
		ShortDescription: "Service reseau chiffre actif inventorie",
		Help:             "Verifier periodiquement la conformite de l'exposition avec la matrice de flux autorisee.",
	},
}

// AllRules returns the deterministic catalog of risk rules in stable order.
func AllRules() []RuleSpec {
	out := make([]RuleSpec, 0, len(orderedRuleIDs))
	for _, id := range orderedRuleIDs {
		out = append(out, rulesCatalog[id])
	}
	return out
}

// ComputeGrade maps a 0-100 posture score to a letter grade.
func ComputeGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 88:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func computeLevel(score int, c SeverityCounts) string {
	switch {
	case c.Critical > 0 || score < 40:
		return "critical"
	case c.High > 0 || score < 65:
		return "high"
	case c.Medium > 0 || score < 85:
		return "medium"
	case c.Low > 0:
		return "low"
	default:
		return "minimal"
	}
}

func severityOrder(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

var (
	cleartextRemotePorts   = map[int]bool{23: true, 512: true, 513: true, 514: true, 2323: true}
	containerRawPorts      = map[int]bool{2375: true, 2379: true, 4243: true, 10255: true}
	databasePorts          = map[int]bool{1433: true, 1434: true, 1521: true, 3306: true, 33060: true, 5432: true, 5984: true, 6379: true, 7000: true, 7474: true, 8086: true, 8123: true, 9042: true, 9200: true, 9300: true, 11211: true, 27017: true, 28017: true}
	lateralPorts           = map[int]bool{111: true, 135: true, 139: true, 445: true, 873: true, 2049: true, 3260: true}
	graphicalOOBPorts      = map[int]bool{623: true, 902: true, 3389: true, 5900: true, 5901: true, 5985: true, 10000: true}
	industrialIoTPorts     = map[int]bool{502: true, 554: true, 1883: true, 4840: true, 5683: true, 7547: true, 47808: true}
	cleartextTransferPorts = map[int]bool{20: true, 21: true, 69: true, 79: true, 110: true, 143: true, 389: true, 8009: true, 9418: true}
	httpVersionRE          = regexp.MustCompile(`/[0-9]+\.[0-9]+`)
	bannerVersionRE        = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)
)

func buildFinding(ruleID, host string, port int, svcLabel, confidence, evidence, rationale, fpNote string) Finding {
	rule := rulesCatalog[ruleID]
	if svcLabel == "" {
		svcLabel = fmt.Sprintf("TCP/%d", port)
	}
	return Finding{
		RuleID:            rule.ID,
		Name:              rule.Name,
		Severity:          rule.Severity,
		Weight:            rule.Weight,
		Confidence:        confidence,
		Host:              host,
		Port:              port,
		Service:           svcLabel,
		Title:             rule.ShortDescription,
		Evidence:          evidence,
		Rationale:         rationale,
		FalsePositiveNote: fpNote,
		Remediation:       rule.Help,
	}
}

// EvaluateHost evaluates open port observations for a single target host.
func EvaluateHost(host string, observations []PortInput) HostSummary {
	findings := make([]Finding, 0)
	openCount := 0

	for _, obs := range observations {
		if obs.State != "open" {
			continue
		}
		openCount++
		port := obs.Port
		svc := obs.Service
		insp := obs.Inspection
		tlsEstablished := insp != nil && insp.TLS != nil && insp.TLS.Established

		if cleartextRemotePorts[port] || svc.ID == "telnet" || svc.ID == "rlogin" || svc.ID == "rexec" {
			conf := "medium"
			ev := fmt.Sprintf("Port TCP/%d (%s) ouvert.", port, svc.Label)
			if insp != nil && insp.Banner != "" {
				conf = "high"
				ev = fmt.Sprintf("Port TCP/%d (%s) ouvert, banniere: %q.", port, svc.Label, insp.Banner)
			}
			findings = append(findings, buildFinding(
				"SN-CRIT-001", host, port, svc.Label, conf, ev,
				"Les protocoles Telnet et r-services transmettent identifiants et sessions en clair.",
				"Un service interne non standard peut reutiliser ce port si aucune banniere n'a ete confirmee.",
			))
		}

		if containerRawPorts[port] && !tlsEstablished {
			conf := "medium"
			if insp != nil && insp.HTTP != nil {
				conf = "high"
			}
			findings = append(findings, buildFinding(
				"SN-CRIT-002", host, port, svc.Label, conf,
				fmt.Sprintf("Port TCP/%d (%s) ouvert sans couche TLS detectee.", port, svc.Label),
				"L'exposition directe de Docker (2375), etcd (2379) ou Kubelet RO (10255) permet souvent une compromission de l'hote.",
				"Peut correspondre a un demon local ecoute uniquement sur 127.0.0.1.",
			))
		}

		if databasePorts[port] || svc.Category == "database" {
			conf := "medium"
			if svc.Confidence == "banner-verified" || (insp != nil && insp.HTTP != nil) {
				conf = "high"
			}
			findings = append(findings, buildFinding(
				"SN-HIGH-001", host, port, svc.Label, conf,
				fmt.Sprintf("Port de donnees TCP/%d (%s) joignable en %.2f ms.", port, svc.Label, obs.LatencyMs),
				"Les bases de donnees et caches exposes sont sensibles au brute-force et aux acces non authentifies.",
				"Attendu uniquement depuis un VLAN applicatif autorise ou sur loopback en developpement.",
			))
		}

		if lateralPorts[port] {
			findings = append(findings, buildFinding(
				"SN-HIGH-002", host, port, svc.Label, "medium",
				fmt.Sprintf("Port d'infrastructure TCP/%d (%s) ouvert.", port, svc.Label),
				"SMB, MSRPC, NFS et rsync facilitent l'enumeration et les mouvements lateraux sur un reseau plat.",
				"Attendu sur un serveur de fichiers ou controleur de domaine dans un segment cloisonne.",
			))
		}

		if graphicalOOBPorts[port] || svc.ID == "vnc" {
			conf := "medium"
			if svc.Confidence == "banner-verified" {
				conf = "high"
			}
			findings = append(findings, buildFinding(
				"SN-HIGH-003", host, port, svc.Label, conf,
				fmt.Sprintf("Port d'administration TCP/%d (%s) ouvert.", port, svc.Label),
				"Les services RDP, VNC, IPMI et WinRM sont frequemment cibles par brute-force et exploits pre-auth.",
				"Acceptable lorsque l'acces reseau est restreint par pare-feu aux seuls bastions.",
			))
		}

		if industrialIoTPorts[port] {
			findings = append(findings, buildFinding(
				"SN-HIGH-004", host, port, svc.Label, "medium",
				fmt.Sprintf("Port OT/IoT TCP/%d (%s) ouvert.", port, svc.Label),
				"De nombreux protocoles industriels et IoT (Modbus, BACnet, MQTT clair) n'integrent pas d'authentification native.",
				"Un processus applicatif distinct peut ecouter sur ce numero de port.",
			))
		}

		if cleartextTransferPorts[port] || svc.ID == "ftp" || svc.ID == "pop3" || svc.ID == "imap" {
			conf := "medium"
			if svc.Confidence == "banner-verified" {
				conf = "high"
			}
			findings = append(findings, buildFinding(
				"SN-MED-001", host, port, svc.Label, conf,
				fmt.Sprintf("Port TCP/%d (%s) ouvert sans TLS implicite.", port, svc.Label),
				"FTP, POP3, IMAP, LDAP sans TLS implicite ou AJP exposent les sessions a l'interception.",
				"Certains serveurs exigent STARTTLS avant toute authentification.",
			))
		}

		if tlsEstablished {
			proto := insp.TLS.Protocol
			if proto == "TLSv1.0" || proto == "TLSv1.1" {
				findings = append(findings, buildFinding(
					"SN-HIGH-005", host, port, svc.Label, "high",
					fmt.Sprintf("Protocole obsolete negocie sur TCP/%d: %s.", port, proto),
					"TLS 1.0 et TLS 1.1 sont deprecies (RFC 8996) en raison de faiblesses cryptographiques connues.",
					"Faible risque de faux positif: version issue directement du handshake TLS.",
				))
			}

			if cert := insp.TLS.Certificate; cert != nil {
				if cert.Expired {
					findings = append(findings, buildFinding(
						"SN-CRIT-003", host, port, svc.Label, "high",
						fmt.Sprintf("Certificat %q expire le %s.", cert.SubjectCN, cert.ValidTo),
						"Un certificat expire invalide la chaine de confiance cryptographique des clients.",
						"Verifier la synchronisation NTP de la machine executant l'audit.",
					))
				} else if cert.ExpiringSoon {
					findings = append(findings, buildFinding(
						"SN-MED-003", host, port, svc.Label, "high",
						fmt.Sprintf("Certificat %q expire dans %d jour(s) (%s).", cert.SubjectCN, cert.DaysRemaining, cert.ValidTo),
						"Une expiration proche expose le service a une panne TLS.",
						"Frequent avec les certificats ACME a courte duree si le renouvellement automatique est actif.",
					))
				}

				if cert.SelfSigned || !insp.TLS.Authorized {
					reason := "chaine non verifiee"
					if cert.SelfSigned {
						reason = "certificat auto-signe"
					} else if insp.TLS.AuthorizationError != "" {
						reason = insp.TLS.AuthorizationError
					}
					findings = append(findings, buildFinding(
						"SN-MED-002", host, port, svc.Label, "high",
						fmt.Sprintf("Validation TLS echouee sur TCP/%d (%s).", port, reason),
						"Les clients ne peuvent pas verifier l'identite du serveur sans autorite de certification approuvee.",
						"Attendu lors d'un scan par IP directe sans SNI ou face a une PKI interne non installee sur la sonde.",
					))
				}
			}
		}

		if insp != nil && insp.HTTP != nil && insp.HTTP.StatusCode > 0 {
			h := insp.HTTP
			redirectsToHTTPS := h.Scheme == "http" &&
				(h.StatusCode == 301 || h.StatusCode == 302 || h.StatusCode == 307 || h.StatusCode == 308) &&
				strings.HasPrefix(strings.ToLower(h.Location), "https://")

			if h.Scheme == "http" && !redirectsToHTTPS {
				findings = append(findings, buildFinding(
					"SN-MED-004", host, port, svc.Label, "high",
					fmt.Sprintf("HTTP/%d repond %d sans redirection HTTPS.", port, h.StatusCode),
					"Le trafic HTTP en clair expose les jetons de session et contenus a l'ecoute reseau.",
					"Acceptable sur 127.0.0.1 ou derriere un reverse proxy assurant la terminaison TLS.",
				))
			}

			if len(h.MissingSecurityHeaders) > 0 && !redirectsToHTTPS {
				findings = append(findings, buildFinding(
					"SN-LOW-001", host, port, svc.Label, "high",
					fmt.Sprintf("En-tetes manquants sur %s/%d: %s.", strings.ToUpper(h.Scheme), port, strings.Join(h.MissingSecurityHeaders, ", ")),
					"Ces en-tetes limitent les risques de clickjacking, MIME-sniffing et downgrade HTTPS.",
					"Impact moindre sur une API purement JSON non destinee aux navigateurs.",
				))
			}

			if (h.Server != "" && httpVersionRE.MatchString(h.Server)) || h.PoweredBy != "" {
				disclosed := strings.TrimSpace(strings.Join([]string{h.Server, h.PoweredBy}, " "))
				findings = append(findings, buildFinding(
					"SN-LOW-002", host, port, svc.Label, "high",
					fmt.Sprintf("En-tete HTTP detaille sur TCP/%d: %q.", port, disclosed),
					"La publication des versions exactes facilite le profilage automatise.",
					"Le masquage d'en-tete est une mesure d'hygiene complementaire aux mises a jour.",
				))
			}
		} else if insp != nil && insp.Banner != "" && svc.ID != "ssh" && bannerVersionRE.MatchString(insp.Banner) {
			findings = append(findings, buildFinding(
				"SN-LOW-002", host, port, svc.Label, "medium",
				fmt.Sprintf("Version detaillee dans la banniere TCP/%d: %q.", port, insp.Banner),
				"La banniere expose un numero de version precis.",
				"Certains protocoles imposent l'annonce de version lors de la connexion.",
			))
		}

		hasHigherFinding := false
		for _, f := range findings {
			if f.Port == port && f.Severity != "low" && f.Severity != "info" {
				hasHigherFinding = true
				break
			}
		}
		if (svc.Encrypted || tlsEstablished) && !hasHigherFinding {
			protoNote := ""
			if tlsEstablished {
				protoNote = ", " + insp.TLS.Protocol
			}
			findings = append(findings, buildFinding(
				"SN-INFO-001", host, port, svc.Label, "high",
				fmt.Sprintf("Service chiffre actif sur TCP/%d (%s%s).", port, svc.Label, protoNote),
				"Point d'entree reseau actif utilisant un transport chiffre.",
				"Observation d'inventaire informative.",
			))
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		si, sj := severityOrder(findings[i].Severity), severityOrder(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].Port < findings[j].Port
	})

	var counts SeverityCounts
	penalty := 0
	for _, f := range findings {
		penalty += f.Weight
		switch f.Severity {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		case "info":
			counts.Info++
		}
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return HostSummary{
		Host:           host,
		Score:          score,
		Grade:          ComputeGrade(score),
		Level:          computeLevel(score, counts),
		OpenPortsCount: openCount,
		Counts:         counts,
		Findings:       findings,
	}
}

// EvaluateScan aggregates host risk evaluations into a global posture summary.
func EvaluateScan(hosts []HostInput) ScanSummary {
	hostSummaries := make([]HostSummary, 0, len(hosts))
	allFindings := make([]Finding, 0)

	for _, h := range hosts {
		hs := EvaluateHost(h.Target, h.Observations)
		hostSummaries = append(hostSummaries, hs)
		allFindings = append(allFindings, hs.Findings...)
	}

	sort.Slice(allFindings, func(i, j int) bool {
		si, sj := severityOrder(allFindings[i].Severity), severityOrder(allFindings[j].Severity)
		if si != sj {
			return si < sj
		}
		if allFindings[i].Host != allFindings[j].Host {
			return allFindings[i].Host < allFindings[j].Host
		}
		return allFindings[i].Port < allFindings[j].Port
	})

	var counts SeverityCounts
	actionable := 0
	for _, f := range allFindings {
		switch f.Severity {
		case "critical":
			counts.Critical++
			actionable++
		case "high":
			counts.High++
			actionable++
		case "medium":
			counts.Medium++
			actionable++
		case "low":
			counts.Low++
			actionable++
		case "info":
			counts.Info++
		}
	}

	score := 100
	if len(hostSummaries) > 0 {
		worst := 100
		sum := 0
		for _, hs := range hostSummaries {
			if hs.Score < worst {
				worst = hs.Score
			}
			sum += hs.Score
		}
		avg := float64(sum) / float64(len(hostSummaries))
		score = int(math.Round(float64(worst)*0.7 + avg*0.3))
	}

	return ScanSummary{
		Score:              score,
		Grade:              ComputeGrade(score),
		Level:              computeLevel(score, counts),
		Counts:             counts,
		TotalFindings:      len(allFindings),
		ActionableFindings: actionable,
		Hosts:              hostSummaries,
		Findings:           allFindings,
	}
}
