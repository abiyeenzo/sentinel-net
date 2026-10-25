package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/baseline"
	"github.com/abiyeenzo/sentinel-net/internal/netscope"
	"github.com/abiyeenzo/sentinel-net/internal/osint"
	"github.com/abiyeenzo/sentinel-net/internal/profiles"
	"github.com/abiyeenzo/sentinel-net/internal/report"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
	"github.com/abiyeenzo/sentinel-net/internal/web"
)

// Version is set at compile time via -ldflags "-X github.com/abiyeenzo/sentinel-net/internal/cli.Version=...".
var Version = "1.2.0"

// IO encapsulates CLI streams and terminal capabilities for clean testing.
type IO struct {
	Stdout    io.Writer
	Stderr    io.Writer
	StdoutTTY bool
	StderrTTY bool
}

// DefaultIO inspects os.Stdout / os.Stderr to build an IO configuration.
func DefaultIO() IO {
	outTTY := false
	if fi, err := os.Stdout.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		outTTY = true
	}
	errTTY := false
	if fi, err := os.Stderr.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		errTTY = true
	}
	return IO{
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		StdoutTTY: outTTY,
		StderrTTY: errTTY,
	}
}

func helpText(bin string) string {
	return fmt.Sprintf(`Sentinel Net v%s - Audit reseau defensif, correlation CVE et reconnaissance OSINT

USAGE:
  %s [options] <cible1> [cible2 ...] -y
  %s osint <domaine-ou-ip> [--web -y] [-f table|json|markdown] [-o fichier]
  %s gui
  %s interfaces [--json]
  %s profiles [--json]
  %s diff <baseline.json> <courant.json> [--format <json|table|markdown>] [--fail-on-drift]
  %s serve [--host 127.0.0.1] [--port 3000]

RACCOURCIS RAPIDES (STYLE NMAP):
  <cible>                     IP (192.168.1.1, ::1), CIDR (192.168.1.0/24), plage ou nom d'hote (-R)
  -y, --authorized            Confirme l'autorisation explicite d'auditer les cibles (OBLIGATOIRE en scan actif)
  -F                          Scan rapide (profil quick : 18 ports critiques)
  -p <ports>                  Ports ou plages (ex: -p 22,80,443,8000-8050) ou -p- (ports 1-4096)
  --top-ports <N>             Scanne les N ports les plus courants (1 a 95)
  -P, --profile <nom>         Profil metier : quick | web | infra | database | containers | iot | top100
  -sV, --banner               Detection passive des services, versions et bannieres TCP
  -sC                         Audit non-intrusif des certificats TLS X.509 et en-tetes HTTP
  --vuln, --script=vuln       Correlation CVE passive avec scope de versions affectees et liens NVD/CVE.org
  --cve-online                Enrichissement CVE temps reel via l'API officielle NIST NVD v2.0 (CPE)
  --osint                     Enrichir le scan avec la reconnaissance OSINT (DNS, SPF/DMARC, CT crt.sh, RDAP, ASN)
  -A, -i, --inspect           Audit complet tout-en-un : versions (-sV) + TLS + HTTP + correlation CVE
  -T1 .. -T5                  Cadence d'execution : -T1 prudent, -T2 poli, -T3 normal, -T4 rapide, -T5 turbo
  -iL, --targets-file <f>     Lire la liste des cibles depuis un fichier texte
  -R, --resolve               Activer la resolution DNS des noms d'hotes (-n pour desactiver)
  --open                      Afficher uniquement les ports ouverts (alias --open-only)
  --nmap                      Afficher la sortie console au format classique Nmap

RECONNAISSANCE OSINT DEDIEE:
  %s osint <cible>            Collecte passive DNS (A/AAAA/MX/NS/TXT/SPF/DMARC), CT (crt.sh), RDAP et Geo/ASN
  --web                       Inspecter en plus /.well-known/security.txt, /robots.txt et technologies Web (requiert -y)

SORTIES ET RAPPORTS:
  -oN <fichier>               Enregistrer le rapport texte style Nmap (inclut |_ vulns: et liens CVE)
  -oJ <fichier>               Enregistrer le rapport JSON structure
  -oS <fichier>               Enregistrer le rapport SARIF 2.1.0 (regles de posture + CVE)
  -oM <fichier>               Enregistrer le rapport Markdown
  -oH, --report-html <f>      Generer un rapport HTML visuel autonome avec liens CVE cliquables
  -oA <prefixe>               Generer d'un coup <prefixe>.txt, .json, .html et .sarif
  -f, --format <fmt>          Format stdout : table | nmap | json | sarif | markdown | csv | html
  -o, --output <fichier>      Ecrire la sortie principale dans un fichier

SUIVI DE DERIVE (BASELINE) ET REGLES CI:
  --save-baseline <fichier>   Enregistrer un snapshot signe SHA-256
  --compare <fichier>         Comparer le scan courant avec une baseline existante
  --fail-on-drift             Retourner le code 3 si l'exposition a change
  --fail-on-severity <niv>    Retourner le code 3 si constat ou CVE >= critical | high | medium | low

REGLAGES MOTEUR AVANCES:
  --timeout <100-15000>       Timeout par sonde en ms (defaut: 1000)
  -c, --concurrency <1-128>   Sondes paralleles max (defaut: 24)
  --retries <0-3>             Nouvelles tentatives sur timeout (defaut: 0)
  --delay-ms <0-5000>         Pause entre sondes en ms (defaut: 0)
  --max-hosts <1-1024>        Plafond d'hotes analyses (defaut: 256)
  --max-ports <1-4096>        Plafond de ports par hote (defaut: 1024)
  --no-color                  Desactiver les couleurs ANSI
  -q, --quiet                 Masquer la progression sur stderr
  -V, --version               Afficher la version
  -h, --help                  Afficher cette aide

EXEMPLES SIMPLES:
  %s gui
  %s -F --vuln 127.0.0.1 -y
  %s osint exemple.com
  %s -A --osint -R exemple.com -y
  %s -sV --script=vuln -p 22,80,443,3306,5432 10.0.0.5 -oA audit-prod -y
`, Version, bin, bin, bin, bin, bin, bin, bin, bin, bin, bin, bin, bin, bin)
}

var valueFlags = map[string]string{
	"--target":           "target",
	"-t":                 "target",
	"--targets-file":     "targets-file",
	"-iL":                "targets-file",
	"--max-hosts":        "max-hosts",
	"--ports":            "ports",
	"-p":                 "ports",
	"--top-ports":        "top-ports",
	"--profile":          "profile",
	"-P":                 "profile",
	"--max-ports":        "max-ports",
	"-T":                 "timing",
	"--timing":           "timing",
	"--timeout":          "timeout",
	"--concurrency":      "concurrency",
	"-c":                 "concurrency",
	"--retries":          "retries",
	"--delay-ms":         "delay-ms",
	"--format":           "format",
	"-f":                 "format",
	"--output":           "output",
	"-o":                 "output",
	"-oN":                "out-nmap",
	"-oJ":                "out-json",
	"-oS":                "out-sarif",
	"-oM":                "out-md",
	"-oH":                "report-html",
	"--report-html":      "report-html",
	"-oA":                "out-all",
	"--save-baseline":    "save-baseline",
	"--compare":          "compare",
	"--fail-on-severity": "fail-on-severity",
	"--script":           "script",
	"--host":             "host",
	"--port":             "port",
}

var boolFlags = map[string]string{
	"--authorized":    "authorized",
	"-y":              "authorized",
	"-F":              "fast",
	"-sT":             "tcp-connect",
	"-Pn":             "skip-ping",
	"--resolve":       "resolve",
	"-R":              "resolve",
	"-n":              "no-resolve",
	"--inspect":       "inspect",
	"-i":              "inspect",
	"-A":              "inspect",
	"--banner":        "banner",
	"-sV":             "banner",
	"-sC":             "scripts",
	"--tls":           "tls",
	"--http":          "http",
	"--vuln":          "vuln",
	"--cve":           "vuln",
	"--cve-online":    "cve-online",
	"--osint":         "osint",
	"--web":           "web",
	"--json":          "json",
	"--nmap":          "nmap-fmt",
	"--open":          "open",
	"--open-only":     "open-only",
	"--fail-on-drift": "fail-on-drift",
	"--no-color":      "no-color",
	"--quiet":         "quiet",
	"-q":              "quiet",
	"--help":          "help",
	"-h":              "help",
	"--version":       "version",
	"-V":              "version",
	"-v":              "v-flag",
}

type timingPreset struct {
	concurrency int
	timeoutMs   int
	delayMs     int
	retries     int
}

var timingTemplates = map[string]timingPreset{
	"0":  {concurrency: 2, timeoutMs: 3000, delayMs: 300, retries: 1},
	"T0": {concurrency: 2, timeoutMs: 3000, delayMs: 300, retries: 1},
	"1":  {concurrency: 2, timeoutMs: 3000, delayMs: 250, retries: 1},
	"T1": {concurrency: 2, timeoutMs: 3000, delayMs: 250, retries: 1},
	"2":  {concurrency: 8, timeoutMs: 2000, delayMs: 60, retries: 1},
	"T2": {concurrency: 8, timeoutMs: 2000, delayMs: 60, retries: 1},
	"3":  {concurrency: 24, timeoutMs: 1000, delayMs: 0, retries: 0},
	"T3": {concurrency: 24, timeoutMs: 1000, delayMs: 0, retries: 0},
	"4":  {concurrency: 64, timeoutMs: 500, delayMs: 0, retries: 1},
	"T4": {concurrency: 64, timeoutMs: 500, delayMs: 0, retries: 1},
	"5":  {concurrency: 128, timeoutMs: 250, delayMs: 0, retries: 0},
	"T5": {concurrency: 128, timeoutMs: 250, delayMs: 0, retries: 0},
}

func parseArgs(args []string) (map[string]string, map[string]bool, []string, error) {
	vals := make(map[string]string)
	bools := make(map[string]bool)
	var pos []string

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		// Compact Nmap flags: -p-, -p22,80, -T0..-T5
		if tok == "-p-" {
			vals["ports"] = "1-4096"
			continue
		}
		if strings.HasPrefix(tok, "-p") && len(tok) > 2 && !strings.HasPrefix(tok, "--") {
			vals["ports"] = tok[2:]
			continue
		}
		if len(tok) == 3 && strings.HasPrefix(tok, "-T") && tok[2] >= '0' && tok[2] <= '5' {
			vals["timing"] = tok[1:]
			continue
		}

		if strings.HasPrefix(tok, "-") && tok != "-" {
			key := tok
			inlineVal := ""
			hasInline := false
			if eq := strings.IndexByte(tok, '='); eq >= 0 {
				key = tok[:eq]
				inlineVal = tok[eq+1:]
				hasInline = true
			}
			if canonical, ok := boolFlags[key]; ok {
				if hasInline {
					bools[canonical] = inlineVal != "false" && inlineVal != "0"
				} else {
					bools[canonical] = true
				}
				continue
			}
			if canonical, ok := valueFlags[key]; ok {
				val := inlineVal
				if !hasInline {
					if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "--") && args[i+1] != "-") {
						return nil, nil, nil, fmt.Errorf("missing value for %s", key)
					}
					i++
					val = args[i]
				}
				vals[canonical] = val
				continue
			}
			return nil, nil, nil, fmt.Errorf("unknown option %q (run with --help for usage)", key)
		}
		pos = append(pos, tok)
	}
	return vals, bools, pos, nil
}

func looksLikeTargetToken(s string) bool {
	if s == "" {
		return false
	}
	if strings.EqualFold(s, "localhost") {
		return true
	}
	return strings.ContainsAny(s, ".:/")
}

func parseIntOpt(vals map[string]string, name string, def int) (int, error) {
	raw, ok := vals[name]
	if !ok || raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("option --%s expects an integer, got %q", name, raw)
	}
	return n, nil
}

func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func checkPolicyGate(rep *scanner.Report, failSeverity string, failOnDrift bool) (string, error) {
	if failOnDrift && rep.Drift != nil {
		if d, ok := rep.Drift.(baseline.DriftReport); ok && d.HasDrift {
			return "baseline drift detected (--fail-on-drift)", nil
		}
	}
	if failSeverity != "" {
		rank := severityRank(failSeverity)
		if rank == 0 {
			return "", errors.New("invalid --fail-on-severity value (expected: critical, high, medium, low)")
		}
		matched := 0
		for _, f := range rep.Risk.Findings {
			if severityRank(f.Severity) >= rank {
				matched++
			}
		}
		for _, v := range rep.Vulnerabilities {
			if severityRank(v.Severity) >= rank {
				matched++
			}
		}
		if matched > 0 {
			return fmt.Sprintf("%d finding(s)/CVE(s) met or exceeded severity %q", matched, failSeverity), nil
		}
	}
	return "", nil
}

// Run executes the CLI command and returns a POSIX process exit code.
func Run(ctx context.Context, argv []string, ioCfg IO) int {
	code, err := runInner(ctx, argv, ioCfg)
	if err != nil {
		_, _ = fmt.Fprintf(ioCfg.Stderr, "Error: %s\n", err.Error())
		if errors.Is(err, scanner.ErrCancelled) || errors.Is(err, context.Canceled) {
			return 130
		}
		return 2
	}
	return code
}

func runInner(parentCtx context.Context, argv []string, ioCfg IO) (int, error) {
	bin := "sentinel-net"
	if len(os.Args) > 0 && os.Args[0] != "" {
		base := filepath.Base(os.Args[0])
		if strings.HasPrefix(strings.ToLower(base), "sentinel-net") {
			bin = base
		}
	}

	if len(argv) == 0 {
		if isStandaloneDesktopLaunch(ioCfg) {
			argv = []string{"gui"}
		} else {
			return 2, fmt.Errorf("explicit target and authorization required (ex: %s -F 127.0.0.1 -y, %s gui, or --help)", bin, bin)
		}
	}

	vals, bools, pos, err := parseArgs(argv)
	if err != nil {
		return 2, err
	}

	if bools["help"] {
		_, _ = io.WriteString(ioCfg.Stdout, helpText(bin))
		return 0, nil
	}
	// -V / --version always prints version; -v prints version when used standalone with no target/subcommand
	if bools["version"] || (bools["v-flag"] && len(pos) == 0 && vals["target"] == "" && vals["targets-file"] == "") {
		_, _ = fmt.Fprintf(ioCfg.Stdout, "sentinel-net v%s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0, nil
	}

	ctx, stopSignals := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	sub := "scan"
	var posTargets []string
	if len(pos) > 0 {
		cand := strings.ToLower(pos[0])
		switch cand {
		case "scan":
			sub = "scan"
			posTargets = pos[1:]
		case "osint", "recon":
			sub = "osint"
			posTargets = pos[1:]
		case "interfaces", "profiles", "diff", "serve", "ui", "gui":
			sub = cand
		default:
			if looksLikeTargetToken(pos[0]) {
				sub = "scan"
				posTargets = pos
			} else {
				return 2, fmt.Errorf("unknown command %q (expected target IP/CIDR or command: scan, osint, gui, interfaces, profiles, diff, serve)", pos[0])
			}
		}
	}

	useColor := ioCfg.StdoutTTY && !bools["no-color"] && os.Getenv("NO_COLOR") == ""

	switch sub {
	case "osint":
		target := vals["target"]
		if target == "" && len(posTargets) > 0 {
			target = posTargets[0]
		}
		if target == "" {
			return 2, fmt.Errorf("usage: %s osint <domaine-ou-ip> [--web -y] [-f table|json|markdown]", bin)
		}
		if bools["web"] && !bools["authorized"] && target != "127.0.0.1" && target != "::1" && !strings.EqualFold(target, "localhost") {
			return 2, errors.New("option --web connects directly to the target web server: pass -y (--authorized) to confirm permission")
		}
		timeoutMs, err := parseIntOpt(vals, "timeout", 6000)
		if err != nil {
			return 2, err
		}
		oRep, err := osint.Run(ctx, target, osint.Options{
			Timeout:   time.Duration(timeoutMs) * time.Millisecond,
			ActiveWeb: bools["web"],
		})
		if err != nil {
			return 2, err
		}
		fmtName := vals["format"]
		if bools["json"] {
			fmtName = "json"
		} else if fmtName == "" {
			if ioCfg.StdoutTTY {
				fmtName = "table"
			} else {
				fmtName = "json"
			}
		}
		rendered, err := report.FormatOSINT(oRep, report.Options{
			Format: fmtName,
			Color:  useColor,
		})
		if err != nil {
			return 2, err
		}
		if vals["output"] != "" {
			if err := os.WriteFile(vals["output"], []byte(rendered), 0o644); err != nil {
				return 2, err
			}
		} else {
			_, _ = io.WriteString(ioCfg.Stdout, rendered)
		}
		return 0, nil

	case "interfaces":
		ifaces, err := netscope.ListLocalInterfaces()
		if err != nil {
			return 2, err
		}
		if bools["json"] || vals["format"] == "json" || !ioCfg.StdoutTTY {
			raw, _ := json.MarshalIndent(map[string]any{"interfaces": ifaces}, "", "  ")
			_, _ = fmt.Fprintf(ioCfg.Stdout, "%s\n", string(raw))
		} else {
			_, _ = fmt.Fprintf(ioCfg.Stdout, "Interfaces reseau locales (%d) :\n", len(ifaces))
			for _, nic := range ifaces {
				addrDisp := nic.CIDR
				if addrDisp == "" {
					addrDisp = nic.Address
				}
				loopTag := ""
				if nic.Internal {
					loopTag = " (loopback)"
				}
				_, _ = fmt.Fprintf(ioCfg.Stdout, "  - %-12s %-5s %-24s scope=%s%s\n", nic.Interface, nic.Family, addrDisp, nic.Scope, loopTag)
			}
		}
		return 0, nil

	case "profiles":
		all := profiles.All()
		if bools["json"] || vals["format"] == "json" || !ioCfg.StdoutTTY {
			raw, _ := json.MarshalIndent(map[string]any{"profiles": all}, "", "  ")
			_, _ = fmt.Fprintf(ioCfg.Stdout, "%s\n", string(raw))
		} else {
			_, _ = fmt.Fprintf(ioCfg.Stdout, "Profils de ports integres (%d) :\n", len(all))
			for _, p := range all {
				_, _ = fmt.Fprintf(ioCfg.Stdout, "  - %-12s (%3d ports) : %s\n", p.ID, len(p.Ports), p.Description)
			}
		}
		return 0, nil

	case "diff":
		if len(pos) < 3 {
			return 2, fmt.Errorf("usage: %s diff <baseline.json> <current.json>", bin)
		}
		baseSnap, err := baseline.LoadFile(pos[1], false)
		if err != nil {
			return 2, err
		}
		currSnap, err := baseline.LoadFile(pos[2], false)
		if err != nil {
			return 2, err
		}
		drift := baseline.Compare(&baseSnap.Report, &currSnap.Report)
		fmtName := vals["format"]
		if bools["json"] || fmtName == "" {
			fmtName = "json"
		}
		if fmtName == "json" {
			raw, _ := json.MarshalIndent(drift, "", "  ")
			_, _ = fmt.Fprintf(ioCfg.Stdout, "%s\n", string(raw))
		} else {
			currSnap.Report.Drift = drift
			rendered, err := report.Format(&currSnap.Report, report.Options{Format: fmtName, Color: useColor})
			if err != nil {
				return 2, err
			}
			_, _ = io.WriteString(ioCfg.Stdout, rendered)
		}
		if bools["fail-on-drift"] && drift.HasDrift {
			_, _ = io.WriteString(ioCfg.Stderr, "Policy gate failed: baseline drift detected.\n")
			return 3, nil
		}
		return 0, nil

	case "serve", "ui", "gui":
		isDesktop := sub == "gui"
		autoOpen := isDesktop || bools["open"]
		if isDesktop {
			hideConsoleWindow()
		}

		host := vals["host"]
		if host == "" {
			host = os.Getenv("HOST")
		}
		if host == "" {
			host = "127.0.0.1"
		}
		explicitPort := false
		portNum := 3000
		if isDesktop && vals["port"] == "" && os.Getenv("PORT") == "" {
			portNum = 0 // Ephemeral conflict-free port for standalone desktop GUI
		}
		if vals["port"] != "" {
			p, err := strconv.Atoi(vals["port"])
			if err != nil || p < 0 || p > 65535 {
				return 2, fmt.Errorf("invalid --port value %q", vals["port"])
			}
			portNum = p
			explicitPort = true
		} else if envPort := os.Getenv("PORT"); envPort != "" {
			if p, err := strconv.Atoi(envPort); err == nil && p >= 0 && p <= 65535 {
				portNum = p
				explicitPort = true
			}
		}

		listenAddr := net.JoinHostPort(host, strconv.Itoa(portNum))
		srv, err := web.StartWithOptions(listenAddr, Version, isDesktop)
		if err != nil && autoOpen && !explicitPort {
			srv, err = web.StartWithOptions(net.JoinHostPort(host, "0"), Version, isDesktop)
		}
		if err != nil {
			return 2, err
		}

		_, actualPort, _ := net.SplitHostPort(srv.Addr())
		browseHost := host
		if browseHost == "" || browseHost == "0.0.0.0" || browseHost == "::" {
			browseHost = "127.0.0.1"
		}
		consoleURL := "http://" + net.JoinHostPort(browseHost, actualPort)
		_, _ = fmt.Fprintf(ioCfg.Stdout, "Sentinel Net v%s web console listening on http://%s\n", Version, srv.Addr())

		var waitWindow func()
		if autoOpen {
			waitWindow, _ = launchDesktopWindow(ctx, consoleURL)
		}

		if waitWindow != nil {
			winClosed := make(chan struct{})
			go func() {
				waitWindow()
				close(winClosed)
			}()
			select {
			case <-ctx.Done():
			case <-winClosed:
			case <-srv.Done():
			}
		} else {
			select {
			case <-ctx.Done():
			case <-srv.Done():
			}
		}

		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Close(shutCtx)
		return 0, nil
	}

	// Scan execution path
	if !bools["authorized"] {
		return 2, errors.New("explicit authorization required: pass -y (or --authorized) only for assets you are permitted to scan")
	}

	var targetTokens []string
	if vals["target"] != "" {
		targetTokens = append(targetTokens, vals["target"])
	}
	targetTokens = append(targetTokens, posTargets...)
	if vals["targets-file"] != "" {
		content, err := os.ReadFile(vals["targets-file"])
		if err != nil {
			return 2, err
		}
		for _, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			targetTokens = append(targetTokens, trimmed)
		}
	}
	if len(targetTokens) == 0 {
		return 2, errors.New("missing target (ex: sentinel-net -F 127.0.0.1 -y)")
	}

	// Timing template defaults (-T0 .. -T5)
	defConc := 24
	defTimeout := 1000
	defDelay := 0
	defRetries := 0
	if rawT := strings.ToUpper(strings.TrimSpace(vals["timing"])); rawT != "" {
		preset, ok := timingTemplates[rawT]
		if !ok {
			return 2, fmt.Errorf("invalid timing template %q (expected -T0 to -T5)", vals["timing"])
		}
		defConc = preset.concurrency
		defTimeout = preset.timeoutMs
		defDelay = preset.delayMs
		defRetries = preset.retries
	}

	maxHosts, err := parseIntOpt(vals, "max-hosts", netscope.DefaultMaxHosts)
	if err != nil {
		return 2, err
	}
	defMaxPorts := netscope.DefaultMaxPorts
	if vals["ports"] == "1-4096" || vals["ports"] == "-" {
		vals["ports"] = "1-4096"
		defMaxPorts = netscope.HardMaxPorts
	}
	maxPorts, err := parseIntOpt(vals, "max-ports", defMaxPorts)
	if err != nil {
		return 2, err
	}
	timeoutMs, err := parseIntOpt(vals, "timeout", defTimeout)
	if err != nil {
		return 2, err
	}
	concurrency, err := parseIntOpt(vals, "concurrency", defConc)
	if err != nil {
		return 2, err
	}
	retries, err := parseIntOpt(vals, "retries", defRetries)
	if err != nil {
		return 2, err
	}
	delayMs, err := parseIntOpt(vals, "delay-ms", defDelay)
	if err != nil {
		return 2, err
	}

	scriptSpec := strings.ToLower(vals["script"])
	enableVuln := bools["vuln"] || bools["cve-online"] || strings.Contains(scriptSpec, "vuln") || strings.Contains(scriptSpec, "cve") || strings.Contains(scriptSpec, "default")
	enableOSINT := bools["osint"] || strings.Contains(scriptSpec, "osint") || strings.Contains(scriptSpec, "asn") || strings.Contains(scriptSpec, "whois")
	enableTLS := bools["tls"] || bools["scripts"] || strings.Contains(scriptSpec, "default") || strings.Contains(scriptSpec, "ssl")
	enableHTTP := bools["http"] || bools["scripts"] || strings.Contains(scriptSpec, "default") || strings.Contains(scriptSpec, "http")

	enableDNS := (bools["resolve"] || enableOSINT) && !bools["no-resolve"]
	resolvedTargets, err := netscope.ResolveTargets(ctx, strings.Join(targetTokens, ","), netscope.ResolveOptions{
		ResolveDNS: enableDNS,
		MaxHosts:   maxHosts,
	})
	if err != nil {
		return 2, err
	}

	profileName := vals["profile"]
	portsSpec := vals["ports"]
	if vals["top-ports"] != "" {
		topN, err := strconv.Atoi(vals["top-ports"])
		pTop, _ := profiles.Get("top100")
		if err != nil || topN < 1 || topN > len(pTop.Ports) {
			return 2, fmt.Errorf("--top-ports expects an integer between 1 and %d", len(pTop.Ports))
		}
		strs := make([]string, topN)
		for idx := 0; idx < topN; idx++ {
			strs[idx] = strconv.Itoa(pTop.Ports[idx])
		}
		portsSpec = strings.Join(strs, ",")
	} else if portsSpec == "" && profileName == "" {
		if bools["fast"] {
			profileName = "quick"
		} else {
			profileName = "top100"
		}
	}

	selectedPorts, err := netscope.ResolvePortSelection(portsSpec, profileName, maxPorts)
	if err != nil {
		return 2, err
	}

	showProgress := (ioCfg.StderrTTY || bools["v-flag"]) && !bools["quiet"]
	var progressCb func(scanner.ProgressEvent)
	if showProgress && ioCfg.StderrTTY {
		progressCb = func(ev scanner.ProgressEvent) {
			_, _ = fmt.Fprintf(ioCfg.Stderr, "\r[sentinel-net] %d/%d (%.1f%%) - %s:%d   ",
				ev.GlobalCompleted, ev.GlobalTotal, ev.Percent, ev.Target, ev.Port)
		}
	}

	rep, err := scanner.ScanNetwork(ctx, scanner.NetworkOptions{
		Targets:     resolvedTargets,
		Ports:       selectedPorts,
		Profile:     profileName,
		Version:     Version,
		Timeout:     time.Duration(timeoutMs) * time.Millisecond,
		Concurrency: concurrency,
		Retries:     retries,
		Delay:       time.Duration(delayMs) * time.Millisecond,
		Inspect:     bools["inspect"],
		Banner:      bools["banner"],
		TLS:         enableTLS,
		HTTP:        enableHTTP,
		Vuln:        enableVuln,
		CVEOnline:   bools["cve-online"],
		OSINT:       enableOSINT,
		OnProgress:  progressCb,
	})
	if showProgress && ioCfg.StderrTTY {
		_, _ = fmt.Fprintf(ioCfg.Stderr, "\r%s\r", strings.Repeat(" ", 78))
	}
	if err != nil {
		return 2, err
	}

	if vals["compare"] != "" {
		baseSnap, err := baseline.LoadFile(vals["compare"], false)
		if err != nil {
			return 2, err
		}
		rep.Drift = baseline.Compare(&baseSnap.Report, rep)
	}

	if vals["save-baseline"] != "" {
		if _, err := baseline.SaveFile(vals["save-baseline"], rep); err != nil {
			return 2, err
		}
	}

	openOnly := bools["open-only"] || bools["open"]

	// Nmap multi-output flags (-oN, -oJ, -oS, -oM, -oH, -oA)
	if prefix := vals["out-all"]; prefix != "" {
		nmapOut := report.FormatNmap(rep, openOnly)
		if err := os.WriteFile(prefix+".txt", []byte(nmapOut), 0o644); err != nil {
			return 2, err
		}
		jsonOut, err := report.FormatJSON(rep)
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(prefix+".json", []byte(jsonOut), 0o644); err != nil {
			return 2, err
		}
		htmlOut := report.FormatHTML(rep)
		if err := os.WriteFile(prefix+".html", []byte(htmlOut), 0o644); err != nil {
			return 2, err
		}
		sarifOut, err := report.FormatSARIF(rep)
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(prefix+".sarif", []byte(sarifOut), 0o644); err != nil {
			return 2, err
		}
	}
	if vals["out-nmap"] != "" {
		if err := os.WriteFile(vals["out-nmap"], []byte(report.FormatNmap(rep, openOnly)), 0o644); err != nil {
			return 2, err
		}
	}
	if vals["out-json"] != "" {
		j, err := report.FormatJSON(rep)
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(vals["out-json"], []byte(j), 0o644); err != nil {
			return 2, err
		}
	}
	if vals["out-sarif"] != "" {
		s, err := report.FormatSARIF(rep)
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(vals["out-sarif"], []byte(s), 0o644); err != nil {
			return 2, err
		}
	}
	if vals["out-md"] != "" {
		if err := os.WriteFile(vals["out-md"], []byte(report.FormatMarkdown(rep)), 0o644); err != nil {
			return 2, err
		}
	}
	if vals["report-html"] != "" {
		htmlOut := report.FormatHTML(rep)
		if err := os.WriteFile(vals["report-html"], []byte(htmlOut), 0o644); err != nil {
			return 2, err
		}
	}

	fmtName := vals["format"]
	if bools["json"] {
		fmtName = "json"
	} else if bools["nmap-fmt"] {
		fmtName = "nmap"
	} else if fmtName == "" {
		if ioCfg.StdoutTTY {
			fmtName = "table"
		} else {
			fmtName = "json"
		}
	}

	rendered, err := report.Format(rep, report.Options{
		Format:   fmtName,
		Color:    useColor,
		OpenOnly: openOnly,
	})
	if err != nil {
		return 2, err
	}

	if vals["output"] != "" {
		if err := os.WriteFile(vals["output"], []byte(rendered), 0o644); err != nil {
			return 2, err
		}
	} else {
		_, _ = io.WriteString(ioCfg.Stdout, rendered)
	}

	gateMsg, err := checkPolicyGate(rep, vals["fail-on-severity"], bools["fail-on-drift"])
	if err != nil {
		return 2, err
	}
	if gateMsg != "" {
		_, _ = fmt.Fprintf(ioCfg.Stderr, "Policy gate failed: %s\n", gateMsg)
		return 3, nil
	}

	return 0, nil
}
