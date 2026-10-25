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
	"github.com/abiyeenzo/sentinel-net/internal/profiles"
	"github.com/abiyeenzo/sentinel-net/internal/report"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
	"github.com/abiyeenzo/sentinel-net/internal/web"
)

// Version is set at compile time via -ldflags "-X github.com/abiyeenzo/sentinel-net/internal/cli.Version=...".
var Version = "1.0.0"

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
	return fmt.Sprintf(`Sentinel Net v%s - Scanner d'audit reseau defensif

USAGE:
  %s [scan] --target <ip|cidr|plage> (--ports <spec> | --profile <nom>) --authorized [options]
  %s interfaces [--json]
  %s profiles [--json]
  %s diff <baseline.json> <courant.json> [--format <json|table|markdown>] [--fail-on-drift]
  %s serve [--host 127.0.0.1] [--port 3000] [--open]
  %s gui

COMMANDES:
  scan          Audit d'exposition TCP/TLS/HTTP borne (commande par defaut)
  interfaces    Liste les interfaces reseau locales et leurs adresses IPv4/IPv6
  profiles      Liste les profils de ports integres (quick, web, infra, database, containers, iot, top100)
  diff          Compare deux fichiers JSON de scan et affiche les derives
  serve (ui)    Demarre la console Web locale d'audit
  gui           Demarre la console Web locale et ouvre le navigateur par defaut

OPTIONS DE CIBLAGE ET PORTS:
  --target, -t <cibles>       IP litterale (IPv4/IPv6), CIDR (/22-/32) ou plage (ex: 192.168.1.1-50)
  --targets-file <fichier>    Fichier texte contenant une cible par ligne (# commentaires ignores)
  --resolve                   Autorise la resolution DNS explicite des noms d'hotes
  --max-hosts <1-1024>        Plafond du nombre d'hotes analyses (defaut: 256)
  --ports, -p <spec>          Ports et plages separes par virgules (ex: 22,80,443,8000-8020)
  --profile <nom>             Profil predefini: quick | web | infra | database | containers | iot | top100
  --max-ports <1-4096>        Plafond de ports uniques par hote (defaut: 1024)
  --authorized                OBLIGATOIRE: confirme l'autorisation explicite d'analyser les cibles

OPTIONS MOTEUR ET INSPECTION:
  --inspect, -i               Active l'inspection complete non-intrusive (banniere + TLS + HTTP)
  --banner                    Lecture passive de la banniere TCP initiale
  --tls                       Audit du handshake TLS et du certificat X.509
  --http                      Audit des en-tetes de securite HTTP/HTTPS (requete HEAD /)
  --timeout <100-15000>       Delai d'attente par sonde en ms (defaut: 1000)
  --concurrency, -c <1-128>   Nombre maximal de sondes simultanees (defaut: 24)
  --retries <0-3>             Nouvelles tentatives en cas de timeout (defaut: 0)
  --delay-ms <0-5000>         Pause en ms entre sondes pour equipements sensibles (defaut: 0)

RAPPORTS, BASELINE ET REGLES CI:
  --format, -f <fmt>          Format de sortie: table | json | sarif | markdown | csv | html
  --json                      Alias pour --format json
  --open-only                 Affiche uniquement les ports ouverts dans le mode table
  --output, -o <fichier>      Ecrit le rapport principal dans un fichier
  --report-html <fichier>     Genere en parallele un rapport HTML autonome
  --save-baseline <fichier>   Enregistre le scan courant en baseline signee SHA-256
  --compare <fichier>         Compare le scan courant a une baseline existante
  --fail-on-drift             Retourne le code 3 si une derive est detectee
  --fail-on-severity <niv>    Retourne le code 3 si constat >= critical | high | medium | low
  --no-color                  Desactive les couleurs ANSI
  --quiet, -q                 Masque la progression sur stderr
  --help, -h                  Affiche cette aide
  --version, -v               Affiche la version

EXEMPLES:
  %s --target 127.0.0.1 --profile quick --inspect --authorized
  %s scan -t 192.168.1.0/24 -p 22,80,443,3389 --tls --http --authorized --report-html audit.html
  %s scan -t 10.0.0.5 --profile database --authorized --format sarif -o findings.sarif
  %s serve --port 3000
`, Version, bin, bin, bin, bin, bin, bin, bin, bin, bin, bin)
}

var valueFlags = map[string]string{
	"--target":           "target",
	"-t":                 "target",
	"--targets-file":     "targets-file",
	"--max-hosts":        "max-hosts",
	"--ports":            "ports",
	"-p":                 "ports",
	"--profile":          "profile",
	"--max-ports":        "max-ports",
	"--timeout":          "timeout",
	"--concurrency":      "concurrency",
	"-c":                 "concurrency",
	"--retries":          "retries",
	"--delay-ms":         "delay-ms",
	"--format":           "format",
	"-f":                 "format",
	"--output":           "output",
	"-o":                 "output",
	"--report-html":      "report-html",
	"--save-baseline":    "save-baseline",
	"--compare":          "compare",
	"--fail-on-severity": "fail-on-severity",
	"--host":             "host",
	"--port":             "port",
}

var boolFlags = map[string]string{
	"--authorized":    "authorized",
	"--resolve":       "resolve",
	"--inspect":       "inspect",
	"-i":              "inspect",
	"--banner":        "banner",
	"--tls":           "tls",
	"--http":          "http",
	"--json":          "json",
	"--open-only":     "open-only",
	"--fail-on-drift": "fail-on-drift",
	"--no-color":      "no-color",
	"--open":          "open",
	"--quiet":         "quiet",
	"-q":              "quiet",
	"--help":          "help",
	"-h":              "help",
	"--version":       "version",
	"-v":              "version",
}

func parseArgs(args []string) (map[string]string, map[string]bool, []string, error) {
	vals := make(map[string]string)
	bools := make(map[string]bool)
	var pos []string

	for i := 0; i < len(args); i++ {
		tok := args[i]
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
					if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
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
		if matched > 0 {
			return fmt.Sprintf("%d finding(s) met or exceeded severity %q", matched, failSeverity), nil
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
			return 2, fmt.Errorf("explicit target and authorization required (run %q --help for usage)", bin)
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
	if bools["version"] {
		_, _ = fmt.Fprintf(ioCfg.Stdout, "sentinel-net v%s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0, nil
	}

	ctx, stopSignals := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	sub := "scan"
	if len(pos) > 0 {
		sub = strings.ToLower(pos[0])
	}
	useColor := ioCfg.StdoutTTY && !bools["no-color"] && os.Getenv("NO_COLOR") == ""

	switch sub {
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
		host := vals["host"]
		if host == "" {
			host = os.Getenv("HOST")
		}
		if host == "" {
			host = "127.0.0.1"
		}
		explicitPort := false
		portNum := 3000
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
		autoOpen := sub == "gui" || bools["open"]
		listenAddr := net.JoinHostPort(host, strconv.Itoa(portNum))
		srv, err := web.Start(listenAddr, Version)
		if err != nil && autoOpen && !explicitPort {
			srv, err = web.Start(net.JoinHostPort(host, "0"), Version)
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
		if autoOpen {
			_, _ = fmt.Fprintf(ioCfg.Stdout, "Ouverture automatique dans le navigateur : %s (Ctrl+C pour quitter)\n", consoleURL)
			_ = openBrowser(consoleURL)
		}
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Close(shutCtx)
		return 0, nil

	case "scan":
		// Handled below
	default:
		return 2, fmt.Errorf("unknown command %q (expected: scan, interfaces, profiles, diff, serve, gui)", pos[0])
	}

	if !bools["authorized"] {
		return 2, errors.New("explicit authorization required: pass --authorized only for assets you are permitted to scan")
	}

	var targetTokens []string
	if vals["target"] != "" {
		targetTokens = append(targetTokens, vals["target"])
	}
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
		return 2, errors.New("missing value for --target (or --targets-file)")
	}

	maxHosts, err := parseIntOpt(vals, "max-hosts", netscope.DefaultMaxHosts)
	if err != nil {
		return 2, err
	}
	maxPorts, err := parseIntOpt(vals, "max-ports", netscope.DefaultMaxPorts)
	if err != nil {
		return 2, err
	}
	timeoutMs, err := parseIntOpt(vals, "timeout", 1000)
	if err != nil {
		return 2, err
	}
	concurrency, err := parseIntOpt(vals, "concurrency", 24)
	if err != nil {
		return 2, err
	}
	retries, err := parseIntOpt(vals, "retries", 0)
	if err != nil {
		return 2, err
	}
	delayMs, err := parseIntOpt(vals, "delay-ms", 0)
	if err != nil {
		return 2, err
	}

	resolvedTargets, err := netscope.ResolveTargets(ctx, strings.Join(targetTokens, ","), netscope.ResolveOptions{
		ResolveDNS: bools["resolve"],
		MaxHosts:   maxHosts,
	})
	if err != nil {
		return 2, err
	}

	selectedPorts, err := netscope.ResolvePortSelection(vals["ports"], vals["profile"], maxPorts)
	if err != nil {
		return 2, err
	}

	showProgress := ioCfg.StderrTTY && !bools["quiet"]
	var progressCb func(scanner.ProgressEvent)
	if showProgress {
		progressCb = func(ev scanner.ProgressEvent) {
			_, _ = fmt.Fprintf(ioCfg.Stderr, "\r[sentinel-net] %d/%d (%.1f%%) - %s:%d   ",
				ev.GlobalCompleted, ev.GlobalTotal, ev.Percent, ev.Target, ev.Port)
		}
	}

	rep, err := scanner.ScanNetwork(ctx, scanner.NetworkOptions{
		Targets:     resolvedTargets,
		Ports:       selectedPorts,
		Profile:     vals["profile"],
		Version:     Version,
		Timeout:     time.Duration(timeoutMs) * time.Millisecond,
		Concurrency: concurrency,
		Retries:     retries,
		Delay:       time.Duration(delayMs) * time.Millisecond,
		Inspect:     bools["inspect"],
		Banner:      bools["banner"],
		TLS:         bools["tls"],
		HTTP:        bools["http"],
		OnProgress:  progressCb,
	})
	if showProgress {
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

	if vals["report-html"] != "" {
		htmlOut := report.FormatHTML(rep)
		if err := os.WriteFile(vals["report-html"], []byte(htmlOut), 0o644); err != nil {
			return 2, err
		}
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

	rendered, err := report.Format(rep, report.Options{
		Format:   fmtName,
		Color:    useColor,
		OpenOnly: bools["open-only"],
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
