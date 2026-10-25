package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"

	"github.com/abiyeenzo/sentinel-net/internal/baseline"
	"github.com/abiyeenzo/sentinel-net/internal/risk"
	"github.com/abiyeenzo/sentinel-net/internal/scanner"
)

// Options controls report output rendering.
type Options struct {
	Format   string
	Color    bool
	OpenOnly bool
}

type ansiPalette struct {
	enabled bool
}

func (p ansiPalette) wrap(code, s string) string {
	if !p.enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p ansiPalette) bold(s string) string   { return p.wrap("1", s) }
func (p ansiPalette) dim(s string) string    { return p.wrap("2", s) }
func (p ansiPalette) cyan(s string) string   { return p.wrap("36", s) }
func (p ansiPalette) green(s string) string  { return p.wrap("32", s) }
func (p ansiPalette) yellow(s string) string { return p.wrap("33", s) }
func (p ansiPalette) red(s string) string    { return p.wrap("31", s) }
func (p ansiPalette) blue(s string) string   { return p.wrap("34", s) }

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func summarizeObservation(obs scanner.Observation) string {
	var parts []string
	if obs.Service.Product != "" {
		parts = append(parts, obs.Service.Product)
	}
	if insp := obs.Inspection; insp != nil {
		if insp.TLS != nil && insp.TLS.Established {
			note := insp.TLS.Protocol
			if cert := insp.TLS.Certificate; cert != nil {
				if cert.Expired {
					note += " (cert expired)"
				} else {
					note += fmt.Sprintf(" (exp:%dd)", cert.DaysRemaining)
				}
				if cert.SelfSigned {
					note += " [self-signed]"
				}
			}
			parts = append(parts, note)
		}
		if insp.HTTP != nil && insp.HTTP.StatusCode > 0 {
			missing := len(insp.HTTP.MissingSecurityHeaders)
			if missing > 0 {
				parts = append(parts, fmt.Sprintf("HTTP %d (-%d sec-hdr)", insp.HTTP.StatusCode, missing))
			} else {
				parts = append(parts, fmt.Sprintf("HTTP %d (headers ok)", insp.HTTP.StatusCode))
			}
		}
		if insp.Banner != "" && obs.Service.Product == "" {
			b := insp.Banner
			if len(b) > 64 {
				b = b[:64] + "..."
			}
			parts = append(parts, b)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, " | ")
	}
	return obs.Service.Description
}

func extractDrift(rep *scanner.Report) *baseline.DriftReport {
	if rep == nil || rep.Drift == nil {
		return nil
	}
	switch v := rep.Drift.(type) {
	case baseline.DriftReport:
		return &v
	case *baseline.DriftReport:
		return v
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var d baseline.DriftReport
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil
		}
		return &d
	}
}

// FormatTable renders a sober, aligned CLI audit summary.
func FormatTable(rep *scanner.Report, color, openOnly bool) string {
	c := ansiPalette{enabled: color}
	var b strings.Builder

	s := rep.Summary
	r := rep.Risk
	sep := strings.Repeat("-", 84)

	gradeStr := fmt.Sprintf("%s (%d/100)", r.Grade, r.Score)
	switch {
	case r.Score >= 88:
		gradeStr = c.green(c.bold(gradeStr))
	case r.Score >= 60:
		gradeStr = c.yellow(c.bold(gradeStr))
	default:
		gradeStr = c.red(c.bold(gradeStr))
	}

	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s v%s - Rapport d'audit reseau\n", c.bold("SENTINEL NET"), rep.Tool.Version))
	b.WriteString(c.dim(sep) + "\n")
	b.WriteString(fmt.Sprintf(
		"%s %s   %s %d/%d actifs   %s %d (%s, %s, %s)   %s %.2f ms\n",
		c.bold("Posture:"), gradeStr,
		c.bold("Hotes:"), s.HostsWithOpenPorts, s.HostsScanned,
		c.bold("Sondes:"), s.TotalProbes,
		c.green(fmt.Sprintf("%d open", s.OpenPorts)),
		c.yellow(fmt.Sprintf("%d closed", s.ClosedPorts)),
		c.dim(fmt.Sprintf("%d unknown", s.UnknownPorts)),
		c.bold("Duree:"), s.DurationMs,
	))
	if s.Latency.SampleCount > 0 && s.Latency.MinMs != nil && s.Latency.AvgMs != nil && s.Latency.P95Ms != nil && s.Latency.MaxMs != nil {
		b.WriteString(fmt.Sprintf(
			"%s min %.2f ms | moy %.2f ms | p95 %.2f ms | max %.2f ms\n",
			c.bold("Latence RTT:"), *s.Latency.MinMs, *s.Latency.AvgMs, *s.Latency.P95Ms, *s.Latency.MaxMs,
		))
	}
	b.WriteString(c.dim(sep) + "\n")

	for _, h := range rep.Hosts {
		targetLabel := h.Target
		if h.Hostname != "" {
			targetLabel = fmt.Sprintf("%s (%s)", h.Target, h.Hostname)
		}
		hGrade := fmt.Sprintf("%s (%d/100)", h.Risk.Grade, h.Risk.Score)
		b.WriteString(fmt.Sprintf(
			"\nCible: %s [%s] | Posture: %s | %d/%d port(s) ouvert(s) en %.2f ms\n",
			c.cyan(c.bold(targetLabel)), h.Scope, hGrade, h.Counts.Open, h.Counts.Total, h.DurationMs,
		))

		var rows []scanner.Observation
		for _, o := range h.Observations {
			if openOnly && o.State != "open" {
				continue
			}
			rows = append(rows, o)
		}
		if len(rows) == 0 {
			b.WriteString("  Aucun port ouvert sur cette cible.\n")
			continue
		}

		b.WriteString(fmt.Sprintf(
			"  %s%s%s%s%s\n",
			c.dim(padRight("PORT", 10)),
			c.dim(padRight("ETAT", 10)),
			c.dim(padRight("RTT", 12)),
			c.dim(padRight("SERVICE", 22)),
			c.dim("DETAILS"),
		))
		for _, o := range rows {
			portCol := padRight(fmt.Sprintf("%d/tcp", o.Port), 10)
			rawState := padRight(strings.ToUpper(o.State), 10)
			var stateCol string
			switch o.State {
			case "open":
				stateCol = c.green(c.bold(rawState))
			case "closed":
				stateCol = c.yellow(rawState)
			default:
				stateCol = c.dim(rawState)
			}
			rttCol := padRight(fmt.Sprintf("%.2f ms", o.LatencyMs), 12)
			svcLabel := o.Service.Label
			if len(svcLabel) > 20 {
				svcLabel = svcLabel[:20]
			}
			svcCol := padRight(svcLabel, 22)
			detail := fmt.Sprintf("reason=%s", o.Reason)
			if o.State == "open" {
				detail = summarizeObservation(o)
			} else {
				detail = c.dim(detail)
			}
			b.WriteString(fmt.Sprintf("  %s%s%s%s%s\n", portCol, stateCol, rttCol, svcCol, detail))
		}
	}

	var actionable []risk.Finding
	for _, f := range r.Findings {
		if f.Severity != "info" {
			actionable = append(actionable, f)
		}
	}

	b.WriteString(fmt.Sprintf("\n%s (%d)\n", c.bold("Constats de securite"), len(actionable)))
	b.WriteString(c.dim(sep) + "\n")
	if len(actionable) == 0 {
		b.WriteString(fmt.Sprintf("  %s\n", c.green("[OK] Aucun constat critique, eleve, moyen ou faible.")))
	} else {
		for _, f := range actionable {
			tag := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
			tagPadded := padRight(tag, 11)
			switch f.Severity {
			case "critical", "high":
				tagPadded = c.red(c.bold(tagPadded))
			case "medium":
				tagPadded = c.yellow(c.bold(tagPadded))
			default:
				tagPadded = c.blue(tagPadded)
			}
			b.WriteString(fmt.Sprintf("  %s %s %s:%d - %s\n", tagPadded, c.bold(f.RuleID), c.cyan(f.Host), f.Port, f.Title))
			b.WriteString(fmt.Sprintf("              Preuve : %s\n", f.Evidence))
			b.WriteString(fmt.Sprintf("              Action : %s\n", f.Remediation))
		}
	}

	if d := extractDrift(rep); d != nil {
		b.WriteString(fmt.Sprintf("\n%s\n", c.bold("Comparaison baseline (drift)")))
		b.WriteString(c.dim(sep) + "\n")
		if !d.HasDrift {
			b.WriteString(fmt.Sprintf("  %s\n", c.green("[OK] Aucune derive detectee par rapport a la baseline.")))
		} else {
			for _, item := range d.NewlyOpened {
				b.WriteString(fmt.Sprintf("  %s %s:%d/tcp (%s) [avant: %s]\n",
					c.red(c.bold("[+ OPEN]")), item.Host, item.Port, item.Service, item.PreviousState))
			}
			for _, item := range d.NewlyClosed {
				b.WriteString(fmt.Sprintf("  %s %s:%d/tcp (%s) [maintenant: %s]\n",
					c.green("[- CLOSED]"), item.Host, item.Port, item.PreviousService, item.CurrentState))
			}
			for _, ch := range d.ServiceChanges {
				b.WriteString(fmt.Sprintf("  %s %s:%d/tcp (%s) %q -> %q\n",
					c.yellow("[~ CHANGE]"), ch.Host, ch.Port, ch.Kind, ch.Before, ch.After))
			}
		}
	}

	b.WriteString("\n")
	return b.String()
}

// FormatJSON renders indented JSON output.
func FormatJSON(rep *scanner.Report) (string, error) {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

// FormatSARIF renders valid SARIF 2.1.0 output for GitHub Security / SIEM ingestion.
func FormatSARIF(rep *scanner.Report) (string, error) {
	type textObj struct {
		Text string `json:"text"`
	}
	type sarifConfig struct {
		Level string `json:"level"`
	}
	type sarifRule struct {
		ID                   string         `json:"id"`
		Name                 string         `json:"name"`
		ShortDescription     textObj        `json:"shortDescription"`
		Help                 textObj        `json:"help"`
		DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
		Properties           map[string]any `json:"properties"`
	}
	type sarifResult struct {
		RuleID     string           `json:"ruleId"`
		Level      string           `json:"level"`
		Message    textObj          `json:"message"`
		Locations  []map[string]any `json:"locations"`
		Properties map[string]any   `json:"properties"`
	}

	levelFor := func(sev string) (string, string) {
		switch sev {
		case "critical":
			return "error", "9.0"
		case "high":
			return "error", "7.5"
		case "medium":
			return "warning", "5.0"
		case "low":
			return "note", "2.5"
		default:
			return "note", "1.0"
		}
	}

	allRules := risk.AllRules()
	sarifRules := make([]sarifRule, 0, len(allRules))
	for _, r := range allRules {
		lvl, secScore := levelFor(r.Severity)
		sarifRules = append(sarifRules, sarifRule{
			ID:                   r.ID,
			Name:                 r.Name,
			ShortDescription:     textObj{Text: r.ShortDescription},
			Help:                 textObj{Text: r.Help},
			DefaultConfiguration: sarifConfig{Level: lvl},
			Properties: map[string]any{
				"tags":              []string{"security", "network", "sentinel-net", r.Severity},
				"security-severity": secScore,
			},
		})
	}

	results := make([]sarifResult, 0, len(rep.Risk.Findings))
	for _, f := range rep.Risk.Findings {
		lvl, _ := levelFor(f.Severity)
		results = append(results, sarifResult{
			RuleID: f.RuleID,
			Level:  lvl,
			Message: textObj{
				Text: fmt.Sprintf("%s - %s Remediation: %s", f.Title, f.Evidence, f.Remediation),
			},
			Locations: []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{
							"uri": fmt.Sprintf("tcp://%s:%d", f.Host, f.Port),
						},
					},
					"logicalLocations": []map[string]any{
						{
							"name":               fmt.Sprintf("%s:%d", f.Host, f.Port),
							"fullyQualifiedName": fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Service),
							"kind":               "network-endpoint",
						},
					},
				},
			},
			Properties: map[string]any{
				"host":              f.Host,
				"port":              f.Port,
				"service":           f.Service,
				"severity":          f.Severity,
				"confidence":        f.Confidence,
				"falsePositiveNote": f.FalsePositiveNote,
			},
		})
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "Sentinel Net",
						"version":        rep.Tool.Version,
						"informationUri": "https://github.com/abiyeenzo/sentinel-net",
						"rules":          sarifRules,
					},
				},
				"invocations": []map[string]any{
					{
						"executionSuccessful": true,
						"startTimeUtc":        rep.StartedAt,
						"endTimeUtc":          rep.FinishedAt,
					},
				},
				"results": results,
			},
		},
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

// FormatMarkdown renders a clean Markdown report suitable for tickets or GitHub Step Summaries.
func FormatMarkdown(rep *scanner.Report) string {
	s := rep.Summary
	r := rep.Risk
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Rapport d'Audit Reseau - Sentinel Net v%s\n\n", rep.Tool.Version))
	b.WriteString(fmt.Sprintf("- **Periode :** `%s` -> `%s` (%.2f ms)\n", rep.StartedAt, rep.FinishedAt, s.DurationMs))
	b.WriteString(fmt.Sprintf("- **Posture :** **%s (%d/100)** - risque `%s`\n", r.Grade, r.Score, strings.ToUpper(r.Level)))
	b.WriteString(fmt.Sprintf("- **Perimetre :** %d hote(s), %d port(s)/hote (%d sondes TCP)\n", s.HostsScanned, s.PortsPerHost, s.TotalProbes))
	b.WriteString(fmt.Sprintf("- **Resultats :** **%d** ouvert(s), **%d** ferme(s), **%d** inconnu(s)/filtre(s)\n\n", s.OpenPorts, s.ClosedPorts, s.UnknownPorts))

	b.WriteString("## Ports ouverts detectes\n\n")
	var openRows []string
	for _, h := range rep.Hosts {
		for _, o := range h.Observations {
			if o.State == "open" {
				detail := strings.ReplaceAll(summarizeObservation(o), "|", "\\|")
				openRows = append(openRows, fmt.Sprintf("| `%s` | `%d/tcp` | %s | %.2f ms | %s |",
					h.Target, o.Port, o.Service.Label, o.LatencyMs, detail))
			}
		}
	}
	if len(openRows) == 0 {
		b.WriteString("_Aucun port TCP ouvert detecte._\n\n")
	} else {
		b.WriteString("| Hote | Port | Service | Latence | Details |\n|---|---|---|---|---|\n")
		for _, row := range openRows {
			b.WriteString(row + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Constats de securite\n\n")
	var actionable []risk.Finding
	for _, f := range r.Findings {
		if f.Severity != "info" {
			actionable = append(actionable, f)
		}
	}
	if len(actionable) == 0 {
		b.WriteString("Aucun constat critique, eleve, moyen ou faible.\n")
	} else {
		b.WriteString("| Severite | Regle | Cible | Constat | Remediation |\n|---|---|---|---|---|\n")
		for _, f := range actionable {
			ev := strings.ReplaceAll(f.Evidence, "|", "\\|")
			rem := strings.ReplaceAll(f.Remediation, "|", "\\|")
			b.WriteString(fmt.Sprintf("| **%s** | `%s` | `%s:%d` | %s (%s) | %s |\n",
				strings.ToUpper(f.Severity), f.RuleID, f.Host, f.Port, f.Title, ev, rem))
		}
	}

	if d := extractDrift(rep); d != nil {
		b.WriteString("\n## Comparaison Baseline\n\n")
		if !d.HasDrift {
			b.WriteString("Aucune derive detectee.\n")
		} else {
			b.WriteString(fmt.Sprintf("- Nouveaux ports ouverts : %d\n", d.Counts.NewlyOpened))
			b.WriteString(fmt.Sprintf("- Ports fermes : %d\n", d.Counts.NewlyClosed))
			b.WriteString(fmt.Sprintf("- Changements de service/certificat : %d\n", d.Counts.ServiceChanges))
		}
	}

	return b.String()
}

// FormatCSV exports all port observations as RFC 4180 CSV.
func FormatCSV(rep *scanner.Report) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	headers := []string{
		"host", "hostname", "scope", "port", "state", "reason", "latency_ms",
		"service_id", "service_label", "category", "encrypted", "product",
		"tls_protocol", "tls_cert_subject", "tls_days_remaining", "http_status",
		"host_score", "host_grade",
	}
	if err := w.Write(headers); err != nil {
		return "", err
	}

	for _, h := range rep.Hosts {
		for _, o := range h.Observations {
			var tlsProto, certSubj, certDays, httpStatus string
			if o.Inspection != nil {
				if o.Inspection.TLS != nil {
					tlsProto = o.Inspection.TLS.Protocol
					if o.Inspection.TLS.Certificate != nil {
						certSubj = o.Inspection.TLS.Certificate.SubjectCN
						certDays = strconv.Itoa(o.Inspection.TLS.Certificate.DaysRemaining)
					}
				}
				if o.Inspection.HTTP != nil && o.Inspection.HTTP.StatusCode > 0 {
					httpStatus = strconv.Itoa(o.Inspection.HTTP.StatusCode)
				}
			}
			row := []string{
				h.Target,
				h.Hostname,
				h.Scope,
				strconv.Itoa(o.Port),
				o.State,
				o.Reason,
				fmt.Sprintf("%.2f", o.LatencyMs),
				o.Service.ID,
				o.Service.Label,
				o.Service.Category,
				strconv.FormatBool(o.Service.Encrypted),
				o.Service.Product,
				tlsProto,
				certSubj,
				certDays,
				httpStatus,
				strconv.Itoa(h.Risk.Score),
				h.Risk.Grade,
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// FormatHTML renders a standalone, offline-ready HTML audit report.
func FormatHTML(rep *scanner.Report) string {
	s := rep.Summary
	r := rep.Risk
	scoreColor := "#10b981"
	if r.Score < 60 {
		scoreColor = "#ef4444"
	} else if r.Score < 88 {
		scoreColor = "#f59e0b"
	}

	var rows strings.Builder
	for _, h := range rep.Hosts {
		for _, o := range h.Observations {
			badgeClass := "b-unknown"
			if o.State == "open" {
				badgeClass = "b-open"
			} else if o.State == "closed" {
				badgeClass = "b-closed"
			}
			detail := "reason=" + o.Reason
			if o.State == "open" {
				detail = summarizeObservation(o)
			}
			searchText := strings.ToLower(fmt.Sprintf("%s %s %d %s %s", h.Target, h.Hostname, o.Port, o.Service.Label, detail))
			hostCell := html.EscapeString(h.Target)
			if h.Hostname != "" {
				hostCell += fmt.Sprintf(` <span class="muted">(%s)</span>`, html.EscapeString(h.Hostname))
			}
			rows.WriteString(fmt.Sprintf(
				`<tr data-state="%s" data-search="%s"><td class="mono">%s</td><td class="mono"><strong>%d</strong>/tcp</td><td><span class="badge %s">%s</span></td><td class="mono">%.2f ms</td><td>%s</td><td class="muted">%s</td></tr>`,
				html.EscapeString(o.State),
				html.EscapeString(searchText),
				hostCell,
				o.Port,
				badgeClass,
				html.EscapeString(strings.ToUpper(o.State)),
				o.LatencyMs,
				html.EscapeString(o.Service.Label),
				html.EscapeString(detail),
			))
		}
	}

	var findingsHTML strings.Builder
	actionableCount := 0
	for _, f := range r.Findings {
		if f.Severity == "info" {
			continue
		}
		actionableCount++
		sevEsc := html.EscapeString(f.Severity)
		findingsHTML.WriteString(fmt.Sprintf(`
		<div class="finding sev-%s">
			<div class="finding-head">
				<span class="pill p-%s">%s</span>
				<span class="mono muted">%s</span>
				<span class="mono target">%s:%d</span>
				<strong>%s</strong>
			</div>
			<p><strong>Preuve :</strong> %s</p>
			<p><strong>Analyse :</strong> %s</p>
			<p><strong>Remediation :</strong> %s</p>
			<p class="muted">Confiance %s - %s</p>
		</div>`,
			sevEsc, sevEsc, html.EscapeString(strings.ToUpper(f.Severity)),
			html.EscapeString(f.RuleID),
			html.EscapeString(f.Host), f.Port,
			html.EscapeString(f.Title),
			html.EscapeString(f.Evidence),
			html.EscapeString(f.Rationale),
			html.EscapeString(f.Remediation),
			html.EscapeString(f.Confidence),
			html.EscapeString(f.FalsePositiveNote),
		))
	}
	if actionableCount == 0 {
		findingsHTML.WriteString(`<div class="ok-box">Aucun constat de risque critique, eleve, moyen ou faible sur le perimetre analyse.</div>`)
	}

	avgRtt := "n/a"
	p95Rtt := "n/a"
	if s.Latency.AvgMs != nil {
		avgRtt = fmt.Sprintf("%.2f ms", *s.Latency.AvgMs)
	}
	if s.Latency.P95Ms != nil {
		p95Rtt = fmt.Sprintf("%.2f ms", *s.Latency.P95Ms)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sentinel Net - Rapport d'Audit (%s)</title>
<style>
  :root { --bg:#0b1120; --panel:#111827; --border:#1f2937; --text:#e5e7eb; --muted:#9ca3af; --accent:#38bdf8; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--text); padding:2rem; line-height:1.5; }
  .wrap { max-width:1180px; margin:0 auto; }
  header { display:flex; justify-content:space-between; align-items:baseline; border-bottom:1px solid var(--border); padding-bottom:1rem; margin-bottom:1.5rem; flex-wrap:wrap; gap:0.75rem; }
  .title { font-size:1.35rem; font-weight:700; color:var(--accent); }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .muted { color:var(--muted); font-size:0.86rem; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1rem; margin-bottom:1.75rem; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:1rem 1.15rem; }
  .card-label { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); }
  .card-val { font-size:1.75rem; font-weight:700; margin-top:0.2rem; }
  h2 { font-size:1.1rem; margin:1.75rem 0 0.85rem; }
  .toolbar { display:flex; gap:0.65rem; margin-bottom:0.85rem; flex-wrap:wrap; }
  input, select { background:var(--panel); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.45rem 0.75rem; font-size:0.88rem; }
  table { width:100%%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; font-size:0.88rem; }
  th, td { text-align:left; padding:0.65rem 0.85rem; border-bottom:1px solid var(--border); }
  th { font-size:0.75rem; text-transform:uppercase; color:var(--muted); background:rgba(255,255,255,0.02); }
  .badge { display:inline-block; padding:0.12rem 0.5rem; border-radius:4px; font-size:0.72rem; font-weight:700; }
  .b-open { background:rgba(16,185,129,0.18); color:#34d399; }
  .b-closed { background:rgba(245,158,11,0.14); color:#fbbf24; }
  .b-unknown { background:rgba(156,163,175,0.12); color:#9ca3af; }
  .finding { background:var(--panel); border:1px solid var(--border); border-left-width:4px; border-radius:8px; padding:0.9rem 1.1rem; margin-bottom:0.75rem; }
  .finding p { margin:0.3rem 0; font-size:0.88rem; }
  .finding-head { display:flex; gap:0.6rem; align-items:center; flex-wrap:wrap; margin-bottom:0.4rem; }
  .sev-critical { border-left-color:#ef4444; }
  .sev-high { border-left-color:#f97316; }
  .sev-medium { border-left-color:#f59e0b; }
  .sev-low { border-left-color:#38bdf8; }
  .pill { font-size:0.7rem; font-weight:700; padding:0.12rem 0.45rem; border-radius:4px; }
  .p-critical { background:#ef4444; color:#fff; }
  .p-high { background:#f97316; color:#fff; }
  .p-medium { background:#f59e0b; color:#111827; }
  .p-low { background:#38bdf8; color:#0f172a; }
  .target { color:var(--accent); font-weight:600; }
  .ok-box { background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.35); color:#6ee7b7; padding:0.9rem 1rem; border-radius:8px; }
  footer { margin-top:2rem; border-top:1px solid var(--border); padding-top:1rem; font-size:0.8rem; color:var(--muted); }
  @media print { body { background:#fff; color:#111; padding:0; } .card, table, .finding { background:#fff; border-color:#ccc; } .toolbar { display:none; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="title">Sentinel Net v%s</div>
      <div class="muted">Rapport d'audit reseau defensif | Fin : %s</div>
    </div>
    <div class="mono muted">Duree : %.2f ms | Sondes : %d</div>
  </header>
  <section class="grid">
    <div class="card"><div class="card-label">Posture</div><div class="card-val" style="color:%s">%s (%d/100)</div><div class="muted">Risque : %s</div></div>
    <div class="card"><div class="card-label">Ports ouverts</div><div class="card-val" style="color:#10b981">%d</div><div class="muted">%d/%d hote(s) actifs</div></div>
    <div class="card"><div class="card-label">Constats</div><div class="card-val">%d</div><div class="muted">Crit: %d | Eleve: %d | Moyen: %d</div></div>
    <div class="card"><div class="card-label">Latence RTT moy</div><div class="card-val">%s</div><div class="muted">P95 : %s</div></div>
  </section>
  <h2>Constats et remediations</h2>
  <section>%s</section>
  <h2>Observations TCP</h2>
  <div class="toolbar">
    <input type="search" id="q" placeholder="Filtrer IP, port, service..." />
    <select id="st">
      <option value="all">Tous les etats (%d)</option>
      <option value="open">Ouverts (%d)</option>
      <option value="closed">Fermes RST (%d)</option>
      <option value="unknown">Inconnus / filtres (%d)</option>
    </select>
  </div>
  <table>
    <thead><tr><th>Hote</th><th>Port</th><th>Etat</th><th>Latence</th><th>Service</th><th>Details</th></tr></thead>
    <tbody id="rows">%s</tbody>
  </table>
  <footer>Sentinel Net - Audit defensif soumis a autorisation explicite.</footer>
</div>
<script>
  const q = document.getElementById('q');
  const st = document.getElementById('st');
  const trs = Array.from(document.querySelectorAll('#rows tr'));
  function filter() {
    const term = q.value.trim().toLowerCase();
    const state = st.value;
    for (const tr of trs) {
      const okS = state === 'all' || tr.dataset.state === state;
      const okQ = !term || tr.dataset.search.includes(term);
      tr.style.display = okS && okQ ? '' : 'none';
    }
  }
  q.addEventListener('input', filter);
  st.addEventListener('change', filter);
</script>
</body>
</html>
`,
		html.EscapeString(rep.StartedAt),
		html.EscapeString(rep.Tool.Version),
		html.EscapeString(rep.FinishedAt),
		s.DurationMs, s.TotalProbes,
		scoreColor, html.EscapeString(r.Grade), r.Score, html.EscapeString(strings.ToUpper(r.Level)),
		s.OpenPorts, s.HostsWithOpenPorts, s.HostsScanned,
		r.ActionableFindings, r.Counts.Critical, r.Counts.High, r.Counts.Medium,
		html.EscapeString(avgRtt), html.EscapeString(p95Rtt),
		findingsHTML.String(),
		s.TotalProbes, s.OpenPorts, s.ClosedPorts, s.UnknownPorts,
		rows.String(),
	)
}

// Format dispatches report rendering by format name.
func Format(rep *scanner.Report, opts Options) (string, error) {
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", "json":
		return FormatJSON(rep)
	case "table", "text":
		return FormatTable(rep, opts.Color, opts.OpenOnly), nil
	case "sarif":
		return FormatSARIF(rep)
	case "markdown", "md":
		return FormatMarkdown(rep), nil
	case "csv":
		return FormatCSV(rep)
	case "html":
		return FormatHTML(rep), nil
	default:
		return "", fmt.Errorf("unsupported format %q (expected: table, json, sarif, markdown, csv, html)", opts.Format)
	}
}
