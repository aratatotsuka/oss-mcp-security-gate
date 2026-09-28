package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/secret"
)

// WriteBundle keeps the requested JSON path and writes human-readable siblings.
// The JSON is the authoritative, hashed report; the other formats are views.
func WriteBundle(path string, r *model.Report) error {
	if err := Seal(r); err != nil {
		return err
	}
	jsonData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	paths := Paths(path)
	v := makeView(r)
	artifacts := []struct {
		path string
		data []byte
	}{
		{paths.HTML, renderHTML(v)},
		{paths.Markdown, renderMarkdown(v)},
		{paths.FindingsCSV, renderCSV(v.Findings)},
		{paths.ReviewRequiredCSV, renderCSV(v.Attention)},
		{path, append(jsonData, '\n')},
	}
	// Prepare every file before publishing any view. JSON is published last so
	// a failed bundle never exposes a new authoritative decision without audit.
	staged := make([]string, 0, len(artifacts))
	defer func() {
		for _, tmp := range staged {
			_ = os.Remove(tmp)
		}
	}()
	for _, artifact := range artifacts {
		tmp, err := stageWrite(artifact.path, artifact.data)
		if err != nil {
			return fmt.Errorf("stage report artifact %s: %w", artifact.path, err)
		}
		staged = append(staged, tmp)
	}
	for i, artifact := range artifacts {
		if err := publishStaged(artifact.path, staged[i]); err != nil {
			return fmt.Errorf("write report artifact %s: %w", artifact.path, err)
		}
	}
	return nil
}

type ArtifactPaths struct {
	HTML, Markdown, FindingsCSV, ReviewRequiredCSV string
}

func Paths(jsonPath string) ArtifactPaths {
	base := strings.TrimSuffix(jsonPath, ".json")
	return ArtifactPaths{base + ".html", base + ".md", base + "-findings.csv", base + "-review-required.csv"}
}

type findingView struct {
	ID, Severity, Category, Scanner, Component, Installed, Fixed string
	Title, Status, Remediation, Exception                        string
}

type scannerView struct {
	Name, Version, Status, ErrorCode, Message string
}

type reportView struct {
	Decision, Target, TargetType, GeneratedAt, PolicyVersion, ResultHash string
	Reasons                                                              []string
	Findings                                                             []findingView
	Attention                                                            []findingView
	Scanners                                                             []scannerView
	SeverityCounts                                                       map[string]int
	StatusCounts                                                         map[string]int
}

func makeView(r *model.Report) reportView {
	v := reportView{
		Decision: string(r.Decision), Target: secret.Text(r.TargetID), TargetType: secret.Text(r.TargetType),
		GeneratedAt:   r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
		PolicyVersion: secret.Text(r.PolicyVersion), ResultHash: r.ResultHash,
		SeverityCounts: map[string]int{}, StatusCounts: map[string]int{},
	}
	for _, reason := range r.Reasons {
		v.Reasons = append(v.Reasons, secret.Text(reason))
	}
	exceptions := map[string]bool{}
	for _, e := range r.ExceptionsUsed {
		exceptions[e.FindingID] = true
	}
	findings := append([]model.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if a != b {
			return a < b
		}
		return findings[i].FindingID < findings[j].FindingID
	})
	for _, f := range findings {
		x := findingView{
			ID: secret.Text(f.FindingID), Severity: string(f.Severity), Category: secret.Text(f.Category),
			Scanner: secret.Text(f.Scanner), Component: secret.Text(f.Component),
			Installed: secret.Text(f.InstalledVersion), Fixed: secret.Text(f.FixedVersion),
			Title: secret.Text(f.Title), Status: string(f.ScanStatus), Remediation: secret.Text(f.Remediation),
		}
		if exceptions[f.FindingID] {
			x.Exception = "yes"
		}
		v.Findings = append(v.Findings, x)
		v.SeverityCounts[x.Severity]++
		if needsAttention(f) {
			v.Attention = append(v.Attention, x)
		}
	}
	for _, s := range r.ScannerRuns {
		v.Scanners = append(v.Scanners, scannerView{
			Name: secret.Text(s.Scanner), Version: secret.Text(s.Version), Status: string(s.Status),
			ErrorCode: secret.Text(s.ErrorCode), Message: secret.Text(s.Message),
		})
		v.StatusCounts[string(s.Status)]++
	}
	return v
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityUnknown:
		return 2
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 4
	default:
		return 5
	}
}

// Attention is a triage filter, not a per-finding policy decision.
func needsAttention(f model.Finding) bool {
	return f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh ||
		f.Severity == model.SeverityUnknown || f.ScanStatus != model.StatusComplete ||
		f.Category == "integrity" || f.Category == "secret" || f.Category == "prohibited-capability" ||
		(f.Category == "mcp" && strings.Contains(strings.ToUpper(f.FindingID), "YARA"))
}

func renderCSV(findings []findingView) []byte {
	var b bytes.Buffer
	b.Write([]byte{0xef, 0xbb, 0xbf}) // Excel-friendly UTF-8
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"finding_id", "severity", "category", "scanner", "component", "installed_version", "fixed_version", "title", "scan_status", "exception_applied", "remediation"})
	for _, f := range findings {
		_ = w.Write([]string{csvCell(f.ID), csvCell(f.Severity), csvCell(f.Category), csvCell(f.Scanner), csvCell(f.Component), csvCell(f.Installed), csvCell(f.Fixed), csvCell(f.Title), csvCell(f.Status), csvCell(f.Exception), csvCell(f.Remediation)})
	}
	w.Flush()
	return b.Bytes()
}

func csvCell(s string) string {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + s
	}
	return s
}

func mdCell(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n':
			b.WriteByte(' ')
		case r >= '!' && r <= '/' || r >= ':' && r <= '@' || r >= '[' && r <= '`' || r >= '{' && r <= '~':
			// Entities render as literal punctuation, without becoming Markdown
			// links/images, HTML or table separators.
			fmt.Fprintf(&b, "&#%d;", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func renderMarkdown(v reportView) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security Gate report\n\n**Decision: %s**\n\n", mdCell(v.Decision))
	fmt.Fprintf(&b, "- Target: %s\n- Type: %s\n- Generated: %s\n- Policy: %s\n- Findings: %d\n- Attention: %d\n- Result hash: %s\n\n", mdCell(v.Target), mdCell(v.TargetType), v.GeneratedAt, mdCell(v.PolicyVersion), len(v.Findings), len(v.Attention), v.ResultHash)
	b.WriteString("The overall decision is authoritative. The attention list is a triage filter, not an individual policy decision.\n\n## Reasons\n\n")
	if len(v.Reasons) == 0 {
		b.WriteString("- None\n")
	}
	for _, reason := range v.Reasons {
		fmt.Fprintf(&b, "- %s\n", mdCell(reason))
	}
	b.WriteString("\n## Scanner runs\n\n| Scanner | Version | Status | Error | Message |\n|---|---|---|---|---|\n")
	for _, s := range v.Scanners {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdCell(s.Name), mdCell(s.Version), mdCell(s.Status), mdCell(s.ErrorCode), mdCell(s.Message))
	}
	b.WriteString("\n## Findings\n\n| Severity | ID | Category | Scanner | Component | Title | Status | Exception |\n|---|---|---|---|---|---|---|---|\n")
	for _, f := range v.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", mdCell(f.Severity), mdCell(f.ID), mdCell(f.Category), mdCell(f.Scanner), mdCell(f.Component), mdCell(f.Title), mdCell(f.Status), mdCell(f.Exception))
	}
	return []byte(b.String())
}

func renderHTML(v reportView) []byte {
	var b bytes.Buffer
	if err := template.Must(template.New("report").Funcs(template.FuncMap{"list": func(values ...string) []string { return values }}).Parse(htmlReport)).Execute(&b, v); err != nil {
		panic(err)
	}
	return b.Bytes()
}

const htmlReport = `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Gate report</title><style>
:root{font-family:system-ui,sans-serif;color-scheme:light dark}body{max-width:1400px;margin:2rem auto;padding:0 1rem;line-height:1.5}
.cards{display:flex;flex-wrap:wrap;gap:.7rem;margin:1rem 0}.card{border:1px solid #94a3b8;border-radius:.5rem;padding:.7rem 1rem;min-width:7rem}
.ALLOW,.COMPLETE{background:#dcfce7;color:#052e16}.REVIEW,.PARTIAL,.UNSUPPORTED{background:#fef3c7;color:#451a03}
.BLOCK,.ERROR,.FAILED,.TIMEOUT,.CRITICAL,.HIGH,.UNKNOWN{background:#fee2e2;color:#450a0a}
.notice{border-left:.35rem solid #d97706;padding:.7rem 1rem;background:#fff7ed;color:#431407}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{border:1px solid #94a3b8;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#e2e8f0;color:#0f172a}code{overflow-wrap:anywhere}small{color:#475569}
</style></head><body><h1>Security Gate report</h1>
<p class="notice">Overall decision is authoritative. The attention CSV is a triage list, not a per-finding policy decision. Incomplete scanner results may require action even when there are no findings.</p>
<div class="cards"><div class="card {{.Decision}}">Decision<br><strong>{{.Decision}}</strong></div><div class="card">Findings<br><strong>{{len .Findings}}</strong></div><div class="card">Attention<br><strong>{{len .Attention}}</strong></div>{{range $severity := (list "CRITICAL" "HIGH" "MEDIUM" "LOW" "INFO" "UNKNOWN")}}<div class="card {{$severity}}">{{$severity}}<br><strong>{{index $.SeverityCounts $severity}}</strong></div>{{end}}</div>
<p>Target: <code>{{.Target}}</code><br>Type: {{.TargetType}}<br>Generated: {{.GeneratedAt}}<br>Policy: {{.PolicyVersion}}<br>Result hash: <code>{{.ResultHash}}</code></p>
<h2>Decision reasons</h2><ul>{{range .Reasons}}<li>{{.}}</li>{{else}}<li>None</li>{{end}}</ul>
<h2>Scanner runs</h2><div class="scroll"><table><thead><tr><th>Scanner</th><th>Version</th><th>Status</th><th>Error</th><th>Message</th></tr></thead><tbody>{{range .Scanners}}<tr class="{{.Status}}"><td>{{.Name}}</td><td>{{.Version}}</td><td>{{.Status}}</td><td>{{.ErrorCode}}</td><td>{{.Message}}</td></tr>{{else}}<tr><td colspan="5">No scanner runs</td></tr>{{end}}</tbody></table></div>
<h2>Findings</h2><div class="scroll"><table><thead><tr><th>Severity</th><th>ID</th><th>Category</th><th>Scanner</th><th>Component</th><th>Installed</th><th>Fixed</th><th>Title</th><th>Status</th><th>Exception</th><th>Remediation</th></tr></thead><tbody>{{range .Findings}}<tr class="{{.Severity}}"><td>{{.Severity}}</td><td>{{.ID}}</td><td>{{.Category}}</td><td>{{.Scanner}}</td><td>{{.Component}}</td><td>{{.Installed}}</td><td>{{.Fixed}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{.Exception}}</td><td>{{.Remediation}}</td></tr>{{else}}<tr><td colspan="11">No findings</td></tr>{{end}}</tbody></table></div>
</body></html>`
