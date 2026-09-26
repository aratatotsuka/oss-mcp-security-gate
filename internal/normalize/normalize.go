package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/secret"
)

type Context struct {
	Scanner, Version, Digest, TargetID string
	ScorecardReviewBelow               int
}

func base(c Context, id, category, title string) model.Finding {
	return model.Finding{SchemaVersion: "1.0", Scanner: c.Scanner, ScannerVersion: c.Version, ScannerArtifactDigest: c.Digest, TargetID: c.TargetID, Category: category, FindingID: id, Severity: model.SeverityUnknown, Confidence: model.ConfidenceHigh, Title: title, ScanStatus: model.StatusComplete, Evidence: map[string]any{}}
}

func Parse(scanner string, raw []byte, c Context) ([]model.Finding, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("malformed %s JSON", scanner)
	}
	switch scanner {
	case "osv-scanner":
		return OSV(raw, c)
	case "trivy":
		return Trivy(raw, c)
	case "gitleaks":
		return Gitleaks(raw, c)
	case "scorecard":
		return Scorecard(raw, c)
	case "mcp-scanner":
		return MCP(raw, c)
	default:
		return nil, fmt.Errorf("unsupported scanner %s", scanner)
	}
}

func OSV(raw []byte, c Context) ([]model.Finding, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if _, ok := envelope["results"]; !ok {
		return nil, fmt.Errorf("malformed osv-scanner JSON: results field is required")
	}
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package         struct{ Name, Version, Ecosystem string } `json:"package"`
				Vulnerabilities []struct {
					ID, Summary, Details string
					Aliases              []string
					Severity             []struct{ Type, Score string }
					DatabaseSpecific     struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
					Affected []struct {
						Ranges []struct{ Events []map[string]string }
					}
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				f := base(c, v.ID, "vulnerability", first(v.Summary, v.ID))
				f.Component = p.Package.Name
				f.InstalledVersion = p.Package.Version
				f.Description = v.Details
				f.Severity = Severity(v.DatabaseSpecific.Severity)
				if f.Severity == model.SeverityUnknown {
					f.Severity = severityFromScores(v.Severity)
				}
				f.References = append([]string(nil), v.Aliases...)
				f.Evidence = secret.Evidence(map[string]any{"source": r.Source.Path, "ecosystem": p.Package.Ecosystem})
				for _, a := range v.Affected {
					for _, rr := range a.Ranges {
						for _, e := range rr.Events {
							if x := e["fixed"]; x != "" {
								f.FixedVersion = x
							}
						}
					}
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func Trivy(raw []byte, c Context) ([]model.Finding, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if _, ok := envelope["Results"]; !ok {
		return nil, fmt.Errorf("malformed trivy JSON: Results field is required")
	}
	var doc struct {
		Results []struct {
			Target          string
			Vulnerabilities []struct {
				VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title, Description, Severity string
				References                                                                             []string
			}
			Misconfigurations []struct{ ID, Title, Description, Severity, Resolution, Status string }
			Secrets           []struct {
				RuleID, Category, Title, Severity, Match string
				StartLine                                int
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			f := base(c, v.VulnerabilityID, "vulnerability", first(v.Title, v.VulnerabilityID))
			f.Component = v.PkgName
			f.InstalledVersion = v.InstalledVersion
			f.FixedVersion = v.FixedVersion
			f.Description = v.Description
			f.Severity = Severity(v.Severity)
			f.References = v.References
			f.Evidence = map[string]any{"target": r.Target}
			out = append(out, f)
		}
		for _, m := range r.Misconfigurations {
			f := base(c, m.ID, "misconfiguration", m.Title)
			f.Description = m.Description
			f.Severity = Severity(m.Severity)
			f.Remediation = m.Resolution
			f.Evidence = map[string]any{"target": r.Target, "status": m.Status}
			out = append(out, f)
		}
		for _, s := range r.Secrets {
			f := base(c, s.RuleID, "secret", s.Title)
			f.Severity = Severity(first(s.Severity, "HIGH"))
			f.Evidence = secret.Evidence(map[string]any{"target": r.Target, "line": s.StartLine, "match": s.Match})
			out = append(out, f)
		}
	}
	return out, nil
}

func Gitleaks(raw []byte, c Context) ([]model.Finding, error) {
	if strings.TrimSpace(string(raw)) == "null" {
		return nil, fmt.Errorf("malformed gitleaks JSON: result array is required")
	}
	var rows []struct {
		RuleID, Description, File, Secret, Fingerprint string
		StartLine                                      int
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]model.Finding, 0, len(rows))
	for _, r := range rows {
		id := r.Fingerprint
		if id == "" {
			h := sha256.Sum256([]byte(r.RuleID + "|" + r.File + "|" + strconv.Itoa(r.StartLine)))
			id = hex.EncodeToString(h[:8])
		}
		f := base(c, id, "secret", first(r.Description, r.RuleID))
		f.Severity = model.SeverityHigh
		f.Evidence = secret.Evidence(map[string]any{"rule_id": r.RuleID, "file": r.File, "line": r.StartLine, "secret": r.Secret})
		out = append(out, f)
	}
	return out, nil
}

func Scorecard(raw []byte, c Context) ([]model.Finding, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if _, ok := envelope["score"]; !ok {
		return nil, fmt.Errorf("malformed scorecard JSON: score field is required")
	}
	if _, ok := envelope["checks"]; !ok {
		return nil, fmt.Errorf("malformed scorecard JSON: checks field is required")
	}
	var doc struct {
		Score  float64
		Checks []struct {
			Name, Reason string
			Score        int
			Details      []string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []model.Finding
	threshold := c.ScorecardReviewBelow
	if threshold <= 0 {
		threshold = 7
	}
	for _, x := range doc.Checks {
		if x.Score >= threshold {
			continue
		}
		f := base(c, "SCORECARD-"+strings.ToUpper(strings.ReplaceAll(x.Name, "-", "_")), "supply-chain", x.Name+" score is below review threshold")
		f.Severity = model.SeverityMedium
		if x.Score < 4 {
			f.Severity = model.SeverityHigh
		}
		f.Confidence = model.ConfidenceMedium
		f.Description = x.Reason
		f.Evidence = secret.Evidence(map[string]any{"score": x.Score, "details": x.Details, "aggregate_score": doc.Score})
		out = append(out, f)
	}
	return out, nil
}

func MCP(raw []byte, c Context) ([]model.Finding, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	switch x := doc.(type) {
	case map[string]any:
		if len(x) == 0 {
			return nil, fmt.Errorf("malformed mcp-scanner JSON: empty object")
		}
	case []any:
		if len(x) == 0 {
			return nil, fmt.Errorf("malformed mcp-scanner JSON: empty array")
		}
	default:
		return nil, fmt.Errorf("malformed mcp-scanner JSON: object or array is required")
	}
	var out []model.Finding
	walkMCP(doc, "", c, &out)
	return out, nil
}
func walkMCP(v any, path string, c Context, out *[]model.Finding) {
	switch x := v.(type) {
	case map[string]any:
		status := strings.ToUpper(str(x["status"]))
		sev := str(x["severity"])
		title := first(str(x["title"]), str(x["threat_summary"]), str(x["message"]))
		analyzer := strings.ToLower(str(x["analyzer"]))
		if status == "UNSAFE" || status == "MALICIOUS" || sev != "" || strings.Contains(analyzer, "yara") {
			id := first(str(x["id"]), str(x["rule_id"]), "MCP-YARA-"+shortHash(path+title))
			f := base(c, id, "mcp", first(title, "Suspicious MCP metadata"))
			f.Severity = Severity(first(sev, "HIGH"))
			f.Confidence = model.ConfidenceHigh
			f.Evidence = secret.Evidence(map[string]any{"path": path, "status": status, "analyzer": analyzer})
			*out = append(*out, f)
			return
		}
		for k, y := range x {
			walkMCP(y, path+"/"+k, c, out)
		}
	case []any:
		for i, y := range x {
			walkMCP(y, path+"/"+strconv.Itoa(i), c, out)
		}
	}
}

func Severity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM", "MODERATE":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	case "INFO", "INFORMATIONAL":
		return model.SeverityInfo
	default:
		return model.SeverityUnknown
	}
}
func severityFromScores(scores []struct{ Type, Score string }) model.Severity {
	max := 0.0
	for _, s := range scores {
		p := strings.Split(s.Score, "/")
		n := p[len(p)-1]
		if v, e := strconv.ParseFloat(n, 64); e == nil && v > max {
			max = v
		}
	}
	if max >= 9 {
		return model.SeverityCritical
	}
	if max >= 7 {
		return model.SeverityHigh
	}
	if max >= 4 {
		return model.SeverityMedium
	}
	if max > 0 {
		return model.SeverityLow
	}
	return model.SeverityUnknown
}
func first(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
func str(v any) string {
	if x, ok := v.(string); ok {
		return x
	}
	return ""
}
func shortHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:6]) }
