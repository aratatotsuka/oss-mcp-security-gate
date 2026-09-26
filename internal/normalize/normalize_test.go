package normalize

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

var ctx = Context{Scanner: "test", Version: "1", Digest: "sha256:" + strings.Repeat("a", 64), TargetID: "target"}

func TestOSV(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"pkg","version":"1.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-test","summary":"bad","severity":[{"type":"CVSS_V3","score":"9.8"}],"affected":[{"ranges":[{"events":[{"fixed":"1.1"}]}]}]}]}]}]}`)
	xs, e := OSV(raw, ctx)
	if e != nil || len(xs) != 1 {
		t.Fatalf("%v %#v", e, xs)
	}
	if xs[0].Severity != model.SeverityCritical || xs[0].FixedVersion != "1.1" {
		t.Fatalf("bad normalization: %#v", xs[0])
	}
}
func TestOSVSeverityFromDatabaseSpecific(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-real-shape","summary":"bad","database_specific":{"severity":"HIGH"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}]}]}`)
	xs, err := OSV(raw, ctx)
	if err != nil || len(xs) != 1 {
		t.Fatalf("%v %#v", err, xs)
	}
	if xs[0].Severity != model.SeverityHigh {
		t.Fatalf("real OSV shape severity = %s", xs[0].Severity)
	}
}
func TestTrivy(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":".","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"}],"Misconfigurations":[{"ID":"AVD-1","Title":"open","Severity":"CRITICAL"}],"Secrets":[{"RuleID":"aws","Title":"AWS key","Severity":"HIGH","Match":"AKIAABCDEFGHIJKLMNOP","StartLine":3}]}]}`)
	xs, e := Trivy(raw, ctx)
	if e != nil || len(xs) != 3 {
		t.Fatalf("%v %#v", e, xs)
	}
	if strings.Contains(mustJSON(xs), "AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("secret leaked")
	}
}
func TestGitleaks(t *testing.T) {
	raw := []byte(`[{"RuleID":"generic-api-key","Description":"key","File":".env","StartLine":1,"Secret":"ghp_abcdefghijklmnopqrstuvwxyz123456","Fingerprint":"fp"}]`)
	xs, e := Gitleaks(raw, ctx)
	if e != nil || len(xs) != 1 {
		t.Fatal(e)
	}
	if strings.Contains(mustJSON(xs), "ghp_abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatal("secret leaked")
	}
}
func TestScorecard(t *testing.T) {
	raw := []byte(`{"score":5.1,"checks":[{"Name":"Dangerous-Workflow","Score":2,"Reason":"bad"},{"Name":"Maintained","Score":9}]}`)
	xs, e := Scorecard(raw, ctx)
	if e != nil || len(xs) != 1 || xs[0].Severity != model.SeverityHigh {
		t.Fatalf("%v %#v", e, xs)
	}
}
func TestMCP(t *testing.T) {
	raw := []byte(`{"tools":[{"name":"x","findings":[{"id":"MCP-YARA-1","title":"ignore previous instructions","status":"UNSAFE","severity":"HIGH","analyzer":"yara"}]}]}`)
	xs, e := MCP(raw, ctx)
	if e != nil || len(xs) != 1 {
		t.Fatalf("%v %#v", e, xs)
	}
}
func TestMalformed(t *testing.T) {
	if _, e := Parse("trivy", []byte(`{`), ctx); e == nil {
		t.Fatal("malformed JSON accepted")
	}
	for scanner, raw := range map[string]string{
		"osv-scanner": `{}`,
		"trivy":       `{}`,
		"gitleaks":    `null`,
		"scorecard":   `{}`,
		"mcp-scanner": `{}`,
	} {
		if _, e := Parse(scanner, []byte(raw), ctx); e == nil {
			t.Errorf("%s accepted structurally invalid JSON", scanner)
		}
	}
}
func TestSeverityMapping(t *testing.T) {
	for in, want := range map[string]model.Severity{"critical": model.SeverityCritical, "moderate": model.SeverityMedium, "n/a": model.SeverityUnknown} {
		if got := Severity(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestScorecardThresholdBoundary(t *testing.T) {
	raw := []byte(`{"score":7,"checks":[{"Name":"Below","Score":6},{"Name":"At","Score":7},{"Name":"Above","Score":8}]}`)
	xs, err := Scorecard(raw, Context{ScorecardReviewBelow: 7})
	if err != nil || len(xs) != 1 || xs[0].FindingID != "SCORECARD-BELOW" || xs[0].Severity != model.SeverityMedium {
		t.Fatalf("threshold boundary: %v %#v", err, xs)
	}
}

func TestGitleaksMissingFingerprintUsesStableID(t *testing.T) {
	raw := []byte(`[{"RuleID":"key","File":".env","StartLine":3,"Secret":"ghp_abcdefghijklmnopqrstuvwxyz123456"}]`)
	first, err := Gitleaks(raw, ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Gitleaks(raw, ctx)
	if err != nil || len(first) != 1 || len(second) != 1 || len(first[0].FindingID) != 16 || first[0].FindingID != second[0].FindingID {
		t.Fatalf("unstable fallback ID: %v %#v %#v", err, first, second)
	}
	if strings.Contains(mustJSON(first), "ghp_abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatal("secret leaked with missing fingerprint")
	}
}

func TestUnsupportedScannerIsRejected(t *testing.T) {
	if _, err := Parse("unknown", []byte(`{}`), ctx); err == nil || !strings.Contains(err.Error(), "unsupported scanner") {
		t.Fatalf("unsupported scanner accepted: %v", err)
	}
}
