package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func baseInput() model.PolicyInput {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	return model.PolicyInput{Now: now, TargetID: "t", ScannerRuns: []model.ScannerRun{{Scanner: "osv", Status: model.StatusComplete, AdvisoryCheckedAt: &now}}}
}
func TestAllowOnlyCompleteClean(t *testing.T) {
	if d := Evaluate(baseInput()); d.Decision != model.DecisionAllow {
		t.Fatal(d)
	}
}
func TestFailuresNeverAllow(t *testing.T) {
	for _, s := range []model.ScanStatus{model.StatusFailed, model.StatusTimeout, model.StatusPartial, model.StatusUnsupported} {
		in := baseInput()
		in.ScannerRuns[0].Status = s
		if d := Evaluate(in); d.Decision == model.DecisionAllow {
			t.Fatalf("%s became ALLOW", s)
		}
	}
}
func TestBlockSecret(t *testing.T) {
	in := baseInput()
	in.Findings = []model.Finding{{FindingID: "s", Category: "secret", Confidence: model.ConfidenceHigh, Severity: model.SeverityHigh, ScanStatus: model.StatusComplete}}
	if d := Evaluate(in); d.Decision != model.DecisionBlock {
		t.Fatal(d)
	}
}
func TestExceptionExpiry(t *testing.T) {
	in := baseInput()
	in.Findings = []model.Finding{{FindingID: "CVE-1", Category: "vulnerability", Confidence: model.ConfidenceHigh, Severity: model.SeverityHigh, ScanStatus: model.StatusComplete}}
	in.Exceptions = []model.Exception{{FindingID: "CVE-1", Scope: "t", ExpiresAt: in.Now.Add(time.Hour)}}
	if d := Evaluate(in); d.Decision != model.DecisionAllow {
		t.Fatal(d)
	}
	in.Exceptions[0].ExpiresAt = in.Now.Add(-time.Second)
	if d := Evaluate(in); d.Decision != model.DecisionReview {
		t.Fatal(d)
	}
}
func TestStaleDBReview(t *testing.T) {
	in := baseInput()
	x := in.Now.Add(-73 * time.Hour)
	in.ScannerRuns[0].DBUpdatedAt = &x
	if d := Evaluate(in); d.Decision != model.DecisionReview {
		t.Fatal(d)
	}
}

func TestIncompleteFindingReview(t *testing.T) {
	in := baseInput()
	in.Findings = []model.Finding{{FindingID: "partial", Severity: model.SeverityLow, ScanStatus: model.StatusPartial}}
	if d := Evaluate(in); d.Decision != model.DecisionReview {
		t.Fatal(d)
	}
}

func TestConfiguredDBAge(t *testing.T) {
	in := baseInput()
	in.Policy.VulnerabilityDBMaxAgeHours = 1
	x := in.Now.Add(-2 * time.Hour)
	in.ScannerRuns[0].DBUpdatedAt = &x
	if d := Evaluate(in); d.Decision != model.DecisionReview {
		t.Fatal(d)
	}
}

func TestEvaluateOPAIntegration(t *testing.T) {
	opa := os.Getenv("OPA_TEST_BIN")
	if opa == "" {
		t.Skip("OPA_TEST_BIN is not set")
	}
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := EvaluateOPA(opa, policies, baseInput(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != model.DecisionAllow {
		t.Fatalf("unexpected OPA decision: %#v", d)
	}
}

func TestNoScannerResultIsError(t *testing.T) {
	in := baseInput()
	in.ScannerRuns = nil
	d := Evaluate(in)
	if d.Decision != model.DecisionError || len(d.Reasons) != 1 || d.Reasons[0] != "no scanner result" {
		t.Fatalf("missing scanner result was not reported: %#v", d)
	}
}

func TestScannerFailureStatuses(t *testing.T) {
	for _, tc := range []struct {
		status model.ScanStatus
		want   model.Decision
	}{
		{model.StatusFailed, model.DecisionError},
		{model.StatusTimeout, model.DecisionError},
		{model.StatusPartial, model.DecisionReview},
		{model.StatusUnsupported, model.DecisionReview},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			in := baseInput()
			in.ScannerRuns[0].Status = tc.status
			if d := Evaluate(in); d.Decision != tc.want || len(d.Reasons) != 1 {
				t.Fatalf("status %s: %#v, want %s and one reason", tc.status, d, tc.want)
			}
		})
	}
}

func TestExceptionCannotOverrideSecurityInvariant(t *testing.T) {
	for _, tc := range []struct {
		name, category, findingID string
	}{
		{"integrity", "integrity", "integrity-1"},
		{"prohibited capability", "prohibited-capability", "capability-1"},
		{"confirmed secret", "secret", "secret-1"},
		{"MCP YARA", "mcp", "MCP-YARA-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Findings = []model.Finding{{FindingID: tc.findingID, Category: tc.category, Confidence: model.ConfidenceHigh, Severity: model.SeverityHigh, ScanStatus: model.StatusComplete}}
			in.Exceptions = []model.Exception{{FindingID: tc.findingID, Scope: "t", ExpiresAt: in.Now.Add(time.Hour)}}
			if d := Evaluate(in); d.Decision != model.DecisionBlock {
				t.Fatalf("exception overrode %s: %#v", tc.category, d)
			}
		})
	}
}

func TestErrorTakesPriorityOverBlock(t *testing.T) {
	in := baseInput()
	in.ScannerRuns[0].Status = model.StatusFailed
	in.Findings = []model.Finding{{FindingID: "secret-1", Category: "secret", Confidence: model.ConfidenceHigh, Severity: model.SeverityHigh}}
	d := Evaluate(in)
	if d.Decision != model.DecisionError || len(d.Reasons) != 2 {
		t.Fatalf("error should outrank block without discarding reasons: %#v", d)
	}
}

func TestExceptionExpiresAtBoundary(t *testing.T) {
	in := baseInput()
	in.Findings = []model.Finding{{FindingID: "CVE-1", Category: "vulnerability", Severity: model.SeverityHigh, ScanStatus: model.StatusComplete}}
	in.Exceptions = []model.Exception{{FindingID: "CVE-1", Scope: "t", ExpiresAt: in.Now}}
	if d := Evaluate(in); d.Decision != model.DecisionReview {
		t.Fatalf("exception active at expiry: %#v", d)
	}
}
