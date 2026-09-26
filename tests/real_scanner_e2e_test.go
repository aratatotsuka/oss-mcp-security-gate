package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/normalize"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/policy"
)

func TestRealScannerOutputsNormalizeAndBlock(t *testing.T) {
	dir := os.Getenv("SECURITY_GATE_REAL_E2E_DIR")
	if dir == "" {
		t.Skip("set SECURITY_GATE_REAL_E2E_DIR to real scanner JSON output directory")
	}

	targetID := "e2e-fixture"
	definitions := []struct {
		name, version, file string
	}{
		{"osv-scanner", "2.6.0", "osv.json"},
		{"trivy", "0.74.0", "trivy.json"},
		{"gitleaks", "8.30.1", "gitleaks.json"},
	}

	var findings []model.Finding
	var runs []model.ScannerRun
	now := time.Now().UTC()
	for _, definition := range definitions {
		raw, err := os.ReadFile(filepath.Join(dir, definition.file))
		if err != nil {
			t.Fatal(err)
		}
		xs, err := normalize.Parse(definition.name, raw, normalize.Context{
			Scanner: definition.name, Version: definition.version,
			Digest: "sha256:" + strings.Repeat("a", 64), TargetID: targetID,
		})
		if err != nil {
			t.Fatalf("normalize %s: %v", definition.name, err)
		}
		if len(xs) == 0 {
			t.Fatalf("%s produced no normalized findings", definition.name)
		}
		findings = append(findings, xs...)
		checked := now
		runs = append(runs, model.ScannerRun{Scanner: definition.name, Version: definition.version, Status: model.StatusComplete, AdvisoryCheckedAt: &checked})
	}

	var vulnerabilities, misconfigurations, secrets int
	var highOSV bool
	for _, finding := range findings {
		switch finding.Category {
		case "vulnerability":
			vulnerabilities++
		case "misconfiguration":
			misconfigurations++
		case "secret":
			secrets++
		}
		if finding.Scanner == "osv-scanner" && (finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityCritical) {
			highOSV = true
		}
	}
	if vulnerabilities == 0 || misconfigurations == 0 || secrets == 0 || !highOSV {
		t.Fatalf("unexpected categories: vulnerabilities=%d misconfigurations=%d secrets=%d high_osv=%v", vulnerabilities, misconfigurations, secrets, highOSV)
	}

	normalized, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(string(normalized), forbidden) {
			t.Fatalf("normalized output leaked fixture credential %q", forbidden)
		}
	}

	input := model.PolicyInput{SchemaVersion: "1.0", Now: now, TargetID: targetID, Findings: findings, ScannerRuns: runs, PolicyVersion: "1.0.0"}
	if decision := policy.Evaluate(input); decision.Decision != model.DecisionBlock {
		t.Fatalf("native policy decision = %s, want BLOCK: %v", decision.Decision, decision.Reasons)
	}

	if opa := os.Getenv("OPA_TEST_BIN"); opa != "" {
		decision, err := policy.EvaluateOPA(opa, filepath.Join("..", "policies"), input, 20*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != model.DecisionBlock {
			t.Fatalf("OPA decision = %s, want BLOCK: %v", decision.Decision, decision.Reasons)
		}
	}
	t.Logf("real E2E normalized %d findings (%d vulnerabilities, %d misconfigurations, %d secrets); decision=BLOCK", len(findings), vulnerabilities, misconfigurations, secrets)
}
