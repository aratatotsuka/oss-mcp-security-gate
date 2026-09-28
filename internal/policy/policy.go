package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/exception"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/runner"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/sandbox"
)

type Config struct {
	PolicyVersion              string `json:"policy_version"`
	VulnerabilityDBMaxAgeHours int    `json:"vulnerability_db_max_age_hours"`
	AdvisoryReviewMaxAgeDays   int    `json:"advisory_review_max_age_days"`
	ScorecardReviewBelow       int    `json:"scorecard_review_below"`
	ExceptionsRequireExpiry    bool   `json:"exceptions_require_expiry"`
	FailClosed                 bool   `json:"fail_closed"`
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("policy config must be JSON-compatible YAML: %w", err)
	}
	if strings.TrimSpace(c.PolicyVersion) == "" || c.VulnerabilityDBMaxAgeHours <= 0 || c.AdvisoryReviewMaxAgeDays <= 0 || c.ScorecardReviewBelow <= 0 || c.ScorecardReviewBelow > 10 {
		return Config{}, fmt.Errorf("policy config contains invalid thresholds or version")
	}
	if !c.ExceptionsRequireExpiry || !c.FailClosed {
		return Config{}, fmt.Errorf("policy config must require exception expiry and fail-closed evaluation")
	}
	return c, nil
}

func (c Config) Settings() model.PolicySettings {
	return model.PolicySettings{
		VulnerabilityDBMaxAgeHours: c.VulnerabilityDBMaxAgeHours,
		AdvisoryReviewMaxAgeDays:   c.AdvisoryReviewMaxAgeDays,
		ScorecardReviewBelow:       c.ScorecardReviewBelow,
		ExceptionsRequireExpiry:    c.ExceptionsRequireExpiry,
		FailClosed:                 c.FailClosed,
	}
}

func Evaluate(in model.PolicyInput) model.PolicyDecision {
	dbMaxAge := in.Policy.VulnerabilityDBMaxAgeHours
	if dbMaxAge <= 0 {
		dbMaxAge = 72
	}
	advisoryMaxAge := in.Policy.AdvisoryReviewMaxAgeDays
	if advisoryMaxAge <= 0 {
		advisoryMaxAge = 30
	}
	reasons := map[string]bool{}
	rank := map[model.Decision]int{model.DecisionAllow: 0, model.DecisionReview: 1, model.DecisionBlock: 2, model.DecisionError: 3}
	d := model.DecisionAllow
	set := func(x model.Decision, r string) {
		if rank[x] > rank[d] {
			d = x
		}
		reasons[r] = true
	}
	if len(in.ScannerRuns) == 0 {
		set(model.DecisionError, "no scanner result")
	}
	for _, r := range in.ScannerRuns {
		switch r.Status {
		case model.StatusFailed:
			set(model.DecisionError, r.Scanner+" failed")
		case model.StatusTimeout:
			set(model.DecisionError, r.Scanner+" timeout")
		case model.StatusPartial, model.StatusUnsupported:
			set(model.DecisionReview, r.Scanner+" scan incomplete: "+string(r.Status))
		}
		if strings.Contains(r.ErrorCode, "INTEGRITY") || strings.Contains(r.ErrorCode, "HASH_MISMATCH") {
			set(model.DecisionError, r.Scanner+" integrity verification prevented scan")
		}
		if r.DBUpdatedAt != nil && in.Now.Sub(*r.DBUpdatedAt) > time.Duration(dbMaxAge)*time.Hour {
			set(model.DecisionReview, r.Scanner+" vulnerability DB is stale")
		}
		if r.AdvisoryCheckedAt == nil || in.Now.Sub(*r.AdvisoryCheckedAt) > time.Duration(advisoryMaxAge)*24*time.Hour {
			set(model.DecisionReview, r.Scanner+" security advisory review is stale")
		}
	}
	for _, f := range in.Findings {
		ex, ok := exception.ActiveFor(in.Exceptions, f, in.TargetID, in.Now)
		_ = ex
		nonOverride := f.Category == "integrity" || f.Category == "secret" || f.Category == "prohibited-capability" || (f.Category == "mcp" && strings.Contains(strings.ToUpper(f.FindingID), "YARA"))
		if ok && !nonOverride {
			continue
		}
		if f.Category == "integrity" || f.Category == "prohibited-capability" {
			set(model.DecisionBlock, f.FindingID+": security invariant violation")
			continue
		}
		if f.Category == "secret" && f.Confidence == model.ConfidenceHigh {
			set(model.DecisionBlock, f.FindingID+": confirmed secret exposure")
			continue
		}
		if f.Category == "mcp" && strings.Contains(strings.ToUpper(f.FindingID), "YARA") {
			set(model.DecisionBlock, f.FindingID+": malicious MCP YARA finding")
			continue
		}
		if f.Category == "misconfiguration" && f.Severity == model.SeverityCritical {
			set(model.DecisionBlock, f.FindingID+": critical misconfiguration")
			continue
		}
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical {
			set(model.DecisionReview, f.FindingID+": high severity finding")
		}
		if f.Severity == model.SeverityUnknown {
			set(model.DecisionReview, f.FindingID+": unknown severity")
		}
		if f.ScanStatus != model.StatusComplete {
			set(model.DecisionReview, f.FindingID+": incomplete finding status")
		}
	}
	list := make([]string, 0, len(reasons))
	for r := range reasons {
		list = append(list, r)
	}
	sort.Strings(list)
	return model.PolicyDecision{Decision: d, Reasons: list}
}

func EvaluateOPA(opaPath, policyDir string, in model.PolicyInput, timeout time.Duration) (model.PolicyDecision, error) {
	return evaluateCommand(opaPath, []string{"eval", "--fail", "--format=json", "--data", policyDir, "--stdin-input", "data.security_gate.result"}, in, timeout)
}

func EvaluateRuntime(image, opaPath, policyDir string, in model.PolicyInput, timeout time.Duration) (model.PolicyDecision, error) {
	if image == "" {
		return EvaluateOPA(opaPath, policyDir, in, timeout)
	}
	args, err := sandbox.DockerArgs(sandbox.DockerSpec{Image: image, Entrypoint: "/scanner", Config: policyDir, Network: "none", Command: []string{"eval", "--fail", "--format=json", "--data", "/gate/config", "--stdin-input", "data.security_gate.result"}})
	if err != nil {
		return model.PolicyDecision{}, err
	}
	args = append([]string{args[0], "--pull", "never", "-i"}, args[1:]...)
	return evaluateCommand("docker", args, in, timeout)
}

func evaluateCommand(name string, args []string, in model.PolicyInput, timeout time.Duration) (model.PolicyDecision, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return model.PolicyDecision{}, err
	}
	r := runner.Run(context.Background(), runner.Spec{Name: name, Args: args, Timeout: timeout, OutputLimit: 2 << 20, Stdin: b})
	if r.Err != nil {
		return model.PolicyDecision{}, fmt.Errorf("OPA_POLICY_EVALUATION_FAILURE: %w: %s", r.Err, string(r.Stderr))
	}
	var out struct {
		Result []struct {
			Expressions []struct {
				Value model.PolicyDecision `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(r.Output, &out); err != nil {
		return model.PolicyDecision{}, fmt.Errorf("OPA malformed result: %w", err)
	}
	if len(out.Result) != 1 || len(out.Result[0].Expressions) != 1 || out.Result[0].Expressions[0].Value.Decision == "" {
		return model.PolicyDecision{}, fmt.Errorf("OPA returned undefined decision")
	}
	return out.Result[0].Expressions[0].Value, nil
}

func LoadInput(path string) (model.PolicyInput, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return model.PolicyInput{}, e
	}
	var in model.PolicyInput
	e = json.Unmarshal(b, &in)
	return in, e
}
