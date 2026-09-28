package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/audit"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/deploy"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/exception"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/integrity"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/normalize"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/policy"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/report"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/runner"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/scanners"
)

type Config struct {
	Root, ManifestPath, PolicyDir, ExceptionsPath, AuditPath, OutputPath string
	Request                                                              scanners.Request
}

func Scan(ctx context.Context, c Config) (model.Report, error) {
	now := time.Now().UTC()
	policyConfig, err := policy.LoadConfig(filepath.Join(c.Root, "config", "policy.yaml"))
	if err != nil {
		return model.Report{}, fmt.Errorf("load policy config: %w", err)
	}
	target, err := filepath.Abs(c.Request.Target)
	if err != nil {
		return model.Report{}, err
	}
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		return model.Report{}, fmt.Errorf("target must be an existing directory")
	}
	c.Request.Target = target
	c.Request.CacheRoot = filepath.Join(c.Root, "var", "cache")
	c.Request.ConfigRoot = filepath.Join(c.Root, "config", "scanner-config")
	m, err := manifest.Load(c.ManifestPath)
	if err != nil {
		return model.Report{}, err
	}
	ex, err := exception.Load(c.ExceptionsPath, now)
	if err != nil {
		return model.Report{}, err
	}
	rpt := model.Report{SchemaVersion: "1.0", ScanID: fmt.Sprintf("scan-%d", now.UnixNano()), TargetID: target, TargetType: c.Request.Type, GeneratedAt: now, PolicyVersion: policyConfig.PolicyVersion, ScannerRuns: []model.ScannerRun{}, Findings: []model.Finding{}, Reasons: []string{}, Metadata: map[string]any{"network_default": "deny", "target_mount": "read-only"}}
	for _, name := range scanners.Required(c.Request) {
		start := time.Now().UTC()
		entry, ok := m.Get(name)
		run := model.ScannerRun{Scanner: name, StartedAt: start, Status: model.StatusFailed}
		if !ok {
			run.ErrorCode = "SCANNER_NOT_APPROVED"
			run.Message = "scanner absent from approved manifest"
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		run.Version = entry.Version
		run.ArtifactDigest = "sha256:" + entry.ArtifactSHA256
		if t, e := entry.AdvisoryReviewTime(); e == nil {
			run.AdvisoryCheckedAt = &t
		}
		iv := integrity.Verify(c.Root, entry)
		if !iv.OK {
			run.ErrorCode = "SCANNER_INTEGRITY_FAILURE"
			run.Message = iv.Error
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		if name == "osv-scanner" || name == "trivy" {
			meta, e := verifyDB(scanners.CachePath(entry, c.Request))
			if e != nil {
				run.ErrorCode = "DB_INTEGRITY_FAILURE"
				run.Message = e.Error()
				run.FinishedAt = time.Now().UTC()
				rpt.ScannerRuns = append(rpt.ScannerRuns, run)
				continue
			}
			run.DBVersion = meta.Version
			run.DBUpdatedAt = &meta.UpdatedAt
		}
		args, e := scanners.DockerCommand(entry, c.Request)
		if e != nil {
			run.Status = model.StatusUnsupported
			run.ErrorCode = "UNSUPPORTED_SECURITY_REQUIREMENT"
			run.Message = e.Error()
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		res := runner.Run(ctx, runner.Spec{Name: "docker", Args: args, Timeout: time.Duration(entry.TimeoutSeconds) * time.Second, OutputLimit: entry.OutputLimitBytes})
		if res.TimedOut {
			run.Status = model.StatusTimeout
			run.ErrorCode = "SCANNER_TIMEOUT"
			run.Message = "scanner exceeded timeout"
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		if res.Err != nil && !scanners.AllowedExitCode(name, res.ExitCode) {
			run.ErrorCode = "SCANNER_EXECUTION_FAILURE"
			run.Message = res.Err.Error()
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		findings, e := normalize.Parse(name, res.Output, normalize.Context{Scanner: name, Version: entry.Version, Digest: "sha256:" + entry.ArtifactSHA256, TargetID: target, ScorecardReviewBelow: policyConfig.ScorecardReviewBelow})
		if e != nil {
			run.ErrorCode = "MALFORMED_SCANNER_OUTPUT"
			run.Message = e.Error()
			run.FinishedAt = time.Now().UTC()
			rpt.ScannerRuns = append(rpt.ScannerRuns, run)
			continue
		}
		run.Status = model.StatusComplete
		run.FinishedAt = time.Now().UTC()
		rpt.ScannerRuns = append(rpt.ScannerRuns, run)
		rpt.Findings = append(rpt.Findings, findings...)
	}
	in := model.PolicyInput{SchemaVersion: "1.0", Now: now, TargetID: target, Findings: rpt.Findings, ScannerRuns: rpt.ScannerRuns, Exceptions: ex, PolicyVersion: policyConfig.PolicyVersion, Policy: policyConfig.Settings()}
	diagnosticReasons := policy.Evaluate(in).Reasons
	opa, ok := m.Get("opa")
	if !ok {
		rpt.Decision = model.DecisionError
		rpt.Reasons = append(diagnosticReasons, "OPA not approved in manifest")
	} else if iv := integrity.Verify(c.Root, opa); !iv.OK {
		rpt.Decision = model.DecisionError
		rpt.Reasons = append(diagnosticReasons, "OPA integrity verification failure")
	} else if d, e := policy.EvaluateRuntime(opa.WorkerImage, filepath.Join(c.Root, opa.RuntimePath), c.PolicyDir, in, 10*time.Second); e != nil {
		rpt.Decision = model.DecisionError
		rpt.Reasons = append(diagnosticReasons, e.Error())
	} else {
		rpt.Decision = d.Decision
		rpt.Reasons = d.Reasons
	}
	for _, f := range rpt.Findings {
		if x, ok := exception.ActiveFor(ex, f, target, now); ok {
			rpt.ExceptionsUsed = append(rpt.ExceptionsUsed, x)
		}
	}
	if err := report.WriteBundle(c.OutputPath, &rpt); err != nil {
		return rpt, err
	}
	u := "unknown"
	if x, e := user.Current(); e == nil {
		u = x.Username
	}
	ids := []string{}
	for _, x := range rpt.ExceptionsUsed {
		ids = append(ids, x.FindingID)
	}
	if err := audit.Append(c.AuditPath, audit.Record{Timestamp: now, Who: u, TargetID: target, ScanID: rpt.ScanID, PolicyVersion: policyConfig.PolicyVersion, ScannerRuns: rpt.ScannerRuns, Decision: rpt.Decision, ExceptionIDs: ids, ResultHash: rpt.ResultHash}); err != nil {
		return rpt, err
	}
	return rpt, nil
}

type dbMetadata = deploy.CacheMetadata

func verifyDB(cache string) (dbMetadata, error) {
	return deploy.VerifyCache(cache)
}
