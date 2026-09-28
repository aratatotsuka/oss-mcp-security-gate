package scanners

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/sandbox"
)

type Request struct{ Target, Type, Tools, Prompts, Resources, Repo, CacheRoot, ConfigRoot string }

func Required(r Request) []string {
	if r.Type == "mcp-static" {
		return []string{"mcp-scanner"}
	}
	xs := []string{"osv-scanner", "trivy", "gitleaks"}
	if r.Repo != "" {
		xs = append(xs, "scorecard")
	}
	return xs
}

func DockerCommand(s manifest.Scanner, r Request) ([]string, error) {
	if strings.Contains(s.WorkerImage, "sha256:0000000000000000000000000000000000000000000000000000000000000000") {
		return nil, fmt.Errorf("UNSUPPORTED_SECURITY_REQUIREMENT: verified internal worker image has not been provisioned")
	}
	cmd := []string{}
	switch s.Name {
	case "osv-scanner":
		cmd = []string{"scan", "source", "--recursive", "--format=json", "--offline", "--local-db-path=/gate/cache", "--no-call-analysis", "--config=/gate/config/osv-scanner.toml", "/target"}
	case "trivy":
		cmd = []string{"fs", "--config=/gate/config/trivy.yaml", "--format=json", "--scanners=vuln,misconfig,secret", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan", "--disable-telemetry", "--no-progress", "--cache-backend=memory", "--cache-dir=/gate/cache", "/target"}
	case "gitleaks":
		cmd = []string{"dir", "/target", "--config=/gate/config/gitleaks.toml", "--report-format=json", "--report-path=/dev/stdout", "--redact=100", "--no-banner", "--max-archive-depth=0"}
	case "mcp-scanner":
		cmd = []string{"static", "--analyzers", "yara", "--format", "raw"}
		for flag, p := range map[string]string{"--tools": r.Tools, "--prompts": r.Prompts, "--resources": r.Resources} {
			if p != "" {
				rel, err := safeRelative(r.Target, p)
				if err != nil {
					return nil, err
				}
				cmd = append(cmd, flag, "/target/"+filepath.ToSlash(rel))
			}
		}
		if len(cmd) == 5 {
			return nil, fmt.Errorf("at least one MCP snapshot is required")
		}
	case "scorecard":
		return nil, fmt.Errorf("UNSUPPORTED_SECURITY_REQUIREMENT: Scorecard requires a dedicated GitHub-only egress proxy")
	default:
		return nil, fmt.Errorf("unknown scanner %s", s.Name)
	}
	if r.CacheRoot == "" {
		return nil, fmt.Errorf("trusted cache root is required")
	}
	if r.ConfigRoot == "" {
		return nil, fmt.Errorf("trusted config root is required")
	}
	cache := CachePath(s, r)
	if s.Name == "gitleaks" {
		cache = "" // Gitleaks needs no DB; do not mount a nonexistent cache directory.
	}
	args, err := sandbox.DockerArgs(sandbox.DockerSpec{Image: s.WorkerImage, Target: r.Target, Cache: cache, Config: r.ConfigRoot, Network: s.Network, Command: cmd, Limits: sandbox.Limits{CPUs: "1.0", Memory: "768m", Tmpfs: "64m", PIDs: 128}})
	if err != nil {
		return nil, err
	}
	args = append([]string{args[0], "--pull", "never"}, args[1:]...)
	if sandbox.ContainsForbidden(args) {
		return nil, fmt.Errorf("prohibited Docker capability")
	}
	return args, nil
}

func CachePath(s manifest.Scanner, r Request) string {
	return filepath.Join(r.CacheRoot, s.Name, s.CacheGeneration)
}

func safeRelative(root, p string) (string, error) {
	a, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	b, e := filepath.Abs(p)
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(a, b)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("snapshot must be inside target directory")
	}
	return rel, nil
}

func AllowedExitCode(name string, code int) bool {
	if code == 0 {
		return true
	}
	return code == 1 && (name == "osv-scanner" || name == "gitleaks")
}
