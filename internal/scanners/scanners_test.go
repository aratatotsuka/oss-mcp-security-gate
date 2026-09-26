package scanners

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
)

func TestRequiredSelectsScannerByTargetType(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  Request
		want string
	}{
		{"MCP static", Request{Type: "mcp-static"}, "mcp-scanner"},
		{"OSS", Request{Type: "oss"}, "osv-scanner,trivy,gitleaks"},
		{"OSS with repository", Request{Type: "oss", Repo: "org/repo"}, "osv-scanner,trivy,gitleaks,scorecard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(Required(tc.req), ","); got != tc.want {
				t.Fatalf("required scanners = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDockerCommandRejectsUnprovisionedWorker(t *testing.T) {
	s := manifest.Scanner{Name: "trivy", WorkerImage: "scanner@sha256:" + strings.Repeat("0", 64)}
	if _, err := DockerCommand(s, Request{}); err == nil || !strings.Contains(err.Error(), "not been provisioned") {
		t.Fatalf("unprovisioned worker accepted: %v", err)
	}
}

func TestDockerCommandRejectsMCPSnapshotOutsideTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	s := manifest.Scanner{Name: "mcp-scanner", WorkerImage: "scanner@sha256:" + strings.Repeat("a", 64), Network: "none"}
	req := Request{Type: "mcp-static", Target: root, Tools: filepath.Join(outside, "tools.json"), CacheRoot: t.TempDir(), ConfigRoot: t.TempDir()}
	if _, err := DockerCommand(s, req); err == nil || !strings.Contains(err.Error(), "inside target directory") {
		t.Fatalf("outside MCP snapshot accepted: %v", err)
	}
}
