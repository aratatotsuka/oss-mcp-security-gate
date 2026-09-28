package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/containerref"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/runner"
)

func VerifyImage(ctx context.Context, ref string) error {
	if !containerref.Provisioned(ref) {
		return fmt.Errorf("UNVERIFIED_SCANNER_IMAGE: immutable image is not provisioned")
	}
	r := runner.Run(ctx, runner.Spec{Name: "docker", Args: []string{"image", "inspect", ref}, Timeout: 15 * time.Second, OutputLimit: 1 << 20})
	if r.Err != nil {
		return fmt.Errorf("UNVERIFIED_SCANNER_IMAGE: %w: %s", r.Err, r.Stderr)
	}
	var xs []struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if json.Unmarshal(r.Output, &xs) != nil || len(xs) != 1 {
		return fmt.Errorf("UNVERIFIED_SCANNER_IMAGE: malformed inspection")
	}
	if imageMatches(ref, xs[0].ID, xs[0].RepoDigests) {
		return nil
	}
	return fmt.Errorf("UNVERIFIED_SCANNER_IMAGE: digest does not match")
}

func imageMatches(ref, id string, repoDigests []string) bool {
	if containerref.Same(ref, id) {
		return true
	}
	for _, d := range repoDigests {
		if containerref.Same(ref, d) {
			return true
		}
	}
	return false
}
