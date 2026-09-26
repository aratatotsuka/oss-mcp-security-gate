package tests

import (
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/sandbox"
)

// These tests verify the generated isolation contract. A privileged Linux CI job
// must additionally run tests/runtime-isolation.sh against its container runtime.
func TestIsolationContract(t *testing.T) {
	target := t.TempDir()
	args, e := sandbox.DockerArgs(sandbox.DockerSpec{Image: "internal/scanner@sha256:" + strings.Repeat("b", 64), Target: target, Network: "none", Command: []string{"scan", "/target"}})
	if e != nil {
		t.Fatal(e)
	}
	joined := " " + strings.Join(args, " ") + " "
	required := []string{" --network none ", " --read-only ", " --user 65532:65532 ", " --cap-drop ALL ", " no-new-privileges:true ", " --pids-limit ", " --memory ", " --cpus ", "dst=/target,readonly"}
	for _, x := range required {
		if !strings.Contains(joined, x) {
			t.Errorf("missing control %s", x)
		}
	}
	for _, x := range []string{"docker.sock", "containerd.sock", "169.254.169.254", "--privileged", "--cap-add", "--network host", "--pid host", "--ipc host"} {
		if strings.Contains(joined, x) {
			t.Errorf("forbidden capability %s", x)
		}
	}
}
