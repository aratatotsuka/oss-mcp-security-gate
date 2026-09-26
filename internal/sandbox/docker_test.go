package sandbox

import (
	"strings"
	"testing"
)

func TestHardenedDockerArgs(t *testing.T) {
	args, e := DockerArgs(DockerSpec{Image: "registry.local/scanner@sha256:" + strings.Repeat("a", 64), Target: t.TempDir(), Network: "none", Command: []string{"scan", "/target"}})
	if e != nil {
		t.Fatal(e)
	}
	s := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --network none ", " --read-only ", " --cap-drop ALL ", " no-new-privileges:true ", "dst=/target,readonly"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %s", want, s)
		}
	}
	if ContainsForbidden(args) {
		t.Fatal("generated forbidden option")
	}
}
func TestRejectUnpinnedAndNetwork(t *testing.T) {
	if _, e := DockerArgs(DockerSpec{Image: "scanner:latest", Target: t.TempDir(), Network: "none"}); e == nil {
		t.Fatal("latest accepted")
	}
	if _, e := DockerArgs(DockerSpec{Image: "x@sha256:" + strings.Repeat("a", 64), Target: t.TempDir(), Network: "restricted"}); e == nil {
		t.Fatal("unenforced restricted network accepted")
	}
}
func TestForbiddenSockets(t *testing.T) {
	if !ContainsForbidden([]string{"run", "-v", "/var/run/docker.sock:/sock"}) {
		t.Fatal("docker socket not rejected")
	}
}

func TestRejectMalformedImageDigest(t *testing.T) {
	if _, err := DockerArgs(DockerSpec{Image: "scanner@sha256:not-a-digest", Target: t.TempDir(), Network: "none"}); err == nil {
		t.Fatal("malformed image SHA-256 digest accepted")
	}
}
