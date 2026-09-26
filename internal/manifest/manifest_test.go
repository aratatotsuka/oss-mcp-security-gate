package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validManifest() Manifest {
	return Manifest{SchemaVersion: "1.0", Scanners: []Scanner{{
		Name: "trivy", Version: "1", ArtifactURI: "https://example.invalid/trivy",
		RuntimePath: "scanner", ArtifactSHA256: strings.Repeat("a", 64),
		WorkerImage: "scanner@sha256:" + strings.Repeat("b", 64),
		Network:     "none", AdvisoryCheckedDate: "2026-09-24",
	}}}
}

func writeManifest(t *testing.T, m Manifest) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scanners.json")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAcceptsValidManifest(t *testing.T) {
	m, err := Load(writeManifest(t, validManifest()))
	if err != nil || len(m.Scanners) != 1 || m.Scanners[0].Name != "trivy" {
		t.Fatalf("valid scanner rejected: %#v %v", m, err)
	}
}

func TestLoadRejectsUnpinnedWorkerImage(t *testing.T) {
	m := validManifest()
	m.Scanners[0].WorkerImage = "scanner:latest"
	if _, err := Load(writeManifest(t, m)); err == nil || !strings.Contains(err.Error(), "digest-pinned") {
		t.Fatalf("mutable worker image accepted: %v", err)
	}
}

func TestLoadRejectsDuplicateScanner(t *testing.T) {
	m := validManifest()
	m.Scanners = append(m.Scanners, m.Scanners[0])
	if _, err := Load(writeManifest(t, m)); err == nil || !strings.Contains(err.Error(), "duplicate scanner") {
		t.Fatalf("duplicate scanner accepted: %v", err)
	}
}

func TestLoadRejectsInvalidArtifactHash(t *testing.T) {
	m := validManifest()
	m.Scanners[0].ArtifactSHA256 = strings.Repeat("Z", 64)
	if _, err := Load(writeManifest(t, m)); err == nil || !strings.Contains(err.Error(), "artifact_sha256") {
		t.Fatalf("invalid artifact hash accepted: %v", err)
	}
}

func TestLoadRejectsMalformedWorkerDigest(t *testing.T) {
	m := validManifest()
	m.Scanners[0].WorkerImage = "scanner@sha256:not-a-digest"
	if _, err := Load(writeManifest(t, m)); err == nil {
		t.Fatal("malformed worker SHA-256 digest accepted")
	}
}
