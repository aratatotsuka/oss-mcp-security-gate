package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validManifest() Manifest {
	return Manifest{SchemaVersion: "1.0", Scanners: []Scanner{{
		Name: "trivy", Version: "1", ArtifactURI: "https://example.invalid/trivy",
		RuntimePath: "scanner", ArtifactSHA256: strings.Repeat("a", 64),
		WorkerImage: "scanner@sha256:" + strings.Repeat("b", 64),
		Network:     "none", AdvisoryCheckedDate: "2026-09-24",
	}}}
}

func TestAdvisoryReviewTime(t *testing.T) {
	for _, tc := range []struct {
		stamp, want string
		valid       bool
	}{
		{"", "2026-09-24T00:00:00Z", true},
		{"2026-09-24T01:02:03.1234567Z", "2026-09-24T01:02:03.1234567Z", true},
		{"2026-09-24T10:02:03+09:00", "2026-09-24T01:02:03Z", true},
		{"2026-09-24", "", false},
		{"2026-09-25T00:00:00Z", "", false},
	} {
		t.Run(tc.stamp, func(t *testing.T) {
			m := validManifest()
			m.Scanners[0].AdvisoryCheckedAt = tc.stamp
			if _, err := Load(writeManifest(t, m)); (err == nil) != tc.valid {
				t.Fatalf("load: %v", err)
			}
			if !tc.valid {
				return
			}
			got, err := m.Scanners[0].AdvisoryReviewTime()
			if err != nil || got.Format(time.RFC3339Nano) != tc.want {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
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
