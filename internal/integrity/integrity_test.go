package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
)

func TestHashMismatch(t *testing.T) {
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "scanner"), []byte("hostile"), 0600); e != nil {
		t.Fatal(e)
	}
	r := Verify(d, manifest.Scanner{Name: "x", RuntimePath: "scanner", ArtifactSHA256: strings.Repeat("0", 64)})
	if r.OK || !strings.Contains(r.Error, "HASH_MISMATCH") {
		t.Fatalf("unexpected: %#v", r)
	}
}

func TestVerifiedArtifact(t *testing.T) {
	d := t.TempDir()
	data := []byte("approved scanner")
	if err := os.WriteFile(filepath.Join(d, "scanner"), data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	r := Verify(d, manifest.Scanner{Name: "x", RuntimePath: "scanner", ArtifactSHA256: want})
	if !r.OK || r.Error != "" || r.Actual != want {
		t.Fatalf("verified artifact rejected: %#v", r)
	}
}

func TestMissingArtifactFailsClosed(t *testing.T) {
	r := Verify(t.TempDir(), manifest.Scanner{Name: "x", RuntimePath: "missing", ArtifactSHA256: strings.Repeat("0", 64)})
	if r.OK || !strings.Contains(r.Error, "UNVERIFIED_SCANNER_ARTIFACT") {
		t.Fatalf("missing artifact accepted: %#v", r)
	}
}
