package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyDBAcceptsMatchingArtifact(t *testing.T) {
	d := t.TempDir()
	data := []byte("database snapshot")
	if err := os.WriteFile(filepath.Join(d, "db.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	want := dbMetadata{Version: "1", UpdatedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Artifact: "db.bin", SHA256: hex.EncodeToString(h[:])}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "metadata.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := verifyDB(d)
	if err != nil || got.Version != want.Version || got.SHA256 != want.SHA256 {
		t.Fatalf("matching DB rejected: %#v %v", got, err)
	}
}

func TestVerifyDBRejectsHashMismatch(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "db.bin"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := dbMetadata{Version: "1", UpdatedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Artifact: "db.bin", SHA256: strings.Repeat("0", 64)}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "metadata.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDB(d); err == nil || !strings.Contains(err.Error(), "DB hash mismatch") {
		t.Fatalf("tampered DB accepted: %v", err)
	}
}

func TestVerifyDBRejectsEscapingArtifact(t *testing.T) {
	d := t.TempDir()
	meta := dbMetadata{Version: "1", UpdatedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Artifact: filepath.Join("..", "outside.bin"), SHA256: strings.Repeat("0", 64)}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "metadata.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDB(d); err == nil || !strings.Contains(err.Error(), "DB artifact escapes cache") {
		t.Fatalf("escaping DB artifact accepted: %v", err)
	}
}
