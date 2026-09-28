package deploy

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractionRejectsArchiveLinksAndTraversal(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind byte
	}{{"../trivy", tar.TypeReg}, {"trivy", tar.TypeSymlink}, {"trivy", tar.TypeLink}} {
		t.Run(tc.name+string(tc.kind), func(t *testing.T) {
			d := t.TempDir()
			p := filepath.Join(d, "artifact.tar.gz")
			f, _ := os.Create(p)
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			payload := []byte("\x7fELFfixture")
			size := int64(0)
			if tc.kind == tar.TypeReg {
				size = int64(len(payload))
			}
			tw.WriteHeader(&tar.Header{Name: tc.name, Typeflag: tc.kind, Size: size, Linkname: "outside"})
			if size > 0 {
				tw.Write(payload)
			}
			tw.Close()
			gz.Close()
			f.Close()
			out := filepath.Join(d, "scanner")
			if err := ExtractBinary(p, "trivy", out); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("rejected archive wrote executable")
			}
		})
	}
}

func TestCacheRejectsMalformedInventory(t *testing.T) {
	for _, tc := range []struct{ path, hash string }{
		{"missing.bin", ""}, // Missing keys must not compare equal to an empty hash.
		{"db.bin", ""}, {"db.bin", strings.Repeat("g", 64)},
		{"db.bin", strings.Repeat("A", 64)}, {"../db.bin", strings.Repeat("a", 64)},
		{"./db.bin", strings.Repeat("a", 64)}, {"db\\file", strings.Repeat("a", 64)},
	} {
		t.Run(tc.path+tc.hash, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, "db.bin"), []byte("database"), 0600); err != nil {
				t.Fatal(err)
			}
			m := CacheMetadata{Version: "generation", UpdatedAt: time.Now(), Files: map[string]string{tc.path: tc.hash}}
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "metadata.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCache(d); err == nil {
				t.Fatal("malformed inventory accepted")
			}
		})
	}
}

func TestLegacyCacheVerifiesArtifact(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "db.bin")
	if err := os.WriteFile(file, []byte("database"), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := HashFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{h, "", strings.Repeat("g", 64)} {
		m := CacheMetadata{Version: "legacy", UpdatedAt: time.Now(), Artifact: "db.bin", SHA256: hash}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "metadata.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyCache(d)
		if (err == nil) != (hash == h) {
			t.Fatalf("hash %q: %v", hash, err)
		}
	}
}

func TestExtractionSelectsExecutable(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "artifact.tar.gz")
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	payload := []byte("\x7fELFfixture")
	tw.WriteHeader(&tar.Header{Name: "trivy", Typeflag: tar.TypeReg, Size: int64(len(payload))})
	tw.Write(payload)
	tw.Close()
	gz.Close()
	f.Close()
	out := filepath.Join(d, "scanner")
	if err := ExtractBinary(p, "trivy", out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != string(payload) {
		t.Fatal("binary changed")
	}
}

func TestCacheInventoryDetectsTamperingAndUnlistedFiles(t *testing.T) {
	for _, mutate := range []string{"modify", "add", "remove"} {
		t.Run(mutate, func(t *testing.T) {
			d := t.TempDir()
			p := filepath.Join(d, "db.bin")
			os.WriteFile(p, []byte("database"), 0600)
			if err := Snapshot(d, "generation", time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCache(d); err != nil {
				t.Fatal(err)
			}
			switch mutate {
			case "modify":
				os.WriteFile(p, []byte("tampered"), 0600)
			case "add":
				os.WriteFile(filepath.Join(d, "extra.bin"), []byte("extra"), 0600)
			case "remove":
				os.Remove(p)
			}
			if _, err := VerifyCache(d); err == nil {
				t.Fatal("tampered cache accepted")
			}
		})
	}
}
