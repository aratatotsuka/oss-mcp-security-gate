package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CacheMetadata struct {
	Version   string            `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	Artifact  string            `json:"artifact,omitempty"`
	SHA256    string            `json:"sha256,omitempty"`
	Files     map[string]string `json:"files,omitempty"`
}

func HashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Inventory(root string) (map[string]string, error) {
	xs := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("cache symlink prohibited: %s", p)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("cache special file prohibited: %s", p)
		}
		r, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if r == "metadata.json" {
			return nil
		}
		if len(xs) >= 100000 {
			return fmt.Errorf("cache file count limit exceeded")
		}
		h, err := HashFile(p)
		if err != nil {
			return err
		}
		xs[filepath.ToSlash(r)] = h
		return nil
	})
	return xs, err
}

func Snapshot(root, version string, updated time.Time) error {
	xs, err := Inventory(root)
	if err != nil {
		return err
	}
	if len(xs) == 0 || version == "" || updated.IsZero() {
		return fmt.Errorf("empty cache snapshot")
	}
	b, err := json.MarshalIndent(CacheMetadata{Version: version, UpdatedAt: updated.UTC(), Files: xs}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "metadata.json"), b, 0600)
}

func VerifyCache(root string) (CacheMetadata, error) {
	var m CacheMetadata
	b, err := os.ReadFile(filepath.Join(root, "metadata.json"))
	if err != nil {
		return m, fmt.Errorf("DB metadata unavailable: %w", err)
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("DB metadata malformed: %w", err)
	}
	if m.Version == "" || m.UpdatedAt.IsZero() {
		return m, fmt.Errorf("DB metadata incomplete")
	}
	if len(m.Files) > 0 {
		xs, err := Inventory(root)
		if err != nil {
			return m, err
		}
		if len(xs) != len(m.Files) {
			return m, fmt.Errorf("DB file inventory mismatch")
		}
		for p, h := range m.Files {
			actual, exists := xs[p]
			if !validCachePath(p) || !validSHA256(h) || !exists || actual != h {
				return m, fmt.Errorf("DB hash mismatch: %s", p)
			}
		}
		return m, nil
	}
	if !validSHA256(m.SHA256) || m.Artifact == "" {
		return m, fmt.Errorf("DB metadata incomplete")
	}
	p := filepath.Join(root, filepath.Clean(m.Artifact))
	r, err := filepath.Rel(root, p)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return m, fmt.Errorf("DB artifact escapes cache")
	}
	if !validCachePath(m.Artifact) {
		return m, fmt.Errorf("DB artifact path is not canonical")
	}
	h, err := HashFile(p)
	if err != nil {
		return m, err
	}
	if h != m.SHA256 {
		return m, fmt.Errorf("DB hash mismatch")
	}
	return m, nil
}

func validSHA256(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

func validCachePath(s string) bool {
	return s != "" && s != "." && s != "metadata.json" &&
		!strings.ContainsAny(s, "\\:\x00") && !strings.HasPrefix(s, "/") &&
		filepath.ToSlash(filepath.Clean(s)) == s &&
		s != ".." && !strings.HasPrefix(s, "../")
}
