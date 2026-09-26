package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func TestWriteMasksSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.json")
	r := model.Report{
		Findings: []model.Finding{{Title: "AKIAABCDEFGHIJKLMNOP", Evidence: map[string]any{"secret": "plain"}}},
		ExceptionsUsed: []model.Exception{{
			Justification: "contains ghp_abcdefghijklmnopqrstuvwxyz123456",
			Evidence:      map[string]any{"token": "plain", "nested": []any{"AKIAABCDEFGHIJKLMNOP"}},
		}},
	}
	if e := Write(p, &r); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "AKIAABCDEFGHIJKLMNOP") || strings.Contains(string(b), "ghp_abcdefghijklmnopqrstuvwxyz123456") || strings.Contains(string(b), "plain") {
		t.Fatalf("secret leaked: %s", b)
	}
	if !strings.HasPrefix(r.ResultHash, "sha256:") {
		t.Fatal("missing hash")
	}
}

func TestWriteRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	r := model.Report{}
	if err := Write(link, &r); err == nil {
		t.Fatal("symlink destination accepted")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "do not overwrite" {
		t.Fatalf("symlink target changed: %q, %v", b, err)
	}
}
