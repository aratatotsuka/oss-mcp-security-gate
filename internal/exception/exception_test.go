package exception

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func TestLoadRejectsMissingRequiredFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "exceptions.json")
	if err := os.WriteFile(p, []byte(`[{"finding_id":"CVE-1","scope":"t"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, time.Time{}); err == nil {
		t.Fatal("incomplete exception accepted")
	}
}

func TestActiveForRequiresMatchingScopeAndUnexpiredTime(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	f := model.Finding{FindingID: "CVE-1"}
	for _, tc := range []struct {
		name, scope string
		expires     time.Time
		want        bool
	}{
		{"target scope", "t", now.Add(time.Second), true},
		{"wildcard scope", "*", now.Add(time.Second), true},
		{"different scope", "other", now.Add(time.Second), false},
		{"expired at boundary", "t", now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := ActiveFor([]model.Exception{{FindingID: f.FindingID, Scope: tc.scope, ExpiresAt: tc.expires}}, f, "t", now)
			if ok != tc.want {
				t.Fatalf("active = %v, want %v", ok, tc.want)
			}
		})
	}
}
