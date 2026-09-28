package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func TestWriteBundlePreservesJSONForOutputExtensions(t *testing.T) {
	for _, name := range []string{"scan.json", "scan.html", "scan.md", "scan.csv", "scan", "scan.JSON"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			r := model.Report{Decision: model.DecisionReview, TargetID: "extension-test"}
			if err := WriteBundle(path, &r); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got model.Report
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("authoritative JSON was overwritten: %v", err)
			}
			if got.Decision != r.Decision || got.TargetID != r.TargetID || got.ResultHash != r.ResultHash {
				t.Fatalf("JSON report changed: %#v", got)
			}
			views := Paths(path)
			seen := map[string]bool{path: true}
			for _, sibling := range []string{views.HTML, views.Markdown, views.FindingsCSV, views.ReviewRequiredCSV} {
				if seen[sibling] {
					t.Fatalf("report paths collide: %s", sibling)
				}
				seen[sibling] = true
				if _, err := os.Stat(sibling); err != nil {
					t.Fatalf("missing view: %v", err)
				}
			}
		})
	}
}
