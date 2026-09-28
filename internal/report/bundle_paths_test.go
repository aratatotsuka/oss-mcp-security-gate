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

func TestWriteBundleStageFailureDoesNotPublish(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, badView := range []int{0, 1, 2, 3} {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.json")
			views := Paths(path)
			paths := []string{views.HTML, views.Markdown, views.FindingsCSV, views.ReviewRequiredCSV, path}
			if existing {
				old := model.Report{Decision: model.DecisionBlock, TargetID: "previous"}
				if err := WriteBundle(path, &old); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(paths[badView]); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(paths[badView], 0700); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for i, p := range paths {
				if existing && i != badView {
					b, err := os.ReadFile(p)
					if err != nil {
						t.Fatal(err)
					}
					before[p] = string(b)
				}
			}
			if err := WriteBundle(path, &model.Report{Decision: model.DecisionAllow, TargetID: "new"}); err == nil {
				t.Fatal("non-regular view was accepted")
			}
			for i, p := range paths {
				if i == badView {
					continue
				}
				b, err := os.ReadFile(p)
				if existing {
					if err != nil || string(b) != before[p] {
						t.Fatalf("previous bundle changed: %s, %v", p, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("failed bundle published %s: %v", p, err)
				}
			}
			temps, err := filepath.Glob(filepath.Join(dir, ".security-gate-report-*"))
			if err != nil || len(temps) != 0 {
				t.Fatalf("staged files leaked: %v, %v", temps, err)
			}
		}
	}
}
