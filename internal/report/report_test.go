package report

import (
	"encoding/csv"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

const (
	testAWSKey      = "AKIA" + "ABCDEFGHIJKLMNOP"
	testGitHubToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
)

func TestWriteMasksSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.json")
	r := model.Report{
		Reasons:     []string{"failed: " + testAWSKey},
		ScannerRuns: []model.ScannerRun{{Message: testGitHubToken}},
		Findings:    []model.Finding{{Title: testAWSKey, Evidence: map[string]any{"secret": "plain"}}},
		ExceptionsUsed: []model.Exception{{
			Justification: "contains " + testGitHubToken,
			Evidence:      map[string]any{"token": "plain", "nested": []any{testAWSKey}},
		}},
	}
	if e := Write(p, &r); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), testAWSKey) || strings.Contains(string(b), testGitHubToken) || strings.Contains(string(b), "plain") {
		t.Fatalf("secret leaked: %s", b)
	}
	if !strings.HasPrefix(r.ResultHash, "sha256:") {
		t.Fatal("missing hash")
	}
}

func TestMarkdownTreatsUntrustedContentAsText(t *testing.T) {
	values := []string{
		"![pixel](https://example.org/pixel)", "[link](https://example.org)",
		"<https://example.org> <img src=x>", "`code` **bold** _italic_ ~~strike~~",
		"# heading\n| column |", "[reference]: https://example.org", "日本語 & &#33; \\ path",
	}
	for _, value := range values {
		got := mdCell(value)
		if decoded := html.UnescapeString(got); decoded != strings.ReplaceAll(value, "\n", " ") {
			t.Fatalf("text changed: %q -> %q", value, decoded)
		}
		for _, syntax := range []string{"![", "](", "<img", "<https:", "https://", "`", "**", "~~", "|"} {
			if strings.Contains(got, syntax) {
				t.Fatalf("active syntax %q in %q", syntax, got)
			}
		}
	}
	attack := values[0]
	md := string(renderMarkdown(reportView{
		Target: attack, Reasons: []string{attack},
		Scanners: []scannerView{{Message: attack}}, Findings: []findingView{{ID: attack, Title: attack}},
	}))
	if strings.Contains(md, attack) || strings.Count(md, mdCell(attack)) != 5 {
		t.Fatalf("unescaped dynamic report field: %s", md)
	}
}

func TestWriteBundleProducesSafeTriageViews(t *testing.T) {
	base := filepath.Join(t.TempDir(), "scan")
	r := model.Report{
		Decision:    model.DecisionReview,
		TargetID:    "project <sample>",
		Reasons:     []string{"scanner <failed>"},
		ScannerRuns: []model.ScannerRun{{Scanner: "trivy", Status: model.StatusFailed, Message: testAWSKey}},
		Findings: []model.Finding{
			{FindingID: "low", Severity: model.SeverityLow, Title: "low item", ScanStatus: model.StatusComplete},
			{FindingID: "high", Severity: model.SeverityHigh, Title: "<script>alert(1)</script> " + testAWSKey, Component: " =HYPERLINK(\"https://evil\")", ScanStatus: model.StatusComplete},
		},
	}
	if err := WriteBundle(base+".json", &r); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".json", ".html", ".md", "-findings.csv", "-review-required.csv"} {
		if _, err := os.Stat(base + suffix); err != nil {
			t.Fatalf("missing %s: %v", suffix, err)
		}
	}
	html, _ := os.ReadFile(base + ".html")
	if strings.Contains(string(html), "<script>") || strings.Contains(string(html), testAWSKey) || !strings.Contains(string(html), "&lt;script&gt;") {
		t.Fatalf("unsafe HTML: %s", html)
	}
	md, _ := os.ReadFile(base + ".md")
	if strings.Contains(string(md), "<script>") || !strings.Contains(string(md), "FAILED") {
		t.Fatalf("unsafe or incomplete Markdown: %s", md)
	}
	f, err := os.Open(base + "-review-required.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][0] != "high" || !strings.HasPrefix(rows[1][4], "'") {
		t.Fatalf("unexpected attention rows: %#v", rows)
	}
}

func TestWriteBundleRejectsSymlinkArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "scan.html")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := WriteBundle(filepath.Join(dir, "scan.json"), &model.Report{}); err == nil {
		t.Fatal("symlink artifact accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "scan.json")); !os.IsNotExist(err) {
		t.Fatalf("failed bundle published authoritative JSON: %v", err)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "preserve" {
		t.Fatalf("symlink target changed: %q, %v", b, err)
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
