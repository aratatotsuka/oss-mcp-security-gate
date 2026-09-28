package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/deploy"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/integrity"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/orchestrator"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/policy"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/report"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/scanners"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(64)
	}
	var code int
	switch os.Args[1] {
	case "scan":
		code = scan(os.Args[2:])
	case "verify-scanners":
		code = verify(os.Args[2:])
	case "policy-check":
		code = policyCheck(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
	default:
		usage()
		code = 64
	}
	os.Exit(code)
}
func usage() { fmt.Fprintln(os.Stderr, "security-gate <scan|verify-scanners|policy-check|version>") }

func rootDefault() string {
	if x := os.Getenv("SECURITY_GATE_ROOT"); x != "" {
		return x
	}
	p, e := os.Getwd()
	if e != nil {
		return "."
	}
	return p
}

func scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	root := fs.String("root", rootDefault(), "trusted Security Gate root")
	target := fs.String("target", "", "target directory")
	typ := fs.String("type", "oss", "oss or mcp-static")
	tools := fs.String("tools", "", "MCP tools JSON inside target")
	prompts := fs.String("prompts", "", "MCP prompts JSON inside target")
	resources := fs.String("resources", "", "MCP resources JSON inside target")
	repo := fs.String("repo", "", "public GitHub repository for Scorecard")
	out := fs.String("output", "security-gate-report.json", "report path")
	exceptions := fs.String("exceptions", "", "trusted exception JSON")
	if fs.Parse(args) != nil {
		return 64
	}
	if *target == "" && fs.NArg() == 1 {
		*target = fs.Arg(0)
	}
	if *target == "" || (*typ != "oss" && *typ != "mcp-static") {
		fmt.Fprintln(os.Stderr, "target and valid type are required")
		return 64
	}
	r, _ := filepath.Abs(*root)
	if e := os.MkdirAll(filepath.Join(r, "var", "audit"), 0700); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 4
	}
	o, _ := filepath.Abs(*out)
	rpt, e := orchestrator.Scan(context.Background(), orchestrator.Config{Root: r, ManifestPath: filepath.Join(r, "config", "scanners.yaml"), PolicyDir: filepath.Join(r, "policies"), ExceptionsPath: *exceptions, AuditPath: filepath.Join(r, "var", "audit", "audit.jsonl"), OutputPath: o, Request: scanners.Request{Target: *target, Type: *typ, Tools: *tools, Prompts: *prompts, Resources: *resources, Repo: *repo}})
	if e != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", e)
		return 4
	}
	paths := report.Paths(o)
	b, _ := json.MarshalIndent(map[string]any{"decision": rpt.Decision, "reasons": rpt.Reasons, "report": o, "report_html": paths.HTML, "report_markdown": paths.Markdown, "findings_csv": paths.FindingsCSV, "review_required_csv": paths.ReviewRequiredCSV}, "", "  ")
	fmt.Println(string(b))
	return decisionCode(rpt.Decision)
}

func verify(args []string) int {
	fs := flag.NewFlagSet("verify-scanners", flag.ContinueOnError)
	root := fs.String("root", rootDefault(), "trusted Security Gate root")
	typ := fs.String("type", "", "verify only oss or mcp-static scanners and OPA")
	manifestPath := fs.String("manifest", "", "candidate manifest to verify before activation")
	if fs.Parse(args) != nil {
		return 64
	}
	r, _ := filepath.Abs(*root)
	if *typ != "" && *typ != "oss" && *typ != "mcp-static" {
		fmt.Fprintln(os.Stderr, "invalid type")
		return 64
	}
	if *manifestPath == "" {
		*manifestPath = filepath.Join(r, "config", "scanners.yaml")
	}
	m, e := manifest.Load(*manifestPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 4
	}
	all := true
	results := []integrity.Result{}
	if *typ != "" {
		for _, name := range append(scanners.Required(scanners.Request{Type: *typ}), "opa") {
			if _, ok := m.Get(name); !ok {
				fmt.Fprintln(os.Stderr, "required scanner missing:", name)
				return 4
			}
		}
	}
	for _, s := range m.Scanners {
		if *typ != "" {
			wanted := s.Name == "opa"
			for _, n := range scanners.Required(scanners.Request{Type: *typ}) {
				wanted = wanted || n == s.Name
			}
			if !wanted {
				continue
			}
		}
		x := integrity.Verify(r, s)
		if x.OK && (s.Name != "opa" || s.WorkerImage != "") {
			if err := integrity.VerifyImage(context.Background(), s.WorkerImage); err != nil {
				x.OK = false
				x.Error = err.Error()
			}
		}
		if x.OK && (s.Name == "osv-scanner" || s.Name == "trivy") {
			if _, err := deploy.VerifyCache(scanners.CachePath(s, scanners.Request{CacheRoot: filepath.Join(r, "var", "cache")})); err != nil {
				x.OK = false
				x.Error = "DB_INTEGRITY_FAILURE: " + err.Error()
			}
		}
		results = append(results, x)
		all = all && x.OK
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(b))
	if !all {
		return 4
	}
	return 0
}

func policyCheck(args []string) int {
	fs := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	root := fs.String("root", rootDefault(), "trusted Security Gate root")
	if fs.Parse(args) != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "policy-check requires one PolicyInput JSON")
		return 64
	}
	r, _ := filepath.Abs(*root)
	m, e := manifest.Load(filepath.Join(r, "config", "scanners.yaml"))
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 4
	}
	opa, ok := m.Get("opa")
	if !ok {
		fmt.Fprintln(os.Stderr, "OPA is not approved")
		return 4
	}
	if v := integrity.Verify(r, opa); !v.OK {
		fmt.Fprintln(os.Stderr, v.Error)
		return 4
	}
	in, e := policy.LoadInput(fs.Arg(0))
	if e != nil {
		fmt.Fprintln(os.Stderr, "malformed policy input:", e)
		return 4
	}
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	policyConfig, e := policy.LoadConfig(filepath.Join(r, "config", "policy.yaml"))
	if e != nil {
		fmt.Fprintln(os.Stderr, "load policy config:", e)
		return 4
	}
	in.PolicyVersion = policyConfig.PolicyVersion
	in.Policy = policyConfig.Settings()
	d, e := policy.EvaluateRuntime(opa.WorkerImage, filepath.Join(r, opa.RuntimePath), filepath.Join(r, "policies"), in, 10*time.Second)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 4
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(b))
	return decisionCode(d.Decision)
}

func decisionCode(d model.Decision) int {
	switch d {
	case model.DecisionAllow:
		return 0
	case model.DecisionReview:
		return 2
	case model.DecisionBlock:
		return 3
	default:
		return 4
	}
}
