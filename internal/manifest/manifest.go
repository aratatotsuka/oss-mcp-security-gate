package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/containerref"
)

type Scanner struct {
	Name                   string   `json:"name"`
	Version                string   `json:"approved_version"`
	ArtifactURI            string   `json:"artifact_uri"`
	ArtifactSHA256         string   `json:"artifact_sha256"`
	RuntimePath            string   `json:"runtime_path"`
	WorkerImage            string   `json:"worker_image"`
	CacheGeneration        string   `json:"cache_generation,omitempty"`
	SignatureVerification  string   `json:"signature_verification"`
	ProvenanceVerification string   `json:"provenance_verification"`
	ApprovedDate           string   `json:"approved_date"`
	AdvisoryCheckedDate    string   `json:"security_advisory_checked_date"`
	AdvisoryCheckedAt      string   `json:"security_advisory_checked_at,omitempty"`
	Network                string   `json:"network"`
	AllowedHosts           []string `json:"allowed_hosts,omitempty"`
	TimeoutSeconds         int      `json:"timeout_seconds"`
	OutputLimitBytes       int64    `json:"output_limit_bytes"`
}

type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	Scanners      []Scanner `json:"scanners"`
}

func Load(path string) (Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest must be JSON-compatible YAML: %w", err)
	}
	if m.SchemaVersion == "" || len(m.Scanners) == 0 {
		return Manifest{}, fmt.Errorf("malformed scanner manifest")
	}
	seen := map[string]bool{}
	for _, s := range m.Scanners {
		if s.Name == "" || s.Version == "" || s.ArtifactURI == "" || s.RuntimePath == "" {
			return Manifest{}, fmt.Errorf("scanner entry has required empty field")
		}
		if s.Name != "opa" || s.WorkerImage != "" {
			if _, ok := containerref.Digest(s.WorkerImage); !ok {
				return Manifest{}, fmt.Errorf("%s: worker_image must be digest-pinned", s.Name)
			}
		}
		if s.CacheGeneration != "" && (s.CacheGeneration == "." || s.CacheGeneration == ".." || strings.Trim(s.CacheGeneration, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "") {
			return Manifest{}, fmt.Errorf("%s: invalid cache generation", s.Name)
		}
		if len(s.ArtifactSHA256) != 64 || strings.Trim(s.ArtifactSHA256, "0123456789abcdef") != "" {
			return Manifest{}, fmt.Errorf("%s: artifact_sha256 must be lowercase SHA-256", s.Name)
		}
		if s.Network != "none" && s.Network != "restricted" {
			return Manifest{}, fmt.Errorf("%s: invalid network mode", s.Name)
		}
		if s.Network == "restricted" && len(s.AllowedHosts) == 0 {
			return Manifest{}, fmt.Errorf("%s: restricted network requires allowed_hosts", s.Name)
		}
		if _, err := s.AdvisoryReviewTime(); err != nil {
			return Manifest{}, fmt.Errorf("%s: invalid advisory date", s.Name)
		}
		if seen[s.Name] {
			return Manifest{}, fmt.Errorf("duplicate scanner %s", s.Name)
		}
		seen[s.Name] = true
	}
	return m, nil
}

// AdvisoryReviewTime preserves exact review instants. Legacy date-only records
// conservatively mean the start of that UTC day, never its end.
func (s Scanner) AdvisoryReviewTime() (time.Time, error) {
	d, err := time.Parse("2006-01-02", s.AdvisoryCheckedDate)
	if err != nil || s.AdvisoryCheckedAt == "" {
		return d, err
	}
	t, err := time.Parse(time.RFC3339Nano, s.AdvisoryCheckedAt)
	if err == nil && t.UTC().Format("2006-01-02") != s.AdvisoryCheckedDate {
		err = fmt.Errorf("advisory timestamp/date disagree")
	}
	return t.UTC(), err
}

func (m Manifest) Get(name string) (Scanner, bool) {
	for _, s := range m.Scanners {
		if s.Name == name {
			return s, true
		}
	}
	return Scanner{}, false
}
