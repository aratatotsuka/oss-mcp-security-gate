package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{PolicyVersion: "1.0", VulnerabilityDBMaxAgeHours: 72, AdvisoryReviewMaxAgeDays: 30, ScorecardReviewBelow: 7, ExceptionsRequireExpiry: true, FailClosed: true}
}

func writeConfig(t *testing.T, c Config) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigAcceptsSecuritySettings(t *testing.T) {
	want := validConfig()
	got, err := LoadConfig(writeConfig(t, want))
	if err != nil || got.PolicyVersion != want.PolicyVersion || !got.FailClosed || !got.ExceptionsRequireExpiry {
		t.Fatalf("valid policy config rejected: %#v %v", got, err)
	}
}

func TestLoadConfigRequiresFailClosedAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"fail closed disabled", func(c *Config) { c.FailClosed = false }},
		{"expiry disabled", func(c *Config) { c.ExceptionsRequireExpiry = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(&c)
			if _, err := LoadConfig(writeConfig(t, c)); err == nil || !strings.Contains(err.Error(), "must require") {
				t.Fatalf("unsafe policy config accepted: %v", err)
			}
		})
	}
}
