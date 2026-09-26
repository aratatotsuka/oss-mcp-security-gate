package secret

import (
	"fmt"
	"strings"
	"testing"
)

func TestMaskKnownSecret(t *testing.T) {
	raw := "AKIAABCDEFGHIJKLMNOP"
	got := Text("key=" + raw)
	if strings.Contains(got, raw) {
		t.Fatal("raw secret remains")
	}
	if !strings.Contains(got, "AKIA") {
		t.Fatal("prefix should aid investigation")
	}
}
func TestEvidenceSensitiveKeys(t *testing.T) {
	got := Evidence(map[string]any{"secret": "top-secret", "safe": "ok"})
	if got["secret"] != "[REDACTED]" || got["safe"] != "ok" {
		t.Fatalf("unexpected evidence: %#v", got)
	}
}

func TestEvidenceMasksNestedArrays(t *testing.T) {
	raw := "AKIAABCDEFGHIJKLMNOP"
	got := Evidence(map[string]any{"items": []any{raw, map[string]any{"value": raw}}})
	if strings.Contains(fmt.Sprint(got), raw) {
		t.Fatalf("nested secret remains: %#v", got)
	}
}
