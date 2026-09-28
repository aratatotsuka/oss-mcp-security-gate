package containerref

import (
	"strings"
	"testing"
)

func TestImmutableReferences(t *testing.T) {
	for _, r := range []string{"sha256:" + strings.Repeat("a", 64), "registry/scanner@sha256:" + strings.Repeat("b", 64)} {
		if !Provisioned(r) {
			t.Fatal(r)
		}
	}
	for _, r := range []string{"scanner:latest", "sha256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("g", 64), "sha256:abc"} {
		if Provisioned(r) {
			t.Fatal(r)
		}
	}
}
