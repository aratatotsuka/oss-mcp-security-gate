package integrity

import (
	"strings"
	"testing"
)

func TestImageInspectionMatchesCanonicalRepository(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		ref, repo string
		want      bool
	}{
		{"docker.io/library/busybox@" + hash, "busybox@" + hash, true},
		{"index.docker.io/busybox@" + hash, "library/busybox@" + hash, true},
		{"busybox:1@" + hash, "busybox@" + hash, true},
		{"docker.io/team/scanner@" + hash, "team/scanner@" + hash, true},
		{"registry.test:5000/team/scanner@" + hash, "registry.test:5000/team/scanner@" + hash, true},
		{"busybox@" + hash, "busybox@" + other, false},
		{"busybox@" + hash, "another@" + hash, false},
		{"registry.test/busybox@" + hash, "busybox@" + hash, false},
		{hash, "busybox@" + hash, false},
	} {
		t.Run(tc.ref+tc.repo, func(t *testing.T) {
			if got := imageMatches(tc.ref, other, []string{tc.repo}); got != tc.want {
				t.Fatalf("match=%v want=%v", got, tc.want)
			}
		})
	}
	if !imageMatches(hash, hash, nil) {
		t.Fatal("local image ID rejected")
	}
	if imageMatches("busybox@"+hash, hash, nil) {
		t.Fatal("manifest digest confused with image ID")
	}
}
