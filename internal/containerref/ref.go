package containerref

import "strings"

// Digest accepts a local content-addressed image ID or a registry manifest digest.
func Digest(ref string) (string, bool) {
	d := ""
	if strings.HasPrefix(ref, "sha256:") {
		d = strings.TrimPrefix(ref, "sha256:")
	} else if image, digest, ok := strings.Cut(ref, "@sha256:"); ok && image != "" && !strings.ContainsAny(image, " \t\r\n") {
		d = digest
	}
	return d, len(d) == 64 && strings.Trim(d, "0123456789abcdef") == ""
}

func Provisioned(ref string) bool {
	d, ok := Digest(ref)
	return ok && d != strings.Repeat("0", 64)
}

// Same compares immutable references after Docker's default registry/library
// expansion. A repository digest must never match another repository or an ID.
func Same(a, b string) bool {
	if !Provisioned(a) || !Provisioned(b) {
		return false
	}
	if strings.HasPrefix(a, "sha256:") || strings.HasPrefix(b, "sha256:") {
		return a == b
	}
	return normalize(a) == normalize(b)
}

func normalize(ref string) string {
	repo, digest, _ := strings.Cut(ref, "@")
	// Tags are only hints when an immutable digest is supplied.
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	first, rest, hasSlash := strings.Cut(repo, "/")
	if !hasSlash || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		first, rest = "docker.io", repo
	}
	if first == "index.docker.io" {
		first = "docker.io"
	}
	if first == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return first + "/" + rest + "@" + digest
}
