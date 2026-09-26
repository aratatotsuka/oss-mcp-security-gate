package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/manifest"
)

type Result struct {
	Scanner, Path, Expected, Actual string
	OK                              bool
	Error                           string
}

func Verify(root string, s manifest.Scanner) Result {
	p := s.RuntimePath
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, filepath.Clean(p))
	}
	r := Result{Scanner: s.Name, Path: p, Expected: s.ArtifactSHA256}
	f, err := os.Open(p)
	if err != nil {
		r.Error = "UNVERIFIED_SCANNER_ARTIFACT: " + err.Error()
		return r
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<31)); err != nil {
		r.Error = err.Error()
		return r
	}
	r.Actual = hex.EncodeToString(h.Sum(nil))
	r.OK = r.Actual == r.Expected
	if !r.OK {
		r.Error = fmt.Sprintf("SCANNER_HASH_MISMATCH expected=%s actual=%s", r.Expected, r.Actual)
	}
	return r
}
