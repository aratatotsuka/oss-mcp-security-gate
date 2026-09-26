package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/secret"
)

func Seal(r *model.Report) error {
	for i := range r.Findings {
		r.Findings[i].Title = secret.Text(r.Findings[i].Title)
		r.Findings[i].Description = secret.Text(r.Findings[i].Description)
		r.Findings[i].Evidence = secret.Evidence(r.Findings[i].Evidence)
	}
	for i := range r.ExceptionsUsed {
		r.ExceptionsUsed[i].Justification = secret.Text(r.ExceptionsUsed[i].Justification)
		r.ExceptionsUsed[i].Approver = secret.Text(r.ExceptionsUsed[i].Approver)
		r.ExceptionsUsed[i].Scope = secret.Text(r.ExceptionsUsed[i].Scope)
		r.ExceptionsUsed[i].Evidence = secret.Evidence(r.ExceptionsUsed[i].Evidence)
	}
	r.ResultHash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	r.ResultHash = "sha256:" + hex.EncodeToString(h[:])
	return nil
}
func Write(path string, r *model.Report) error {
	if err := Seal(r); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := atomicWrite(path, b); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func atomicWrite(path string, data []byte) (err error) {
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular report destination")
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".security-gate-report-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// os.Rename replaces an existing file atomically on Unix. Windows requires
	// removing the already-validated regular destination first.
	if runtime.GOOS == "windows" {
		if _, statErr := os.Lstat(path); statErr == nil {
			if err = os.Remove(path); err != nil {
				return err
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
	}
	return os.Rename(tmpPath, path)
}
