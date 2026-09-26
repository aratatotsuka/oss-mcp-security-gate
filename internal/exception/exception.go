package exception

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func Load(path string, now time.Time) ([]model.Exception, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var xs []model.Exception
	if err := json.Unmarshal(b, &xs); err != nil {
		return nil, err
	}
	for i, x := range xs {
		if strings.TrimSpace(x.FindingID) == "" || strings.TrimSpace(x.Justification) == "" || strings.TrimSpace(x.Approver) == "" || strings.TrimSpace(x.Scope) == "" || x.CreatedAt.IsZero() || x.ExpiresAt.IsZero() || len(x.Evidence) == 0 {
			return nil, fmt.Errorf("exception[%d] missing required field", i)
		}
		if !x.ExpiresAt.After(x.CreatedAt) {
			return nil, fmt.Errorf("exception[%d] expires_at must be after created_at", i)
		}
	}
	return xs, nil
}

func ActiveFor(xs []model.Exception, f model.Finding, target string, now time.Time) (model.Exception, bool) {
	for _, x := range xs {
		if x.FindingID == f.FindingID && now.Before(x.ExpiresAt) && (x.Scope == "*" || x.Scope == target) {
			return x, true
		}
	}
	return model.Exception{}, false
}
