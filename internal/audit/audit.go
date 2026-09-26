package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

type Record struct {
	Timestamp     time.Time          `json:"timestamp"`
	Who           string             `json:"who"`
	TargetID      string             `json:"target_id"`
	ScanID        string             `json:"scan_id"`
	PolicyVersion string             `json:"policy_version"`
	ScannerRuns   []model.ScannerRun `json:"scanner_runs"`
	Decision      model.Decision     `json:"decision"`
	ExceptionIDs  []string           `json:"exception_ids,omitempty"`
	ResultHash    string             `json:"result_hash,omitempty"`
	PreviousHash  string             `json:"previous_hash,omitempty"`
	RecordHash    string             `json:"record_hash"`
}

func Append(path string, r Record) error {
	prev, err := lastHash(path)
	if err != nil {
		return err
	}
	r.PreviousHash = prev
	r.RecordHash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	r.RecordHash = "sha256:" + hex.EncodeToString(h[:])
	b, err = json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func lastHash(path string) (string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1<<20)
	var last []byte
	for s.Scan() {
		last = append(last[:0], s.Bytes()...)
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	if len(last) == 0 {
		return "", nil
	}
	var r Record
	if err := json.Unmarshal(last, &r); err != nil {
		return "", fmt.Errorf("audit chain malformed: %w", err)
	}
	return r.RecordHash, nil
}
