package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/model"
)

func TestAppendHashChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, id := range []string{"one", "two"} {
		if err := Append(p, Record{Timestamp: time.Now().UTC(), Who: "tester", ScanID: id, Decision: model.DecisionReview}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var rows []Record
	for s.Scan() {
		var r Record
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	if len(rows) != 2 || rows[0].RecordHash == "" || rows[1].PreviousHash != rows[0].RecordHash {
		t.Fatalf("broken chain: %#v", rows)
	}
}
