package secret

import (
	"regexp"
	"strings"
)

var sensitiveKey = regexp.MustCompile(`(?i)(secret|token|password|passwd|private[_-]?key|api[_-]?key|access[_-]?key|match|raw)`)
var knownSecret = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)

func MaskValue(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "****"
	}
	keep := 4
	if len(r) > 12 {
		keep = 8
	}
	return string(r[:keep]) + strings.Repeat("*", min(16, len(r)-keep))
}

func Text(s string) string { return knownSecret.ReplaceAllStringFunc(s, MaskValue) }

func Evidence(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if sensitiveKey.MatchString(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = sanitize(v)
	}
	return out
}

func sanitize(v any) any {
	switch x := v.(type) {
	case string:
		return Text(x)
	case map[string]any:
		return Evidence(x)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = sanitize(x[i])
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i := range x {
			out[i] = Text(x[i])
		}
		return out
	default:
		return x
	}
}
