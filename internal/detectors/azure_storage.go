package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

var reAzureConn = regexp.MustCompile(`(?i)AccountName=[^;\s]+;AccountKey=([A-Za-z0-9+/=]{80,});`)

func AzureStorageKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "azure_storage_key") {
			continue
		}
		if m := reAzureConn.FindStringSubmatch(t); len(m) == 2 {
			out = append(out, types.Finding{Path: path, Line: line, Match: m[1], Detector: "azure_storage_key", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
