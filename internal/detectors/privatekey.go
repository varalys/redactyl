package detectors

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

func PrivateKeyBlock(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "-----BEGIN ") && strings.Contains(t, " PRIVATE KEY-----") {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: "BEGIN PRIVATE KEY",
				Detector: "private_key_block", Severity: types.SevHigh, Confidence: 0.99,
			})
		}
	}
	return out
}
