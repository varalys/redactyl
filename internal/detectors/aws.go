package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
)

var (
	reAWSAccess = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	// Very broad; keep confidence medium unless paired with secret-like context
	reAWSSecret = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|secretKey)["'\s:=]+([A-Za-z0-9/+=]{40})`)
)

func AWSKeys(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		txt := sc.Text()
		if reAWSAccess.FindStringIndex(txt) != nil {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: reAWSAccess.FindString(txt),
				Detector: "aws_access_key", Severity: types.SevHigh, Confidence: 0.9,
			})
		}
		if m := reAWSSecret.FindStringSubmatch(txt); len(m) == 3 {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: m[2],
				Detector: "aws_secret_key", Severity: types.SevHigh, Confidence: 0.95,
			})
		}
	}
	return out
}
