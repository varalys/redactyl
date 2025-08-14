package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
	"github.com/redactyl/redactyl/internal/validate"
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
			m := reAWSAccess.FindString(txt)
			if validate.LooksLikeAWSAccessKey(m) {
				out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "aws_access_key", Severity: types.SevHigh, Confidence: 0.95})
			}
		}
		if m := reAWSSecret.FindStringSubmatch(txt); len(m) == 3 {
			candidate := m[2]
			if validate.LooksLikeAWSSecretKey(candidate) {
				out = append(out, types.Finding{Path: path, Line: line, Match: candidate, Detector: "aws_secret_key", Severity: types.SevHigh, Confidence: 0.97})
			}
		}
	}
	return out
}
