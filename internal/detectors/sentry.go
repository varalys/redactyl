package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Sentry DSN: https://<key>@o<org>.ingest.sentry.io/<project>
var reSentryDSN = regexp.MustCompile(`https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+`)

func SentryDSN(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reSentryDSN.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "sentry_dsn", Severity: types.SevMed, Confidence: 0.9})
		}
	}
	return out
}
