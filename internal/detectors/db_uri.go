package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

var (
	rePostgresURI = regexp.MustCompile(`\bpostgres(?:ql)?://[^\s:@/]+:[^\s@/]+@[^\s/]+/[^\s?]+`)
	reMySQLURI    = regexp.MustCompile(`\bmysql://[^\s:@/]+:[^\s@/]+@[^\s/]+/[^\s?]+`)
	reMongoURI    = regexp.MustCompile(`\bmongodb(?:\+srv)?:/{2}[^\s:@/]+:[^\s@/]+@[^\s/]+/[^\s?]+`)
)

func dbURIFinding(path string, line int, match, id string) types.Finding {
	return types.Finding{Path: path, Line: line, Match: match, Detector: id, Severity: types.SevHigh, Confidence: 0.9}
}

func DBURIs(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "db_uri") {
			continue
		}
		if m := rePostgresURI.FindString(t); m != "" {
			out = append(out, dbURIFinding(path, line, m, "postgres_uri_creds"))
		}
		if m := reMySQLURI.FindString(t); m != "" {
			out = append(out, dbURIFinding(path, line, m, "mysql_uri_creds"))
		}
		if m := reMongoURI.FindString(t); m != "" {
			out = append(out, dbURIFinding(path, line, m, "mongodb_uri_creds"))
		}
	}
	return out
}
