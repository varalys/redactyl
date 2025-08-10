package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reSQLServerUR = regexp.MustCompile(`\bsqlserver://[^:/\s]+:(?P<pw>[^@\s]+)@`)

func SQLServerURICreds(path string, data []byte) []types.Finding {
	return findSimple(path, data, reSQLServerUR, "sqlserver_uri_creds", types.SevHigh, 0.95)
}
