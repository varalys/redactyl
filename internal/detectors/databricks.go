package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Allow 26-40 suffix length to accommodate sample variance
var reDatabricks = regexp.MustCompile(`\bdapi[A-Za-z0-9]{26,40}\b`)

func DatabricksPAT(path string, data []byte) []types.Finding {
	return findSimple(path, data, reDatabricks, "databricks_pat", types.SevHigh, 0.95)
}
