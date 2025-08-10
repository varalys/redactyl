package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var rePyPI = regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{50,}\b`)

func PyPIToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, rePyPI, "pypi_token", types.SevHigh, 0.95)
}
