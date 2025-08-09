package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9._-]+?\.[A-Za-z0-9._-]+`)

func JWTToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if reJWT.FindStringIndex(sc.Text()) != nil {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: reJWT.FindString(sc.Text()),
				Detector: "jwt", Severity: types.SevMed, Confidence: 0.7,
			})
		}
	}
	return out
}
