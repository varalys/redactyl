// internal/detectors/stripe.go
package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

var reStripe = regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)

func StripeSecret(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "stripe_secret") {
			continue
		}
		if reStripe.FindStringIndex(t) != nil {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: reStripe.FindString(t),
				Detector: "stripe_secret", Severity: types.SevHigh, Confidence: 0.9,
			})
		}
	}
	return out
}
