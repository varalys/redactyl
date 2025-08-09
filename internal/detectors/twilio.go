package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

// Twilio formats worth catching:
// - Account SID: AC + 32 hex
// - Auth Token: 32 hex (context required to avoid collisions with generic hashes)
// - API Key SID: SK + 32 base32/hex-ish
// - API Key Secret: 32+ urlsafe base64-ish (context required)

var (
	reTwilioAcctSID     = regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)
	reTwilioAuthTok     = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reTwilioKeySID      = regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)
	reContextTwilio     = regexp.MustCompile(`(?i)(twilio|tw[_-]?auth|tw[_-]?token|tw[_-]?sid|account[_-]?sid|auth[_-]?token|api[_-]?key)`)
	reTwilioMaybeSecret = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{20,}`)
)

func Twilio(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "twilio") {
			continue
		}

		// Account SID is distinctive enough on its own
		if m := reTwilioAcctSID.FindString(t); m != "" {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: m,
				Detector: "twilio_account_sid", Severity: types.SevMed, Confidence: 0.9,
			})
		}

		// API Key SID prefix
		if m := reTwilioKeySID.FindString(t); m != "" {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: m,
				Detector: "twilio_api_key_sid", Severity: types.SevMed, Confidence: 0.85,
			})
		}

		// Auth token needs context to avoid random 32-hex matches
		if reContextTwilio.MatchString(t) {
			if m := reTwilioAuthTok.FindString(t); m != "" {
				out = append(out, types.Finding{
					Path: path, Line: line, Match: m,
					Detector: "twilio_auth_token", Severity: types.SevHigh, Confidence: 0.85,
				})
			}
			// API Key secret (looser) — only report with context present
			if m := reTwilioMaybeSecret.FindString(t); m != "" && len(m) >= 32 {
				out = append(out, types.Finding{
					Path: path, Line: line, Match: m,
					Detector: "twilio_api_key_secret_like", Severity: types.SevMed, Confidence: 0.6,
				})
			}
		}
	}
	return out
}
