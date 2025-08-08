package detectors

import "github.com/redactyl/redactyl/internal/types"

type Detector func(path string, data []byte) []types.Finding

var all = []Detector{
	AWSKeys, GitHubToken, SlackToken, JWTToken, PrivateKeyBlock, EntropyNearbySecrets, StripeSecret, Twilio,
}

func RunAll(path string, data []byte) []types.Finding {
	var out []types.Finding
	for _, d := range all {
		out = append(out, d(path, data)...)
	}
	return dedupe(out)
}

func IDs() []string {
	return []string{
		"aws_access_key",
		"aws_secret_key",
		"github_token",
		"slack_token",
		"jwt",
		"private_key_block",
		"entropy_context",
		"stripe_secret",
		"twilio_account_sid",
		"twilio_api_key_sid",
		"twilio_auth_token",
		"twilio_api_key_secret_like",
	}
}

// Simple function IDs for detector testing (coarse-grained groups)
var funcByID = map[string]Detector{
	"aws":        AWSKeys,
	"github":     GitHubToken,
	"slack":      SlackToken,
	"jwt":        JWTToken,
	"privatekey": PrivateKeyBlock,
	"entropy":    EntropyNearbySecrets,
	"stripe":     StripeSecret,
	"twilio":     Twilio,
}

func FunctionIDs() []string {
	return []string{"aws", "github", "slack", "jwt", "privatekey", "entropy", "stripe", "twilio"}
}

func RunFunction(id, path string, data []byte) []types.Finding {
	if f, ok := funcByID[id]; ok {
		return f(path, data)
	}
	return nil
}

func dedupe(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var result []types.Finding

	for _, f := range findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}
