package detectors

import (
	"strings"

	"github.com/redactyl/redactyl/internal/ctxparse"
	"github.com/redactyl/redactyl/internal/types"
	v "github.com/redactyl/redactyl/internal/validate"
)

// EnableStructured controls whether structured JSON/YAML scanning is applied.
var EnableStructured = true

// StructuredFields scans JSON/YAML files for provider-specific keys and validates values.
// It complements line-by-line detectors by catching values split across lines or nested.
func StructuredFields(path string, data []byte) []types.Finding {
	lower := strings.ToLower(path)
	var fields []ctxparse.Field
	switch {
	case strings.HasSuffix(lower, ".json"):
		fields = ctxparse.JSONFields(data)
	case strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".yaml"):
		fields = ctxparse.YAMLFields(data)
	default:
		return nil
	}
	if len(fields) == 0 {
		return nil
	}
	var out []types.Finding
	for _, f := range fields {
		key := strings.ToLower(f.Key)
		val := strings.TrimSpace(f.Value)
		// Firebase
		if strings.Contains(key, "firebase") {
			if m := reFirebaseAPIKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "firebase_api_key", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Terraform Cloud
		if strings.Contains(key, "terraform") {
			if m := reTerraformCloud.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "terraform_cloud_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Strip surrounding quotes commonly present in JSON dumps
		val = strings.TrimPrefix(val, "\"")
		val = strings.TrimSuffix(val, "\"")

		// OpenAI
		if strings.Contains(key, "openai") && v.LooksLikeOpenAIKey(val) {
			out = append(out, types.Finding{Path: path, Line: f.Line, Match: val, Detector: "openai_api_key", Severity: types.SevHigh, Confidence: 0.96})
			continue
		}
		// GitHub PAT
		if strings.Contains(key, "github") {
			if m := reGHP.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "github_token", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// AWS
		if strings.Contains(key, "aws_access_key_id") && v.LooksLikeAWSAccessKey(val) {
			out = append(out, types.Finding{Path: path, Line: f.Line, Match: val, Detector: "aws_access_key", Severity: types.SevHigh, Confidence: 0.96})
			continue
		}
		if strings.Contains(key, "aws_secret_access_key") && v.LooksLikeAWSSecretKey(val) {
			out = append(out, types.Finding{Path: path, Line: f.Line, Match: val, Detector: "aws_secret_key", Severity: types.SevHigh, Confidence: 0.97})
			continue
		}
		// Slack/Discord webhooks
		if strings.Contains(key, "slack") {
			if m := reSlackWebhook.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "slack_webhook", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		if strings.Contains(key, "discord") {
			if m := reDiscordWebhook.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "discord_webhook", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// Stripe
		if strings.Contains(key, "stripe") {
			if m := reStripe.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "stripe_secret", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Google
		if strings.Contains(key, "google") {
			if m := reGoogleAPIKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "google_api_key", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Netlify
		if strings.Contains(key, "netlify") {
			if m := reNetlifyToken.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "netlify_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
			if m := reNetlifyBuildHook.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "netlify_build_hook", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
		}
		// Render
		if strings.Contains(key, "render") {
			if m := reRenderAPIKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "render_api_key", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Datadog
		if strings.Contains(key, "datadog") || strings.Contains(key, "dd_") {
			if m := reDDAPIKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "datadog_api_key", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
			if m := reDDAppKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "datadog_app_key", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// Okta (SSWS <token>)
		if strings.Contains(key, "okta") || strings.Contains(strings.ToLower(val), "ssws ") {
			if m := reOktaToken.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "okta_api_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Notion
		if strings.Contains(key, "notion") {
			if m := reNotion.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "notion_api_key", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Snyk
		if strings.Contains(key, "snyk") {
			if m := reSnyk.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "snyk_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// DigitalOcean
		if strings.Contains(key, "digitalocean") || strings.Contains(key, "dop_v1") {
			if m := reDigitalOceanPAT.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "digitalocean_pat", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// Vercel
		if strings.Contains(key, "vercel") {
			if m := reVercelToken.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "vercel_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Mapbox
		if strings.Contains(key, "mapbox") {
			if m := reMapboxToken.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "mapbox_token", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
		}
		// DockerHub
		if strings.Contains(key, "docker") || strings.Contains(key, "dockerhub") {
			if m := reDockerHubPAT.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "dockerhub_pat", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// NewRelic
		if strings.Contains(key, "newrelic") || strings.Contains(key, "nr") {
			if m := reNewRelicAPIKey.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "newrelic_api_key", Severity: types.SevHigh, Confidence: 0.96})
				continue
			}
		}
		// Airtable
		if strings.Contains(key, "airtable") {
			if m := reAirtablePAT.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "airtable_pat", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// GitLab
		if strings.Contains(key, "gitlab") {
			if m := reGitLabPAT.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "gitlab_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Cloudflare
		if strings.Contains(key, "cloudflare") || strings.Contains(key, "cf_") {
			if m := reCloudflareToken.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "cloudflare_token", Severity: types.SevHigh, Confidence: 0.95})
				continue
			}
		}
		// Twilio
		if strings.Contains(key, "twilio") {
			if m := reTwilioAcctSID.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "twilio_account_sid", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
			if m := reTwilioKeySID.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "twilio_api_key_sid", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
			if m := reTwilioAuthTok.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "twilio_auth_token", Severity: types.SevHigh, Confidence: 0.9})
				continue
			}
		}
		// JWT
		if strings.Contains(key, "jwt") {
			if m := reJWT.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "jwt", Severity: types.SevMed, Confidence: 0.9})
				continue
			}
		}
		// Zapier/IFTTT webhooks
		if strings.Contains(key, "zapier") {
			if m := reZapierWebhook.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "zapier_webhook_url", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
		}
		if strings.Contains(key, "ifttt") {
			if m := reIFTTTWebhook.FindString(val); m != "" {
				out = append(out, types.Finding{Path: path, Line: f.Line, Match: m, Detector: "ifttt_webhook_url", Severity: types.SevMed, Confidence: 0.95})
				continue
			}
		}
	}
	return out
}
