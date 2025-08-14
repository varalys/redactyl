package detectors

import (
	"strings"

	"github.com/redactyl/redactyl/internal/types"
	v "github.com/redactyl/redactyl/internal/validate"
)

// EnableValidators controls whether detector-specific validators run post-detection.
var EnableValidators = true

type findingValidator func(f types.Finding) (types.Finding, bool)

var ruleValidators = map[string]findingValidator{
	"github_token": func(f types.Finding) (types.Finding, bool) {
		if !v.LooksLikeGitHubToken(f.Match) {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	"aws_access_key": func(f types.Finding) (types.Finding, bool) {
		if !v.LooksLikeAWSAccessKey(f.Match) {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	"aws_secret_key": func(f types.Finding) (types.Finding, bool) {
		if !v.LooksLikeAWSSecretKey(f.Match) {
			return f, false
		}
		if f.Confidence < 0.95 {
			f.Confidence = 0.97
		}
		return f, true
	},
	"jwt": func(f types.Finding) (types.Finding, bool) {
		if !v.IsJWTStructure(f.Match) {
			return f, false
		}
		if f.Confidence < 0.8 {
			f.Confidence = 0.85
		}
		return f, true
	},
	"openai_api_key": func(f types.Finding) (types.Finding, bool) {
		if !v.LooksLikeOpenAIKey(f.Match) {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	// Webhook shapes
	"slack_webhook": func(f types.Finding) (types.Finding, bool) {
		// Expect 3 segments after /services/: T{9+}/B{9+}/{24+ alnum}
		m := f.Match
		ok := v.LengthBetween(m, 60, 200)
		if !ok {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	"discord_webhook": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		ok := v.LengthBetween(m, 40, 200)
		if !ok {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	// Stripe
	"stripe_secret": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !(len(m) >= len("sk_live_")+24 && strings.HasPrefix(m, "sk_live_")) {
			return f, false
		}
		// tail base62
		if !v.IsAlphabet(m[len("sk_live_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		if f.Confidence < 0.9 {
			f.Confidence = 0.95
		}
		return f, true
	},
	// Twilio family: basic length checks; formats already tight in regex
	"twilio_account_sid": func(f types.Finding) (types.Finding, bool) {
		// AC + 32 hex
		if len(f.Match) != 34 {
			return f, false
		}
		return f, true
	},
	"twilio_api_key_sid": func(f types.Finding) (types.Finding, bool) {
		if len(f.Match) != 34 {
			return f, false
		}
		return f, true
	},
	"twilio_auth_token": func(f types.Finding) (types.Finding, bool) {
		if len(f.Match) != 32 {
			return f, false
		}
		return f, true
	},
	// GitLab PAT: glpat- + 20 base62/underscore/dash
	"gitlab_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !v.LengthBetween(m, len("glpat-")+20, len("glpat-")+50) {
			return f, false
		}
		if !v.IsAlphabet(m[len("glpat-"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") {
			return f, false
		}
		return f, true
	},
	// Sentry DSN key is 32 hex
	"sentry_dsn": func(f types.Finding) (types.Finding, bool) {
		// length already long URL; just accept as-is
		return f, true
	},
	"sentry_auth_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !v.LengthBetween(m, len("sntrys_")+40, len("sntrys_")+80) {
			return f, false
		}
		if !v.IsAlphabet(m[len("sntrys_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") {
			return f, false
		}
		return f, true
	},
	// Terraform Cloud tokens: tfe./tfc. + 30+ base62
	"terraform_cloud_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !(strings.HasPrefix(m, "tfe.") || strings.HasPrefix(m, "tfc.")) {
			return f, false
		}
		if len(m) < 4+30 {
			return f, false
		}
		if !v.IsAlphabet(m[4:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Mapbox tokens: pk.<50+> or sk.<70+>
	"mapbox_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if strings.HasPrefix(m, "pk.") && len(m) >= 3+50 {
			if v.IsAlphabet(m[3:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
				return f, true
			}
		}
		if strings.HasPrefix(m, "sk.") && len(m) >= 3+70 {
			if v.IsAlphabet(m[3:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
				return f, true
			}
		}
		return f, false
	},
	// Datadog keys are fixed hex lengths and context-gated already
	"datadog_api_key": func(f types.Finding) (types.Finding, bool) { return f, true },
	"datadog_app_key": func(f types.Finding) (types.Finding, bool) { return f, true },
	// Google API key: AIza + 35 base62-_ already enforced by regex
	"google_api_key": func(f types.Finding) (types.Finding, bool) { return f, true },
	// NPM: npm_ + 36 base62
	"npm_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "npm_") || len(m) != len("npm_")+36 {
			return f, false
		}
		if !v.IsAlphabet(m[4:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Heroku: context-gated regex; ensure reasonable length
	"heroku_api_key": func(f types.Finding) (types.Finding, bool) {
		if !v.LengthBetween(f.Match, 32, 128) {
			return f, false
		}
		return f, true
	},
	// DigitalOcean PAT: dop_v1_ + 64 hex
	"digitalocean_pat": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "dop_v1_") || len(m) != len("dop_v1_")+64 {
			return f, false
		}
		if !v.IsHex(m[len("dop_v1_"):]) {
			return f, false
		}
		return f, true
	},
	// Vercel: sanity length checks; regex is already specific
	"vercel_token": func(f types.Finding) (types.Finding, bool) {
		return f, v.LengthBetween(f.Match, 20, 100)
	},
	// Snyk: snyk_ + >=30 base62
	"snyk_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "snyk_") || len(m) < len("snyk_")+30 {
			return f, false
		}
		if !v.IsAlphabet(m[len("snyk_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Okta: SSWS token follows 'SSWS <token>' with base64url-ish
	"okta_api_token": func(f types.Finding) (types.Finding, bool) {
		return f, v.LengthBetween(f.Match, 40, 200)
	},
	// Notion: secret_ + >=40 base62
	"notion_api_key": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "secret_") || len(m) < len("secret_")+40 {
			return f, false
		}
		if !v.IsAlphabet(m[len("secret_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// PostHog: phc_/phx_ + 32 base62
	"posthog_project_key": func(f types.Finding) (types.Finding, bool) {
		return f, len(f.Match) == len("phc_")+32
	},
	"posthog_personal_key": func(f types.Finding) (types.Finding, bool) {
		return f, len(f.Match) == len("phx_")+32
	},
	// Redis URI creds: rely on regex; not adding extra validation
	"redis_uri_creds": func(f types.Finding) (types.Finding, bool) { return f, true },
	// Cloudflare token: >=40 base62 with context already
	"cloudflare_token": func(f types.Finding) (types.Finding, bool) {
		return f, v.LengthBetween(f.Match, 40, 200)
	},
	// Airtable PAT: pat_ + >=14 base62
	"airtable_pat": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "pat_") || len(m) < len("pat_")+14 {
			return f, false
		}
		if !v.IsAlphabet(m[len("pat_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Netlify token: nf_ + >=20 base62
	"netlify_token": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "nf_") || len(m) < len("nf_")+20 {
			return f, false
		}
		if !v.IsAlphabet(m[len("nf_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Netlify build hook: URL length sanity only (regex enforces host/path)
	"netlify_build_hook": func(f types.Finding) (types.Finding, bool) {
		return f, v.LengthBetween(f.Match, 40, 200)
	},
	// Render API key: rnd_ + >=32 base62
	"render_api_key": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "rnd_") || len(m) < len("rnd_")+32 {
			return f, false
		}
		if !v.IsAlphabet(m[len("rnd_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
			return f, false
		}
		return f, true
	},
	// Shopify tokens: shp{at,ua,ss}_ + >=32 hex
	"shopify_token": func(f types.Finding) (types.Finding, bool) {
		parts := strings.SplitN(f.Match, "_", 2)
		if len(parts) != 2 {
			return f, false
		}
		if !strings.HasPrefix(parts[0], "shp") {
			return f, false
		}
		return f, v.IsHex(parts[1]) && len(parts[1]) >= 32
	},
	// Databricks: dapi + 26-40 base62
	"databricks_pat": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		if !strings.HasPrefix(m, "dapi") || !v.LengthBetween(m, 4+26, 4+40) {
			return f, false
		}
		return f, v.IsAlphabet(m[4:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	},
	// Linear: lin_api_ + 40 base62
	"linear_api_key": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		return f, len(m) == len("lin_api_")+40 && v.IsAlphabet(m[len("lin_api_"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	},
	// Kaggle JSON key: rely on regex shape
	"kaggle_json_key": func(f types.Finding) (types.Finding, bool) { return f, true },
	// Prisma data proxy URL: rely on regex; non-empty path
	"prisma_data_proxy_url": func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 12, 300) },
	// Hasura & Supabase: rely on context-gated regex + min length
	"hasura_admin_secret":       func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 16, 256) },
	"supabase_service_role_key": func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 16, 256) },
	// AI providers additional: Anthropic, Groq, Cohere, Mistral, AI21, Azure OpenAI
	"anthropic_api_key": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		return f, strings.HasPrefix(m, "sk-ant-") && v.LengthBetween(m, len("sk-ant-")+30, 200)
	},
	"groq_api_key": func(f types.Finding) (types.Finding, bool) {
		m := f.Match
		return f, strings.HasPrefix(m, "gsk_") && v.LengthBetween(m, len("gsk_")+30, 200)
	},
	"cohere_api_key":       func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 32, 128) },
	"mistral_api_key":      func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 32, 128) },
	"ai21_api_key":         func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 32, 128) },
	"azure_openai_api_key": func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 32, 128) },
	// DockerHub & NewRelic
	"dockerhub_pat":    func(f types.Finding) (types.Finding, bool) { return f, len(f.Match) == len("dckr_pat_")+64 },
	"newrelic_api_key": func(f types.Finding) (types.Finding, bool) { return f, v.LengthBetween(f.Match, 10, 100) },
}

func applyValidators(fs []types.Finding) []types.Finding {
	if !EnableValidators || len(fs) == 0 {
		return fs
	}
	out := make([]types.Finding, 0, len(fs))
	for _, f := range fs {
		if vfn, ok := ruleValidators[f.Detector]; ok {
			if nf, ok2 := vfn(f); ok2 {
				out = append(out, nf)
			}
			continue
		}
		out = append(out, f)
	}
	return out
}
