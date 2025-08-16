package detectors

import "testing"

// Additional coverage for StructuredFields across JSON and YAML
func TestStructured_More_JSON_And_YAML(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		body   string
		expect map[string]bool
	}{
		{
			name: "AWS JSON split",
			path: "config.json",
			body: `{
  "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}`,
			expect: map[string]bool{"aws_access_key": true, "aws_secret_key": true},
		},
		{
			name:   "OpenAI JSON",
			path:   "env.json",
			body:   `{"openai_api_key": "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			expect: map[string]bool{"openai_api_key": true},
		},
		{
			name:   "Slack webhook YAML",
			path:   "hooks.yaml",
			body:   "slack_webhook: https://hooks.slack.com/services/AAA111111/BBB222222/cccccccccccccccccccccccc",
			expect: map[string]bool{"slack_webhook": true},
		},
		{
			name:   "Stripe JSON",
			path:   "payments.json",
			body:   `{"stripe_secret": "sk_live_abcdefghijklmnopqrstuvwxyz123456"}`,
			expect: map[string]bool{"stripe_secret": true},
		},
		{
			name:   "Google JSON",
			path:   "google.json",
			body:   `{"google_api_key": "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			expect: map[string]bool{"google_api_key": true},
		},
		// Additional parity and context-gated cases
		{
			name:   "Discord webhook JSON",
			path:   "discord.json",
			body:   `{"discord": "https://discord.com/api/webhooks/123456789012345/abcDEF_123"}`,
			expect: map[string]bool{"discord_webhook": true},
		},
		{
			name:   "OpenAI YAML",
			path:   "env.yaml",
			body:   "openai_api_key: sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expect: map[string]bool{"openai_api_key": true},
		},
		{
			name:   "Stripe YAML",
			path:   "payments.yaml",
			body:   "stripe_secret: sk_live_abcdefghijklmnopqrstuvwxyz123456",
			expect: map[string]bool{"stripe_secret": true},
		},
		{
			name:   "Okta JSON with context",
			path:   "okta.json",
			body:   `{"auth": "Bearer SSWS abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123", "issuer": "okta"}`,
			expect: map[string]bool{"okta_api_token": true},
		},
		{
			name:   "Okta YAML with context",
			path:   "okta.yaml",
			body:   "issuer: okta.com\nauthorization: SSWS abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123",
			expect: map[string]bool{"okta_api_token": true},
		},
		{
			name:   "Twilio auth token positive (context)",
			path:   "twilio.json",
			body:   `{"service": "twilio", "token": "auth token 0123456789abcdef0123456789abcdef"}`,
			expect: map[string]bool{"twilio_auth_token": true},
		},
		{
			name:   "Twilio auth token negative (no context)",
			path:   "no_twilio.json",
			body:   `{"token": "nonsecretvalue"}`,
			expect: map[string]bool{},
		},
		{
			name:   "Negative control",
			path:   "random.yaml",
			body:   "foo: bar\nbaz: qux",
			expect: map[string]bool{},
		},
		// Third batch: more providers commonly used
		{
			name:   "Mailgun JSON",
			path:   "mailgun.json",
			body:   `{"mailgun_api_key": "key-0123456789abcdef0123456789abcdef"}`,
			expect: map[string]bool{"mailgun_api_key": true},
		},
		{
			name:   "Cloudflare JSON with context",
			path:   "cloudflare.json",
			body:   `{"CF_API_TOKEN": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			expect: map[string]bool{"cloudflare_token": true},
		},
		{
			name:   "Netlify JSON",
			path:   "netlify.json",
			body:   `{"netlify_token": "nf_ABCDEFGHIJKLMNOPQRST"}`,
			expect: map[string]bool{"netlify_token": true},
		},
		{
			name:   "Render JSON",
			path:   "render.json",
			body:   `{"render_api_key": "rnd_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"}`,
			expect: map[string]bool{"render_api_key": true},
		},
		{
			name:   "Cloudinary YAML",
			path:   "cloudinary.yaml",
			body:   "cloudinary_url: cloudinary://123456:Abcdefghij_kLMNO@demo",
			expect: map[string]bool{"cloudinary_url_creds": true},
		},
		{
			name:   "Datadog JSON with context (api key)",
			path:   "dd.json",
			body:   `{"DD_API_KEY": "0123456789abcdef0123456789abcdef"}`,
			expect: map[string]bool{"datadog_api_key": true},
		},
	}

	for _, tc := range cases {
		fs := RunAll(tc.path, []byte(tc.body))
		got := map[string]bool{}
		for _, f := range fs {
			got[f.Detector] = true
		}
		for id := range tc.expect {
			if !got[id] {
				t.Fatalf("%s: expected detector %q to trigger; got=%v", tc.name, id, got)
			}
		}
		// ensure no unexpected extras in strict-negative cases
		if len(tc.expect) == 0 && len(got) != 0 {
			t.Fatalf("%s: expected no findings; got=%v", tc.name, got)
		}
	}
}
