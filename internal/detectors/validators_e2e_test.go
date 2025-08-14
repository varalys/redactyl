package detectors

import (
	"strings"
	"testing"
)

func TestJWTValidator_DropsInvalidStructure(t *testing.T) {
	EnableValidators = true
	// header is valid base64url JSON; payload is a single char which fails base64url decode
	data := []byte("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.a.signature")
	fs := RunAll("jwt.txt", data)
	// Expect zero jwt findings after validators
	for _, f := range fs {
		if f.Detector == "jwt" {
			t.Fatalf("expected validator to drop invalid jwt, got jwt finding: %v", f.Match)
		}
	}
	// Disabling validators should allow raw regex hit
	EnableValidators = false
	fs2 := RunAll("jwt.txt", data)
	found := false
	for _, f := range fs2 {
		if f.Detector == "jwt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected regex jwt match when validators disabled")
	}
	EnableValidators = true
}

func TestOpenAIValidator_BumpsConfidence(t *testing.T) {
	EnableValidators = true
	key := "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD"
	data := []byte("OPENAI_API_KEY=" + key)
	fs := RunAll("openai.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected openai key finding")
	}
	var found bool
	for _, f := range fs {
		if f.Detector == "openai_api_key" {
			found = true
			if f.Confidence < 0.95 {
				t.Fatalf("expected confidence bump, got %.2f", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected openai finding")
	}
}

func TestStripeValidator_AcceptsLiveSecret(t *testing.T) {
	EnableValidators = true
	secret := "sk_live_abcdefghijklmnopqrstuvwxyz012345"
	fs := RunAll("stripe.txt", []byte(secret))
	if len(fs) == 0 {
		t.Fatalf("expected stripe secret finding")
	}
}

func TestSlackWebhook_Validator(t *testing.T) {
	EnableValidators = true
	hook := "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwxyzAB"
	fs := RunAll("slack.txt", []byte(hook))
	if len(fs) == 0 {
		t.Fatalf("expected slack webhook finding")
	}
}

func TestTwilio_Validators(t *testing.T) {
	EnableValidators = true
	acct := "AC0123456789abcdef0123456789abcdef"
	fs1 := RunAll("twilio.txt", []byte(acct))
	if len(fs1) == 0 {
		t.Fatalf("expected twilio account sid finding")
	}
	keySID := "SK0123456789abcdef0123456789abcdef"
	fs2 := RunAll("twilio.txt", []byte(keySID))
	if len(fs2) == 0 {
		t.Fatalf("expected twilio api key sid finding")
	}
	auth := "twilio auth token: 0123456789abcdef0123456789abcdef"
	fs3 := RunAll("twilio.txt", []byte(auth))
	if len(fs3) == 0 {
		t.Fatalf("expected twilio auth token finding")
	}
}

func TestNPMToken_Validator(t *testing.T) {
	EnableValidators = true
	tok := "npm_abcdefghijklmnopqrstuvwxyz0123456789"
	fs := RunAll("npm.txt", []byte(tok))
	if len(fs) == 0 {
		t.Fatalf("expected npm token finding")
	}
}

func TestDigitalOceanPAT_Validator(t *testing.T) {
	EnableValidators = true
	tok := "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fs := RunAll("do.txt", []byte(tok))
	if len(fs) == 0 {
		t.Fatalf("expected do pat finding")
	}
}

func TestVercelToken_Validator(t *testing.T) {
	EnableValidators = true
	tok := "vercel_abcdefghijklmnopqrstuvwxyz012345"
	fs := RunAll("vercel.txt", []byte(tok))
	if len(fs) == 0 {
		t.Fatalf("expected vercel token finding")
	}
}

func TestSnyk_Notion_Okta_PostHog_Validators(t *testing.T) {
	EnableValidators = true
	snyk := "snyk_abcdefghijklmnopqrstuvwxyz0123456789"
	notion := "secret_abcdefghijklmnopqrstuvwxyz0123456789abcdefghij"
	okta := "SSWS abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	phc := "phc_abcdefghijklmnopqrstuvwxyz012345"
	phx := "phx_abcdefghijklmnopqrstuvwxyz012345"
	data := []byte(strings.Join([]string{snyk, notion, okta, phc, phx}, "\n"))
	fs := RunAll("misc.txt", data)
	want := map[string]bool{
		"snyk_token":           false,
		"notion_api_key":       false,
		"okta_api_token":       false,
		"posthog_project_key":  false,
		"posthog_personal_key": false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}

func TestCloudflare_Airtable_Netlify_Render_Shopify_Validators(t *testing.T) {
	EnableValidators = true
	cloudflare := "CF_API_TOKEN=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHijkl"
	airtable := "pat_abcdefghijklmnopqrstuvwxyz"
	netlify := "nf_abcdefghijklmnopqrstuvwxyz0123456789"
	hook := "https://api.netlify.com/build_hooks/abcdefghijklmnopqrstuvwxyzAB"
	render := "rnd_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	shopify := "shpat_0123456789abcdef0123456789abcdef"
	data := []byte(strings.Join([]string{cloudflare, airtable, netlify, hook, render, shopify}, "\n"))
	fs := RunAll("batch.txt", data)
	want := map[string]bool{
		"cloudflare_token":   false,
		"airtable_pat":       false,
		"netlify_token":      false,
		"netlify_build_hook": false,
		"render_api_key":     false,
		"shopify_token":      false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}

func TestDatabricks_Linear_Kaggle_Prisma_Hasura_Supabase_Validators(t *testing.T) {
	EnableValidators = true
	dapi := "dapiABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
	lin := "lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD"
	kaggle := `{"username":"user","key":"abcdefghijklmnopqrstuvwxyz012345"}`
	prisma := "prisma://myproj.us1.prisma-data.com/abcdef"
	hasura := "HASURA_GRAPHQL_ADMIN_SECRET=supersecretvalue0123"
	supabase := "SUPABASE_SERVICE_ROLE_KEY=supersecretvalue0123"
	data := []byte(strings.Join([]string{dapi, lin, kaggle, prisma, hasura, supabase}, "\n"))
	fs := RunAll("batch2.txt", data)
	want := map[string]bool{
		"databricks_pat":            false,
		"linear_api_key":            false,
		"kaggle_json_key":           false,
		"prisma_data_proxy_url":     false,
		"hasura_admin_secret":       false,
		"supabase_service_role_key": false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}

func TestAIProviders_Validators(t *testing.T) {
	EnableValidators = true
	anthropic := "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	groq := "gsk_abcdefghijklmnopqrstuvwxyz0123456789"
	cohere := "COHERE_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	mistral := "MISTRAL_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	ai21 := "AI21_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	az := "api-key: abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	data := []byte(strings.Join([]string{anthropic, groq, cohere, mistral, ai21, az}, "\n"))
	fs := RunAll("ai.txt", data)
	want := map[string]bool{
		"anthropic_api_key":    false,
		"groq_api_key":         false,
		"cohere_api_key":       false,
		"mistral_api_key":      false,
		"ai21_api_key":         false,
		"azure_openai_api_key": false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}

func TestSendGrid_HuggingFace_WandB_Validators(t *testing.T) {
	EnableValidators = true
	sg := "SG.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyz0123456789"
	hf := "hf_abcdefghijklmnopqrstuvwxyz0123456789ABCDE"
	wb := "WANDB_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	data := []byte(strings.Join([]string{sg, hf, wb}, "\n"))
	fs := RunAll("ml.txt", data)
	want := map[string]bool{
		"sendgrid_api_key":  false,
		"huggingface_token": false,
		"wandb_api_key":     false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}

func TestDockerHub_NewRelic_Validators(t *testing.T) {
	EnableValidators = true
	dckr := "dckr_pat_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
	nr := "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
	data := []byte(strings.Join([]string{dckr, nr}, "\n"))
	fs := RunAll("ops.txt", data)
	want := map[string]bool{
		"dockerhub_pat":    false,
		"newrelic_api_key": false,
	}
	for _, f := range fs {
		if _, ok := want[f.Detector]; ok {
			want[f.Detector] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Fatalf("expected finding for %s", k)
		}
	}
}
