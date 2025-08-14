# Rule reference

Short descriptions and examples for each detector. Use `redactyl detectors` to list the current set.

## Conventions
- Severity: low | medium | high
- Confidence: 0.0–1.0 (approximate likelihood)
- Inline suppression: `# redactyl:ignore`, `# redactyl:ignore-next-line`, region blocks
- Structured JSON/YAML: some rules can also be detected from structured fields when values are assigned to well-known keys (e.g., `aws_access_key_id`, `aws_secret_access_key`, `openai_api_key`, `apiKey`).

---

## aws_access_key
- Detects AWS Access Key IDs (AKIA...)
- Example true positive:
```
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
```
- Example false positive:
```
# Partial string that doesn't fit full pattern
key = "AKIA123"
```

## aws_secret_key
- Detects AWS Secret Access Keys
- Example true positive:
```
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
- Example false positive:
```
# Random base64 that doesn't match checks
x = "ZXhhbXBsZQ=="
```

## github_token
- Detects GitHub personal access tokens
- Example true positive:
```
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234
```
- Example false positive:
Validator notes:
- Prefix must be one of `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- Tail must be 36 base62 characters
Structured keys:
- JSON/YAML keys containing `github`
```
# Short or wrong prefix
GITHUB_TOKEN=ghp_short
```

## jwt
- Detects JWT-like tokens
- Example true positive:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature
```
- Example false positive:
Validator notes:
- Header and payload segments must be base64url-decodable (no padding); signature not validated
```
# Two dot segments but non-base64 words
x = "foo.bar.baz"
```

## private_key_block
- Detects PEM private key blocks
- Example true positive:
```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```
- Example false positive:
```
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

## openai_api_key
- Detects OpenAI API keys
- Example true positive:
```
OPENAI_API_KEY=sk-abcdef1234567890abcdef1234
```
- Example false positive:
Validator notes:
- `sk-` prefix; tail 40–64 base62 characters
Structured keys:
- JSON/YAML keys containing `openai` or `openai_api_key`
## stripe_secret
- Detects Stripe live secrets (`sk_live_...`)
Validator notes:
- `sk_live_` prefix; tail base62 with length >= 24

## slack_webhook
- Detects Slack incoming webhooks
Validator notes:
- URL shape `https://hooks.slack.com/services/<seg>/<seg>/<token>`; overall length sanity-checked

## discord_webhook
- Detects Discord webhooks
Validator notes:
- URL shape `https://discord.com/api/webhooks/<id>/<token>`; overall length sanity-checked

## twilio_* (account_sid, api_key_sid, auth_token)
Validator notes:
- `AC`/`SK` + 32 hex for SIDs; auth token 32 hex

## gitlab_token
- Detects GitLab PATs
Validator notes:
- `glpat-` + 20+ characters from base62/underscore/dash

## terraform_cloud_token
- Detects Terraform Cloud/Enterprise tokens
Validator notes:
- `tfe.` or `tfc.` prefix; tail base62 with length >= 30

## mapbox_token
- Detects Mapbox tokens
Validator notes:
- `pk.` + >=50 base62 or `sk.` + >=70 base62
```
# Wrong length/prefix
OPENAI_API_KEY=sk-test-abc
```

---

For the full detector list, see the main README detectors section. Each SARIF rule will link here via its anchor (e.g., #github_token).


