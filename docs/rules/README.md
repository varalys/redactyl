# Rule reference

Short descriptions and examples for each detector. Use `redactyl detectors` to list the current set.

## Conventions
- Severity: low | medium | high
- Confidence: 0.0–1.0 (approximate likelihood)
- Inline suppression: `# redactyl:ignore`, `# redactyl:ignore-next-line`, region blocks

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
```
# Wrong length/prefix
OPENAI_API_KEY=sk-test-abc
```

---

For the full detector list, see the main README detectors section. Each SARIF rule will link here via its anchor (e.g., #github_token).


