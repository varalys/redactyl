package validate

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// LengthBetween returns true if n is within [min,max].
func LengthBetween(s string, min, max int) bool {
	n := len(s)
	return n >= min && n <= max
}

// IsAlphabet returns true if all characters in s are in allowed set.
func IsAlphabet(s, allowed string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(allowed, rune(s[i])) {
			return false
		}
	}
	return true
}

// IsBase64URLNoPad reports whether s is valid base64url (no padding) for JWT segments.
func IsBase64URLNoPad(s string) bool {
	if s == "" {
		return false
	}
	// base64.RawURLEncoding ignores padding; try decode
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// IsBase64Std reports whether s is valid standard base64 (padding optional).
func IsBase64Std(s string) bool {
	if s == "" {
		return false
	}
	// Accept both with and without padding
	_, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return true
	}
	_, err = base64.RawStdEncoding.DecodeString(s)
	return err == nil
}

// IsBase32Std reports whether s is valid base32 (padding optional).
func IsBase32Std(s string) bool {
	if s == "" {
		return false
	}
	_, err := base32.StdEncoding.DecodeString(s)
	if err == nil {
		return true
	}
	_, err = base32.HexEncoding.DecodeString(s)
	return err == nil
}

// IsHex returns true if s is valid hex.
func IsHex(s string) bool {
	if s == "" || len(s)%2 == 1 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// LooksLikeGitHubToken performs simple validation on a GitHub token candidate.
// Accepts ghp_, gho_, ghu_, ghs_, ghr_ followed by 36 base62 chars.
func LooksLikeGitHubToken(s string) bool {
	if !strings.HasPrefix(s, "gh") || len(s) != len("ghp_")+36 {
		// quick length filter: all prefixes are 4 chars like ghp_
		// prefix variants: gh[p|o|u|s|r]_
		if !(strings.HasPrefix(s, "ghp_") || strings.HasPrefix(s, "gho_") || strings.HasPrefix(s, "ghu_") || strings.HasPrefix(s, "ghs_") || strings.HasPrefix(s, "ghr_")) {
			return false
		}
	}
	if !(strings.HasPrefix(s, "ghp_") || strings.HasPrefix(s, "gho_") || strings.HasPrefix(s, "ghu_") || strings.HasPrefix(s, "ghs_") || strings.HasPrefix(s, "ghr_")) {
		return false
	}
	tail := s[4:]
	if len(tail) != 36 {
		return false
	}
	const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return IsAlphabet(tail, base62)
}

// LooksLikeOpenAIKey checks sk- prefix and reasonable alphabet/length.
func LooksLikeOpenAIKey(s string) bool {
	if !strings.HasPrefix(s, "sk-") {
		return false
	}
	tail := s[3:]
	// OpenAI keys are typically >= 40 base62 chars
	if !LengthBetween(tail, 40, 64) {
		return false
	}
	const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return IsAlphabet(tail, base62)
}

// LooksLikeAWSAccessKey checks for AKIA/ASIA + 16 uppercase alnum.
func LooksLikeAWSAccessKey(s string) bool {
	if !(strings.HasPrefix(s, "AKIA") || strings.HasPrefix(s, "ASIA")) {
		return false
	}
	if len(s) != 20 {
		return false
	}
	const upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return IsAlphabet(s[4:], upperAlnum)
}

// LooksLikeAWSSecretKey checks base64-like alphabet and exact length 40.
func LooksLikeAWSSecretKey(s string) bool {
	if len(s) != 40 {
		return false
	}
	// Many valid secrets are base64; allow / and + plus = padding, but we avoid decode to keep cheap
	const b64like = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
	return IsAlphabet(s, b64like)
}

// IsJWTStructure verifies 3 segments base64url-decodable for header and payload.
func IsJWTStructure(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	if !IsBase64URLNoPad(parts[0]) || !IsBase64URLNoPad(parts[1]) {
		return false
	}
	// signature can be empty or non-decodable; we do not require decoding
	return true
}
