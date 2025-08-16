package validate

import "testing"

func TestLengthBetween(t *testing.T) {
	if !LengthBetween("abcd", 2, 5) {
		t.Fatal("expected true for length between")
	}
	if LengthBetween("a", 2, 5) {
		t.Fatal("expected false for too short")
	}
	if LengthBetween("abcdef", 2, 5) {
		t.Fatal("expected false for too long")
	}
}

func TestIsAlphabet(t *testing.T) {
	if !IsAlphabet("abcXYZ09", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
		t.Fatal("expected alnum to be allowed")
	}
	if IsAlphabet("abc-", "abc") {
		t.Fatal("expected false when char not allowed")
	}
}

func TestBase64AndBase32AndHex(t *testing.T) {
	if !IsBase64URLNoPad("eyJmb28iOiJiYXIifQ") { // {"foo":"bar"}
		t.Fatal("expected valid base64url")
	}
	if !IsBase64Std("YWJjZA==") { // abcd
		t.Fatal("expected valid base64 std")
	}
	if !IsBase32Std("MFRGGZDFMZTWQ2LK") { // helloworld
		t.Fatal("expected valid base32 std")
	}
	if !IsHex("deadbeef") {
		t.Fatal("expected valid hex")
	}
	if IsHex("abc") { // odd length
		t.Fatal("expected odd-length hex to be invalid")
	}
}

func TestLooksLikeGitHubToken(t *testing.T) {
	good := "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" // 36 tail
	if !LooksLikeGitHubToken(good) {
		t.Fatalf("expected valid github token: %s", good)
	}
	bad := "ghp_short"
	if LooksLikeGitHubToken(bad) {
		t.Fatal("expected invalid github token")
	}
}

func TestLooksLikeOpenAIKey(t *testing.T) {
	good := "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123" // tail len 52
	if !LooksLikeOpenAIKey(good) {
		t.Fatalf("expected valid openai key: %s", good)
	}
	bad := "sk-short"
	if LooksLikeOpenAIKey(bad) {
		t.Fatal("expected invalid openai key")
	}
}

func TestAWSKeyValidators(t *testing.T) {
	if !LooksLikeAWSAccessKey("AKIAABCDEFGHIJKLMNOP") { // 16 after prefix
		t.Fatal("expected valid aws access key")
	}
	if LooksLikeAWSAccessKey("AKIA123") {
		t.Fatal("expected invalid aws access key (too short)")
	}
	if !LooksLikeAWSSecretKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") { // 40 chars
		t.Fatal("expected valid aws secret key")
	}
	if LooksLikeAWSSecretKey("short") {
		t.Fatal("expected invalid aws secret key")
	}
}

func TestIsJWTStructure(t *testing.T) {
	// header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	// payload: {"sub":"1234567890"} -> eyJzdWIiOiIxMjM0NTY3ODkwIn0
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	if !IsJWTStructure(jwt) {
		t.Fatalf("expected valid jwt structure: %s", jwt)
	}
	if IsJWTStructure("not.jwt") {
		t.Fatal("expected invalid jwt structure")
	}
}
