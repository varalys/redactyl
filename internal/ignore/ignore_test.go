package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreMatch(t *testing.T) {
	dir := t.TempDir()
	ig := filepath.Join(dir, ".redactylignore")
	content := "node_modules/\n*.pem\n# comment\n\nsecret.env\n"
	if err := os.WriteFile(ig, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := Load(ig)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"node_modules/pkg/index.js": true,
		"certs/key.pem":             true,
		"secret.env":                true,
		"src/app.go":                false,
	}
	for p, want := range cases {
		if got := m.Match(p); got != want {
			t.Fatalf("Match(%q)=%v want %v", p, got, want)
		}
	}
}
