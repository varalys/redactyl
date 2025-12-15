package tui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "long secret shows first 6 chars",
			input:  "ghp_SuperSecretToken12345",
			expect: "ghp_Su...",
		},
		{
			name:   "exactly 7 chars shows first 6",
			input:  "1234567",
			expect: "123456...",
		},
		{
			name:   "6 chars or less fully redacted",
			input:  "123456",
			expect: "...",
		},
		{
			name:   "3 chars fully redacted",
			input:  "abc",
			expect: "...",
		},
		{
			name:   "empty string",
			input:  "",
			expect: "...",
		},
		{
			name:   "AWS key prefix preserved",
			input:  "AKIA1234567890ABCDEF",
			expect: "AKIA12...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecret(tt.input)
			if got != tt.expect {
				t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestDefaultPrefs(t *testing.T) {
	prefs := DefaultPrefs()
	if !prefs.HideSecrets {
		t.Error("DefaultPrefs().HideSecrets should be true")
	}
}

func TestLoadPrefs_NoFile(t *testing.T) {
	// When no prefs file exists, should return defaults
	prefs := LoadPrefs()
	if !prefs.HideSecrets {
		t.Error("LoadPrefs() with no file should return defaults (HideSecrets=true)")
	}
}

func TestSaveAndLoadPrefs(t *testing.T) {
	// Create a temp directory for testing
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)
	os.Setenv("HOME", tmpDir)

	// Test saving with HideSecrets = false
	prefs := Prefs{HideSecrets: false}
	err := SavePrefs(prefs)
	if err != nil {
		t.Fatalf("SavePrefs failed: %v", err)
	}

	// Verify file was created
	prefsFile := filepath.Join(tmpDir, ".redactyl", "tui_prefs.json")
	if _, err := os.Stat(prefsFile); os.IsNotExist(err) {
		t.Fatal("prefs file was not created")
	}

	// Load and verify
	loaded := LoadPrefs()
	if loaded.HideSecrets != false {
		t.Error("Loaded prefs should have HideSecrets=false")
	}

	// Test saving with HideSecrets = true
	prefs.HideSecrets = true
	err = SavePrefs(prefs)
	if err != nil {
		t.Fatalf("SavePrefs failed: %v", err)
	}

	loaded = LoadPrefs()
	if loaded.HideSecrets != true {
		t.Error("Loaded prefs should have HideSecrets=true")
	}
}
