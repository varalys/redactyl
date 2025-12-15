package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Prefs holds user preferences for the TUI that persist across sessions.
type Prefs struct {
	// HideSecrets controls whether secret values are redacted in the display.
	// Defaults to true for security (prevents shoulder surfing).
	HideSecrets bool `json:"hide_secrets"`
}

// DefaultPrefs returns the default preferences.
func DefaultPrefs() Prefs {
	return Prefs{
		HideSecrets: true, // Default to hidden for security
	}
}

// prefsPath returns the path to the TUI preferences file.
func prefsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".redactyl", "tui_prefs.json"), nil
}

// LoadPrefs loads user preferences from disk, returning defaults if not found.
func LoadPrefs() Prefs {
	prefs := DefaultPrefs()

	path, err := prefsPath()
	if err != nil {
		return prefs
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return prefs // File doesn't exist yet, use defaults
	}

	// Ignore unmarshal errors, just use defaults
	_ = json.Unmarshal(data, &prefs) //nolint:errcheck // Intentionally ignore: fall back to defaults
	return prefs
}

// SavePrefs persists user preferences to disk.
func SavePrefs(prefs Prefs) error {
	path, err := prefsPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// redactSecret returns a redacted version of a secret string.
// Shows first 4 characters followed by "***" for context.
// Very short secrets are fully redacted.
func redactSecret(s string) string {
	if len(s) <= 4 {
		return "***"
	}
	return s[:4] + "***"
}
