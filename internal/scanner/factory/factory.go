package factory

import (
	"fmt"

	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/scanner"
	"github.com/redactyl/redactyl/internal/scanner/gitleaks"
)

// Config is the subset of configuration needed to create a scanner.
type Config struct {
	Root           string
	GitleaksConfig config.GitleaksConfig
}

// New creates a new scanner instance based on the configuration.
// Currently, it defaults to the Gitleaks scanner.
func New(cfg Config) (scanner.Scanner, error) {
	// Try to auto-detect .gitleaks.toml if not explicitly configured
	if cfg.GitleaksConfig.GetConfigPath() == "" {
		if detected := gitleaks.DetectConfigPath(cfg.Root); detected != "" {
			cfgPath := detected
			cfg.GitleaksConfig.ConfigPath = &cfgPath
		}
	}

	// Create Gitleaks scanner
	scnr, err := gitleaks.NewScanner(cfg.GitleaksConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create gitleaks scanner: %w", err)
	}

	return scnr, nil
}

// DefaultDetectors returns a list of common detector IDs.
// This is used for UI and help commands without instantiating a full scanner.
func DefaultDetectors() []string {
	// In the future, this could aggregate from multiple scanner types.
	// For now, we expose Gitleaks defaults.
	return []string{
		"github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token",
		"aws-access-key", "aws-secret-key", "aws-mws-key",
		"stripe-access-token", "stripe-secret-key",
		"slack-webhook-url", "slack-bot-token", "slack-app-token",
		"google-api-key", "google-oauth", "gcp-service-account",
		"gitlab-pat", "gitlab-pipeline-token", "gitlab-runner-token",
		"sendgrid-api-key",
		"openai-api-key",
		"anthropic-api-key",
		"npm-access-token",
		"pypi-token",
		"docker-config-auth",
		"jwt",
		"private-key",
		"generic-api-key",
	}
}
