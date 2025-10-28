package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileConfig is the on-disk YAML configuration shape for Redactyl.
type FileConfig struct {
	Include           *string  `yaml:"include"`
	Exclude           *string  `yaml:"exclude"`
	MaxBytes          *int64   `yaml:"max_bytes"`
	Enable            *string  `yaml:"enable"`
	Disable           *string  `yaml:"disable"`
	Threads           *int     `yaml:"threads"`
	MinConfidence     *float64 `yaml:"min_confidence"`
	NoColor           *bool    `yaml:"no_color"`
	DefaultExcludes   *bool    `yaml:"default_excludes"`
	NoValidators      *bool    `yaml:"no_validators"`
	NoStructured      *bool    `yaml:"no_structured"`
	VerifyMode        *string  `yaml:"verify"`
	DisableValidators *string  `yaml:"disable_validators"`
	DisableStructured *string  `yaml:"disable_structured"`

	// Deep scanning config mirrors CLI flags
	Archives             *bool   `yaml:"archives"`
	Containers           *bool   `yaml:"containers"`
	IaC                  *bool   `yaml:"iac"`
	Helm                 *bool   `yaml:"helm"`
	K8s                  *bool   `yaml:"k8s"`
	MaxArchiveBytes      *int64  `yaml:"max_archive_bytes"`
	MaxEntries           *int    `yaml:"max_entries"`
	MaxDepth             *int    `yaml:"max_depth"`
	ScanTimeBudget       *string `yaml:"scan_time_budget"`
	GlobalArtifactBudget *string `yaml:"global_artifact_budget"`

	// Gitleaks integration config
	Gitleaks *GitleaksConfig `yaml:"gitleaks"`
}

// GitleaksConfig holds configuration for Gitleaks integration.
type GitleaksConfig struct {
	// ConfigPath is the path to a .gitleaks.toml configuration file.
	// If empty, Gitleaks will use its default rules.
	ConfigPath *string `yaml:"config"`

	// BinaryPath is an explicit path to the gitleaks binary.
	// If empty, the binary will be searched in $PATH and ~/.redactyl/bin.
	BinaryPath *string `yaml:"binary"`

	// AutoDownload enables automatic downloading of the gitleaks binary
	// if it's not found. Defaults to true.
	AutoDownload *bool `yaml:"auto_download"`

	// Version pins a specific version of gitleaks to use/download.
	// If empty, the latest available version will be used.
	Version *string `yaml:"version"`
}

// LoadFile reads a YAML config file from the provided path.
func LoadFile(path string) (FileConfig, error) {
	var cfg FileConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// LoadLocal searches for a repo-local config file in the given root.
// It supports .redactyl.yml/.yaml and redactyl.yml/.yaml.
func LoadLocal(repoRoot string) (FileConfig, error) {
	var cfg FileConfig
	for _, name := range []string{".redactyl.yml", ".redactyl.yaml", "redactyl.yml", "redactyl.yaml"} {
		p := filepath.Join(repoRoot, name)
		if _, err := os.Stat(p); err == nil {
			return LoadFile(p)
		}
	}
	return cfg, errors.New("no local config")
}

// LoadGlobal loads the global config file from XDG base directory or ~/.config.
func LoadGlobal() (FileConfig, error) {
	var cfg FileConfig
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			base = filepath.Join(home, ".config")
		}
	}
	if base == "" {
		return cfg, errors.New("no config dir")
	}
	p := filepath.Join(base, "redactyl", "config.yml")
	if _, err := os.Stat(p); err == nil {
		return LoadFile(p)
	}
	return cfg, errors.New("no global config")
}

// GetGitleaksConfig returns the Gitleaks configuration with sensible defaults.
func (fc FileConfig) GetGitleaksConfig() GitleaksConfig {
	if fc.Gitleaks == nil {
		// Return default config
		autoDownload := true
		return GitleaksConfig{
			AutoDownload: &autoDownload,
		}
	}

	// Apply defaults for nil fields
	cfg := *fc.Gitleaks
	if cfg.AutoDownload == nil {
		autoDownload := true
		cfg.AutoDownload = &autoDownload
	}

	return cfg
}

// GetGitleaksBinaryPath returns the custom binary path or empty string.
func (gc GitleaksConfig) GetBinaryPath() string {
	if gc.BinaryPath == nil {
		return ""
	}
	return *gc.BinaryPath
}

// GetGitleaksConfigPath returns the config file path or empty string.
func (gc GitleaksConfig) GetConfigPath() string {
	if gc.ConfigPath == nil {
		return ""
	}
	return *gc.ConfigPath
}

// IsAutoDownloadEnabled returns true if auto-download is enabled (default: true).
func (gc GitleaksConfig) IsAutoDownloadEnabled() bool {
	if gc.AutoDownload == nil {
		return true // Default to true
	}
	return *gc.AutoDownload
}

// GetVersion returns the pinned version or empty string for latest.
func (gc GitleaksConfig) GetVersion() string {
	if gc.Version == nil {
		return ""
	}
	return *gc.Version
}
