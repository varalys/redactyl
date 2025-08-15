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
	Archives        *bool   `yaml:"archives"`
	Containers      *bool   `yaml:"containers"`
	IaC             *bool   `yaml:"iac"`
	MaxArchiveBytes *int64  `yaml:"max_archive_bytes"`
	MaxEntries      *int    `yaml:"max_entries"`
	MaxDepth        *int    `yaml:"max_depth"`
	ScanTimeBudget  *string `yaml:"scan_time_budget"`
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
