package redactyl

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/franzer/redactyl/internal/config"
	"github.com/franzer/redactyl/internal/detectors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	cfgPreset          string
	cfgOutput          string
	cfgEnable          string
	cfgDisable         string
	cfgThreads         int
	cfgMaxBytes        int64
	cfgMinConfidence   float64
	cfgNoColor         bool
	cfgDefaultExcludes bool
)

func init() {
	cfgCmd := &cobra.Command{Use: "config", Short: "Configuration helpers"}
	rootCmd.AddCommand(cfgCmd)

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a .redactyl.yml with selected detectors and options",
		RunE:  runConfigInit,
	}
	cfgCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&cfgPreset, "preset", "standard", "detector preset: minimal | standard | maximal")
	initCmd.Flags().StringVar(&cfgOutput, "output", ".redactyl.yml", "output file path")
	initCmd.Flags().StringVar(&cfgEnable, "enable", "", "comma-separated detector IDs to enable (overrides preset if set)")
	initCmd.Flags().StringVar(&cfgDisable, "disable", "", "comma-separated detector IDs to disable")
	initCmd.Flags().IntVar(&cfgThreads, "threads", 0, "worker threads (0=GOMAXPROCS)")
	initCmd.Flags().Int64Var(&cfgMaxBytes, "max-bytes", 1<<20, "skip files larger than this")
	initCmd.Flags().Float64Var(&cfgMinConfidence, "min-confidence", 0.0, "minimum detector confidence (0.0-1.0)")
	initCmd.Flags().BoolVar(&cfgNoColor, "no-color", false, "disable color output by default")
	initCmd.Flags().BoolVar(&cfgDefaultExcludes, "default-excludes", true, "enable default ignore patterns")
}

func runConfigInit(_ *cobra.Command, _ []string) error {
	// Determine enable set
	enable := strings.TrimSpace(cfgEnable)
	if enable == "" {
		switch strings.ToLower(cfgPreset) {
		case "minimal":
			enable = strings.Join([]string{
				"aws_access_key", "aws_secret_key", "private_key_block", "github_token", "jwt",
			}, ",")
		case "maximal":
			ids := detectors.IDs()
			sort.Strings(ids)
			enable = strings.Join(ids, ",")
		default: // standard
			ids := detectors.IDs()
			sort.Strings(ids)
			enable = strings.Join(ids, ",")
		}
	}

	fc := config.FileConfig{
		Include:         nil,
		Exclude:         nil,
		MaxBytes:        int64Ptr(cfgMaxBytes),
		Enable:          strPtr(enable),
		Disable:         optStrPtr(cfgDisable),
		Threads:         intPtr(cfgThreads),
		MinConfidence:   floatPtr(cfgMinConfidence),
		NoColor:         boolPtr(cfgNoColor),
		DefaultExcludes: boolPtr(cfgDefaultExcludes),
	}

	b, err := yaml.Marshal(&fc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgOutput, b, 0644); err != nil {
		return err
	}
	fmt.Println("Wrote", cfgOutput)
	return nil
}

func strPtr(s string) *string { return &s }
func optStrPtr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}
func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}
func int64Ptr(v int64) *int64     { return &v }
func floatPtr(v float64) *float64 { return &v }
func boolPtr(v bool) *bool        { return &v }
