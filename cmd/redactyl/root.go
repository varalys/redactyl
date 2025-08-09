package redactyl

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	flagJSON            bool
	flagSARIF           bool
	flagThreads         int
	flagFailOn          string
	flagNoColor         bool
	flagMinConfidence   float64
	flagDryRun          bool
	flagNoCache         bool
	flagDefaultExcludes bool
	flagNoUpdateCheck   bool
	flagSelfUpdate      bool

	version = "0.1.0"
)

// rootCmd is the base Cobra command for the Redactyl CLI.
var rootCmd = &cobra.Command{
	Use:           "redactyl",
	Short:         "Find secrets in your repo",
	Long:          "Redactyl scans your working tree, staged changes, diffs or history and reports secrets with low noise.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the Redactyl CLI. It should be called by the main package.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit JSON")
	rootCmd.PersistentFlags().BoolVar(&flagSARIF, "sarif", false, "emit SARIF 2.1.0")
	rootCmd.PersistentFlags().IntVar(&flagThreads, "threads", 0, "worker count (0 = GOMAXPROCS)")
	rootCmd.PersistentFlags().StringVar(&flagFailOn, "fail-on", "medium", "fail on low|medium|high")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colorized output")
	rootCmd.PersistentFlags().Float64Var(&flagMinConfidence, "min-confidence", 0.0, "only show findings with confidence >= value (0-1)")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "show what would be scanned without opening files")
	rootCmd.PersistentFlags().BoolVar(&flagNoCache, "no-cache", false, "disable incremental scan cache")
	rootCmd.PersistentFlags().BoolVar(&flagDefaultExcludes, "default-excludes", true, "apply built-in exclude list (node_modules, dist, images, etc.)")
	rootCmd.PersistentFlags().BoolVar(&flagNoUpdateCheck, "no-update-check", false, "disable update check")
	rootCmd.PersistentFlags().BoolVar(&flagSelfUpdate, "self-update", false, "update redactyl to the latest release")
}
