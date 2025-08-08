package redactyl

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/redactyl/redactyl/internal/engine"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage baselines",
	}

	update := &cobra.Command{
		Use:   "update",
		Short: "Update baseline from current scan",
		RunE: func(cmd *cobra.Command, _ []string) error {
			abs, _ := filepath.Abs(".")
			cfg := engine.Config{Root: abs, Threads: flagThreads}
			results, err := engine.Scan(cfg)
			if err != nil {
				return err
			}
			if err := report.SaveBaseline("redactyl.baseline.json", results); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "Baseline updated.")
			return nil
		},
	}

	rootCmd.AddCommand(cmd)
	cmd.AddCommand(update)
}
