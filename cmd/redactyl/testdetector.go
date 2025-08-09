package redactyl

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/franzer/redactyl/internal/detectors"
	"github.com/franzer/redactyl/internal/report"
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "test-detector <id>",
		Short: "Run a detector against provided text (stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id := args[0]
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			fs := detectors.RunFunction(id, "stdin", data)
			if fs == nil {
				fmt.Fprintf(os.Stderr, "unknown detector id: %s\n", id)
				fmt.Fprintf(os.Stderr, "available: %s\n", strings.Join(detectors.FunctionIDs(), ", "))
				os.Exit(2)
			}
			// Pretty print using current table renderer
			report.PrintTable(os.Stdout, fs, report.PrintOptions{})
			return nil
		},
	}
	// help message includes function IDs
	cmd.Long = "Available detectors: " + strings.Join(detectors.FunctionIDs(), ", ")
	rootCmd.AddCommand(cmd)
}
