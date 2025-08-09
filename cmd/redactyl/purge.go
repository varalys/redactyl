package redactyl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/franzer/redactyl/internal/gitexec"
	"github.com/spf13/cobra"
)

func init() {
	purge := &cobra.Command{Use: "purge", Short: "History rewrite helpers (git filter-repo)"}
	rootCmd.AddCommand(purge)

	var yes bool
	var backup string
	var dryRun bool
	var summary string
	pathCmd := &cobra.Command{
		Use:   "path <file>",
		Short: "Remove a file from all history (DANGEROUS: rewrites history)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := gitexec.DetectFilterRepo(); err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("refusing to rewrite history without --yes")
			}
			if backup == "" {
				backup = time.Now().Format("redactyl-backup-20060102-150405")
			}
			// commands we will run
			commands := [][]string{
				{"git", "branch", backup},
				{"git", "filter-repo", "--path", args[0], "--invert-paths"},
			}
			if dryRun {
				for _, c := range commands {
					fmt.Fprintln(os.Stderr, strings.Join(c, " "))
				}
			} else {
				ctx, cancel := gitexec.WithTimeout(10 * time.Minute)
				defer cancel()
				if err := gitexec.Git(ctx, "branch", backup); err != nil {
					return err
				}
				if err := gitexec.Git(ctx, "filter-repo", "--path", args[0], "--invert-paths"); err != nil {
					return err
				}
				fmt.Println("History rewritten. You likely need to force-push:")
				fmt.Println("  git push --force --all && git push --force --tags")
				fmt.Printf("A backup branch was created: %s\n", backup)
			}
			if summary != "" {
				_ = writePurgeSummary(summary, map[string]any{
					"action":        "purge.path",
					"target":        args[0],
					"backup_branch": backup,
					"dry_run":       dryRun,
					"commands":      commands,
					"timestamp":     time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	pathCmd.Flags().BoolVar(&yes, "yes", false, "confirm history rewrite")
	pathCmd.Flags().StringVar(&backup, "backup-branch", "", "name of backup branch to create")
	pathCmd.Flags().BoolVar(&dryRun, "dry-run", false, "print commands without executing")
	pathCmd.Flags().StringVar(&summary, "summary", "", "write remediation summary JSON to this path")
	purge.AddCommand(pathCmd)

	// purge pattern: remove paths by glob(s)
	var globs []string
	var dryRunPat bool
	var summaryPat string
	var yesPat bool
	var backupPat string
	patternCmd := &cobra.Command{
		Use:   "pattern",
		Short: "Remove files from all history by glob(s) (DANGEROUS)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := gitexec.DetectFilterRepo(); err != nil {
				return err
			}
			if !yesPat {
				return fmt.Errorf("refusing to rewrite history without --yes")
			}
			if len(globs) == 0 {
				return fmt.Errorf("--glob required (repeatable)")
			}
			if backupPat == "" {
				backupPat = time.Now().Format("redactyl-backup-20060102-150405")
			}
			// compose command
			cmdArgs := []string{"filter-repo"}
			for _, g := range globs {
				cmdArgs = append(cmdArgs, "--path-glob", g)
			}
			cmdArgs = append(cmdArgs, "--invert-paths")

			commands := [][]string{{"git", "branch", backupPat}, append([]string{"git"}, cmdArgs...)}
			if dryRunPat {
				for _, c := range commands {
					fmt.Fprintln(os.Stderr, strings.Join(c, " "))
				}
			} else {
				ctx, cancel := gitexec.WithTimeout(10 * time.Minute)
				defer cancel()
				if err := gitexec.Git(ctx, "branch", backupPat); err != nil {
					return err
				}
				if err := gitexec.Git(ctx, cmdArgs...); err != nil {
					return err
				}
				fmt.Println("History rewritten. You likely need to force-push:")
				fmt.Println("  git push --force --all && git push --force --tags")
				fmt.Printf("A backup branch was created: %s\n", backupPat)
			}
			if summaryPat != "" {
				_ = writePurgeSummary(summaryPat, map[string]any{
					"action":        "purge.pattern",
					"globs":         globs,
					"backup_branch": backupPat,
					"dry_run":       dryRunPat,
					"commands":      commands,
					"timestamp":     time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	patternCmd.Flags().StringSliceVar(&globs, "glob", nil, "glob pattern(s) to purge (repeatable)")
	patternCmd.Flags().BoolVar(&dryRunPat, "dry-run", false, "print commands without executing")
	patternCmd.Flags().StringVar(&summaryPat, "summary", "", "write remediation summary JSON to this path")
	patternCmd.Flags().BoolVar(&yesPat, "yes", false, "confirm history rewrite")
	patternCmd.Flags().StringVar(&backupPat, "backup-branch", "", "name of backup branch to create")
	purge.AddCommand(patternCmd)

	// purge replace: replace content using filter-repo replace-text file
	var replFile string
	var dryRunRepl bool
	var summaryRepl string
	var yesRepl bool
	var backupRepl string
	replaceCmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace sensitive content across history using --replace-text file (DANGEROUS)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := gitexec.DetectFilterRepo(); err != nil {
				return err
			}
			if !yesRepl {
				return fmt.Errorf("refusing to rewrite history without --yes")
			}
			if replFile == "" {
				return fmt.Errorf("--replacements file is required")
			}
			if backupRepl == "" {
				backupRepl = time.Now().Format("redactyl-backup-20060102-150405")
			}

			commands := [][]string{
				{"git", "branch", backupRepl},
				{"git", "filter-repo", "--replace-text", replFile},
			}
			if dryRunRepl {
				for _, c := range commands {
					fmt.Fprintln(os.Stderr, strings.Join(c, " "))
				}
			} else {
				ctx, cancel := gitexec.WithTimeout(10 * time.Minute)
				defer cancel()
				if err := gitexec.Git(ctx, "branch", backupRepl); err != nil {
					return err
				}
				if err := gitexec.Git(ctx, "filter-repo", "--replace-text", replFile); err != nil {
					return err
				}
				fmt.Println("History rewritten. You likely need to force-push:")
				fmt.Println("  git push --force --all && git push --force --tags")
				fmt.Printf("A backup branch was created: %s\n", backupRepl)
			}
			if summaryRepl != "" {
				_ = writePurgeSummary(summaryRepl, map[string]any{
					"action":        "purge.replace",
					"replace_file":  replFile,
					"backup_branch": backupRepl,
					"dry_run":       dryRunRepl,
					"commands":      commands,
					"timestamp":     time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	replaceCmd.Flags().StringVar(&replFile, "replacements", "", "path to filter-repo replace-text file")
	replaceCmd.Flags().BoolVar(&dryRunRepl, "dry-run", false, "print commands without executing")
	replaceCmd.Flags().StringVar(&summaryRepl, "summary", "", "write remediation summary JSON to this path")
	replaceCmd.Flags().BoolVar(&yesRepl, "yes", false, "confirm history rewrite")
	replaceCmd.Flags().StringVar(&backupRepl, "backup-branch", "", "name of backup branch to create")
	purge.AddCommand(replaceCmd)
}

// writePurgeSummary writes a JSON summary file for purge actions.
func writePurgeSummary(path string, data map[string]any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
