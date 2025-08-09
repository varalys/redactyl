package redactyl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/franzer/redactyl/internal/files"
	"github.com/franzer/redactyl/internal/gitexec"
	"github.com/franzer/redactyl/internal/redact"
	"github.com/spf13/cobra"
)

func init() {
	fix := &cobra.Command{Use: "fix", Short: "Forward remediation helpers"}
	rootCmd.AddCommand(fix)

	var keepLocal bool
	var addIgnore bool
	var dryRun bool
	var summary string
	pathCmd := &cobra.Command{
		Use:   "path <file>",
		Short: "Remove a tracked secret file from the repo and ignore it",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := args[0]
			abs, _ := filepath.Abs(".")
			if addIgnore {
				if err := files.AppendIgnore(abs, p); err != nil {
					return err
				}
			}
			cmdRm := []string{"git", "rm", "--cached", p}
			cmdCommit := []string{"git", "commit", "-m", fmt.Sprintf("Remove %s from repo; add to .gitignore", p)}
			if dryRun {
				fmt.Fprintln(os.Stderr, strings.Join(cmdRm, " "))
				fmt.Fprintln(os.Stderr, strings.Join(cmdCommit, " "))
			} else {
				// remove from index only
				ctx, cancel := gitexec.WithTimeout(10 * time.Second)
				defer cancel()
				if err := gitexec.Git(ctx, "rm", "--cached", p); err != nil {
					return fmt.Errorf("git rm --cached failed: %w", err)
				}
				if err := gitexec.Git(ctx, "commit", "-m", fmt.Sprintf("Remove %s from repo; add to .gitignore", p)); err != nil {
					return fmt.Errorf("git commit failed: %w", err)
				}
			}
			if keepLocal {
				// ensure file exists locally (rm --cached kept it on disk)
				fmt.Fprintln(os.Stderr, "kept local working copy of", p)
			}
			if dryRun {
				fmt.Println("(dry-run) would remove and commit:", p)
			} else {
				fmt.Println("Committed removal of", p)
			}
			if summary != "" {
				// write simple one-line summary JSON
				_ = writeFixSummary(summary, map[string]any{
					"action":    "fix.path",
					"target":    p,
					"addIgnore": addIgnore,
					"dry_run":   dryRun,
					"timestamp": time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	pathCmd.Flags().BoolVar(&keepLocal, "keep-local", true, "keep working copy after removing from index")
	pathCmd.Flags().BoolVar(&addIgnore, "add-ignore", true, "append path to .gitignore")
	pathCmd.Flags().BoolVar(&dryRun, "dry-run", false, "print commands without executing")
	pathCmd.Flags().StringVar(&summary, "summary", "", "write remediation summary JSON to this path")
	fix.AddCommand(pathCmd)

	var pattern, replace string
	var dryRunRedact bool
	var summaryRedact string
	redactCmd := &cobra.Command{
		Use:   "redact --file <path> --pattern <regex> --replace <text>",
		Short: "Redact secrets in a tracked file by regex and commit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			file, _ := cmd.Flags().GetString("file")
			if file == "" || pattern == "" {
				return fmt.Errorf("--file and --pattern are required")
			}
			rx, err := regexp.Compile(pattern)
			if err != nil {
				return err
			}
			reps := []redact.Replacement{{Pattern: rx, Replace: replace}}
			if dryRunRedact {
				would, err := redact.WouldChange(file, reps)
				if err != nil {
					return err
				}
				if !would {
					fmt.Println("(dry-run) no changes needed")
					return nil
				}
				fmt.Fprintln(os.Stderr, strings.Join([]string{"apply redaction to", file}, " "))
				fmt.Fprintln(os.Stderr, strings.Join([]string{"git", "add", file}, " "))
				fmt.Fprintln(os.Stderr, strings.Join([]string{"git", "commit", "-m", fmt.Sprintf("Redact secrets in %s", file)}, " "))
			} else {
				changed, err := redact.Apply(file, reps)
				if err != nil {
					return err
				}
				if !changed {
					fmt.Println("No changes needed")
					return nil
				}
				ctx, cancel := gitexec.WithTimeout(10 * time.Second)
				defer cancel()
				if err := gitexec.Git(ctx, "add", file); err != nil {
					return err
				}
				msg := fmt.Sprintf("Redact secrets in %s", file)
				if err := gitexec.Git(ctx, "commit", "-m", msg); err != nil {
					return err
				}
				fmt.Println("Committed redaction in", file)
			}
			if summaryRedact != "" {
				_ = writeFixSummary(summaryRedact, map[string]any{
					"action":    "fix.redact",
					"file":      file,
					"pattern":   pattern,
					"dry_run":   dryRunRedact,
					"timestamp": time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	redactCmd.Flags().String("file", "", "file to redact in-place")
	redactCmd.Flags().StringVar(&pattern, "pattern", "", "regex to match secret content to redact")
	redactCmd.Flags().StringVar(&replace, "replace", "<redacted>", "replacement text")
	redactCmd.Flags().BoolVar(&dryRunRedact, "dry-run", false, "print actions without executing")
	redactCmd.Flags().StringVar(&summaryRedact, "summary", "", "write remediation summary JSON to this path")
	fix.AddCommand(redactCmd)

	// fix dotenv: create/update .env.example and optionally untrack .env
	var srcDotenv string
	var dstExample string
	var keepValues bool
	var addGitignore bool
	var dryRunEnv bool
	var summaryEnv string
	dotenvCmd := &cobra.Command{
		Use:   "dotenv",
		Short: "Generate .env.example from .env (and optionally untrack .env)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if srcDotenv == "" {
				srcDotenv = ".env"
			}
			if dstExample == "" {
				dstExample = ".env.example"
			}
			// read source
			content, err := os.ReadFile(srcDotenv)
			if err != nil {
				return fmt.Errorf("read %s: %w", srcDotenv, err)
			}
			// transform: strip values unless keepValues
			lines := strings.Split(string(content), "\n")
			for i, ln := range lines {
				// ignore comments and blanks; scrub only KEY=VALUE lines
				if strings.HasPrefix(strings.TrimSpace(ln), "#") || !strings.Contains(ln, "=") {
					continue
				}
				if keepValues {
					continue
				}
				kv := strings.SplitN(ln, "=", 2)
				key := strings.TrimSpace(kv[0])
				lines[i] = key + "="
			}
			out := strings.Join(lines, "\n")
			if dryRunEnv {
				fmt.Fprintf(os.Stderr, "write %s (derived from %s)\n", dstExample, srcDotenv)
				if addGitignore {
					fmt.Fprintln(os.Stderr, "echo '.env' >> .gitignore (idempotent)")
				}
				fmt.Fprintln(os.Stderr, "git add", dstExample)
				fmt.Fprintln(os.Stderr, "git commit -m \"Add/refresh .env.example\"")
			} else {
				if err := os.WriteFile(dstExample, []byte(out), 0644); err != nil {
					return err
				}
				if addGitignore {
					abs, _ := filepath.Abs(".")
					if err := files.AppendIgnore(abs, ".env"); err != nil {
						return err
					}
				}
				ctx, cancel := gitexec.WithTimeout(10 * time.Second)
				defer cancel()
				if err := gitexec.Git(ctx, "add", dstExample); err != nil {
					return err
				}
				if err := gitexec.Git(ctx, "commit", "-m", "Add/refresh .env.example"); err != nil {
					return err
				}
				fmt.Println("Committed", dstExample)
			}
			if summaryEnv != "" {
				_ = writeFixSummary(summaryEnv, map[string]any{
					"action":       "fix.dotenv",
					"source":       srcDotenv,
					"destination":  dstExample,
					"keepValues":   keepValues,
					"addGitignore": addGitignore,
					"dry_run":      dryRunEnv,
					"timestamp":    time.Now().Format(time.RFC3339),
				})
			}
			return nil
		},
	}
	dotenvCmd.Flags().StringVar(&srcDotenv, "from", ".env", "source dotenv file")
	dotenvCmd.Flags().StringVar(&dstExample, "to", ".env.example", "destination example file")
	dotenvCmd.Flags().BoolVar(&keepValues, "keep-values", false, "keep existing values in example (defaults to blanking)")
	dotenvCmd.Flags().BoolVar(&addGitignore, "add-ignore", true, "ensure .env is ignored by git")
	dotenvCmd.Flags().BoolVar(&dryRunEnv, "dry-run", false, "print actions without executing")
	dotenvCmd.Flags().StringVar(&summaryEnv, "summary", "", "write remediation summary JSON to this path")
	fix.AddCommand(dotenvCmd)
}

// writeFixSummary writes a JSON summary file for fix actions.
func writeFixSummary(path string, data map[string]any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
