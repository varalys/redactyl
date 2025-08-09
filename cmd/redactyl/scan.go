package redactyl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/franzer/redactyl/internal/config"
	"github.com/franzer/redactyl/internal/engine"
	"github.com/franzer/redactyl/internal/report"
	"github.com/franzer/redactyl/internal/types"
	"github.com/franzer/redactyl/internal/update"
	"github.com/spf13/cobra"
)

var (
	flagPath        string
	flagStaged      bool
	flagHistory     int
	flagBase        string
	flagInclude     string
	flagExclude     string
	flagMaxBytes    int64
	flagEnable      string
	flagDisable     string
	flagGuide       bool
	flagUploadURL   string
	flagUploadToken string
)

func init() {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan files for secrets",
		RunE:  runScan,
	}
	rootCmd.AddCommand(cmd)

	cmd.Flags().StringVarP(&flagPath, "path", "p", ".", "path to scan")
	cmd.Flags().BoolVar(&flagStaged, "staged", false, "scan staged changes")
	cmd.Flags().IntVar(&flagHistory, "history", 0, "scan last N commits (0=off)")
	cmd.Flags().StringVar(&flagBase, "base", "", "scan diff vs base branch (e.g. main)")
	cmd.Flags().StringVar(&flagInclude, "include", "", "comma-separated include globs")
	cmd.Flags().StringVar(&flagExclude, "exclude", "", "comma-separated exclude globs")
	cmd.Flags().Int64Var(&flagMaxBytes, "max-bytes", 1<<20, "skip files larger than this")
	cmd.Flags().StringVar(&flagEnable, "enable", "", "only run these detectors (comma-separated IDs)")
	cmd.Flags().StringVar(&flagDisable, "disable", "", "disable these detectors (comma-separated IDs)")
	cmd.Flags().BoolVar(&flagGuide, "guide", false, "print suggested remediation commands for findings")
	cmd.Flags().StringVar(&flagUploadURL, "upload", "", "POST findings (JSON) to this URL after scan")
	cmd.Flags().StringVar(&flagUploadToken, "upload-token", "", "Bearer token for upload auth")
}

func runScan(cmd *cobra.Command, _ []string) error {
	abs, _ := filepath.Abs(flagPath)
	// Load configs: CLI > local > global
	var gcfg, lcfg config.FileConfig
	if c, err := config.LoadGlobal(); err == nil {
		gcfg = c
	}
	if c, err := config.LoadLocal(abs); err == nil {
		lcfg = c
	}

	cfg := engine.Config{
		Root:             abs,
		IncludeGlobs:     pickString(flagInclude, lcfg.Include, gcfg.Include),
		ExcludeGlobs:     pickString(flagExclude, lcfg.Exclude, gcfg.Exclude),
		MaxBytes:         pickInt64(flagMaxBytes, lcfg.MaxBytes, gcfg.MaxBytes),
		ScanStaged:       flagStaged,
		HistoryCommits:   flagHistory,
		BaseBranch:       flagBase,
		Threads:          pickInt(flagThreads, lcfg.Threads, gcfg.Threads),
		EnableDetectors:  pickString(flagEnable, lcfg.Enable, gcfg.Enable),
		DisableDetectors: pickString(flagDisable, lcfg.Disable, gcfg.Disable),
		MinConfidence:    pickFloat(flagMinConfidence, lcfg.MinConfidence, gcfg.MinConfidence),
		DryRun:           pickBool(flagDryRun, nil, nil),
		NoColor:          pickBool(flagNoColor, lcfg.NoColor, gcfg.NoColor),
		NoCache:          pickBool(flagNoCache, nil, nil),
		DefaultExcludes:  flagDefaultExcludes,
	}

	// Friendly banner before scanning
	if !flagJSON && !flagSARIF {
		if !flagNoUpdateCheck {
			if latest, newer, _ := update.Check(version, false); newer && latest != "" {
				fmt.Fprintf(os.Stderr, "(new version available: v%s)  run 'redactyl update' to upgrade\n", latest)
			}
		}
		if flagSelfUpdate {
			// invoke in-band self update
			if err := selfUpdate(); err == nil {
				fmt.Fprintln(os.Stderr, "updated to latest; re-run command")
				return nil
			}
		}
		fmt.Fprintf(os.Stderr, "Scanning %s with %d detectors...\n", abs, len(engine.DetectorIDs()))
	}

	// Optional progress bar: simple textual bar
	total, _ := engine.CountTargets(cfg)
	progressed := 0
	if total > 0 && !flagJSON && !flagSARIF {
		cfg.Progress = func() {
			progressed++
			if progressed%10 == 0 || progressed == total {
				pct := float64(progressed) / float64(total) * 100
				fmt.Fprintf(os.Stderr, "\r[%d/%d] %.0f%%", progressed, total, pct)
			}
		}
	}
	res, err := engine.ScanWithStats(cfg)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}
	if total > 0 && !flagJSON && !flagSARIF {
		fmt.Fprintln(os.Stderr)
	}

	baseline, _ := report.LoadBaseline("redactyl.baseline.json")
	newFindings := report.FilterNewFindings(res.Findings, baseline)
	if newFindings == nil {
		newFindings = []types.Finding{}
	} // no `null` in JSON

	switch {
	case flagSARIF:
		if err := report.WriteSARIF(os.Stdout, newFindings); err != nil {
			return fmt.Errorf("sarif error: %w", err)
		}
	case flagJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(newFindings)
	default:
		report.PrintTable(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned})
		if flagGuide && len(newFindings) > 0 {
			fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				// conservative guidance: if file looks like dotenv, suggest fix dotenv
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				// otherwise suggest redact for the match span and path-based removal if binary/secret files
				fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
	}

	// Optional upload step: do not fail the scan on upload errors
	if flagUploadURL != "" {
		if err := uploadFindings(flagUploadURL, flagUploadToken, convertFindings(newFindings)); err != nil {
			fmt.Fprintln(os.Stderr, "upload warning:", err)
		}
	}

	if cmd.Flags().Changed("enable") || cmd.Flags().Changed("disable") {
		fmt.Fprintf(os.Stderr, "detectors active: %s\n", activeSetSummary(cfg))
	}

	if report.ShouldFail(newFindings, flagFailOn) {
		os.Exit(1)
	}
	return nil
}

// minimal regexp quoting to embed a literal in a single-quoted shell arg
func regexpQuote(s string) string {
	// escape backslashes and special regex meta. Keep it simple.
	replacer := strings.NewReplacer(`\`, `\\`, `.`, `\.`, `*`, `\*`, `+`, `\+`, `?`, `\?`, `(`, `\(`, `)`, `\)`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`, `^`, `\^`, `$`, `\$`, `|`, `\|`)
	return replacer.Replace(s)
}

func activeSetSummary(cfg engine.Config) string {
	ids := engine.DetectorIDs()
	if cfg.EnableDetectors != "" {
		ids = strings.Split(cfg.EnableDetectors, ",")
	}
	if cfg.DisableDetectors != "" && cfg.EnableDetectors == "" {
		disabled := map[string]bool{}
		for _, d := range strings.Split(cfg.DisableDetectors, ",") {
			disabled[strings.TrimSpace(d)] = true
		}
		var kept []string
		for _, id := range ids {
			if !disabled[strings.TrimSpace(id)] {
				kept = append(kept, id)
			}
		}
		ids = kept
	}
	return strings.Join(ids, ",")
}
