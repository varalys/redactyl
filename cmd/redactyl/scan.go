package redactyl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/detectors"
	"github.com/redactyl/redactyl/internal/engine"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
	"github.com/redactyl/redactyl/internal/update"
	"github.com/spf13/cobra"
)

var (
	flagPath         string
	flagStaged       bool
	flagHistory      int
	flagBase         string
	flagInclude      string
	flagExclude      string
	flagMaxBytes     int64
	flagEnable       string
	flagDisable      string
	flagGuide        bool
	flagUploadURL    string
	flagUploadToken  string
	flagNoUploadMeta bool
	flagTable        bool
	flagText         bool
	flagNoValidators bool
	flagNoStructured bool
	flagVerify       string
	// deep scanning toggles and limits
	flagArchives        bool
	flagContainers      bool
	flagIaC             bool
	flagMaxArchiveBytes int64
	flagMaxEntries      int
	flagMaxDepth        int
	flagScanTimeBudget  time.Duration
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
	cmd.Flags().BoolVar(&flagNoUploadMeta, "no-upload-metadata", false, "do not include repo/commit/branch in upload envelope")
	cmd.Flags().BoolVar(&flagTable, "table", false, "output in table format with borders (now default)")
	cmd.Flags().BoolVar(&flagText, "text", false, "output in plain text columnar format")
	cmd.Flags().BoolVar(&flagNoValidators, "no-validators", false, "disable post-detection validator heuristics")
	cmd.Flags().BoolVar(&flagNoStructured, "no-structured", false, "disable structured JSON/YAML key scanning")
	cmd.Flags().StringVar(&flagVerify, "verify", "off", "soft verify mode: off|safe|custom")
	// deep scanning flags
	cmd.Flags().BoolVar(&flagArchives, "archives", false, "enable deep scanning of archives (zip/tar/gz)")
	cmd.Flags().BoolVar(&flagContainers, "containers", false, "enable deep scanning of container tarballs (Docker save)")
	cmd.Flags().BoolVar(&flagIaC, "iac", false, "enable scanning IaC hotspots (tfstate, kubeconfigs)")
	cmd.Flags().Int64Var(&flagMaxArchiveBytes, "max-archive-bytes", 32<<20, "max decompressed bytes per artifact before aborting")
	cmd.Flags().IntVar(&flagMaxEntries, "max-entries", 1000, "max entries per archive/container before aborting")
	cmd.Flags().IntVar(&flagMaxDepth, "max-depth", 2, "max recursion depth for nested archives")
	cmd.Flags().DurationVar(&flagScanTimeBudget, "scan-time-budget", 10*time.Second, "time budget per artifact (e.g., 10s)")
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

	// Resolve time budget precedence: CLI > local > global
	budget := flagScanTimeBudget
	if lcfg.ScanTimeBudget != nil {
		if d, err := time.ParseDuration(*lcfg.ScanTimeBudget); err == nil {
			budget = d
		}
	} else if gcfg.ScanTimeBudget != nil {
		if d, err := time.ParseDuration(*gcfg.ScanTimeBudget); err == nil {
			budget = d
		}
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
		ScanArchives:     pickBool(flagArchives, lcfg.Archives, gcfg.Archives),
		ScanContainers:   pickBool(flagContainers, lcfg.Containers, gcfg.Containers),
		ScanIaC:          pickBool(flagIaC, lcfg.IaC, gcfg.IaC),
		MaxArchiveBytes:  pickInt64(flagMaxArchiveBytes, lcfg.MaxArchiveBytes, gcfg.MaxArchiveBytes),
		MaxEntries:       pickInt(flagMaxEntries, lcfg.MaxEntries, gcfg.MaxEntries),
		MaxDepth:         pickInt(flagMaxDepth, lcfg.MaxDepth, gcfg.MaxDepth),
		ScanTimeBudget:   budget,
	}

	// toggles: CLI overrides config when present
	nv := pickBool(flagNoValidators, lcfg.NoValidators, gcfg.NoValidators)
	ns := pickBool(flagNoStructured, lcfg.NoStructured, gcfg.NoStructured)
	detectors.EnableValidators = !nv
	detectors.EnableStructured = !ns
	// verify: CLI > local > global
	if v := pickString(flagVerify, lcfg.VerifyMode, gcfg.VerifyMode); v != "" {
		detectors.VerifyMode = v
	}
	// per-detector disable lists (optional, comma-separated)
	if lcfg.DisableValidators != nil || gcfg.DisableValidators != nil {
		ids := pickString("", lcfg.DisableValidators, gcfg.DisableValidators)
		for _, id := range strings.Split(ids, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				detectors.DisabledValidatorsIDs[id] = true
			}
		}
	}
	if lcfg.DisableStructured != nil || gcfg.DisableStructured != nil {
		ids := pickString("", lcfg.DisableStructured, gcfg.DisableStructured)
		for _, id := range strings.Split(ids, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				detectors.DisabledStructuredIDs[id] = true
			}
		}
	}

	// Friendly banner before scanning
	if !flagJSON && !flagSARIF {
		if !flagNoUpdateCheck {
			if latest, newer, _ := update.Check(version, false); newer && latest != "" {
				_, _ = fmt.Fprintf(os.Stderr, "(new version available: v%s)  run 'redactyl update' to upgrade\n", latest)
			}
		}
		if flagSelfUpdate {
			// invoke in-band self update
			if err := selfUpdate(); err == nil {
				_, _ = fmt.Fprintln(os.Stderr, "updated to latest; re-run command")
				return nil
			}
		}
		_, _ = fmt.Fprintf(os.Stderr, "Scanning %s with %d detectors...\n", abs, len(engine.DetectorIDs()))
	}

	// Optional progress bar: simple textual bar
	total, _ := engine.CountTargets(cfg)
	progressed := 0
	if total > 0 && !flagJSON && !flagSARIF {
		cfg.Progress = func() {
			progressed++
			if progressed%10 == 0 || progressed == total {
				pct := float64(progressed) / float64(total) * 100
				_, _ = fmt.Fprintf(os.Stderr, "\r[%d/%d] %.0f%%", progressed, total, pct)
			}
		}
	}
	res, err := engine.ScanWithStats(cfg)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}
	if total > 0 && !flagJSON && !flagSARIF {
		_, _ = fmt.Fprintln(os.Stderr)
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
		if err := enc.Encode(newFindings); err != nil {
			return err
		}
	case flagText:
		report.PrintText(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				// conservative guidance: if file looks like dotenv, suggest fix dotenv
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				// otherwise suggest redact for the match span and path-based removal if binary/secret files
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
	case flagTable:
		report.PrintTable(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				// conservative guidance: if file looks like dotenv, suggest fix dotenv
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				// otherwise suggest redact for the match span and path-based removal if binary/secret files
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
	default:
		// Default to table format now
		report.PrintTable(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				// conservative guidance: if file looks like dotenv, suggest fix dotenv
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				// otherwise suggest redact for the match span and path-based removal if binary/secret files
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
	}

	// Optional upload step: do not fail the scan on upload errors
	if flagUploadURL != "" {
		if err := uploadFindings(abs, flagUploadURL, flagUploadToken, flagNoUploadMeta, convertFindings(newFindings)); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "upload warning:", err)
		}
	}

	if cmd.Flags().Changed("enable") || cmd.Flags().Changed("disable") {
		_, _ = fmt.Fprintf(os.Stderr, "detectors active: %s\n", activeSetSummary(cfg))
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
