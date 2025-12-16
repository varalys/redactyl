package redactyl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/redactyl/redactyl/internal/audit"
	"github.com/redactyl/redactyl/internal/cache"
	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/engine"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/tui"
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

	flagArchives             bool
	flagContainers           bool
	flagIaC                  bool
	flagHelm                 bool
	flagK8s                  bool
	flagMaxArchiveBytes      int64
	flagMaxEntries           int
	flagMaxDepth             int
	flagScanTimeBudget       time.Duration
	flagGlobalArtifactBudget time.Duration

	flagJSONExtended bool
	flagNoTUI        bool
	flagViewLast     bool
	flagDemo         bool

	flagRegistryImages []string
)

func init() {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan files for secrets",
		RunE:  runScan,
	}
	rootCmd.AddCommand(cmd)

	cmd.Flags().StringVarP(&flagPath, "path", "p", ".", "path to scan")
	cmd.Flags().BoolVar(&flagNoTUI, "no-tui", false, "disable interactive TUI mode (for CI/CD or piping output)")
	cmd.Flags().BoolVar(&flagViewLast, "view-last", false, "view last scan results in TUI without rescanning")
	cmd.Flags().BoolVar(&flagDemo, "demo", false, "launch TUI with sample data (for screenshots/demos)")
	_ = cmd.Flags().MarkHidden("demo")

	// Backward compatibility: -i now does nothing (TUI is default), but keep flag to avoid breaking existing scripts
	var flagInteractiveDeprecated bool
	cmd.Flags().BoolVarP(&flagInteractiveDeprecated, "interactive", "i", false, "deprecated: TUI is now the default, use --no-tui to disable")
	_ = cmd.Flags().MarkDeprecated("interactive", "TUI is now the default mode. Use --no-tui to disable it.")
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
	// deep scanning flags
	cmd.Flags().BoolVar(&flagArchives, "archives", false, "enable deep scanning of archives (zip/tar/gz)")
	cmd.Flags().BoolVar(&flagContainers, "containers", false, "enable deep scanning of container tarballs (Docker save)")
	cmd.Flags().BoolVar(&flagIaC, "iac", false, "enable scanning IaC hotspots (tfstate, kubeconfigs)")
	cmd.Flags().BoolVar(&flagHelm, "helm", false, "enable scanning Helm charts (.tgz archives and directories)")
	cmd.Flags().BoolVar(&flagK8s, "k8s", false, "enable scanning Kubernetes manifests (YAML files)")
	cmd.Flags().StringArrayVar(&flagRegistryImages, "registry", nil, "scan remote container registry image (e.g. gcr.io/project/image:tag)")
	cmd.Flags().Int64Var(&flagMaxArchiveBytes, "max-archive-bytes", 32<<20, "max decompressed bytes per artifact before aborting")
	cmd.Flags().IntVar(&flagMaxEntries, "max-entries", 1000, "max entries per archive/container before aborting")
	cmd.Flags().IntVar(&flagMaxDepth, "max-depth", 2, "max recursion depth for nested archives")
	cmd.Flags().DurationVar(&flagScanTimeBudget, "scan-time-budget", 10*time.Second, "time budget per artifact (e.g., 10s)")
	cmd.Flags().DurationVar(&flagGlobalArtifactBudget, "global-artifact-budget", 0, "optional global time budget across all artifacts (e.g., 10s)")
	cmd.Flags().BoolVar(&flagJSONExtended, "json-extended", false, "when used with --json, include artifact stats in the JSON object; adds a schema_version field")
}

func resolveBudgets(flagBudget time.Duration, lcfg, gcfg config.FileConfig, flagGlobalBudget time.Duration) (time.Duration, time.Duration) {
	budget := flagBudget
	if lcfg.ScanTimeBudget != nil {
		if d, err := time.ParseDuration(*lcfg.ScanTimeBudget); err == nil {
			budget = d
		}
	} else if gcfg.ScanTimeBudget != nil {
		if d, err := time.ParseDuration(*gcfg.ScanTimeBudget); err == nil {
			budget = d
		}
	}

	globalBudget := flagGlobalBudget
	if lcfg.GlobalArtifactBudget != nil {
		if d, err := time.ParseDuration(*lcfg.GlobalArtifactBudget); err == nil {
			globalBudget = d
		}
	} else if gcfg.GlobalArtifactBudget != nil {
		if d, err := time.ParseDuration(*gcfg.GlobalArtifactBudget); err == nil {
			globalBudget = d
		}
	}
	return budget, globalBudget
}

func cloneStringPtr(src *string) *string {
	if src == nil {
		return nil
	}
	val := *src
	return &val
}

func cloneBoolPtr(src *bool) *bool {
	if src == nil {
		return nil
	}
	val := *src
	return &val
}

func mergeGitleaksConfig(gcfg, lcfg config.FileConfig) config.GitleaksConfig {
	var merged config.GitleaksConfig
	apply := func(src *config.GitleaksConfig) {
		if src == nil {
			return
		}
		if src.ConfigPath != nil {
			merged.ConfigPath = cloneStringPtr(src.ConfigPath)
		}
		if src.BinaryPath != nil {
			merged.BinaryPath = cloneStringPtr(src.BinaryPath)
		}
		if src.AutoDownload != nil {
			merged.AutoDownload = cloneBoolPtr(src.AutoDownload)
		}
		if src.Version != nil {
			merged.Version = cloneStringPtr(src.Version)
		}
	}
	apply(gcfg.Gitleaks)
	apply(lcfg.Gitleaks)
	return merged
}

func runScan(cmd *cobra.Command, _ []string) error {
	abs, _ := filepath.Abs(flagPath)

	if flagViewLast {
		results, err := cache.LoadResults(abs)
		if err != nil {
			return fmt.Errorf("no cached results found: %w\nRun a scan first with 'redactyl scan -i' to cache results", err)
		}
		baseline, _ := report.LoadBaseline("redactyl.baseline.json")
		rescanFunc := func() ([]types.Finding, error) {
			return nil, fmt.Errorf("rescan not available in view-only mode - exit and run 'redactyl scan -i' to rescan")
		}
		return tui.RunCachedWithBaseline(results.Findings, baseline, rescanFunc, results.Timestamp)
	}

	if flagDemo {
		findings := generateDemoFindings()
		rescanFunc := func() ([]types.Finding, error) {
			return findings, nil // Just return same demo data
		}
		return tui.Run(findings, rescanFunc)
	}

	var gcfg, lcfg config.FileConfig
	if c, err := config.LoadGlobal(); err == nil {
		gcfg = c
	}
	if c, err := config.LoadLocal(abs); err == nil {
		lcfg = c
	}

	budget, globalBudget := resolveBudgets(flagScanTimeBudget, lcfg, gcfg, flagGlobalArtifactBudget)

	cfg := engine.Config{
		Root:                 abs,
		IncludeGlobs:         pickString(flagInclude, lcfg.Include, gcfg.Include),
		ExcludeGlobs:         pickString(flagExclude, lcfg.Exclude, gcfg.Exclude),
		MaxBytes:             pickInt64(flagMaxBytes, lcfg.MaxBytes, gcfg.MaxBytes),
		ScanStaged:           flagStaged,
		HistoryCommits:       flagHistory,
		BaseBranch:           flagBase,
		Threads:              pickInt(flagThreads, lcfg.Threads, gcfg.Threads),
		EnableDetectors:      pickString(flagEnable, lcfg.Enable, gcfg.Enable),
		DisableDetectors:     pickString(flagDisable, lcfg.Disable, gcfg.Disable),
		MinConfidence:        pickFloat(flagMinConfidence, lcfg.MinConfidence, gcfg.MinConfidence),
		DryRun:               pickBool(flagDryRun, nil, nil),
		NoColor:              pickBool(flagNoColor, lcfg.NoColor, gcfg.NoColor),
		NoCache:              pickBool(flagNoCache, nil, nil),
		DefaultExcludes:      flagDefaultExcludes,
		ScanArchives:         pickBool(flagArchives, lcfg.Archives, gcfg.Archives),
		ScanContainers:       pickBool(flagContainers, lcfg.Containers, gcfg.Containers),
		ScanIaC:              pickBool(flagIaC, lcfg.IaC, gcfg.IaC),
		ScanHelm:             pickBool(flagHelm, lcfg.Helm, gcfg.Helm),
		ScanK8s:              pickBool(flagK8s, lcfg.K8s, gcfg.K8s),
		RegistryImages:       flagRegistryImages,
		MaxArchiveBytes:      pickInt64(flagMaxArchiveBytes, lcfg.MaxArchiveBytes, gcfg.MaxArchiveBytes),
		MaxEntries:           pickInt(flagMaxEntries, lcfg.MaxEntries, gcfg.MaxEntries),
		MaxDepth:             pickInt(flagMaxDepth, lcfg.MaxDepth, gcfg.MaxDepth),
		ScanTimeBudget:       budget,
		GlobalArtifactBudget: globalBudget,
		GitleaksConfig:       mergeGitleaksConfig(gcfg, lcfg),
	}

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
	}

	auditFindings := res.Findings
	if len(res.Findings) == 0 {
		if cached, err := cache.LoadResults(abs); err == nil && len(cached.Findings) > 0 {
			auditFindings = cached.Findings
			newFindings = report.FilterNewFindings(auditFindings, baseline)
			if newFindings == nil {
				newFindings = []types.Finding{}
			}
		}
	}

	auditLog := audit.NewAuditLog(abs)
	auditRecord := audit.CreateScanRecord(
		abs,
		auditFindings,
		newFindings,
		res.FilesScanned,
		res.Duration,
		"redactyl.baseline.json",
	)
	if err := auditLog.LogScan(auditRecord); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: failed to write audit log: %v\n", err)
	}

	useTUI := !flagNoTUI && !flagJSON && !flagSARIF
	if useTUI && !isTerminal(os.Stdout) {
		useTUI = false
	}

	if useTUI {
		rescanFunc := func() ([]types.Finding, error) {
			newCfg := cfg
			newCfg.NoCache = true
			newRes, err := engine.ScanWithStats(newCfg)
			if err != nil {
				return nil, err
			}
			if len(newRes.Findings) > 0 {
				if err := cache.SaveResults(abs, newRes.Findings); err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Warning: failed to cache results: %v\n", err)
				}
			}
			return newRes.Findings, nil
		}

		findingsToShow := res.Findings
		var cachedTime time.Time
		viewingCached := false

		if len(res.Findings) == 0 {
			if cached, err := cache.LoadResults(abs); err == nil && len(cached.Findings) > 0 {
				findingsToShow = cached.Findings
				cachedTime = cached.Timestamp
				viewingCached = true
			}
		} else {
			if err := cache.SaveResults(abs, res.Findings); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Warning: failed to cache results: %v\n", err)
			}
		}

		if viewingCached {
			if err := tui.RunCachedWithBaseline(findingsToShow, baseline, rescanFunc, cachedTime); err != nil {
				return err
			}
		} else {
			if err := tui.RunWithBaseline(findingsToShow, baseline, rescanFunc); err != nil {
				return err
			}
		}
		return nil
	}

	if len(res.Findings) > 0 {
		if err := cache.SaveResults(abs, res.Findings); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: failed to cache results: %v\n", err)
		}
	}

	switch {
	case flagSARIF:
		stats := map[string]int{
			"bytes":   res.ArtifactStats.AbortedByBytes,
			"entries": res.ArtifactStats.AbortedByEntries,
			"depth":   res.ArtifactStats.AbortedByDepth,
			"time":    res.ArtifactStats.AbortedByTime,
		}
		if err := report.WriteSARIFWithStats(os.Stdout, newFindings, stats); err != nil {
			return fmt.Errorf("sarif error: %w", err)
		}
	case flagJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if flagJSONExtended {
			payload := map[string]any{
				"schema_version": "1",
				"findings":       newFindings,
				"artifact_stats": map[string]int{
					"bytes":   res.ArtifactStats.AbortedByBytes,
					"entries": res.ArtifactStats.AbortedByEntries,
					"depth":   res.ArtifactStats.AbortedByDepth,
					"time":    res.ArtifactStats.AbortedByTime,
				},
			}
			if err := enc.Encode(payload); err != nil {
				return err
			}
		} else {
			if err := enc.Encode(newFindings); err != nil {
				return err
			}
		}
	case flagText:
		report.PrintText(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
		if res.ArtifactStats.AbortedByBytes+res.ArtifactStats.AbortedByEntries+res.ArtifactStats.AbortedByDepth+res.ArtifactStats.AbortedByTime > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "\nArtifact limits: bytes=%d entries=%d depth=%d time=%d\n", res.ArtifactStats.AbortedByBytes, res.ArtifactStats.AbortedByEntries, res.ArtifactStats.AbortedByDepth, res.ArtifactStats.AbortedByTime)
		}
	case flagTable:
		report.PrintTable(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
		if res.ArtifactStats.AbortedByBytes+res.ArtifactStats.AbortedByEntries+res.ArtifactStats.AbortedByDepth+res.ArtifactStats.AbortedByTime > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "\nArtifact limits: bytes=%d entries=%d depth=%d time=%d\n", res.ArtifactStats.AbortedByBytes, res.ArtifactStats.AbortedByEntries, res.ArtifactStats.AbortedByDepth, res.ArtifactStats.AbortedByTime)
		}
	default:
		report.PrintTable(os.Stdout, newFindings, report.PrintOptions{NoColor: flagNoColor, Duration: res.Duration, FilesScanned: res.FilesScanned, TotalFiles: total, TotalFindings: len(res.Findings)})
		if flagGuide && len(newFindings) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "\nSuggested remediation commands:")
			for _, f := range newFindings {
				lower := strings.ToLower(f.Path)
				if strings.HasSuffix(lower, ".env") || strings.Contains(lower, ".env") {
					_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix dotenv --from", f.Path, "--add-ignore --summary remediation.json")
					continue
				}
				_, _ = fmt.Fprintln(os.Stderr, "  redactyl fix redact --file", f.Path, "--pattern", "'"+regexpQuote(f.Match)+"'", "--replace '<redacted>' --summary remediation.json")
			}
		}
		if res.ArtifactStats.AbortedByBytes+res.ArtifactStats.AbortedByEntries+res.ArtifactStats.AbortedByDepth+res.ArtifactStats.AbortedByTime > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "\nArtifact limits: bytes=%d entries=%d depth=%d time=%d\n", res.ArtifactStats.AbortedByBytes, res.ArtifactStats.AbortedByEntries, res.ArtifactStats.AbortedByDepth, res.ArtifactStats.AbortedByTime)
		}
	}

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

func regexpQuote(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `.`, `\.`, `*`, `\*`, `+`, `\+`, `?`, `\?`, `(`, `\(`, `)`, `\)`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`, `^`, `\^`, `$`, `\$`, `|`, `\|`)
	return replacer.Replace(s)
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
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

// generateDemoFindings creates sample findings for demo/screenshot purposes.
// Each finding includes realistic code context and metadata for display in the TUI.
func generateDemoFindings() []types.Finding {
	return []types.Finding{
		{
			Path: "src/config/database.go", Detector: "aws-access-key", Line: 45, Column: 15, Severity: types.SevHigh,
			Match:    "AKIAIOSFODNN7EXAMPLE",
			Context:  "func connectDB() (*sql.DB, error) {\n    accessKey := \"AKIAIOSFODNN7EXAMPLE\"\n    secretKey := os.Getenv(\"AWS_SECRET\")",
			Metadata: map[string]string{"entropy": "4.25", "gitleaks_rule_id": "aws-access-key", "commit": "a1b2c3d", "author": "dev@example.com", "date": "2025-01-15"},
		},
		{
			Path: "src/config/database.go", Detector: "aws-secret-key", Line: 46, Column: 15, Severity: types.SevHigh,
			Match:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
			Context:  "    accessKey := os.Getenv(\"AWS_ACCESS\")\n    secretKey := \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE\"\n    return sql.Open(\"postgres\", dsn)",
			Metadata: map[string]string{"entropy": "5.12", "gitleaks_rule_id": "aws-secret-key", "commit": "a1b2c3d", "author": "dev@example.com", "date": "2025-01-15"},
		},
		{
			Path: "deploy/k8s/secrets.yaml", Detector: "github-pat", Line: 18, Column: 14, Severity: types.SevHigh,
			Match:    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Context:  "apiVersion: v1\nkind: Secret\ndata:\n  GITHUB_TOKEN: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Metadata: map[string]string{"entropy": "4.78", "gitleaks_rule_id": "github-pat", "commit": "b2c3d4e", "author": "ops@example.com", "date": "2025-02-20"},
		},
		{
			Path: "deploy/k8s/secrets.yaml", Detector: "jwt-token", Line: 24, Column: 10, Severity: types.SevHigh,
			Match:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI",
			Context:  "metadata:\n  name: api-secrets\nstringData:\n  JWT_SECRET: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI",
			Metadata: map[string]string{"entropy": "4.95", "gitleaks_rule_id": "jwt-token", "commit": "b2c3d4e", "author": "ops@example.com", "date": "2025-02-20"},
		},
		{
			Path: "deploy/docker-compose.yml", Detector: "stripe-key", Line: 32, Column: 18, Severity: types.SevHigh,
			Match:    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			Context:  "services:\n  api:\n    environment:\n      - STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			Metadata: map[string]string{"entropy": "4.67", "gitleaks_rule_id": "stripe-api-key", "commit": "c3d4e5f", "author": "dev@example.com", "date": "2025-03-10"},
		},
		{
			Path: ".env.production", Detector: "openai-key", Line: 12, Column: 1, Severity: types.SevHigh,
			Match:    "sk-proj-abc123def456ghi789jkl012mno345",
			Context:  "# API Keys\nDATABASE_URL=postgres://...\nOPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345\nREDIS_URL=redis://...",
			Metadata: map[string]string{"entropy": "4.89", "gitleaks_rule_id": "openai-api-key", "commit": "d4e5f6g", "author": "admin@example.com", "date": "2025-03-15"},
		},
		{
			Path: ".env.production", Detector: "stripe-key", Line: 15, Column: 1, Severity: types.SevHigh,
			Match:    "sk_live_abc123xyz789def456ghi012jkl",
			Context:  "OPENAI_API_KEY=sk-...\nSENDGRID_KEY=SG...\nSTRIPE_SECRET_KEY=sk_live_abc123xyz789def456ghi012jkl\nSENTRY_DSN=https://...",
			Metadata: map[string]string{"entropy": "4.72", "gitleaks_rule_id": "stripe-api-key", "commit": "d4e5f6g", "author": "admin@example.com", "date": "2025-03-15"},
		},
		{
			Path: "src/services/auth.ts", Detector: "private-key", Line: 89, Column: 5, Severity: types.SevHigh,
			Match:    "-----BEGIN RSA PRIVATE KEY-----",
			Context:  "const privateKey = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Z3qX2BTLS4e...\n-----END RSA PRIVATE KEY-----`;",
			Metadata: map[string]string{"entropy": "5.45", "gitleaks_rule_id": "private-key", "commit": "e5f6g7h", "author": "security@example.com", "date": "2025-01-08"},
		},
		{
			Path: "src/services/payment.go", Detector: "square-key", Line: 156, Column: 22, Severity: types.SevMed,
			Match:    "sq0csp-xxxxxxxxxxxxxxxxxxxxxxxx",
			Context:  "func initSquare() {\n    client := square.NewClient(\n        square.WithAccessToken(\"sq0csp-xxxxxxxxxxxxxxxxxxxxxxxx\"),\n    )",
			Metadata: map[string]string{"entropy": "3.85", "gitleaks_rule_id": "square-access-token", "commit": "f6g7h8i", "author": "dev@example.com", "date": "2025-02-28"},
		},
		{
			Path: "scripts/deploy.sh", Detector: "docker-token", Line: 8, Column: 1, Severity: types.SevMed,
			Match:    "dckr_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Context:  "#!/bin/bash\nset -e\n\nexport DOCKER_TOKEN=dckr_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx\ndocker login -u user -p $DOCKER_TOKEN",
			Metadata: map[string]string{"entropy": "4.15", "gitleaks_rule_id": "docker-pat", "commit": "g7h8i9j", "author": "ops@example.com", "date": "2025-03-01"},
		},
		{
			Path: "terraform/main.tf", Detector: "github-pat", Line: 42, Column: 12, Severity: types.SevMed,
			Match:    "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Context:  "provider \"github\" {\n  owner = \"myorg\"\n  token = \"github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"\n}",
			Metadata: map[string]string{"entropy": "4.33", "gitleaks_rule_id": "github-pat", "commit": "h8i9j0k", "author": "infra@example.com", "date": "2025-02-14"},
		},
		{
			Path: "helm/values.yaml", Detector: "slack-token", Line: 67, Column: 10, Severity: types.SevMed,
			Match:    "xoxb-xxxxxxxxxxxx-xxxxxxxxxxxxxxxx",
			Context:  "notifications:\n  slack:\n    enabled: true\n    apiKey: xoxb-xxxxxxxxxxxx-xxxxxxxxxxxxxxxx\n    channel: \"#alerts\"",
			Metadata: map[string]string{"entropy": "4.02", "gitleaks_rule_id": "slack-bot-token", "commit": "i9j0k1l", "author": "ops@example.com", "date": "2025-03-05"},
		},
		{
			Path: "src/utils/logger.go", Detector: "datadog-key", Line: 23, Column: 8, Severity: types.SevMed,
			Match:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Context:  "func initDatadog() {\n    apiKey := \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"\n    tracer.Start(tracer.WithAgentAddr(apiKey))\n}",
			Metadata: map[string]string{"entropy": "3.78", "gitleaks_rule_id": "datadog-api-key", "commit": "j0k1l2m", "author": "dev@example.com", "date": "2025-01-22"},
		},
		{
			Path: "docs/setup.md", Detector: "generic-api-key", Line: 45, Column: 8, Severity: types.SevLow,
			Match:    "test_key_example_12345",
			Context:  "```bash\n# For local development only\nexport API_KEY=test_key_example_12345\nnpm run dev\n```",
			Metadata: map[string]string{"entropy": "3.21", "gitleaks_rule_id": "generic-api-key", "commit": "k1l2m3n", "author": "docs@example.com", "date": "2025-02-01"},
		},
		{
			Path: "examples/config.json", Detector: "password", Line: 12, Column: 17, Severity: types.SevLow,
			Match:    "changeme123",
			Context:  "{\n  \"database\": {\n    \"host\": \"localhost\",\n    \"password\": \"changeme123\"\n  }\n}",
			Metadata: map[string]string{"entropy": "2.95", "gitleaks_rule_id": "generic-password", "commit": "l2m3n4o", "author": "dev@example.com", "date": "2025-01-05"},
		},
	}
}
