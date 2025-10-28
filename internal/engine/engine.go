package engine

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	doublestar "github.com/bmatcuk/doublestar/v4"
	xxhash "github.com/cespare/xxhash/v2"
	"github.com/redactyl/redactyl/internal/artifacts"
	"github.com/redactyl/redactyl/internal/cache"
	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/git"
	"github.com/redactyl/redactyl/internal/ignore"
	"github.com/redactyl/redactyl/internal/scanner"
	"github.com/redactyl/redactyl/internal/scanner/gitleaks"
	"github.com/redactyl/redactyl/internal/types"
	"golang.org/x/sync/errgroup"
)

// Config controls scanning behavior including scope, performance, and filters.
type Config struct {
	Root             string
	IncludeGlobs     string
	ExcludeGlobs     string
	MaxBytes         int64
	ScanStaged       bool
	HistoryCommits   int
	BaseBranch       string
	Threads          int
	EnableDetectors  string
	DisableDetectors string
	MinConfidence    float64
	DryRun           bool
	NoColor          bool
	DefaultExcludes  bool
	NoCache          bool
	Progress         func()

	// Deep artifact scanning (optional)
	ScanArchives         bool
	ScanContainers       bool
	ScanIaC              bool
	ScanHelm             bool // Scan Helm charts
	ScanK8s              bool // Scan Kubernetes manifests
	MaxArchiveBytes      int64
	MaxEntries           int
	MaxDepth             int
	ScanTimeBudget       time.Duration
	GlobalArtifactBudget time.Duration

	// Gitleaks configuration (for scanner integration)
	GitleaksConfig config.GitleaksConfig
}

var (
	EnableDetectors  string
	DisableDetectors string
)

// DetectorIDs returns the list of available Gitleaks detector IDs.
// This is a representative list of common Gitleaks rules for UI purposes.
// The actual detection is performed by Gitleaks with its full rule set.
func DetectorIDs() []string {
	return []string{
		"github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token",
		"aws-access-key", "aws-secret-key", "aws-mws-key",
		"stripe-access-token", "stripe-secret-key",
		"slack-webhook-url", "slack-bot-token", "slack-app-token",
		"google-api-key", "google-oauth", "gcp-service-account",
		"gitlab-pat", "gitlab-pipeline-token", "gitlab-runner-token",
		"sendgrid-api-key",
		"openai-api-key",
		"anthropic-api-key",
		"npm-access-token",
		"pypi-token",
		"docker-config-auth",
		"jwt",
		"private-key",
		"generic-api-key",
		// Note: This is a subset for display. Gitleaks has 200+ rules.
	}
}

// Scan runs a scan and returns only findings (without stats).
func Scan(cfg Config) ([]types.Finding, error) {
	res, err := ScanWithStats(cfg)
	if err != nil {
		return nil, err
	}
	return res.Findings, nil
}

// Result contains findings and basic scan statistics.
type Result struct {
	Findings      []types.Finding
	FilesScanned  int
	Duration      time.Duration
	ArtifactStats DeepStats
}

// DeepStats summarizes artifact scanning abort reasons.
type DeepStats struct {
	AbortedByBytes   int
	AbortedByEntries int
	AbortedByDepth   int
	AbortedByTime    int
}

// ScanWithStats runs a scan and returns findings along with timing and counts.
func ScanWithStats(cfg Config) (Result, error) {
	var result Result

	// Initialize scanner (Gitleaks integration)
	scnr, err := initializeScanner(cfg)
	if err != nil {
		return result, fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Load incremental cache if available
	var db cache.DB
	if !cfg.NoCache {
		db, _ = cache.Load(cfg.Root)
	} else {
		db.Entries = map[string]string{}
	}
	// collect updated hashes to persist once at end
	updated := map[string]string{}
	threads := cfg.Threads
	if threads <= 0 {
		threads = runtime.GOMAXPROCS(0)
	}
	// working tree processing is done inline via Walk; staged/base/history use bounded parallelism

	ign, _ := ignore.Load(filepath.Join(cfg.Root, ".redactylignore"))
	ctx := context.Background()

	var out []types.Finding
	started := time.Now()
	emit := func(fs []types.Finding) {
		out = append(out, fs...)
	}

	// working tree / staged
	if cfg.HistoryCommits == 0 && cfg.BaseBranch == "" {
		err := Walk(ctx, cfg, ign, func(p string, data []byte) {
			// compute cheap content hash; small overhead but enables skipping next run
			h := fastHash(data)
			if !cfg.NoCache && db.Entries != nil && db.Entries[p] == h {
				return
			}
			result.FilesScanned++
			if cfg.Progress != nil {
				cfg.Progress()
			}
			if cfg.DryRun {
				return
			}
			fs, err := scnr.Scan(p, data)
			if err != nil {
				// Log error but don't fail entire scan
				// TODO: Consider adding error reporting mechanism
				return
			}
			fs = filterByConfidence(fs, cfg.MinConfidence)
			fs = filterByIDs(fs, cfg.EnableDetectors, cfg.DisableDetectors)
			emit(fs)
			if !cfg.NoCache {
				updated[p] = h
			}
		})
		if err != nil {
			return result, err
		}
	}

	// staged (parallel)
	if cfg.ScanStaged {
		files, data, err := git.StagedDiff(cfg.Root)
		if err == nil {
			var scanned int64
			var mu sync.Mutex
			g, _ := errgroup.WithContext(context.Background())
			g.SetLimit(threads)

			findingsCh := make(chan []types.Finding, threads*2)
			done := make(chan struct{})
			go func() {
				for fs := range findingsCh {
					emit(fs)
				}
				close(done)
			}()

			for i, p := range files {
				i, p := i, p
				g.Go(func() error {
					if !allowedByGlobs(p, cfg) {
						return nil
					}
					if cfg.MaxBytes > 0 && int64(len(data[i])) > cfg.MaxBytes {
						return nil
					}
					atomic.AddInt64(&scanned, 1)
					if cfg.DryRun {
						if cfg.Progress != nil {
							cfg.Progress()
						}
						return nil
					}
					fs, err := scnr.Scan(p, data[i])
					if err != nil {
						// Log error but continue scanning other files
						return nil
					}
					fs = filterByConfidence(fs, cfg.MinConfidence)
					fs = filterByIDs(fs, cfg.EnableDetectors, cfg.DisableDetectors)
					findingsCh <- fs
					if !cfg.NoCache {
						h := fastHash(data[i])
						mu.Lock()
						updated[p] = h
						mu.Unlock()
					}
					if cfg.Progress != nil {
						cfg.Progress()
					}
					return nil
				})
			}
			_ = g.Wait()
			close(findingsCh)
			<-done
			result.FilesScanned += int(scanned)
		}
	}

	// history (parallel)
	if cfg.HistoryCommits > 0 {
		entries, err := git.LastNCommits(cfg.Root, cfg.HistoryCommits)
		if err == nil {
			type pair struct {
				path string
				blob []byte
			}
			var items []pair
			for _, e := range entries {
				for path, blob := range e.Files {
					if !allowedByGlobs(path, cfg) {
						continue
					}
					if ign.Match(path) {
						continue
					}
					if int64(len(blob)) > cfg.MaxBytes {
						continue
					}
					items = append(items, pair{path: path, blob: blob})
				}
			}
			var scanned int64
			var mu sync.Mutex
			g, _ := errgroup.WithContext(context.Background())
			g.SetLimit(threads)
			findingsCh := make(chan []types.Finding, threads*2)
			done := make(chan struct{})
			go func() {
				for fs := range findingsCh {
					emit(fs)
				}
				close(done)
			}()
			for _, it := range items {
				it := it
				g.Go(func() error {
					atomic.AddInt64(&scanned, 1)
					if cfg.DryRun {
						if cfg.Progress != nil {
							cfg.Progress()
						}
						return nil
					}
					fs, err := scnr.Scan(it.path, it.blob)
					if err != nil {
						// Log error but continue scanning other files
						return nil
					}
					fs = filterByConfidence(fs, cfg.MinConfidence)
					fs = filterByIDs(fs, cfg.EnableDetectors, cfg.DisableDetectors)
					findingsCh <- fs
					if !cfg.NoCache {
						h := fastHash(it.blob)
						mu.Lock()
						updated[it.path] = h
						mu.Unlock()
					}
					if cfg.Progress != nil {
						cfg.Progress()
					}
					return nil
				})
			}
			_ = g.Wait()
			close(findingsCh)
			<-done
			result.FilesScanned += int(scanned)
		}
	}

	// diff vs base branch (parallel)
	if cfg.BaseBranch != "" {
		files, data, err := git.DiffAgainst(cfg.Root, cfg.BaseBranch)
		if err == nil {
			var scanned int64
			var mu sync.Mutex
			g, _ := errgroup.WithContext(context.Background())
			g.SetLimit(threads)
			findingsCh := make(chan []types.Finding, threads*2)
			done := make(chan struct{})
			go func() {
				for fs := range findingsCh {
					emit(fs)
				}
				close(done)
			}()
			for i, p := range files {
				i, p := i, p
				g.Go(func() error {
					if !allowedByGlobs(p, cfg) {
						return nil
					}
					if ign.Match(p) {
						return nil
					}
					if cfg.MaxBytes > 0 && int64(len(data[i])) > cfg.MaxBytes {
						return nil
					}
					atomic.AddInt64(&scanned, 1)
					if cfg.DryRun {
						if cfg.Progress != nil {
							cfg.Progress()
						}
						return nil
					}
					fs, err := scnr.Scan(p, bytes.TrimSpace(data[i]))
					if err != nil {
						// Log error but continue scanning other files
						return nil
					}
					fs = filterByConfidence(fs, cfg.MinConfidence)
					fs = filterByIDs(fs, cfg.EnableDetectors, cfg.DisableDetectors)
					findingsCh <- fs
					if !cfg.NoCache {
						h := fastHash(data[i])
						mu.Lock()
						updated[p] = h
						mu.Unlock()
					}
					if cfg.Progress != nil {
						cfg.Progress()
					}
					return nil
				})
			}
			_ = g.Wait()
			close(findingsCh)
			<-done
			result.FilesScanned += int(scanned)
		}
	}

	// Optional deep artifact scanning (sequential orchestration, internal parallelism TBD)
	if cfg.ScanArchives || cfg.ScanContainers || cfg.ScanIaC || cfg.ScanHelm || cfg.ScanK8s {
		lim := artifacts.Limits{
			MaxArchiveBytes: cfg.MaxArchiveBytes,
			MaxEntries:      cfg.MaxEntries,
			MaxDepth:        cfg.MaxDepth,
			TimeBudget:      cfg.ScanTimeBudget,
			Workers:         cfg.Threads,
		}
		// Establish a global deadline across all artifacts if a global time budget is provided
		if cfg.GlobalArtifactBudget > 0 {
			lim.GlobalDeadline = time.Now().Add(cfg.GlobalArtifactBudget)
		}
		emitArtifact := func(p string, b []byte) {
			if cfg.DryRun {
				return
			}
			fs, err := scnr.Scan(p, b)
			if err != nil {
				// Log error but continue scanning other artifacts
				return
			}
			fs = filterByConfidence(fs, cfg.MinConfidence)
			fs = filterByIDs(fs, cfg.EnableDetectors, cfg.DisableDetectors)
			emit(fs)
			if !cfg.NoCache {
				updated[p] = fastHash(b)
			}
			result.FilesScanned++
			if cfg.Progress != nil {
				cfg.Progress()
			}
		}
		// Reuse include/exclude globs to filter which artifact filenames are processed
		allowArtifact := func(rel string) bool { return allowedByGlobs(rel, cfg) }
		var artStats artifacts.Stats
		if cfg.ScanArchives {
			_ = artifacts.ScanArchivesWithStats(cfg.Root, lim, allowArtifact, emitArtifact, &artStats) //nolint:errcheck
		}
		if cfg.ScanContainers {
			_ = artifacts.ScanContainersWithStats(cfg.Root, lim, allowArtifact, emitArtifact, &artStats) //nolint:errcheck
		}
		if cfg.ScanIaC {
			_ = artifacts.ScanIaCWithFilter(cfg.Root, lim, allowArtifact, emitArtifact) //nolint:errcheck
		}
		if cfg.ScanHelm {
			_ = artifacts.ScanHelmChartsWithFilter(cfg.Root, lim, allowArtifact, emitArtifact) //nolint:errcheck
		}
		if cfg.ScanK8s {
			_ = artifacts.ScanK8sManifestsWithFilter(cfg.Root, lim, allowArtifact, emitArtifact) //nolint:errcheck
		}
		result.ArtifactStats = DeepStats{
			AbortedByBytes:   artStats.AbortedByBytes,
			AbortedByEntries: artStats.AbortedByEntries,
			AbortedByDepth:   artStats.AbortedByDepth,
			AbortedByTime:    artStats.AbortedByTime,
		}
	}

	result.Findings = out
	result.Duration = time.Since(started)
	// Save cache best-effort
	if !cfg.NoCache && len(updated) > 0 {
		if db.Entries == nil {
			db.Entries = map[string]string{}
		}
		for k, v := range updated {
			db.Entries[k] = v
		}
		_ = cache.Save(cfg.Root, db)
	}
	return result, nil
}

// fastHash returns a short hex digest for quick change detection.
func fastHash(b []byte) string {
	if len(b) == 0 {
		return "0000000000000000"
	}
	sum := xxhash.Sum64(b)
	// fixed-width lower-hex for stable cache keys
	var buf [16]byte
	const hex = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		buf[i] = hex[sum&0xF]
		sum >>= 4
	}
	return string(buf[:])
}

func filterByConfidence(fs []types.Finding, min float64) []types.Finding {
	if min <= 0 {
		return fs
	}
	var out []types.Finding
	for _, f := range fs {
		if f.Confidence >= min {
			out = append(out, f)
		}
	}
	return out
}

func filterByIDs(fs []types.Finding, enable, disable string) []types.Finding {
	if enable == "" && disable == "" {
		return fs
	}
	allowed := map[string]bool{}
	if enable != "" {
		for _, id := range strings.Split(enable, ",") {
			allowed[strings.TrimSpace(id)] = true
		}
	}
	blocked := map[string]bool{}
	if disable != "" {
		for _, id := range strings.Split(disable, ",") {
			blocked[strings.TrimSpace(id)] = true
		}
	}
	var out []types.Finding
	for _, f := range fs {
		if enable != "" && !allowed[f.Detector] {
			continue
		}
		if disable != "" && blocked[f.Detector] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// allowedByGlobs returns true if the given path is allowed by the include/exclude
// glob configuration. Include globs are comma-separated and, if provided, act as
// a positive filter. Exclude globs are subtracted last. Matching uses forward-slash
// semantics via path.Match.
func allowedByGlobs(relPath string, cfg Config) bool {
	rp := strings.ReplaceAll(relPath, "\\", "/")
	includes := parseGlobsList(cfg.IncludeGlobs)
	excludes := parseGlobsList(cfg.ExcludeGlobs)
	if len(includes) > 0 {
		matched := matchAnyGlob(rp, includes)
		if !matched {
			return false
		}
	}
	if len(excludes) > 0 && matchAnyGlob(rp, excludes) {
		return false
	}
	return true
}

func parseGlobsList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
			// add variant without leading "./" and "**/" so patterns like "**/*.go" also match top-level files
			out = append(out, trimGlobPrefix(p))
		}
	}
	return out
}

func matchAnyGlob(pathToMatch string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, pathToMatch); ok {
			return true
		}
		// Also try against basename for simple patterns like "*.go"
		if ok, _ := doublestar.Match(g, filepath.Base(pathToMatch)); ok {
			return true
		}
	}
	return false
}

func trimGlobPrefix(g string) string {
	s := strings.TrimPrefix(g, "./")
	for strings.HasPrefix(s, "**/") {
		s = strings.TrimPrefix(s, "**/")
	}
	return s
}

// initializeScanner creates a scanner instance from configuration.
// For now, it always creates a Gitleaks scanner. In the future, this could
// support multiple scanner types based on configuration.
func initializeScanner(cfg Config) (scanner.Scanner, error) {
	// Try to auto-detect .gitleaks.toml if not explicitly configured
	if cfg.GitleaksConfig.GetConfigPath() == "" {
		if detected := gitleaks.DetectConfigPath(cfg.Root); detected != "" {
			cfgPath := detected
			cfg.GitleaksConfig.ConfigPath = &cfgPath
		}
	}

	// Create Gitleaks scanner
	scnr, err := gitleaks.NewScanner(cfg.GitleaksConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create gitleaks scanner: %w", err)
	}

	return scnr, nil
}
