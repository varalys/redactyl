package engine

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	doublestar "github.com/bmatcuk/doublestar/v4"
	xxhash "github.com/cespare/xxhash/v2"
	"github.com/redactyl/redactyl/internal/artifacts"
	"github.com/redactyl/redactyl/internal/cache"
	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/git"
	"github.com/redactyl/redactyl/internal/ignore"
	"github.com/redactyl/redactyl/internal/scanner"
	"github.com/redactyl/redactyl/internal/scanner/factory"
	"github.com/redactyl/redactyl/internal/types"
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
	ScanHelm             bool     // Scan Helm charts
	ScanK8s              bool     // Scan Kubernetes manifests
	RegistryImages       []string // Remote registry images to scan (e.g. gcr.io/proj/img:tag)
	MaxArchiveBytes      int64
	MaxEntries           int
	MaxDepth             int
	ScanTimeBudget       time.Duration
	GlobalArtifactBudget time.Duration

	// Gitleaks configuration (for scanner integration)
	GitleaksConfig config.GitleaksConfig
}

type pendingScan struct {
	input    scanner.BatchInput
	cacheKey string
	cacheVal string
}

func cloneMetadata(meta map[string]string) map[string]string {
	if meta == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return out
}

func makeBatchInput(path string, data []byte, ctx *scanner.ScanContext) scanner.BatchInput {
	var sc scanner.ScanContext
	if ctx != nil {
		sc = *ctx
		sc.Metadata = cloneMetadata(ctx.Metadata)
	} else {
		sc = scanner.ScanContext{}
	}
	if sc.VirtualPath == "" {
		sc.VirtualPath = path
	}
	if sc.RealPath == "" {
		sc.RealPath = path
	}
	if sc.Metadata == nil {
		sc.Metadata = map[string]string{}
	}
	return scanner.BatchInput{
		Path:    sc.VirtualPath,
		Data:    data,
		Context: sc,
	}
}

func determineBatchSize(threads int) int {
	if threads <= 0 {
		threads = runtime.GOMAXPROCS(0)
	}
	if threads < 2 {
		threads = 2
	}
	if threads > 32 {
		threads = 32
	}
	return threads * 4
}

func processChunk(scnr scanner.Scanner, cfg Config, chunk []pendingScan, emit func([]types.Finding), updated map[string]string, res *Result) error {
	if len(chunk) == 0 {
		return nil
	}

	cacheOK := true
	if !cfg.DryRun {
		inputs := make([]scanner.BatchInput, len(chunk))
		for i, job := range chunk {
			inputs[i] = job.input
		}
		findings, err := scnr.ScanBatch(inputs)
		if err == nil {
			findings = filterByConfidence(findings, cfg.MinConfidence)
			findings = filterByIDs(findings, cfg.EnableDetectors, cfg.DisableDetectors)
			emit(findings)
		} else {
			cacheOK = false
		}
	}

	for _, job := range chunk {
		res.FilesScanned++
		if cfg.Progress != nil {
			cfg.Progress()
		}
		if cacheOK && !cfg.NoCache && !cfg.DryRun && job.cacheKey != "" && job.cacheVal != "" {
			updated[job.cacheKey] = job.cacheVal
		}
	}
	return nil
}

// DetectorIDs returns the list of available Gitleaks detector IDs.
// This is a representative list of common Gitleaks rules for UI purposes.
// The actual detection is performed by Gitleaks with its full rule set.
func DetectorIDs() []string {
	return factory.DefaultDetectors()
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
	Findings       []types.Finding
	FilesScanned   int
	Duration       time.Duration
	ArtifactStats  DeepStats
	ArtifactErrors []error
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

	scnr, err := initializeScanner(cfg)
	if err != nil {
		return result, fmt.Errorf("failed to initialize scanner: %w", err)
	}

	var db cache.DB
	if !cfg.NoCache {
		db, _ = cache.Load(cfg.Root)
	} else {
		db.Entries = map[string]string{}
	}
	updated := map[string]string{}

	if cfg.Threads <= 0 {
		cfg.Threads = runtime.GOMAXPROCS(0)
	}

	ign, _ := ignore.Load(filepath.Join(cfg.Root, ".redactylignore"))
	ctx := context.Background()

	var out []types.Finding
	started := time.Now()
	emit := func(fs []types.Finding) {
		out = append(out, fs...)
	}

	if cfg.HistoryCommits == 0 && cfg.BaseBranch == "" {
		if err := scanFilesystem(ctx, cfg, scnr, ign, db, emit, updated, &result); err != nil {
			return result, err
		}
	}

	if cfg.ScanStaged {
		if err := scanStaged(cfg, scnr, emit, updated, &result); err != nil {
			return result, err
		}
	}

	if cfg.HistoryCommits > 0 {
		if err := scanHistory(cfg, scnr, ign, emit, updated, &result); err != nil {
			return result, err
		}
	}

	if cfg.BaseBranch != "" {
		if err := scanDiff(cfg, scnr, ign, emit, updated, &result); err != nil {
			return result, err
		}
	}

	if cfg.ScanArchives || cfg.ScanContainers || cfg.ScanIaC || cfg.ScanHelm || cfg.ScanK8s {
		if err := scanArtifacts(cfg, scnr, emit, updated, &result); err != nil {
			return result, err
		}
	}

	result.Findings = out
	result.Duration = time.Since(started)
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

func scanFilesystem(ctx context.Context, cfg Config, scnr scanner.Scanner, ign ignore.Matcher, db cache.DB, emit func([]types.Finding), updated map[string]string, result *Result) error {
	batchSize := determineBatchSize(cfg.Threads)
	queue := make([]pendingScan, 0, batchSize)
	var walkErr error

	err := Walk(ctx, cfg, ign, func(p string, data []byte) {
		if walkErr != nil {
			return
		}
		h := fastHash(data)
		if !cfg.NoCache && db.Entries != nil && db.Entries[p] == h {
			return
		}
		queue = append(queue, pendingScan{
			input:    makeBatchInput(p, data, nil),
			cacheKey: p,
			cacheVal: h,
		})
		if len(queue) >= batchSize {
			if err := processChunk(scnr, cfg, queue, emit, updated, result); err != nil {
				walkErr = err
			}
			queue = queue[:0]
		}
	})
	if err != nil {
		return err
	}
	if walkErr != nil {
		return walkErr
	}
	return processChunk(scnr, cfg, queue, emit, updated, result)
}

func scanStaged(cfg Config, scnr scanner.Scanner, emit func([]types.Finding), updated map[string]string, result *Result) error {
	files, data, err := git.StagedDiff(cfg.Root)
	if err != nil {
		return err
	}

	batchSize := determineBatchSize(cfg.Threads)
	jobs := make([]pendingScan, 0, len(files))
	for i, p := range files {
		if !allowedByGlobs(p, cfg) {
			continue
		}
		if cfg.MaxBytes > 0 && int64(len(data[i])) > cfg.MaxBytes {
			continue
		}
		jobs = append(jobs, pendingScan{
			input:    makeBatchInput(p, data[i], nil),
			cacheKey: p,
			cacheVal: fastHash(data[i]),
		})
	}
	for len(jobs) > 0 {
		end := batchSize
		if end > len(jobs) {
			end = len(jobs)
		}
		chunk := jobs[:end]
		if err := processChunk(scnr, cfg, chunk, emit, updated, result); err != nil {
			return err
		}
		jobs = jobs[end:]
	}
	return nil
}

func scanHistory(cfg Config, scnr scanner.Scanner, ign ignore.Matcher, emit func([]types.Finding), updated map[string]string, result *Result) error {
	entries, err := git.LastNCommits(cfg.Root, cfg.HistoryCommits)
	if err != nil {
		return err
	}

	batchSize := determineBatchSize(cfg.Threads)
	var jobs []pendingScan
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
			jobs = append(jobs, pendingScan{
				input:    makeBatchInput(path, blob, nil),
				cacheKey: path,
				cacheVal: fastHash(blob),
			})
		}
	}
	for len(jobs) > 0 {
		end := batchSize
		if end > len(jobs) {
			end = len(jobs)
		}
		chunk := jobs[:end]
		if err := processChunk(scnr, cfg, chunk, emit, updated, result); err != nil {
			return err
		}
		jobs = jobs[end:]
	}
	return nil
}

func scanDiff(cfg Config, scnr scanner.Scanner, ign ignore.Matcher, emit func([]types.Finding), updated map[string]string, result *Result) error {
	files, data, err := git.DiffAgainst(cfg.Root, cfg.BaseBranch)
	if err != nil {
		return err
	}

	batchSize := determineBatchSize(cfg.Threads)
	jobs := make([]pendingScan, 0, len(files))
	for i, p := range files {
		if !allowedByGlobs(p, cfg) {
			continue
		}
		if ign.Match(p) {
			continue
		}
		if cfg.MaxBytes > 0 && int64(len(data[i])) > cfg.MaxBytes {
			continue
		}
		trimmed := bytes.TrimSpace(data[i])
		jobs = append(jobs, pendingScan{
			input:    makeBatchInput(p, trimmed, nil),
			cacheKey: p,
			cacheVal: fastHash(trimmed),
		})
	}
	for len(jobs) > 0 {
		end := batchSize
		if end > len(jobs) {
			end = len(jobs)
		}
		chunk := jobs[:end]
		if err := processChunk(scnr, cfg, chunk, emit, updated, result); err != nil {
			return err
		}
		jobs = jobs[end:]
	}
	return nil
}

func scanArtifacts(cfg Config, scnr scanner.Scanner, emit func([]types.Finding), updated map[string]string, result *Result) error {
	lim := artifacts.Limits{
		MaxArchiveBytes: cfg.MaxArchiveBytes,
		MaxEntries:      cfg.MaxEntries,
		MaxDepth:        cfg.MaxDepth,
		TimeBudget:      cfg.ScanTimeBudget,
		Workers:         cfg.Threads,
	}
	if cfg.GlobalArtifactBudget > 0 {
		lim.GlobalDeadline = time.Now().Add(cfg.GlobalArtifactBudget)
	}
	batchSize := determineBatchSize(cfg.Threads)
	artifactQueue := make([]pendingScan, 0, batchSize)
	var artifactErr error
	flushArtifacts := func() {
		if len(artifactQueue) == 0 {
			return
		}
		defer func() { artifactQueue = artifactQueue[:0] }()
		if artifactErr != nil {
			return
		}
		if err := processChunk(scnr, cfg, artifactQueue, emit, updated, result); err != nil {
			artifactErr = err
		}
	}
	emitArtifact := func(p string, b []byte) {
		if artifactErr != nil {
			return
		}
		if cfg.DryRun {
			return
		}
		ctx := scanner.ScanContext{
			VirtualPath: p,
			RealPath:    p,
		}
		artifactQueue = append(artifactQueue, pendingScan{
			input:    makeBatchInput(p, b, &ctx),
			cacheKey: p,
			cacheVal: fastHash(b),
		})
		if len(artifactQueue) >= batchSize {
			flushArtifacts()
		}
	}
	allowArtifact := func(rel string) bool { return allowedByGlobs(rel, cfg) }
	var artStats artifacts.Stats

	if cfg.ScanArchives {
		if err := artifacts.ScanArchivesWithStats(cfg.Root, lim, allowArtifact, emitArtifact, &artStats); err != nil {
			result.ArtifactErrors = append(result.ArtifactErrors, err)
		}
	}
	if cfg.ScanContainers {
		if err := artifacts.ScanContainersWithStats(cfg.Root, lim, allowArtifact, emitArtifact, &artStats); err != nil {
			result.ArtifactErrors = append(result.ArtifactErrors, err)
		}
	}
	if cfg.ScanIaC {
		if err := artifacts.ScanIaCWithFilter(cfg.Root, lim, allowArtifact, emitArtifact); err != nil {
			result.ArtifactErrors = append(result.ArtifactErrors, err)
		}
	}
	if cfg.ScanHelm {
		if err := artifacts.ScanHelmChartsWithFilter(cfg.Root, lim, allowArtifact, emitArtifact); err != nil {
			result.ArtifactErrors = append(result.ArtifactErrors, err)
		}
	}
	if cfg.ScanK8s {
		if err := artifacts.ScanK8sManifestsWithFilter(cfg.Root, lim, allowArtifact, emitArtifact); err != nil {
			result.ArtifactErrors = append(result.ArtifactErrors, err)
		}
	}
	if len(cfg.RegistryImages) > 0 {
		for _, img := range cfg.RegistryImages {
			if err := artifacts.ScanRegistryImage(img, lim, emitArtifact, &artStats); err != nil {
				result.ArtifactErrors = append(result.ArtifactErrors, err)
			}
		}
	}
	flushArtifacts()
	if artifactErr != nil {
		return artifactErr
	}
	result.ArtifactStats = DeepStats{
		AbortedByBytes:   artStats.AbortedByBytes,
		AbortedByEntries: artStats.AbortedByEntries,
		AbortedByDepth:   artStats.AbortedByDepth,
		AbortedByTime:    artStats.AbortedByTime,
	}
	return nil
}

func fastHash(b []byte) string {
	if len(b) == 0 {
		return "0000000000000000"
	}
	sum := xxhash.Sum64(b)
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

func initializeScanner(cfg Config) (scanner.Scanner, error) {
	return factory.New(factory.Config{
		Root:           cfg.Root,
		GitleaksConfig: cfg.GitleaksConfig,
	})
}
