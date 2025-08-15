package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/redactyl/redactyl/internal/ignore"
	yaml "gopkg.in/yaml.v3"
)

// safeClose closes an io.Closer and ignores any error (lint-safe).
func safeClose(c io.Closer) {
	_ = c.Close() //nolint:errcheck
}

// Limits controls bounded deep scanning of artifacts like archives and containers.
type Limits struct {
	MaxArchiveBytes int64
	MaxEntries      int
	MaxDepth        int
	TimeBudget      time.Duration
	Workers         int
}

// Stats collects counters for artifacts aborted due to guardrails.
type Stats struct {
	AbortedByBytes   int
	AbortedByEntries int
	AbortedByDepth   int
	AbortedByTime    int
}

func (s *Stats) add(reason string) {
	if s == nil || reason == "" {
		return
	}
	switch reason {
	case "bytes":
		s.AbortedByBytes++
	case "entries":
		s.AbortedByEntries++
	case "depth":
		s.AbortedByDepth++
	case "time":
		s.AbortedByTime++
	}
}

// PathAllowFunc returns true if the given relative artifact filename should be
// considered for deep scanning (after .redactylignore filtering). When nil,
// all artifact filenames are allowed.
type PathAllowFunc func(rel string) bool

// ScanArchives walks recognized archive files under root and emits text entries.
// It enforces per-artifact limits and does not extract to disk.
func ScanArchives(root string, limits Limits, emit func(path string, data []byte)) error {
	return ScanArchivesWithFilter(root, limits, nil, emit)
}

// ScanArchivesWithFilter is like ScanArchives but also consults an optional
// allow predicate to filter which artifact filenames are processed.
func ScanArchivesWithFilter(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte)) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))
	// Walk the filesystem and locate candidate archives by extension
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}
		if allow != nil && !allow(rel) {
			return nil
		}
		if !isArchivePath(rel) {
			return nil
		}
		// Avoid double-processing container images: skip .tar that looks like a Docker save
		if strings.HasSuffix(strings.ToLower(rel), ".tar") {
			ok, ierr := isContainerTar(p)
			if ierr != nil {
				return nil
			}
			if ok {
				return nil
			}
		}
		// per-artifact counters and deadline
		started := time.Now()
		deadline := time.Time{}
		if limits.TimeBudget > 0 {
			deadline = started.Add(limits.TimeBudget)
		}
		var decompressed int64
		var entries int
		_ = scanArchiveFile(p, rel, limits, &decompressed, &entries, 0, deadline, emit) //nolint:errcheck
		return nil
	})
	return nil
}

// ScanContainers walks recognized container image/layer tarballs and emits text entries.
// Heuristic: presence of manifest.json or entries ending with "/layer.tar".
func ScanContainers(root string, limits Limits, emit func(path string, data []byte)) error {
	return ScanContainersWithFilter(root, limits, nil, emit)
}

// ScanContainersWithFilter is like ScanContainers but also consults an optional
// allow predicate to filter which artifact filenames are processed.
func ScanContainersWithFilter(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte)) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(rel), ".tar") {
			return nil
		}
		isContainer, ierr := isContainerTar(p)
		if ierr != nil || !isContainer {
			return nil
		}
		if allow != nil && !allow(rel) {
			return nil
		}
		// per-artifact counters and deadline
		started := time.Now()
		deadline := time.Time{}
		if limits.TimeBudget > 0 {
			deadline = started.Add(limits.TimeBudget)
		}
		var decompressed int64
		var entries int
		// stream through outer tar and process each layer tar entry
		f, oerr := os.Open(p)
		if oerr != nil {
			return nil
		}
		defer safeClose(f)
		tr := tar.NewReader(f)
		for {
			if r := limitsExceededReason(limits, decompressed, entries, 0, deadline); r != "" {
				return nil
			}
			hdr, nerr := tr.Next()
			if errors.Is(nerr, io.EOF) || hdr == nil {
				return nil
			}
			if nerr != nil {
				return nil
			}
			name := hdr.Name
			if hdr.FileInfo().IsDir() {
				continue
			}
			// layer tar entries have a path like "<layerID>/layer.tar"
			if strings.HasSuffix(name, "/layer.tar") || strings.HasSuffix(name, "\\layer.tar") {
				layerID := filepath.Dir(name)
				if i := strings.LastIndex(layerID, "/"); i >= 0 {
					layerID = layerID[i+1:]
				}
				if i := strings.LastIndex(layerID, "\\"); i >= 0 {
					layerID = layerID[i+1:]
				}
				// Limit reader to this entry size and hand off to tar reader using '/' join for layer path
				lr := &io.LimitedReader{R: tr, N: hdr.Size}
				vp := rel + "::" + layerID
				_ = scanTarReaderJoin(vp, "/", limits, &decompressed, &entries, 1, deadline, emit, lr) //nolint:errcheck
			}
		}
	})
	return nil
}

// ScanContainersWithStats is like ScanContainersWithFilter but also increments
// the provided stats counters when a guardrail abort reason is encountered.
func ScanContainersWithStats(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte), stats *Stats) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(rel), ".tar") {
			return nil
		}
		isContainer, err := isContainerTar(p)
		if err != nil || !isContainer {
			return nil
		}
		if allow != nil && !allow(rel) {
			return nil
		}
		// per-artifact counters and deadline
		started := time.Now()
		deadline := time.Time{}
		if limits.TimeBudget > 0 {
			deadline = started.Add(limits.TimeBudget)
		}
		var decompressed int64
		var entries int
		// stream through outer tar and process each layer tar entry
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer safeClose(f)
		tr := tar.NewReader(f)
		for {
			if r := limitsExceededReason(limits, decompressed, entries, 0, deadline); r != "" {
				if stats != nil {
					stats.add(r)
				}
				return nil
			}
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) || hdr == nil {
				return nil
			}
			if err != nil {
				return nil
			}
			name := hdr.Name
			if hdr.FileInfo().IsDir() {
				continue
			}
			// layer tar entries have a path like "<layerID>/layer.tar"
			if strings.HasSuffix(name, "/layer.tar") || strings.HasSuffix(name, "\\layer.tar") {
				layerID := filepath.Dir(name)
				if i := strings.LastIndex(layerID, "/"); i >= 0 {
					layerID = layerID[i+1:]
				}
				if i := strings.LastIndex(layerID, "\\"); i >= 0 {
					layerID = layerID[i+1:]
				}
				// Limit reader to this entry size and hand off to tar reader using '/' join for layer path
				lr := &io.LimitedReader{R: tr, N: hdr.Size}
				vp := rel + "::" + layerID
				_ = scanTarReaderJoin(vp, "/", limits, &decompressed, &entries, 1, deadline, emit, lr) //nolint:errcheck
			}
		}
	})
	return nil
}

// ScanIaC scans IaC hotspots like Terraform state files and kubeconfigs.
// Minimal placeholder: handled in a subsequent step.
func ScanIaC(root string, limits Limits, emit func(path string, data []byte)) error {
	return ScanIaCWithFilter(root, limits, nil, emit)
}

// ScanIaCWithFilter scans IaC hotspots like Terraform state files and kubeconfigs.
// For small Terraform state files, it extracts likely secret fields and emits them
// individually to reduce noise. For larger files, it falls back to text emission
// bounded by limits. Kubeconfigs are emitted as text for structured detectors to parse.
func ScanIaCWithFilter(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte)) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}
		if allow != nil && !allow(rel) {
			return nil
		}
		lower := strings.ToLower(rel)
		isTF := strings.HasSuffix(lower, ".tfstate")
		isKC := strings.HasSuffix(lower, ".kubeconfig") || isKubeConfigPath(rel)
		if !isTF && !isKC {
			return nil
		}
		// establish time budget
		started := time.Now()
		deadline := time.Time{}
		if limits.TimeBudget > 0 {
			deadline = started.Add(limits.TimeBudget)
		}
		var decompressed int64
		// Terraform state selective scan
		if isTF {
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer safeClose(f)
			b, readErr := readAllBounded(f, limits, &decompressed, deadline)
			if readErr == nil {
				// Skip selective JSON parsing for very large tfstate to avoid overhead
				const tfstateSelectiveMaxBytes = 2 << 20 // 2 MiB
				if len(b) <= tfstateSelectiveMaxBytes {
					var data any
					if json.Unmarshal(b, &data) == nil {
						count := 0
						emitKV := func(pathStr string, value string) {
							// stop if limits exceeded by entries
							if limitsExceeded(limits, decompressed, count, 0, deadline) {
								return
							}
							buf := []byte(pathStr + ": " + value)
							emit(rel+"::json:"+pathStr, buf)
							count++
						}
						extractSensitiveJSON("", data, emitKV)
						return nil
					}
				}
			}
			// fallback: emit bounded text content
			if len(b) > 0 {
				emit(rel, b)
			}
			return nil
		}
		// Kubeconfigs: try selective YAML extraction, else emit entire file
		if isKC {
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer safeClose(f)
			b, rerr := readAllBounded(f, limits, &decompressed, deadline)
			if rerr != nil {
				return nil
			}
			if len(b) > 0 {
				if emitted := tryExtractKubeconfig(rel, b, emit); !emitted {
					emit(rel, b)
				}
			}
		}
		return nil
	})
	return nil
}

// isKubeConfigPath returns true if the path looks like a default kube config location
// such as ".kube/config" anywhere in the repo tree.
func isKubeConfigPath(rel string) bool {
	sep := string(os.PathSeparator)
	parts := strings.Split(rel, sep)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == ".kube" && parts[i+1] == "config" {
			return true
		}
	}
	return false
}

// extractSensitiveJSON walks decoded JSON and emits string values for keys
// that are likely to contain secrets based on name heuristics.
func extractSensitiveJSON(prefix string, node any, emitKV func(pathStr string, value string)) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if keyLooksSensitive(k) {
				if s, ok := val.(string); ok {
					emitKV(path, s)
				} else if obj, ok := val.(map[string]any); ok {
					// common nested form: {"value": "..."}
					if s, ok := obj["value"].(string); ok {
						emitKV(path+".value", s)
					}
				}
			}
			extractSensitiveJSON(path, val, emitKV)
		}
	case []any:
		for i, it := range v {
			path := prefix + "[" + strconv.Itoa(i) + "]"
			extractSensitiveJSON(path, it, emitKV)
		}
	}
}

func keyLooksSensitive(k string) bool {
	l := strings.ToLower(k)
	if l == "token" || l == "password" || l == "secret" || l == "client_secret" || l == "access_key" || l == "secret_key" || l == "api_key" || l == "private_key" || l == "bearer_token" || l == "auth_token" || l == "refresh_token" || l == "cert" || l == "certificate" || l == "key" {
		return true
	}
	if strings.Contains(l, "password") || strings.Contains(l, "secret") || strings.Contains(l, "token") || strings.Contains(l, "apikey") || strings.Contains(l, "accesskey") || strings.Contains(l, "privatekey") || strings.Contains(l, "client_secret") || strings.Contains(l, "bearer") || strings.Contains(l, "certificate") {
		return true
	}
	return false
}

// --- helpers ---

func isArchivePath(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".gz") {
		return true
	}
	return false
}

func isContainerTar(fullPath string) (bool, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return false, err
	}
	defer safeClose(f)
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) || hdr == nil {
			return false, nil
		}
		if err != nil {
			return false, nil
		}
		name := hdr.Name
		if name == "manifest.json" || strings.HasSuffix(name, "/layer.tar") || strings.HasSuffix(name, "\\layer.tar") {
			return true, nil
		}
	}
}

func scanArchiveFile(fullPath string, rel string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte)) error {
	// respect depth only for nested archives; top-level depth is 0
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer safeClose(f)

	lower := strings.ToLower(rel)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return scanZipReader(rel, limits, decompressed, entries, depth, deadline, emit, f)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		return scanTarReader(rel, limits, decompressed, entries, depth, deadline, emit, gz)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReader(rel, limits, decompressed, entries, depth, deadline, emit, f)
	case strings.HasSuffix(lower, ".gz"):
		// single-file gzip: emit decompressed content as a single entry
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		name := gz.Name
		if name == "" {
			name = strings.TrimSuffix(rel, ".gz")
		}
		b, readErr := readAllBounded(gz, limits, decompressed, deadline)
		if readErr != nil {
			return nil
		}
		if looksBinary(b) || looksNonTextMIME(name, b) {
			return nil
		}
		vp := rel + "::" + name
		emit(vp, b)
		*entries++
		return nil
	default:
		return nil
	}
}

func scanZipReader(archivePath string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), r io.ReaderAt) error {
	// Determine size for zip.NewReader: we need an io.ReaderAt and size.
	// Unfortunately we cannot get size from a generic io.ReaderAt; reopen the file by path if possible.
	// Here archivePath is a virtual path (relative); attempt to use current working dir join is unreliable.
	// As a compromise for local filesystem, require r to be *os.File for top-level; nested uses bytes.Reader with known size.
	switch v := r.(type) {
	case *os.File:
		fi, err := v.Stat()
		if err != nil {
			return nil
		}
		zr, err := zip.NewReader(v, fi.Size())
		if err != nil {
			return nil
		}
		for _, f := range zr.File {
			if limitsExceeded(limits, *decompressed, *entries, depth, deadline) {
				return nil
			}
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, readErr := readAllBounded(rc, limits, decompressed, deadline)
			safeClose(rc)
			if readErr != nil {
				continue
			}
			name := f.Name
			if looksBinary(b) || looksNonTextMIME(name, b) {
				if depth < limits.MaxDepth && isArchivePath(name) {
					_ = scanNestedArchive(archivePath+"::"+name, name, b, limits, decompressed, entries, depth+1, deadline, emit)
				}
				continue
			}
			vp := archivePath + "::" + name
			emit(vp, b)
			*entries++
		}
	default:
		// Cannot determine size; skip
		return nil
	}
	return nil
}

func scanTarReader(archivePath string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), r io.Reader) error {
	return scanTarReaderJoin(archivePath, "::", limits, decompressed, entries, depth, deadline, emit, r)
}

func scanTarReaderJoin(archivePath string, sep string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		if limitsExceeded(limits, *decompressed, *entries, depth, deadline) {
			return nil
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) || hdr == nil {
			return nil
		}
		if err != nil {
			return nil
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		b, readErr := readAllBounded(tr, limits, decompressed, deadline)
		if readErr != nil {
			continue
		}
		name := hdr.Name
		if looksBinary(b) || looksNonTextMIME(name, b) {
			if depth < limits.MaxDepth && isArchivePath(name) {
				_ = scanNestedArchive(archivePath+sep+name, name, b, limits, decompressed, entries, depth+1, deadline, emit) //nolint:errcheck
			}
			continue
		}
		vp := archivePath + sep + name
		emit(vp, b)
		*entries++
	}
}

func scanNestedArchive(pathChain string, name string, blob []byte, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte)) error {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			return nil
		}
		for _, f := range zr.File {
			if limitsExceeded(limits, *decompressed, *entries, depth, deadline) {
				return nil
			}
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, readErr := readAllBounded(rc, limits, decompressed, deadline)
			safeClose(rc)
			if readErr != nil {
				continue
			}
			fname := f.Name
			if looksBinary(b) || looksNonTextMIME(fname, b) {
				if depth < limits.MaxDepth && isArchivePath(fname) {
					_ = scanNestedArchive(pathChain+"::"+fname, fname, b, limits, decompressed, entries, depth+1, deadline, emit)
				}
				continue
			}
			emit(pathChain+"::"+fname, b)
			*entries++
		}
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		return scanTarReader(pathChain, limits, decompressed, entries, depth, deadline, emit, gz)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReader(pathChain, limits, decompressed, entries, depth, deadline, emit, bytes.NewReader(blob))
	case strings.HasSuffix(lower, ".gz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		name := gz.Name
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(pathChain), ".gz")
		}
		b, readErr := readAllBounded(gz, limits, decompressed, deadline)
		if readErr != nil {
			return nil
		}
		if looksBinary(b) || looksNonTextMIME(name, b) {
			return nil
		}
		emit(pathChain+"::"+name, b)
		*entries++
	}
	return nil
}

func readAllBounded(r io.Reader, limits Limits, decompressed *int64, deadline time.Time) ([]byte, error) {
	// enforce time budget prior to read
	if !deadline.IsZero() && time.Now().After(deadline) {
		return nil, errors.New("time budget exceeded")
	}
	// bound by MaxArchiveBytes remaining
	remain := int64(1 << 62)
	if limits.MaxArchiveBytes > 0 {
		remain = limits.MaxArchiveBytes - *decompressed
		if remain <= 0 {
			return nil, errors.New("byte budget exceeded")
		}
	}
	// copy in chunks up to remain, checking deadline between chunks
	var buf bytes.Buffer
	chunk := int64(32 * 1024)
	for remain > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, errors.New("time budget exceeded")
		}
		sz := chunk
		if sz > remain {
			sz = remain
		}
		n, err := io.CopyN(&buf, r, sz)
		*decompressed += n
		remain -= n
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func limitsExceeded(l Limits, decompressed int64, entries int, depth int, deadline time.Time) bool {
	if l.MaxEntries > 0 && entries >= l.MaxEntries {
		return true
	}
	if l.MaxArchiveBytes > 0 && decompressed >= l.MaxArchiveBytes {
		return true
	}
	if l.MaxDepth > 0 && depth > l.MaxDepth {
		return true
	}
	if !deadline.IsZero() && time.Now().After(deadline) {
		return true
	}
	return false
}

// limitsExceededReason returns the specific reason guardrails were exceeded, or "" if within limits.
func limitsExceededReason(l Limits, decompressed int64, entries int, depth int, deadline time.Time) string {
	if l.MaxEntries > 0 && entries >= l.MaxEntries {
		return "entries"
	}
	if l.MaxArchiveBytes > 0 && decompressed >= l.MaxArchiveBytes {
		return "bytes"
	}
	if l.MaxDepth > 0 && depth > l.MaxDepth {
		return "depth"
	}
	if !deadline.IsZero() && time.Now().After(deadline) {
		return "time"
	}
	return ""
}

// text heuristics similar to engine; small and fast
func looksBinary(b []byte) bool {
	const sniff = 800
	if len(b) == 0 {
		return false
	}
	n := sniff
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

func looksNonTextMIME(path string, b []byte) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg") || strings.HasSuffix(lower, ".gif") || strings.HasSuffix(lower, ".pdf") || strings.HasSuffix(lower, ".webp") || strings.HasSuffix(lower, ".ico") {
		return true
	}
	// basic header sniffers
	if len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n" {
		return true
	}
	if len(b) >= 2 && b[0] == 'P' && b[1] == 'K' {
		// zip header
		return true
	}
	return false
}

// --- kubeconfig helpers ---

// tryExtractKubeconfig attempts to parse kubeconfig YAML and emit sensitive fields.
// Returns true if any entries were emitted.
func tryExtractKubeconfig(rel string, b []byte, emit func(path string, data []byte)) bool {
	type userEntry struct {
		Name string `yaml:"name"`
		User struct {
			Token          string         `yaml:"token"`
			ClientCertData string         `yaml:"client-certificate-data"`
			ClientKeyData  string         `yaml:"client-key-data"`
			Exec           map[string]any `yaml:"exec"`
			AuthProvider   map[string]any `yaml:"auth-provider"`
		} `yaml:"user"`
	}
	type clusterEntry struct {
		Name    string `yaml:"name"`
		Cluster struct {
			CACertData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	}
	var doc struct {
		Users    []userEntry    `yaml:"users"`
		Clusters []clusterEntry `yaml:"clusters"`
	}
	if !looksLikeYAML(b) {
		return false
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return false
	}
	emitted := false
	for i, u := range doc.Users {
		base := rel + "::yaml:users[" + strconv.Itoa(i) + "].user"
		if u.User.Token != "" {
			emit(base+".token", []byte(u.User.Token))
			emitted = true
		}
		if u.User.ClientCertData != "" {
			emit(base+".client-certificate-data", []byte(u.User.ClientCertData))
			emitted = true
		}
		if u.User.ClientKeyData != "" {
			emit(base+".client-key-data", []byte(u.User.ClientKeyData))
			emitted = true
		}
		if ap := u.User.AuthProvider; ap != nil {
			if cfg, ok := ap["config"].(map[string]any); ok {
				if t, ok := cfg["access-token"].(string); ok && t != "" {
					emit(base+".auth-provider.config.access-token", []byte(t))
					emitted = true
				}
				if rt, ok := cfg["refresh-token"].(string); ok && rt != "" {
					emit(base+".auth-provider.config.refresh-token", []byte(rt))
					emitted = true
				}
			}
		}
	}
	for i, c := range doc.Clusters {
		base := rel + "::yaml:clusters[" + strconv.Itoa(i) + "].cluster"
		if c.Cluster.CACertData != "" {
			emit(base+".certificate-authority-data", []byte(c.Cluster.CACertData))
			emitted = true
		}
	}
	return emitted
}

var yamlDocRx = regexp.MustCompile(`(?m)^\s*(apiVersion|clusters|users)\s*:`)

func looksLikeYAML(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return yamlDocRx.Find(b) != nil
}

// --- archive stats helpers (opt-in) ---

// ScanArchivesWithStats mirrors ScanArchivesWithFilter but also records guardrail abort reasons into stats.
func ScanArchivesWithStats(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte), stats *Stats) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))
	type item struct{ full, rel string }
	var items []item
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}
		if allow != nil && !allow(rel) {
			return nil
		}
		if !isArchivePath(rel) {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(rel), ".tar") {
			ok, _ := isContainerTar(p)
			if ok {
				return nil
			}
		}
		items = append(items, item{full: p, rel: rel})
		return nil
	})
	workers := limits.Workers
	if workers <= 0 {
		workers = 1
	}
	ch := make(chan item, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				started := time.Now()
				deadline := time.Time{}
				if limits.TimeBudget > 0 {
					deadline = started.Add(limits.TimeBudget)
				}
				var decompressed int64
				var entries int
				_ = scanArchiveFileWithStats(it.full, it.rel, limits, &decompressed, &entries, 0, deadline, emit, stats)
			}
		}()
	}
	for _, it := range items {
		ch <- it
	}
	close(ch)
	wg.Wait()
	return nil
}

func scanArchiveFileWithStats(fullPath string, rel string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), stats *Stats) error {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer safeClose(f)

	lower := strings.ToLower(rel)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return scanZipReaderWithStats(rel, limits, decompressed, entries, depth, deadline, emit, f, stats)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		return scanTarReaderWithStats(rel, limits, decompressed, entries, depth, deadline, emit, gz, stats)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReaderWithStats(rel, limits, decompressed, entries, depth, deadline, emit, f, stats)
	case strings.HasSuffix(lower, ".gz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		name := gz.Name
		if name == "" {
			name = strings.TrimSuffix(rel, ".gz")
		}
		b, readErr := readAllBounded(gz, limits, decompressed, deadline)
		if readErr != nil {
			if stats != nil {
				if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
					stats.add(r)
				}
			}
			return nil
		}
		if looksBinary(b) || looksNonTextMIME(name, b) {
			return nil
		}
		emit(rel+"::"+name, b)
		*entries++
		return nil
	default:
		return nil
	}
}

func scanZipReaderWithStats(archivePath string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), r io.ReaderAt, stats *Stats) error {
	switch v := r.(type) {
	case *os.File:
		fi, err := v.Stat()
		if err != nil {
			return nil
		}
		zr, err := zip.NewReader(v, fi.Size())
		if err != nil {
			return nil
		}
		for _, f := range zr.File {
			if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
				if stats != nil {
					stats.add(r)
				}
				return nil
			}
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, readErr := readAllBounded(rc, limits, decompressed, deadline)
			safeClose(rc)
			if readErr != nil {
				if stats != nil {
					if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
						stats.add(r)
					}
				}
				continue
			}
			name := f.Name
			if looksBinary(b) || looksNonTextMIME(name, b) {
				if depth < limits.MaxDepth && isArchivePath(name) {
					_ = scanNestedArchiveWithStats(archivePath+"::"+name, name, b, limits, decompressed, entries, depth+1, deadline, emit, stats) //nolint:errcheck
				} else if stats != nil && isArchivePath(name) {
					stats.add("depth")
				}
				continue
			}
			emit(archivePath+"::"+name, b)
			*entries++
		}
	default:
		return nil
	}
	return nil
}

func scanTarReaderWithStats(archivePath string, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), r io.Reader, stats *Stats) error {
	tr := tar.NewReader(r)
	for {
		if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
			if stats != nil {
				stats.add(r)
			}
			return nil
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) || hdr == nil {
			return nil
		}
		if err != nil {
			return nil
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		b, readErr := readAllBounded(tr, limits, decompressed, deadline)
		if readErr != nil {
			if stats != nil {
				if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
					stats.add(r)
				}
			}
			continue
		}
		name := hdr.Name
		if looksBinary(b) || looksNonTextMIME(name, b) {
			if depth < limits.MaxDepth && isArchivePath(name) {
				_ = scanNestedArchiveWithStats(archivePath+"::"+name, name, b, limits, decompressed, entries, depth+1, deadline, emit, stats) //nolint:errcheck
			} else if stats != nil && isArchivePath(name) {
				stats.add("depth")
			}
			continue
		}
		emit(archivePath+"::"+name, b)
		*entries++
	}
}

func scanNestedArchiveWithStats(pathChain string, name string, blob []byte, limits Limits, decompressed *int64, entries *int, depth int, deadline time.Time, emit func(path string, data []byte), stats *Stats) error {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			return nil
		}
		for _, f := range zr.File {
			if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
				if stats != nil {
					stats.add(r)
				}
				return nil
			}
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, readErr := readAllBounded(rc, limits, decompressed, deadline)
			safeClose(rc)
			if readErr != nil {
				if stats != nil {
					if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
						stats.add(r)
					}
				}
				continue
			}
			fname := f.Name
			if looksBinary(b) || looksNonTextMIME(fname, b) {
				if depth < limits.MaxDepth && isArchivePath(fname) {
					_ = scanNestedArchiveWithStats(pathChain+"::"+fname, fname, b, limits, decompressed, entries, depth+1, deadline, emit, stats) //nolint:errcheck
				} else if stats != nil && isArchivePath(fname) {
					stats.add("depth")
				}
				continue
			}
			emit(pathChain+"::"+fname, b)
			*entries++
		}
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		return scanTarReaderWithStats(pathChain, limits, decompressed, entries, depth, deadline, emit, gz, stats)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReaderWithStats(pathChain, limits, decompressed, entries, depth, deadline, emit, bytes.NewReader(blob), stats) //nolint:errcheck
	case strings.HasSuffix(lower, ".gz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer safeClose(gz)
		n := gz.Name
		if n == "" {
			n = strings.TrimSuffix(filepath.Base(pathChain), ".gz")
		}
		b, readErr := readAllBounded(gz, limits, decompressed, deadline)
		if readErr != nil {
			if stats != nil {
				if r := limitsExceededReason(limits, *decompressed, *entries, depth, deadline); r != "" {
					stats.add(r)
				}
			}
			return nil
		}
		if looksBinary(b) || looksNonTextMIME(n, b) {
			return nil
		}
		emit(pathChain+"::"+n, b)
		*entries++
	}
	return nil
}
