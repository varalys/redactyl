package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redactyl/redactyl/internal/ignore"
)

// Limits controls bounded deep scanning of artifacts like archives and containers.
type Limits struct {
	MaxArchiveBytes int64
	MaxEntries      int
	MaxDepth        int
	TimeBudget      time.Duration
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
			ok, _ := isContainerTar(p)
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
		_ = scanArchiveFile(p, rel, limits, &decompressed, &entries, 0, deadline, emit)
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
		defer f.Close()
		tr := tar.NewReader(f)
		for {
			if limitsExceeded(limits, decompressed, entries, 0, deadline) {
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
				_ = scanTarReaderJoin(vp, "/", limits, &decompressed, &entries, 1, deadline, emit, lr)
			}
		}
	})
	return nil
}

// ScanIaC scans IaC hotspots like Terraform state files and kubeconfigs.
// Minimal placeholder: handled in a subsequent step.
func ScanIaC(root string, limits Limits, emit func(path string, data []byte)) error {
	_ = root
	_ = limits
	_ = emit
	return nil
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
	defer f.Close()
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
	defer f.Close()

	lower := strings.ToLower(rel)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return scanZipReader(rel, limits, decompressed, entries, depth, deadline, emit, f)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gz.Close()
		return scanTarReader(rel, limits, decompressed, entries, depth, deadline, emit, gz)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReader(rel, limits, decompressed, entries, depth, deadline, emit, f)
	case strings.HasSuffix(lower, ".gz"):
		// single-file gzip: emit decompressed content as a single entry
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gz.Close()
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
		*entries = *entries + 1
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
			_ = rc.Close()
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
			*entries = *entries + 1
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
				_ = scanNestedArchive(archivePath+sep+name, name, b, limits, decompressed, entries, depth+1, deadline, emit)
			}
			continue
		}
		vp := archivePath + sep + name
		emit(vp, b)
		*entries = *entries + 1
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
			_ = rc.Close()
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
			*entries = *entries + 1
		}
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer gz.Close()
		return scanTarReader(pathChain, limits, decompressed, entries, depth, deadline, emit, gz)
	case strings.HasSuffix(lower, ".tar"):
		return scanTarReader(pathChain, limits, decompressed, entries, depth, deadline, emit, bytes.NewReader(blob))
	case strings.HasSuffix(lower, ".gz"):
		gz, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil
		}
		defer gz.Close()
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
		*entries = *entries + 1
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
