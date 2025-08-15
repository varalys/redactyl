package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func makeGzip(t *testing.T, path string, name string, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	gw.Name = name
	_, _ = gw.Write([]byte(content))
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
}

func makeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))})
		_, _ = tw.Write([]byte(content))
	}
	_ = tw.Close()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	_, _ = gw.Write(buf.Bytes())
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanArchives_ZipAndGz(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "sample.zip")
	gzPath := filepath.Join(dir, "log.txt.gz")
	makeZip(t, zipPath, map[string]string{"a.txt": "hello", "b/b.txt": "world"})
	makeGzip(t, gzPath, "log.txt", "line1\nline2")

	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 100, MaxDepth: 2, TimeBudget: 2 * time.Second}
	var got []string
	emit := func(p string, _ []byte) { got = append(got, p) }
	if err := ScanArchives(dir, lim, emit); err != nil {
		t.Fatalf("ScanArchives error: %v", err)
	}
	// Expect virtual paths
	if len(got) < 3 {
		t.Fatalf("expected at least 3 emitted entries, got %d: %v", len(got), got)
	}
}

func TestScanArchives_MaxEntries(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "many.zip")
	files := map[string]string{}
	for i := 0; i < 50; i++ {
		files[filepath.Join("d", "f", "file_"+itoa(i)+".txt")] = "x"
	}
	makeZip(t, zipPath, files)
	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 10, MaxDepth: 1, TimeBudget: 1 * time.Second}
	count := 0
	emit := func(string, []byte) { count++ }
	_ = ScanArchives(dir, lim, emit)
	if count > lim.MaxEntries {
		t.Fatalf("should have capped at max entries; got %d > %d", count, lim.MaxEntries)
	}
}

func TestScanArchives_TarTgz(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "archive.tgz")
	makeTarGz(t, tgz, map[string]string{"x.txt": "1", "y/y.txt": "2"})
	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 100, MaxDepth: 2, TimeBudget: 2 * time.Second}
	count := 0
	emit := func(string, []byte) { count++ }
	if err := ScanArchives(dir, lim, emit); err != nil {
		t.Fatalf("ScanArchives error: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected >=2 entries from tgz, got %d", count)
	}
}

func TestScanArchives_MaxBytesAndTimeBudget(t *testing.T) {
	dir := t.TempDir()
	// Create a zip with many moderately large text files to trip size/time limits
	zipPath := filepath.Join(dir, "heavy.zip")
	files := map[string]string{}
	var big bytes.Buffer
	for i := 0; i < 20000; i++ {
		big.WriteString("abcdefghij")
	} // ~200KB
	for i := 0; i < 50; i++ {
		files["f"+itoa(i)+".txt"] = big.String()
	}
	makeZip(t, zipPath, files)

	lim := Limits{MaxArchiveBytes: 100 << 10, MaxEntries: 1000, MaxDepth: 1, TimeBudget: 10 * time.Millisecond}
	count := 0
	emit := func(string, []byte) { count++ }
	// Should exit early due to size or time budget; just ensure it doesn't blow up
	if err := ScanArchives(dir, lim, emit); err != nil {
		t.Fatalf("ScanArchives error: %v", err)
	}
}

func TestScanContainers_Heuristic(t *testing.T) {
	dir := t.TempDir()
	// Build a fake docker save tar: manifest.json and one layer with layer.tar containing one file
	outer := filepath.Join(dir, "image.tar")
	f, err := os.Create(outer)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	// manifest.json
	man := `[ {"Config":"config.json","Layers":["123/layer.tar"]} ]`
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(man))})
	_, _ = tw.Write([]byte(man))
	// layer dir file (we won't create a directory entry explicitly)
	// write "123/layer.tar" as a tar entry whose content is itself a tar archive
	var layerBuf bytes.Buffer
	ltw := tar.NewWriter(&layerBuf)
	content := "secret: value\n"
	_ = ltw.WriteHeader(&tar.Header{Name: "etc/app.txt", Mode: 0600, Size: int64(len(content))})
	_, _ = ltw.Write([]byte(content))
	_ = ltw.Close()
	data := layerBuf.Bytes()
	_ = tw.WriteHeader(&tar.Header{Name: "123/layer.tar", Mode: 0600, Size: int64(len(data))})
	_, _ = tw.Write(data)
	_ = tw.Close()
	_ = f.Close()

	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 100, MaxDepth: 2, TimeBudget: 1 * time.Second}
	count := 0
	emit := func(p string, b []byte) {
		_ = b
		if strings.Contains(p, "image.tar::123/") {
			count++
		}
	}
	if err := ScanContainers(dir, lim, emit); err != nil {
		t.Fatalf("ScanContainers error: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected entries from container layer")
	}
}

func TestScanArchivesWithFilter_IncludeExclude(t *testing.T) {
	dir := t.TempDir()
	// Create two archives at different paths
	incl := filepath.Join(dir, "keep", "a.zip")
	excl := filepath.Join(dir, "drop", "b.zip")
	if err := os.MkdirAll(filepath.Dir(incl), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(excl), 0755); err != nil {
		t.Fatal(err)
	}
	makeZip(t, incl, map[string]string{"x.txt": "1"})
	makeZip(t, excl, map[string]string{"y.txt": "2"})

	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 100, MaxDepth: 2, TimeBudget: 1 * time.Second}
	var got []string
	emit := func(p string, _ []byte) { got = append(got, p) }
	allow := func(rel string) bool {
		// Normalize to forward slashes for simplicity like engine.allowedByGlobs does
		r := strings.ReplaceAll(rel, "\\", "/")
		// allow only keep/** and not drop/**
		return strings.HasPrefix(r, "keep/")
	}
	if err := ScanArchivesWithFilter(dir, lim, allow, emit); err != nil {
		t.Fatalf("ScanArchivesWithFilter error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected entries from allowed archive, got none")
	}
	for _, p := range got {
		if strings.HasPrefix(p, "drop/") {
			t.Fatalf("should not have scanned excluded archive: %s", p)
		}
	}
}

func TestScanContainersWithFilter_IncludeExclude(t *testing.T) {
	dir := t.TempDir()
	// Build two fake docker save tars: one allowed, one excluded
	mk := func(path string) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		man := `[ {"Config":"config.json","Layers":["123/layer.tar"]} ]`
		_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(man))})
		_, _ = tw.Write([]byte(man))
		var layerBuf bytes.Buffer
		ltw := tar.NewWriter(&layerBuf)
		content := "secret: value\n"
		_ = ltw.WriteHeader(&tar.Header{Name: "etc/app.txt", Mode: 0600, Size: int64(len(content))})
		_, _ = ltw.Write([]byte(content))
		_ = ltw.Close()
		data := layerBuf.Bytes()
		_ = tw.WriteHeader(&tar.Header{Name: "123/layer.tar", Mode: 0600, Size: int64(len(data))})
		_, _ = tw.Write(data)
		_ = tw.Close()
		_ = f.Close()
	}
	incl := filepath.Join(dir, "keep", "image.tar")
	excl := filepath.Join(dir, "drop", "image.tar")
	mk(incl)
	mk(excl)

	lim := Limits{MaxArchiveBytes: 1 << 20, MaxEntries: 100, MaxDepth: 2, TimeBudget: 1 * time.Second}
	var got []string
	emit := func(p string, _ []byte) { got = append(got, p) }
	allow := func(rel string) bool {
		r := strings.ReplaceAll(rel, "\\", "/")
		return strings.HasPrefix(r, "keep/")
	}
	if err := ScanContainersWithFilter(dir, lim, allow, emit); err != nil {
		t.Fatalf("ScanContainersWithFilter error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected entries from allowed container, got none")
	}
	for _, p := range got {
		if strings.HasPrefix(p, "drop/") {
			t.Fatalf("should not have scanned excluded container: %s", p)
		}
	}
}

func itoa(i int) string { return fmtInt(i) }

func fmtInt(i int) string {
	// small, allocation-free-ish int to string for predictable test output
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
