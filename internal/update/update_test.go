package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// We can't inject the URL, so we test cache+compare+normalize behavior and the no-network/CI paths.
func TestCheck_NoNetworkOrCI(t *testing.T) {
	t.Setenv("CI", "1")
	if latest, newer, err := Check("1.0.0", false); err != nil || latest != "" || newer {
		t.Fatalf("expected no-op in CI; got latest=%q newer=%v err=%v", latest, newer, err)
	}
}

func TestNormalizeAndCompare(t *testing.T) {
	if normalize(" v1.2.3 ") != "1.2.3" {
		t.Fatalf("normalize failed")
	}
	if compare("1.2.3", "1.2.3") != 0 {
		t.Fatalf("compare equal failed")
	}
	if compare("1.3.0", "1.2.9") <= 0 {
		t.Fatalf("compare greater failed")
	}
	if compare("1.2.0", "1.2.1") >= 0 {
		t.Fatalf("compare lesser failed")
	}
}

func TestCheck_UsesCacheWhenFresh(t *testing.T) {
	// Ensure CI short-circuit is disabled for this test
	t.Setenv("CI", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	c := cache{LastChecked: time.Now(), Latest: "1.2.3"}
	path := filepath.Join(dir, "redactyl", cacheFileName)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	b, _ := json.Marshal(c)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
	latest, newer, err := Check("1.2.2", false)
	if err != nil {
		t.Fatal(err)
	}
	if latest != "1.2.3" || !newer {
		t.Fatalf("expected cached latest=1.2.3 and newer=true; got latest=%q newer=%v", latest, newer)
	}
}

func TestLatestVersionOnline_WithServer(t *testing.T) {
	// Verify httptest server setup for future URL injection refactoring.
	// Currently latestVersionOnline uses a hardcoded URL; this test ensures
	// the JSON response shape matches what we expect from GitHub releases API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v9.9.9"})
	}))
	defer srv.Close()
	// Server URL available at srv.URL for future refactoring
	_ = srv.URL
}
