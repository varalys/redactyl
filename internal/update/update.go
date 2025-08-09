package update

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	repoLatestURL = "https://api.github.com/repos/franzer/redactyl/releases/latest"
	cacheFileName = "update.json"
)

type cache struct {
	LastChecked time.Time `json:"last_checked"`
	Latest      string    `json:"latest"`
}

func configDir() string {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "redactyl")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "redactyl")
}

func loadCache() (cache, error) {
	var c cache
	dir := configDir()
	if dir == "" {
		return c, errors.New("no config dir")
	}
	b, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal(b, &c)
	return c, nil
}

func saveCache(c cache) {
	dir := configDir()
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0755)
	b, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, cacheFileName), b, 0644)
}

func latestVersionOnline() (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", repoLatestURL, nil)
	req.Header.Set("User-Agent", "redactyl-updater")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var obj struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", err
	}
	v := obj.TagName
	if v == "" {
		v = obj.Name
	}
	return v, nil
}

// Check returns (latest, isNewer, error). It uses a 24h cache and skips in CI.
func Check(current string, noNetwork bool) (string, bool, error) {
	if os.Getenv("CI") != "" || noNetwork {
		return "", false, nil
	}
	current = normalize(current)
	c, _ := loadCache()
	latest := c.Latest
	if time.Since(c.LastChecked) > 24*time.Hour || latest == "" {
		if v, err := latestVersionOnline(); err == nil {
			latest = normalize(v)
			c.Latest = latest
			c.LastChecked = time.Now()
			saveCache(c)
		}
	}
	if latest == "" || current == "" {
		return latest, false, nil
	}
	newer := compare(latest, current) > 0
	return latest, newer, nil
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	return strings.TrimPrefix(v, "v")
}

// compare returns 1 if a>b, -1 if a<b, 0 if equal, using dot-separated ints.
func compare(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(as) {
			ai = atoiSafe(as[i])
		}
		if i < len(bs) {
			bi = atoiSafe(bs[i])
		}
		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	return 0
}

func atoiSafe(s string) int {
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			v = v*10 + int(s[i]-'0')
		} else {
			break
		}
	}
	return v
}
