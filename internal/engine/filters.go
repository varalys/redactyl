package engine

import "strings"

var defaultExcludeDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"target":       true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"out":          true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"coverage":     true,
	"bin":          true,
	"obj":          true,
}

var defaultExcludeFileSuffixes = []string{
	".min.js", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
	".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z",
	".jar", ".class", ".exe", ".dll", ".so",
	".wasm", ".pyc",
	".pb.go", ".gen.go",
}

var defaultExcludeFileNames = map[string]bool{
	"yarn.lock":                true,
	"package-lock.json":        true,
	"pnpm-lock.yaml":           true,
	"composer.lock":            true,
	"poetry.lock":              true,
	".DS_Store":                true,
	".redactyl_audit.jsonl":    true, // Redactyl's own audit log (contains previous findings)
	".redactyl_last_scan.json": true, // Redactyl's scan cache (contains previous findings)
	".redactyl_baseline.json":  true, // Redactyl's baseline file
}

func isDefaultDirExcluded(name string) bool {
	return defaultExcludeDirs[name] || strings.HasPrefix(name, ".git")
}

func isDefaultFileExcluded(lowerRel string) bool {
	if strings.HasSuffix(lowerRel, ".lock") {
		return true
	}
	for _, s := range defaultExcludeFileSuffixes {
		if strings.HasSuffix(lowerRel, s) {
			return true
		}
	}
	if strings.Contains(lowerRel, ".gen.") {
		return true
	}
	parts := strings.Split(lowerRel, "/")
	if len(parts) > 0 {
		base := parts[len(parts)-1]
		if defaultExcludeFileNames[base] {
			return true
		}
	}
	return false
}
