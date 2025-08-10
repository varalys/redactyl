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

// suffixes treated as non-text/big or noisy artifacts when default excludes enabled
var defaultExcludeFileSuffixes = []string{
	".min.js", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
	".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z",
	".jar", ".class", ".exe", ".dll", ".so",
	".wasm", ".pyc",
	// common generated code outputs
	".pb.go", ".gen.go",
}

// exact filenames commonly safe to exclude when default excludes enabled
var defaultExcludeFileNames = map[string]bool{
	// lockfiles (package managers)
	"yarn.lock":         true,
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"composer.lock":     true,
	"poetry.lock":       true,
	// OS cruft
	".DS_Store": true,
}

func isDefaultDirExcluded(name string) bool {
	return defaultExcludeDirs[name] || strings.HasPrefix(name, ".git")
}

func isDefaultFileExcluded(lowerRel string) bool {
	// fast check for any *.lock
	if strings.HasSuffix(lowerRel, ".lock") {
		return true
	}
	for _, s := range defaultExcludeFileSuffixes {
		if strings.HasSuffix(lowerRel, s) {
			return true
		}
	}
	// generic generated artifacts pattern
	if strings.Contains(lowerRel, ".gen.") {
		return true
	}
	// exact filename checks (using lowerRel basename)
	parts := strings.Split(lowerRel, "/")
	if len(parts) > 0 {
		base := parts[len(parts)-1]
		if defaultExcludeFileNames[base] {
			return true
		}
	}
	return false
}
