package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Entry struct {
	Hash  string
	Files map[string][]byte
}

// validateRoot validates and normalizes a git repository root path.
// Returns the cleaned absolute path or an error if invalid.
func validateRoot(root string) (string, error) {
	// Check for null bytes (potential injection)
	if strings.ContainsRune(root, 0) {
		return "", fmt.Errorf("invalid path: contains null byte")
	}

	// Clean and make absolute
	cleaned := filepath.Clean(root)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", root, err)
	}

	// Verify it's a directory
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("cannot access path %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", root)
	}

	return abs, nil
}

// RepoMetadata returns (repo, commit, branch) best-effort for the given root.
// Empty strings are returned on failure. It avoids heavy git calls and uses
// simple plumbing to remain fast in CI.
func RepoMetadata(root string) (string, string, string) {
	validRoot, err := validateRoot(root)
	if err != nil {
		return "", "", ""
	}

	// repo (remote origin URL short)
	repo := ""
	if out, err := exec.Command("git", "-C", validRoot, "config", "--get", "remote.origin.url").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		// trim common suffix
		s = strings.TrimSuffix(s, ".git")
		// keep owner/name when possible
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = s[i+1:]
		}
		if i := strings.Index(s, "github.com/"); i >= 0 {
			s = s[i+len("github.com/"):]
		}
		repo = s
	}
	// commit
	commit := ""
	if out, err := exec.Command("git", "-C", validRoot, "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	// branch (try symbolic-ref, fallback to show-branch)
	branch := ""
	if out, err := exec.Command("git", "-C", validRoot, "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		branch = strings.TrimSpace(string(out))
	}
	return repo, commit, branch
}

func LastNCommits(root string, n int) ([]Entry, error) {
	if n <= 0 {
		return nil, nil
	}

	validRoot, err := validateRoot(root)
	if err != nil {
		return nil, err
	}

	// Use `git show` per commit to keep it simple
	cmd := exec.Command("git", "-C", validRoot, "rev-list", "--max-count", fmt.Sprintf("%d", n), "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	hashes := strings.Fields(string(out))

	var entries []Entry
	for _, h := range hashes {
		// get changed files + content in commit
		cmd = exec.Command("git", "-C", validRoot, "show", h, "--name-only", "--pretty=")
		filesOut, err := cmd.Output()
		if err != nil {
			continue
		}
		fileList := strings.Fields(string(filesOut))
		files := map[string][]byte{}
		for _, p := range fileList {
			show := exec.Command("git", "-C", validRoot, "show", h+":"+p)
			b, err := show.Output()
			if err == nil {
				files[p] = b
			}
		}
		entries = append(entries, Entry{Hash: h, Files: files})
	}
	return entries, nil
}

func DiffAgainst(root, base string) ([]string, [][]byte, error) {
	validRoot, err := validateRoot(root)
	if err != nil {
		return nil, nil, err
	}

	cmd := exec.Command("git", "-C", validRoot, "diff", "--name-only", base)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}
	paths := strings.Fields(string(out))
	var data [][]byte
	for _, p := range paths {
		show := exec.Command("git", "-C", validRoot, "diff", "--unified=0", base, "--", p)
		b, err := show.Output()
		if err != nil {
			b = []byte{}
		}
		// Extract only added lines from unified diff ('+' lines, excluding headers like '+++' and '@@')
		buf := bytes.NewBuffer(nil)
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "@@") {
				continue
			}
			if strings.HasPrefix(line, "+") {
				buf.WriteString(strings.TrimPrefix(line, "+"))
				buf.WriteByte('\n')
			}
		}
		data = append(data, buf.Bytes())
	}
	return paths, data, nil
}

func StagedDiff(root string) ([]string, [][]byte, error) {
	validRoot, err := validateRoot(root)
	if err != nil {
		return nil, nil, err
	}

	cmd := exec.Command("git", "-C", validRoot, "diff", "--name-only", "--cached")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}
	paths := strings.Fields(string(out))
	var data [][]byte
	for _, p := range paths {
		show := exec.Command("git", "-C", validRoot, "show", ":"+p)
		b, err := show.Output()
		if err != nil {
			b = []byte{}
		}
		data = append(data, b)
	}
	return paths, data, nil
}
