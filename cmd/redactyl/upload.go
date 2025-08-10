package redactyl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/franzer/redactyl/internal/git"
	"github.com/franzer/redactyl/internal/types"
	"github.com/franzer/redactyl/pkg/core"
)

const uploadSchemaVersion = "1"

type uploadEnvelope struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Schema   string         `json:"schema_version"`
	Repo     string         `json:"repo,omitempty"`
	Commit   string         `json:"commit,omitempty"`
	Branch   string         `json:"branch,omitempty"`
	Findings []core.Finding `json:"findings"`
}

func uploadFindings(rootPath, url, token string, noMeta bool, findings []core.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	env := uploadEnvelope{Tool: "redactyl", Version: version, Schema: uploadSchemaVersion, Findings: findings}
	if !noMeta {
		// Best-effort git metadata
		repo, commit, branch := git.RepoMetadata(rootPath)
		env.Repo, env.Commit, env.Branch = repo, commit, branch
	}
	body, _ := json.Marshal(env)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload status %d", resp.StatusCode)
	}
	return nil
}

// convertFindings adapts internal type to public facade type when needed.
// Currently Finding is a type alias, but keep function for future decoupling.
func convertFindings(in []types.Finding) []core.Finding {
	out := make([]core.Finding, len(in))
	for i := range in {
		out[i] = core.Finding(in[i])
	}
	return out
}
