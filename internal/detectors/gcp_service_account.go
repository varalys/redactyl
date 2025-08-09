package detectors

import (
	"bytes"
	"encoding/json"

	"github.com/franzer/redactyl/internal/types"
)

// Heuristic: detect JSON containing a service account with private_key
func GCPServiceAccountKey(path string, data []byte) []types.Finding {
	// avoid large files
	if len(data) > 1<<20 { // 1 MiB
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil
	}
	if t, ok := obj["type"].(string); !ok || t != "service_account" {
		return nil
	}
	if pk, ok := obj["private_key"].(string); !ok || !bytes.Contains([]byte(pk), []byte("BEGIN PRIVATE KEY")) {
		return nil
	}
	return []types.Finding{{
		Path: path, Line: 1, Match: "gcp service account private_key", Detector: "gcp_service_account_key", Severity: types.SevHigh, Confidence: 0.98,
	}}
}
