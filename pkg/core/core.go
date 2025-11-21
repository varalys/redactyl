package core

import (
	"github.com/redactyl/redactyl/internal/engine"
	"github.com/redactyl/redactyl/internal/types"
)

// Re-export selected internal types as a stable public API surface.
// These are type aliases so external consumers can depend on a stable path.
// We can replace these with decoupled structs later without breaking callers.
type Config = engine.Config
type Finding = types.Finding
type Result = engine.Result
type DeepStats = engine.DeepStats

// Scan is the stable entrypoint for other programs.
func Scan(cfg Config) ([]Finding, error) {
	return engine.Scan(cfg)
}

// ScanWithStats is the extended entrypoint that returns findings plus statistics.
// This is useful for integrations that need to report on scan performance or partial failures.
func ScanWithStats(cfg Config) (Result, error) {
	return engine.ScanWithStats(cfg)
}

// DetectorIDs returns the list of configured detector IDs.
// This is exposed for convenience to avoid importing internals directly.
func DetectorIDs() []string { return engine.DetectorIDs() }
