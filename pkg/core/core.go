package core

import (
	"github.com/franzer/redactyl/internal/engine"
	"github.com/franzer/redactyl/internal/types"
)

// Re-export selected internal types as a stable public API surface.
// These are type aliases so external consumers can depend on a stable path.
// We can replace these with decoupled structs later without breaking callers.
type Config = engine.Config
type Finding = types.Finding

// Scan is the stable entrypoint for other programs.
func Scan(cfg Config) ([]Finding, error) {
	return engine.Scan(cfg)
}

// DetectorIDs returns the list of configured detector IDs.
// This is exposed for convenience to avoid importing internals directly.
func DetectorIDs() []string { return engine.DetectorIDs() }
