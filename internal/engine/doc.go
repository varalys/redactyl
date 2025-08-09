// Package engine contains the core scanning logic for Redactyl. It traverses
// target files, runs detectors, and returns structured findings. This package
// is internal; external consumers should use the stable facade in pkg/core.
package engine
