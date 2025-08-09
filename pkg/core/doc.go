// Package core provides a small, stable facade over Redactyl's internal engine
// for external integrations. It deliberately re-exports a narrow API surface
// to allow Enterprise and third-party tools to depend on a stable import path
// without exposing internal implementation packages.
//
// Example:
//
//	cfg := core.Config{Root: ".", Threads: 0}
//	findings, err := core.Scan(cfg)
//	if err != nil { /* handle */ }
//	_ = core.MarshalFindings(os.Stdout, findings)
package core
