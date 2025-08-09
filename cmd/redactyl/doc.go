// Package redactyl provides the command-line interface for the Redactyl tool.
// It configures subcommands (scan, baseline, fix, etc.), parses flags, and
// executes the selected command.
//
// Typical usage from a main package:
//
//	package main
//	import "github.com/franzer/redactyl/cmd/redactyl"
//	func main() { redactyl.Execute() }
package redactyl
