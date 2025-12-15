package core_test

import (
	"fmt"
	"os"
	"time"

	"github.com/redactyl/redactyl/pkg/core"
)

// ExampleScan demonstrates how to perform a simple scan of a directory.
func ExampleScan() {
	// 1. Configure the scan
	cfg := core.Config{
		Root:            ".",   // Scan the current directory
		Threads:         4,     // Number of concurrent workers
		IncludeGlobs:    "*.go", // Only scan Go files (optional)
		MaxBytes:        1024 * 1024, // Skip files larger than 1MB
	}

	// 2. Run the scan
	findings, err := core.Scan(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		return
	}

	// 3. Process findings
	if len(findings) == 0 {
		fmt.Println("No secrets found.")
	} else {
		fmt.Printf("Found %d secrets.\n", len(findings))
		// Helper to write JSON output to stdout
		_ = core.MarshalFindings(os.Stdout, findings)
	}
}

// ExampleScanWithStats shows how to run a scan and retrieve execution statistics.
func ExampleScanWithStats() {
	cfg := core.Config{
		Root:           "test/integration/fixtures", // Point to a directory
		ScanTimeBudget: 5 * time.Second,            // Set a time limit per artifact
	}

	// Run scan and get detailed result object
	result, err := core.ScanWithStats(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Scanned %d files in %s\n", result.FilesScanned, result.Duration)
	fmt.Printf("Found %d secrets\n", len(result.Findings))
	
	// Check artifact scanning stats
	if result.ArtifactStats.AbortedByTime > 0 {
		fmt.Printf("Warning: %d artifacts timed out\n", result.ArtifactStats.AbortedByTime)
	}
}
