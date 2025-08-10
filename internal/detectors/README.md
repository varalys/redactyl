Detectors

This package contains Redactyl's secret detectors. Each detector scans a file's contents and returns zero or more findings.

Adding a new detector

Follow this checklist to add a detector:

1) Create a new file named `servicename.go` (lowercase; use underscores for multi-word names) in this directory.
2) Implement a detector function with signature (use helpers in `helpers.go`):

```go
package detectors

import (
    "bufio"
    "bytes"
    "regexp"
    "strings"

    "github.com/franzer/redactyl/internal/types"
)

// Example: GitHub token using findSimple
var reExample = regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}`)

func ExampleServiceToken(path string, data []byte) []types.Finding {
    return findSimple(path, data, reExample, "example_service_token", types.SevHigh, 0.9)
}
```

3) Register the detector in `detectors.go`:
- Add the function to the `all` slice
- Add its stable string ID to `IDs()`
- Optionally add a short function ID to `funcByID` and `FunctionIDs()` for `test-detector`

4) Add tests (required):
- Create `servicename_test.go`
- Include positive cases (env-var style, JSON/YAML style if applicable) and negative cases (near-misses)
- Keep tests fast and deterministic

5) Run tests locally:

```sh
go test ./...
```

6) Update documentation if needed:
- If adding a notable category (e.g., a new provider type), update the detectors section in the top-level `README.md`

Conventions

- File naming: `servicename.go`; multi-word with underscores, e.g., `azure_sas.go`
- Detector ID naming: lowercase with underscores, e.g., `azure_sas_token`
- Severity: set to `high` for real secrets (keys, PATs, webhooks, DB creds); `medium` for sometimes-public tokens; consider splitting public vs secret variants
- Confidence: prefer 0.9+ for precise regexes; context-gate broader patterns to keep noise low
- Inline ignores: respect `redactyl:ignore` when it clearly targets your detector (use a meaningful substring like the provider name)

Tips

- Prefer simple, precise regexes; avoid catastrophic backtracking
- Use context-gated matching for providers without strong prefixes (check for env var names or nearby keywords)
- For URL-style detectors, anchor to well-known hostnames and path shapes
- Reuse helper patterns where appropriate; keep helpers simple and local to the detector if only used once

Developer tools

- List detectors: `redactyl detectors`
- Try a detector against text: `redactyl test-detector <short-id>` and paste sample input on stdin

