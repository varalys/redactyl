package core

import (
	"encoding/json"
	"io"
)

// MarshalFindings pretty-prints findings as JSON for humans or pipelines.
func MarshalFindings(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// UnmarshalFindings decodes findings JSON, useful for ingestion tests.
func UnmarshalFindings(r io.Reader) ([]Finding, error) {
	var fs []Finding
	if err := json.NewDecoder(r).Decode(&fs); err != nil {
		return nil, err
	}
	return fs, nil
}
