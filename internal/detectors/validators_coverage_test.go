package detectors

import "testing"

// TestRuleValidatorsKeysAreValid ensures every validator is mapped to a known detector ID.
func TestRuleValidatorsKeysAreValid(t *testing.T) {
	ids := map[string]bool{}
	for _, id := range IDs() {
		ids[id] = true
	}
	for k := range ruleValidators {
		if !ids[k] {
			t.Fatalf("validator key %q not found in detectors IDs()", k)
		}
	}
}
