package detectors

import "testing"

// Verifies structured JSON/YAML scanning detects secrets when key/value are split across lines
// such that line-by-line regex detectors would normally miss them.
func TestStructured_YAML_AWSKeys_SplitLines(t *testing.T) {
	yaml := `aws_access_key_id: |
  AKIAIOSFODNN7EXAMPLE
aws_secret_access_key: |
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`
	fs := RunAll("config.yaml", []byte(yaml))
	var gotAccess, gotSecret bool
	for _, f := range fs {
		switch f.Detector {
		case "aws_access_key":
			gotAccess = true
		case "aws_secret_key":
			gotSecret = true
		}
	}
	if !gotAccess || !gotSecret {
		t.Fatalf("expected structured scan to find aws_access_key and aws_secret_key; got access=%v secret=%v", gotAccess, gotSecret)
	}
}
