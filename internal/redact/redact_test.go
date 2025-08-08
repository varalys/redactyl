package redact

import (
	"os"
	"regexp"
	"testing"
)

func TestApplyAndWouldChange(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "redact-*.env")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()

	original := "PASSWORD=supersecret\nOTHER=value\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	rx := regexp.MustCompile(`PASSWORD=\S+`)
	reps := []Replacement{{Pattern: rx, Replace: "PASSWORD=<redacted>"}}

	would, err := WouldChange(path, reps)
	if err != nil {
		t.Fatal(err)
	}
	if !would {
		t.Fatalf("expected WouldChange to be true")
	}

	changed, err := Apply(path, reps)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatalf("expected Apply to modify the file")
	}

	b, _ := os.ReadFile(path)
	got := string(b)
	if got == original {
		t.Fatalf("file contents did not change")
	}
	if got != "PASSWORD=<redacted>\nOTHER=value\n" {
		t.Fatalf("unexpected contents: %q", got)
	}

	// second apply should be no-op
	changed, err = Apply(path, reps)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatalf("expected second Apply to be no change")
	}
}
