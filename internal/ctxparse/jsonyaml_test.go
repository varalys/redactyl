package ctxparse

import "testing"

func TestJSONFields_SimpleAndNested(t *testing.T) {
	good := `{
  "a": 1,
  "b": "val",
  "nested": {"k": "v"}
}`
	f := JSONFields([]byte(good))
	if len(f) == 0 {
		t.Fatal("expected some fields for valid json")
	}
	// ensure at least basic keys present
	foundB := false
	for _, x := range f {
		if x.Key == "b" {
			foundB = true
			break
		}
	}
	if !foundB {
		t.Fatalf("expected to find key 'b' in JSONFields: %#v", f)
	}

	bad := `{"a":` // invalid
	if g := JSONFields([]byte(bad)); g != nil {
		t.Fatalf("expected nil for invalid json, got: %#v", g)
	}
}

func TestYAMLFields_ScalarsAndStructure(t *testing.T) {
	y := "" +
		"root:\n" +
		"  name: service\n" +
		"  nested:\n" +
		"    key: value\n" +
		"list:\n" +
		"  - item1\n"
	f := YAMLFields([]byte(y))
	if len(f) == 0 {
		t.Fatal("expected some fields for valid yaml")
	}
	// check that a scalar path was captured
	found := false
	for _, x := range f {
		if x.Key == "root.name" && x.Value == "service" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find root.name=service in YAMLFields: %#v", f)
	}

	// Do not assert invalid YAML behavior here because many strings are valid YAML scalars
}
