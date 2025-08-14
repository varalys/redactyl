package ctxparse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Field represents a simple key/value and the 1-based line number where the value appears.
type Field struct {
	Key   string
	Value string
	Line  int
}

// JSONFields performs a light pass to extract key/value pairs with approximate line numbers.
// It attempts a decode; if that fails, it returns nil.
func JSONFields(b []byte) []Field {
	// We avoid building a full AST with positions (encoding/json lacks pos), so we fallback to a crude scan
	// when the content smells JSON.
	var tmp any
	if err := json.Unmarshal(b, &tmp); err != nil {
		return nil
	}
	// Line map by scanning lines, looking for "key" : value on same line.
	var out []Field
	sc := bufio.NewScanner(bytes.NewReader(b))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if !strings.Contains(t, ":") || !strings.Contains(t, "\"") {
			continue
		}
		// Cheap extraction: first quoted segment as key, rest as value snippet
		// This is best-effort to provide line hints for detectors.
		i := strings.Index(t, "\"")
		j := -1
		if i >= 0 {
			j = strings.Index(t[i+1:], "\"")
			if j >= 0 {
				j = i + 1 + j
			}
		}
		if i >= 0 && j > i {
			key := t[i+1 : j]
			// value after colon
			k := strings.Index(t[j+1:], ":")
			if k >= 0 {
				val := strings.TrimSpace(t[j+1+k+1:])
				out = append(out, Field{Key: key, Value: val, Line: line})
			}
		}
	}
	return out
}

// YAMLFields uses yaml.v3 which provides line numbers for nodes; we flatten simple scalars.
func YAMLFields(b []byte) []Field {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil
	}
	var out []Field
	var walk func(n *yaml.Node, path []string)
	walk = func(n *yaml.Node, path []string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.MappingNode:
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				v := n.Content[i+1]
				key := k.Value
				walk(v, append(path, key))
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.ScalarNode:
			if len(path) > 0 {
				out = append(out, Field{Key: strings.Join(path, "."), Value: n.Value, Line: n.Line})
			}
		}
	}
	walk(&root, nil)
	return out
}
