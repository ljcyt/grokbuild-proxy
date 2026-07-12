package requestpatch

import (
	"encoding/json"
	"testing"
)

func TestApply_AppendWebSearch(t *testing.T) {
	p := &Patcher{Rules: []Rule{{
		Name:   "web_search",
		Models: []string{"default", "grok-4.5"},
		Set: map[string]json.RawMessage{
			"tools.-1": json.RawMessage(`{"type":"web_search"}`),
		},
	}}}
	out, err := p.Apply([]byte(`{"model":"grok-4.5","input":"hi","tools":[{"type":"function","name":"f"}]}`), "grok-4.5")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	tools, _ := body["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools=%v", tools)
	}
	second, _ := tools[1].(map[string]any)
	if second["type"] != "web_search" {
		t.Fatalf("second tool=%v", second)
	}
}

func TestApply_CreateToolsWhenMissing(t *testing.T) {
	p := &Patcher{Rules: []Rule{{
		Name: "web_search",
		Set: map[string]json.RawMessage{
			"tools.-1": json.RawMessage(`{"type":"web_search"}`),
		},
	}}}
	out, err := p.Apply([]byte(`{"model":"grok-4.5","input":"hi"}`), "grok-4.5")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	tools, _ := body["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools=%v", tools)
	}
}

func TestApply_SkipDuplicateToolType(t *testing.T) {
	p := &Patcher{Rules: []Rule{{
		Name: "web_search",
		Set: map[string]json.RawMessage{
			"tools.-1": json.RawMessage(`{"type":"web_search"}`),
		},
	}}}
	out, err := p.Apply([]byte(`{"tools":[{"type":"web_search"}]}`), "grok-4.5")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	tools, _ := body["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools=%v", tools)
	}
}

func TestApply_ModelFilter(t *testing.T) {
	p := &Patcher{Rules: []Rule{{
		Name:   "only-45",
		Models: []string{"grok-4.5"},
		Set: map[string]json.RawMessage{
			"temperature": json.RawMessage(`0.2`),
		},
	}}}
	out, err := p.Apply([]byte(`{"model":"other"}`), "other")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"model":"other"}` {
		t.Fatalf("unexpected body %s", out)
	}
	out, err = p.Apply([]byte(`{"model":"grok-4.5"}`), "grok-4.5")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	if body["temperature"] != 0.2 {
		t.Fatalf("temperature=%v", body["temperature"])
	}
}

func TestApply_NestedObjectRaw(t *testing.T) {
	p := &Patcher{Rules: []Rule{{
		Name: "schema",
		Set: map[string]json.RawMessage{
			"text.format": json.RawMessage(`{"type":"json_schema","name":"out","schema":{"type":"object"}}`),
		},
	}}}
	out, err := p.Apply([]byte(`{"input":"x"}`), "grok-4.5")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	text, _ := body["text"].(map[string]any)
	format, _ := text["format"].(map[string]any)
	if format["type"] != "json_schema" || format["name"] != "out" {
		t.Fatalf("format=%v", format)
	}
}
