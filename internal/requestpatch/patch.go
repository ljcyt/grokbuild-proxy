// Package requestpatch applies operator-defined raw JSON path overrides
// to upstream Responses request bodies after protocol translation.
package requestpatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Rule is one raw-path override group.
//
// Paths use dotted JSON paths. Array indexes are numeric segments; "-1"
// appends to an array (creating it when missing). Values are raw JSON
// fragments, suitable for complex fields such as tools or text.format.
type Rule struct {
	Name   string
	Models []string // empty or containing "*" matches every model
	Set    map[string]json.RawMessage
}

// Patcher applies ordered rules to a request body.
type Patcher struct {
	Rules []Rule
}

// Apply mutates body according to matching rules. model is the resolved
// upstream model id used for rule matching. Returns the patched body.
func (p *Patcher) Apply(body []byte, model string) ([]byte, error) {
	if p == nil || len(p.Rules) == 0 {
		return body, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return body, nil
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("request_patch: decode body: %w", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("request_patch: body must be a JSON object")
	}
	model = strings.TrimSpace(model)
	changed := false
	for _, rule := range p.Rules {
		if !ruleMatches(rule, model) {
			continue
		}
		for path, raw := range rule.Set {
			path = strings.TrimSpace(path)
			if path == "" {
				return nil, fmt.Errorf("request_patch: rule %q has empty path", rule.Name)
			}
			value, err := decodeRaw(raw)
			if err != nil {
				return nil, fmt.Errorf("request_patch: rule %q path %q: %w", rule.Name, path, err)
			}
			if err := setPath(obj, path, value); err != nil {
				return nil, fmt.Errorf("request_patch: rule %q path %q: %w", rule.Name, path, err)
			}
			changed = true
		}
	}
	if !changed {
		return body, nil
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("request_patch: encode body: %w", err)
	}
	return out, nil
}

func ruleMatches(rule Rule, model string) bool {
	if len(rule.Models) == 0 {
		return true
	}
	for _, item := range rule.Models {
		item = strings.TrimSpace(item)
		if item == "" || item == "*" || strings.EqualFold(item, "default") {
			return true
		}
		if item == model {
			return true
		}
	}
	return false
}

func decodeRaw(raw json.RawMessage) (any, error) {
	raw = json.RawMessage(bytes.TrimSpace(raw))
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty raw value")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("invalid raw JSON: %w", err)
	}
	return value, nil
}

func setPath(root map[string]any, path string, value any) error {
	segments := splitPath(path)
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}
	return setAt(root, segments, value)
}

func splitPath(path string) []string {
	parts := strings.Split(path, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func setAt(node any, segments []string, value any) error {
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}
	seg := segments[0]
	last := len(segments) == 1

	switch cur := node.(type) {
	case map[string]any:
		if isAppendIndex(seg) {
			return fmt.Errorf("cannot use append index on object")
		}
		if last {
			cur[seg] = value
			return nil
		}
		child, exists := cur[seg]
		if !exists || child == nil {
			if isArraySegment(segments[1]) {
				child = []any{}
			} else {
				child = map[string]any{}
			}
			cur[seg] = child
		}
		// For arrays we must re-store after mutation because append may reallocate.
		if arr, ok := child.([]any); ok {
			if err := setAtArray(&arr, segments[1:], value); err != nil {
				return err
			}
			cur[seg] = arr
			return nil
		}
		return setAt(child, segments[1:], value)

	default:
		return fmt.Errorf("cannot set path on %T", node)
	}
}

func setAtArray(arr *[]any, segments []string, value any) error {
	if arr == nil {
		return fmt.Errorf("nil array")
	}
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}
	seg := segments[0]
	last := len(segments) == 1

	if isAppendIndex(seg) {
		if !last {
			return fmt.Errorf("append index must be terminal")
		}
		if shouldSkipToolAppend(*arr, value) {
			return nil
		}
		*arr = append(*arr, value)
		return nil
	}

	idx, err := strconv.Atoi(seg)
	if err != nil {
		return fmt.Errorf("array segment %q is not an index", seg)
	}
	if idx < 0 {
		return fmt.Errorf("array index %d out of range", idx)
	}
	for len(*arr) <= idx {
		*arr = append(*arr, nil)
	}
	if last {
		(*arr)[idx] = value
		return nil
	}
	child := (*arr)[idx]
	if child == nil {
		if isArraySegment(segments[1]) {
			return fmt.Errorf("nested arrays under index are unsupported")
		}
		child = map[string]any{}
		(*arr)[idx] = child
	}
	obj, ok := child.(map[string]any)
	if !ok {
		return fmt.Errorf("array index %d is %T, want object", idx, child)
	}
	return setAt(obj, segments[1:], value)
}

func isAppendIndex(seg string) bool {
	return seg == "-1" || seg == "[]" || seg == "+"
}

func isArraySegment(seg string) bool {
	if isAppendIndex(seg) {
		return true
	}
	_, err := strconv.Atoi(seg)
	return err == nil
}

func shouldSkipToolAppend(existing []any, value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		return false
	}
	wantType, _ := obj["type"].(string)
	if strings.TrimSpace(wantType) == "" {
		return false
	}
	for _, item := range existing {
		cur, ok := item.(map[string]any)
		if !ok {
			continue
		}
		gotType, _ := cur["type"].(string)
		if gotType == wantType {
			return true
		}
	}
	return false
}
