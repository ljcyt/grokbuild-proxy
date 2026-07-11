package openai

import (
	"encoding/json"
	"fmt"
	"strings"
)

const MaxPromptCacheKeyBytes = 512

// SanitizeResult is the sanitized Responses payload plus extracted model.
type SanitizeResult struct {
	Body  map[string]any
	Model string
	// Stream is the effective stream flag after sanitize.
	Stream bool
	// ConvID is the prompt_cache_key / sticky conversation id used.
	ConvID string
}

// SanitizeResponses rewrites a Responses API JSON body for cli-chat-proxy.
//
// Rules:
//   - preserve native Responses reasoning items for stateless continuation
//   - aggregate system/developer messages into top-level instructions
//   - response_format → text.format
//   - prompt_cache_key defaults to convID when empty
//   - reasoning.effort: "minimal" → "low"
//
// body may be []byte, json.RawMessage, map[string]any, or any JSON-marshalable value.
// convID is used as the default prompt_cache_key when the body does not set one.
func SanitizeResponses(body any, convID string) (*SanitizeResult, error) {
	obj, err := asObjectMap(body)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		obj = map[string]any{}
	}

	// 1) Aggregate system/developer → instructions.
	var instructionParts []string
	if existing := asString(obj["instructions"]); existing != "" {
		instructionParts = append(instructionParts, existing)
	}

	if input, ok := obj["input"]; ok {
		rewritten, extra, err := sanitizeInput(input)
		if err != nil {
			return nil, err
		}
		instructionParts = append(instructionParts, extra...)
		if rewritten == nil {
			delete(obj, "input")
		} else {
			obj["input"] = rewritten
		}
	}

	// Also scan messages[] if present (chat-shaped body mistakenly sent to responses).
	if messages, ok := obj["messages"]; ok {
		rewritten, extra, err := sanitizeInput(messages)
		if err != nil {
			return nil, err
		}
		instructionParts = append(instructionParts, extra...)
		if rewritten == nil {
			delete(obj, "messages")
		} else if _, hasInput := obj["input"]; !hasInput {
			obj["input"] = rewritten
			delete(obj, "messages")
		} else {
			obj["messages"] = rewritten
		}
	}

	if len(instructionParts) > 0 {
		obj["instructions"] = strings.Join(instructionParts, "\n\n")
	}

	// 2) response_format → text.format
	if rf, ok := obj["response_format"]; ok {
		textObj, _ := obj["text"].(map[string]any)
		if textObj == nil {
			textObj = map[string]any{}
		}
		if _, hasFormat := textObj["format"]; !hasFormat {
			textObj["format"] = normalizeResponseFormat(rf)
		}
		obj["text"] = textObj
		delete(obj, "response_format")
	}

	// 3) max_tokens → max_output_tokens (common chat field leakage)
	if _, has := obj["max_output_tokens"]; !has {
		if mt, ok := obj["max_tokens"]; ok {
			obj["max_output_tokens"] = mt
			delete(obj, "max_tokens")
		}
	} else {
		delete(obj, "max_tokens")
	}

	// 4) Canonicalize effort to reasoning.effort. The flat spelling is a
	// compatibility alias; conflicting values are rejected instead of silently
	// choosing one.
	if err := normalizeResponsesReasoning(obj); err != nil {
		return nil, err
	}

	// 5) prompt_cache_key default = convID
	convID = strings.TrimSpace(convID)
	pck := strings.TrimSpace(asString(obj["prompt_cache_key"]))
	if pck == "" {
		pck = strings.TrimSpace(asString(obj["prompt_cache_id"]))
		if pck != "" {
			obj["prompt_cache_key"] = pck
			delete(obj, "prompt_cache_id")
		}
	}
	if pck == "" && convID != "" {
		obj["prompt_cache_key"] = convID
		pck = convID
	}
	if len(pck) > MaxPromptCacheKeyBytes {
		return nil, fmt.Errorf("openai sanitize: prompt_cache_key must be at most %d bytes", MaxPromptCacheKeyBytes)
	}

	model := strings.TrimSpace(asString(obj["model"]))
	stream := asBool(obj["stream"])

	return &SanitizeResult{
		Body:   obj,
		Model:  model,
		Stream: stream,
		ConvID: pck,
	}, nil
}

// SanitizeResponsesBytes is a convenience wrapper returning marshaled JSON.
func SanitizeResponsesBytes(raw []byte, convID string) (sanitized []byte, model string, stream bool, err error) {
	res, err := SanitizeResponses(raw, convID)
	if err != nil {
		return nil, "", false, err
	}
	out, err := json.Marshal(res.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("openai sanitize: marshal: %w", err)
	}
	return out, res.Model, res.Stream, nil
}

func sanitizeInput(input any) (rewritten any, instructions []string, err error) {
	switch v := input.(type) {
	case string:
		return v, nil, nil
	case []any:
		return sanitizeInputList(v)
	case []map[string]any:
		list := make([]any, len(v))
		for i := range v {
			list[i] = v[i]
		}
		return sanitizeInputList(list)
	default:
		b, mErr := json.Marshal(v)
		if mErr != nil {
			return nil, nil, fmt.Errorf("openai sanitize: input: %w", mErr)
		}
		var list []any
		if uErr := json.Unmarshal(b, &list); uErr != nil {
			return v, nil, nil
		}
		return sanitizeInputList(list)
	}
}

func sanitizeInputList(items []any) (any, []string, error) {
	out := make([]any, 0, len(items))
	var instructions []string
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			b, err := json.Marshal(it)
			if err != nil {
				out = append(out, it)
				continue
			}
			var mm map[string]any
			if json.Unmarshal(b, &mm) != nil {
				out = append(out, it)
				continue
			}
			m = mm
		}
		typ := strings.ToLower(strings.TrimSpace(asString(m["type"])))
		role := strings.ToLower(strings.TrimSpace(asString(m["role"])))

		// system/developer → instructions
		if role == "system" || role == "developer" || typ == "system" || typ == "developer" {
			if text := extractMessageText(m); text != "" {
				instructions = append(instructions, text)
			}
			continue
		}

		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, instructions, nil
	}
	return out, instructions, nil
}

func normalizeResponsesReasoning(obj map[string]any) error {
	rawReasoning, hasReasoning := obj["reasoning"]
	var reasoning map[string]any
	if rawReasoning != nil {
		var ok bool
		reasoning, ok = rawReasoning.(map[string]any)
		if !ok {
			return fmt.Errorf("openai sanitize: reasoning must be an object")
		}
	}

	nestedEffort := ""
	nestedSet := false
	if reasoning != nil {
		var err error
		nestedEffort, nestedSet, err = normalizeReasoningEffortValue(reasoning["effort"])
		if err != nil {
			return fmt.Errorf("openai sanitize: reasoning.effort: %w", err)
		}
	}

	flatValue, hasFlat := obj["reasoning_effort"]
	flatEffort, flatSet, err := normalizeReasoningEffortValue(flatValue)
	if err != nil {
		return fmt.Errorf("openai sanitize: reasoning_effort: %w", err)
	}
	if nestedSet && flatSet && nestedEffort != flatEffort {
		return fmt.Errorf(
			"openai sanitize: reasoning.effort %q conflicts with reasoning_effort %q",
			nestedEffort,
			flatEffort,
		)
	}

	effort := nestedEffort
	if effort == "" {
		effort = flatEffort
	}
	if effort != "" {
		if reasoning == nil {
			reasoning = map[string]any{}
		}
		reasoning["effort"] = effort
		obj["reasoning"] = reasoning
	} else if hasReasoning && rawReasoning == nil {
		// Keep an explicit null untouched when there is no flat alias.
		obj["reasoning"] = nil
	}
	if hasFlat {
		delete(obj, "reasoning_effort")
	}
	return nil
}

func normalizeReasoningEffortValue(value any) (string, bool, error) {
	if value == nil {
		return "", false, nil
	}
	effort, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("must be a string")
	}
	effort = strings.ToLower(strings.TrimSpace(effort))
	if effort == "" {
		return "", false, nil
	}
	if effort == "minimal" {
		effort = "low"
	}
	return effort, true, nil
}

func extractMessageText(m map[string]any) string {
	if s := asString(m["content"]); s != "" {
		return s
	}
	switch c := m["content"].(type) {
	case []any:
		var parts []string
		for _, p := range c {
			pm, ok := p.(map[string]any)
			if !ok {
				if s := asString(p); s != "" {
					parts = append(parts, s)
				}
				continue
			}
			if t := asString(pm["text"]); t != "" {
				parts = append(parts, t)
			} else if t := asString(pm["content"]); t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	if s := asString(m["text"]); s != "" {
		return s
	}
	return ""
}

func normalizeResponseFormat(rf any) any {
	if m, ok := rf.(map[string]any); ok {
		if strings.EqualFold(asString(m["type"]), "json_schema") {
			if schema, ok := m["json_schema"].(map[string]any); ok {
				out := map[string]any{"type": "json_schema"}
				for _, key := range []string{"name", "description", "schema", "strict"} {
					if value, exists := schema[key]; exists {
						out[key] = value
					}
				}
				return out
			}
		}
		return m
	}
	if s := strings.TrimSpace(asString(rf)); s != "" {
		return map[string]any{"type": s}
	}
	return rf
}

func asObjectMap(body any) (map[string]any, error) {
	if body == nil {
		return map[string]any{}, nil
	}
	switch v := body.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = val
		}
		return out, nil
	case []byte:
		if len(v) == 0 {
			return map[string]any{}, nil
		}
		var out map[string]any
		if err := json.Unmarshal(v, &out); err != nil {
			return nil, fmt.Errorf("openai sanitize: invalid json: %w", err)
		}
		if out == nil {
			out = map[string]any{}
		}
		return out, nil
	case json.RawMessage:
		return asObjectMap([]byte(v))
	case string:
		return asObjectMap([]byte(v))
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("openai sanitize: marshal body: %w", err)
		}
		return asObjectMap(b)
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case fmt.Stringer:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		s := string(b)
		if len(s) >= 2 && s[0] == '"' {
			var un string
			if json.Unmarshal(b, &un) == nil {
				return un
			}
		}
		return s
	}
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true
		}
	case float64:
		return t != 0
	case json.Number:
		i, err := t.Int64()
		return err == nil && i != 0
	}
	return false
}
