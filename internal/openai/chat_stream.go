package openai

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type chatToolStream struct {
	Index        int
	ID           string
	Name         string
	SawArgs      bool
	Finalized    bool
	IdentitySent bool
}

type chatStreamTranslator struct {
	id           string
	model        string
	fixedModel   string
	created      int64
	sentRole     bool
	terminal     bool
	failed       bool
	sawTool      bool
	includeUsage bool
	usage        map[string]any
	tools        map[string]*chatToolStream
	nextTool     int
}

func newChatStreamTranslator(includeUsage bool, requestedModel string) *chatStreamTranslator {
	return &chatStreamTranslator{
		id:           "chatcmpl-proxy",
		model:        strings.TrimSpace(requestedModel),
		fixedModel:   strings.TrimSpace(requestedModel),
		created:      time.Now().Unix(),
		includeUsage: includeUsage,
		tools:        make(map[string]*chatToolStream),
	}
}

func (t *chatStreamTranslator) process(data []byte) ([]map[string]any, error) {
	payload := strings.TrimSpace(string(data))
	if payload == "" {
		return nil, nil
	}
	if payload == "[DONE]" {
		if t.terminal {
			return nil, nil
		}
		return t.finish(""), nil
	}

	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("openai chat stream: invalid event: %w", err)
	}
	typ := strings.ToLower(strings.TrimSpace(asString(event["type"])))
	if response, ok := event["response"].(map[string]any); ok {
		t.updateResponseMetadata(response)
	}

	switch typ {
	case "response.created", "response.in_progress":
		if t.sentRole {
			return nil, nil
		}
		t.sentRole = true
		return []map[string]any{t.chunk(map[string]any{"role": "assistant"}, nil)}, nil

	case "response.output_text.delta", "response.text.delta":
		text := asString(event["delta"])
		if text == "" {
			text = asString(event["text"])
		}
		if text == "" {
			return nil, nil
		}
		delta := map[string]any{"content": text}
		if !t.sentRole {
			delta["role"] = "assistant"
			t.sentRole = true
		}
		return []map[string]any{t.chunk(delta, nil)}, nil

	case "response.output_item.added":
		item, _ := event["item"].(map[string]any)
		if strings.ToLower(asString(item["type"])) != "function_call" {
			return nil, nil
		}
		key, tool := t.ensureTool(event, item)
		_ = key
		return []map[string]any{t.toolChunk(tool, "", true)}, nil

	case "response.function_call_arguments.delta":
		key, tool := t.ensureTool(event, nil)
		_ = key
		args := asString(event["delta"])
		if args == "" {
			return nil, nil
		}
		tool.SawArgs = true
		return []map[string]any{t.toolChunk(tool, args, true)}, nil

	case "response.function_call_arguments.done":
		key, tool := t.ensureTool(event, nil)
		_ = key
		if tool.Finalized {
			return nil, nil
		}
		tool.Finalized = true
		if tool.SawArgs {
			return nil, nil
		}
		args := asString(event["arguments"])
		if args == "" {
			args = "{}"
		}
		tool.SawArgs = true
		return []map[string]any{t.toolChunk(tool, args, true)}, nil

	case "response.output_item.done":
		item, _ := event["item"].(map[string]any)
		if strings.ToLower(asString(item["type"])) != "function_call" {
			return nil, nil
		}
		_, tool := t.ensureTool(event, item)
		if tool.Finalized {
			return nil, nil
		}
		tool.Finalized = true
		if tool.SawArgs {
			return nil, nil
		}
		args := asString(item["arguments"])
		if args == "" {
			args = "{}"
		}
		tool.SawArgs = true
		return []map[string]any{t.toolChunk(tool, args, true)}, nil

	case "response.completed", "response.done":
		return t.finish(""), nil

	case "response.incomplete":
		return t.finish("length"), nil

	case "response.failed", "error":
		t.terminal = true
		t.failed = true
		message := chatStreamErrorMessage(event)
		return []map[string]any{{
			"error": map[string]any{
				"message": message,
				"type":    "server_error",
				"code":    "upstream_stream_failed",
			},
		}}, nil

	default:
		return nil, nil
	}
}

func (t *chatStreamTranslator) finish(reason string) []map[string]any {
	if t.terminal {
		return nil
	}
	t.terminal = true
	if reason == "" {
		if t.sawTool {
			reason = "tool_calls"
		} else {
			reason = "stop"
		}
	}
	out := []map[string]any{t.chunk(map[string]any{}, reason)}
	if t.includeUsage {
		usage := t.usage
		if usage == nil {
			usage = map[string]any{}
		}
		out = append(out, map[string]any{
			"id":      t.id,
			"object":  "chat.completion.chunk",
			"created": t.created,
			"model":   t.model,
			"choices": []any{},
			"usage":   usage,
		})
	}
	return out
}

func (t *chatStreamTranslator) updateResponseMetadata(response map[string]any) {
	if id := asString(response["id"]); id != "" {
		if strings.HasPrefix(id, "resp_") {
			id = "chatcmpl-" + strings.TrimPrefix(id, "resp_")
		}
		t.id = id
	}
	if model := asString(response["model"]); model != "" && t.fixedModel == "" {
		t.model = model
	}
	if created, ok := asInt64(response["created_at"]); ok && created > 0 {
		t.created = created
	} else if created, ok := asInt64(response["created"]); ok && created > 0 {
		t.created = created
	}
	if rawUsage, ok := response["usage"].(map[string]any); ok {
		prompt, _ := asInt64(rawUsage["input_tokens"])
		completion, _ := asInt64(rawUsage["output_tokens"])
		total, ok := asInt64(rawUsage["total_tokens"])
		if !ok {
			total = prompt + completion
		}
		t.usage = map[string]any{
			"prompt_tokens":     prompt,
			"completion_tokens": completion,
			"total_tokens":      total,
		}
	}
}

func (t *chatStreamTranslator) ensureTool(event, item map[string]any) (string, *chatToolStream) {
	key := firstNonEmptyChat(
		asString(event["item_id"]),
		asString(event["call_id"]),
		asString(item["id"]),
		asString(item["call_id"]),
		asString(event["output_index"]),
	)
	if key == "" {
		key = fmt.Sprintf("tool-%d", t.nextTool)
	}
	if tool := t.tools[key]; tool != nil {
		if tool.ID == "" {
			tool.ID = firstNonEmptyChat(asString(event["call_id"]), asString(item["call_id"]), asString(item["id"]))
		}
		if tool.Name == "" {
			tool.Name = firstNonEmptyChat(asString(event["name"]), asString(item["name"]))
		}
		return key, tool
	}
	tool := &chatToolStream{
		Index: t.nextTool,
		ID: firstNonEmptyChat(
			asString(event["call_id"]),
			asString(item["call_id"]),
			asString(item["id"]),
			key,
		),
		Name: firstNonEmptyChat(asString(event["name"]), asString(item["name"])),
	}
	t.nextTool++
	t.tools[key] = tool
	t.sawTool = true
	return key, tool
}

func (t *chatStreamTranslator) chunk(delta map[string]any, finish any) map[string]any {
	return map[string]any{
		"id":      t.id,
		"object":  "chat.completion.chunk",
		"created": t.created,
		"model":   t.model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"delta":         delta,
				"finish_reason": finish,
			},
		},
	}
}

func (t *chatStreamTranslator) toolChunk(tool *chatToolStream, args string, includeIdentity bool) map[string]any {
	function := map[string]any{"arguments": args}
	call := map[string]any{"index": tool.Index, "function": function}
	if includeIdentity && !tool.IdentitySent {
		call["id"] = tool.ID
		call["type"] = "function"
		function["name"] = tool.Name
		tool.IdentitySent = true
	}
	delta := map[string]any{"tool_calls": []any{call}}
	if !t.sentRole {
		delta["role"] = "assistant"
		t.sentRole = true
	}
	return t.chunk(delta, nil)
}

func chatStreamErrorMessage(event map[string]any) string {
	if message := asString(event["message"]); message != "" {
		return message
	}
	if detail, ok := event["error"].(map[string]any); ok {
		if message := asString(detail["message"]); message != "" {
			return message
		}
	}
	if response, ok := event["response"].(map[string]any); ok {
		if detail, ok := response["error"].(map[string]any); ok {
			if message := asString(detail["message"]); message != "" {
				return message
			}
		}
	}
	return http.StatusText(http.StatusBadGateway)
}

func firstNonEmptyChat(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
