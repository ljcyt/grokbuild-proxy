package openai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ChatCompletionRequest is a minimal OpenAI chat.completions request shape.
// Unknown fields are ignored during conversion.
type ChatCompletionRequest struct {
	Model             string          `json:"model"`
	Messages          []ChatMessage   `json:"messages"`
	Stream            bool            `json:"stream,omitempty"`
	MaxTokens         *int            `json:"max_tokens,omitempty"`
	MaxCompletionTok  *int            `json:"max_completion_tokens,omitempty"`
	Temperature       *float64        `json:"temperature,omitempty"`
	TopP              *float64        `json:"top_p,omitempty"`
	Tools             []ChatTool      `json:"tools,omitempty"`
	ToolChoice        json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat    json.RawMessage `json:"response_format,omitempty"`
	User              string          `json:"user,omitempty"`
	N                 int             `json:"n,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	Stop              json.RawMessage `json:"stop,omitempty"`
	Logprobs          *bool           `json:"logprobs,omitempty"`
	Audio             json.RawMessage `json:"audio,omitempty"`
	Modalities        []string        `json:"modalities,omitempty"`
	// ReasoningEffort is accepted from some clients and mapped into Responses.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

// ChatMessage is a chat message.
type ChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"`
	Name       string          `json:"name,omitempty"`
	ToolCalls  []ChatToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

// ChatToolCall is an assistant tool call in chat format.
type ChatToolCall struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ChatTool is a function tool definition.
type ChatTool struct {
	Type     string `json:"type"`
	Function *struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
	} `json:"function,omitempty"`
}

// ChatToResponses converts a chat.completions body into a minimal Responses body.
// The returned map is not yet fully sanitized; callers should run SanitizeResponses.
func ChatToResponses(raw []byte) (map[string]any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("openai chat: invalid json: %w", err)
	}
	messages, ok := fields["messages"]
	if !ok || strings.TrimSpace(string(messages)) == "null" {
		return nil, fmt.Errorf("openai chat: missing field `messages`")
	}
	var req ChatCompletionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("openai chat: invalid json: %w", err)
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("openai chat: messages must not be empty")
	}
	return ChatRequestToResponses(&req)
}

// ChatRequestToResponses converts a parsed chat request into Responses body fields.
func ChatRequestToResponses(req *ChatCompletionRequest) (map[string]any, error) {
	if req == nil {
		return nil, fmt.Errorf("openai chat: nil request")
	}
	if req.N > 1 {
		return nil, fmt.Errorf("openai chat: n > 1 is not supported")
	}
	if req.Logprobs != nil && *req.Logprobs {
		return nil, fmt.Errorf("openai chat: logprobs is not supported")
	}
	if len(req.Audio) > 0 && string(req.Audio) != "null" {
		return nil, fmt.Errorf("openai chat: audio is not supported")
	}
	for _, modality := range req.Modalities {
		if !strings.EqualFold(strings.TrimSpace(modality), "text") {
			return nil, fmt.Errorf("openai chat: modality %q is not supported", modality)
		}
	}
	if len(req.Stop) > 0 && string(req.Stop) != "null" {
		return nil, fmt.Errorf("openai chat: stop is not supported by this upstream")
	}
	out := map[string]any{}
	if m := strings.TrimSpace(req.Model); m != "" {
		out["model"] = m
	}
	if req.Stream {
		out["stream"] = true
	}

	input, instructions, err := chatMessagesToInput(req.Messages)
	if err != nil {
		return nil, err
	}
	if len(instructions) > 0 {
		out["instructions"] = strings.Join(instructions, "\n\n")
	}
	if len(input) > 0 {
		out["input"] = input
	}

	if req.MaxTokens != nil {
		out["max_output_tokens"] = *req.MaxTokens
	} else if req.MaxCompletionTok != nil {
		out["max_output_tokens"] = *req.MaxCompletionTok
	}
	if req.Temperature != nil {
		out["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		out["top_p"] = *req.TopP
	}
	if len(req.ResponseFormat) > 0 && string(req.ResponseFormat) != "null" {
		var rf any
		if err := json.Unmarshal(req.ResponseFormat, &rf); err == nil {
			out["response_format"] = rf
		}
	}
	if tools := chatToolsToResponses(req.Tools); len(tools) > 0 {
		out["tools"] = tools
	}
	if len(req.ToolChoice) > 0 && string(req.ToolChoice) != "null" {
		var tc any
		if err := json.Unmarshal(req.ToolChoice, &tc); err == nil {
			out["tool_choice"] = normalizeToolChoice(tc)
		}
	}
	if req.ParallelToolCalls != nil {
		out["parallel_tool_calls"] = *req.ParallelToolCalls
	}
	if u := strings.TrimSpace(req.User); u != "" {
		out["user"] = u
	}
	if e := strings.TrimSpace(req.ReasoningEffort); e != "" {
		out["reasoning_effort"] = e
	}
	return out, nil
}

func chatMessagesToInput(messages []ChatMessage) (input []any, instructions []string, err error) {
	for i, msg := range messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		switch role {
		case "system", "developer":
			text, e := contentToString(msg.Content)
			if e != nil {
				return nil, nil, fmt.Errorf("openai chat: message[%d] content: %w", i, e)
			}
			if text != "" {
				instructions = append(instructions, text)
			}
		case "user":
			content, _, e := chatContentToResponses(msg.Content)
			if e != nil {
				return nil, nil, fmt.Errorf("openai chat: message[%d] content: %w", i, e)
			}
			input = append(input, map[string]any{
				"type":    "message",
				"role":    "user",
				"content": content,
			})
		case "assistant":
			if text, e := contentToString(msg.Content); e == nil && strings.TrimSpace(text) != "" {
				input = append(input, map[string]any{
					"type":    "message",
					"role":    "assistant",
					"content": text,
				})
			}
			for _, tc := range msg.ToolCalls {
				name := strings.TrimSpace(tc.Function.Name)
				if name == "" {
					continue
				}
				item := map[string]any{
					"type":      "function_call",
					"name":      name,
					"arguments": tc.Function.Arguments,
				}
				if id := strings.TrimSpace(tc.ID); id != "" {
					item["call_id"] = id
					item["id"] = id
				}
				input = append(input, item)
			}
		case "tool":
			outText, e := contentToString(msg.Content)
			if e != nil {
				return nil, nil, fmt.Errorf("openai chat: message[%d] content: %w", i, e)
			}
			item := map[string]any{
				"type":    "function_call_output",
				"output":  outText,
				"call_id": strings.TrimSpace(msg.ToolCallID),
			}
			input = append(input, item)
		default:
			text, e := contentToString(msg.Content)
			if e != nil {
				return nil, nil, fmt.Errorf("openai chat: message[%d] content: %w", i, e)
			}
			input = append(input, map[string]any{
				"type":    "message",
				"role":    role,
				"content": text,
			})
		}
	}
	return input, instructions, nil
}

func chatToolsToResponses(tools []ChatTool) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		typ := strings.ToLower(strings.TrimSpace(t.Type))
		if typ == "" {
			typ = "function"
		}
		if typ != "function" || t.Function == nil {
			b, err := json.Marshal(t)
			if err != nil {
				continue
			}
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				out = append(out, m)
			}
			continue
		}
		fn := map[string]any{
			"type": "function",
			"name": t.Function.Name,
		}
		if d := strings.TrimSpace(t.Function.Description); d != "" {
			fn["description"] = d
		}
		if len(t.Function.Parameters) > 0 && string(t.Function.Parameters) != "null" {
			var params any
			if err := json.Unmarshal(t.Function.Parameters, &params); err == nil {
				fn["parameters"] = params
			}
		}
		out = append(out, fn)
	}
	return out
}

func normalizeToolChoice(tc any) any {
	switch v := tc.(type) {
	case string:
		return v
	case map[string]any:
		if strings.ToLower(asString(v["type"])) == "function" {
			if fn, ok := v["function"].(map[string]any); ok {
				name := asString(fn["name"])
				if name != "" {
					return map[string]any{"type": "function", "name": name}
				}
			}
			if name := asString(v["name"]); name != "" {
				return v
			}
		}
		return v
	default:
		return tc
	}
}

func chatContentToResponses(raw json.RawMessage) (any, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	var parts []map[string]any
	if err := json.Unmarshal(raw, &parts); err != nil {
		text, textErr := contentToString(raw)
		return text, false, textErr
	}

	hasImage := false
	out := make([]any, 0, len(parts))
	var textOnly []string
	for _, part := range parts {
		switch strings.ToLower(strings.TrimSpace(asString(part["type"]))) {
		case "", "text", "input_text":
			if text := asString(part["text"]); text != "" {
				textOnly = append(textOnly, text)
				out = append(out, map[string]any{"type": "input_text", "text": text})
			}
		case "image_url", "input_image":
			urlValue := ""
			detail := ""
			switch image := part["image_url"].(type) {
			case string:
				urlValue = image
			case map[string]any:
				urlValue = asString(image["url"])
				detail = asString(image["detail"])
			}
			if urlValue == "" {
				urlValue = asString(part["url"])
			}
			if urlValue == "" {
				return nil, false, fmt.Errorf("image_url part is missing url")
			}
			imagePart := map[string]any{"type": "input_image", "image_url": urlValue}
			if detail != "" {
				imagePart["detail"] = detail
			}
			out = append(out, imagePart)
			hasImage = true
		default:
			return nil, false, fmt.Errorf("content part type %q is not supported", asString(part["type"]))
		}
	}
	if hasImage {
		return out, true, nil
	}
	return strings.Join(textOnly, "\n"), false, nil
}

func contentToString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var parts []any
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for i, p := range parts {
			switch t := p.(type) {
			case string:
				if i > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(t)
			case map[string]any:
				if text := asString(t["text"]); text != "" {
					if i > 0 {
						b.WriteByte('\n')
					}
					b.WriteString(text)
				}
			}
		}
		return b.String(), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		if text := asString(obj["text"]); text != "" {
			return text, nil
		}
	}
	return strings.TrimSpace(string(raw)), nil
}

// ResponsesToChat converts a non-stream Responses JSON body into chat.completion.
func ResponsesToChat(raw []byte) ([]byte, error) {
	return ResponsesToChatWithModel(raw, "")
}

// ResponsesToChatWithModel converts a Responses response while retaining the
// model name requested by the client. The upstream may return an internal
// tiered name such as grok-4.5-build-free, which is not a valid client model.
func ResponsesToChatWithModel(raw []byte, requestedModel string) ([]byte, error) {
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("openai chat: responses json: %w", err)
	}
	if requestedModel = strings.TrimSpace(requestedModel); requestedModel != "" {
		resp["model"] = requestedModel
	}
	out := responsesMapToChat(resp)
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("openai chat: marshal chat: %w", err)
	}
	return b, nil
}

func responsesMapToChat(resp map[string]any) map[string]any {
	id := asString(resp["id"])
	if id == "" {
		id = "chatcmpl-proxy"
	}
	model := asString(resp["model"])
	created := int64(0)
	if c, ok := asInt64(resp["created_at"]); ok {
		created = c
	} else if c, ok := asInt64(resp["created"]); ok {
		created = c
	}
	if created == 0 {
		created = time.Now().Unix()
	}

	content, toolCalls, finish := extractOutput(resp)

	message := map[string]any{
		"role":    "assistant",
		"content": content,
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
		if content == "" {
			message["content"] = nil
		}
	}

	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finish,
		"logprobs":      nil,
	}

	out := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{choice},
	}
	if usage := mapUsage(resp["usage"]); usage != nil {
		out["usage"] = usage
	}
	return out
}

func extractOutput(resp map[string]any) (content string, toolCalls []any, finish string) {
	finish = "stop"
	if ot := asString(resp["output_text"]); ot != "" {
		content = ot
	}

	output, _ := resp["output"].([]any)
	var textParts []string
	for _, item := range output {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(asString(m["type"])))
		switch typ {
		case "message":
			textParts = append(textParts, extractOutputMessageText(m)...)
		case "function_call", "tool_call":
			finish = "tool_calls"
			name := asString(m["name"])
			if name == "" {
				if fn, ok := m["function"].(map[string]any); ok {
					name = asString(fn["name"])
				}
			}
			args := asString(m["arguments"])
			if args == "" {
				if fn, ok := m["function"].(map[string]any); ok {
					args = asString(fn["arguments"])
				}
			}
			if args == "" {
				if a, ok := m["arguments"]; ok && asString(a) == "" {
					if b, err := json.Marshal(a); err == nil {
						args = string(b)
					}
				}
			}
			id := asString(m["call_id"])
			if id == "" {
				id = asString(m["id"])
			}
			if id == "" {
				id = fmt.Sprintf("call_%d", len(toolCalls))
			}
			tc := map[string]any{
				"id":   id,
				"type": "function",
				"function": map[string]any{
					"name":      name,
					"arguments": args,
				},
			}
			toolCalls = append(toolCalls, tc)
		case "reasoning":
			// ignore in chat content for MVP
		default:
			if t := asString(m["text"]); t != "" {
				textParts = append(textParts, t)
			}
		}
	}
	if content == "" && len(textParts) > 0 {
		content = strings.Join(textParts, "")
	}
	if status := strings.ToLower(asString(resp["status"])); status == "incomplete" {
		if finish == "stop" {
			finish = "length"
		}
	}
	return content, toolCalls, finish
}

func extractOutputMessageText(m map[string]any) []string {
	var parts []string
	switch c := m["content"].(type) {
	case string:
		if c != "" {
			parts = append(parts, c)
		}
	case []any:
		for _, p := range c {
			pm, ok := p.(map[string]any)
			if !ok {
				if s := asString(p); s != "" {
					parts = append(parts, s)
				}
				continue
			}
			typ := strings.ToLower(asString(pm["type"]))
			if typ == "output_text" || typ == "text" || typ == "" {
				if t := asString(pm["text"]); t != "" {
					parts = append(parts, t)
				}
			}
		}
	}
	if len(parts) == 0 {
		if t := asString(m["text"]); t != "" {
			parts = append(parts, t)
		}
	}
	return parts
}

func mapUsage(u any) map[string]any {
	m, ok := u.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	prompt, _ := asInt64(m["input_tokens"])
	if prompt == 0 {
		prompt, _ = asInt64(m["prompt_tokens"])
	}
	completion, _ := asInt64(m["output_tokens"])
	if completion == 0 {
		completion, _ = asInt64(m["completion_tokens"])
	}
	total, _ := asInt64(m["total_tokens"])
	if total == 0 {
		total = prompt + completion
	}
	return map[string]any{
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      total,
	}
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		return i, err == nil
	case string:
		var n json.Number = json.Number(t)
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
