package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

func TestTranslateRequest_ToolUseAndToolResult(t *testing.T) {
	raw := []byte(`{
		"model": "claude-sonnet-4",
		"max_tokens": 1024,
		"system": "You are helpful.",
		"metadata": {"user_id":"claude-code"},
		"top_k": 40,
		"stop_sequences": ["END"],
		"messages": [
			{"role":"user","content":"what time?"},
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"private","signature":"opaque-anthropic-signature"},
				{"type":"redacted_thinking","data":"opaque-redacted-thinking"},
				{"type":"tool_use","id":"toolu_1","name":"get_time","input":{"tz":"UTC"}}
			]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"12:00"}]}
		],
		"tools": [{"name":"get_time","description":"get time","input_schema":{"type":"object","properties":{"tz":{"type":"string"}}}}],
		"stream": true,
		"thinking": {"type":"enabled","budget_tokens":1024}
	}`)

	body, orig, stream, err := TranslateRequest(raw, TranslateReqOptions{
		ResolvedModel:     "grok-4.5",
		ConvID:            "sess-abc",
		StripUnknownBetas: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if orig != "claude-sonnet-4" {
		t.Fatalf("orig model=%q", orig)
	}
	if !stream {
		t.Fatal("expected stream=true")
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["model"] != "grok-4.5" {
		t.Fatalf("model=%v", out["model"])
	}
	if out["instructions"] != "You are helpful." {
		t.Fatalf("instructions=%v", out["instructions"])
	}
	if out["max_output_tokens"].(float64) != 1024 {
		t.Fatalf("max_output_tokens=%v", out["max_output_tokens"])
	}
	if out["prompt_cache_key"] != "sess-abc" {
		t.Fatalf("prompt_cache_key=%v", out["prompt_cache_key"])
	}
	if _, ok := out["metadata"]; ok {
		t.Fatalf("metadata must not reach Grok Build: %s", body)
	}
	if _, ok := out["top_k"]; ok {
		t.Fatalf("top_k must not reach Grok Build: %s", body)
	}
	if _, ok := out["stop_sequences"]; ok {
		t.Fatalf("stop_sequences must not reach Grok Build: %s", body)
	}
	// Anthropic controls map to Grok reasoning; CPA signatures replay as
	// encrypted_content rather than a provider-native "signature" field.
	if _, ok := out["thinking"]; ok {
		t.Fatal("native thinking should not be forwarded")
	}
	reasoning, _ := out["reasoning"].(map[string]any)
	if reasoning["effort"] != "low" {
		t.Fatalf("reasoning=%v", reasoning)
	}
	include, _ := out["include"].([]any)
	if len(include) != 1 || include[0] != "reasoning.encrypted_content" {
		t.Fatalf("include=%v", include)
	}
	if bytes.Contains(body, []byte("opaque-redacted-thinking")) {
		t.Fatalf("Anthropic redacted thinking leaked upstream: %s", body)
	}

	input, ok := out["input"].([]any)
	if !ok || len(input) != 4 {
		t.Fatalf("input len=%d body=%s", len(input), string(body))
	}

	// user text message
	m0, _ := input[0].(map[string]any)
	if m0["type"] != "message" || m0["role"] != "user" {
		t.Fatalf("m0=%v", m0)
	}

	// assistant thinking signature → replayable Grok reasoning item
	replay, _ := input[1].(map[string]any)
	if replay["type"] != "reasoning" ||
		replay["encrypted_content"] != "opaque-anthropic-signature" {
		t.Fatalf("replay=%v", replay)
	}

	// assistant tool_use → function_call
	fc, _ := input[2].(map[string]any)
	if fc["type"] != "function_call" {
		t.Fatalf("fc type=%v", fc["type"])
	}
	if fc["call_id"] != "toolu_1" {
		t.Fatalf("call_id=%v", fc["call_id"])
	}
	if fc["name"] != "get_time" {
		t.Fatalf("name=%v", fc["name"])
	}
	args, _ := fc["arguments"].(string)
	if !strings.Contains(args, "tz") {
		t.Fatalf("arguments=%q", args)
	}

	// tool_result → function_call_output
	fo, _ := input[3].(map[string]any)
	if fo["type"] != "function_call_output" {
		t.Fatalf("fo type=%v", fo["type"])
	}
	if fo["call_id"] != "toolu_1" {
		t.Fatalf("fo call_id=%v", fo["call_id"])
	}
	if fo["output"] != "12:00" {
		t.Fatalf("output=%v", fo["output"])
	}

	// tools shape
	tools, _ := out["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools=%v", tools)
	}
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "get_time" {
		t.Fatalf("tool=%v", tool)
	}
	if tool["parameters"] == nil {
		t.Fatal("missing parameters")
	}
}

func TestTranslateRequestMapsServerWebSearch(t *testing.T) {
	raw := []byte(`{
		"model":"claude-sonnet-5",
		"max_tokens":512,
		"messages":[{"role":"user","content":"Search current information."}],
		"tools":[{
			"type":"web_search_20260318",
			"name":"web_search",
			"max_uses":3,
			"allowed_domains":["go.dev"]
		}],
		"tool_choice":{"type":"tool","name":"web_search"}
	}`)
	body, _, _, err := TranslateRequest(raw, TranslateReqOptions{
		ResolvedModel:     "grok-4.5",
		StripUnknownBetas: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Tools      []map[string]any `json:"tools"`
		ToolChoice any              `json:"tool_choice"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 1 || out.Tools[0]["type"] != "web_search" {
		t.Fatalf("tools=%v body=%s", out.Tools, body)
	}
	if _, ok := out.Tools[0]["name"]; ok {
		t.Fatalf("server web search was converted to a client function: %v", out.Tools[0])
	}
	if out.ToolChoice != "auto" {
		t.Fatalf("server web search tool_choice=%v want auto", out.ToolChoice)
	}
}

func TestTranslateResponse_FunctionCallToToolUse(t *testing.T) {
	raw := []byte(`{
		"id": "resp_abc123",
		"object": "response",
		"model": "grok-4.5",
		"status": "completed",
		"output": [
			{
				"type": "message",
				"role": "assistant",
				"content": [{"type":"output_text","text":"Let me check."}]
			},
			{
				"type": "function_call",
				"id": "fc_1",
				"call_id": "call_xyz",
				"name": "get_time",
				"arguments": "{\"tz\":\"UTC\"}"
			}
		],
		"usage": {"input_tokens": 10, "output_tokens": 5}
	}`)

	msg, err := TranslateResponse(raw, TranslateRespOptions{RequestModel: "claude-sonnet-4"})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != "message" || msg.Role != "assistant" {
		t.Fatalf("msg meta=%+v", msg)
	}
	if msg.Model != "claude-sonnet-4" {
		t.Fatalf("model=%q want request alias", msg.Model)
	}
	if !strings.HasPrefix(msg.ID, "msg_") {
		t.Fatalf("id=%q", msg.ID)
	}
	if msg.StopReason != "tool_use" {
		t.Fatalf("stop_reason=%q", msg.StopReason)
	}
	if msg.Usage.InputTokens != 10 || msg.Usage.OutputTokens != 5 {
		t.Fatalf("usage=%+v", msg.Usage)
	}
	if len(msg.Content) != 2 {
		t.Fatalf("content=%+v", msg.Content)
	}
	if msg.Content[0].Type != "text" || msg.Content[0].Text != "Let me check." {
		t.Fatalf("text block=%+v", msg.Content[0])
	}
	tu := msg.Content[1]
	if tu.Type != "tool_use" {
		t.Fatalf("type=%q", tu.Type)
	}
	if tu.ID != "call_xyz" {
		t.Fatalf("id=%q", tu.ID)
	}
	if tu.Name != "get_time" {
		t.Fatalf("name=%q", tu.Name)
	}
	var input map[string]any
	if err := json.Unmarshal(tu.Input, &input); err != nil {
		t.Fatal(err)
	}
	if input["tz"] != "UTC" {
		t.Fatalf("input=%v", input)
	}
}

func TestTranslateResponse_ReasoningToThinkingBlock(t *testing.T) {
	raw := []byte(`{
		"id":"resp_thinking",
		"model":"grok-4.5",
		"status":"completed",
		"output":[
			{
				"type":"reasoning",
				"id":"rs_1",
				"summary":[{"type":"summary_text","text":"I should inspect the repository."}],
				"encrypted_content":"enc_reasoning_1"
			},
			{
				"type":"function_call",
				"call_id":"call_1",
				"name":"inspect",
				"arguments":"{}"
			}
		]
	}`)
	msg, err := TranslateResponse(raw, TranslateRespOptions{
		RequestModel: "claude-opus-4-6",
		Thinking: ThinkingBridgeOptions{
			Enabled: true,
			Display: "summarized",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Content) != 2 {
		t.Fatalf("content=%+v", msg.Content)
	}
	thinking := msg.Content[0]
	if thinking.Type != "thinking" ||
		thinking.Thinking == nil ||
		*thinking.Thinking != "I should inspect the repository." ||
		thinking.Signature != "enc_reasoning_1" {
		t.Fatalf("thinking=%+v", thinking)
	}
	if msg.Content[1].Type != "tool_use" || msg.StopReason != "tool_use" {
		t.Fatalf("tool result=%+v stop=%q", msg.Content[1], msg.StopReason)
	}
}

func TestTranslateResponse_OmittedThinkingKeepsSignature(t *testing.T) {
	raw := []byte(`{
		"id":"resp_thinking",
		"output":[{
			"type":"reasoning",
			"summary":[{"type":"summary_text","text":"hidden summary"}],
			"encrypted_content":"enc_reasoning_2"
		}]
	}`)
	msg, err := TranslateResponse(raw, TranslateRespOptions{
		Thinking: ThinkingBridgeOptions{Enabled: true, Display: "omitted"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Content) != 1 {
		t.Fatalf("content=%+v", msg.Content)
	}
	block := msg.Content[0]
	if block.Type != "thinking" ||
		block.Thinking == nil ||
		*block.Thinking != "" ||
		block.Signature != "enc_reasoning_2" {
		t.Fatalf("thinking=%+v", block)
	}
}

func TestErrorTypeMapping(t *testing.T) {
	cases := map[int]string{
		401: "authentication_error",
		400: "invalid_request_error",
		429: "rate_limit_error",
		500: "api_error",
		502: "api_error",
		529: "overloaded_error",
		404: "not_found_error",
	}
	for status, want := range cases {
		if got := ErrorTypeFromStatus(status); got != want {
			t.Errorf("status %d: got %q want %q", status, got, want)
		}
		env := NewErrorEnvelope(status, "boom")
		if env.Type != "error" || env.Error.Type != want || env.Error.Message != "boom" {
			t.Errorf("envelope status %d: %+v", status, env)
		}
	}

	// WriteError body shape
	rr := httptest.NewRecorder()
	WriteError(rr, 429, "slow down")
	if rr.Code != 429 {
		t.Fatalf("code=%d", rr.Code)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Type != "rate_limit_error" {
		t.Fatalf("type=%q", env.Error.Type)
	}
}

func TestModelAliasResolve(t *testing.T) {
	cfg := config.Default()
	// via Config.ResolveModel
	if got := cfg.ResolveModel("claude-sonnet-4"); got != "grok-4.5" {
		t.Fatalf("alias=%q", got)
	}
	if got := cfg.ResolveModel("grok-composer-2.5-fast"); got != "grok-composer-2.5-fast" {
		t.Fatalf("passthrough=%q", got)
	}

	// Handlers.resolve with nil ResolveModel uses Cfg
	h := &Handlers{Cfg: cfg.Anthropic}
	if got := h.resolve("claude-haiku-4"); got != "grok-composer-2.5-fast" {
		t.Fatalf("handler resolve=%q", got)
	}
	if got := h.resolve("claude-opus-4-99-20990101"); got != "claude-opus-4-99-20990101" {
		t.Fatalf("handler guessed unknown future model=%q", got)
	}
	// custom ResolveModel wins
	h.ResolveModel = func(s string) string { return "custom-" + s }
	if got := h.resolve("x"); got != "custom-x" {
		t.Fatalf("custom=%q", got)
	}

	// AliasModels discovery entries start with claude
	entries := AliasModels([]upstream.Model{
		{ID: "grok-4.5", ContextWindow: 500000, APIBackend: "responses"},
	}, cfg.Anthropic)
	if len(entries) == 0 {
		t.Fatal("no alias entries")
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.ID, "claude") {
			t.Fatalf("non-claude id %q", e.ID)
		}
		if e.UpstreamModel == "" {
			t.Fatalf("missing upstream for %q", e.ID)
		}
	}
	// short names like sonnet must not appear
	for _, e := range entries {
		if e.ID == "sonnet" || e.ID == "opus" || e.ID == "haiku" {
			t.Fatalf("short name should not be discovery id: %q", e.ID)
		}
	}
}

func TestStream_MessageStartPrefixNotBufferedDump(t *testing.T) {
	// Mock upstream SSE with delayed deltas.
	upstreamSSE := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_s1","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"Hel"}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"lo"}`,
		``,
		`data: {"type":"response.completed","response":{"id":"resp_s1","model":"grok-4.5","status":"completed","usage":{"input_tokens":3,"output_tokens":2},"output":[{"type":"message","content":[{"type":"output_text","text":"Hello"}]}]}}`,
		``,
	}, "\n")

	h := &Handlers{
		Cfg: config.Default().Anthropic,
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			if !stream {
				t.Error("expected stream=true")
			}
			if model != "grok-4.5" {
				t.Errorf("model=%q", model)
			}
			// Verify translate put function-free simple body
			var probe map[string]any
			_ = json.Unmarshal(body, &probe)
			if probe["model"] != "grok-4.5" {
				t.Errorf("body model=%v", probe["model"])
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(upstreamSSE)),
			}, nil
		},
		ResolveModel: func(s string) string {
			if s == "claude-sonnet-4" {
				return "grok-4.5"
			}
			return s
		},
	}

	reqBody := `{"model":"claude-sonnet-4","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("x-claude-code-session-id", "sess-stream-1")
	rr := httptest.NewRecorder()
	h.HandleMessages(rr, req)

	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type=%q", ct)
	}
	out := rr.Body.String()
	// Must start with message_start (not a single dumped JSON message)
	if !strings.Contains(out, "event: message_start") {
		t.Fatalf("missing message_start event; out prefix=%q", truncate(out, 200))
	}
	// Prefix check: first non-empty content should be message_start, not full message dump
	idxStart := strings.Index(out, "event: message_start")
	idxDelta := strings.Index(out, "event: content_block_delta")
	idxStop := strings.Index(out, "event: message_stop")
	if idxStart < 0 || idxDelta < 0 || idxStop < 0 {
		t.Fatalf("missing events start=%d delta=%d stop=%d out=%s", idxStart, idxDelta, idxStop, out)
	}
	if !(idxStart < idxDelta && idxDelta < idxStop) {
		t.Fatalf("event order wrong: start=%d delta=%d stop=%d", idxStart, idxDelta, idxStop)
	}
	// Not a one-shot JSON dump of Anthropic message
	if strings.HasPrefix(strings.TrimSpace(out), `{"id"`) {
		t.Fatal("looks like non-stream dump")
	}
	if !strings.Contains(out, `"text":"Hel"`) && !strings.Contains(out, `"text":"Hello"`) {
		// At least one delta should carry text
		if !strings.Contains(out, "Hel") {
			t.Fatalf("missing text deltas: %s", out)
		}
	}
}

func TestStreamDoesNotReplayDonePayloads(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_dup","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"Hel"}`,
		``,
		`data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"lo"}`,
		``,
		`data: {"type":"response.content_part.done","item_id":"msg_1","part":{"type":"output_text","text":"Hello"}}`,
		``,
		`data: {"type":"response.output_item.done","item":{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"Hello"}]}}`,
		``,
		`data: {"type":"response.completed","response":{"id":"resp_dup","status":"completed","output":[{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"Hello"}]}]}}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(&out, nil, "claude-sonnet-4")
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), `"type":"text_delta"`); got != 2 {
		t.Fatalf("text deltas=%d output=%s", got, out.String())
	}
	if strings.Contains(out.String(), `"text":"Hello"`) {
		t.Fatalf("done payload was replayed: %s", out.String())
	}
}

func TestStreamParallelToolsKeepDistinctIndexes(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_tools","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_1","call_id":"call_1","type":"function_call","name":"one"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_2","call_id":"call_2","type":"function_call","name":"two"}}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"a\":"}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_2","delta":"{\"b\":2}"}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"1}"}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"a\":1}"}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_2","arguments":"{\"b\":2}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed"}}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(&out, nil, "claude-sonnet-4")
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if strings.Count(body, `"type":"tool_use"`) != 2 {
		t.Fatalf("tool starts were duplicated or missing: %s", body)
	}
	if strings.Count(body, `"partial_json"`) != 3 {
		t.Fatalf("argument deltas were replayed: %s", body)
	}
	if !strings.Contains(body, `"index":0`) || !strings.Contains(body, `"index":1`) {
		t.Fatalf("parallel tools did not receive distinct indexes: %s", body)
	}
	if !strings.Contains(body, `"stop_reason":"tool_use"`) {
		t.Fatalf("missing tool_use stop: %s", body)
	}
}

func TestStreamReasoningBecomesSignedThinkingBeforeTool(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_think","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"rs_1","type":"reasoning","encrypted_content":"enc_early"}}`,
		``,
		`data: {"type":"response.reasoning_summary_part.added","item_id":"rs_1"}`,
		``,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"rs_1","delta":"Need a tool."}`,
		``,
		`data: {"type":"response.reasoning_summary_part.done","item_id":"rs_1"}`,
		``,
		`data: {"type":"response.output_item.done","item":{"id":"rs_1","type":"reasoning","encrypted_content":"enc_final"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_1","call_id":"call_1","type":"function_call","name":"inspect"}}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_1","call_id":"call_1","arguments":"{}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"Need a tool."}],"encrypted_content":"enc_final"},{"id":"fc_1","call_id":"call_1","type":"function_call","name":"inspect","arguments":"{}"}]}}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(
		&out,
		nil,
		"claude-opus-4-6",
		ThinkingBridgeOptions{Enabled: true, Display: "summarized"},
	)
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	thinkingStart := strings.Index(body, `"content_block":{"thinking":"","type":"thinking"}`)
	thinkingDelta := strings.Index(body, `"thinking":"Need a tool.","type":"thinking_delta"`)
	signatureDelta := strings.Index(body, `"signature":"enc_final","type":"signature_delta"`)
	toolStart := strings.Index(body, `"type":"tool_use"`)
	if thinkingStart < 0 || thinkingDelta < 0 || signatureDelta < 0 || toolStart < 0 {
		t.Fatalf("missing thinking/tool events: %s", body)
	}
	if !(thinkingStart < thinkingDelta && thinkingDelta < signatureDelta && signatureDelta < toolStart) {
		t.Fatalf(
			"event order thinking_start=%d thinking_delta=%d signature=%d tool=%d",
			thinkingStart,
			thinkingDelta,
			signatureDelta,
			toolStart,
		)
	}
	if strings.Count(body, `"type":"signature_delta"`) != 1 {
		t.Fatalf("signature replayed from terminal output: %s", body)
	}
}

func TestStreamSignatureOnlyReasoningProducesOmittedThinking(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_sig","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"rs_sig","type":"reasoning","encrypted_content":"enc_sig"}}`,
		``,
		`data: {"type":"response.output_item.done","item":{"id":"rs_sig","type":"reasoning"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_sig","call_id":"call_sig","type":"function_call","name":"inspect"}}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_sig","call_id":"call_sig","arguments":"{}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed"}}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(
		&out,
		nil,
		"claude-opus-4-6",
		ThinkingBridgeOptions{Enabled: true, Display: "omitted"},
	)
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, `"signature":"enc_sig","type":"signature_delta"`) {
		t.Fatalf("missing signature delta: %s", body)
	}
	if strings.Contains(body, `"type":"thinking_delta"`) {
		t.Fatalf("omitted thinking must not expose summary deltas: %s", body)
	}
	if strings.Index(body, `"type":"signature_delta"`) > strings.Index(body, `"type":"tool_use"`) {
		t.Fatalf("thinking signature must precede tool use: %s", body)
	}
}

func TestStreamFailureIsTerminalWithoutMessageStop(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_fail","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.failed","response":{"error":{"message":"upstream exploded"}}}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(&out, nil, "claude-sonnet-4")
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "event: error") {
		t.Fatalf("missing error event: %s", out.String())
	}
	if strings.Contains(out.String(), "event: message_stop") {
		t.Fatalf("failed stream must not end normally: %s", out.String())
	}
}

func TestStreamUnexpectedEOFFails(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_cut","model":"grok-4.5"}}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"partial"}`,
		``,
	}, "\n")
	var out bytes.Buffer
	tr := NewStreamTranslator(&out, nil, "claude-sonnet-4")
	if err := PipeResponsesSSE(strings.NewReader(sse), tr); err == nil {
		t.Fatal("truncated stream must fail")
	}
	if strings.Contains(out.String(), "event: message_stop") {
		t.Fatalf("truncated stream must not synthesize success: %s", out.String())
	}
}

func TestHandleCountTokens_Disabled404(t *testing.T) {
	h := &Handlers{Cfg: config.AnthropicConfig{CountTokens: false}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{}`))
	h.HandleCountTokens(rr, req)
	if rr.Code != 404 {
		t.Fatalf("code=%d", rr.Code)
	}
	var env ErrorEnvelope
	_ = json.Unmarshal(rr.Body.Bytes(), &env)
	if env.Error.Type != "not_found_error" {
		t.Fatalf("type=%q", env.Error.Type)
	}
}

func TestHandleMessagesHonorsConfiguredBodyLimit(t *testing.T) {
	h := &Handlers{
		MaxBody: 2,
		Post: func(context.Context, string, string, []byte, bool) (*http.Response, error) {
			t.Fatal("upstream must not be called")
			return nil, nil
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`+"x"))
	h.HandleMessages(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNoCredentialUsesServiceUnavailable(t *testing.T) {
	h := &Handlers{
		Post: func(context.Context, string, string, []byte, bool) (*http.Response, error) {
			return nil, lb.ErrNoCredential
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4",
		"max_tokens":16,
		"messages":[{"role":"user","content":"hello"}]
	}`))
	rr := httptest.NewRecorder()
	h.HandleMessages(rr, req)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d headers=%v body=%s", rr.Code, rr.Header(), rr.Body.String())
	}
}

func TestCopyUpstreamHeadersPreservesLocalRequestID(t *testing.T) {
	dst := make(http.Header)
	dst.Set("X-Request-Id", "local-request")
	src := make(http.Header)
	src.Set("X-Request-Id", "upstream-request")
	copyAnthropicUpstreamHeaders(dst, src)
	if dst.Get("X-Request-Id") != "local-request" {
		t.Fatalf("local request id overwritten: %v", dst)
	}
	if dst.Get("X-Upstream-Request-Id") != "upstream-request" {
		t.Fatalf("upstream request id missing: %v", dst)
	}
}

func TestHandleMessages_NonStream(t *testing.T) {
	up := `{
		"id":"resp_n1",
		"model":"grok-4.5",
		"status":"completed",
		"output":[{"type":"message","content":[{"type":"output_text","text":"hi there"}]}],
		"usage":{"input_tokens":1,"output_tokens":2}
	}`
	h := &Handlers{
		Cfg: config.Default().Anthropic,
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			if stream {
				t.Error("expected non-stream")
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(up)),
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(
		`{"model":"claude-sonnet-4","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"stream":false}`,
	))
	rr := httptest.NewRecorder()
	h.HandleMessages(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	var msg MessageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.StopReason != "end_turn" {
		t.Fatalf("stop=%q", msg.StopReason)
	}
	if len(msg.Content) != 1 || msg.Content[0].Text != "hi there" {
		t.Fatalf("content=%+v", msg.Content)
	}
	if msg.Model != "claude-sonnet-4" {
		t.Fatalf("model=%q", msg.Model)
	}
}

func TestSessionIDFromHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("x-claude-code-session-id", "sess-xyz")
	if got := sessionIDFromRequest(req); got != "sess-xyz" {
		t.Fatalf("got %q", got)
	}
}

func TestHandleMessagesRejectsOversizedSessionID(t *testing.T) {
	called := false
	h := &Handlers{
		Cfg: config.Default().Anthropic,
		Post: func(context.Context, string, string, []byte, bool) (*http.Response, error) {
			called = true
			return nil, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4","max_tokens":16,"messages":[{"role":"user","content":"hi"}]
	}`))
	req.Header.Set("x-claude-code-session-id", strings.Repeat("x", 513))
	rr := httptest.NewRecorder()
	h.HandleMessages(rr, req)
	if rr.Code != http.StatusBadRequest || called {
		t.Fatalf("status=%d called=%v body=%s", rr.Code, called, rr.Body.String())
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
