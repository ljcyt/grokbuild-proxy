package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
)

func TestSanitizeResponses_PreserveReasoningAndAggregateSystem(t *testing.T) {
	raw := []byte(`{
		"model": "grok-4.5",
		"instructions": "base",
		"input": [
			{"type":"message","role":"system","content":"be helpful"},
			{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"ciphertext","status":"completed"},
			{"type":"message","role":"user","content":"hi"},
			{"type":"message","role":"developer","content":"dev note"}
		],
		"response_format": {"type":"json_object"},
		"reasoning": {"effort":"minimal"},
		"max_tokens": 128
	}`)

	res, err := SanitizeResponses(raw, "conv-abc")
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if res.Model != "grok-4.5" {
		t.Fatalf("model=%q", res.Model)
	}
	if res.ConvID != "conv-abc" {
		t.Fatalf("conv=%q", res.ConvID)
	}
	if asString(res.Body["prompt_cache_key"]) != "conv-abc" {
		t.Fatalf("prompt_cache_key=%v", res.Body["prompt_cache_key"])
	}
	inst := asString(res.Body["instructions"])
	if !strings.Contains(inst, "base") || !strings.Contains(inst, "be helpful") || !strings.Contains(inst, "dev note") {
		t.Fatalf("instructions=%q", inst)
	}
	input, ok := res.Body["input"].([]any)
	if !ok || len(input) != 2 {
		t.Fatalf("input=%v", res.Body["input"])
	}
	reasoningItem := input[0].(map[string]any)
	if asString(reasoningItem["type"]) != "reasoning" ||
		asString(reasoningItem["id"]) != "rs_1" ||
		asString(reasoningItem["encrypted_content"]) != "ciphertext" {
		t.Fatalf("reasoning item changed=%v", reasoningItem)
	}
	userItem := input[1].(map[string]any)
	if asString(userItem["role"]) != "user" {
		t.Fatalf("remaining user item=%v", userItem)
	}
	if _, has := res.Body["response_format"]; has {
		t.Fatalf("response_format should be removed")
	}
	text, ok := res.Body["text"].(map[string]any)
	if !ok {
		t.Fatalf("text missing: %v", res.Body["text"])
	}
	format, _ := text["format"].(map[string]any)
	if asString(format["type"]) != "json_object" {
		t.Fatalf("format=%v", text["format"])
	}
	reasoning, _ := res.Body["reasoning"].(map[string]any)
	if asString(reasoning["effort"]) != "low" {
		t.Fatalf("effort=%v", reasoning["effort"])
	}
	if _, has := res.Body["max_tokens"]; has {
		t.Fatalf("max_tokens should be remapped")
	}
	if v, _ := asInt64(res.Body["max_output_tokens"]); v != 128 {
		t.Fatalf("max_output_tokens=%v", res.Body["max_output_tokens"])
	}
}

func TestSanitizeResponsesRejectsOversizedPromptCacheKey(t *testing.T) {
	oversized := strings.Repeat("x", MaxPromptCacheKeyBytes+1)
	raw, err := json.Marshal(map[string]any{"model": "grok-4.5", "input": "hi", "prompt_cache_key": oversized})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SanitizeResponses(raw, ""); err == nil || !strings.Contains(err.Error(), "prompt_cache_key") {
		t.Fatalf("err=%v", err)
	}
	if _, err := SanitizeResponses([]byte(`{"model":"grok-4.5","input":"hi"}`), oversized); err == nil {
		t.Fatal("oversized header-derived conversation id was accepted")
	}
}

func TestSanitizeResponses_ReasoningEffortAlias(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantEffort string
		wantError  bool
	}{
		{
			name:       "flat canonicalized",
			raw:        `{"reasoning_effort":" Medium "}`,
			wantEffort: "medium",
		},
		{
			name:       "equal forms accepted",
			raw:        `{"reasoning":{"effort":"high"},"reasoning_effort":"HIGH"}`,
			wantEffort: "high",
		},
		{
			name:       "minimal equals low",
			raw:        `{"reasoning":{"effort":"minimal"},"reasoning_effort":"low"}`,
			wantEffort: "low",
		},
		{
			name:      "conflict rejected",
			raw:       `{"reasoning":{"effort":"low"},"reasoning_effort":"high"}`,
			wantError: true,
		},
		{
			name:      "reasoning must be object",
			raw:       `{"reasoning":"high"}`,
			wantError: true,
		},
		{
			name:      "effort must be string",
			raw:       `{"reasoning":{"effort":3}}`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SanitizeResponses([]byte(tc.raw), "")
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			reasoning, _ := res.Body["reasoning"].(map[string]any)
			if asString(reasoning["effort"]) != tc.wantEffort {
				t.Fatalf("reasoning=%v", reasoning)
			}
			if _, ok := res.Body["reasoning_effort"]; ok {
				t.Fatalf("flat alias not removed: %v", res.Body)
			}
		})
	}
}

func TestSanitizeResponses_PreservesReasoningToolOrder(t *testing.T) {
	raw := []byte(`{
		"model":"grok-4.5",
		"input":[
			{"type":"message","role":"user","content":"inspect both"},
			{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"ciphertext"},
			{"type":"function_call","call_id":"call_a","name":"read_a","arguments":"{}"},
			{"type":"function_call","call_id":"call_b","name":"read_b","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_a","output":"A"},
			{"type":"function_call_output","call_id":"call_b","output":"B"}
		]
	}`)
	res, err := SanitizeResponses(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	input, ok := res.Body["input"].([]any)
	if !ok || len(input) != 6 {
		t.Fatalf("input=%v", res.Body["input"])
	}
	wantTypes := []string{
		"message",
		"reasoning",
		"function_call",
		"function_call",
		"function_call_output",
		"function_call_output",
	}
	wantCalls := []string{"", "", "call_a", "call_b", "call_a", "call_b"}
	for i := range input {
		item, _ := input[i].(map[string]any)
		if got := asString(item["type"]); got != wantTypes[i] {
			t.Fatalf("item %d type=%q want=%q input=%v", i, got, wantTypes[i], input)
		}
		if got := asString(item["call_id"]); got != wantCalls[i] {
			t.Fatalf("item %d call_id=%q want=%q input=%v", i, got, wantCalls[i], input)
		}
	}
}

func TestSanitizeResponses_KeepsExistingPromptCacheKey(t *testing.T) {
	raw := []byte(`{"model":"m","prompt_cache_key":"keep-me","input":"hi"}`)
	res, err := SanitizeResponses(raw, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if asString(res.Body["prompt_cache_key"]) != "keep-me" {
		t.Fatalf("got %v", res.Body["prompt_cache_key"])
	}
	if res.ConvID != "keep-me" {
		t.Fatalf("conv %q", res.ConvID)
	}
}

func TestSanitizeResponses_ExpandsChatJSONSchema(t *testing.T) {
	res, err := SanitizeResponses([]byte(`{
		"model":"m",
		"input":"x",
		"response_format":{
			"type":"json_schema",
			"json_schema":{"name":"answer","schema":{"type":"object"},"strict":true}
		}
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	text := res.Body["text"].(map[string]any)
	format := text["format"].(map[string]any)
	if asString(format["type"]) != "json_schema" || asString(format["name"]) != "answer" {
		t.Fatalf("format=%v", format)
	}
	if _, nested := format["json_schema"]; nested {
		t.Fatalf("json_schema must be flattened for Responses: %v", format)
	}
}

func TestCopyUpstreamHeadersPreservesLocalRequestID(t *testing.T) {
	dst := make(http.Header)
	dst.Set("X-Request-Id", "local-request")
	src := make(http.Header)
	src.Set("X-Request-Id", "upstream-request")
	copyUpstreamResponseHeaders(dst, src)
	if dst.Get("X-Request-Id") != "local-request" {
		t.Fatalf("local request id overwritten: %v", dst)
	}
	if dst.Get("X-Upstream-Request-Id") != "upstream-request" {
		t.Fatalf("upstream request id missing: %v", dst)
	}
}

func TestNoCredentialUsesServiceUnavailable(t *testing.T) {
	h := &Handlers{
		Post: func(context.Context, string, string, []byte, bool) (*http.Response, error) {
			return nil, lb.ErrNoCredential
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{
		"model":"grok-4.5",
		"input":"hello"
	}`))
	rr := httptest.NewRecorder()
	h.HandleResponses(rr, req)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d headers=%v body=%s", rr.Code, rr.Header(), rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "credential_pool_unavailable") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestChatToResponses_Table(t *testing.T) {
	maxTok := 64
	temp := 0.2
	tests := []struct {
		name  string
		in    string
		check func(t *testing.T, body map[string]any)
	}{
		{
			name: "basic messages",
			in: `{
				"model":"grok-4.5",
				"messages":[
					{"role":"system","content":"sys"},
					{"role":"user","content":"hello"}
				],
				"max_tokens": 64,
				"temperature": 0.2
			}`,
			check: func(t *testing.T, body map[string]any) {
				if asString(body["model"]) != "grok-4.5" {
					t.Fatalf("model %v", body["model"])
				}
				if asString(body["instructions"]) != "sys" {
					t.Fatalf("instructions %v", body["instructions"])
				}
				input, _ := body["input"].([]any)
				if len(input) != 1 {
					t.Fatalf("input len %d", len(input))
				}
				if v, _ := asInt64(body["max_output_tokens"]); v != int64(maxTok) {
					t.Fatalf("max_output_tokens %v", body["max_output_tokens"])
				}
				if body["temperature"] != temp && asString(body["temperature"]) != "0.2" {
					// json number may be float64 0.2
					if f, ok := body["temperature"].(float64); !ok || f != temp {
						t.Fatalf("temperature %v", body["temperature"])
					}
				}
			},
		},
		{
			name: "tools and tool_choice",
			in: `{
				"model":"m",
				"messages":[{"role":"user","content":"use tool"}],
				"tools":[{
					"type":"function",
					"function":{
						"name":"get_weather",
						"description":"weather",
						"parameters":{"type":"object","properties":{"city":{"type":"string"}}}
					}
				}],
				"tool_choice":{"type":"function","function":{"name":"get_weather"}}
			}`,
			check: func(t *testing.T, body map[string]any) {
				tools, _ := body["tools"].([]any)
				if len(tools) != 1 {
					t.Fatalf("tools %v", body["tools"])
				}
				tool := tools[0].(map[string]any)
				if asString(tool["name"]) != "get_weather" {
					t.Fatalf("tool %v", tool)
				}
				tc, _ := body["tool_choice"].(map[string]any)
				if asString(tc["name"]) != "get_weather" {
					t.Fatalf("tool_choice %v", body["tool_choice"])
				}
			},
		},
		{
			name: "assistant tool_calls and tool result",
			in: `{
				"model":"m",
				"messages":[
					{"role":"user","content":"q"},
					{"role":"assistant","content":null,"tool_calls":[
						{"id":"call_1","type":"function","function":{"name":"fn","arguments":"{\"a\":1}"}}
					]},
					{"role":"tool","tool_call_id":"call_1","content":"result"}
				]
			}`,
			check: func(t *testing.T, body map[string]any) {
				input, _ := body["input"].([]any)
				if len(input) != 3 {
					t.Fatalf("input len=%d val=%v", len(input), input)
				}
				fc := input[1].(map[string]any)
				if asString(fc["type"]) != "function_call" || asString(fc["name"]) != "fn" {
					t.Fatalf("fc %v", fc)
				}
				out := input[2].(map[string]any)
				if asString(out["type"]) != "function_call_output" || asString(out["output"]) != "result" {
					t.Fatalf("out %v", out)
				}
			},
		},
		{
			name: "multipart content",
			in: `{
				"model":"m",
				"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]
			}`,
			check: func(t *testing.T, body map[string]any) {
				input, _ := body["input"].([]any)
				item := input[0].(map[string]any)
				if asString(item["content"]) != "a\nb" {
					t.Fatalf("content %v", item["content"])
				}
			},
		},
		{
			name: "image content",
			in: `{
				"model":"m",
				"messages":[{"role":"user","content":[
					{"type":"text","text":"describe"},
					{"type":"image_url","image_url":{"url":"https://example.invalid/image.png","detail":"low"}}
				]}]
			}`,
			check: func(t *testing.T, body map[string]any) {
				input := body["input"].([]any)
				item := input[0].(map[string]any)
				parts := item["content"].([]any)
				if len(parts) != 2 || asString(parts[1].(map[string]any)["type"]) != "input_image" {
					t.Fatalf("content=%v", item["content"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := ChatToResponses([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			// also ensure sanitize succeeds
			if _, err := SanitizeResponses(body, "c1"); err != nil {
				t.Fatalf("sanitize after convert: %v", err)
			}
			tc.check(t, body)
		})
	}
}

func TestChatToResponsesRejectsSemanticLoss(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","messages":[],"n":2}`,
		`{"model":"m","messages":[],"logprobs":true}`,
		`{"model":"m","messages":[],"modalities":["audio"]}`,
		`{"model":"m","messages":[],"stop":["END"]}`,
	} {
		if _, err := ChatToResponses([]byte(body)); err == nil {
			t.Fatalf("expected unsupported field error for %s", body)
		}
	}
}

func TestChatToResponsesRequiresMessages(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"model":"grok-4.5"}`,
		`{"model":"grok-4.5","messages":null}`,
	} {
		if _, err := ChatToResponses([]byte(raw)); err == nil || !strings.Contains(err.Error(), "missing field `messages`") {
			t.Fatalf("raw=%s error=%v", raw, err)
		}
	}
	if _, err := ChatToResponses([]byte(`{"model":"grok-4.5","messages":[]}`)); err == nil || !strings.Contains(err.Error(), "messages must not be empty") {
		t.Fatalf("empty messages error=%v", err)
	}
}

func TestResponsesToChat_TextAndTools(t *testing.T) {
	raw := []byte(`{
		"id":"resp_1",
		"model":"grok-4.5",
		"created_at": 1700000000,
		"status":"completed",
		"output":[
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]},
			{"type":"function_call","id":"call_9","call_id":"call_9","name":"lookup","arguments":"{\"q\":\"x\"}"}
		],
		"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}
	}`)
	out, err := ResponsesToChat(raw)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if asString(m["object"]) != "chat.completion" {
		t.Fatalf("object %v", m["object"])
	}
	choices := m["choices"].([]any)
	c0 := choices[0].(map[string]any)
	msg := c0["message"].(map[string]any)
	if asString(msg["content"]) != "hello" {
		t.Fatalf("content %v", msg["content"])
	}
	if asString(c0["finish_reason"]) != "tool_calls" {
		t.Fatalf("finish %v", c0["finish_reason"])
	}
	tcs := msg["tool_calls"].([]any)
	tc0 := tcs[0].(map[string]any)
	fn := tc0["function"].(map[string]any)
	if asString(fn["name"]) != "lookup" {
		t.Fatalf("tool %v", tc0)
	}
	usage := m["usage"].(map[string]any)
	if v, _ := asInt64(usage["prompt_tokens"]); v != 10 {
		t.Fatalf("usage %v", usage)
	}
}

func TestHandleResponses_NonStream(t *testing.T) {
	fixed := []byte(`{"id":"resp_ok","model":"grok-4.5-build-free","output":[],"status":"completed"}`)
	h := &Handlers{
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			if stream {
				t.Fatalf("expected non-stream")
			}
			if model != "grok-4.5" {
				t.Fatalf("model %q", model)
			}
			if convID != "sticky-1" {
				t.Fatalf("conv %q", convID)
			}
			var obj map[string]any
			if err := json.Unmarshal(body, &obj); err != nil {
				t.Fatal(err)
			}
			if asString(obj["prompt_cache_key"]) != "sticky-1" {
				t.Fatalf("body pck %v", obj["prompt_cache_key"])
			}
			// system should be folded
			if asString(obj["instructions"]) == "" {
				t.Fatalf("expected instructions, body=%s", body)
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(fixed)),
			}, nil
		},
	}

	reqBody := `{"model":"grok-4.5","input":[{"role":"system","content":"s"},{"role":"user","content":"u"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(reqBody))
	req.Header.Set("X-Grok-Conv-Id", "sticky-1")
	rr := httptest.NewRecorder()
	h.HandleResponses(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"resp_ok"`)) {
		t.Fatalf("body %s", rr.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if got := asString(response["model"]); got != "grok-4.5" {
		t.Fatalf("response model=%q", got)
	}
}

func TestHandleResponses_ResolvesConfiguredAlias(t *testing.T) {
	var posted map[string]any
	h := &Handlers{
		ResolveModel: func(model string) string {
			if model == "claude-sonnet-4" {
				return "grok-4.5"
			}
			return model
		},
		Post: func(_ context.Context, model, _ string, body []byte, _ bool) (*http.Response, error) {
			if model != "grok-4.5" {
				t.Fatalf("upstream model=%q", model)
			}
			if err := json.Unmarshal(body, &posted); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"id":"resp_alias","model":"grok-4.5","output":[]}`)),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"claude-sonnet-4","input":"hello"}`))
	rr := httptest.NewRecorder()
	h.HandleResponses(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := asString(posted["model"]); got != "grok-4.5" {
		t.Fatalf("body model=%q", got)
	}
}

func TestHandleResponses_StreamFlush(t *testing.T) {
	sse := "data: {\"type\":\"response.created\",\"response\":{\"model\":\"grok-4.5-build-free\"}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\ndata: [DONE]\n\n"
	h := &Handlers{
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			if !stream {
				t.Fatalf("expected stream")
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(sse)),
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m","stream":true,"input":"x"}`))
	rr := httptest.NewRecorder()
	h.HandleResponses(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("ct %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "response.output_text.delta") {
		t.Fatalf("body %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "grok-4.5-build-free") || !strings.Contains(rr.Body.String(), `"model":"m"`) {
		t.Fatalf("stream model was not normalized: %s", rr.Body.String())
	}
}

func TestHandleResponses_UpstreamError(t *testing.T) {
	h := &Handlers{
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			return &http.Response{
				StatusCode: 429,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"slow down","type":"rate_limit_error","code":"rate_limit"}}`)),
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m","input":"x"}`))
	rr := httptest.NewRecorder()
	h.HandleResponses(rr, req)
	if rr.Code != 429 {
		t.Fatalf("status %d", rr.Code)
	}
	var eb ErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
		t.Fatal(err)
	}
	if eb.Error.Message != "slow down" {
		t.Fatalf("err %v", eb)
	}
}

func TestHandleChatCompletions_NonStream(t *testing.T) {
	up := []byte(`{
		"id":"resp_chat",
		"model":"grok-4.5-build-free",
		"created_at": 1700000001,
		"output":[{"type":"message","content":[{"type":"output_text","text":"pong"}]}],
		"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}
	}`)
	var gotBody []byte
	h := &Handlers{
		Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
			gotBody = append([]byte(nil), body...)
			if stream {
				t.Fatalf("non-stream expected")
			}
			if model != "grok-4.5" {
				t.Fatalf("model %q", model)
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(up)),
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{
		"model":"grok-4.5",
		"messages":[{"role":"system","content":"s"},{"role":"user","content":"ping"}],
		"max_tokens": 10
	}`))
	rr := httptest.NewRecorder()
	h.HandleChatCompletions(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var chat map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &chat); err != nil {
		t.Fatal(err)
	}
	if asString(chat["object"]) != "chat.completion" {
		t.Fatalf("object %v", chat["object"])
	}
	if got := asString(chat["model"]); got != "grok-4.5" {
		t.Fatalf("chat response model=%q", got)
	}
	choices := chat["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if asString(msg["content"]) != "pong" {
		t.Fatalf("content %v", msg["content"])
	}

	// posted body should be responses-shaped
	var posted map[string]any
	if err := json.Unmarshal(gotBody, &posted); err != nil {
		t.Fatal(err)
	}
	if asString(posted["instructions"]) != "s" {
		t.Fatalf("posted instructions %v body=%s", posted["instructions"], gotBody)
	}
	if _, has := posted["messages"]; has {
		t.Fatalf("messages should not remain: %s", gotBody)
	}
	if v, _ := asInt64(posted["max_output_tokens"]); v != 10 {
		t.Fatalf("max_output_tokens %v", posted["max_output_tokens"])
	}
}

func TestHandleChatCompletions_ResolvesConfiguredAlias(t *testing.T) {
	var posted map[string]any
	h := &Handlers{
		ResolveModel: func(model string) string {
			if model == "haiku" {
				return "grok-4.5"
			}
			return model
		},
		Post: func(_ context.Context, model, _ string, body []byte, _ bool) (*http.Response, error) {
			if model != "grok-4.5" {
				t.Fatalf("upstream model=%q", model)
			}
			if err := json.Unmarshal(body, &posted); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{
					"id":"resp_alias","model":"grok-4.5","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}]
				}`)),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"haiku","messages":[{"role":"user","content":"hello"}]}`))
	rr := httptest.NewRecorder()
	h.HandleChatCompletions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := asString(posted["model"]); got != "grok-4.5" {
		t.Fatalf("body model=%q", got)
	}
}

func TestHandleChatCompletions_StreamParallelToolsAndUsage(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_chat_stream","model":"grok-4.5-build-free","created_at":1700000002}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_1","call_id":"call_1","type":"function_call","name":"one"}}`,
		``,
		`data: {"type":"response.output_item.added","item":{"id":"fc_2","call_id":"call_2","type":"function_call","name":"two"}}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"a\":1}"}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_2","delta":"{\"b\":2}"}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"a\":1}"}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_2","arguments":"{\"b\":2}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":3,"output_tokens":4}}}`,
		``,
	}, "\n")
	h := &Handlers{Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse)),
		}, nil
	}}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{
		"model":"grok-4.5",
		"messages":[{"role":"user","content":"tools"}],
		"stream":true,
		"stream_options":{"include_usage":true}
	}`))
	rr := httptest.NewRecorder()
	h.HandleChatCompletions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"created":1700000002`) {
		t.Fatalf("missing created: %s", body)
	}
	if !strings.Contains(body, `"index":0`) || !strings.Contains(body, `"index":1`) {
		t.Fatalf("missing distinct tool indexes: %s", body)
	}
	if strings.Count(body, `{\"a\":1}`) != 1 || strings.Count(body, `{\"b\":2}`) != 1 {
		t.Fatalf("tool arguments duplicated: %s", body)
	}
	if !strings.Contains(body, `"finish_reason":"tool_calls"`) {
		t.Fatalf("wrong finish reason: %s", body)
	}
	if !strings.Contains(body, `"choices":[]`) || !strings.Contains(body, `"prompt_tokens":3`) {
		t.Fatalf("missing usage terminal chunk: %s", body)
	}
	if !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("missing DONE: %s", body)
	}
	if strings.Contains(body, "grok-4.5-build-free") || !strings.Contains(body, `"model":"grok-4.5"`) {
		t.Fatalf("stream response model=%s", body)
	}
}

func TestHandleChatCompletions_TruncatedStreamIsError(t *testing.T) {
	sse := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
	h := &Handlers{Post: func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse)),
		}, nil
	}}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(
		`{"model":"grok-4.5","messages":[{"role":"user","content":"x"}],"stream":true}`,
	))
	rr := httptest.NewRecorder()
	h.HandleChatCompletions(rr, req)
	if !strings.Contains(rr.Body.String(), `"code":"upstream_stream_truncated"`) {
		t.Fatalf("truncation was not surfaced: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"finish_reason":"stop"`) {
		t.Fatalf("truncation was reported as success: %s", rr.Body.String())
	}
}

func TestWriteErrorShape(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteError(rr, 400, "bad", "invalid_request_error", "invalid_body")
	var eb ErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
		t.Fatal(err)
	}
	if eb.Error.Message != "bad" || eb.Error.Type != "invalid_request_error" {
		t.Fatalf("%+v", eb)
	}
	if eb.Error.Code == nil || *eb.Error.Code != "invalid_body" {
		t.Fatalf("code %+v", eb.Error.Code)
	}
}
