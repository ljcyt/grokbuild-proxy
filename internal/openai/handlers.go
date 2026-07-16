package openai

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/promptcache"
	"github.com/GreyGunG/grokbuild-proxy/internal/requestidentity"
)

// HandleResponses serves POST /v1/responses.
// It sanitizes the body, calls the injected Post func, and proxies stream/non-stream.
func (h *Handlers) HandleResponses(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Post == nil {
		WriteError(w, http.StatusInternalServerError, "responses handler not configured", "server_error", "not_configured")
		return
	}
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}

	raw, err := h.readBody(r)
	if err != nil {
		if err == errBodyTooLarge {
			WriteError(w, http.StatusRequestEntityTooLarge, "request body too large", "invalid_request_error", "body_too_large")
			return
		}
		WriteError(w, http.StatusBadRequest, "failed to read body: "+err.Error(), "invalid_request_error", "invalid_body")
		return
	}

	convHint := convIDFromRequest(r, extractBodyConvID(raw))
	res, err := SanitizeResponses(raw, convHint)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_body")
		return
	}
	requestedModel := res.Model
	resolvedModel := h.resolve(requestedModel)
	res.Body["model"] = resolvedModel
	sanitized, err := marshalBody(res.Body)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to encode request", "server_error", "encode_error")
		return
	}
	sanitized, cacheKey, err := promptcache.Apply(sanitized, requestidentity.ClientID(r.Context()), resolvedModel, res.ConvID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to derive prompt cache key", "server_error", "prompt_cache_error")
		return
	}
	if cacheKey != "" {
		res.ConvID = cacheKey
	}

	resp, err := h.Post(r.Context(), resolvedModel, res.ConvID, sanitized, res.Stream)
	if err != nil {
		writePostError(w, err)
		return
	}
	if resp == nil {
		WriteError(w, http.StatusBadGateway, "upstream returned nil response", "server_error", "upstream_error")
		return
	}

	if res.Stream || isSSEContentType(resp.Header.Get("Content-Type")) {
		streamUpstreamSSE(w, resp, requestedModel, h.ObserveUsage)
		return
	}
	proxyUpstreamJSON(w, resp, requestedModel, h.ObserveUsage)
}

// HandleResponsesCompact serves POST /v1/responses/compact. It shares request
// sanitization and model alias handling with Responses, but rejects streaming
// because the upstream compact endpoint only returns a JSON result.
func (h *Handlers) HandleResponsesCompact(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.PostCompact == nil {
		WriteError(w, http.StatusNotImplemented, "responses compact is not configured", "server_error", "not_configured")
		return
	}
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	raw, err := h.readBody(r)
	if err != nil {
		if err == errBodyTooLarge {
			WriteError(w, http.StatusRequestEntityTooLarge, "request body too large", "invalid_request_error", "body_too_large")
			return
		}
		WriteError(w, http.StatusBadRequest, "failed to read body: "+err.Error(), "invalid_request_error", "invalid_body")
		return
	}
	convHint := convIDFromRequest(r, extractBodyConvID(raw))
	res, err := SanitizeResponses(raw, convHint)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_body")
		return
	}
	if res.Stream {
		WriteError(w, http.StatusBadRequest, "responses/compact does not support streaming", "invalid_request_error", "stream_not_supported")
		return
	}
	requestedModel := res.Model
	resolvedModel := h.resolve(requestedModel)
	res.Body["model"] = resolvedModel
	sanitized, err := marshalBody(res.Body)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to encode request", "server_error", "encode_error")
		return
	}
	sanitized, cacheKey, err := promptcache.Apply(sanitized, requestidentity.ClientID(r.Context()), resolvedModel, res.ConvID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to derive prompt cache key", "server_error", "prompt_cache_error")
		return
	}
	if cacheKey != "" {
		res.ConvID = cacheKey
	}
	resp, err := h.PostCompact(r.Context(), resolvedModel, res.ConvID, sanitized, false)
	if err != nil {
		writePostError(w, err)
		return
	}
	if resp == nil {
		WriteError(w, http.StatusBadGateway, "upstream returned nil response", "server_error", "upstream_error")
		return
	}
	proxyUpstreamJSON(w, resp, requestedModel, h.ObserveUsage)
}

// HandleChatCompletions serves POST /v1/chat/completions.
// Converts chat → Responses, posts upstream, converts non-stream Responses → chat.completion.
// Stream chat is best-effort: converts output_text.delta events when possible.
func (h *Handlers) HandleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Post == nil {
		WriteError(w, http.StatusInternalServerError, "chat handler not configured", "server_error", "not_configured")
		return
	}
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}

	raw, err := h.readBody(r)
	if err != nil {
		if err == errBodyTooLarge {
			WriteError(w, http.StatusRequestEntityTooLarge, "request body too large", "invalid_request_error", "body_too_large")
			return
		}
		WriteError(w, http.StatusBadRequest, "failed to read body: "+err.Error(), "invalid_request_error", "invalid_body")
		return
	}

	body, err := ChatToResponses(raw)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_body")
		return
	}

	convHint := convIDFromRequest(r, extractBodyConvID(raw))
	sanitizedRes, err := SanitizeResponses(body, convHint)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_body")
		return
	}
	requestedModel := sanitizedRes.Model
	stream := sanitizedRes.Stream
	model := h.resolve(requestedModel)
	sanitizedRes.Body["model"] = model
	sanitized, err := marshalBody(sanitizedRes.Body)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to encode request", "server_error", "encode_error")
		return
	}
	convID := sanitizedRes.ConvID
	if convID == "" {
		convID = convHint
	}
	sanitized, cacheKey, err := promptcache.Apply(sanitized, requestidentity.ClientID(r.Context()), model, convID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to derive prompt cache key", "server_error", "prompt_cache_error")
		return
	}
	if cacheKey != "" {
		convID = cacheKey
	}

	resp, err := h.Post(r.Context(), model, convID, sanitized, stream)
	if err != nil {
		writePostError(w, err)
		return
	}
	if resp == nil {
		WriteError(w, http.StatusBadGateway, "upstream returned nil response", "server_error", "upstream_error")
		return
	}
	copyUpstreamResponseHeaders(w.Header(), resp.Header)

	if stream {
		handleChatStream(w, resp, chatStreamIncludesUsage(raw), requestedModel)
		return
	}

	defer resp.Body.Close()
	upRaw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		WriteError(w, http.StatusBadGateway, "failed to read upstream response", "server_error", "upstream_read_error")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		MapUpstreamError(w, resp.StatusCode, upRaw)
		return
	}
	if h.ObserveUsage != nil {
		input, cached, output, reasoning := responseUsage(upRaw)
		h.ObserveUsage(input, cached, output, reasoning)
	}
	chatRaw, err := ResponsesToChatWithModel(upRaw, requestedModel)
	if err != nil {
		writeJSON(w, resp.StatusCode, upRaw)
		return
	}
	writeJSON(w, http.StatusOK, chatRaw)
}

func writePostError(w http.ResponseWriter, err error) {
	if errors.Is(err, lb.ErrNoCredential) {
		w.Header().Set("Retry-After", "1")
		WriteError(
			w,
			http.StatusServiceUnavailable,
			"no usable upstream credentials",
			"server_error",
			"credential_pool_unavailable",
		)
		return
	}
	WriteError(w, http.StatusBadGateway, "upstream request failed: "+err.Error(), "server_error", "upstream_error")
}

func handleChatStream(w http.ResponseWriter, resp *http.Response, includeUsage bool, requestedModel string) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		MapUpstreamError(w, resp.StatusCode, raw)
		return
	}

	if !isSSEContentType(resp.Header.Get("Content-Type")) {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			WriteError(w, http.StatusBadGateway, "failed to read upstream response", "server_error", "upstream_read_error")
			return
		}
		chatRaw, err := ResponsesToChatWithModel(raw, requestedModel)
		if err != nil {
			WriteError(w, http.StatusNotImplemented, "chat stream conversion not available for this upstream response", "server_error", "stream_not_supported")
			return
		}
		writeChatSSEFromCompletion(w, chatRaw)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	translator := newChatStreamTranslator(includeUsage, requestedModel)
	var processErr error
	scanErr := scanSSEDataLines(resp.Body, func(data []byte) bool {
		chunks, err := translator.process(data)
		if err != nil {
			processErr = err
			return false
		}
		for _, chunk := range chunks {
			raw, err := json.Marshal(chunk)
			if err != nil {
				processErr = err
				return false
			}
			if _, err := w.Write(append(append([]byte("data: "), raw...), '\n', '\n')); err != nil {
				processErr = err
				return false
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		return true
	})

	if !translator.terminal {
		message := "upstream stream ended before a terminal event"
		if processErr != nil {
			message = processErr.Error()
		} else if scanErr != nil {
			message = scanErr.Error()
		}
		translator.terminal = true
		translator.failed = true
		raw, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": message,
			"type":    "server_error",
			"code":    "upstream_stream_truncated",
		}})
		_, _ = w.Write(append(append([]byte("data: "), raw...), '\n', '\n'))
	}

	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func chatStreamIncludesUsage(raw []byte) bool {
	var probe struct {
		StreamOptions struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.StreamOptions.IncludeUsage
}

func writeChatSSEFromCompletion(w http.ResponseWriter, chatRaw []byte) {
	var comp map[string]any
	if err := json.Unmarshal(chatRaw, &comp); err != nil {
		WriteError(w, http.StatusBadGateway, "invalid chat conversion", "server_error", "convert_error")
		return
	}
	chunk := map[string]any{
		"id":      comp["id"],
		"object":  "chat.completion.chunk",
		"created": comp["created"],
		"model":   comp["model"],
		"choices": []any{},
	}
	if choices, ok := comp["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			delta := map[string]any{"role": "assistant"}
			if msg, ok := c0["message"].(map[string]any); ok {
				if content, exists := msg["content"]; exists {
					delta["content"] = content
				}
				if tcs, exists := msg["tool_calls"]; exists {
					delta["tool_calls"] = tcs
				}
			}
			chunk["choices"] = []any{
				map[string]any{
					"index":         0,
					"delta":         delta,
					"finish_reason": c0["finish_reason"],
				},
			}
		}
	}
	raw, err := marshalBody(chunk)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "encode error", "server_error", "encode_error")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte("\n\ndata: [DONE]\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// responsesSSEToChatChunk converts one Responses SSE JSON payload to a chat chunk.
func responsesSSEToChatChunk(data []byte, id, model *string) (chunk []byte, ok bool) {
	var ev map[string]any
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, false
	}
	typ := strings.ToLower(asString(ev["type"]))
	if typ == "" {
		if _, has := ev["output"]; has {
			chat := responsesMapToChat(ev)
			return completionToFinalChunk(chat), true
		}
		return nil, false
	}

	if resp, okm := ev["response"].(map[string]any); okm {
		if s := asString(resp["id"]); s != "" {
			*id = s
		}
		if s := asString(resp["model"]); s != "" {
			*model = s
		}
	}

	switch typ {
	case "response.output_text.delta", "response.text.delta":
		deltaText := asString(ev["delta"])
		if deltaText == "" {
			deltaText = asString(ev["text"])
		}
		if deltaText == "" {
			return nil, true
		}
		ch := map[string]any{
			"id":     *id,
			"object": "chat.completion.chunk",
			"model":  *model,
			"choices": []any{
				map[string]any{
					"index": 0,
					"delta": map[string]any{
						"content": deltaText,
					},
					"finish_reason": nil,
				},
			},
		}
		b, err := marshalBody(ch)
		if err != nil {
			return nil, false
		}
		return b, true
	case "response.completed", "response.done":
		ch := map[string]any{
			"id":     *id,
			"object": "chat.completion.chunk",
			"model":  *model,
			"choices": []any{
				map[string]any{
					"index":         0,
					"delta":         map[string]any{},
					"finish_reason": "stop",
				},
			},
		}
		b, err := marshalBody(ch)
		if err != nil {
			return nil, false
		}
		return b, true
	case "response.output_item.done":
		item, _ := ev["item"].(map[string]any)
		if item == nil {
			return nil, true
		}
		if strings.ToLower(asString(item["type"])) != "function_call" {
			return nil, true
		}
		name := asString(item["name"])
		args := asString(item["arguments"])
		callID := asString(item["call_id"])
		if callID == "" {
			callID = asString(item["id"])
		}
		ch := map[string]any{
			"id":     *id,
			"object": "chat.completion.chunk",
			"model":  *model,
			"choices": []any{
				map[string]any{
					"index": 0,
					"delta": map[string]any{
						"tool_calls": []any{
							map[string]any{
								"index": 0,
								"id":    callID,
								"type":  "function",
								"function": map[string]any{
									"name":      name,
									"arguments": args,
								},
							},
						},
					},
					"finish_reason": nil,
				},
			},
		}
		b, err := marshalBody(ch)
		if err != nil {
			return nil, false
		}
		return b, true
	default:
		return nil, true
	}
}

func completionToFinalChunk(chat map[string]any) []byte {
	delta := map[string]any{"role": "assistant"}
	finish := any("stop")
	if choices, ok := chat["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			if msg, ok := c0["message"].(map[string]any); ok {
				if c, exists := msg["content"]; exists {
					delta["content"] = c
				}
				if t, exists := msg["tool_calls"]; exists {
					delta["tool_calls"] = t
				}
			}
			if fr, exists := c0["finish_reason"]; exists {
				finish = fr
			}
		}
	}
	ch := map[string]any{
		"id":      chat["id"],
		"object":  "chat.completion.chunk",
		"created": chat["created"],
		"model":   chat["model"],
		"choices": []any{
			map[string]any{
				"index":         0,
				"delta":         delta,
				"finish_reason": finish,
			},
		},
	}
	b, _ := marshalBody(ch)
	return b
}
