package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PostResponsesFunc is injected by the server/LB layer.
// It must select credentials, ensure tokens, and call upstream PostResponses.
// The returned *http.Response body is NOT consumed by the injector; Handlers own it.
//
// model/convID are hints from the OpenAI surface after sanitize.
// body is the sanitized JSON payload.
// stream indicates Accept: text/event-stream should be used upstream.
type PostResponsesFunc func(ctx context.Context, model, convID string, body []byte, stream bool) (resp *http.Response, err error)

// DefaultMaxBody is 20 MiB when Handlers.MaxBody is unset.
const DefaultMaxBody int64 = 20 << 20

// Handlers implements OpenAI-compatible HTTP endpoints.
type Handlers struct {
	// Post performs the upstream Responses call. Required.
	Post PostResponsesFunc
	// ResolveModel maps a client-facing alias to an upstream Grok model. If nil,
	// the requested model is sent unchanged.
	ResolveModel func(string) string
	// MaxBody limits request body size. Zero uses DefaultMaxBody.
	MaxBody int64
}

func (h *Handlers) resolve(model string) string {
	model = strings.TrimSpace(model)
	if h != nil && h.ResolveModel != nil {
		if resolved := strings.TrimSpace(h.ResolveModel(model)); resolved != "" {
			return resolved
		}
	}
	return model
}

func (h *Handlers) maxBody() int64 {
	if h != nil && h.MaxBody > 0 {
		return h.MaxBody
	}
	return DefaultMaxBody
}

// readBody reads and limits the request body.
func (h *Handlers) readBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("missing body")
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, h.maxBody()+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	if int64(len(raw)) > h.maxBody() {
		return nil, errBodyTooLarge
	}
	return raw, nil
}

var errBodyTooLarge = fmt.Errorf("request body too large")

// convIDFromRequest extracts a conversation / sticky id from headers or body.
func convIDFromRequest(r *http.Request, bodyConv string) string {
	if r != nil {
		candidates := []string{
			r.Header.Get("X-Grok-Conv-Id"),
			r.Header.Get("x-grok-conv-id"),
			r.Header.Get("X-Session-Id"),
			r.Header.Get("x-session-id"),
			r.Header.Get("X-Client-Request-Id"),
		}
		for _, c := range candidates {
			if s := strings.TrimSpace(c); s != "" {
				return s
			}
		}
	}
	return strings.TrimSpace(bodyConv)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// proxyUpstreamJSON copies a non-stream upstream response to the client.
func proxyUpstreamJSON(w http.ResponseWriter, resp *http.Response, requestedModel string) {
	defer resp.Body.Close()
	copyUpstreamResponseHeaders(w.Header(), resp.Header)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		WriteError(w, http.StatusBadGateway, "failed to read upstream response", "server_error", "upstream_read_error")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		MapUpstreamError(w, resp.StatusCode, raw)
		return
	}
	raw = rewriteResponseModel(raw, requestedModel)
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(raw)
}

// streamUpstreamSSE copies upstream SSE to the client with Flush.
func streamUpstreamSSE(w http.ResponseWriter, resp *http.Response, requestedModel string) {
	defer resp.Body.Close()
	copyUpstreamResponseHeaders(w.Header(), resp.Header)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		MapUpstreamError(w, resp.StatusCode, raw)
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/event-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 32<<20)
	for scanner.Scan() {
		line := rewriteSSEModelLine(scanner.Bytes(), requestedModel)
		if _, err := w.Write(append(line, '\n')); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// rewriteResponseModel returns the original payload if it is not a JSON object.
func rewriteResponseModel(raw []byte, requestedModel string) []byte {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return raw
	}
	var response map[string]any
	if json.Unmarshal(raw, &response) != nil {
		return raw
	}
	response["model"] = requestedModel
	updated, err := json.Marshal(response)
	if err != nil {
		return raw
	}
	return updated
}

// rewriteSSEModelLine preserves an SSE line unless it contains a JSON event
// that already carries a model name. It avoids adding fields to delta events.
func rewriteSSEModelLine(line []byte, requestedModel string) []byte {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" || !bytes.HasPrefix(line, []byte("data:")) {
		return line
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	var event map[string]any
	if json.Unmarshal(payload, &event) != nil {
		return line
	}
	changed := false
	if _, ok := event["model"]; ok {
		event["model"] = requestedModel
		changed = true
	}
	if response, ok := event["response"].(map[string]any); ok {
		if _, hasModel := response["model"]; hasModel {
			response["model"] = requestedModel
			changed = true
		}
	}
	if !changed {
		return line
	}
	updated, err := json.Marshal(event)
	if err != nil {
		return line
	}
	return append([]byte("data: "), updated...)
}

func copyUpstreamResponseHeaders(dst, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for _, key := range []string{
		"Retry-After",
		"Request-Id",
		"X-Ratelimit-Limit-Requests",
		"X-Ratelimit-Remaining-Requests",
		"X-Ratelimit-Reset-Requests",
	} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
	if value := src.Get("X-Request-Id"); value != "" {
		dst.Set("X-Upstream-Request-Id", value)
	}
}

// extractBodyConvID peeks prompt_cache_key from raw JSON without full sanitize.
func extractBodyConvID(raw []byte) string {
	var probe struct {
		PromptCacheKey string `json:"prompt_cache_key"`
		User           string `json:"user"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	if s := strings.TrimSpace(probe.PromptCacheKey); s != "" {
		return s
	}
	return strings.TrimSpace(probe.User)
}

// isSSEContentType reports whether ct looks like event-stream.
func isSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}

// scanSSEDataLines is a small helper for chat stream conversion.
func scanSSEDataLines(r io.Reader, fn func(data []byte) bool) error {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	// Match anthropic stream: large tool-call SSE lines need >4MiB headroom.
	sc.Buffer(buf, 32<<20)
	var dataBuf []byte
	flush := func() bool {
		if len(dataBuf) == 0 {
			return true
		}
		payload := bytes.TrimSuffix(dataBuf, []byte("\n"))
		dataBuf = nil
		return fn(payload)
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if !flush() {
				return nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if len(dataBuf) > 0 {
				dataBuf = append(dataBuf, '\n')
			}
			dataBuf = append(dataBuf, payload...)
		}
	}
	_ = flush()
	return sc.Err()
}

func marshalBody(v any) ([]byte, error) {
	return json.Marshal(v)
}

func unmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
