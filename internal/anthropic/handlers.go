package anthropic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/promptcache"
	"github.com/GreyGunG/grokbuild-proxy/internal/requestidentity"
)

// PostResponsesFunc posts a Responses body to upstream and returns the raw HTTP response.
// body is already translated JSON. stream indicates Accept preference.
// Caller of HandleMessages closes resp.Body.
type PostResponsesFunc func(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error)

// Handlers serves Anthropic Messages endpoints.
type Handlers struct {
	Post PostResponsesFunc
	Cfg  config.AnthropicConfig
	// ResolveModel maps client model → upstream. If nil, uses Cfg.ModelAliases + passthrough.
	ResolveModel func(string) string
	MaxBody      int64
}

func (h *Handlers) maxBody() int64 {
	if h != nil && h.MaxBody > 0 {
		return h.MaxBody
	}
	return 20 << 20
}

// resolve applies ResolveModel or config aliases.
func (h *Handlers) resolve(model string) string {
	if h.ResolveModel != nil {
		return h.ResolveModel(model)
	}
	return h.Cfg.ResolveModel(model)
}

// HandleMessages serves POST /v1/messages (query ?beta=true is ignored).
func (h *Handlers) HandleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.Post == nil {
		WriteError(w, http.StatusInternalServerError, "upstream not configured")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody()))
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		WriteError(w, status, "failed to read body")
		return
	}
	_ = r.Body.Close()

	var probe struct {
		Model    string          `json:"model"`
		Stream   bool            `json:"stream"`
		Thinking json.RawMessage `json:"thinking"`
	}
	_ = json.Unmarshal(raw, &probe)

	resolved := h.resolve(probe.Model)
	convID := sessionIDFromRequest(r)
	if len(convID) > 512 {
		WriteError(w, http.StatusBadRequest, "session id must be at most 512 bytes")
		return
	}
	thinkingBridge := thinkingBridgeFromRaw(probe.Thinking)

	body, originalModel, stream, err := TranslateRequest(raw, TranslateReqOptions{
		ResolvedModel:     resolved,
		ConvID:            convID,
		StripUnknownBetas: h.Cfg.StripUnknownBetas,
	})
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, cacheKey, err := promptcache.Apply(body, requestidentity.ClientID(r.Context()), resolved, convID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "failed to derive prompt cache key")
		return
	}
	if cacheKey != "" {
		convID = cacheKey
	}

	resp, err := h.Post(r.Context(), resolved, convID, body, stream)
	if err != nil {
		if errors.Is(err, lb.ErrNoCredential) {
			w.Header().Set("Retry-After", "1")
			WriteError(w, http.StatusServiceUnavailable, "no usable upstream credentials")
			return
		}
		WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	copyAnthropicUpstreamHeaders(w.Header(), resp.Header)

	if resp.StatusCode >= 400 {
		rawErr, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		msg := FormatErrorMessage(resp.StatusCode, rawErr)
		WriteError(w, resp.StatusCode, msg)
		return
	}

	ct := resp.Header.Get("Content-Type")
	isSSE := stream || strings.Contains(ct, "text/event-stream")

	if isSSE {
		WriteClaudeSSEHeaders(w)
		var flusher http.Flusher
		if f, ok := w.(http.Flusher); ok {
			flusher = f
		}
		reqModel := probe.Model
		if reqModel == "" {
			reqModel = originalModel
		}
		tr := NewStreamTranslator(w, flusher, reqModel, thinkingBridge)
		if err := PipeResponsesSSE(resp.Body, tr); err != nil {
			if tr.State.Started && !tr.State.Finished {
				_ = tr.Fail(http.StatusBadGateway, err.Error())
				return
			}
			if tr.State.Finished {
				return
			}
			WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		return
	}

	// Non-stream JSON
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		WriteError(w, http.StatusBadGateway, "failed to read upstream body")
		return
	}
	msg, err := TranslateResponse(rawResp, TranslateRespOptions{
		RequestModel:  probe.Model,
		FallbackModel: resolved,
		Thinking:      thinkingBridge,
	})
	if err != nil {
		WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(msg)
}

func copyAnthropicUpstreamHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Retry-After",
		"Request-Id",
		"Anthropic-Request-Id",
	} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
	if value := src.Get("X-Request-Id"); value != "" {
		dst.Set("X-Upstream-Request-Id", value)
	}
}

// HandleCountTokens deliberately returns 404 so clients use a local estimate.
// Returning a fabricated zero would cause unsafe context-window decisions.
func (h *Handlers) HandleCountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	WriteError(w, http.StatusNotFound, "count_tokens is not implemented")
}

// sessionIDFromRequest extracts sticky conv id for Grok prompt cache.
func sessionIDFromRequest(r *http.Request) string {
	if r == nil {
		return newSessionID()
	}
	for _, k := range []string{
		"x-claude-code-session-id",
		"X-Claude-Code-Session-Id",
		"x-session-id",
		"x-grok-conv-id",
	} {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			return v
		}
	}
	return newSessionID()
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "sess_fallback"
	}
	return "sess_" + hex.EncodeToString(b[:])
}

// Register attaches Anthropic routes on mux (optional helper).
func (h *Handlers) Register(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/v1/messages", h.HandleMessages)
	mux.HandleFunc("/v1/messages/count_tokens", h.HandleCountTokens)
}
