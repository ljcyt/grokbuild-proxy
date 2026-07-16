package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PostResponsesOptions configures a /v1/responses call.
type PostResponsesOptions struct {
	AccessToken string
	// Model is used for x-grok-model-override (and may also appear in body).
	Model string
	// ConvID sets x-grok-conv-id for sticky sessions / prompt cache.
	ConvID string
	// Stream when true sets Accept: text/event-stream (body.stream should also be true).
	Stream bool
	// ExtraHeaders optional overrides.
	ExtraHeaders http.Header
}

// PostResponses calls POST /v1/responses and returns the raw *http.Response.
//
// IMPORTANT: The response body is NOT consumed. Callers that stream must copy
// resp.Body incrementally and Close it. Non-stream callers should ReadAll + Close.
//
// body may be []byte, json.RawMessage, io.Reader, or any value that json.Marshal accepts.
func (c *Client) PostResponses(ctx context.Context, body any, opts PostResponsesOptions) (*http.Response, error) {
	if c == nil {
		return nil, fmt.Errorf("upstream: nil client")
	}
	reader, modelFromBody, err := encodeBody(body)
	if err != nil {
		return nil, err
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = modelFromBody
	}
	accept := "application/json"
	if opts.Stream {
		accept = "text/event-stream"
	}
	req, err := c.NewRequest(ctx, http.MethodPost, "/responses", reader, RequestOptions{
		AccessToken:  opts.AccessToken,
		Model:        model,
		ConvID:       opts.ConvID,
		Accept:       accept,
		ContentType:  "application/json",
		ExtraHeaders: opts.ExtraHeaders,
	})
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostResponsesCompact calls POST /v1/responses/compact. The compact endpoint
// only returns JSON, so streaming is deliberately not supported here.
func (c *Client) PostResponsesCompact(ctx context.Context, body any, opts PostResponsesOptions) (*http.Response, error) {
	if c == nil {
		return nil, fmt.Errorf("upstream: nil client")
	}
	reader, modelFromBody, err := encodeBody(body)
	if err != nil {
		return nil, err
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = modelFromBody
	}
	req, err := c.NewRequest(ctx, http.MethodPost, "/responses/compact", reader, RequestOptions{
		AccessToken:  opts.AccessToken,
		Model:        model,
		ConvID:       opts.ConvID,
		Accept:       "application/json",
		ContentType:  "application/json",
		ExtraHeaders: opts.ExtraHeaders,
	})
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostResponsesJSON is a non-stream helper that fully reads the body.
func (c *Client) PostResponsesJSON(ctx context.Context, body any, opts PostResponsesOptions) (status int, header http.Header, raw []byte, err error) {
	opts.Stream = false
	resp, err := c.PostResponses(ctx, body, opts)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, resp.Header.Clone(), nil, fmt.Errorf("upstream responses: read body: %w", err)
	}
	return resp.StatusCode, resp.Header.Clone(), raw, nil
}

func encodeBody(body any) (io.Reader, string, error) {
	if body == nil {
		return bytes.NewReader([]byte("{}")), "", nil
	}
	switch v := body.(type) {
	case io.Reader:
		return v, "", nil
	case []byte:
		return bytes.NewReader(v), extractModel(v), nil
	case json.RawMessage:
		return bytes.NewReader(v), extractModel(v), nil
	case string:
		b := []byte(v)
		return bytes.NewReader(b), extractModel(b), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, "", fmt.Errorf("upstream responses: marshal body: %w", err)
		}
		return bytes.NewReader(b), extractModel(b), nil
	}
}

func extractModel(raw []byte) string {
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return strings.TrimSpace(probe.Model)
}
