package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Model is one entry from GET /v1/models (OpenAI-list shaped + Grok extensions).
type Model struct {
	ID                      string          `json:"id"`
	Object                  string          `json:"object,omitempty"`
	Created                 int64           `json:"created,omitempty"`
	OwnedBy                 string          `json:"owned_by,omitempty"`
	Name                    string          `json:"name,omitempty"`
	Description             string          `json:"description,omitempty"`
	APIBackend              string          `json:"api_backend,omitempty"`
	ContextWindow           int             `json:"context_window,omitempty"`
	MaxCompletionTokens     *int            `json:"max_completion_tokens,omitempty"`
	SupportsReasoningEffort bool            `json:"supports_reasoning_effort,omitempty"`
	ReasoningEffort         string          `json:"reasoning_effort,omitempty"`
	ReasoningEfforts        json.RawMessage `json:"reasoning_efforts,omitempty"`
	AgentType               string          `json:"agent_type,omitempty"`
	Hidden                  bool            `json:"hidden,omitempty"`
	SupportedInAPI          *bool           `json:"supported_in_api,omitempty"`
	// Raw preserves the original object for forward-compatible fields.
	Raw json.RawMessage `json:"-"`
}

// ModelList is the OpenAI-compatible list envelope.
type ModelList struct {
	Object string  `json:"object,omitempty"`
	Data   []Model `json:"data"`
}

// ListModels calls GET /v1/models.
func (c *Client) ListModels(ctx context.Context, accessToken string) (*ModelList, error) {
	status, _, raw, err := c.DoJSON(ctx, http.MethodGet, "/models", nil, RequestOptions{
		AccessToken: accessToken,
		Accept:      "application/json",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "upstream models", StatusCode: status, Body: truncate(string(raw), 512),
		}
	}
	return ParseModelList(raw)
}

// ParseModelList parses an OpenAI-shaped models list, or a bare array, or a
// Grok models_cache-like map under "models".
func ParseModelList(raw []byte) (*ModelList, error) {
	// Canonical: {object, data:[...]}
	var list ModelList
	if err := json.Unmarshal(raw, &list); err == nil && list.Data != nil {
		for i := range list.Data {
			if list.Data[i].ID == "" {
				// Some payloads use "model" instead of "id".
				var alt struct {
					Model string `json:"model"`
				}
				_ = json.Unmarshal(mustRaw(list.Data[i]), &alt)
				if alt.Model != "" {
					list.Data[i].ID = alt.Model
				}
			}
		}
		if list.Object == "" {
			list.Object = "list"
		}
		return &list, nil
	}

	// Bare array.
	var arr []Model
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return &ModelList{Object: "list", Data: arr}, nil
	}

	// models_cache style: {"models":{"id":{"info":{...}}}}
	var cache struct {
		Models map[string]struct {
			Info Model `json:"info"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &cache); err == nil && len(cache.Models) > 0 {
		out := &ModelList{Object: "list", Data: make([]Model, 0, len(cache.Models))}
		for id, entry := range cache.Models {
			m := entry.Info
			if m.ID == "" {
				m.ID = id
			}
			out.Data = append(out.Data, m)
		}
		return out, nil
	}

	return nil, fmt.Errorf("upstream models: unrecognized payload")
}

// Find returns the first model whose id matches (case-sensitive).
func (l *ModelList) Find(id string) *Model {
	if l == nil {
		return nil
	}
	for i := range l.Data {
		if l.Data[i].ID == id {
			return &l.Data[i]
		}
	}
	return nil
}

// IDs returns all model ids.
func (l *ModelList) IDs() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l.Data))
	for _, m := range l.Data {
		if strings.TrimSpace(m.ID) != "" {
			out = append(out, m.ID)
		}
	}
	return out
}

func mustRaw(m Model) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
