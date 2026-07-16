// Package promptcache derives non-secret, tenant-isolated xAI prompt cache keys.
package promptcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const keyPrefix = "grokcache-v1-"

// Apply replaces prompt_cache_key with a stable opaque key when the request is
// authenticated by a durable local client ID. A caller-provided session ID is
// preferred; otherwise a stable prompt prefix is used. When no safe anchor is
// available, the body is returned unchanged.
func Apply(body []byte, clientID, upstreamModel, explicitSession string) ([]byte, string, error) {
	clientID = strings.TrimSpace(clientID)
	upstreamModel = strings.TrimSpace(upstreamModel)
	if clientID == "" || upstreamModel == "" {
		return body, "", nil
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, "", fmt.Errorf("prompt cache: invalid request body: %w", err)
	}

	seed := strings.TrimSpace(explicitSession)
	if seed == "" {
		seed = strings.TrimSpace(stringValue(request["prompt_cache_key"]))
	}
	if seed == "" {
		prefix, ok := stablePrefix(request)
		if !ok {
			return body, "", nil
		}
		encoded, err := json.Marshal(prefix)
		if err != nil {
			return nil, "", fmt.Errorf("prompt cache: encode stable prefix: %w", err)
		}
		seed = string(encoded)
	}

	hash := sha256.Sum256([]byte("grok-prompt-cache:v1\x00" + clientID + "\x00" + upstreamModel + "\x00" + seed))
	key := keyPrefix + hex.EncodeToString(hash[:16])
	request["prompt_cache_key"] = key
	updated, err := json.Marshal(request)
	if err != nil {
		return nil, "", fmt.Errorf("prompt cache: encode request: %w", err)
	}
	return updated, key, nil
}

func stablePrefix(request map[string]any) (map[string]any, bool) {
	firstUser, ok := firstUserContent(request["input"])
	if !ok {
		return nil, false
	}
	prefix := map[string]any{"first_user": firstUser}
	for _, field := range []string{"instructions", "tools", "tool_choice", "reasoning", "text"} {
		if value, exists := request[field]; exists {
			prefix[field] = value
		}
	}
	return prefix, true
}

func firstUserContent(input any) (any, bool) {
	switch value := input.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			return value, true
		}
	case []any:
		for _, item := range value {
			message, ok := item.(map[string]any)
			if !ok || !strings.EqualFold(strings.TrimSpace(stringValue(message["role"])), "user") {
				continue
			}
			if content, exists := message["content"]; exists && hasContent(content) {
				return content, true
			}
		}
	}
	return nil, false
}

func hasContent(value any) bool {
	switch content := value.(type) {
	case string:
		return strings.TrimSpace(content) != ""
	case []any:
		return len(content) > 0
	case nil:
		return false
	default:
		return true
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
