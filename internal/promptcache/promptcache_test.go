package promptcache

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestApplyStableAcrossAppendedConversationAndIsolated(t *testing.T) {
	firstBody := []byte(`{"model":"grok-4.5","instructions":"be concise","tools":[{"type":"function","name":"lookup"}],"input":[{"role":"user","content":"first question"}]}`)
	secondBody := []byte(`{"model":"grok-4.5","instructions":"be concise","tools":[{"type":"function","name":"lookup"}],"input":[{"role":"user","content":"first question"},{"role":"assistant","content":"first answer"},{"role":"user","content":"second question"}]}`)

	_, firstKey, err := Apply(firstBody, "client-a", "grok-4.5", "")
	if err != nil {
		t.Fatal(err)
	}
	_, secondKey, err := Apply(secondBody, "client-a", "grok-4.5", "")
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == "" || firstKey != secondKey {
		t.Fatalf("keys first=%q second=%q", firstKey, secondKey)
	}
	_, otherClientKey, _ := Apply(firstBody, "client-b", "grok-4.5", "")
	_, otherModelKey, _ := Apply(firstBody, "client-a", "grok-composer-2.5-fast", "")
	if firstKey == otherClientKey || firstKey == otherModelKey {
		t.Fatalf("cache key isolation failed: base=%q client=%q model=%q", firstKey, otherClientKey, otherModelKey)
	}
}

func TestApplyHashesExplicitSessionAndNeverForwardsIt(t *testing.T) {
	updated, key, err := Apply([]byte(`{"model":"grok-4.5","prompt_cache_key":"raw-client-session","input":"hello"}`), "client-a", "grok-4.5", "raw-client-session")
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || bytes.Contains(updated, []byte("raw-client-session")) {
		t.Fatalf("key=%q body=%s", key, updated)
	}
	var body map[string]any
	if err := json.Unmarshal(updated, &body); err != nil {
		t.Fatal(err)
	}
	if body["prompt_cache_key"] != key {
		t.Fatalf("body=%v key=%q", body, key)
	}
}

func TestApplySkipsRequestsWithoutClientIdentityOrStableAnchor(t *testing.T) {
	body := []byte(`{"model":"grok-4.5","instructions":"system only"}`)
	for _, clientID := range []string{"", "client-a"} {
		updated, key, err := Apply(body, clientID, "grok-4.5", "")
		if err != nil {
			t.Fatal(err)
		}
		if key != "" || !bytes.Equal(updated, body) {
			t.Fatalf("client=%q key=%q body=%s", clientID, key, updated)
		}
	}
}
