package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplyHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	ApplyHeaders(req, HeaderInput{
		AccessToken:      "tok",
		Model:            "grok-4.5",
		ConvID:           "conv-1",
		ClientVersion:    "0.2.93",
		ClientIdentifier: "grok-pager",
		TokenAuth:        "xai-grok-cli",
		UserAgent:        "grok-pager/0.2.93",
		Accept:           "application/json",
	})
	checks := map[string]string{
		"Authorization":            "Bearer tok",
		"X-XAI-Token-Auth":         "xai-grok-cli",
		"x-grok-client-version":    "0.2.93",
		"x-grok-client-identifier": "grok-pager",
		"x-grok-model-override":    "grok-4.5",
		"x-grok-conv-id":           "conv-1",
		"User-Agent":               "grok-pager/0.2.93",
		"Accept":                   "application/json",
	}
	for k, want := range checks {
		if got := req.Header.Get(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
}

func TestApplyHeaders_ExtraOverrides(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	extra := http.Header{}
	extra.Set("User-Agent", "custom-ua")
	extra.Set("X-Custom", "1")
	ApplyHeaders(req, HeaderInput{
		AccessToken: "t",
		UserAgent:   "default-ua",
		Extra:       extra,
	})
	if got := req.Header.Get("User-Agent"); got != "custom-ua" {
		t.Errorf("ua=%q", got)
	}
	if got := req.Header.Get("X-Custom"); got != "1" {
		t.Errorf("custom=%q", got)
	}
}

func TestListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" && r.URL.Path != "/models" {
			// Client joins base+path; base includes /v1 so path is /models → /v1/models
			if !strings.HasSuffix(r.URL.Path, "/models") {
				t.Errorf("path=%s", r.URL.Path)
			}
		}
		assertGrokHeaders(t, r, "")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{
				{
					"id":                        "grok-4.5",
					"api_backend":               "responses",
					"context_window":            500000,
					"supports_reasoning_effort": true,
				},
				{
					"id":             "grok-composer-2.5-fast",
					"api_backend":    "responses",
					"context_window": 200000,
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	list, err := c.ListModels(context.Background(), "access-tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 2 {
		t.Fatalf("len=%d", len(list.Data))
	}
	if list.Find("grok-4.5") == nil {
		t.Fatal("missing grok-4.5")
	}
	ids := list.IDs()
	if len(ids) != 2 {
		t.Fatalf("ids=%v", ids)
	}
}

func TestParseModelList_CacheShape(t *testing.T) {
	raw := []byte(`{
  "models": {
    "grok-4.5": {
      "info": {
        "id": "grok-4.5",
        "api_backend": "responses",
        "context_window": 500000
      }
    }
  }
}`)
	list, err := ParseModelList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if list.Find("grok-4.5") == nil {
		t.Fatal("not found")
	}
}

func TestGetBilling(t *testing.T) {
	var sawCredits bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertGrokHeaders(t, r, "")
		if strings.Contains(r.URL.RawQuery, "format=credits") {
			sawCredits = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"creditUsagePercent": 36.0,
				"billingPeriodEnd":   "2026-07-01T00:00:00Z",
			})
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/billing") {
			t.Errorf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"monthlyLimit":     4000,
			"used":             1421,
			"onDemandCap":      0,
			"billingPeriodEnd": "2026-08-01T00:00:00Z",
		})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	m, err := c.GetBilling(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if m.MonthlyLimit == nil || *m.MonthlyLimit != 4000 || m.Used == nil || *m.Used != 1421 {
		t.Fatalf("%+v", m)
	}
	if m.RemainingCredits() != 4000-1421 {
		t.Errorf("remaining=%v", m.RemainingCredits())
	}
	snap, err := c.GetBillingSnapshot(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Monthly == nil || snap.Weekly == nil {
		t.Fatalf("snap=%+v sawCredits=%v", snap, sawCredits)
	}
	if snap.Weekly.CreditUsagePercent == nil || *snap.Weekly.CreditUsagePercent != 36 {
		t.Errorf("weekly=%+v", snap.Weekly)
	}
}

func TestParseMonthlyBilling_NestedConfig(t *testing.T) {
	raw := []byte(`{"config":{"monthlyLimit":100,"used":10,"billingPeriodEnd":"2026-01-01T00:00:00Z"}}`)
	m, err := ParseMonthlyBilling(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.MonthlyLimit == nil || *m.MonthlyLimit != 100 || m.Used == nil || *m.Used != 10 {
		t.Fatalf("%+v", m)
	}
}

func TestParseMonthlyBilling_ConfigValWrapper(t *testing.T) {
	// Live cli-chat-proxy shape (2026-07): numbers wrapped as {"val":N} under config.
	raw := []byte(`{"config":{"monthlyLimit":{"val":20000},"used":{"val":2704},"onDemandCap":{"val":0},"billingPeriodStart":"2026-07-01T00:00:00+00:00","billingPeriodEnd":"2026-08-01T00:00:00+00:00"}}`)
	m, err := ParseMonthlyBilling(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.MonthlyLimit == nil || *m.MonthlyLimit != 20000 || m.Used == nil || *m.Used != 2704 {
		t.Fatalf("limit/used: %+v", m)
	}
	if m.BillingPeriodStart == "" || m.BillingPeriodEnd == "" {
		t.Fatalf("period missing: %+v", m)
	}
	if m.RemainingCredits() != 20000-2704 {
		t.Errorf("remaining=%v", m.RemainingCredits())
	}
}

func TestParseWeeklyCredits_ConfigValWrapper(t *testing.T) {
	raw := []byte(`{"config":{"creditUsagePercent":66.0,"billingPeriodEnd":"2026-07-13T04:20:32.192591+00:00","productUsage":[{"product":"Api","usagePercent":66.0}]}}`)
	w, err := ParseWeeklyCredits(raw)
	if err != nil {
		t.Fatal(err)
	}
	if w.CreditUsagePercent == nil || *w.CreditUsagePercent != 66 {
		t.Fatalf("percent=%v", w.CreditUsagePercent)
	}
	if w.BillingPeriodEnd == "" {
		t.Fatal("missing period end")
	}
	if len(w.ProductUsage) == 0 {
		t.Fatal("expected productUsage")
	}
}

func TestBillingDistinguishesZeroFromMissingAndKeepsRaw(t *testing.T) {
	m, err := ParseMonthlyBilling([]byte(`{"monthlyLimit":0,"extra":"kept"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.MonthlyLimit == nil || *m.MonthlyLimit != 0 || m.Used != nil {
		t.Fatalf("monthly=%+v", m)
	}
	if string(m.Raw["extra"]) != `"kept"` {
		t.Fatalf("raw=%v", m.Raw)
	}
	w, err := ParseWeeklyCredits([]byte(`{"productUsage":[{"product":"GrokBuild","usagePercent":0,"extra":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if w.CreditUsagePercent != nil || len(w.ProductUsage) != 1 || w.ProductUsage[0].UsagePercent == nil || *w.ProductUsage[0].UsagePercent != 0 {
		t.Fatalf("weekly=%+v", w)
	}
	if _, ok := w.ProductUsage[0].Raw["extra"]; !ok {
		t.Fatalf("product raw=%v", w.ProductUsage[0].Raw)
	}
	nested, err := ParseWeeklyCredits([]byte(`{"trace":"outer","config":{"creditUsagePercent":1,"unknown":"inner"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(nested.Raw["trace"]) != `"outer"` || len(nested.Raw["config"]) == 0 {
		t.Fatalf("nested root shape was not preserved: raw=%v", nested.Raw)
	}
}

func TestBillingParsersRejectInvalidOrNonObjectJSON(t *testing.T) {
	tests := []struct {
		name  string
		parse func([]byte) error
		raw   string
	}{
		{"monthly invalid", func(raw []byte) error { _, err := ParseMonthlyBilling(raw); return err }, `{"used":`},
		{"monthly array", func(raw []byte) error { _, err := ParseMonthlyBilling(raw); return err }, `[]`},
		{"monthly null", func(raw []byte) error { _, err := ParseMonthlyBilling(raw); return err }, `null`},
		{"monthly invalid config", func(raw []byte) error { _, err := ParseMonthlyBilling(raw); return err }, `{"config":[]}`},
		{"weekly invalid", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `not-json`},
		{"weekly scalar", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `42`},
		{"weekly invalid config", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `{"config":null}`},
		{"monthly numeric suffix", func(raw []byte) error { _, err := ParseMonthlyBilling(raw); return err }, `{"used":"42junk"}`},
		{"weekly non-finite", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `{"creditUsagePercent":"NaN"}`},
		{"weekly product object", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `{"productUsage":{"product":"GrokBuild"}}`},
		{"weekly product scalar", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `{"productUsage":[42]}`},
		{"weekly product non-finite", func(raw []byte) error { _, err := ParseWeeklyCredits(raw); return err }, `{"productUsage":[{"product":"GrokBuild","usagePercent":"Inf"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.parse([]byte(tt.raw)); err == nil {
				t.Fatalf("accepted invalid billing payload %s", tt.raw)
			}
		})
	}
}

func TestBillingClientsReturnParseErrorForInvalid200Payload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if _, err := client.GetBilling(context.Background(), "token"); err == nil || !strings.Contains(err.Error(), "expected JSON object") {
		t.Fatalf("monthly error=%v", err)
	}
	if _, err := client.GetBillingCredits(context.Background(), "token"); err == nil || !strings.Contains(err.Error(), "expected JSON object") {
		t.Fatalf("weekly error=%v", err)
	}
}

func TestBillingSnapshotAllowsOneSideFailureAndNormalizesGrokBuild(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "format=credits") {
			_ = json.NewEncoder(w).Encode(map[string]any{"creditUsagePercent": 42, "billingPeriodEnd": "2026-07-20", "productUsage": []map[string]any{{"product": "Api", "usagePercent": 7}, {"product": "GrokBuild", "usagePercent": 35}}})
			return
		}
		http.Error(w, "monthly unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NewClient(Config{BaseURL: srv.URL, HTTPClient: srv.Client()})
	snap, err := c.GetBillingSnapshot(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Monthly != nil || snap.MonthlyError == "" || snap.Weekly == nil {
		t.Fatalf("snap=%+v", snap)
	}
	if !snap.GrokBuild.Reported || snap.GrokBuild.SharedWeeklyUsagePercent == nil || *snap.GrokBuild.SharedWeeklyUsagePercent != 42 || snap.GrokBuild.GrokBuildContribution == nil || *snap.GrokBuild.GrokBuildContribution != 35 {
		t.Fatalf("view=%+v", snap.GrokBuild)
	}
}

func TestParseWeeklyCredits_SnakeCaseProductUsage(t *testing.T) {
	raw := []byte(`{"config":{"credit_usage_percent":{"val":0},"current_period":{"start":"2026-07-01"},"product_usage":[{"name":"Api","usage_percent":{"val":4}},{"name":"GrokBuild","usage_percent":{"val":12.5}}]}}`)
	w, err := ParseWeeklyCredits(raw)
	if err != nil {
		t.Fatal(err)
	}
	if w.CreditUsagePercent == nil || *w.CreditUsagePercent != 0 {
		t.Fatalf("shared usage=%v", w.CreditUsagePercent)
	}
	if len(w.CurrentPeriod) == 0 || len(w.ProductUsage) != 2 {
		t.Fatalf("weekly=%+v", w)
	}
	product := w.ProductUsage[0]
	if product.Product != "GrokBuild" || product.UsagePercent == nil || *product.UsagePercent != 12.5 {
		t.Fatalf("product=%+v", product)
	}
	if w.ProductUsage[1].Product != "Api" {
		t.Fatalf("GrokBuild product was not sorted first: %+v", w.ProductUsage)
	}
}

func TestPostResponses_DoesNotConsumeBody(t *testing.T) {
	const payload = `data: {"type":"response.output_text.delta","delta":"hi"}` + "\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/responses") {
			t.Errorf("path=%s", r.URL.Path)
		}
		assertGrokHeaders(t, r, "grok-4.5")
		if r.Header.Get("x-grok-conv-id") != "c1" {
			t.Errorf("conv=%q", r.Header.Get("x-grok-conv-id"))
		}
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("accept=%q", r.Header.Get("Accept"))
		}
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		if m["model"] != "grok-4.5" {
			t.Errorf("body model=%v", m["model"])
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	resp, err := c.PostResponses(context.Background(), map[string]any{
		"model":  "grok-4.5",
		"input":  "hello",
		"stream": true,
	}, PostResponsesOptions{
		AccessToken: "tok",
		Model:       "grok-4.5",
		ConvID:      "c1",
		Stream:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Critical: body not pre-consumed — we can still read the stream.
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("body=%q", got)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPostResponsesJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertGrokHeaders(t, r, "grok-4.5")
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("accept=%q", r.Header.Get("Accept"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "resp_1",
			"object": "response",
			"status": "completed",
		})
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	status, _, raw, err := c.PostResponsesJSON(context.Background(), []byte(`{"model":"grok-4.5","input":"x"}`), PostResponsesOptions{
		AccessToken: "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Fatalf("status=%d", status)
	}
	if !strings.Contains(string(raw), "resp_1") {
		t.Fatalf("raw=%s", raw)
	}
}

func TestPostResponses_ModelFromBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-grok-model-override") != "grok-composer-2.5-fast" {
			t.Errorf("model override=%q", r.Header.Get("x-grok-model-override"))
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	resp, err := c.PostResponses(context.Background(), json.RawMessage(`{"model":"grok-composer-2.5-fast","input":[]}`), PostResponsesOptions{
		AccessToken: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient(Config{})
	if c.BaseURL() != DefaultBaseURL {
		t.Errorf("base=%s", c.BaseURL())
	}
	cfg := c.Config()
	if cfg.TokenAuth != DefaultTokenAuth || cfg.ClientVersion != DefaultClientVersion {
		t.Errorf("%+v", cfg)
	}
}

func TestJoinURL(t *testing.T) {
	if got := joinURL("https://cli-chat-proxy.grok.com/v1/", "/models"); got != "https://cli-chat-proxy.grok.com/v1/models" {
		t.Fatal(got)
	}
	if got := joinURL("https://cli-chat-proxy.grok.com/v1", "billing"); got != "https://cli-chat-proxy.grok.com/v1/billing" {
		t.Fatal(got)
	}
}

func assertGrokHeaders(t *testing.T, r *http.Request, model string) {
	t.Helper()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		t.Errorf("Authorization=%q", r.Header.Get("Authorization"))
	}
	if r.Header.Get("X-XAI-Token-Auth") != DefaultTokenAuth {
		t.Errorf("X-XAI-Token-Auth=%q", r.Header.Get("X-XAI-Token-Auth"))
	}
	if r.Header.Get("x-grok-client-version") == "" {
		t.Error("missing x-grok-client-version")
	}
	if r.Header.Get("x-grok-client-identifier") == "" {
		t.Error("missing x-grok-client-identifier")
	}
	if r.Header.Get("User-Agent") == "" {
		t.Error("missing User-Agent")
	}
	if model != "" && r.Header.Get("x-grok-model-override") != model {
		t.Errorf("model-override=%q want %q", r.Header.Get("x-grok-model-override"), model)
	}
}
