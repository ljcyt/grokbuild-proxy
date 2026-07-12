package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/admin"
	"github.com/GreyGunG/grokbuild-proxy/internal/anthropic"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

type stubClientStore struct {
	keys map[string]storage.ClientKey
}

type stubModelLister struct {
	data []upstream.Model
}

func (s stubModelLister) ListModels(context.Context) (*upstream.ModelList, error) {
	return &upstream.ModelList{Object: "list", Data: s.data}, nil
}

func (s stubClientStore) LookupClientByPlaintext(plaintext string) (storage.ClientKey, bool, error) {
	if s.keys == nil {
		return storage.ClientKey{}, false, nil
	}
	c, ok := s.keys[plaintext]
	return c, ok, nil
}

type countingReadinessStore struct {
	stubClientStore
	mu    sync.Mutex
	calls int
	creds []storage.Credential
}

func (s *countingReadinessStore) ListCredentials() ([]storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return append([]storage.Credential(nil), s.creds...), nil
}

func TestMiddlewareRejectsMissingKey(t *testing.T) {
	opts := Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Store:    stubClientStore{},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "missing api key") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestAnthropicAuthErrorUsesAnthropicEnvelope(t *testing.T) {
	h := New(Options{
		Config:    config.Default(),
		Store:     stubClientStore{},
		Anthropic: &anthropic.Handlers{},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env anthropic.ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "error" || env.Error.Type != "authentication_error" {
		t.Fatalf("envelope=%+v", env)
	}
}

func TestMiddlewareRejectsAdminKeyAsClient(t *testing.T) {
	opts := Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Store:    stubClientStore{},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-admin-good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareAcceptsAPIKey(t *testing.T) {
	cfg := config.Default()
	cfg.Anthropic.Enabled = true
	opts := Options{
		Config:   cfg,
		AdminKey: "sk-admin-good",
		Store: stubClientStore{keys: map[string]storage.ClientKey{
			"sk-api-good": {ID: "client-test"},
		}},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-api-good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "object") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestModelsOnlyAdvertisesConfiguredModelsAndUsableAliases(t *testing.T) {
	cfg := config.Default()
	h := New(Options{
		Config: cfg,
		Store: stubClientStore{keys: map[string]storage.ClientKey{
			"sk-api-good": {ID: "client-test"},
		}},
		ModelList: stubModelLister{data: []upstream.Model{
			{ID: "grok-4.5", OwnedBy: "xai"},
			{ID: "grok-composer-2.5-fast", OwnedBy: "xai"},
		}},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-api-good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]bool, len(response.Data))
	for _, row := range response.Data {
		ids[row.ID] = true
	}
	if !ids["grok-4.5"] || !ids["claude-sonnet-4"] || !ids["haiku"] {
		t.Fatalf("missing supported models: %#v", ids)
	}
	if ids["grok-composer-2.5-fast"] {
		t.Fatalf("unavailable composer must not be advertised: %#v", ids)
	}
}

func TestHealthzNoAuth(t *testing.T) {
	h := New(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestReadinessUsesShortLivedSnapshotInsteadOfReadingStorePerRequest(t *testing.T) {
	store := &countingReadinessStore{creds: []storage.Credential{{
		ID: "ready", Enabled: true, AccessToken: "access",
	}}}
	h := New(Options{Config: config.Default(), Store: store, ReadinessCacheTTL: time.Minute})
	for range 50 {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
	store.mu.Lock()
	calls := store.calls
	store.mu.Unlock()
	if calls != 1 {
		t.Fatalf("ListCredentials calls=%d want 1", calls)
	}
}

func TestReadinessMetricsAndRequestID(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var logs bytes.Buffer
	metrics := &Metrics{}
	h := New(Options{
		Config:            config.Default(),
		Store:             store,
		Metrics:           metrics,
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
		ReadinessCacheTTL: time.Nanosecond,
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-Id", "contract-ready-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty readiness status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Request-Id") != "contract-ready-1" {
		t.Fatalf("request id=%q", rr.Header().Get("X-Request-Id"))
	}

	created, err := store.CreateCredential(storage.CreateCredentialInput{
		Name:         "ready",
		AccessToken:  "access",
		RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := store.PatchCredential(created.ID, func(c *storage.Credential) error {
		c.RefreshToken = ""
		c.ExpiresAt = time.Now().Add(-time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired readiness status=%d body=%s", rr.Code, rr.Body.String())
	}

	metricsRR := httptest.NewRecorder()
	h.ServeHTTP(metricsRR, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsRR.Body.String(), "grokbuild_http_requests_total") {
		t.Fatalf("metrics=%s", metricsRR.Body.String())
	}
	if !strings.Contains(logs.String(), `"route":"/readyz"`) ||
		!strings.Contains(logs.String(), `"request_id":"contract-ready-1"`) {
		t.Fatalf("structured logs=%s", logs.String())
	}
}

func TestXAPIKeyHeader(t *testing.T) {
	opts := Options{
		Config: config.Default(),
		Store: stubClientStore{keys: map[string]storage.ClientKey{
			"sk-from-header": {ID: "client-test"},
		}},
	}
	h := New(opts)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("x-api-key", "sk-from-header")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBootstrapClientCanBeRevoked(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	apiKey, _, _, _, err := store.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := store.ListClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients=%d err=%v", len(clients), err)
	}

	h := New(Options{Config: config.Default(), Store: store})
	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request(); got != http.StatusOK {
		t.Fatalf("before revoke status=%d", got)
	}
	if _, err := store.SetClientDisabled(clients[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if got := request(); got != http.StatusUnauthorized {
		t.Fatalf("after revoke status=%d", got)
	}
}

func TestAdminUIServesLoginWithoutAuth(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	for _, path := range []string{"/admin", "/admin/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "localhost:8080"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		ct := rr.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Fatalf("%s Content-Type=%q want text/html", path, ct)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "html") && !strings.Contains(body, "Admin") {
			t.Fatalf("%s body missing admin UI marker", path)
		}
	}
}

func TestAdminAPIStillRequiresAuth(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/system", nil)
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s want 401", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("API must not return HTML, got Content-Type=%q", rr.Header().Get("Content-Type"))
	}
}

func TestAdminUIAssetsServedWithoutAuth(t *testing.T) {
	h := New(Options{Config: config.Default()})

	req := httptest.NewRequest(http.MethodGet, "/admin/ui/app.js", nil)
	req.Host = "[::1]:8080"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type=%q want javascript", ct)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("empty app.js body")
	}
}

func TestCredentialsNotServedAsHTML(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/credentials", nil)
	req.Host = "localhost"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s want 401", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") || strings.Contains(body, "<html") {
		t.Fatal("GET /admin/credentials must not return SPA HTML")
	}
}

func TestAdminRejectsUntrustedHostWithoutTrustingForwardedHost(t *testing.T) {
	cfg := config.Default()
	cfg.AdminTrustedHosts = []string{"admin.example.test"}
	h := New(Options{Config: cfg, AdminKey: "sk-admin-good", Admin: &admin.Handlers{}})

	for _, path := range []string{"/admin", "/admin/ui/app.js", "/admin/system"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "attacker.example.test:8080"
		req.Header.Set("X-Forwarded-Host", "admin.example.test")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMisdirectedRequest {
			t.Fatalf("%s status=%d body=%s want 421", path, rr.Code, rr.Body.String())
		}
	}
}

func TestAdminAllowsExplicitTrustedHostAndLeavesPublicAPIUnchanged(t *testing.T) {
	cfg := config.Default()
	cfg.AdminTrustedHosts = []string{"Admin.Example.Test."}
	h := New(Options{Config: cfg, AdminKey: "sk-admin-good", Admin: &admin.Handlers{}})

	adminReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	adminReq.Host = "admin.example.test:9443"
	adminRR := httptest.NewRecorder()
	h.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusOK {
		t.Fatalf("trusted admin status=%d body=%s", adminRR.Code, adminRR.Body.String())
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthReq.Host = "attacker.example.test"
	healthRR := httptest.NewRecorder()
	h.ServeHTTP(healthRR, healthReq)
	if healthRR.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", healthRR.Code, healthRR.Body.String())
	}
}
