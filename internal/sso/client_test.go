package sso

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type staticSettings struct{ value storage.RuntimeSettings }

func (s staticSettings) Current() storage.RuntimeSettings { return s.value }

type mutableSettings struct {
	mu    sync.RWMutex
	value storage.RuntimeSettings
}

func (s *mutableSettings) Current() storage.RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}
func (s *mutableSettings) set(value storage.RuntimeSettings) {
	s.mu.Lock()
	s.value = value
	s.mu.Unlock()
}

type staticHTTPFactory struct{ client *http.Client }

func (f staticHTTPFactory) ClientFor(_ *storage.Credential, _ time.Duration) (*http.Client, outbound.ResolvedProxy, error) {
	return f.client, outbound.ResolvedProxy{Mode: outbound.ModeDirect}, nil
}

type recordingHTTPFactory struct {
	client     *http.Client
	credential *storage.Credential
}

func (f *recordingHTTPFactory) ClientFor(credential *storage.Credential, _ time.Duration) (*http.Client, outbound.ResolvedProxy, error) {
	if credential != nil {
		copy := *credential
		f.credential = &copy
	} else {
		f.credential = nil
	}
	return f.client, outbound.ResolvedProxy{}, nil
}

func TestClientConvertsBatchesAndPreservesPartialFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		var request struct {
			Items []struct {
				SSO string `json:"sso"`
			} `json:"items"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		results := make([]map[string]any, len(request.Items))
		for index, item := range request.Items {
			if item.SSO == "bad" {
				results[index] = map[string]any{"index": index, "ok": false}
				continue
			}
			results[index] = map[string]any{
				"index": index,
				"ok":    true,
				"credential": map[string]any{
					"key":            "access-" + item.SSO,
					"refresh_token":  "refresh-" + item.SSO,
					"user_id":        "user-" + item.SSO,
					"expires_at":     "2026-07-11T06:00:00.000000000Z",
					"oidc_issuer":    "https://auth.x.ai",
					"oidc_client_id": "client",
				},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer server.Close()

	settings := storage.DefaultRuntimeSettings()
	settings.SSOConverter = storage.SSOConverterSettings{
		Enabled: true, Endpoint: server.URL, APIKey: "test-key",
		AllowInsecure: true, TimeoutSec: 10, MaxBatch: 2,
	}
	client := &Client{
		Settings: staticSettings{settings},
		Outbound: staticHTTPFactory{client: server.Client()},
	}
	converted, err := client.Convert(t.Context(), []string{"one", "bad", "three"})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
	if converted[0].UserID != "user-one" || converted[0].AccessToken != "access-one" {
		t.Fatalf("first=%+v", converted[0])
	}
	if converted[1].Error == "" || converted[1].AccessToken != "" {
		t.Fatalf("failed=%+v", converted[1])
	}
	if converted[2].UserID != "user-three" {
		t.Fatalf("third=%+v", converted[2])
	}
}

func TestClientRequiresEnabledSecureConfiguration(t *testing.T) {
	settings := storage.DefaultRuntimeSettings()
	client := &Client{
		Settings: staticSettings{settings},
		Outbound: staticHTTPFactory{client: http.DefaultClient},
	}
	if _, err := client.Convert(t.Context(), []string{"sso"}); err == nil {
		t.Fatal("disabled converter must fail")
	}
	settings.SSOConverter = storage.SSOConverterSettings{
		Enabled: true, Endpoint: "http://converter.test", APIKey: "key",
		TimeoutSec: 10, MaxBatch: 1,
	}
	client.Settings = staticSettings{settings}
	if _, err := client.Convert(t.Context(), []string{"sso"}); err == nil {
		t.Fatal("insecure HTTP must require explicit opt-in")
	}
}

func TestClientForcesPrivateConverterDirectInsteadOfGlobalProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{
			"index": 0, "ok": true, "credential": map[string]any{
				"key": "access", "refresh_token": "refresh", "user_id": "direct-user",
			},
		}}})
	}))
	defer server.Close()
	settings := storage.DefaultRuntimeSettings()
	settings.SSOConverter = storage.SSOConverterSettings{
		Enabled: true, Endpoint: server.URL, APIKey: "sidecar-key",
		AllowInsecure: true, TimeoutSec: 10, MaxBatch: 1,
	}
	factory := &recordingHTTPFactory{client: server.Client()}
	client := &Client{Settings: staticSettings{settings}, Outbound: factory}
	if _, err := client.Convert(t.Context(), []string{"raw-sso"}); err != nil {
		t.Fatal(err)
	}
	if factory.credential == nil || factory.credential.ProxyMode != storage.CredentialProxyDirect {
		t.Fatalf("private converter route=%+v want direct", factory.credential)
	}
	if got := converterRouteCredential("https://converter.example.com"); got != nil {
		t.Fatalf("public HTTPS converter unexpectedly forced direct: %+v", got)
	}
}

func TestClientCanBeEnabledThroughRuntimeSettingsWithoutRewiring(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{
					"index": 0,
					"ok":    true,
					"credential": map[string]any{
						"key": "access", "refresh_token": "refresh", "user_id": "runtime-user",
					},
				},
			},
		})
	}))
	defer server.Close()
	provider := &mutableSettings{value: storage.DefaultRuntimeSettings()}
	client := &Client{Settings: provider, Outbound: staticHTTPFactory{client: server.Client()}}
	if _, err := client.Convert(t.Context(), []string{"sso"}); err == nil {
		t.Fatal("disabled runtime setting unexpectedly converted")
	}
	next := provider.Current()
	next.SSOConverter = storage.SSOConverterSettings{
		Enabled: true, Endpoint: server.URL, APIKey: "key", AllowInsecure: true,
		TimeoutSec: 10, MaxBatch: 1,
	}
	provider.set(next)
	converted, err := client.Convert(t.Context(), []string{"sso"})
	if err != nil {
		t.Fatal(err)
	}
	if len(converted) != 1 || converted[0].UserID != "runtime-user" {
		t.Fatalf("converted=%+v", converted)
	}
}

func TestValidateEndpointRestrictsInsecureHTTPToPrivateHosts(t *testing.T) {
	accepted := []string{
		"https://converter.example.com",
		"http://localhost:8090",
		"http://127.0.0.1:8090",
		"http://[::1]:8090",
		"http://10.10.0.4:8090",
		"http://172.20.0.4:8090",
		"http://192.168.1.4:8090",
		"http://sso-import:8090",
	}
	for _, endpoint := range accepted {
		if _, err := ValidateEndpoint(endpoint, true); err != nil {
			t.Errorf("ValidateEndpoint(%q): %v", endpoint, err)
		}
	}

	rejected := []string{
		"http://converter.example.com:8090",
		"http://8.8.8.8:8090",
		"http://100.64.0.1:8090",
		"http://2130706433:8090",
		"http://bad_internal:8090",
	}
	for _, endpoint := range rejected {
		if _, err := ValidateEndpoint(endpoint, true); err == nil {
			t.Errorf("ValidateEndpoint(%q) unexpectedly succeeded", endpoint)
		}
	}
}

func TestConvertBatchRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", int(maxResponseBytes)+1))
	}))
	defer server.Close()

	_, err := convertBatch(t.Context(), server.Client(), server.URL, "key", []string{"sso"})
	if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestConvertBatchRejectsResultCountBeforeDecodingUnboundedArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"index":0,"ok":false},{"index":1,"ok":false}]}`)
	}))
	defer server.Close()
	_, err := convertBatch(t.Context(), server.Client(), server.URL, "key", []string{"one"})
	if err == nil || !strings.Contains(err.Error(), "too many results") {
		t.Fatalf("err=%v", err)
	}
}

func TestClientDoesNotForwardSecretsAcrossRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				redirected.Add(1)
			}))
			defer target.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer redirect-secret" {
					t.Fatalf("origin authorization=%q", r.Header.Get("Authorization"))
				}
				w.Header().Set("Location", target.URL+"/capture")
				w.WriteHeader(status)
			}))
			defer origin.Close()

			settings := storage.DefaultRuntimeSettings()
			settings.SSOConverter = storage.SSOConverterSettings{
				Enabled: true, Endpoint: origin.URL, APIKey: "redirect-secret",
				AllowInsecure: true, TimeoutSec: 10, MaxBatch: 1,
			}
			client := &Client{Settings: staticSettings{settings}, Outbound: staticHTTPFactory{client: origin.Client()}}
			_, err := client.Convert(t.Context(), []string{"sso-secret"})
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
				t.Fatalf("err=%v", err)
			}
			if redirected.Load() != 0 {
				t.Fatalf("redirect target received %d requests", redirected.Load())
			}
		})
	}
}

func TestClientRejectsSidecarLimitMismatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		timeout  int
		maxBatch int
	}{
		{name: "batch", timeout: 10, maxBatch: maxBatchItems + 1},
		{name: "timeout", timeout: maxTimeoutSec + 1, maxBatch: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := storage.DefaultRuntimeSettings()
			settings.SSOConverter = storage.SSOConverterSettings{
				Enabled: true, Endpoint: "http://localhost:8090", APIKey: "key",
				AllowInsecure: true, TimeoutSec: tc.timeout, MaxBatch: tc.maxBatch,
			}
			client := &Client{Settings: staticSettings{settings}, Outbound: staticHTTPFactory{client: http.DefaultClient}}
			if _, err := client.Convert(t.Context(), []string{"sso"}); err == nil {
				t.Fatal("expected sidecar limit validation error")
			}
		})
	}
}
