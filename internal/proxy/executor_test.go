package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

type memStore struct {
	mu      sync.Mutex
	creds   map[string]storage.Credential
	patches int
	gets    int
}

func newMemStore(creds ...storage.Credential) *memStore {
	m := &memStore{creds: make(map[string]storage.Credential)}
	for _, c := range creds {
		m.creds[c.ID] = c
	}
	return m
}

func (m *memStore) ListCredentials() ([]storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]storage.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		out = append(out, c)
	}
	return out, nil
}

func (m *memStore) GetCredential(id string) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	c, ok := m.creds[id]
	if !ok {
		return storage.Credential{}, storageNotFound(id)
	}
	return c, nil
}

func (m *memStore) UpdateCredential(c storage.Credential) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[c.ID]; !ok {
		return storage.Credential{}, storageNotFound(c.ID)
	}
	m.creds[c.ID] = c
	return c, nil
}

func (m *memStore) PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patches++
	c, ok := m.creds[id]
	if !ok {
		return storage.Credential{}, storageNotFound(id)
	}
	if mutate != nil {
		if err := mutate(&c); err != nil {
			return storage.Credential{}, err
		}
	}
	c.ID = id
	c.Revision++
	m.creds[id] = c
	return c, nil
}

func TestTouchLastUsedIsThrottled(t *testing.T) {
	credential := storage.Credential{ID: "cred-usage", Enabled: true}
	store := newMemStore(credential)
	now := time.Date(2026, 7, 10, 4, 0, 0, 0, time.UTC)
	executor := &Executor{Store: store, Now: func() time.Time { return now }}
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	patches := store.patches
	store.mu.Unlock()
	if patches != 1 {
		t.Fatalf("patches=%d want 1", patches)
	}
	now = now.Add(31 * time.Second)
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	patches = store.patches
	store.mu.Unlock()
	if patches != 2 {
		t.Fatalf("patches=%d want 2", patches)
	}
}

type notFoundError string

func (e notFoundError) Error() string { return "storage: credential " + string(e) + " not found" }

func storageNotFound(id string) error { return notFoundError(id) }

type passthroughRefresher struct{}

func (passthroughRefresher) EnsureAccess(_ context.Context, _ string, current auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return current, nil
}

func (passthroughRefresher) ForceRefresh(_ context.Context, _ string, current auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return current, nil
}

type routeRecordingUpstream struct {
	mu    sync.Mutex
	calls []string
}

func (u *routeRecordingUpstream) record(call string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, call)
}

func (u *routeRecordingUpstream) PostResponses(context.Context, any, upstream.PostResponsesOptions) (*http.Response, error) {
	u.record("post")
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}
func (u *routeRecordingUpstream) ListModels(context.Context, string) (*upstream.ModelList, error) {
	u.record("models")
	return &upstream.ModelList{}, nil
}
func (u *routeRecordingUpstream) GetBilling(context.Context, string) (*upstream.MonthlyBilling, error) {
	u.record("billing")
	return &upstream.MonthlyBilling{}, nil
}
func (u *routeRecordingUpstream) GetBillingCredits(context.Context, string) (*upstream.WeeklyCredits, error) {
	u.record("billing_credits")
	return &upstream.WeeklyCredits{}, nil
}
func (u *routeRecordingUpstream) GetBillingSnapshot(context.Context, string) (*upstream.BillingSnapshot, error) {
	u.record("billing_snapshot")
	return &upstream.BillingSnapshot{}, nil
}

type recordingRefresher struct {
	mu   sync.Mutex
	keys []string
}

type failingRefresher struct{ err error }

func (r failingRefresher) EnsureAccess(context.Context, string, auth.TokenSet, auth.TokenLoadFunc, auth.TokenPersistFunc) (auth.TokenSet, error) {
	return auth.TokenSet{}, r.err
}

func (r failingRefresher) ForceRefresh(context.Context, string, auth.TokenSet, auth.TokenLoadFunc, auth.TokenPersistFunc) (auth.TokenSet, error) {
	return auth.TokenSet{}, r.err
}

type hookRefresher struct {
	ensure func(context.Context, string, auth.TokenSet, auth.TokenLoadFunc, auth.TokenPersistFunc) (auth.TokenSet, error)
	force  func(context.Context, string, auth.TokenSet, auth.TokenLoadFunc, auth.TokenPersistFunc) (auth.TokenSet, error)
}

func (r hookRefresher) EnsureAccess(ctx context.Context, key string, current auth.TokenSet, load auth.TokenLoadFunc, persist auth.TokenPersistFunc) (auth.TokenSet, error) {
	if r.ensure != nil {
		return r.ensure(ctx, key, current, load, persist)
	}
	return current, nil
}

func (r hookRefresher) ForceRefresh(ctx context.Context, key string, current auth.TokenSet, load auth.TokenLoadFunc, persist auth.TokenPersistFunc) (auth.TokenSet, error) {
	if r.force != nil {
		return r.force(ctx, key, current, load, persist)
	}
	return current, nil
}

type postFuncUpstream struct {
	post func(context.Context, upstream.PostResponsesOptions) (*http.Response, error)
}

func (u postFuncUpstream) PostResponses(ctx context.Context, _ any, opts upstream.PostResponsesOptions) (*http.Response, error) {
	return u.post(ctx, opts)
}
func (postFuncUpstream) ListModels(context.Context, string) (*upstream.ModelList, error) {
	return &upstream.ModelList{}, nil
}
func (postFuncUpstream) GetBilling(context.Context, string) (*upstream.MonthlyBilling, error) {
	return &upstream.MonthlyBilling{}, nil
}
func (postFuncUpstream) GetBillingCredits(context.Context, string) (*upstream.WeeklyCredits, error) {
	return &upstream.WeeklyCredits{}, nil
}
func (postFuncUpstream) GetBillingSnapshot(context.Context, string) (*upstream.BillingSnapshot, error) {
	return &upstream.BillingSnapshot{}, nil
}

type quotaProbeUpstream struct {
	weekly *upstream.WeeklyCredits
	err    error
}

func (u quotaProbeUpstream) PostResponses(context.Context, any, upstream.PostResponsesOptions) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected PostResponses")
}
func (u quotaProbeUpstream) ListModels(context.Context, string) (*upstream.ModelList, error) {
	return &upstream.ModelList{}, nil
}
func (u quotaProbeUpstream) GetBilling(context.Context, string) (*upstream.MonthlyBilling, error) {
	return &upstream.MonthlyBilling{}, nil
}
func (u quotaProbeUpstream) GetBillingCredits(context.Context, string) (*upstream.WeeklyCredits, error) {
	return u.weekly, u.err
}
func (u quotaProbeUpstream) GetBillingSnapshot(context.Context, string) (*upstream.BillingSnapshot, error) {
	return &upstream.BillingSnapshot{}, nil
}

func (r *recordingRefresher) record(key string, current auth.TokenSet) (auth.TokenSet, error) {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return current, nil
}
func (r *recordingRefresher) EnsureAccess(_ context.Context, key string, current auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return r.record(key, current)
}
func (r *recordingRefresher) ForceRefresh(_ context.Context, key string, current auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return r.record(key, current)
}

func TestCredentialOperationsResolveOneConsistentRoute(t *testing.T) {
	credential := storage.Credential{
		ID: "cred-route", Enabled: true, Priority: 100,
		AccessToken: "access", RefreshToken: "refresh",
		ProxyMode: storage.CredentialProxyURL, ProxyURL: "http://proxy.test:8080",
	}
	store := newMemStore(credential)
	selector := lb.New(config.LBConfig{Strategy: "priority_rr", StickyTTLSec: 60})
	refresher := &recordingRefresher{}
	up := &routeRecordingUpstream{}
	var resolved []storage.Credential
	var resolvedMu sync.Mutex
	executor := &Executor{
		Store: store, Selector: selector, Refresher: refresher,
		UpstreamFor: func(credential storage.Credential) (Upstream, error) {
			resolvedMu.Lock()
			resolved = append(resolved, credential)
			resolvedMu.Unlock()
			return up, nil
		},
	}
	response, err := executor.Post(context.Background(), "grok-4.5", "route-conv", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if _, err := executor.ListModels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.GetBillingSnapshot(context.Background(), credential.ID); err != nil {
		t.Fatal(err)
	}
	if status, err := executor.ProbeCredential(context.Background(), credential.ID); err != nil || status != 200 {
		t.Fatalf("probe status=%d err=%v", status, err)
	}
	if _, err := executor.RefreshCredential(context.Background(), credential.ID); err != nil {
		t.Fatal(err)
	}
	resolvedMu.Lock()
	defer resolvedMu.Unlock()
	if len(resolved) != 4 {
		t.Fatalf("route resolutions=%d want 4", len(resolved))
	}
	for _, got := range resolved {
		if got.ID != credential.ID || got.ProxyMode != credential.ProxyMode || got.ProxyURL != credential.ProxyURL {
			t.Fatalf("route changed across operations: %+v", resolved)
		}
	}
	refresher.mu.Lock()
	defer refresher.mu.Unlock()
	for _, key := range refresher.keys {
		if key != credential.ID {
			t.Fatalf("refresh used a different credential key: %q", key)
		}
	}
}

func TestProbeCredentialMapsInvalidTokenRefreshFailureToUnauthorized(t *testing.T) {
	credential := storage.Credential{ID: "invalid", RefreshToken: "refresh", Enabled: true}
	executor := &Executor{
		Store: newMemStore(credential),
		Refresher: failingRefresher{err: &auth.HTTPStatusError{
			StatusCode: http.StatusUnauthorized, Body: `{"error":"invalid_token"}`,
		}},
	}
	status, err := executor.ProbeCredential(context.Background(), credential.ID)
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestHealthySnapshotProbeUsesBoundedDurableChecks(t *testing.T) {
	credential := storage.Credential{
		ID: "snapshot", Revision: 7, AccessToken: "access", RefreshToken: "refresh",
		Enabled: true, LifecycleState: storage.CredentialStateActive,
	}
	store := newMemStore(credential)
	executor := &Executor{
		Store: store, Refresher: passthroughRefresher{}, Upstream: &routeRecordingUpstream{},
	}
	status, observed, err := executor.ProbeCredentialSnapshot(context.Background(), credential)
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d observed=%+v err=%v", status, observed, err)
	}
	store.mu.Lock()
	gets := store.gets
	store.mu.Unlock()
	if gets != 3 {
		t.Fatalf("healthy snapshot probe durable reads=%d want 3", gets)
	}
}

func TestRefreshDoesNotOverwriteConcurrentImportedRefreshToken(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.Form.Get("refresh_token"); got != "old-refresh" {
			t.Errorf("refresh_token=%q want old-refresh", got)
		}
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stale-flight-access", "refresh_token": "stale-flight-refresh", "expires_in": 3600,
		})
	}))
	defer server.Close()

	store := newMemStore(storage.Credential{
		ID: "import-race", AccessToken: "old-access", RefreshToken: "old-refresh", Enabled: true,
	})
	refresher := &auth.Refresher{OAuth: &auth.OAuthClient{
		HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true,
	}}
	executor := &Executor{Store: store, Refresher: refresher}
	done := make(chan error, 1)
	go func() {
		_, _, err := executor.ForceRefreshToken(context.Background(), "import-race")
		done <- err
	}()

	<-started
	if _, err := store.PatchCredential("import-race", func(credential *storage.Credential) error {
		credential.AccessToken = "imported-access"
		credential.RefreshToken = "imported-refresh"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, auth.ErrRefreshInvalidated) {
		t.Fatalf("err=%v want ErrRefreshInvalidated", err)
	}
	credential, err := store.GetCredential("import-race")
	if err != nil {
		t.Fatal(err)
	}
	if credential.AccessToken != "imported-access" || credential.RefreshToken != "imported-refresh" {
		t.Fatalf("stale refresh overwrote imported tokens: %+v", credential)
	}
	if _, ok := refresher.Cached("import-race"); ok {
		t.Fatal("rejected stale refresh was cached")
	}
}

func TestPostDoesNotGrantAfterDisableOrGlobalRouteChange(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*memStore, *atomic.Uint64) error
	}{
		{
			name: "disabled",
			mutate: func(store *memStore, _ *atomic.Uint64) error {
				_, err := store.PatchCredential("cred", func(credential *storage.Credential) error {
					credential.Enabled = false
					credential.ManualDisabled = true
					return nil
				})
				return err
			},
		},
		{
			name: "global route changed",
			mutate: func(_ *memStore, revision *atomic.Uint64) error {
				revision.Add(1)
				return nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			store := newMemStore(storage.Credential{
				ID: "cred", Enabled: true, AccessToken: "access", RefreshToken: "refresh", Revision: 1,
			})
			var forceCalls atomic.Int32
			refresher := hookRefresher{force: func(context.Context, string, auth.TokenSet, auth.TokenLoadFunc, auth.TokenPersistFunc) (auth.TokenSet, error) {
				forceCalls.Add(1)
				return auth.TokenSet{AccessToken: "should-not-be-used", RefreshToken: "rotated"}, nil
			}}
			up := postFuncUpstream{post: func(context.Context, upstream.PostResponsesOptions) (*http.Response, error) {
				close(started)
				<-release
				return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			}}
			var routeRevision atomic.Uint64
			executor := &Executor{
				Store: store, Selector: lb.New(config.LBConfig{Strategy: "priority_rr"}), Upstream: up,
				Refresher: refresher, MaxAttempts: 1, RouteRevision: routeRevision.Load,
			}
			type outcome struct {
				response *http.Response
				err      error
			}
			done := make(chan outcome, 1)
			go func() {
				response, err := executor.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
				done <- outcome{response: response, err: err}
			}()
			<-started
			if err := test.mutate(store, &routeRevision); err != nil {
				t.Fatal(err)
			}
			close(release)
			result := <-done
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.response != nil {
				_ = result.response.Body.Close()
			}
			if forceCalls.Load() != 0 {
				t.Fatalf("force refresh calls=%d want 0", forceCalls.Load())
			}
		})
	}
}

func TestPostNeverSendsTokenSupersededBetweenEnsureAndDurableReload(t *testing.T) {
	store := newMemStore(storage.Credential{
		ID: "cred", Enabled: true, AccessToken: "old-access", RefreshToken: "old-refresh", Revision: 1,
	})
	var mutated atomic.Bool
	refresher := hookRefresher{ensure: func(_ context.Context, _ string, current auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
		if mutated.CompareAndSwap(false, true) {
			_, err := store.PatchCredential("cred", func(credential *storage.Credential) error {
				credential.AccessToken = "imported-access"
				credential.RefreshToken = "imported-refresh"
				return nil
			})
			if err != nil {
				return auth.TokenSet{}, err
			}
		}
		return current, nil
	}}
	var seen []string
	executor := &Executor{
		Store: store, Selector: lb.New(config.LBConfig{Strategy: "priority_rr"}), Refresher: refresher, MaxAttempts: 2,
		Upstream: postFuncUpstream{post: func(_ context.Context, opts upstream.PostResponsesOptions) (*http.Response, error) {
			seen = append(seen, opts.AccessToken)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		}},
	}
	response, err := executor.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(seen) != 1 || seen[0] != "imported-access" {
		t.Fatalf("access tokens sent=%v", seen)
	}
}

func TestPostNeverRetriesWithRefreshResultSupersededByImport(t *testing.T) {
	store := newMemStore(storage.Credential{
		ID: "cred", Enabled: true, AccessToken: "old-access", RefreshToken: "old-refresh", Revision: 1,
	})
	refresher := hookRefresher{force: func(_ context.Context, _ string, _ auth.TokenSet, _ auth.TokenLoadFunc, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
		_, err := store.PatchCredential("cred", func(credential *storage.Credential) error {
			credential.AccessToken = "imported-access"
			credential.RefreshToken = "imported-refresh"
			return nil
		})
		if err != nil {
			return auth.TokenSet{}, err
		}
		return auth.TokenSet{AccessToken: "refresh-result-access", RefreshToken: "refresh-result-refresh"}, nil
	}}
	var seen []string
	executor := &Executor{
		Store: store, Selector: lb.New(config.LBConfig{Strategy: "priority_rr"}), Refresher: refresher, MaxAttempts: 2,
		Upstream: postFuncUpstream{post: func(_ context.Context, opts upstream.PostResponsesOptions) (*http.Response, error) {
			seen = append(seen, opts.AccessToken)
			status := http.StatusUnauthorized
			if opts.AccessToken == "imported-access" {
				status = http.StatusOK
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		}},
	}
	response, err := executor.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(seen) != 2 || seen[0] != "old-access" || seen[1] != "imported-access" {
		t.Fatalf("access tokens sent=%v", seen)
	}
}

func TestSecondForceRefreshWorksAfterStorageTruncatesExpiry(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	credential, err := store.CreateCredential(storage.CreateCredentialInput{
		Name: "force-twice", AccessToken: "access-r0", RefreshToken: "refresh-r0",
	})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("access-r%d", call), "refresh_token": fmt.Sprintf("refresh-r%d", call), "expires_in": 3600,
		})
	}))
	defer server.Close()
	executor := &Executor{Store: store, Refresher: &auth.Refresher{OAuth: &auth.OAuthClient{
		HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true,
	}}}
	if _, _, err := executor.ForceRefreshToken(context.Background(), credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executor.ForceRefreshToken(context.Background(), credential.ID); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("OAuth calls=%d want 2", calls.Load())
	}
}

func TestExecutorPostSuccess(t *testing.T) {
	var gotAuth string
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotModel = r.Header.Get("x-grok-model-override")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed"}`))
	}))
	t.Cleanup(srv.Close)

	up := upstream.NewClient(upstream.Config{
		BaseURL:    srv.URL + "/v1",
		HTTPClient: srv.Client(),
	})
	store := newMemStore(storage.Credential{
		ID:          "cred_a",
		Name:        "a",
		AccessToken: "access-token-a",
		Enabled:     true,
		Priority:    100,
	})
	sel := lb.New(config.LBConfig{Strategy: "priority_rr", StickyTTLSec: 60})
	ex := &Executor{
		Store:     store,
		Selector:  sel,
		Upstream:  up,
		Refresher: passthroughRefresher{},
	}

	resp, err := ex.Post(context.Background(), "grok-4.5", "conv-1", []byte(`{"model":"grok-4.5","input":"hi"}`), false)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "resp_1") {
		t.Fatalf("body = %s", body)
	}
	if gotAuth != "Bearer access-token-a" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotModel != "grok-4.5" {
		t.Fatalf("model override = %q", gotModel)
	}
}

func TestExecutorPostFailoverOn429(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	keys := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		mu.Lock()
		hits[authz]++
		n := hits[authz]
		keys[authz] = r.Header.Get("Idempotency-Key")
		mu.Unlock()
		if strings.Contains(authz, "token-a") && n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "ok", "token": authz})
	}))
	t.Cleanup(srv.Close)

	up := upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	store := newMemStore(
		storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true, Priority: 200},
		storage.Credential{ID: "cred_b", AccessToken: "token-b", Enabled: true, Priority: 100},
	)
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    up,
		Refresher:   passthroughRefresher{},
		MaxAttempts: 3,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5"}`), false)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "token-b") {
		t.Fatalf("expected failover to token-b, body=%s hits=%v", raw, hits)
	}
	if keys["Bearer token-a"] == "" || keys["Bearer token-a"] != keys["Bearer token-b"] {
		t.Fatalf("attempts must share an idempotency key: %v", keys)
	}
}

func TestExecutorPostFailoverOnPaymentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token-a") {
			w.WriteHeader(http.StatusPaymentRequired)
			_, _ = w.Write([]byte(`{"error":{"message":"quota exhausted"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok-from-b"}`))
	}))
	t.Cleanup(srv.Close)

	store := newMemStore(
		storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true, Priority: 200},
		storage.Credential{ID: "cred_b", AccessToken: "token-b", Enabled: true, Priority: 100},
	)
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher:   passthroughRefresher{},
		MaxAttempts: 2,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "ok-from-b") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestExecutorPreservesFinalUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"all accounts limited"}}`))
	}))
	t.Cleanup(srv.Close)
	store := newMemStore(storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true})
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher:   passthroughRefresher{},
		MaxAttempts: 3,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "7" {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(string(raw), "all accounts limited") {
		t.Fatalf("body=%s", raw)
	}
}

func TestProbeCredentialTreatsExhaustedWeeklyCreditsAsUnavailable(t *testing.T) {
	used := 100.0
	store := newMemStore(storage.Credential{ID: "cred", AccessToken: "token", Enabled: true})
	executor := &Executor{
		Store:    store,
		Selector: lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream: quotaProbeUpstream{weekly: &upstream.WeeklyCredits{CreditUsagePercent: &used}},
	}
	status, err := executor.ProbeCredential(context.Background(), "cred")
	if err != nil || status != http.StatusPaymentRequired {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("12"); d != 12*time.Second {
		t.Fatalf("got %v", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Fatalf("empty=%v", d)
	}
	now := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	if d := parseRetryAfterAt(now.Add(30*time.Second).Format(http.TimeFormat), now); d != 30*time.Second {
		t.Fatalf("date=%v", d)
	}
}
