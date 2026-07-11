package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestParseGrokAuthJSON_MapShape(t *testing.T) {
	// Fixture mirrors ~/.grok/auth.json shape WITHOUT real tokens.
	const fixture = `{
  "https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828": {
    "key": "access-token-fixture",
    "auth_mode": "oidc",
    "create_time": "2026-07-09T13:32:31.815457884Z",
    "user_id": "user-fixture-id",
    "email": "fixture@example.com",
    "first_name": "fixture",
    "principal_type": "User",
    "principal_id": "user-fixture-id",
    "team_id": "team-fixture-id",
    "coding_data_retention_opt_out": false,
    "refresh_token": "refresh-token-fixture",
    "expires_at": "2026-07-09T19:32:31.815457884Z",
    "oidc_issuer": "https://auth.x.ai",
    "oidc_client_id": "b1a00492-073a-47ea-816f-4c329264a828"
  }
}`
	creds, err := ParseGrokAuthJSON([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 cred, got %d", len(creds))
	}
	c := creds[0]
	if c.AccessToken != "access-token-fixture" {
		t.Errorf("access = %q", c.AccessToken)
	}
	if c.RefreshToken != "refresh-token-fixture" {
		t.Errorf("refresh = %q", c.RefreshToken)
	}
	if c.Email != "fixture@example.com" {
		t.Errorf("email = %q", c.Email)
	}
	if c.UserID != "user-fixture-id" {
		t.Errorf("user_id = %q", c.UserID)
	}
	if c.TeamID != "team-fixture-id" {
		t.Errorf("team_id = %q", c.TeamID)
	}
	if c.OIDCClientID != DefaultClientID {
		t.Errorf("client_id = %q", c.OIDCClientID)
	}
	if c.OIDCIssuer != Issuer {
		t.Errorf("issuer = %q", c.OIDCIssuer)
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expires_at not parsed")
	}
	if c.ExpiresAt.Year() != 2026 || c.ExpiresAt.Month() != 7 || c.ExpiresAt.Day() != 9 {
		t.Errorf("expires_at = %v", c.ExpiresAt)
	}
	ts := c.ToTokenSet()
	if ts.AccessToken != c.AccessToken || ts.RefreshToken != c.RefreshToken {
		t.Errorf("ToTokenSet mismatch: %+v", ts)
	}
}

func TestParseGrokAuthJSON_BareEntry(t *testing.T) {
	raw := `{"key":"a","refresh_token":"r","email":"e@x.ai","expires_at":"2026-01-02T03:04:05Z"}`
	creds, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].AccessToken != "a" || creds[0].RefreshToken != "r" {
		t.Fatalf("unexpected: %+v", creds)
	}
	if creds[0].OIDCClientID != DefaultClientID {
		t.Errorf("default client id missing: %q", creds[0].OIDCClientID)
	}
}

func TestParseGrokAuthJSON_SourceKeyFallback(t *testing.T) {
	raw := `{
  "https://auth.x.ai::custom-client-id": {
    "key": "k",
    "refresh_token": "r"
  }
}`
	creds, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if creds[0].OIDCClientID != "custom-client-id" {
		t.Errorf("client_id from key = %q", creds[0].OIDCClientID)
	}
	if creds[0].OIDCIssuer != "https://auth.x.ai" {
		t.Errorf("issuer from key = %q", creds[0].OIDCIssuer)
	}
}

func TestParseGrokAuthJSONRejectsUntrustedIssuer(t *testing.T) {
	raw := []byte(`{
  "https://evil.example::client": {
    "key": "access",
    "refresh_token": "refresh-secret",
    "user_id": "user",
    "oidc_issuer": "https://evil.example",
    "oidc_client_id": "client"
  }
}`)
	if _, err := ParseGrokAuthJSON(raw); err == nil {
		t.Fatal("untrusted imported OIDC issuer was accepted")
	}
}

func TestParseGrokAuthJSONPreservesDuplicateTopLevelKeys(t *testing.T) {
	raw := `{
		"https://auth.x.ai::same-client":{"key":"a1","refresh_token":"r1","user_id":"u1"},
		"https://auth.x.ai::same-client":{"key":"a2","refresh_token":"r2","user_id":"u2"}
	}`
	credentials, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("credentials=%+v", credentials)
	}
	if credentials[0].SourceKey == credentials[1].SourceKey {
		t.Fatalf("source keys must be unique: %+v", credentials)
	}
	if credentials[0].OIDCClientID != "same-client" || credentials[1].OIDCClientID != "same-client" {
		t.Fatalf("client ids=%q/%q", credentials[0].OIDCClientID, credentials[1].OIDCClientID)
	}
	if credentials[0].UserID != "u1" || credentials[1].UserID != "u2" {
		t.Fatalf("users=%q/%q", credentials[0].UserID, credentials[1].UserID)
	}
}

func TestParseGrokAuthJSONBareArrayAndCPA(t *testing.T) {
	raw := `[
			{"type":"xai","access_token":"a1","refresh_token":"r1","sub":"sub-1","expired":"2026-07-09T19:32:31Z","disabled":true},
		{"key":"a2","refresh_token":"r2","user_id":"u2"}
	]`
	credentials, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("credentials=%+v", credentials)
	}
	if credentials[0].AccessToken != "a1" || credentials[0].UserID != "sub-1" ||
		credentials[0].ExpiresAt.IsZero() || !credentials[0].Disabled {
		t.Fatalf("CPA credential=%+v", credentials[0])
	}
}

func TestParseGrokAuthJSONDetailedReportsUnknownField(t *testing.T) {
	raw := `{"key":"access-secret","refresh_token":"refresh-secret","future_option":"value-secret"}`
	credentials, warnings, err := ParseGrokAuthJSONDetailed([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || len(warnings) != 0 || len(credentials[0].Warnings) != 1 {
		t.Fatalf("credentials=%+v warnings=%+v", credentials, warnings)
	}
	warning := credentials[0].Warnings[0]
	if warning.Field != "future_option" || strings.Contains(warning.Message, "value-secret") {
		t.Fatalf("warning=%+v", warning)
	}
}

func TestParseGrokAuthJSONRequiresCPATypeXAI(t *testing.T) {
	for _, raw := range []string{
		`{"access_token":"a","refresh_token":"r","sub":"user","expired":"2026-07-09T19:32:31Z"}`,
		`{"type":"openai","access_token":"a","refresh_token":"r","sub":"user","expired":"2026-07-09T19:32:31Z"}`,
	} {
		_, err := ParseGrokAuthJSON([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), `field "type"`) || strings.Contains(err.Error(), "access_token") {
			t.Fatalf("raw=%s err=%v", raw, err)
		}
	}
}

func TestImportGrokAuthFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	content := `{
  "https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828": {
    "key": "file-access",
    "refresh_token": "file-refresh",
    "email": "file@example.com",
    "expires_at": "2026-07-09T19:32:31Z"
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := ImportGrokAuthFile(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].AccessToken != "file-access" {
		t.Fatalf("unexpected: %+v", creds)
	}
}

func TestTokenSetExpired(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	ts := TokenSet{ExpiresAt: now.Add(2 * time.Minute)}
	if ts.Expired(now, 3*time.Minute) {
		// 2m left, skew 3m → expired
	} else {
		t.Fatal("expected expired under skew")
	}
	if ts.Expired(now, 30*time.Second) {
		t.Fatal("should still be valid with small skew")
	}
	if (TokenSet{}).Expired(now, time.Minute) {
		t.Fatal("zero ExpiresAt should not be expired")
	}
}

func TestOAuthRefresh(t *testing.T) {
	var gotGrant, gotClient, gotRefresh string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type %q", ct)
		}
		_ = r.ParseForm()
		gotGrant = r.Form.Get("grant_type")
		gotClient = r.Form.Get("client_id")
		gotRefresh = r.Form.Get("refresh_token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	c := &OAuthClient{
		HTTPClient:           srv.Client(),
		TokenEndpoint:        srv.URL,
		ClientID:             DefaultClientID,
		AllowUnsafeEndpoints: true,
	}
	ts, err := c.Refresh(context.Background(), "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if gotGrant != "refresh_token" {
		t.Errorf("grant_type=%q", gotGrant)
	}
	if gotClient != DefaultClientID {
		t.Errorf("client_id=%q", gotClient)
	}
	if gotRefresh != "old-refresh" {
		t.Errorf("refresh_token=%q", gotRefresh)
	}
	if ts.AccessToken != "new-access" || ts.RefreshToken != "new-refresh" {
		t.Errorf("token set: %+v", ts)
	}
	if ts.ExpiresIn != 3600 || ts.ExpiresAt.IsZero() {
		t.Errorf("expiry: %+v", ts)
	}
}

func TestOAuthRefresh_PreservesRefreshWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "a2",
			"expires_in":   60,
		})
	}))
	t.Cleanup(srv.Close)
	c := &OAuthClient{HTTPClient: srv.Client(), TokenEndpoint: srv.URL, AllowUnsafeEndpoints: true}
	ts, err := c.Refresh(context.Background(), "keep-me")
	if err != nil {
		t.Fatal(err)
	}
	if ts.RefreshToken != "keep-me" {
		t.Errorf("refresh not preserved: %q", ts.RefreshToken)
	}
}

func TestOAuthTokenPostDoesNotFollow307Or308(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var leaked atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked.Add(1)
				_ = r.ParseForm()
				if got := r.Form.Get("refresh_token"); got != "" {
					t.Errorf("redirect target received refresh token %q", got)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()

			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer source.Close()

			client := &OAuthClient{
				HTTPClient: source.Client(), TokenEndpoint: source.URL, AllowUnsafeEndpoints: true,
			}
			_, err := client.Refresh(context.Background(), "never-leak-this-refresh-token")
			if err == nil || StatusCode(err) != status {
				t.Fatalf("err=%v status=%d", err, StatusCode(err))
			}
			if leaked.Load() != 0 {
				t.Fatalf("redirect target was contacted %d times", leaked.Load())
			}
		})
	}
}

func TestOAuthRefreshRejectsUntrustedIssuerBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	client := &OAuthClient{HTTPClient: server.Client(), Issuer: server.URL}
	if _, err := client.Refresh(context.Background(), "refresh-secret"); err == nil {
		t.Fatal("refresh with untrusted issuer unexpectedly succeeded")
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted issuer was contacted before rejection")
	}
}

func TestOAuthDiscover_RejectsNonXAI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://evil.example/authorize",
			"token_endpoint":         "https://evil.example/token",
		})
	}))
	t.Cleanup(srv.Close)
	c := &OAuthClient{HTTPClient: srv.Client(), DiscoveryURL: srv.URL, AllowUnsafeEndpoints: true}
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected reject non-x.ai host")
	}
}

func TestRefresherSingleflight(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond) // force overlap
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "shared-access",
			"refresh_token": "rotated-refresh",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	oauth := &OAuthClient{HTTPClient: srv.Client(), TokenEndpoint: srv.URL, AllowUnsafeEndpoints: true}
	ref := &Refresher{
		OAuth: oauth,
		Skew:  time.Minute,
		Now:   func() time.Time { return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC) },
	}

	current := TokenSet{
		AccessToken:  "old",
		RefreshToken: "r1",
		ExpiresAt:    time.Date(2026, 7, 9, 12, 0, 10, 0, time.UTC), // within skew → refresh
	}

	var persistCount atomic.Int32
	persist := func(ctx context.Context, _ TokenSet, next TokenSet) error {
		persistCount.Add(1)
		if next.AccessToken != "shared-access" {
			return fmt.Errorf("bad token %q", next.AccessToken)
		}
		return nil
	}

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	resCh := make(chan TokenSet, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ts, err := ref.EnsureAccess(context.Background(), "cred-1", current, nil, persist)
			if err != nil {
				errCh <- err
				return
			}
			resCh <- ts
		}()
	}
	wg.Wait()
	close(errCh)
	close(resCh)
	for err := range errCh {
		t.Fatalf("ensure: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 refresh call, got %d", calls.Load())
	}
	if persistCount.Load() != 1 {
		t.Fatalf("expected 1 persist, got %d", persistCount.Load())
	}
	for ts := range resCh {
		if ts.AccessToken != "shared-access" || ts.RefreshToken != "rotated-refresh" {
			t.Fatalf("unexpected token set: %+v", ts)
		}
	}
}

func TestCredentialInvalidationPersistsRotationButDoesNotCacheOrExposeIt(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "old-route-access", "refresh_token": "old-route-refresh", "expires_in": 3600,
		})
	}))
	defer server.Close()
	refresher := &Refresher{
		OAuth: &OAuthClient{HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true},
	}
	var persisted atomic.Int32
	done := make(chan error, 1)
	go func() {
		_, err := refresher.ForceRefresh(context.Background(), "credential-route", TokenSet{RefreshToken: "refresh"}, nil, func(context.Context, TokenSet, TokenSet) error {
			persisted.Add(1)
			return nil
		})
		done <- err
	}()
	<-started
	refresher.Invalidate("credential-route")
	close(release)
	err := <-done
	if !errors.Is(err, ErrRefreshInvalidated) {
		t.Fatalf("err=%v want ErrRefreshInvalidated", err)
	}
	if persisted.Load() != 1 {
		t.Fatalf("successful rotated token was not durably persisted: calls=%d", persisted.Load())
	}
	if _, ok := refresher.Cached("credential-route"); ok {
		t.Fatal("invalidated refresh repopulated cache")
	}
}

func TestStaleSnapshotNeverReusesRotatedRefreshTokenAfterInvalidation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var requestedMu sync.Mutex
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		requestedMu.Lock()
		requested = append(requested, r.Form.Get("refresh_token"))
		requestedMu.Unlock()
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-r1", "refresh_token": "refresh-r1", "expires_in": 3600,
		})
	}))
	defer server.Close()

	refresher := &Refresher{OAuth: &OAuthClient{
		HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true,
	}}
	durable := TokenSet{AccessToken: "access-r0", RefreshToken: "refresh-r0"}
	var durableMu sync.Mutex
	load := func(context.Context) (TokenSet, error) {
		durableMu.Lock()
		defer durableMu.Unlock()
		return durable, nil
	}
	persist := func(_ context.Context, previous, next TokenSet) error {
		durableMu.Lock()
		defer durableMu.Unlock()
		if durable.RefreshToken != previous.RefreshToken {
			return ErrRefreshInvalidated
		}
		durable = next
		return nil
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := refresher.ForceRefresh(context.Background(), "credential", TokenSet{
			AccessToken: "access-r0", RefreshToken: "refresh-r0",
		}, load, persist)
		firstDone <- err
	}()
	<-started
	refresher.Invalidate("credential")
	close(release)
	if err := <-firstDone; !errors.Is(err, ErrRefreshInvalidated) {
		t.Fatalf("first err=%v want ErrRefreshInvalidated", err)
	}

	_, err := refresher.ForceRefresh(context.Background(), "credential", TokenSet{
		AccessToken: "access-r0", RefreshToken: "refresh-r0",
	}, load, persist)
	if !errors.Is(err, ErrRefreshInvalidated) {
		t.Fatalf("second err=%v want ErrRefreshInvalidated", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("stale snapshot caused another grant: calls=%d", calls.Load())
	}
	requestedMu.Lock()
	defer requestedMu.Unlock()
	if len(requested) != 1 || requested[0] != "refresh-r0" {
		t.Fatalf("refresh tokens sent=%v", requested)
	}
}

func TestInvalidationDoesNotStartParallelGrantForSameCredential(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "rotated-access", "refresh_token": "rotated-refresh", "expires_in": 3600,
		})
	}))
	defer server.Close()
	refresher := &Refresher{OAuth: &OAuthClient{
		HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true,
	}}
	errorsCh := make(chan error, 2)
	refresh := func() {
		_, err := refresher.ForceRefresh(context.Background(), "stable-flight", TokenSet{RefreshToken: "same-refresh"}, nil, nil)
		errorsCh <- err
	}
	go refresh()
	<-started
	refresher.Invalidate("stable-flight")
	go refresh()
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("invalidation started %d parallel grants", got)
	}
	close(release)
	for range 2 {
		if err := <-errorsCh; !errors.Is(err, ErrRefreshInvalidated) {
			t.Fatalf("err=%v want ErrRefreshInvalidated", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("network grant calls=%d want 1", got)
	}
}

func TestRefresherDoesNotCacheUnpersistedRotatedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access", "refresh_token": "rotated-but-unpersisted", "expires_in": 3600,
		})
	}))
	defer server.Close()
	refresher := &Refresher{OAuth: &OAuthClient{
		HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true,
	}}
	persistErr := errors.New("disk unavailable")
	_, err := refresher.ForceRefresh(context.Background(), "persist-failure", TokenSet{RefreshToken: "old-refresh"}, nil,
		func(context.Context, TokenSet, TokenSet) error { return persistErr })
	if !errors.Is(err, persistErr) {
		t.Fatalf("err=%v want persistence error", err)
	}
	if _, ok := refresher.Cached("persist-failure"); ok {
		t.Fatal("unpersisted rotated token entered refresh cache")
	}
}

func TestRefresherEnsureAccess_NoRefreshWhenValid(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)
	ref := &Refresher{
		OAuth: &OAuthClient{HTTPClient: srv.Client(), TokenEndpoint: srv.URL, AllowUnsafeEndpoints: true},
		Skew:  time.Minute,
		Now:   func() time.Time { return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC) },
	}
	current := TokenSet{
		AccessToken:  "still-good",
		RefreshToken: "r",
		ExpiresAt:    time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC),
	}
	ts, err := ref.EnsureAccess(context.Background(), "c", current, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ts.AccessToken != "still-good" {
		t.Errorf("got %q", ts.AccessToken)
	}
	if calls.Load() != 0 {
		t.Fatalf("should not refresh, calls=%d", calls.Load())
	}
}

func TestRefresherEnsureAccessPrefersNewerCachedTokenOverStaleValidSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "refreshed-access", "refresh_token": "rotated-refresh", "expires_in": 3600,
		})
	}))
	defer server.Close()
	ref := &Refresher{
		OAuth: &OAuthClient{HTTPClient: server.Client(), TokenEndpoint: server.URL, AllowUnsafeEndpoints: true},
		Now:   func() time.Time { return now }, Skew: time.Minute,
	}
	if _, err := ref.ForceRefresh(context.Background(), "credential", TokenSet{
		AccessToken: "snapshot-before-refresh", RefreshToken: "old-refresh", ExpiresAt: now.Add(30 * time.Minute),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	got, err := ref.EnsureAccess(context.Background(), "credential", TokenSet{
		AccessToken: "snapshot-before-refresh", RefreshToken: "old-refresh", ExpiresAt: now.Add(30 * time.Minute),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "refreshed-access" || got.RefreshToken != "rotated-refresh" {
		t.Fatalf("EnsureAccess returned stale snapshot: %+v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("staggered stale snapshot triggered another refresh: calls=%d", calls.Load())
	}
}

func TestForceRefreshAlwaysHitsNetwork(t *testing.T) {
	// Even when cache has a still-valid access token, ForceRefresh must network-refresh
	// (401 path / admin force). Returning the cached AT would retry the failed token.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "fresh-access",
			"refresh_token": "fresh-refresh",
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	}))
	t.Cleanup(srv.Close)
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	ref := &Refresher{
		OAuth: &OAuthClient{HTTPClient: srv.Client(), TokenEndpoint: srv.URL, AllowUnsafeEndpoints: true},
		Skew:  time.Minute,
		Now:   func() time.Time { return now },
	}
	// Seed cache with a still-valid access token.
	ref.store("cred-force", TokenSet{
		AccessToken:  "cached-still-valid",
		RefreshToken: "rt-cached",
		ExpiresAt:    now.Add(2 * time.Hour),
		TokenType:    "Bearer",
	})
	var previous TokenSet
	ts, err := ref.ForceRefresh(context.Background(), "cred-force", TokenSet{
		AccessToken:  "old-at",
		RefreshToken: "rt-caller",
		ExpiresAt:    now.Add(-time.Hour),
	}, nil, func(_ context.Context, used, _ TokenSet) error {
		previous = used
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("ForceRefresh must hit network even with valid cache, calls=%d", calls.Load())
	}
	if ts.AccessToken != "fresh-access" {
		t.Fatalf("expected fresh access, got %q", ts.AccessToken)
	}
	if ts.RefreshToken != "fresh-refresh" {
		t.Fatalf("expected fresh refresh, got %q", ts.RefreshToken)
	}
	if previous.RefreshToken != "rt-cached" || previous.AccessToken != "cached-still-valid" {
		t.Fatalf("persist did not receive the cached token set actually used: %+v", previous)
	}
}

func TestRefresherWaiterCancellationDoesNotHang(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ref := &Refresher{
		OAuth:   &OAuthClient{HTTPClient: client, TokenEndpoint: "https://auth.x.ai/test-token", AllowUnsafeEndpoints: true},
		Timeout: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := ref.ForceRefresh(ctx, "cancelled", TokenSet{RefreshToken: "rt"}, nil, nil)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context canceled", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("cancelled waiter returned too slowly")
	}
}

func TestRefresherSharedOperationHasDeadline(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ref := &Refresher{
		OAuth:   &OAuthClient{HTTPClient: client, TokenEndpoint: "https://auth.x.ai/test-token", AllowUnsafeEndpoints: true},
		Timeout: 25 * time.Millisecond,
	}
	start := time.Now()
	_, err := ref.ForceRefresh(context.Background(), "timeout", TokenSet{RefreshToken: "rt"}, nil, nil)
	if err == nil {
		t.Fatal("expected refresh timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("refresh timeout was not enforced")
	}
}

func TestBoundedGrokParserStopsAtEntryLimit(t *testing.T) {
	var document strings.Builder
	document.WriteByte('[')
	for index := 0; index < 50_000; index++ {
		if index > 0 {
			document.WriteByte(',')
		}
		document.WriteString(`{"key":"a"}`)
	}
	document.WriteByte(']')
	_, _, err := ParseGrokAuthJSONDetailedLimit([]byte(document.String()), 10)
	if !errors.Is(err, ErrImportEntryLimit) {
		t.Fatalf("err=%v want ErrImportEntryLimit", err)
	}
}

func TestRequestDeviceCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != DefaultClientID {
			t.Errorf("client_id=%q", r.Form.Get("client_id"))
		}
		if r.Form.Get("scope") == "" {
			t.Error("missing scope")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://auth.x.ai/device",
			"verification_uri_complete": "https://auth.x.ai/device?user_code=ABCD-EFGH",
			"expires_in":                1800,
			"interval":                  5,
		})
	}))
	t.Cleanup(srv.Close)
	c := &OAuthClient{HTTPClient: srv.Client(), DeviceAuthEndpoint: srv.URL, AllowUnsafeEndpoints: true}
	dc, err := c.RequestDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dc.UserCode != "ABCD-EFGH" || dc.DeviceCode != "dev" {
		t.Fatalf("%+v", dc)
	}
}

func TestRequestDeviceCodeRejectsUntrustedVerificationURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev",
			"user_code":        "ABCD-EFGH",
			"verification_uri": "https://example.invalid/device",
			"expires_in":       1800,
			"interval":         5,
		})
	}))
	t.Cleanup(srv.Close)
	client := &OAuthClient{HTTPClient: srv.Client(), DeviceAuthEndpoint: srv.URL, AllowUnsafeEndpoints: true}
	if _, err := client.RequestDeviceCode(context.Background()); err == nil {
		t.Fatal("expected untrusted verification URI to be rejected")
	}
}

func TestConstants(t *testing.T) {
	if DefaultClientID != "b1a00492-073a-47ea-816f-4c329264a828" {
		t.Fatal(DefaultClientID)
	}
	if !strings.Contains(DefaultScope, "grok-cli:access") {
		t.Fatal(DefaultScope)
	}
	if Issuer != "https://auth.x.ai" {
		t.Fatal(Issuer)
	}
}

func TestResolveGrokAuthPathJail(t *testing.T) {
	// Outside home .grok must be rejected.
	if _, err := ResolveGrokAuthPath("/etc/passwd"); err == nil {
		t.Fatal("expected /etc/passwd rejected")
	}
	// Empty uses default (may or may not exist).
	p, err := ResolveGrokAuthPath("")
	if err != nil {
		t.Fatal(err)
	}
	if p == "" {
		t.Fatal("empty path should resolve to default")
	}
	// data_dir root allowed when provided.
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"key":"a","refresh_token":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveGrokAuthPath(authPath, dir)
	if err != nil {
		t.Fatalf("data_dir path should be allowed: %v", err)
	}
	if got == "" {
		t.Fatal("empty resolved")
	}
	// traversal out of root rejected
	if _, err := ResolveGrokAuthPath(filepath.Join(dir, "..", "outside.json"), dir); err == nil {
		// may resolve outside — must reject
		t.Fatal("expected path escape rejected")
	}
}
