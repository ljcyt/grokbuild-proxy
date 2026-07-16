package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type preRefreshStore struct{ credentials []storage.Credential }

func (s preRefreshStore) ListCredentials() ([]storage.Credential, error) {
	return append([]storage.Credential(nil), s.credentials...), nil
}

type preRefreshExecutor struct{ calls []string }

func (e *preRefreshExecutor) EnsureToken(_ context.Context, credential storage.Credential) (auth.TokenSet, error) {
	e.calls = append(e.calls, credential.ID)
	return auth.TokenSet{}, nil
}

func TestPreRefresherOnlyRefreshesDueRefreshableCredentials(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	executor := &preRefreshExecutor{}
	runner := &PreRefresher{
		Store: preRefreshStore{credentials: []storage.Credential{
			{ID: "due", Enabled: true, RefreshToken: "refresh", ExpiresAt: now.Add(time.Minute)},
			{ID: "later", Enabled: true, RefreshToken: "refresh", ExpiresAt: now.Add(time.Hour)},
			{ID: "missing", Enabled: true, ExpiresAt: now.Add(time.Minute)},
			{ID: "disabled", Enabled: false, RefreshToken: "refresh", ExpiresAt: now.Add(time.Minute)},
		}},
		Executor: executor, Skew: 2 * time.Minute, Concurrency: 2,
	}
	runner.now = func() time.Time { return now }
	count, err := runner.RunOnce(context.Background())
	if err != nil || count != 1 || len(executor.calls) != 1 || executor.calls[0] != "due" {
		t.Fatalf("count=%d calls=%v err=%v", count, executor.calls, err)
	}
}
