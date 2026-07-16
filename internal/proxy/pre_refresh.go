package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

// PreRefresher renews refreshable OAuth credentials before client traffic needs
// them. It deliberately does not disable or quarantine accounts: normal request
// and inspection paths remain the authority for health decisions.
type PreRefresher struct {
	Store interface {
		ListCredentials() ([]storage.Credential, error)
	}
	Executor interface {
		EnsureToken(context.Context, storage.Credential) (auth.TokenSet, error)
	}
	Skew        time.Duration
	Interval    time.Duration
	Concurrency int
	Timeout     time.Duration
	Logger      *slog.Logger

	mu           sync.Mutex
	failureCount map[string]int
	nextAttempt  map[string]time.Time
	now          func() time.Time
}

// Run executes a low-cost periodic scan. It starts after a short delay so
// server startup is not held by OAuth work.
func (p *PreRefresher) Run(ctx context.Context) {
	if p == nil || p.Store == nil || p.Executor == nil {
		return
	}
	interval := p.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	timer := time.NewTimer(minDuration(10*time.Second, interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if _, err := p.RunOnce(ctx); err != nil && p.Logger != nil && ctx.Err() == nil {
				p.Logger.Warn("credential_pre_refresh_failed", "error", err)
			}
			timer.Reset(interval)
		}
	}
}

// RunOnce is exported for deterministic tests and operator-triggered use.
func (p *PreRefresher) RunOnce(ctx context.Context) (int, error) {
	if p == nil || p.Store == nil || p.Executor == nil {
		return 0, fmt.Errorf("proxy: pre-refresher is not configured")
	}
	now := p.clock()
	skew := p.Skew
	if skew <= 0 {
		return 0, nil
	}
	credentials, err := p.Store.ListCredentials()
	if err != nil {
		return 0, err
	}
	due := make([]storage.Credential, 0)
	for _, credential := range credentials {
		if !credential.Enabled || credential.ManualDisabled || strings.TrimSpace(credential.RefreshToken) == "" || credential.ExpiresAt.IsZero() || credential.ExpiresAt.After(now.Add(skew)) {
			continue
		}
		if p.retryAfter(credential.ID).After(now) {
			continue
		}
		due = append(due, credential)
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ExpiresAt.Before(due[j].ExpiresAt) })
	if len(due) == 0 {
		return 0, nil
	}
	workers := p.Concurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > len(due) {
		workers = len(due)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	jobs := make(chan storage.Credential)
	var wg sync.WaitGroup
	var refreshed int
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range jobs {
				workCtx, cancel := context.WithTimeout(ctx, timeout)
				_, refreshErr := p.Executor.EnsureToken(workCtx, credential)
				cancel()
				if refreshErr != nil {
					p.recordFailure(credential.ID, now)
					if p.Logger != nil {
						p.Logger.Debug("credential_pre_refresh_credential_failed", "credential_id", credential.ID, "error", refreshErr)
					}
					continue
				}
				p.recordSuccess(credential.ID)
				p.mu.Lock()
				refreshed++
				p.mu.Unlock()
			}
		}()
	}
	for _, credential := range due {
		if ctx.Err() != nil {
			break
		}
		jobs <- credential
	}
	close(jobs)
	wg.Wait()
	return refreshed, ctx.Err()
}

func (p *PreRefresher) clock() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}
	return time.Now().UTC()
}

func (p *PreRefresher) retryAfter(id string) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nextAttempt[id]
}

func (p *PreRefresher) recordSuccess(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.failureCount, id)
	delete(p.nextAttempt, id)
}

func (p *PreRefresher) recordFailure(id string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failureCount == nil {
		p.failureCount = make(map[string]int)
		p.nextAttempt = make(map[string]time.Time)
	}
	p.failureCount[id]++
	failures := min(p.failureCount[id]-1, 4)
	backoff := 30 * time.Second * time.Duration(1<<failures)
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}
	p.nextAttempt[id] = now.Add(backoff)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
