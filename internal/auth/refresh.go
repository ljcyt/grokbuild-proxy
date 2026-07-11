package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// TokenPersistFunc is called after a successful refresh so callers can
// atomically compare the token material actually used by the OAuth request and
// write the new tokens (including rotated refresh tokens). This prevents an
// older in-flight refresh from overwriting a newer import or refresh.
// Returning an error prevents the result from entering the in-memory cache;
// otherwise a rotated refresh token that was never durably stored could be
// consumed again and lost.
type TokenPersistFunc func(ctx context.Context, previous TokenSet, next TokenSet) error

// TokenLoadFunc returns the durable token state for a credential immediately
// before a refresh grant is sent. It closes the gap where a caller keeps an
// old credential snapshot after cache invalidation and would otherwise reuse a
// refresh token that has already been rotated and persisted.
type TokenLoadFunc func(ctx context.Context) (TokenSet, error)

// Refresher performs singleflight token refresh per credential/refresh-token key.
type Refresher struct {
	OAuth *OAuthClient
	// OAuthFor resolves a credential-specific OAuth client by refresh key.
	// It is used for per-credential proxy/issuer/client-id routing.
	OAuthFor func(key string) (*OAuthClient, error)
	// Skew is how early tokens are considered expired. Zero uses DefaultRefreshSkew.
	Skew time.Duration
	// Timeout bounds the shared refresh operation. Zero uses DefaultHTTPTimeout.
	Timeout time.Duration
	// Now is optional clock injection for tests.
	Now func() time.Time

	group singleflight.Group

	mu         sync.Mutex
	cache      map[string]TokenSet // keyed by flight key
	generation uint64
	keyEpoch   map[string]uint64
}

var ErrRefreshInvalidated = errors.New("auth refresh: invalidated while in progress")

// EnsureAccess returns a non-expired access token.
// If current is still valid (respecting skew), it is returned as-is.
// Otherwise a singleflight refresh is performed for the refresh token.
//
// key should uniquely identify the credential (e.g. credential id). When empty,
// the refresh token itself is used as the flight key.
// persist may be nil; when set it is invoked once per successful refresh.
func (r *Refresher) EnsureAccess(ctx context.Context, key string, current TokenSet, load TokenLoadFunc, persist TokenPersistFunc) (TokenSet, error) {
	if r == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil refresher")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := r.now()
	skew := r.skew()
	// Prefer in-process cache after a concurrent refresh (avoid stale RT from caller's snapshot).
	flightKey := strings.TrimSpace(key)
	if flightKey == "" {
		flightKey = strings.TrimSpace(current.RefreshToken)
	}
	if flightKey != "" {
		if cached, ok := r.Cached(flightKey); ok {
			if strings.TrimSpace(cached.AccessToken) != "" && !cached.Expired(now, skew) {
				return cached, nil
			}
			if strings.TrimSpace(cached.RefreshToken) != "" {
				current.RefreshToken = cached.RefreshToken
				if strings.TrimSpace(cached.AccessToken) != "" {
					current.AccessToken = cached.AccessToken
				}
				if !cached.ExpiresAt.IsZero() {
					current.ExpiresAt = cached.ExpiresAt
				}
			}
		}
	}
	// Check the caller snapshot only after the shared cache. A request may have
	// loaded this snapshot before another request completed a refresh; returning
	// it first would ignore the newer token and can trigger a staggered refresh
	// storm as those stale snapshots reach their skew window.
	if strings.TrimSpace(current.AccessToken) != "" && !current.Expired(now, skew) {
		return current, nil
	}
	if strings.TrimSpace(current.RefreshToken) == "" {
		return TokenSet{}, fmt.Errorf("auth refresh: access expired and no refresh_token")
	}
	return r.ForceRefresh(ctx, key, current, load, persist)
}

// ForceRefresh always performs a singleflight refresh for the given token set.
func (r *Refresher) ForceRefresh(ctx context.Context, key string, current TokenSet, load TokenLoadFunc, persist TokenPersistFunc) (TokenSet, error) {
	if r == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil refresher")
	}
	if r.OAuth == nil && r.OAuthFor == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil oauth client")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(current.RefreshToken) == "" {
		return TokenSet{}, fmt.Errorf("auth refresh: refresh_token is required")
	}

	flightKey := strings.TrimSpace(key)
	if flightKey == "" {
		flightKey = strings.TrimSpace(current.RefreshToken)
	}
	generation, keyEpoch := r.currentGenerations(flightKey)
	// The grant mutex key must remain stable across invalidation. Starting a new
	// flight with the same rotating refresh token while the old one is still on
	// the wire can trigger token-reuse detection or lose whichever rotation wins
	// at the provider. Epochs govern cache visibility, not network concurrency.
	groupKey := flightKey

	// Deduplicate concurrent refresh for the same credential.
	// Note: singleflight shares the same result; refresh_token rotation is safe
	// because only one network call runs.
	//
	// ForceRefresh must hit the network (401 / admin force). Do not return a
	// still-unexpired cached access token — that may be the exact token that
	// just failed upstream. Only borrow a newer refresh_token from cache so
	// concurrent EnsureAccess rotations are not overwritten with a stale RT.
	resultCh := r.group.DoChan(groupKey, func() (any, error) {
		previous := current
		if cached, ok := r.Cached(flightKey); ok {
			if rt := strings.TrimSpace(cached.RefreshToken); rt != "" {
				previous.RefreshToken = rt
				if strings.TrimSpace(cached.AccessToken) != "" {
					previous.AccessToken = cached.AccessToken
				}
				if !cached.ExpiresAt.IsZero() {
					previous.ExpiresAt = cached.ExpiresAt
				}
			}
		}
		// A shared operation must outlive any one waiter, but it still needs a
		// hard deadline so a stuck token endpoint cannot hold the flight forever.
		opCtx, cancel := context.WithTimeout(context.Background(), r.timeout())
		defer cancel()
		if load != nil {
			durable, err := load(opCtx)
			if err != nil {
				return nil, fmt.Errorf("auth refresh: load durable token: %w", err)
			}
			if tokenMaterialChanged(previous, durable) {
				// Do not send the caller's stale refresh token. Returning the durable
				// state with an invalidation error makes the caller reload/retry while
				// preserving the latest token family.
				return &durable, ErrRefreshInvalidated
			}
			previous = durable
		}
		if !r.generationsCurrent(flightKey, generation, keyEpoch) {
			return &previous, ErrRefreshInvalidated
		}
		refreshToken := strings.TrimSpace(previous.RefreshToken)
		if refreshToken == "" {
			return nil, fmt.Errorf("auth refresh: durable refresh_token is required")
		}
		oauth := r.OAuth
		if r.OAuthFor != nil {
			resolved, err := r.OAuthFor(flightKey)
			if err != nil {
				return nil, fmt.Errorf("auth refresh: resolve client: %w", err)
			}
			oauth = resolved
		}
		if oauth == nil {
			return nil, fmt.Errorf("auth refresh: nil oauth client")
		}
		next, err := oauth.Refresh(opCtx, refreshToken)
		if err != nil {
			return nil, err
		}
		// Preserve prior refresh token if server omitted rotation.
		if strings.TrimSpace(next.RefreshToken) == "" {
			next.RefreshToken = refreshToken
		}
		if err := r.commitIfCurrent(opCtx, flightKey, previous, *next, generation, keyEpoch, persist); err != nil {
			return next, err
		}
		return next, nil
	})
	var v any
	var err error
	select {
	case <-ctx.Done():
		return TokenSet{}, ctx.Err()
	case result := <-resultCh:
		v, err = result.Val, result.Err
	}
	if err != nil {
		// If persist failed but we have tokens, try to surface them.
		if ts, ok := v.(*TokenSet); ok && ts != nil && strings.TrimSpace(ts.AccessToken) != "" {
			return *ts, err
		}
		return TokenSet{}, err
	}
	ts, ok := v.(*TokenSet)
	if !ok || ts == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: invalid singleflight result")
	}
	return *ts, nil
}

func tokenMaterialChanged(left, right TokenSet) bool {
	return strings.TrimSpace(left.AccessToken) != strings.TrimSpace(right.AccessToken) ||
		strings.TrimSpace(left.RefreshToken) != strings.TrimSpace(right.RefreshToken)
}

// Cached returns the last successful refresh result for key, if any.
func (r *Refresher) Cached(key string) (TokenSet, bool) {
	if r == nil {
		return TokenSet{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		return TokenSet{}, false
	}
	ts, ok := r.cache[key]
	return ts, ok
}

// Invalidate forgets cached token material after an import, proxy change, or reactivation.
func (r *Refresher) Invalidate(key string) {
	if r == nil {
		return
	}
	key = strings.TrimSpace(key)
	r.mu.Lock()
	if r.keyEpoch == nil {
		r.keyEpoch = make(map[string]uint64)
	}
	r.keyEpoch[key]++
	if r.cache != nil {
		delete(r.cache, key)
	}
	r.mu.Unlock()
}

func (r *Refresher) InvalidateAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = make(map[string]TokenSet)
	r.generation++
	r.keyEpoch = make(map[string]uint64)
	r.mu.Unlock()
}

func (r *Refresher) currentGenerations(key string) (uint64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation, r.keyEpoch[key]
}

func (r *Refresher) generationsCurrent(key string, generation, keyEpoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation == generation && r.keyEpoch[key] == keyEpoch
}

func (r *Refresher) commitIfCurrent(
	ctx context.Context,
	key string,
	previous TokenSet,
	ts TokenSet,
	generation uint64,
	keyEpoch uint64,
	persist TokenPersistFunc,
) error {
	// A successful OAuth response may already have rotated the provider-side
	// refresh token. Always attempt the caller's token CAS before consulting the
	// cache epoch; dropping the response here would leave only the now-invalid
	// previous token on disk. Persist must not run under r.mu because it performs
	// storage I/O and admin invalidation also needs this mutex.
	if persist != nil {
		if err := persist(ctx, previous, ts); err != nil {
			if errors.Is(err, ErrRefreshInvalidated) {
				return err
			}
			return fmt.Errorf("auth refresh: persist: %w", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.generation != generation || r.keyEpoch[key] != keyEpoch {
		return ErrRefreshInvalidated
	}
	if r.cache == nil {
		r.cache = make(map[string]TokenSet)
	}
	r.cache[key] = ts
	return nil
}

func (r *Refresher) store(key string, ts TokenSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = make(map[string]TokenSet)
	}
	r.cache[key] = ts
}

func (r *Refresher) now() time.Time {
	if r != nil && r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Refresher) skew() time.Duration {
	if r != nil && r.Skew > 0 {
		return r.Skew
	}
	return DefaultRefreshSkew
}

func (r *Refresher) timeout() time.Duration {
	if r != nil && r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultHTTPTimeout
}
