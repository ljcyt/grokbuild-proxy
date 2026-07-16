// Package proxy provides the multi-credential upstream executor used by OpenAI/Anthropic handlers.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
	"golang.org/x/sync/singleflight"
)

// DefaultMaxAttempts is the max number of credential picks for a single Post.
const DefaultMaxAttempts = 10

// billingSnapshotTimeout bounds the shared admin billing lookup. It is kept
// separate from request forwarding so a slow diagnostics endpoint cannot hold
// credential refresh or proxy work indefinitely.
const billingSnapshotTimeout = 30 * time.Second

// ErrUpgradeRequired is returned when upstream responds 426 (protocol upgrade required).
var ErrUpgradeRequired = errors.New("proxy: upstream requires protocol upgrade (426)")

// Store is the subset of storage used by the executor.
type Store interface {
	ListCredentials() ([]storage.Credential, error)
	ListCredentialCandidates() ([]storage.Credential, error)
	GetCredential(id string) (storage.Credential, error)
	UpdateCredential(c storage.Credential) (storage.Credential, error)
	// PatchCredential applies a mutation under a single store lock (preferred for concurrent updates).
	PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error)
}

// Selector is the subset of lb.Selector used by the executor.
type Selector interface {
	Pick(creds []storage.Credential, stickyKey string, now time.Time) (storage.Credential, error)
	MarkSuccess(credID, stickyKey string, now time.Time)
	MarkFailure(credID string, status int, retryAfter time.Duration, now time.Time)
}

type selectorReleaser interface {
	Release(credID string)
}

type quotaExhaustionMarker interface {
	MarkQuotaExhausted(credID string, now time.Time)
}

type quotaExhaustionUntilMarker interface {
	MarkQuotaExhaustedUntil(credID string, now time.Time, resetAt time.Time)
}

type successHoldingSelector interface {
	HoldSuccessfulResponse() bool
	MarkSuccessHold(credID, stickyKey string, now time.Time)
}

// Upstream is the subset of upstream.Client used by the executor.
type Upstream interface {
	PostResponses(ctx context.Context, body any, opts upstream.PostResponsesOptions) (*http.Response, error)
	ListModels(ctx context.Context, accessToken string) (*upstream.ModelList, error)
	GetBilling(ctx context.Context, accessToken string) (*upstream.MonthlyBilling, error)
	GetBillingCredits(ctx context.Context, accessToken string) (*upstream.WeeklyCredits, error)
	GetBillingSnapshot(ctx context.Context, accessToken string) (*upstream.BillingSnapshot, error)
}

type compactUpstream interface {
	PostResponsesCompact(ctx context.Context, body any, opts upstream.PostResponsesOptions) (*http.Response, error)
}

// TokenRefresher is the subset of auth.Refresher used by the executor.
type TokenRefresher interface {
	EnsureAccess(ctx context.Context, key string, current auth.TokenSet, load auth.TokenLoadFunc, persist auth.TokenPersistFunc) (auth.TokenSet, error)
	ForceRefresh(ctx context.Context, key string, current auth.TokenSet, load auth.TokenLoadFunc, persist auth.TokenPersistFunc) (auth.TokenSet, error)
}

type UpstreamResolver func(credential storage.Credential) (Upstream, error)

// Executor selects credentials, refreshes tokens, and posts to upstream /v1/responses.
type Executor struct {
	Store    Store
	Selector Selector
	Upstream Upstream
	// UpstreamFor overrides Upstream with a credential-routed client.
	UpstreamFor UpstreamResolver
	Refresher   TokenRefresher
	// MaxAttempts caps credential failover. Zero uses DefaultMaxAttempts.
	MaxAttempts int
	// Now is optional clock injection for tests.
	Now func() time.Time
	// Logger receives credential-selection outcomes without request bodies/tokens.
	Logger *slog.Logger
	// RequestID extracts a correlation ID from ctx.
	RequestID func(context.Context) string
	// RouteRevision returns a monotonic runtime-route revision. It lets a 401
	// retry detect a global proxy change and restart instead of sending a newly
	// refreshed access token through a transport resolved under old settings.
	RouteRevision func() uint64
	// BodyPatch optionally rewrites the upstream Responses body after protocol
	// translation (raw JSON path overrides such as tools.-1).
	BodyPatch func(body []byte, model string) ([]byte, error)
	// CandidateCacheTTL bounds how long the secret-free candidate view is reused.
	// Zero uses a conservative 250ms default.
	CandidateCacheTTL time.Duration

	usageMu         sync.Mutex
	lastUsed        map[string]time.Time
	billingFlight   singleflight.Group
	candidateMu     sync.Mutex
	candidates      []storage.Credential
	candidatesTill  time.Time
	candidateTTL    time.Duration
	candidateFlight singleflight.Group
}

// Post implements openai.PostResponsesFunc / anthropic.PostResponsesFunc.
//
// It may switch credentials on 401/429/5xx only before the response is returned
// to the caller (body not yet delivered). After a successful 2xx, MarkSuccess is
// recorded. 426 is never failed-over; the original response is returned.
func (e *Executor) Post(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
	return e.post(ctx, model, convID, body, stream, false)
}

// PostCompact implements the OpenAI Responses compact endpoint using the same
// credential selection, refresh, quota handling, and failover path as Post.
func (e *Executor) PostCompact(ctx context.Context, model, convID string, body []byte, stream bool) (*http.Response, error) {
	if stream {
		return nil, fmt.Errorf("proxy: responses compact does not support streaming")
	}
	return e.post(ctx, model, convID, body, false, true)
}

func (e *Executor) post(ctx context.Context, model, convID string, body []byte, stream, compact bool) (*http.Response, error) {
	if e == nil {
		return nil, fmt.Errorf("proxy: nil executor")
	}
	if e.Store == nil || e.Selector == nil || (e.Upstream == nil && e.UpstreamFor == nil) {
		return nil, fmt.Errorf("proxy: executor not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e.BodyPatch != nil {
		patched, err := e.BodyPatch(body, model)
		if err != nil {
			return nil, err
		}
		body = patched
	}

	maxAttempts := e.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}

	tried := make(map[string]struct{})
	var lastErr error
	var lastResp *http.Response
	idempotencyKey := newIdempotencyKey()
	candidates, err := e.listCredentialCandidates()
	if err != nil {
		return nil, fmt.Errorf("proxy: list credential candidates: %w", err)
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Exclude already-tried credentials from this request.
		filtered := make([]storage.Credential, 0, len(candidates))
		for _, c := range candidates {
			if _, ok := tried[c.ID]; ok {
				continue
			}
			filtered = append(filtered, c)
		}

		now := e.now()
		cred, err := e.Selector.Pick(filtered, convID, now)
		if err != nil {
			if lastResp != nil {
				return lastResp, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		tried[cred.ID] = struct{}{}
		selectionCompleted := false
		releaseSelection := func() {
			if selectionCompleted {
				return
			}
			if releaser, ok := e.Selector.(selectorReleaser); ok {
				releaser.Release(cred.ID)
			}
			selectionCompleted = true
		}
		markSuccess := func(resp *http.Response) {
			if holder, ok := e.Selector.(successHoldingSelector); ok && holder.HoldSuccessfulResponse() && resp != nil && resp.Body != nil {
				holder.MarkSuccessHold(cred.ID, convID, e.now())
				if releaser, ok := e.Selector.(selectorReleaser); ok {
					resp.Body = &releaseOnClose{ReadCloser: resp.Body, release: func() { releaser.Release(cred.ID) }}
				} else {
					e.Selector.MarkSuccess(cred.ID, convID, e.now())
				}
			} else {
				e.Selector.MarkSuccess(cred.ID, convID, e.now())
			}
			selectionCompleted = true
		}
		markFailure := func(status int, retryAfter time.Duration) {
			e.Selector.MarkFailure(cred.ID, status, retryAfter, e.now())
			selectionCompleted = true
		}
		e.log(ctx, slog.LevelDebug, "credential_selected",
			"credential_id", cred.ID,
			"attempt", attempt+1,
		)
		selected, gerr := e.Store.GetCredential(cred.ID)
		if gerr != nil {
			lastErr = gerr
			releaseSelection()
			continue
		}
		cred = selected

		tokens, err := e.EnsureToken(ctx, cred)
		if err != nil {
			lastErr = err
			e.log(ctx, slog.LevelWarn, "credential_token_failed",
				"credential_id", cred.ID,
				"attempt", attempt+1,
				"error", err,
			)
			// Invalidation means a concurrent admin/import mutation retired this
			// caller's view. Retry selection without penalizing the credential; the
			// successful rotation, if any, has already been CAS-persisted.
			if errors.Is(err, auth.ErrRefreshInvalidated) {
				releaseSelection()
				delete(tried, cred.ID)
				continue
			}
			// Only cool down if store still has the same (failed) refresh material;
			// a concurrent refresh may already have rotated tokens successfully.
			if latest, gerr := e.Store.GetCredential(cred.ID); gerr == nil {
				if strings.TrimSpace(latest.RefreshToken) != "" &&
					strings.TrimSpace(latest.RefreshToken) != strings.TrimSpace(cred.RefreshToken) {
					releaseSelection()
					delete(tried, cred.ID)
					continue
				}
			}
			markFailure(http.StatusUnauthorized, 0)
			continue
		}
		// Bind the request to one durable token/revision snapshot. If an import or
		// admin mutation won after EnsureToken returned, restart without sending
		// the superseded in-memory token.
		latest, gerr := e.Store.GetCredential(cred.ID)
		if gerr != nil {
			lastErr = gerr
			releaseSelection()
			continue
		}
		if !latest.Enabled || latest.ManualDisabled || !tokenMatchesCredential(tokens, latest) {
			lastErr = auth.ErrRefreshInvalidated
			if latest.Enabled && !latest.ManualDisabled {
				delete(tried, cred.ID)
			}
			releaseSelection()
			continue
		}
		cred = latest
		routeRevisionBeforeResolve := e.routeRevision()
		selectedUpstream, err := e.upstreamFor(cred)
		if err != nil {
			lastErr = err
			markFailure(0, 0)
			continue
		}
		selectedRouteRevision := e.routeRevision()
		verifiedCredential, verr := e.Store.GetCredential(cred.ID)
		if verr != nil || selectedRouteRevision != routeRevisionBeforeResolve ||
			e.routeRevision() != selectedRouteRevision ||
			verifiedCredential.Revision != cred.Revision || !verifiedCredential.Enabled ||
			verifiedCredential.ManualDisabled || !tokenMatchesCredential(tokens, verifiedCredential) {
			lastErr = auth.ErrRefreshInvalidated
			if verr == nil && verifiedCredential.Enabled && !verifiedCredential.ManualDisabled {
				delete(tried, cred.ID)
			}
			releaseSelection()
			continue
		}
		cred = verifiedCredential
		resp, err := e.postUpstream(selectedUpstream, compact, ctx, body, upstream.PostResponsesOptions{
			AccessToken:  verifiedCredential.AccessToken,
			Model:        model,
			ConvID:       convID,
			Stream:       stream,
			ExtraHeaders: idempotencyHeaders(idempotencyKey),
		})
		if err != nil {
			lastErr = err
			e.log(ctx, slog.LevelWarn, "upstream_request_failed",
				"credential_id", cred.ID,
				"attempt", attempt+1,
				"error", err,
			)
			markFailure(0, 0)
			continue
		}

		// 426: do not failover; return original response (or typed error if nil).
		if resp.StatusCode == http.StatusUpgradeRequired {
			releaseSelection()
			return resp, nil
		}

		// Success path.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			e.log(ctx, slog.LevelDebug, "upstream_request_succeeded",
				"credential_id", cred.ID,
				"attempt", attempt+1,
				"upstream_status", resp.StatusCode,
			)
			// Free-tier X-Ratelimit-* headers are only present on Responses.
			// Persist the snapshot always; if remaining hits 0 after this successful
			// turn, cool the account down so the next turn switches credentials
			// before the client sees chat-endpoint Forbidden.
			if exhausted, resetAfter := e.observeRateLimit(cred.ID, resp.Header); exhausted {
				e.log(ctx, slog.LevelInfo, "credential_rate_limit_exhausted",
					"credential_id", cred.ID,
					"attempt", attempt+1,
				)
				// This successful response is still returned; the next turn switches.
				e.markQuotaExhausted(cred.ID, resetAfter)
			} else {
				markSuccess(resp)
			}
			_ = e.touchLastUsed(cred)
			return resp, nil
		}

		// 401: force refresh once on the same credential, then retry once.
		if resp.StatusCode == http.StatusUnauthorized {
			unauthorizedResp := bufferErrorResponse(resp)
			latest, gerr := e.Store.GetCredential(cred.ID)
			if gerr != nil {
				lastErr = gerr
				lastResp = unauthorizedResp
				releaseSelection()
				continue
			}
			// A completed disable/quarantine or credential/global route mutation
			// retires the original 401 attempt. Restart selection without issuing a
			// fresh OAuth grant under a state the operator has already replaced.
			if !latest.Enabled || latest.ManualDisabled || latest.Revision != cred.Revision ||
				e.routeRevision() != selectedRouteRevision {
				lastErr = auth.ErrRefreshInvalidated
				lastResp = unauthorizedResp
				if latest.Enabled && !latest.ManualDisabled {
					delete(tried, cred.ID)
				}
				releaseSelection()
				continue
			}
			refreshed, rerr := e.forceRefresh(ctx, latest)
			if rerr != nil {
				lastErr = rerr
				lastResp = unauthorizedResp
				if errors.Is(rerr, auth.ErrRefreshInvalidated) {
					releaseSelection()
					delete(tried, cred.ID)
					continue
				}
				markFailure(http.StatusUnauthorized, 0)
				continue
			}
			// Refresh persistence increments the credential revision. Reload both
			// credential and route before retrying, then perform one last revision
			// check to close the refresh-to-request transition window.
			retryCredential, gerr := e.Store.GetCredential(cred.ID)
			if gerr != nil || !retryCredential.Enabled || retryCredential.ManualDisabled ||
				!tokenMatchesCredential(refreshed, retryCredential) {
				lastErr = auth.ErrRefreshInvalidated
				lastResp = unauthorizedResp
				if gerr == nil && retryCredential.Enabled && !retryCredential.ManualDisabled {
					delete(tried, cred.ID)
				}
				releaseSelection()
				continue
			}
			retryRouteRevision := e.routeRevision()
			retryUpstream, uerr := e.upstreamFor(retryCredential)
			if uerr != nil {
				lastErr = uerr
				lastResp = unauthorizedResp
				releaseSelection()
				continue
			}
			verifiedCredential, verr := e.Store.GetCredential(cred.ID)
			if verr != nil || verifiedCredential.Revision != retryCredential.Revision ||
				!verifiedCredential.Enabled || verifiedCredential.ManualDisabled ||
				e.routeRevision() != retryRouteRevision ||
				!tokenMatchesCredential(refreshed, verifiedCredential) {
				lastErr = auth.ErrRefreshInvalidated
				lastResp = unauthorizedResp
				if verr == nil && verifiedCredential.Enabled && !verifiedCredential.ManualDisabled {
					delete(tried, cred.ID)
				}
				releaseSelection()
				continue
			}
			retry, rerr := e.postUpstream(retryUpstream, compact, ctx, body, upstream.PostResponsesOptions{
				AccessToken:  verifiedCredential.AccessToken,
				Model:        model,
				ConvID:       convID,
				Stream:       stream,
				ExtraHeaders: idempotencyHeaders(idempotencyKey),
			})
			if rerr != nil {
				lastErr = rerr
				markFailure(http.StatusUnauthorized, 0)
				continue
			}
			if retry.StatusCode >= 200 && retry.StatusCode < 300 {
				if exhausted, resetAfter := e.observeRateLimit(cred.ID, retry.Header); exhausted {
					e.markQuotaExhausted(cred.ID, resetAfter)
				} else {
					markSuccess(retry)
				}
				_ = e.touchLastUsed(cred)
				return retry, nil
			}
			if retry.StatusCode == http.StatusUpgradeRequired {
				releaseSelection()
				return retry, nil
			}
			// Still failing after refresh → mark and switch credentials.
			ra := parseRetryAfterAt(retry.Header.Get("Retry-After"), e.now())
			status := retry.StatusCode
			lastResp = bufferErrorResponse(retry)
			if exhausted, resetAfter := e.observeRateLimit(cred.ID, retry.Header); exhausted || isChatEndpointQuotaDenied(lastResp) {
				e.markQuotaExhausted(cred.ID, resetAfter)
			} else {
				markFailure(status, ra)
			}
			e.log(ctx, slog.LevelWarn, "upstream_retryable_status",
				"credential_id", cred.ID,
				"attempt", attempt+1,
				"upstream_status", status,
				"retry_after_ms", ra.Milliseconds(),
			)
			lastErr = fmt.Errorf("proxy: upstream status %d after refresh", status)
			continue
		}

		// Retryable statuses before body delivery: 429 / 5xx / 403.
		if isRetryableStatus(resp.StatusCode) {
			ra := parseRetryAfterAt(resp.Header.Get("Retry-After"), e.now())
			status := resp.StatusCode
			lastResp = bufferErrorResponse(resp)
			// Capture free-tier remaining counters when present (often missing on errors).
			if exhausted, resetAfter := e.observeRateLimit(cred.ID, resp.Header); exhausted || isChatEndpointQuotaDenied(lastResp) {
				e.markQuotaExhausted(cred.ID, resetAfter)
			} else {
				markFailure(status, ra)
			}
			e.log(ctx, slog.LevelWarn, "upstream_retryable_status",
				"credential_id", cred.ID,
				"attempt", attempt+1,
				"upstream_status", status,
				"retry_after_ms", ra.Milliseconds(),
			)
			lastErr = fmt.Errorf("proxy: upstream status %d", status)
			continue
		}

		// Non-retryable error: return as-is for the handler to map.
		releaseSelection()
		return resp, nil
	}

	if lastResp != nil {
		return lastResp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, lb.ErrNoCredential
}

func (e *Executor) postUpstream(client Upstream, compact bool, ctx context.Context, body []byte, opts upstream.PostResponsesOptions) (*http.Response, error) {
	if !compact {
		return client.PostResponses(ctx, body, opts)
	}
	compactClient, ok := client.(compactUpstream)
	if !ok {
		return nil, fmt.Errorf("proxy: upstream compact endpoint is not configured")
	}
	return compactClient.PostResponsesCompact(ctx, body, opts)
}

func (e *Executor) listCredentialCandidates() ([]storage.Credential, error) {
	if e == nil || e.Store == nil {
		return nil, fmt.Errorf("proxy: credential store is not configured")
	}
	ttl := e.CandidateCacheTTL
	if ttl <= 0 {
		ttl = 250 * time.Millisecond
	}
	now := e.now()
	e.candidateMu.Lock()
	if now.Before(e.candidatesTill) {
		values := append([]storage.Credential(nil), e.candidates...)
		e.candidateMu.Unlock()
		return values, nil
	}
	e.candidateMu.Unlock()

	loaded, err, _ := e.candidateFlight.Do("credential-candidates", func() (any, error) {
		checkNow := e.now()
		e.candidateMu.Lock()
		if checkNow.Before(e.candidatesTill) {
			values := append([]storage.Credential(nil), e.candidates...)
			e.candidateMu.Unlock()
			return values, nil
		}
		e.candidateMu.Unlock()
		values, err := e.Store.ListCredentialCandidates()
		if err != nil {
			return nil, err
		}
		e.candidateMu.Lock()
		e.candidates = append(e.candidates[:0], values...)
		e.candidatesTill = checkNow.Add(ttl)
		e.candidateMu.Unlock()
		return values, nil
	})
	if err != nil {
		return nil, err
	}
	return append([]storage.Credential(nil), loaded.([]storage.Credential)...), nil
}

type releaseOnClose struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (r *releaseOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		if r.release != nil {
			r.release()
		}
	})
	return err
}

// EnsureToken ensures a non-expired access token for the given credential,
// persisting rotated tokens via Store.UpdateCredential.
func (e *Executor) EnsureToken(ctx context.Context, cred storage.Credential) (auth.TokenSet, error) {
	if e == nil || e.Refresher == nil {
		// No refresher: return stored tokens as-is.
		return auth.TokenSet{
			AccessToken:  cred.AccessToken,
			RefreshToken: cred.RefreshToken,
			ExpiresAt:    cred.ExpiresAt,
			TokenType:    "Bearer",
		}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current := auth.TokenSet{
		AccessToken:  cred.AccessToken,
		RefreshToken: cred.RefreshToken,
		ExpiresAt:    cred.ExpiresAt,
		TokenType:    "Bearer",
	}
	return e.Refresher.EnsureAccess(ctx, cred.ID, current, e.loadFunc(cred.ID), e.persistFunc(cred.ID))
}

// EnsureTokenByID loads a credential and ensures a valid access token.
func (e *Executor) EnsureTokenByID(ctx context.Context, credID string) (auth.TokenSet, storage.Credential, error) {
	if e == nil || e.Store == nil {
		return auth.TokenSet{}, storage.Credential{}, fmt.Errorf("proxy: executor not configured")
	}
	cred, err := e.Store.GetCredential(credID)
	if err != nil {
		return auth.TokenSet{}, storage.Credential{}, err
	}
	ts, err := e.EnsureToken(ctx, cred)
	if err != nil {
		return auth.TokenSet{}, cred, err
	}
	if latest, gerr := e.Store.GetCredential(credID); gerr == nil {
		cred = latest
	}
	return ts, cred, nil
}

// ForceRefreshToken forces an OAuth refresh for admin use.
func (e *Executor) ForceRefreshToken(ctx context.Context, credID string) (auth.TokenSet, storage.Credential, error) {
	if e == nil || e.Store == nil {
		return auth.TokenSet{}, storage.Credential{}, fmt.Errorf("proxy: executor not configured")
	}
	cred, err := e.Store.GetCredential(credID)
	if err != nil {
		return auth.TokenSet{}, storage.Credential{}, err
	}
	ts, err := e.forceRefresh(ctx, cred)
	if err != nil {
		return auth.TokenSet{}, cred, err
	}
	if latest, gerr := e.Store.GetCredential(credID); gerr == nil {
		cred = latest
	}
	return ts, cred, nil
}

// RefreshCredential forces an OAuth refresh for the inspection runner.
// Unlike ForceRefreshToken, it exposes only the token set required by the
// inspection.Prober contract.
func (e *Executor) RefreshCredential(ctx context.Context, credID string) (auth.TokenSet, error) {
	ts, _, err := e.ForceRefreshToken(ctx, credID)
	return ts, err
}

// RefreshCredentialSnapshot refreshes from an inspection run snapshot and
// returns the final durable credential revision. The normal healthy path never
// calls this method; 401 handling pays at most the extra durable reload.
func (e *Executor) RefreshCredentialSnapshot(ctx context.Context, credential storage.Credential) (auth.TokenSet, storage.Credential, error) {
	latest, loadErr := e.Store.GetCredential(credential.ID)
	if loadErr != nil {
		return auth.TokenSet{}, credential, loadErr
	}
	if !inspectionCredentialGuardMatches(credential, latest) {
		return auth.TokenSet{}, latest, auth.ErrRefreshInvalidated
	}
	tokens, err := e.forceRefreshForInspection(ctx, latest)
	if err != nil {
		return tokens, latest, err
	}
	latest, loadErr = e.Store.GetCredential(credential.ID)
	if loadErr != nil {
		return auth.TokenSet{}, credential, loadErr
	}
	if !inspectionCredentialUsable(latest) || !tokenMatchesCredential(tokens, latest) {
		return tokens, latest, auth.ErrRefreshInvalidated
	}
	return tokens, latest, nil
}

// ListModels picks any usable credential, ensures a token, and lists upstream models.
func (e *Executor) ListModels(ctx context.Context) (*upstream.ModelList, error) {
	if e == nil || e.Store == nil || e.Selector == nil {
		return nil, fmt.Errorf("proxy: executor not configured")
	}
	maxAttempts := e.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	tried := make(map[string]struct{})
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		credentials, err := e.Store.ListCredentials()
		if err != nil {
			return nil, err
		}
		filtered := make([]storage.Credential, 0, len(credentials))
		for _, credential := range credentials {
			if _, seen := tried[credential.ID]; !seen {
				filtered = append(filtered, credential)
			}
		}
		credential, err := e.Selector.Pick(filtered, "", e.now())
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		tried[credential.ID] = struct{}{}
		selectionCompleted := false
		releaseSelection := func() {
			if selectionCompleted {
				return
			}
			if releaser, ok := e.Selector.(selectorReleaser); ok {
				releaser.Release(credential.ID)
			}
			selectionCompleted = true
		}
		markSuccess := func() {
			e.Selector.MarkSuccess(credential.ID, "", e.now())
			selectionCompleted = true
		}
		markFailure := func(status int) {
			e.Selector.MarkFailure(credential.ID, status, 0, e.now())
			selectionCompleted = true
		}
		tokens, durable, err := e.ensureDurableCredential(ctx, credential, true)
		if err != nil {
			lastErr = err
			if errors.Is(err, auth.ErrRefreshInvalidated) {
				releaseSelection()
				delete(tried, credential.ID)
				continue
			}
			if status := auth.StatusCode(err); shouldMarkDiscoveryFailure(status) {
				markFailure(status)
			} else {
				releaseSelection()
			}
			continue
		}
		client, verified, err := e.resolveVerifiedUpstream(durable, tokens, true)
		if err != nil {
			lastErr = err
			if errors.Is(err, auth.ErrRefreshInvalidated) {
				releaseSelection()
				delete(tried, credential.ID)
				continue
			}
			releaseSelection()
			continue
		}
		models, err := client.ListModels(ctx, verified.AccessToken)
		if err != nil {
			lastErr = err
			if status := upstream.StatusCode(err); shouldMarkDiscoveryFailure(status) {
				markFailure(status)
			} else {
				releaseSelection()
			}
			continue
		}
		markSuccess()
		_ = e.touchLastUsed(verified)
		return models, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, lb.ErrNoCredential
}

// GetBillingSnapshot fetches billing for a specific credential id.
func (e *Executor) GetBillingSnapshot(ctx context.Context, credID string) (*upstream.BillingSnapshot, error) {
	if e == nil || e.Store == nil {
		return nil, fmt.Errorf("proxy: executor not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	credID = strings.TrimSpace(credID)
	if credID == "" {
		return nil, fmt.Errorf("proxy: credential id is required")
	}

	resultCh := e.billingFlight.DoChan(credID, func() (any, error) {
		sharedCtx, cancel := context.WithTimeout(context.Background(), billingSnapshotTimeout)
		defer cancel()
		return e.getBillingSnapshot(sharedCtx, credID)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.Err != nil {
			return nil, result.Err
		}
		snapshot, ok := result.Val.(*upstream.BillingSnapshot)
		if !ok || snapshot == nil {
			return nil, fmt.Errorf("proxy: invalid billing snapshot result")
		}
		return snapshot, nil
	}
}

func (e *Executor) getBillingSnapshot(ctx context.Context, credID string) (*upstream.BillingSnapshot, error) {
	credential, err := e.Store.GetCredential(credID)
	if err != nil {
		return nil, err
	}
	tokens, durable, err := e.ensureDurableCredential(ctx, credential, false)
	if err != nil {
		return nil, err
	}
	client, verified, err := e.resolveVerifiedUpstream(durable, tokens, false)
	if err != nil {
		return nil, err
	}
	return client.GetBillingSnapshot(ctx, verified.AccessToken)
}

// ProbeCredential validates one credential without selecting or failing over to
// another account. It returns an HTTP status when the failure is classifiable.
func (e *Executor) ProbeCredential(ctx context.Context, credID string) (int, error) {
	tokens, credential, err := e.EnsureTokenByID(ctx, credID)
	if err != nil {
		if auth.IsTerminalCredentialError(err) {
			return http.StatusUnauthorized, err
		}
		return auth.StatusCode(err), err
	}
	client, err := e.upstreamFor(credential)
	if err != nil {
		return 0, err
	}
	if _, err := client.ListModels(ctx, tokens.AccessToken); err != nil {
		return upstream.StatusCode(err), err
	}
	if exhausted, status, err := probeQuotaAvailability(ctx, client, tokens.AccessToken); exhausted || status != 0 {
		return status, err
	}
	return http.StatusOK, nil
}

// ProbeCredentialSnapshot rebases a run snapshot onto durable state before
// network use, then verifies it again around route resolution. Runner bounds
// each run so these safety reads cannot amplify without limit.
func (e *Executor) ProbeCredentialSnapshot(ctx context.Context, credential storage.Credential) (int, storage.Credential, error) {
	latest, loadErr := e.Store.GetCredential(credential.ID)
	if loadErr != nil {
		return 0, credential, loadErr
	}
	if !inspectionCredentialUsable(latest) {
		return 0, latest, auth.ErrRefreshInvalidated
	}
	tokens, err := e.ensureTokenForInspection(ctx, latest)
	if err != nil {
		if auth.IsTerminalCredentialError(err) {
			return http.StatusUnauthorized, latest, err
		}
		return auth.StatusCode(err), latest, err
	}
	latest, loadErr = e.Store.GetCredential(credential.ID)
	if loadErr != nil {
		return 0, credential, loadErr
	}
	if !inspectionCredentialUsable(latest) || !tokenMatchesCredential(tokens, latest) {
		return 0, latest, auth.ErrRefreshInvalidated
	}
	routeRevisionBeforeResolve := e.routeRevision()
	client, err := e.upstreamFor(latest)
	if err != nil {
		return 0, latest, err
	}
	routeRevisionAfterResolve := e.routeRevision()
	verified, verifyErr := e.Store.GetCredential(credential.ID)
	if verifyErr != nil || routeRevisionBeforeResolve != routeRevisionAfterResolve ||
		e.routeRevision() != routeRevisionAfterResolve || verified.Revision != latest.Revision ||
		!inspectionCredentialUsable(verified) || !tokenMatchesCredential(tokens, verified) {
		return 0, verified, auth.ErrRefreshInvalidated
	}
	if _, err := client.ListModels(ctx, verified.AccessToken); err != nil {
		return upstream.StatusCode(err), verified, err
	}
	if exhausted, status, err := probeQuotaAvailability(ctx, client, verified.AccessToken); exhausted || status != 0 {
		return status, verified, err
	}
	return http.StatusOK, verified, nil
}

// probeQuotaAvailability adds quota awareness to the inexpensive model probe.
// An unavailable billing endpoint is ignored unless it gives a credential or
// quota status, so an upstream billing outage cannot evict healthy accounts.
func probeQuotaAvailability(ctx context.Context, client Upstream, accessToken string) (exhausted bool, status int, err error) {
	weekly, err := client.GetBillingCredits(ctx, accessToken)
	if err != nil {
		status = upstream.StatusCode(err)
		switch status {
		case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusTooManyRequests:
			return false, status, err
		default:
			return false, 0, nil
		}
	}
	if weekly != nil && weekly.CreditUsagePercent != nil && *weekly.CreditUsagePercent >= 100 {
		return true, http.StatusPaymentRequired, nil
	}
	return false, 0, nil
}

func (e *Executor) ensureDurableCredential(ctx context.Context, credential storage.Credential, requireEnabled bool) (auth.TokenSet, storage.Credential, error) {
	tokens, err := e.EnsureToken(ctx, credential)
	if err != nil {
		return auth.TokenSet{}, credential, err
	}
	latest, err := e.Store.GetCredential(credential.ID)
	if err != nil {
		return auth.TokenSet{}, credential, err
	}
	if (requireEnabled && (!latest.Enabled || latest.ManualDisabled)) ||
		!tokenMatchesCredential(tokens, latest) {
		return tokens, latest, auth.ErrRefreshInvalidated
	}
	return tokens, latest, nil
}

func (e *Executor) resolveVerifiedUpstream(credential storage.Credential, tokens auth.TokenSet, requireEnabled bool) (Upstream, storage.Credential, error) {
	routeRevisionBeforeResolve := e.routeRevision()
	client, err := e.upstreamFor(credential)
	if err != nil {
		return nil, credential, err
	}
	routeRevisionAfterResolve := e.routeRevision()
	verified, err := e.Store.GetCredential(credential.ID)
	if err != nil {
		return nil, credential, err
	}
	if routeRevisionBeforeResolve != routeRevisionAfterResolve ||
		e.routeRevision() != routeRevisionAfterResolve ||
		verified.Revision != credential.Revision ||
		(requireEnabled && (!verified.Enabled || verified.ManualDisabled)) ||
		!tokenMatchesCredential(tokens, verified) {
		return nil, verified, auth.ErrRefreshInvalidated
	}
	return client, verified, nil
}

func (e *Executor) forceRefresh(ctx context.Context, cred storage.Credential) (auth.TokenSet, error) {
	if e.Refresher == nil {
		return auth.TokenSet{}, fmt.Errorf("proxy: refresher not configured")
	}
	current := auth.TokenSet{
		AccessToken:  cred.AccessToken,
		RefreshToken: cred.RefreshToken,
		ExpiresAt:    cred.ExpiresAt,
		TokenType:    "Bearer",
	}
	return e.Refresher.ForceRefresh(ctx, cred.ID, current, e.loadFunc(cred.ID), e.persistFunc(cred.ID))
}

func (e *Executor) ensureTokenForInspection(ctx context.Context, credential storage.Credential) (auth.TokenSet, error) {
	if e.Refresher == nil {
		return auth.TokenSet{
			AccessToken: credential.AccessToken, RefreshToken: credential.RefreshToken,
			ExpiresAt: credential.ExpiresAt, TokenType: "Bearer",
		}, nil
	}
	current := auth.TokenSet{
		AccessToken: credential.AccessToken, RefreshToken: credential.RefreshToken,
		ExpiresAt: credential.ExpiresAt, TokenType: "Bearer",
	}
	routeRevision := e.routeRevision()
	return e.Refresher.EnsureAccess(
		ctx, credential.ID, current,
		e.inspectionLoadFunc(credential, routeRevision), e.persistFunc(credential.ID),
	)
}

func (e *Executor) forceRefreshForInspection(ctx context.Context, credential storage.Credential) (auth.TokenSet, error) {
	if e.Refresher == nil {
		return auth.TokenSet{}, fmt.Errorf("proxy: refresher not configured")
	}
	current := auth.TokenSet{
		AccessToken: credential.AccessToken, RefreshToken: credential.RefreshToken,
		ExpiresAt: credential.ExpiresAt, TokenType: "Bearer",
	}
	routeRevision := e.routeRevision()
	return e.Refresher.ForceRefresh(
		ctx, credential.ID, current,
		e.inspectionLoadFunc(credential, routeRevision), e.persistFunc(credential.ID),
	)
}

func (e *Executor) inspectionLoadFunc(expected storage.Credential, routeRevision uint64) auth.TokenLoadFunc {
	return func(context.Context) (auth.TokenSet, error) {
		if e.Store == nil {
			return auth.TokenSet{}, fmt.Errorf("proxy: store not configured")
		}
		current, err := e.Store.GetCredential(expected.ID)
		if err != nil {
			return auth.TokenSet{}, err
		}
		if e.routeRevision() != routeRevision || !inspectionCredentialGuardMatches(expected, current) {
			return auth.TokenSet{}, auth.ErrRefreshInvalidated
		}
		return auth.TokenSet{
			AccessToken: current.AccessToken, RefreshToken: current.RefreshToken,
			ExpiresAt: current.ExpiresAt, TokenType: "Bearer",
		}, nil
	}
}

func (e *Executor) upstreamFor(credential storage.Credential) (Upstream, error) {
	if e == nil {
		return nil, fmt.Errorf("proxy: executor not configured")
	}
	if e.UpstreamFor != nil {
		client, err := e.UpstreamFor(credential)
		if err != nil {
			return nil, fmt.Errorf("proxy: resolve upstream client: %w", err)
		}
		if client == nil {
			return nil, fmt.Errorf("proxy: resolved nil upstream client")
		}
		return client, nil
	}
	if e.Upstream == nil {
		return nil, fmt.Errorf("proxy: upstream not configured")
	}
	return e.Upstream, nil
}

func (e *Executor) persistFunc(credID string) auth.TokenPersistFunc {
	return func(ctx context.Context, previous, next auth.TokenSet) error {
		if e.Store == nil {
			return fmt.Errorf("proxy: store not configured")
		}
		// Atomic compare-and-patch: a refresh may outlive an admin import. Only
		// commit when the refresh token actually sent to OAuth is still current,
		// otherwise the older flight would overwrite newer imported credentials.
		_, err := e.Store.PatchCredential(credID, func(c *storage.Credential) error {
			if strings.TrimSpace(c.RefreshToken) != strings.TrimSpace(previous.RefreshToken) {
				return auth.ErrRefreshInvalidated
			}
			c.AccessToken = next.AccessToken
			if strings.TrimSpace(next.RefreshToken) != "" {
				c.RefreshToken = next.RefreshToken
			}
			if !next.ExpiresAt.IsZero() {
				c.ExpiresAt = next.ExpiresAt
			}
			return nil
		})
		return err
	}
}

func (e *Executor) loadFunc(credID string) auth.TokenLoadFunc {
	return func(context.Context) (auth.TokenSet, error) {
		if e.Store == nil {
			return auth.TokenSet{}, fmt.Errorf("proxy: store not configured")
		}
		credential, err := e.Store.GetCredential(credID)
		if err != nil {
			return auth.TokenSet{}, err
		}
		return auth.TokenSet{
			AccessToken:  credential.AccessToken,
			RefreshToken: credential.RefreshToken,
			ExpiresAt:    credential.ExpiresAt,
			TokenType:    "Bearer",
		}, nil
	}
}

func (e *Executor) routeRevision() uint64 {
	if e != nil && e.RouteRevision != nil {
		return e.RouteRevision()
	}
	return 0
}

func tokenMatchesCredential(tokens auth.TokenSet, credential storage.Credential) bool {
	return strings.TrimSpace(tokens.AccessToken) == strings.TrimSpace(credential.AccessToken) &&
		strings.TrimSpace(tokens.RefreshToken) == strings.TrimSpace(credential.RefreshToken)
}

func inspectionCredentialUsable(credential storage.Credential) bool {
	return !credential.ManualDisabled &&
		(credential.Enabled || credential.LifecycleState == storage.CredentialStateQuarantined)
}

func inspectionCredentialGuardMatches(expected, current storage.Credential) bool {
	return inspectionCredentialUsable(current) &&
		expected.ID == current.ID &&
		expected.Enabled == current.Enabled &&
		expected.ManualDisabled == current.ManualDisabled &&
		expected.LifecycleState == current.LifecycleState &&
		strings.TrimSpace(expected.AccessToken) == strings.TrimSpace(current.AccessToken) &&
		strings.TrimSpace(expected.RefreshToken) == strings.TrimSpace(current.RefreshToken) &&
		strings.TrimSpace(expected.ProxyMode) == strings.TrimSpace(current.ProxyMode) &&
		strings.TrimSpace(expected.ProxyURL) == strings.TrimSpace(current.ProxyURL) &&
		strings.TrimSpace(expected.OIDCIssuer) == strings.TrimSpace(current.OIDCIssuer) &&
		strings.TrimSpace(expected.OIDCClientID) == strings.TrimSpace(current.OIDCClientID)
}

func shouldMarkDiscoveryFailure(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden,
		http.StatusProxyAuthRequired, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

// observeRateLimit persists free-tier X-Ratelimit-* counters for a credential.
// It returns true when remaining requests or tokens have reached zero, so the
// caller can apply a long cooldown and switch accounts on the next turn.
func (e *Executor) observeRateLimit(credID string, header http.Header) (bool, time.Duration) {
	if e == nil || e.Store == nil || credID == "" || header == nil {
		return false, 0
	}
	limit, ok := upstream.ParseRateLimitHeaders(header)
	if !ok {
		return false, 0
	}
	now := e.now().UTC().Truncate(time.Second)
	_, err := e.Store.PatchCredential(credID, func(c *storage.Credential) error {
		c.RateLimitLimitRequests = cloneInt64Ptr(limit.LimitRequests)
		c.RateLimitRemainingRequests = cloneInt64Ptr(limit.RemainingRequests)
		c.RateLimitLimitTokens = cloneInt64Ptr(limit.LimitTokens)
		c.RateLimitRemainingTokens = cloneInt64Ptr(limit.RemainingTokens)
		observed := now
		c.RateLimitObservedAt = &observed
		return nil
	})
	if err != nil {
		e.log(context.Background(), slog.LevelDebug, "credential_rate_limit_persist_failed",
			"credential_id", credID,
			"error", err,
		)
	}
	return limit.Exhausted(), limit.ResetAfter(e.now())
}

func (e *Executor) markQuotaExhausted(credID string, resetAfter time.Duration) {
	if e == nil || e.Selector == nil || credID == "" {
		return
	}
	if marker, ok := e.Selector.(quotaExhaustionUntilMarker); ok && resetAfter > 0 {
		marker.MarkQuotaExhaustedUntil(credID, e.now(), e.now().Add(resetAfter))
		return
	}
	if marker, ok := e.Selector.(quotaExhaustionMarker); ok {
		marker.MarkQuotaExhausted(credID, e.now())
		return
	}
	// Keep custom selectors compatible while retaining the previous behavior.
	e.Selector.MarkFailure(credID, http.StatusPaymentRequired, 0, e.now())
}

func cloneInt64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}

func (e *Executor) touchLastUsed(cred storage.Credential) error {
	if e.Store == nil || cred.ID == "" {
		return nil
	}
	now := e.now().UTC().Truncate(time.Second)
	e.usageMu.Lock()
	if e.lastUsed == nil {
		e.lastUsed = make(map[string]time.Time)
	}
	previous := e.lastUsed[cred.ID]
	if cred.LastUsedAt != nil && cred.LastUsedAt.After(previous) {
		previous = *cred.LastUsedAt
	}
	if !previous.IsZero() && (now.Before(previous) || now.Sub(previous) < 30*time.Second) {
		e.usageMu.Unlock()
		return nil
	}
	e.lastUsed[cred.ID] = now
	e.usageMu.Unlock()
	// Only mutate LastUsedAt under the store lock so concurrent token rotates cannot be clobbered.
	_, err := e.Store.PatchCredential(cred.ID, func(c *storage.Credential) error {
		c.LastUsedAt = &now
		return nil
	})
	if err != nil {
		e.usageMu.Lock()
		if e.lastUsed[cred.ID].Equal(now) {
			delete(e.lastUsed, cred.ID)
		}
		e.usageMu.Unlock()
	}
	return err
}

func (e *Executor) now() time.Time {
	if e != nil && e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Executor) log(ctx context.Context, level slog.Level, message string, args ...any) {
	if e == nil || e.Logger == nil {
		return
	}
	if e.RequestID != nil {
		if requestID := e.RequestID(ctx); requestID != "" {
			args = append([]any{"request_id", requestID}, args...)
		}
	}
	e.Logger.Log(ctx, level, message, args...)
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusPaymentRequired, http.StatusTooManyRequests, http.StatusForbidden:
		return true
	default:
		return code >= 500 && code <= 599
	}
}

// parseRetryAfter parses a Retry-After header (seconds or HTTP-date). Zero if unknown.
func parseRetryAfter(v string) time.Duration {
	return parseRetryAfterAt(v, time.Now())
}

func parseRetryAfterAt(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if sec, err := strconv.Atoi(v); err == nil {
		if sec < 0 {
			return 0
		}
		return time.Duration(sec) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

func newIdempotencyKey() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return "grokbuild-" + hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("grokbuild-%d", time.Now().UnixNano())
}

func idempotencyHeaders(key string) http.Header {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", key)
	headers.Set("X-Idempotency-Key", key)
	return headers
}

func bufferErrorResponse(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	clone := new(http.Response)
	*clone = *resp
	clone.Header = resp.Header.Clone()
	clone.Body = io.NopCloser(strings.NewReader(string(raw)))
	clone.ContentLength = int64(len(raw))
	return clone
}

func isChatEndpointQuotaDenied(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusForbidden || resp.Body == nil {
		return false
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(raw)))
	resp.ContentLength = int64(len(raw))
	return strings.Contains(strings.ToLower(string(raw)), "access to the chat endpoint is denied")
}

// DrainAndClose is a helper for callers that abandon a response.
func DrainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
