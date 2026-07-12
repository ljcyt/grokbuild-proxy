// Package inspection validates credentials and quarantines confirmed 401s.
package inspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type Store interface {
	ListCredentials() ([]storage.Credential, error)
	ApplyInspectionActions(actions []storage.InspectionAction) ([]storage.InspectionActionResult, error)
}

type Prober interface {
	ProbeCredential(ctx context.Context, credentialID string) (status int, err error)
	RefreshCredential(ctx context.Context, credentialID string) (auth.TokenSet, error)
}

type snapshotProber interface {
	ProbeCredentialSnapshot(ctx context.Context, credential storage.Credential) (status int, observed storage.Credential, err error)
	RefreshCredentialSnapshot(ctx context.Context, credential storage.Credential) (tokens auth.TokenSet, observed storage.Credential, err error)
}

type SettingsProvider interface {
	Current() storage.RuntimeSettings
}

type revisionedSettingsProvider interface {
	SettingsProvider
	Revision() uint64
	WithRevision(expected uint64, fn func() error) (bool, error)
}

type Result struct {
	CredentialID string `json:"credential_id"`
	Status       string `json:"status"`
	Action       string `json:"action,omitempty"`
	Error        string `json:"error,omitempty"`
}

type Summary struct {
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	Inspected        int       `json:"inspected"`
	Healthy          int       `json:"healthy"`
	Unauthorized     int       `json:"unauthorized"`
	RateLimited      int       `json:"rate_limited"`
	Errors           int       `json:"errors"`
	Skipped          int       `json:"skipped"`
	Quarantined      int       `json:"quarantined"`
	Reactivated      int       `json:"reactivated"`
	Purged           int       `json:"purged"`
	MassFailureGuard bool      `json:"mass_failure_guard"`
	Results          []Result  `json:"results,omitempty"`
}

type Runner struct {
	Store             Store
	Prober            Prober
	Settings          SettingsProvider
	Logger            *slog.Logger
	RateLimitCooldown time.Duration
	QuotaCooldown     time.Duration
	// InvalidateCredential retires any in-process refresh flight/cache before
	// and after automatic deletion. It is intentionally optional for tests and
	// alternative stores.
	InvalidateCredential func(string)

	mu      sync.RWMutex
	running bool
	last    *Summary
	now     func() time.Time
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil {
		return
	}
	delay := time.Duration(r.currentSettings().InitialDelaySec) * time.Second
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			settings := r.currentSettings()
			if settings.Enabled {
				if _, err := r.RunOnce(ctx); err != nil && r.Logger != nil {
					r.Logger.Warn("credential_inspection_failed", "error", err)
				}
			}
			wait := time.Duration(settings.IntervalSec) * time.Second
			if !settings.Enabled && wait > 15*time.Second {
				wait = 15 * time.Second
			}
			if wait <= 0 {
				wait = time.Minute
			}
			timer.Reset(wait)
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) (Summary, error) {
	if r == nil || r.Store == nil || r.Prober == nil {
		return Summary{}, fmt.Errorf("inspection: runner is not configured")
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return Summary{}, fmt.Errorf("inspection: run already in progress")
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	settings, settingsRevision := r.currentSettingsSnapshot()
	now := r.clock().UTC().Truncate(time.Second)
	summary := Summary{StartedAt: now, Results: []Result{}}
	credentials, err := r.Store.ListCredentials()
	if err != nil {
		return Summary{}, err
	}

	type checked struct {
		credential       storage.Credential
		result           Result
		purgeCandidate   bool
		probeFingerprint string
		inspected        bool
		resetEvidence    bool
		stalePurgeAfter  *time.Time
		staleFingerprint string
	}
	type candidate struct {
		credential     storage.Credential
		purgeCandidate bool
	}
	var checkedResults []checked
	var checkedMu sync.Mutex
	limit := settings.MaxCredentialsPerRun
	if limit <= 0 {
		limit = storage.DefaultRuntimeSettings().Inspection.MaxCredentialsPerRun
	}
	eligibleCandidates := make([]candidate, 0, len(credentials))
	for _, credential := range credentials {
		isPurgeCandidate := purgeDue(credential, now)
		if !isPurgeCandidate && !eligible(credential, settings, now) {
			summary.Skipped++
			continue
		}
		eligibleCandidates = append(eligibleCandidates, candidate{credential: credential, purgeCandidate: isPurgeCandidate})
	}
	// Restart-safe fairness: due purges first, then never/least-recently
	// inspected credentials. Unlike an in-memory cursor, rolling restarts cannot
	// starve the tail of a large credential set.
	sort.SliceStable(eligibleCandidates, func(left, right int) bool {
		a := eligibleCandidates[left]
		b := eligibleCandidates[right]
		if a.purgeCandidate != b.purgeCandidate {
			return a.purgeCandidate
		}
		leftAt := a.credential.LastInspectionAt
		rightAt := b.credential.LastInspectionAt
		if leftAt == nil || rightAt == nil {
			if leftAt == nil && rightAt != nil {
				return true
			}
			if leftAt != nil && rightAt == nil {
				return false
			}
		} else if !leftAt.Equal(*rightAt) {
			return leftAt.Before(*rightAt)
		}
		return a.credential.ID < b.credential.ID
	})
	if limit > len(eligibleCandidates) {
		limit = len(eligibleCandidates)
	}
	candidates := append([]candidate(nil), eligibleCandidates[:limit]...)
	summary.Skipped += len(eligibleCandidates) - len(candidates)

	// A semaphore inside one goroutine per credential still allocates an
	// unbounded number of waiting goroutine stacks. Feed a fixed worker pool so
	// Concurrency limits both active probes and scheduler/memory pressure.
	jobs := make(chan candidate)
	workerCount := min(max(1, settings.Concurrency), len(candidates))
	var wait sync.WaitGroup
	wait.Add(workerCount)
	for range workerCount {
		go func() {
			defer wait.Done()
			for candidate := range jobs {
				credential := candidate.credential
				purgeCandidate := candidate.purgeCandidate

				// ListCredentials is the run snapshot. Production snapshot probing can
				// use it directly on the healthy path; every final action remains bound
				// to the observed revision by the batch CAS below.
				fingerprint := tokenFingerprint(credential)
				resetEvidence := false
				var stalePurgeAfter *time.Time
				staleFingerprint := ""
				if purgeCandidate && (!purgeDue(credential, now) ||
					credential.QuarantineTokenFingerprint == "" ||
					credential.QuarantineTokenFingerprint != fingerprint) {
					// The token family changed after the old quarantine evidence was
					// recorded. Reinspect it as a normal quarantined credential and create
					// one fresh retention window instead of permanently occupying a due
					// purge slot with stale evidence.
					purgeCandidate = false
					resetEvidence = true
					stalePurgeAfter = credential.PurgeAfter
					staleFingerprint = credential.QuarantineTokenFingerprint
				}
				timeout := time.Duration(settings.TimeoutSec) * time.Second
				probeCtx, cancel := context.WithTimeout(ctx, timeout)
				result, observed := r.inspectOne(probeCtx, credential, settings.ConfirmUnauthorized, settingsRevision)
				cancel()
				if observed.ID == "" {
					observed = credential
				}
				resetEvidence = resetEvidence && !observed.Enabled && !observed.ManualDisabled &&
					observed.LifecycleState == storage.CredentialStateQuarantined &&
					observed.DisableReason == storage.DisableReasonInvalidAuth
				checkedMu.Lock()
				checkedResults = append(checkedResults, checked{
					credential: observed, result: result, purgeCandidate: purgeCandidate,
					probeFingerprint: tokenFingerprint(observed), inspected: true, resetEvidence: resetEvidence,
					stalePurgeAfter: stalePurgeAfter, staleFingerprint: staleFingerprint,
				})
				checkedMu.Unlock()
			}
		}()
	}
	for _, candidate := range candidates {
		jobs <- candidate
	}
	close(jobs)
	wait.Wait()

	for _, checked := range checkedResults {
		if !checked.inspected {
			if checked.result.Status == "storage_error" {
				summary.Errors++
			}
			continue
		}
		summary.Inspected++
		switch checked.result.Status {
		case "healthy":
			summary.Healthy++
		case "unauthorized":
			summary.Unauthorized++
		case "rate_limited", "quota_exhausted":
			summary.RateLimited++
		case "state_changed", "settings_changed":
			summary.Skipped++
		default:
			summary.Errors++
		}
	}
	if summary.Unauthorized >= settings.MassFailureMinimum && summary.Inspected > 0 &&
		float64(summary.Unauthorized)/float64(summary.Inspected) >= settings.MassFailureRatio {
		summary.MassFailureGuard = true
	}

	type pendingAction struct {
		result     Result
		action     storage.InspectionAction
		heldAction string
	}
	pending := make([]pendingAction, 0, len(checkedResults))
	for _, checked := range checkedResults {
		if !checked.inspected {
			continue
		}
		result := checked.result
		action := storage.InspectionAction{
			ID: result.CredentialID, ExpectedRevision: checked.credential.Revision, At: now,
		}
		if checked.resetEvidence {
			action.ResetQuarantineEvidence = true
			action.ExpectedPurgeAfter = checked.stalePurgeAfter
			action.ExpectedTokenFingerprint = checked.staleFingerprint
			if settings.PurgeAfterSec > 0 {
				value := now.Add(time.Duration(settings.PurgeAfterSec) * time.Second)
				action.PurgeAfter = &value
			}
		}
		heldAction := "inspection_result_held"
		switch result.Status {
		case "healthy":
			action.Kind = storage.InspectionActionHealthy
			heldAction = "healthy_result_held"
		case "unauthorized":
			if summary.MassFailureGuard {
				result.Action = "held_by_mass_failure_guard"
				action.Kind = storage.InspectionActionFailure
				action.Status = "mass_failure_guard"
				action.Message = "confirmed unauthorized"
				heldAction = "mass_failure_result_held"
			} else if checked.purgeCandidate {
				action.Kind = storage.InspectionActionPurge
				action.ExpectedPurgeAfter = checked.credential.PurgeAfter
				action.ExpectedTokenFingerprint = checked.probeFingerprint
				heldAction = "purge_held"
			} else {
				action.Kind = storage.InspectionActionQuarantine
				if action.PurgeAfter == nil && settings.PurgeAfterSec > 0 {
					value := now.Add(time.Duration(settings.PurgeAfterSec) * time.Second)
					action.PurgeAfter = &value
				}
				heldAction = "quarantine_held"
			}
		case "rate_limited", "quota_exhausted":
			action.Kind = storage.InspectionActionFailure
			action.Status = result.Status
			action.Message = result.Error
			cooldown := r.RateLimitCooldown
			if result.Status == "quota_exhausted" && r.QuotaCooldown > 0 {
				cooldown = r.QuotaCooldown
			}
			if cooldown <= 0 {
				cooldown = time.Minute
			}
			until := now.Add(cooldown)
			action.CooldownUntil = &until
			heldAction = "rate_limit_result_held"
		case "state_changed", "settings_changed":
			action.Kind = storage.InspectionActionAttempt
			action.Status = result.Status
			action.Message = result.Error
		default:
			action.Kind = storage.InspectionActionFailure
			action.Status = result.Status
			action.Message = result.Error
		}
		pending = append(pending, pendingAction{result: result, action: action, heldAction: heldAction})
	}

	actions := make([]storage.InspectionAction, len(pending))
	for index := range pending {
		actions[index] = pending[index].action
	}
	var actionResults []storage.InspectionActionResult
	settingsApplied, applyErr := r.withSettingsRevision(settingsRevision, func() error {
		for _, action := range actions {
			if action.Kind == storage.InspectionActionPurge && r.InvalidateCredential != nil {
				r.InvalidateCredential(action.ID)
			}
		}
		var err error
		actionResults, err = r.Store.ApplyInspectionActions(actions)
		if err != nil {
			return err
		}
		for _, result := range actionResults {
			if result.Deleted && r.InvalidateCredential != nil {
				r.InvalidateCredential(result.ID)
			}
		}
		return nil
	})
	resolved := make(map[string]Result, len(pending))
	for index, item := range pending {
		result := item.result
		if applyErr != nil {
			result.Status = "storage_error"
			result.Action = item.heldAction
			result.Error = "failed to persist inspection result"
			summary.Errors++
		} else if !settingsApplied {
			result.Status = "settings_changed"
			result.Action = item.heldAction
			result.Error = "runtime settings changed during inspection"
		} else if index >= len(actionResults) || !actionResults[index].Applied {
			result.Status = "state_changed"
			result.Action = item.heldAction
			result.Error = "credential changed during inspection"
		} else {
			actionResult := actionResults[index]
			switch item.action.Kind {
			case storage.InspectionActionHealthy:
				if actionResult.Reactivated {
					result.Action = "reactivated"
					summary.Reactivated++
				}
			case storage.InspectionActionQuarantine:
				if actionResult.Quarantined {
					result.Action = "quarantined"
					summary.Quarantined++
				} else {
					result.Action = "quarantine_retained"
				}
			case storage.InspectionActionPurge:
				result.Action = "purged"
				summary.Purged++
			}
		}
		resolved[item.action.ID] = result
	}
	for _, checked := range checkedResults {
		if checked.inspected {
			summary.Results = append(summary.Results, resolved[checked.credential.ID])
		} else {
			summary.Results = append(summary.Results, checked.result)
		}
	}
	if maxResults := settings.MaxPersistedRunResults; maxResults > 0 && len(summary.Results) > maxResults {
		summary.Results = append([]Result(nil), summary.Results[:maxResults]...)
	}
	summary.FinishedAt = r.clock().UTC().Truncate(time.Second)
	r.mu.Lock()
	snapshot := summary
	snapshot.Results = append([]Result(nil), summary.Results...)
	r.last = &snapshot
	r.mu.Unlock()
	return summary, nil
}

func (r *Runner) Last() (Summary, bool) {
	if r == nil {
		return Summary{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.last == nil {
		return Summary{}, false
	}
	out := *r.last
	out.Results = append([]Result(nil), r.last.Results...)
	return out, true
}

func (r *Runner) Running() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *Runner) inspectOne(ctx context.Context, credential storage.Credential, confirmations int, settingsRevision uint64) (Result, storage.Credential) {
	result := Result{CredentialID: credential.ID}
	if !r.settingsRevisionCurrent(settingsRevision) {
		result.Status = "settings_changed"
		result.Action = "inspection_result_held"
		result.Error = "runtime settings changed during inspection"
		return result, credential
	}
	probe := func(current storage.Credential) (int, storage.Credential, error) {
		if prober, ok := r.Prober.(snapshotProber); ok {
			return prober.ProbeCredentialSnapshot(ctx, current)
		}
		status, err := r.Prober.ProbeCredential(ctx, current.ID)
		return status, current, err
	}
	refresh := func(current storage.Credential) (auth.TokenSet, storage.Credential, error) {
		if prober, ok := r.Prober.(snapshotProber); ok {
			return prober.RefreshCredentialSnapshot(ctx, current)
		}
		tokens, err := r.Prober.RefreshCredential(ctx, current.ID)
		return tokens, current, err
	}

	status, observed, err := probe(credential)
	if errors.Is(err, auth.ErrRefreshInvalidated) {
		result.Status = "state_changed"
		result.Action = "inspection_result_held"
		result.Error = "credential or route changed during inspection"
		return result, observed
	}
	if status == http.StatusOK && err == nil {
		result.Status = "healthy"
		return result, observed
	}
	if status == http.StatusTooManyRequests {
		result.Status = "rate_limited"
		result.Error = "status 429"
		return result, observed
	}
	if status == http.StatusPaymentRequired {
		result.Status = "quota_exhausted"
		result.Error = "status 402"
		return result, observed
	}
	if status != http.StatusUnauthorized {
		result.Status = statusLabel(status)
		result.Error = safeProbeError(status, err)
		return result, observed
	}

	refreshTerminal := false
	if !r.settingsRevisionCurrent(settingsRevision) {
		result.Status = "settings_changed"
		result.Action = "inspection_result_held"
		result.Error = "runtime settings changed during inspection"
		return result, observed
	}
	if _, refreshed, refreshErr := refresh(observed); refreshErr != nil {
		if errors.Is(refreshErr, auth.ErrRefreshInvalidated) {
			result.Status = "state_changed"
			result.Action = "inspection_result_held"
			result.Error = "credential or route changed during inspection"
			return result, refreshed
		}
		kind := auth.ClassifyError(refreshErr)
		if kind == auth.ErrorTerminal {
			// A terminal refresh error is necessary but not sufficient for
			// quarantine. Re-probe below to confirm the original 401 persists.
			refreshTerminal = true
		} else if kind == auth.ErrorSystem {
			result.Status = "system_error"
			result.Error = safeProbeError(auth.StatusCode(refreshErr), refreshErr)
			return result, refreshed
		} else {
			result.Status = "refresh_error"
			result.Error = safeProbeError(auth.StatusCode(refreshErr), refreshErr)
			return result, refreshed
		}
		observed = refreshed
	} else {
		observed = refreshed
	}
	if confirmations < 2 {
		confirmations = 2
	}
	for attempt := 1; attempt < confirmations; attempt++ {
		if !r.settingsRevisionCurrent(settingsRevision) {
			result.Status = "settings_changed"
			result.Action = "inspection_result_held"
			result.Error = "runtime settings changed during inspection"
			return result, observed
		}
		status, observed, err = probe(observed)
		if errors.Is(err, auth.ErrRefreshInvalidated) {
			result.Status = "state_changed"
			result.Action = "inspection_result_held"
			result.Error = "credential or route changed during inspection"
			return result, observed
		}
		if status == http.StatusOK && err == nil {
			result.Status = "healthy"
			return result, observed
		}
		if status == http.StatusTooManyRequests {
			result.Status = "rate_limited"
			result.Error = "status 429"
			return result, observed
		}
		if status != http.StatusUnauthorized {
			result.Status = statusLabel(status)
			result.Error = safeProbeError(status, err)
			return result, observed
		}
	}
	if refreshTerminal {
		result.Status = "unauthorized"
		result.Error = "confirmed unauthorized after terminal refresh failure"
	} else {
		result.Status = "unauthorized_unconfirmed"
		result.Error = "authorization remained unavailable after successful refresh"
	}
	return result, observed
}

func tokenFingerprint(credential storage.Credential) string {
	sum := sha256.Sum256([]byte(credential.AccessToken + "\x00" + credential.RefreshToken))
	return hex.EncodeToString(sum[:])
}

func (r *Runner) currentSettings() storage.InspectionSettings {
	settings, _ := r.currentSettingsSnapshot()
	return settings
}

func (r *Runner) currentSettingsSnapshot() (storage.InspectionSettings, uint64) {
	if r != nil && r.Settings != nil {
		revision := uint64(0)
		if provider, ok := r.Settings.(revisionedSettingsProvider); ok {
			revision = provider.Revision()
		}
		return r.Settings.Current().Inspection, revision
	}
	return storage.DefaultRuntimeSettings().Inspection, 0
}

func (r *Runner) withSettingsRevision(expected uint64, fn func() error) (bool, error) {
	if r != nil && r.Settings != nil {
		if provider, ok := r.Settings.(revisionedSettingsProvider); ok {
			return provider.WithRevision(expected, fn)
		}
	}
	if fn == nil {
		return true, nil
	}
	return true, fn()
}

func (r *Runner) settingsRevisionCurrent(expected uint64) bool {
	if r != nil && r.Settings != nil {
		if provider, ok := r.Settings.(revisionedSettingsProvider); ok {
			return provider.Revision() == expected
		}
	}
	return true
}

func (r *Runner) clock() time.Time {
	if r != nil && r.now != nil {
		return r.now()
	}
	return time.Now()
}

func eligible(credential storage.Credential, settings storage.InspectionSettings, now time.Time) bool {
	if credential.ManualDisabled {
		return false
	}
	if credential.LifecycleState == storage.CredentialStateQuarantined && !settings.InspectQuarantined {
		return false
	}
	if !credential.Enabled && credential.LifecycleState != storage.CredentialStateQuarantined {
		return false
	}
	if settings.SkipRecentSuccessSec > 0 && credential.LastSuccessAt != nil &&
		now.Sub(*credential.LastSuccessAt) < time.Duration(settings.SkipRecentSuccessSec)*time.Second {
		return false
	}
	return true
}

func purgeDue(credential storage.Credential, now time.Time) bool {
	return !credential.ManualDisabled &&
		credential.LifecycleState == storage.CredentialStateQuarantined &&
		credential.DisableReason == storage.DisableReasonInvalidAuth &&
		credential.PurgeAfter != nil && !credential.PurgeAfter.After(now)
}

func safeProbeError(status int, err error) string {
	if status > 0 {
		return fmt.Sprintf("status %d", status)
	}
	if err == context.DeadlineExceeded {
		return "timeout"
	}
	return "network or protocol error"
}

func statusLabel(status int) string {
	if status > 0 {
		return "http_error"
	}
	return "probe_error"
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
