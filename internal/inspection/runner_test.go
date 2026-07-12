package inspection

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type memoryStore struct {
	mu          sync.Mutex
	credentials map[string]storage.Credential
	listCalls   int
	applyCalls  int
}

func (s *memoryStore) ListCredentials() ([]storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	out := make([]storage.Credential, 0, len(s.credentials))
	for _, credential := range s.credentials {
		out = append(out, credential)
	}
	return out, nil
}

func (s *memoryStore) ApplyInspectionActions(actions []storage.InspectionAction) ([]storage.InspectionActionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyCalls++
	results := make([]storage.InspectionActionResult, len(actions))
	for index, action := range actions {
		result := storage.InspectionActionResult{ID: action.ID, Kind: action.Kind}
		credential, ok := s.credentials[action.ID]
		if !ok {
			results[index] = result
			continue
		}
		at := action.At.UTC().Truncate(time.Second)
		if credential.Revision != action.ExpectedRevision {
			credential.LastInspectionAt = &at
			credential.LastInspectionStatus = "state_changed"
			credential.LastInspectionError = "credential changed during inspection"
			credential.Revision++
			s.credentials[action.ID] = credential
			result.AttemptRecorded = true
			results[index] = result
			continue
		}
		if action.ResetQuarantineEvidence {
			expectedPurgeMatches := (credential.PurgeAfter == nil && action.ExpectedPurgeAfter == nil) ||
				(credential.PurgeAfter != nil && action.ExpectedPurgeAfter != nil && credential.PurgeAfter.Equal(*action.ExpectedPurgeAfter))
			if !credential.Enabled && !credential.ManualDisabled &&
				credential.LifecycleState == storage.CredentialStateQuarantined &&
				credential.DisableReason == storage.DisableReasonInvalidAuth && expectedPurgeMatches &&
				credential.QuarantineTokenFingerprint == action.ExpectedTokenFingerprint {
				credential.QuarantinedAt = &at
				credential.PurgeAfter = action.PurgeAfter
				credential.QuarantineTokenFingerprint = tokenFingerprint(credential)
			}
		}
		switch action.Kind {
		case storage.InspectionActionHealthy:
			credential.LastInspectionAt = &at
			credential.LastInspectionStatus = "healthy"
			credential.LastInspectionError = ""
			credential.ConsecutiveUnauthorized = 0
			if credential.LifecycleState == storage.CredentialStateQuarantined &&
				credential.DisableReason == storage.DisableReasonInvalidAuth && !credential.ManualDisabled {
				credential.Enabled = true
				credential.LifecycleState = storage.CredentialStateActive
				credential.DisableReason = ""
				credential.QuarantinedAt = nil
				credential.PurgeAfter = nil
				credential.QuarantineTokenFingerprint = ""
				result.Reactivated = true
			}
			result.Applied = true
		case storage.InspectionActionAttempt:
			credential.LastInspectionAt = &at
			credential.LastInspectionStatus = action.Status
			credential.LastInspectionError = action.Message
			result.Applied = true
		case storage.InspectionActionFailure:
			credential.LastInspectionAt = &at
			credential.LastInspectionStatus = action.Status
			credential.LastInspectionError = action.Message
			if action.Status == "mass_failure_guard" {
				credential.ConsecutiveUnauthorized++
			} else if action.Status != "unauthorized" {
				credential.ConsecutiveUnauthorized = 0
			}
			if action.CooldownUntil != nil {
				credential.CooldownUntil = action.CooldownUntil
			}
			result.Applied = true
		case storage.InspectionActionQuarantine:
			if !credential.ManualDisabled {
				alreadyQuarantined := credential.LifecycleState == storage.CredentialStateQuarantined &&
					credential.DisableReason == storage.DisableReasonInvalidAuth
				credential.Enabled = false
				credential.LifecycleState = storage.CredentialStateQuarantined
				credential.DisableReason = storage.DisableReasonInvalidAuth
				if credential.QuarantinedAt == nil {
					credential.QuarantinedAt = &at
				}
				if credential.PurgeAfter == nil {
					credential.PurgeAfter = action.PurgeAfter
				}
				if credential.QuarantineTokenFingerprint == "" {
					credential.QuarantineTokenFingerprint = tokenFingerprint(credential)
				}
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = "unauthorized"
				credential.LastInspectionError = "confirmed unauthorized"
				credential.ConsecutiveUnauthorized++
				result.Applied = true
				result.Quarantined = !alreadyQuarantined
			}
		case storage.InspectionActionPurge:
			if action.ExpectedPurgeAfter != nil && credential.PurgeAfter != nil &&
				credential.PurgeAfter.Equal(*action.ExpectedPurgeAfter) && !credential.Enabled &&
				!credential.ManualDisabled && credential.LifecycleState == storage.CredentialStateQuarantined &&
				credential.DisableReason == storage.DisableReasonInvalidAuth &&
				credential.QuarantineTokenFingerprint == action.ExpectedTokenFingerprint &&
				tokenFingerprint(credential) == action.ExpectedTokenFingerprint {
				delete(s.credentials, action.ID)
				result.Applied = true
				result.Deleted = true
			}
		}
		if result.Applied && !result.Deleted {
			credential.Revision++
			s.credentials[action.ID] = credential
		}
		results[index] = result
	}
	return results, nil
}

func (s *memoryStore) GetCredential(id string) (storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[id]
	if !ok {
		return storage.Credential{}, fmt.Errorf("not found")
	}
	return credential, nil
}

func (s *memoryStore) PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[id]
	if !ok {
		return storage.Credential{}, fmt.Errorf("not found")
	}
	if err := mutate(&credential); err != nil {
		return storage.Credential{}, err
	}
	credential.Revision++
	s.credentials[id] = credential
	return credential, nil
}

func (s *memoryStore) DeleteCredentialIfPurgeEligible(id string, expectedRevision uint64, expectedPurgeAfter time.Time, expectedTokenFingerprint string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[id]
	if !ok {
		return false, fmt.Errorf("not found")
	}
	if credential.Revision != expectedRevision || credential.ManualDisabled || credential.Enabled ||
		credential.LifecycleState != storage.CredentialStateQuarantined ||
		credential.DisableReason != storage.DisableReasonInvalidAuth ||
		credential.PurgeAfter == nil || !credential.PurgeAfter.Equal(expectedPurgeAfter) ||
		credential.QuarantineTokenFingerprint != expectedTokenFingerprint ||
		tokenFingerprint(credential) != expectedTokenFingerprint {
		return false, nil
	}
	delete(s.credentials, id)
	return true, nil
}

type probeStep struct {
	status int
	err    error
}

type fakeProber struct {
	mu      sync.Mutex
	steps   map[string][]probeStep
	refresh map[string]error
}

type blockingProber struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

// raceWindowProber lets a target finish a confirmed-401 inspection while a
// second credential keeps RunOnce from applying actions. Tests rotate the
// target token in that deterministic window.
type raceWindowProber struct {
	targetID       string
	blockerID      string
	targetDone     chan struct{}
	blockerStarted chan struct{}
	releaseBlocker chan struct{}

	mu           sync.Mutex
	targetProbes int
	targetOnce   sync.Once
	blockerOnce  sync.Once
}

func (p *raceWindowProber) ProbeCredential(_ context.Context, id string) (int, error) {
	switch id {
	case p.targetID:
		p.mu.Lock()
		p.targetProbes++
		finished := p.targetProbes >= 2
		p.mu.Unlock()
		if finished {
			p.targetOnce.Do(func() { close(p.targetDone) })
		}
		return 401, nil
	case p.blockerID:
		p.blockerOnce.Do(func() { close(p.blockerStarted) })
		<-p.releaseBlocker
		return 200, nil
	default:
		return 200, nil
	}
}

func (p *raceWindowProber) RefreshCredential(_ context.Context, id string) (auth.TokenSet, error) {
	if id == p.targetID {
		return auth.TokenSet{}, &auth.HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}
	}
	return auth.TokenSet{}, nil
}

func (p *blockingProber) ProbeCredential(context.Context, string) (int, error) {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return 200, nil
}

func (p *blockingProber) RefreshCredential(context.Context, string) (auth.TokenSet, error) {
	return auth.TokenSet{}, nil
}

func (p *fakeProber) ProbeCredential(_ context.Context, id string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	steps := p.steps[id]
	if len(steps) == 0 {
		return 200, nil
	}
	step := steps[0]
	p.steps[id] = steps[1:]
	return step.status, step.err
}

func (p *fakeProber) RefreshCredential(_ context.Context, id string) (auth.TokenSet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return auth.TokenSet{AccessToken: "new"}, p.refresh[id]
}

type staticSettings struct{ value storage.RuntimeSettings }

func (s staticSettings) Current() storage.RuntimeSettings { return s.value }

type mutableSettings struct {
	mu       sync.RWMutex
	value    storage.RuntimeSettings
	revision uint64
}

func (s *mutableSettings) Current() storage.RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}

func (s *mutableSettings) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *mutableSettings) WithRevision(expected uint64, fn func() error) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revision != expected {
		return false, nil
	}
	return true, fn()
}

func (s *mutableSettings) update(mutate func(*storage.RuntimeSettings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutate(&s.value)
	s.revision++
}

type actionWindowProber struct {
	targetID       string
	blockerID      string
	targetStatus   int
	targetDone     chan struct{}
	blockerStarted chan struct{}
	releaseBlocker chan struct{}
	targetOnce     sync.Once
	blockerOnce    sync.Once
}

func (p *actionWindowProber) ProbeCredential(_ context.Context, id string) (int, error) {
	switch id {
	case p.targetID:
		p.targetOnce.Do(func() { close(p.targetDone) })
		return p.targetStatus, nil
	case p.blockerID:
		p.blockerOnce.Do(func() { close(p.blockerStarted) })
		<-p.releaseBlocker
		return http.StatusOK, nil
	default:
		return http.StatusOK, nil
	}
}

func (*actionWindowProber) RefreshCredential(context.Context, string) (auth.TokenSet, error) {
	return auth.TokenSet{}, nil
}

func TestConfirmed401IsQuarantined(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &fakeProber{steps: map[string][]probeStep{
		"one": {{status: 401}, {status: 401}},
	}, refresh: map[string]error{
		"one": &auth.HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`},
	}}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.MassFailureMinimum = 3
	settings.Inspection.PurgeAfterSec = 3600
	now := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}, now: func() time.Time { return now }}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Quarantined != 1 || summary.RateLimited != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	credential := store.credentials["one"]
	if credential.Enabled || credential.LifecycleState != storage.CredentialStateQuarantined ||
		credential.DisableReason != storage.DisableReasonInvalidAuth || credential.PurgeAfter == nil {
		t.Fatalf("credential=%+v", credential)
	}
}

func TestSuccessfulRefreshFollowedBy401DoesNotQuarantine(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &fakeProber{
		steps:   map[string][]probeStep{"one": {{status: 401}, {status: 401}}},
		refresh: map[string]error{},
	}
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{storage.DefaultRuntimeSettings()}}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential := store.credentials["one"]
	if summary.Quarantined != 0 || !credential.Enabled || credential.LifecycleState != storage.CredentialStateActive {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
	if credential.LastInspectionStatus != "unauthorized_unconfirmed" {
		t.Fatalf("status=%q", credential.LastInspectionStatus)
	}
}

func Test429OnlyCoolsDown(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &fakeProber{steps: map[string][]probeStep{"one": {{status: 429}}}, refresh: map[string]error{}}
	settings := storage.DefaultRuntimeSettings()
	now := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	runner := &Runner{
		Store: store, Prober: prober, Settings: staticSettings{settings},
		RateLimitCooldown: 2 * time.Minute, now: func() time.Time { return now },
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential := store.credentials["one"]
	if summary.RateLimited != 1 || !credential.Enabled ||
		credential.LifecycleState != storage.CredentialStateActive ||
		credential.CooldownUntil == nil || !credential.CooldownUntil.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func Test402MarksQuotaExhaustedWithLongCooldown(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &fakeProber{steps: map[string][]probeStep{"one": {{status: http.StatusPaymentRequired}}}, refresh: map[string]error{}}
	settings := storage.DefaultRuntimeSettings()
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	runner := &Runner{
		Store: store, Prober: prober, Settings: staticSettings{settings},
		RateLimitCooldown: time.Minute, QuotaCooldown: time.Hour, now: func() time.Time { return now },
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential := store.credentials["one"]
	if summary.RateLimited != 1 || !credential.Enabled || credential.LastInspectionStatus != "quota_exhausted" ||
		credential.CooldownUntil == nil || !credential.CooldownUntil.Equal(now.Add(time.Hour)) {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func TestRefreshSystemAndTransientErrorsNeverQuarantine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status string
	}{
		{"invalid_client", &auth.HTTPStatusError{StatusCode: 401, Body: `{"error":"invalid_client"}`}, "system_error"},
		{"server", &auth.HTTPStatusError{StatusCode: 503}, "refresh_error"},
		{"network", context.DeadlineExceeded, "refresh_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{credentials: map[string]storage.Credential{"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive}}}
			runner := &Runner{Store: store, Prober: &fakeProber{steps: map[string][]probeStep{"one": {{status: 401}}}, refresh: map[string]error{"one": tc.err}}, Settings: staticSettings{storage.DefaultRuntimeSettings()}}
			summary, err := runner.RunOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if summary.Quarantined != 0 || !store.credentials["one"].Enabled || store.credentials["one"].LastInspectionStatus != tc.status {
				t.Fatalf("summary=%+v credential=%+v", summary, store.credentials["one"])
			}
		})
	}
}

func TestNon401ProbeFailuresNeverQuarantine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
	}{
		{"payment_required", 402, nil},
		{"forbidden", 403, nil},
		{"proxy_auth", 407, nil},
		{"server", 503, nil},
		{"network", 0, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{credentials: map[string]storage.Credential{
				"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
			}}
			runner := &Runner{
				Store: store,
				Prober: &fakeProber{steps: map[string][]probeStep{
					"one": {{status: tc.status, err: tc.err}},
				}, refresh: map[string]error{}},
				Settings: staticSettings{storage.DefaultRuntimeSettings()},
			}
			summary, err := runner.RunOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if summary.Quarantined != 0 || !store.credentials["one"].Enabled {
				t.Fatalf("summary=%+v credential=%+v", summary, store.credentials["one"])
			}
		})
	}
}

func TestRunOnceRejectsOverlap(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"one": {ID: "one", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &blockingProber{started: make(chan struct{}), release: make(chan struct{})}
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{storage.DefaultRuntimeSettings()}}
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunOnce(context.Background())
		done <- err
	}()
	<-prober.started
	progress, active := runner.Progress()
	if !active || progress.Scheduled != 1 || progress.Completed != 0 {
		t.Fatalf("progress=%+v active=%v", progress, active)
	}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("overlapping inspection run was accepted")
	}
	close(prober.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, active := runner.Progress(); active {
		t.Fatal("progress should clear after the run completes")
	}
}

func TestManualDisabledCredentialIsNeverInspectedOrReactivated(t *testing.T) {
	credential := storage.Credential{
		ID: "manual", Enabled: false, ManualDisabled: true,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonManual,
	}
	store := &memoryStore{credentials: map[string]storage.Credential{"manual": credential}}
	runner := &Runner{Store: store, Prober: &fakeProber{}, Settings: staticSettings{storage.DefaultRuntimeSettings()}}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := store.credentials["manual"]
	if summary.Skipped != 1 || got.Enabled || !got.ManualDisabled || got.DisableReason != storage.DisableReasonManual {
		t.Fatalf("summary=%+v credential=%+v", summary, got)
	}
}

func TestMassFailureGuardPreventsQuarantine(t *testing.T) {
	credentials := make(map[string]storage.Credential)
	steps := make(map[string][]probeStep)
	for _, id := range []string{"one", "two", "three"} {
		credentials[id] = storage.Credential{ID: id, Enabled: true, LifecycleState: storage.CredentialStateActive}
		steps[id] = []probeStep{{status: 401}, {status: 401}}
	}
	refreshErrors := make(map[string]error)
	for _, id := range []string{"one", "two", "three"} {
		refreshErrors[id] = &auth.HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}
	}
	store := &memoryStore{credentials: credentials}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.MassFailureMinimum = 3
	settings.Inspection.MassFailureRatio = 0.5
	runner := &Runner{
		Store: store, Prober: &fakeProber{steps: steps, refresh: refreshErrors},
		Settings: staticSettings{settings},
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !summary.MassFailureGuard || summary.Quarantined != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	for _, credential := range store.credentials {
		if !credential.Enabled || credential.LifecycleState == storage.CredentialStateQuarantined {
			t.Fatalf("credential=%+v", credential)
		}
	}
}

func TestTokenRotationAfterProbePreventsQuarantine(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target": {
			ID: "target", AccessToken: "old-access", RefreshToken: "old-refresh",
			Enabled: true, LifecycleState: storage.CredentialStateActive,
		},
		"blocker": {ID: "blocker", AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &raceWindowProber{
		targetID: "target", blockerID: "blocker", targetDone: make(chan struct{}),
		blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	settings.Inspection.MassFailureMinimum = 10
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.AccessToken = "new-access"
		credential.RefreshToken = "new-refresh"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential := store.credentials["target"]
	if summary.Quarantined != 0 || !credential.Enabled ||
		credential.LifecycleState != storage.CredentialStateActive ||
		credential.AccessToken != "new-access" {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func TestProxyChangeAfterProbePreventsQuarantine(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target": {
			ID: "target", AccessToken: "access", RefreshToken: "refresh",
			Enabled: true, LifecycleState: storage.CredentialStateActive,
			ProxyMode: storage.CredentialProxyInherit,
		},
		"blocker": {ID: "blocker", AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &raceWindowProber{
		targetID: "target", blockerID: "blocker", targetDone: make(chan struct{}),
		blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	settings.Inspection.MassFailureMinimum = 10
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.ProxyMode = storage.CredentialProxyDirect
		credential.ProxyURL = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential := store.credentials["target"]
	if summary.Quarantined != 0 || !credential.Enabled ||
		credential.LifecycleState != storage.CredentialStateActive ||
		credential.ProxyMode != storage.CredentialProxyDirect {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func TestRuntimeSettingsChangeAfterProbeHoldsWholeRunActions(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target": {
			ID: "target", Revision: 1, AccessToken: "access", RefreshToken: "refresh",
			Enabled: true, LifecycleState: storage.CredentialStateActive,
		},
		"blocker": {ID: "blocker", Revision: 1, AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &raceWindowProber{
		targetID: "target", blockerID: "blocker", targetDone: make(chan struct{}),
		blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	settings.Inspection.MassFailureMinimum = 10
	provider := &mutableSettings{value: settings, revision: 1}
	runner := &Runner{Store: store, Prober: prober, Settings: provider}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	provider.update(func(value *storage.RuntimeSettings) {
		value.GlobalProxy = storage.GlobalProxySettings{Mode: "direct"}
	})
	close(prober.releaseBlocker)
	summary := <-done
	credential := store.credentials["target"]
	if summary.Quarantined != 0 || !credential.Enabled || credential.LifecycleState != storage.CredentialStateActive {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
	foundHeld := false
	for _, result := range summary.Results {
		if result.CredentialID == "target" && result.Status == "settings_changed" && result.Action == "quarantine_held" {
			foundHeld = true
		}
	}
	if !foundHeld {
		t.Fatalf("target result was not held after settings change: %+v", summary.Results)
	}
}

func TestCredentialChangeAfterHealthyProbeDoesNotReactivate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	future := now.Add(time.Hour)
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target": {
			ID: "target", Revision: 1, AccessToken: "access", RefreshToken: "refresh", Enabled: false,
			LifecycleState: storage.CredentialStateQuarantined, DisableReason: storage.DisableReasonInvalidAuth,
			PurgeAfter: &future,
		},
		"blocker": {ID: "blocker", Revision: 1, AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &actionWindowProber{
		targetID: "target", blockerID: "blocker", targetStatus: http.StatusOK,
		targetDone: make(chan struct{}), blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}, now: func() time.Time { return now }}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.ProxyMode = storage.CredentialProxyDirect
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential := store.credentials["target"]
	if summary.Reactivated != 0 || credential.Enabled || credential.LifecycleState != storage.CredentialStateQuarantined {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func TestCredentialChangeAfterRateLimitProbeDoesNotWriteCooldown(t *testing.T) {
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target":  {ID: "target", Revision: 1, AccessToken: "access", RefreshToken: "refresh", Enabled: true, LifecycleState: storage.CredentialStateActive},
		"blocker": {ID: "blocker", Revision: 1, AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &actionWindowProber{
		targetID: "target", blockerID: "blocker", targetStatus: http.StatusTooManyRequests,
		targetDone: make(chan struct{}), blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.AccessToken = "imported-access"
		credential.RefreshToken = "imported-refresh"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential := store.credentials["target"]
	if summary.RateLimited != 1 || credential.CooldownUntil != nil {
		t.Fatalf("summary=%+v credential=%+v", summary, credential)
	}
}

func TestRunUsesOneSnapshotReadAndOneBatchApply(t *testing.T) {
	credentials := make(map[string]storage.Credential, 1000)
	for index := 0; index < 1000; index++ {
		id := fmt.Sprintf("cred-%04d", index)
		credentials[id] = storage.Credential{ID: id, Revision: 1, AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive}
	}
	store := &memoryStore{credentials: credentials}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 8
	settings.Inspection.MaxCredentialsPerRun = 1000
	runner := &Runner{Store: store, Prober: &fakeProber{}, Settings: staticSettings{settings}}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inspected != 1000 || store.listCalls != 1 || store.applyCalls != 1 {
		t.Fatalf("summary=%+v list_calls=%d apply_calls=%d", summary, store.listCalls, store.applyCalls)
	}
}

func TestDueQuarantineIsPurgedOnlyAfterConfirmedReinspection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	auto := storage.Credential{
		ID: "auto", AccessToken: "access", RefreshToken: "refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
	}
	auto.QuarantineTokenFingerprint = tokenFingerprint(auto)
	store := &memoryStore{credentials: map[string]storage.Credential{
		"auto": auto,
		"manual": {
			ID: "manual", Enabled: false, ManualDisabled: true,
			LifecycleState: storage.CredentialStateActive, DisableReason: storage.DisableReasonManual,
			PurgeAfter: &past,
		},
	}}
	settings := storage.DefaultRuntimeSettings()
	var invalidations []string
	runner := &Runner{
		Store: store, Prober: &fakeProber{
			steps:   map[string][]probeStep{"auto": {{status: 401}, {status: 401}}},
			refresh: map[string]error{"auto": &auth.HTTPStatusError{StatusCode: 401, Body: "invalid_grant"}},
		},
		Settings: staticSettings{settings}, now: func() time.Time { return now },
		InvalidateCredential: func(id string) { invalidations = append(invalidations, id) },
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Purged != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	if _, ok := store.credentials["auto"]; ok {
		t.Fatal("automatic quarantine was not purged")
	}
	if _, ok := store.credentials["manual"]; !ok {
		t.Fatal("manual-disabled credential was purged")
	}
	if len(invalidations) != 2 || invalidations[0] != "auto" || invalidations[1] != "auto" {
		t.Fatalf("refresh invalidations=%v", invalidations)
	}
}

func TestRepeatedUnauthorizedKeepsOriginalPurgeDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	originalQuarantinedAt := now.Add(-time.Hour)
	originalPurgeAfter := now.Add(time.Hour)
	credential := storage.Credential{
		ID: "one", Revision: 1, AccessToken: "access", RefreshToken: "refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined, DisableReason: storage.DisableReasonInvalidAuth,
		QuarantinedAt: &originalQuarantinedAt, PurgeAfter: &originalPurgeAfter,
	}
	credential.QuarantineTokenFingerprint = tokenFingerprint(credential)
	store := &memoryStore{credentials: map[string]storage.Credential{"one": credential}}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.PurgeAfterSec = 7200
	settings.Inspection.MassFailureMinimum = 10
	runner := &Runner{
		Store: store, Settings: staticSettings{settings}, now: func() time.Time { return now },
		Prober: &fakeProber{
			steps:   map[string][]probeStep{"one": {{status: 401}, {status: 401}}},
			refresh: map[string]error{"one": &auth.HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}},
		},
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	updated := store.credentials["one"]
	if updated.PurgeAfter == nil || !updated.PurgeAfter.Equal(originalPurgeAfter) ||
		updated.QuarantinedAt == nil || !updated.QuarantinedAt.Equal(originalQuarantinedAt) {
		t.Fatalf("summary=%+v credential=%+v", summary, updated)
	}
	if summary.Quarantined != 0 {
		t.Fatalf("repeat quarantine counted as new: %+v", summary)
	}
}

func TestMassFailureGuardIncludesDuePurgeReinspections(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	credentials := make(map[string]storage.Credential)
	steps := make(map[string][]probeStep)
	refresh := make(map[string]error)
	for _, id := range []string{"one", "two", "three"} {
		credential := storage.Credential{
			ID: id, AccessToken: "access-" + id, RefreshToken: "refresh-" + id, Enabled: false,
			LifecycleState: storage.CredentialStateQuarantined,
			DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
		}
		credential.QuarantineTokenFingerprint = tokenFingerprint(credential)
		credentials[id] = credential
		steps[id] = []probeStep{{status: 401}, {status: 401}}
		refresh[id] = &auth.HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}
	}
	store := &memoryStore{credentials: credentials}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.MassFailureMinimum = 3
	settings.Inspection.MassFailureRatio = 0.5
	runner := &Runner{
		Store: store, Prober: &fakeProber{steps: steps, refresh: refresh},
		Settings: staticSettings{settings}, now: func() time.Time { return now },
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !summary.MassFailureGuard || summary.Inspected != 3 || summary.Unauthorized != 3 || summary.Purged != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if len(store.credentials) != 3 {
		t.Fatalf("mass-failure guard deleted purge candidates: remaining=%d", len(store.credentials))
	}
}

func TestTokenRotationAfterPurgeReinspectionPreventsDelete(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	target := storage.Credential{
		ID: "target", AccessToken: "old-access", RefreshToken: "old-refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
	}
	target.QuarantineTokenFingerprint = tokenFingerprint(target)
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target":  target,
		"blocker": {ID: "blocker", AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &raceWindowProber{
		targetID: "target", blockerID: "blocker", targetDone: make(chan struct{}),
		blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	settings.Inspection.MassFailureMinimum = 10
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}, now: func() time.Time { return now }}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.AccessToken = "new-access"
		credential.RefreshToken = "new-refresh"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential, exists := store.credentials["target"]
	if summary.Purged != 0 || !exists || credential.AccessToken != "new-access" {
		t.Fatalf("summary=%+v credential=%+v exists=%v", summary, credential, exists)
	}
}

func TestExplicitEnableAfterPurgeReinspectionPreventsDelete(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	target := storage.Credential{
		ID: "target", AccessToken: "access", RefreshToken: "refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
	}
	target.QuarantineTokenFingerprint = tokenFingerprint(target)
	store := &memoryStore{credentials: map[string]storage.Credential{
		"target":  target,
		"blocker": {ID: "blocker", AccessToken: "access", Enabled: true, LifecycleState: storage.CredentialStateActive},
	}}
	prober := &raceWindowProber{
		targetID: "target", blockerID: "blocker", targetDone: make(chan struct{}),
		blockerStarted: make(chan struct{}), releaseBlocker: make(chan struct{}),
	}
	settings := storage.DefaultRuntimeSettings()
	settings.Inspection.Concurrency = 2
	settings.Inspection.MassFailureMinimum = 10
	runner := &Runner{Store: store, Prober: prober, Settings: staticSettings{settings}, now: func() time.Time { return now }}
	done := make(chan Summary, 1)
	go func() {
		summary, _ := runner.RunOnce(context.Background())
		done <- summary
	}()
	<-prober.targetDone
	<-prober.blockerStarted
	if _, err := store.PatchCredential("target", func(credential *storage.Credential) error {
		credential.Enabled = true
		credential.ManualDisabled = false
		credential.LifecycleState = storage.CredentialStateActive
		credential.DisableReason = ""
		credential.PurgeAfter = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(prober.releaseBlocker)
	summary := <-done
	credential, exists := store.credentials["target"]
	if summary.Purged != 0 || !exists || !credential.Enabled ||
		credential.LifecycleState != storage.CredentialStateActive {
		t.Fatalf("summary=%+v credential=%+v exists=%v", summary, credential, exists)
	}
}

func TestDueQuarantineIsNotPurgedWhenTokenChanged(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	credential := storage.Credential{
		ID: "one", AccessToken: "new-access", RefreshToken: "refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
		QuarantineTokenFingerprint: tokenFingerprint(storage.Credential{AccessToken: "old-access", RefreshToken: "refresh"}),
	}
	store := &memoryStore{credentials: map[string]storage.Credential{"one": credential}}
	runner := &Runner{Store: store, Prober: &fakeProber{}, Settings: staticSettings{storage.DefaultRuntimeSettings()}, now: func() time.Time { return now }}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Purged != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if _, ok := store.credentials["one"]; !ok {
		t.Fatal("credential with changed token was purged")
	}
}

func TestDueQuarantineIsNotPurgedWhenReinspectionRecovers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Minute)
	credential := storage.Credential{
		ID: "one", AccessToken: "access", RefreshToken: "refresh", Enabled: false,
		LifecycleState: storage.CredentialStateQuarantined,
		DisableReason:  storage.DisableReasonInvalidAuth, PurgeAfter: &past,
	}
	credential.QuarantineTokenFingerprint = tokenFingerprint(credential)
	store := &memoryStore{credentials: map[string]storage.Credential{"one": credential}}
	runner := &Runner{
		Store: store, Prober: &fakeProber{steps: map[string][]probeStep{"one": {{status: 200}}}, refresh: map[string]error{}},
		Settings: staticSettings{storage.DefaultRuntimeSettings()}, now: func() time.Time { return now },
	}
	summary, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Purged != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if _, ok := store.credentials["one"]; !ok {
		t.Fatal("recovered credential was purged")
	}
	recovered := store.credentials["one"]
	if !recovered.Enabled || recovered.LifecycleState != storage.CredentialStateActive || recovered.DisableReason != "" {
		t.Fatalf("recovered credential was not reactivated: %+v", recovered)
	}
}
