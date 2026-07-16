package lb

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

func testCfg(strategy string) config.LBConfig {
	return config.LBConfig{
		Strategy:             strategy,
		QuotaCooldownSec:     7 * 24 * 60 * 60,
		QuotaReserveRequests: 1,
		StickyTTLSec:         3600,
		Cooldown: config.CooldownConfig{
			BaseSec: 300,
			MaxSec:  3600,
		},
	}
}

func cred(id string, priority int, enabled bool) storage.Credential {
	return storage.Credential{
		ID:       id,
		Name:     id,
		Enabled:  enabled,
		Priority: priority,
	}
}

func withCooldown(c storage.Credential, until time.Time) storage.Credential {
	t := until
	c.CooldownUntil = &t
	return c
}

func TestAvailable_FiltersDisabledAndCooldown(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	creds := []storage.Credential{
		cred("a", 100, true),
		cred("b", 100, false),
		withCooldown(cred("c", 50, true), now.Add(time.Minute)),
		withCooldown(cred("d", 50, true), now.Add(-time.Minute)), // expired cooldown
	}
	got := Available(creds, now)
	if len(got) != 2 {
		t.Fatalf("Available len=%d want 2: %+v", len(got), ids(got))
	}
	if got[0].ID != "a" || got[1].ID != "d" {
		t.Fatalf("Available ids=%v want [a d]", ids(got))
	}
}

func TestPick_NoAvailable(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Now().UTC()
	_, err := s.Pick(nil, "", now)
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("empty: err=%v want ErrNoCredential", err)
	}
	_, err = s.Pick([]storage.Credential{cred("x", 1, false)}, "", now)
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("disabled: err=%v want ErrNoCredential", err)
	}
	until := now.Add(time.Hour)
	_, err = s.Pick([]storage.Credential{withCooldown(cred("y", 1, true), until)}, "", now)
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("cooldown: err=%v want ErrNoCredential", err)
	}
}

func TestPick_StickyHit(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	creds := []storage.Credential{
		cred("high", 200, true),
		cred("low", 50, true),
	}

	// First pick without sticky takes highest priority.
	c1, err := s.Pick(creds, "sess-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID != "high" {
		t.Fatalf("first pick=%s want high", c1.ID)
	}

	// Force sticky to low via MarkSuccess after manual bind simulation:
	// re-pick with sticky after binding low.
	s.MarkSuccess("low", "sess-1", now)

	c2, err := s.Pick(creds, "sess-1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c2.ID != "low" {
		t.Fatalf("sticky pick=%s want low", c2.ID)
	}

	// Different sticky key still prefers priority.
	c3, err := s.Pick(creds, "sess-2", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c3.ID != "high" {
		t.Fatalf("other sticky=%s want high", c3.ID)
	}
}

func TestPickPriorityRRBalancesInFlightCredentials(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	creds := []storage.Credential{
		cred("a", 100, true),
		cred("b", 100, true),
	}

	first, err := s.Pick(creds, "", now)
	if err != nil || first.ID != "a" {
		t.Fatalf("first pick=%+v err=%v", first, err)
	}
	second, err := s.Pick(creds, "", now)
	if err != nil || second.ID != "b" {
		t.Fatalf("second pick=%+v err=%v", second, err)
	}

	// Completing b makes it the least-loaded account, even though the next
	// round-robin cursor would otherwise point at a.
	s.MarkSuccess("b", "", now)
	third, err := s.Pick(creds, "", now)
	if err != nil || third.ID != "b" {
		t.Fatalf("least-loaded pick=%+v err=%v", third, err)
	}

	s.Release("a")
	s.Release("b")
}

func TestPick_StickyRebindWhenUnavailable(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	creds := []storage.Credential{
		cred("a", 100, true),
		cred("b", 100, true),
	}
	s.MarkSuccess("a", "k", now)

	// a goes into cooldown via failure.
	s.MarkFailure("a", 429, 0, now)

	c, err := s.Pick(creds, "k", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "b" {
		t.Fatalf("rebind pick=%s want b", c.ID)
	}
	// Subsequent sticky should stay on b.
	c2, err := s.Pick(creds, "k", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c2.ID != "b" {
		t.Fatalf("sticky after rebind=%s want b", c2.ID)
	}
}

func TestPick_PriorityGroups(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Now().UTC()
	creds := []storage.Credential{
		cred("p100-a", 100, true),
		cred("p100-b", 100, true),
		cred("p50", 50, true),
	}

	// Always stay in priority 100 group; RR between a and b.
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		c, err := s.Pick(creds, "", now)
		if err != nil {
			t.Fatal(err)
		}
		if c.Priority != 100 {
			t.Fatalf("pick[%d]=%s priority=%d want 100", i, c.ID, c.Priority)
		}
		seen[c.ID]++
	}
	if seen["p100-a"] == 0 || seen["p100-b"] == 0 {
		t.Fatalf("expected RR within p100, seen=%v", seen)
	}
	if seen["p50"] != 0 {
		t.Fatalf("should not pick lower priority while higher available, seen=%v", seen)
	}

	// Cool down entire p100 group → fall to p50.
	s.MarkFailure("p100-a", 429, time.Hour, now)
	s.MarkFailure("p100-b", 429, time.Hour, now)
	c, err := s.Pick(creds, "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "p50" {
		t.Fatalf("after p100 cooldown pick=%s want p50", c.ID)
	}
}

func TestPick_RoundRobin(t *testing.T) {
	s := New(testCfg("round_robin"))
	now := time.Now().UTC()
	creds := []storage.Credential{
		cred("a", 1, true),
		cred("b", 99, true),
		cred("c", 50, true),
	}
	// Flat RR ignores priority ordering of selection (uses slice order).
	var order []string
	for i := 0; i < 6; i++ {
		c, err := s.Pick(creds, "", now)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, c.ID)
	}
	// Expect a,b,c,a,b,c
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("RR order=%v want %v", order, want)
		}
	}
}

func TestMarkFailure_429CooldownSkips(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	creds := []storage.Credential{
		cred("a", 100, true),
		cred("b", 100, true),
	}

	c1, err := s.Pick(creds, "", now)
	if err != nil {
		t.Fatal(err)
	}
	// Cool down the picked one with explicit Retry-After.
	s.MarkFailure(c1.ID, 429, 10*time.Minute, now)

	// Next picks must skip c1 while cooldown active.
	for i := 0; i < 3; i++ {
		c, err := s.Pick(creds, "", now.Add(time.Duration(i+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if c.ID == c1.ID {
			t.Fatalf("pick[%d] still returned cooled-down %s", i, c1.ID)
		}
	}

	// After cooldown expires, both become available again.
	later := now.Add(11 * time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		c, err := s.Pick(creds, "", later)
		if err != nil {
			t.Fatal(err)
		}
		seen[c.ID] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("after cooldown both should be pickable, seen=%v", seen)
	}
}

func TestMarkFailure_StatusCooldowns(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Now().UTC()

	// 5xx → short cooldown; still cooling after 5s, free after base.
	s.MarkFailure("x5", 503, 0, now)
	s.mu.Lock()
	until5 := s.states["x5"].CooldownUntil
	s.mu.Unlock()
	shortMax := now.Add(300 * time.Second) // base
	if !until5.After(now.Add(10 * time.Second)) {
		t.Fatalf("5xx cooldown too short: %v", until5.Sub(now))
	}
	if until5.After(shortMax.Add(time.Minute)) {
		t.Fatalf("5xx cooldown too long: %v", until5.Sub(now))
	}

	// 401 → longer (~base*4)
	s2 := New(testCfg("priority_rr"))
	s2.MarkFailure("x1", 401, 0, now)
	s2.mu.Lock()
	until1 := s2.states["x1"].CooldownUntil
	s2.mu.Unlock()
	if until1.Sub(now) < 10*time.Minute {
		t.Fatalf("401 cooldown too short: %v", until1.Sub(now))
	}

	// 403 → max
	s3 := New(testCfg("priority_rr"))
	s3.MarkFailure("x3", 403, 0, now)
	s3.mu.Lock()
	until3 := s3.states["x3"].CooldownUntil
	s3.mu.Unlock()
	if until3.Sub(now) < 50*time.Minute {
		t.Fatalf("403 cooldown too short: %v", until3.Sub(now))
	}
}

func TestMarkQuotaExhaustedUsesDedicatedCooldown(t *testing.T) {
	cfg := testCfg("priority_rr")
	cfg.QuotaCooldownSec = 7 * 24 * 60 * 60
	s := New(cfg)
	now := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	s.MarkSuccess("quota", "session", now)
	s.MarkQuotaExhausted("quota", now)

	s.mu.Lock()
	state := *s.states["quota"]
	_, sticky := s.sticky["session"]
	s.mu.Unlock()
	if sticky {
		t.Fatal("quota exhaustion must clear sticky bindings")
	}
	if state.LastError != "quota_exhausted" {
		t.Fatalf("last error=%q", state.LastError)
	}
	if got := state.CooldownUntil.Sub(now); got != 7*24*time.Hour {
		t.Fatalf("quota cooldown=%v", got)
	}
}

func TestMarkQuotaExhaustedUsesKnownResetDeadline(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	resetAt := now.Add(45 * time.Minute)
	s.MarkQuotaExhaustedUntil("quota", now, resetAt)
	s.mu.Lock()
	until := s.states["quota"].CooldownUntil
	s.mu.Unlock()
	if !until.Equal(resetAt) {
		t.Fatalf("cooldown=%v want %v", until, resetAt)
	}
}

func TestPickPrefersQuotaHeadroomOverPriority(t *testing.T) {
	cfg := testCfg("priority_rr")
	cfg.QuotaReserveRequests = 1
	s := New(cfg)
	now := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	one := int64(1)
	creds := []storage.Credential{
		{ID: "tight", Enabled: true, Priority: 200, RateLimitRemainingRequests: &one},
		{ID: "safe", Enabled: true, Priority: 100},
	}
	picked, err := s.Pick(creds, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if picked.ID != "safe" {
		t.Fatalf("pick=%q want safe account with quota headroom", picked.ID)
	}
}

func TestMarkSuccess_ClearsCooldown(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Now().UTC()
	creds := []storage.Credential{cred("only", 1, true)}

	s.MarkFailure("only", 429, time.Hour, now)
	_, err := s.Pick(creds, "", now.Add(time.Second))
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("expected no cred during cooldown, err=%v", err)
	}

	s.MarkSuccess("only", "sess", now.Add(2*time.Second))
	c, err := s.Pick(creds, "sess", now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "only" {
		t.Fatalf("pick=%s want only", c.ID)
	}
}

func TestApplyCooldownToCredential(t *testing.T) {
	s := New(testCfg("priority_rr"))
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	s.MarkFailure("z", 429, 5*time.Minute, now)

	c := cred("z", 1, true)
	s.ApplyCooldownToCredential(&c)
	if c.CooldownUntil == nil {
		t.Fatal("expected CooldownUntil set")
	}
	// Retry-After path still adds jitter (0..10%), accept [5m, 5m+30s].
	delta := c.CooldownUntil.Sub(now)
	if delta < 5*time.Minute || delta > 5*time.Minute+30*time.Second {
		t.Fatalf("CooldownUntil delta=%v", delta)
	}
	if c.FailureCount != 1 {
		t.Fatalf("FailureCount=%d want 1", c.FailureCount)
	}

	s.MarkSuccess("z", "", now.Add(time.Minute))
	s.ApplyCooldownToCredential(&c)
	if c.CooldownUntil != nil {
		t.Fatalf("expected nil CooldownUntil after success, got %v", c.CooldownUntil)
	}
	if c.FailureCount != 0 {
		t.Fatalf("FailureCount=%d want 0", c.FailureCount)
	}
}

func TestPick_MemoryCooldownOverlaysStorage(t *testing.T) {
	s := New(testCfg("round_robin"))
	now := time.Now().UTC()
	creds := []storage.Credential{
		cred("a", 1, true),
		cred("b", 1, true),
	}
	s.MarkFailure("a", 429, 30*time.Minute, now)

	// Storage still shows a as free, but memory cooldown must skip it.
	for i := 0; i < 3; i++ {
		c, err := s.Pick(creds, "", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if c.ID != "b" {
			t.Fatalf("expected b due to memory cooldown, got %s", c.ID)
		}
	}
}

func TestHealthPersistsAcrossSelectorRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateCredential(storage.CreateCredentialInput{
		Name:         "persisted",
		AccessToken:  "access",
		RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	selector := New(testCfg("priority_rr")).SetHealthStore(store)
	selector.MarkFailure(created.ID, 402, 0, now)
	persisted, err := store.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.FailureCount != 1 || persisted.CooldownUntil == nil || persisted.LastError != "http 402" {
		t.Fatalf("persisted health=%+v", persisted)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted := New(testCfg("priority_rr")).SetHealthStore(reopened)
	creds, _ := reopened.ListCredentials()
	if _, err := restarted.Pick(creds, "", now.Add(time.Minute)); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("cooldown did not survive restart: %v", err)
	}
	if _, err := restarted.Pick(creds, "", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("credential should recover after cooldown: %v", err)
	}
	restarted.MarkSuccess(created.ID, "", now.Add(2*time.Hour))
	healthy, err := reopened.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if healthy.FailureCount != 0 || healthy.CooldownUntil != nil || healthy.LastSuccessAt == nil {
		t.Fatalf("success health=%+v", healthy)
	}
}

func TestStickyBindingsAreBounded(t *testing.T) {
	selector := New(testCfg("priority_rr"))
	now := time.Now()
	selector.mu.Lock()
	for i := 0; i < maxStickyBindings; i++ {
		selector.bindSticky(fmt.Sprintf("session-%d", i), "credential", now)
	}
	selector.bindSticky("new-session", "credential", now)
	count := len(selector.sticky)
	_, keptNew := selector.sticky[stickyMapKey("new-session")]
	selector.mu.Unlock()
	if count != maxStickyBindings || !keptNew {
		t.Fatalf("sticky count=%d kept_new=%v", count, keptNew)
	}
}

func TestStickyMapHashesUntrustedSessionKeys(t *testing.T) {
	selector := New(testCfg("priority_rr"))
	credential := storage.Credential{ID: "cred", Enabled: true}
	huge := strings.Repeat("x", 2<<20)
	now := time.Now()
	if _, err := selector.Pick([]storage.Credential{credential}, huge, now); err != nil {
		t.Fatal(err)
	}
	selector.MarkSuccess(credential.ID, huge, now)
	selector.mu.Lock()
	defer selector.mu.Unlock()
	if len(selector.sticky) != 1 {
		t.Fatalf("sticky entries=%d", len(selector.sticky))
	}
	for key := range selector.sticky {
		if len(key) != 64 || strings.Contains(key, huge[:128]) {
			t.Fatalf("unbounded sticky key retained: len=%d", len(key))
		}
	}
}

type blockingHealthStore struct {
	mu      sync.Mutex
	cred    storage.Credential
	calls   int
	started chan struct{}
	release chan struct{}
}

func (s *blockingHealthStore) PatchCredential(
	id string,
	mutate func(*storage.Credential) error,
) (storage.Credential, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 1 {
		close(s.started)
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mutate(&s.cred); err != nil {
		return storage.Credential{}, err
	}
	return s.cred, nil
}

func TestPersistedHealthCannotReorderFailureAfterSuccess(t *testing.T) {
	store := &blockingHealthStore{
		cred:    storage.Credential{ID: "ordered"},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	selector := New(testCfg("priority_rr")).SetHealthStore(store)
	now := time.Now().UTC()
	failureDone := make(chan struct{})
	go func() {
		selector.MarkFailure("ordered", 429, time.Minute, now)
		close(failureDone)
	}()
	<-store.started

	successDone := make(chan struct{})
	go func() {
		selector.MarkSuccess("ordered", "", now.Add(time.Second))
		close(successDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		selector.mu.Lock()
		version := selector.states["ordered"].Version
		selector.mu.Unlock()
		if version >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("success state was not applied")
		}
		time.Sleep(time.Millisecond)
	}
	close(store.release)
	<-failureDone
	<-successDone

	store.mu.Lock()
	final := store.cred
	store.mu.Unlock()
	if final.FailureCount != 0 || final.CooldownUntil != nil || final.LastSuccessAt == nil {
		t.Fatalf("persisted state was reordered: %+v", final)
	}
}

func ids(creds []storage.Credential) []string {
	out := make([]string, len(creds))
	for i, c := range creds {
		out[i] = c.ID
	}
	return out
}
