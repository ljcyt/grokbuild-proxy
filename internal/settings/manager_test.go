package settings

import (
	"sync"
	"testing"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type memoryStore struct {
	mu       sync.Mutex
	settings storage.RuntimeSettings
}

func (s *memoryStore) LoadRuntimeSettings(defaults ...storage.RuntimeSettings) (storage.RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings.SSOConverter.TimeoutSec != 0 {
		return s.settings, nil
	}
	return defaults[0], nil
}

func (s *memoryStore) SaveRuntimeSettings(value storage.RuntimeSettings) (storage.RuntimeSettings, error) {
	s.mu.Lock()
	s.settings = value
	s.mu.Unlock()
	return value, nil
}

func TestUpdateSerializesReadModifyWrite(t *testing.T) {
	store := &memoryStore{}
	manager, err := New(store, storage.DefaultRuntimeSettings())
	if err != nil {
		t.Fatal(err)
	}

	const updates = 64
	var wg sync.WaitGroup
	wg.Add(updates)
	for range updates {
		go func() {
			defer wg.Done()
			if _, err := manager.Update(func(settings *storage.RuntimeSettings) error {
				settings.Inspection.InitialDelaySec++
				return nil
			}); err != nil {
				t.Errorf("Update: %v", err)
			}
		}()
	}
	wg.Wait()

	want := storage.DefaultRuntimeSettings().Inspection.InitialDelaySec + updates
	if got := manager.Current().Inspection.InitialDelaySec; got != want {
		t.Fatalf("initial_delay_sec=%d want=%d", got, want)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if got := store.settings.Inspection.InitialDelaySec; got != want {
		t.Fatalf("persisted initial_delay_sec=%d want=%d", got, want)
	}
}

func TestFailedUpdateDoesNotPublishPartialMutation(t *testing.T) {
	manager, err := New(&memoryStore{}, storage.DefaultRuntimeSettings())
	if err != nil {
		t.Fatal(err)
	}
	original := manager.Current()
	if _, err := manager.Update(func(settings *storage.RuntimeSettings) error {
		settings.SSOConverter.TimeoutSec++
		return assertError{}
	}); err == nil {
		t.Fatal("expected mutation error")
	}
	if got := manager.Current().SSOConverter.TimeoutSec; got != original.SSOConverter.TimeoutSec {
		t.Fatalf("failed update leaked mutation: got=%d want=%d", got, original.SSOConverter.TimeoutSec)
	}
}

type assertError struct{}

func (assertError) Error() string { return "stop" }
