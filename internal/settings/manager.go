package settings

import (
	"fmt"
	"sync"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type Store interface {
	LoadRuntimeSettings(defaults ...storage.RuntimeSettings) (storage.RuntimeSettings, error)
	SaveRuntimeSettings(storage.RuntimeSettings) (storage.RuntimeSettings, error)
}

// Manager keeps validated runtime settings in memory and persists complete snapshots.
type Manager struct {
	mu                sync.RWMutex
	store             Store
	current           storage.RuntimeSettings
	globalProxySource string
	revision          uint64
}

func New(store Store, defaults storage.RuntimeSettings) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("settings: store is required")
	}
	current, err := store.LoadRuntimeSettings(defaults)
	if err != nil {
		return nil, err
	}
	if err := current.Validate(); err != nil {
		return nil, err
	}
	source := "config"
	if detector, ok := store.(interface{ RuntimeSettingsExist() (bool, error) }); ok {
		exists, err := detector.RuntimeSettingsExist()
		if err != nil {
			return nil, err
		}
		if exists {
			source = "runtime"
		}
	}
	return &Manager{store: store, current: current, globalProxySource: source, revision: 1}, nil
}

func (m *Manager) Current() storage.RuntimeSettings {
	if m == nil {
		return storage.DefaultRuntimeSettings()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *Manager) GlobalProxySource() string {
	if m == nil {
		return "config"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.globalProxySource == "runtime" {
		return "runtime"
	}
	return "config"
}

// Revision returns the in-process generation of runtime settings. A process
// restart also terminates any in-flight users, so the counter only needs to be
// monotonic for the lifetime of this manager.
func (m *Manager) Revision() uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revision
}

// WithRevision runs fn while holding a settings read lock, but only when the
// expected revision is still current. This makes a long-running inspection's
// final credential mutation linearizable with settings updates.
func (m *Manager) WithRevision(expected uint64, fn func() error) (bool, error) {
	if m == nil {
		return false, fmt.Errorf("settings: manager is not configured")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.revision != expected {
		return false, nil
	}
	if fn == nil {
		return true, nil
	}
	return true, fn()
}

func (m *Manager) Replace(next storage.RuntimeSettings) (storage.RuntimeSettings, error) {
	if m == nil || m.store == nil {
		return storage.RuntimeSettings{}, fmt.Errorf("settings: manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.replaceLocked(next)
}

func (m *Manager) replaceLocked(next storage.RuntimeSettings) (storage.RuntimeSettings, error) {
	if err := next.Validate(); err != nil {
		return storage.RuntimeSettings{}, err
	}
	saved, err := m.store.SaveRuntimeSettings(next)
	if err != nil {
		return storage.RuntimeSettings{}, err
	}
	m.current = saved
	m.globalProxySource = "runtime"
	m.revision++
	return saved, nil
}

func (m *Manager) Update(mutate func(*storage.RuntimeSettings) error) (storage.RuntimeSettings, error) {
	if mutate == nil {
		return storage.RuntimeSettings{}, fmt.Errorf("settings: mutate function is required")
	}
	if m == nil || m.store == nil {
		return storage.RuntimeSettings{}, fmt.Errorf("settings: manager is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.current
	if err := mutate(&next); err != nil {
		return storage.RuntimeSettings{}, err
	}
	return m.replaceLocked(next)
}
