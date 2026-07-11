package lb

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const maxStickyBindings = 10_000

// stickyBinding maps a sticky session key to a credential for a TTL window.
type stickyBinding struct {
	CredID    string
	ExpiresAt time.Time
}

// getSticky returns the bound credential id if the sticky key is still live.
// Caller must hold s.mu.
func (s *Selector) getSticky(key string, now time.Time) (credID string, ok bool) {
	if key == "" || s.stickyTTL <= 0 {
		return "", false
	}
	key = stickyMapKey(key)
	b, exists := s.sticky[key]
	if !exists {
		return "", false
	}
	if !b.ExpiresAt.After(now) {
		delete(s.sticky, key)
		return "", false
	}
	return b.CredID, true
}

// bindSticky stores / refreshes a sticky key → credID mapping.
// Caller must hold s.mu.
func (s *Selector) bindSticky(key, credID string, now time.Time) {
	if key == "" || credID == "" || s.stickyTTL <= 0 {
		return
	}
	key = stickyMapKey(key)
	if _, exists := s.sticky[key]; !exists {
		if len(s.stickySlots) < maxStickyBindings {
			s.stickySlots = append(s.stickySlots, key)
		} else {
			// Fixed-size ring eviction keeps attacker-controlled unique keys O(1)
			// after capacity is reached. Slots may reference entries removed by TTL
			// or credential invalidation; deleting a missing key is harmless.
			old := s.stickySlots[s.stickyCursor]
			delete(s.sticky, old)
			s.stickySlots[s.stickyCursor] = key
			s.stickyCursor = (s.stickyCursor + 1) % len(s.stickySlots)
		}
	}
	s.sticky[key] = stickyBinding{
		CredID:    credID,
		ExpiresAt: now.Add(s.stickyTTL),
	}
}

func stickyMapKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// pruneSticky removes expired bindings. Caller must hold s.mu.
func (s *Selector) pruneSticky(now time.Time) {
	for key, binding := range s.sticky {
		if !binding.ExpiresAt.After(now) {
			delete(s.sticky, key)
		}
	}
}

// clearStickyForCred drops all sticky bindings pointing at credID.
// Caller must hold s.mu.
func (s *Selector) clearStickyForCred(credID string) {
	if credID == "" {
		return
	}
	for k, b := range s.sticky {
		if b.CredID == credID {
			delete(s.sticky, k)
		}
	}
}
