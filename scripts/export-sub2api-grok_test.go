package main

import (
	"testing"
	"time"
)

func int64Ptr(v int64) *int64 { return &v }

func TestEligible(t *testing.T) {
	now := time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)
	base := credential{
		Enabled:      true,
		AccessToken:  "access",
		RefreshToken: "refresh",
	}
	tests := []struct {
		name           string
		credential     credential
		includeUnknown bool
		want           bool
	}{
		{name: "remaining quota", credential: withQuota(base, 1, 100), want: true},
		{name: "no requests remaining", credential: withQuota(base, 0, 100), want: false},
		{name: "no tokens remaining", credential: withQuota(base, 1, 0), want: false},
		{name: "cooling down", credential: withCooldown(base, now.Add(time.Minute)), want: false},
		{name: "quota exhausted", credential: withStatus(base, "", "quota_exhausted"), want: false},
		{name: "quarantined", credential: withLifecycle(base, "quarantined"), want: false},
		{name: "unknown quota is excluded", credential: base, want: false},
		{name: "unknown quota can be explicitly included", credential: base, includeUnknown: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eligible(tt.credential, now, tt.includeUnknown); got != tt.want {
				t.Fatalf("eligible() = %v, want %v", got, tt.want)
			}
		})
	}
}

func withQuota(c credential, requests, tokens int64) credential {
	c.RemainingRequests = int64Ptr(requests)
	c.RemainingTokens = int64Ptr(tokens)
	return c
}

func withCooldown(c credential, until time.Time) credential {
	c.CooldownUntil = &until
	return c
}

func withStatus(c credential, lastError, inspectionStatus string) credential {
	c.LastError = lastError
	c.LastInspectionStatus = inspectionStatus
	return c
}

func withLifecycle(c credential, lifecycle string) credential {
	c.LifecycleState = lifecycle
	return c
}
