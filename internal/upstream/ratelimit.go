package upstream

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RateLimit is the free-tier / chat endpoint quota advertised on Responses headers.
type RateLimit struct {
	LimitRequests     *int64
	RemainingRequests *int64
	LimitTokens       *int64
	RemainingTokens   *int64
	ResetRequestsAt   *time.Time
	ResetTokensAt     *time.Time
}

// ParseRateLimitHeaders reads X-Ratelimit-* headers from an upstream Responses response.
// Returns ok=false when none of the known headers are present.
func ParseRateLimitHeaders(h http.Header) (RateLimit, bool) {
	if h == nil {
		return RateLimit{}, false
	}
	var out RateLimit
	found := false
	if v, ok := headerInt64(h, "X-Ratelimit-Limit-Requests"); ok {
		out.LimitRequests = &v
		found = true
	}
	if v, ok := headerInt64(h, "X-Ratelimit-Remaining-Requests"); ok {
		out.RemainingRequests = &v
		found = true
	}
	if v, ok := headerInt64(h, "X-Ratelimit-Limit-Tokens"); ok {
		out.LimitTokens = &v
		found = true
	}
	if v, ok := headerInt64(h, "X-Ratelimit-Remaining-Tokens"); ok {
		out.RemainingTokens = &v
		found = true
	}
	if v, ok := headerResetAt(h, "X-Ratelimit-Reset-Requests", time.Now()); ok {
		out.ResetRequestsAt = &v
		found = true
	}
	if v, ok := headerResetAt(h, "X-Ratelimit-Reset-Tokens", time.Now()); ok {
		out.ResetTokensAt = &v
		found = true
	}
	return out, found
}

// ResetAfter returns the latest reset applicable to an exhausted counter.
// Unknown or malformed headers are ignored so callers retain their safe fallback.
func (r RateLimit) ResetAfter(now time.Time) time.Duration {
	var reset time.Time
	if r.RemainingRequests != nil && *r.RemainingRequests <= 0 && r.ResetRequestsAt != nil {
		reset = *r.ResetRequestsAt
	}
	if r.RemainingTokens != nil && *r.RemainingTokens <= 0 && r.ResetTokensAt != nil && r.ResetTokensAt.After(reset) {
		reset = *r.ResetTokensAt
	}
	if !reset.After(now) {
		return 0
	}
	return reset.Sub(now)
}

// Exhausted reports whether either remaining counter has reached zero.
func (r RateLimit) Exhausted() bool {
	if r.RemainingRequests != nil && *r.RemainingRequests <= 0 {
		return true
	}
	if r.RemainingTokens != nil && *r.RemainingTokens <= 0 {
		return true
	}
	return false
}

func headerInt64(h http.Header, name string) (int64, bool) {
	raw := strings.TrimSpace(h.Get(name))
	if raw == "" {
		return 0, false
	}
	// Some gateways append units or extra tokens; take the leading integer.
	raw = strings.Fields(raw)[0]
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func headerResetAt(h http.Header, name string, now time.Time) (time.Time, bool) {
	raw := strings.TrimSpace(h.Get(name))
	if raw == "" {
		return time.Time{}, false
	}
	if duration, err := time.ParseDuration(raw); err == nil && duration > 0 && duration <= 30*24*time.Hour {
		return now.Add(duration), true
	}
	if value, err := strconv.ParseInt(raw, 10, 64); err == nil && value > 0 {
		if value >= 1_000_000_000 {
			at := time.Unix(value, 0)
			if at.After(now) && at.Before(now.Add(30*24*time.Hour)) {
				return at, true
			}
			return time.Time{}, false
		}
		if value <= int64((30 * 24 * time.Hour).Seconds()) {
			return now.Add(time.Duration(value) * time.Second), true
		}
	}
	if at, err := time.Parse(time.RFC3339, raw); err == nil && at.After(now) && at.Before(now.Add(30*24*time.Hour)) {
		return at, true
	}
	return time.Time{}, false
}
