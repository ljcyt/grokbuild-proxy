package upstream

import (
	"net/http"
	"strconv"
	"strings"
)

// RateLimit is the free-tier / chat endpoint quota advertised on Responses headers.
type RateLimit struct {
	LimitRequests     *int64
	RemainingRequests *int64
	LimitTokens       *int64
	RemainingTokens   *int64
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
	return out, found
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
