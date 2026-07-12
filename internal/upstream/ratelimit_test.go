package upstream

import (
	"net/http"
	"testing"
)

func TestParseRateLimitHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Ratelimit-Limit-Requests", "21")
	h.Set("X-Ratelimit-Remaining-Requests", "21")
	h.Set("X-Ratelimit-Limit-Tokens", "2000000")
	h.Set("X-Ratelimit-Remaining-Tokens", "2000000")
	got, ok := ParseRateLimitHeaders(h)
	if !ok {
		t.Fatal("expected headers")
	}
	if got.LimitRequests == nil || *got.LimitRequests != 21 {
		t.Fatalf("limit requests=%v", got.LimitRequests)
	}
	if got.RemainingRequests == nil || *got.RemainingRequests != 21 {
		t.Fatalf("remaining requests=%v", got.RemainingRequests)
	}
	if got.LimitTokens == nil || *got.LimitTokens != 2000000 {
		t.Fatalf("limit tokens=%v", got.LimitTokens)
	}
	if got.RemainingTokens == nil || *got.RemainingTokens != 2000000 {
		t.Fatalf("remaining tokens=%v", got.RemainingTokens)
	}
	if got.Exhausted() {
		t.Fatal("should not be exhausted")
	}
}

func TestRateLimitExhausted(t *testing.T) {
	zero := int64(0)
	one := int64(1)
	if !(RateLimit{RemainingRequests: &zero}.Exhausted()) {
		t.Fatal("remaining requests 0")
	}
	if !(RateLimit{RemainingTokens: &zero}.Exhausted()) {
		t.Fatal("remaining tokens 0")
	}
	if (RateLimit{RemainingRequests: &one, RemainingTokens: &one}.Exhausted()) {
		t.Fatal("remaining > 0 should not exhaust")
	}
	if _, ok := ParseRateLimitHeaders(http.Header{}); ok {
		t.Fatal("empty headers")
	}
}
