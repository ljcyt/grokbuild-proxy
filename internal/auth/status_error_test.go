package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestClassifyOAuthErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"invalid grant", &HTTPStatusError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}, ErrorTerminal},
		{"invalid token", &HTTPStatusError{StatusCode: 401, Body: `{"error":"invalid_token"}`}, ErrorTerminal},
		{"invalid client", &HTTPStatusError{StatusCode: 401, Body: `{"error":"invalid_client"}`}, ErrorSystem},
		{"rate limit", &HTTPStatusError{StatusCode: http.StatusTooManyRequests}, ErrorTransient},
		{"server", &HTTPStatusError{StatusCode: 503}, ErrorTransient},
		{"network", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), ErrorTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Fatalf("got=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestOAuthStatusErrorDoesNotExposeResponseBody(t *testing.T) {
	err := &HTTPStatusError{
		Operation:  "auth token",
		StatusCode: http.StatusBadRequest,
		Body:       `{"error":"invalid_grant","error_description":"refresh secret-value rejected"}`,
	}
	message := err.Error()
	if !strings.Contains(message, "invalid_grant") {
		t.Fatalf("safe OAuth code missing: %q", message)
	}
	if strings.Contains(message, "secret-value") || strings.Contains(message, "error_description") {
		t.Fatalf("OAuth response body leaked: %q", message)
	}
	unknown := (&HTTPStatusError{StatusCode: 502, Body: "upstream dumped token-secret"}).Error()
	if strings.Contains(unknown, "token-secret") {
		t.Fatalf("unknown OAuth body leaked: %q", unknown)
	}
}
