package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type ErrorKind string

const (
	ErrorTerminal  ErrorKind = "terminal_credential"
	ErrorSystem    ErrorKind = "system_configuration"
	ErrorTransient ErrorKind = "transient"
	ErrorUnknown   ErrorKind = "unknown"
)

// HTTPStatusError preserves an OAuth HTTP status for safe classification.
type HTTPStatusError struct {
	Operation  string
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "auth: HTTP status error"
	}
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "auth"
	}
	if code := oauthErrorCode(e.Body); code != "" {
		return fmt.Sprintf("%s: status %d: %s", operation, e.StatusCode, code)
	}
	return fmt.Sprintf("%s: status %d", operation, e.StatusCode)
}

func oauthErrorCode(body string) string {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &payload) == nil {
		code := strings.ToLower(strings.TrimSpace(payload.Error))
		if isSafeOAuthCode(code) {
			return code
		}
	}
	lower := strings.ToLower(body)
	for _, code := range []string{
		"invalid_grant", "invalid_token", "invalid_client", "authorization_pending",
		"slow_down", "expired_token", "access_denied", "temporarily_unavailable",
	} {
		if strings.Contains(lower, code) {
			return code
		}
	}
	return ""
}

func isSafeOAuthCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func StatusCode(err error) int {
	var statusError *HTTPStatusError
	if errors.As(err, &statusError) {
		return statusError.StatusCode
	}
	return 0
}

func IsInvalidGrant(err error) bool {
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) {
		return false
	}
	body := strings.ToLower(statusError.Body)
	return strings.Contains(body, "invalid_grant") ||
		strings.Contains(body, "invalid refresh") ||
		strings.Contains(body, "refresh token") && strings.Contains(body, "invalid")
}

// IsTerminalCredentialError reports OAuth failures that mean the presented
// credential material itself is no longer usable. These errors are mapped to
// an upstream-style 401 so the inspection confirmation/quarantine policy is
// applied instead of treating them as an unclassified probe failure.
func IsTerminalCredentialError(err error) bool {
	return ClassifyError(err) == ErrorTerminal
}

func ClassifyError(err error) ErrorKind {
	if err == nil {
		return ErrorUnknown
	}
	var statusError *HTTPStatusError
	if errors.As(err, &statusError) {
		body := strings.ToLower(statusError.Body)
		switch {
		case strings.Contains(body, "invalid_client"):
			return ErrorSystem
		case strings.Contains(body, "invalid_grant"), strings.Contains(body, "invalid_token"), strings.Contains(body, "invalid refresh"):
			return ErrorTerminal
		case statusError.StatusCode == http.StatusTooManyRequests || statusError.StatusCode >= 500:
			return ErrorTransient
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrorTransient
	}
	return ErrorUnknown
}
