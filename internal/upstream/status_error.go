package upstream

import (
	"errors"
	"fmt"
	"strings"
)

// HTTPStatusError preserves an upstream status without requiring string parsing.
type HTTPStatusError struct {
	Operation  string
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "upstream: HTTP status error"
	}
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "upstream"
	}
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("%s: status %d", operation, e.StatusCode)
	}
	return fmt.Sprintf("%s: status %d: %s", operation, e.StatusCode, strings.TrimSpace(e.Body))
}

func StatusCode(err error) int {
	var statusError *HTTPStatusError
	if errors.As(err, &statusError) {
		return statusError.StatusCode
	}
	return 0
}
