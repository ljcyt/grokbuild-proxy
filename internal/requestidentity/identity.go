// Package requestidentity carries non-secret authenticated client metadata.
package requestidentity

import (
	"context"
	"strings"
)

type clientIDKey struct{}

// WithClientID attaches the durable local client record ID to a request
// context. It must never be used with an API key plaintext.
func WithClientID(ctx context.Context, clientID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, clientIDKey{}, strings.TrimSpace(clientID))
}

// ClientID returns the authenticated local client record ID, if present.
func ClientID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	clientID, _ := ctx.Value(clientIDKey{}).(string)
	return strings.TrimSpace(clientID)
}
