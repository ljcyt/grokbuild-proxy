package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/anthropic"
	"github.com/GreyGunG/grokbuild-proxy/internal/openai"
	"github.com/GreyGunG/grokbuild-proxy/internal/requestidentity"
)

// ClientAuthenticator validates client API keys (not admin).
type ClientAuthenticator interface {
	// AuthenticateClient returns true when the plaintext key is a valid client key.
	// Bootstrap api_key and hashed client keys both count.
	AuthenticateClient(plaintext string) (ok bool, err error)
}

// ClientIdentityAuthenticator optionally returns the durable local client ID
// after authenticating a plaintext key. The ID is safe to carry in context and
// lets protocol handlers namespace upstream prompt-cache keys.
type ClientIdentityAuthenticator interface {
	AuthenticateClientID(plaintext string) (clientID string, ok bool, err error)
}

// Middleware holds shared middleware dependencies.
type Middleware struct {
	Clients  ClientAuthenticator
	AdminKey string
	MaxBody  int64
	// MaxConcurrent limits in-flight authenticated API requests. Zero disables.
	MaxConcurrent int
	// RequestTimeout bounds the complete request, including upstream streaming.
	RequestTimeout time.Duration
	Logger         *slog.Logger
	Metrics        *Metrics

	sem      chan struct{}
	semOnce  sync.Once
	inflight atomic.Int64
}

// Timeout applies a request context deadline without using Server.WriteTimeout,
// which would terminate SSE writes without a protocol-level error.
func (m *Middleware) Timeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || m.RequestTimeout <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), m.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) ensureSem() {
	m.semOnce.Do(func() {
		if m.MaxConcurrent > 0 {
			m.sem = make(chan struct{}, m.MaxConcurrent)
		}
	})
}

// extractAPIKey reads Authorization: Bearer or x-api-key.
func extractAPIKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get("x-api-key")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) >= 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	if v := strings.TrimSpace(r.Header.Get("anthropic-api-key")); v != "" {
		return v
	}
	return ""
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// RequireClient enforces client API key auth. Admin keys are rejected as clients.
func (m *Middleware) RequireClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractAPIKey(r)
		if key == "" {
			writeRouteError(w, r, http.StatusUnauthorized, "missing api key")
			return
		}
		if m.AdminKey != "" && constantTimeEq(key, m.AdminKey) {
			writeRouteError(w, r, http.StatusUnauthorized, "admin key cannot be used as client key")
			return
		}
		if m.Clients == nil {
			writeRouteError(w, r, http.StatusServiceUnavailable, "auth not configured")
			return
		}
		var clientID string
		var ok bool
		var err error
		if identityAuthenticator, supportsIdentity := m.Clients.(ClientIdentityAuthenticator); supportsIdentity {
			clientID, ok, err = identityAuthenticator.AuthenticateClientID(key)
		} else {
			ok, err = m.Clients.AuthenticateClient(key)
		}
		if err != nil {
			writeRouteError(w, r, http.StatusInternalServerError, "auth lookup failed")
			return
		}
		if !ok {
			writeRouteError(w, r, http.StatusUnauthorized, "invalid api key")
			return
		}
		if clientID != "" {
			r = r.WithContext(requestidentity.WithClientID(r.Context(), clientID))
		}
		next.ServeHTTP(w, r)
	})
}

// LimitConcurrency rejects with 503 when MaxConcurrent in-flight requests are active.
func (m *Middleware) LimitConcurrency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ensureSem()
		if m.sem == nil {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case m.sem <- struct{}{}:
			m.inflight.Add(1)
			defer func() {
				<-m.sem
				m.inflight.Add(-1)
			}()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeRouteError(w, r, http.StatusServiceUnavailable, "too many concurrent requests")
		}
	})
}

// LimitBody wraps the request body with MaxBytesReader when MaxBody > 0.
func (m *Middleware) LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.MaxBody > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, m.MaxBody)
		}
		next.ServeHTTP(w, r)
	})
}

// Chain applies middlewares in order (first is outermost).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func writeRouteError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if r != nil && strings.HasPrefix(r.URL.Path, "/v1/messages") {
		anthropic.WriteError(w, status, message)
		return
	}
	openai.WriteError(w, status, message, "", "")
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
