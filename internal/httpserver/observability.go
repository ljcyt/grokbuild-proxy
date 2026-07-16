package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type requestIDContextKey struct{}

// RequestIDFromContext returns the request correlation ID assigned by middleware.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

// Metrics contains low-cardinality process counters.
type Metrics struct {
	requests      atomic.Uint64
	errors        atomic.Uint64
	inflight      atomic.Int64
	responseBytes atomic.Uint64
	durationNanos atomic.Uint64
}

// Snapshot returns a stable, JSON-safe view for the local admin dashboard.
func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	requests := m.requests.Load()
	errors := m.errors.Load()
	avgLatencyMS := float64(0)
	if requests > 0 {
		avgLatencyMS = float64(m.durationNanos.Load()) / float64(requests) / float64(time.Millisecond)
	}
	errorRate := float64(0)
	if requests > 0 {
		errorRate = float64(errors) / float64(requests)
	}
	return map[string]any{
		"requests_total":       requests,
		"errors_total":         errors,
		"success_total":        requests - errors,
		"inflight":             m.inflight.Load(),
		"response_bytes_total": m.responseBytes.Load(),
		"avg_latency_ms":       avgLatencyMS,
		"error_rate":           errorRate,
	}
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w,
			"# TYPE grokbuild_http_requests_total counter\n"+
				"grokbuild_http_requests_total %d\n"+
				"# TYPE grokbuild_http_errors_total counter\n"+
				"grokbuild_http_errors_total %d\n"+
				"# TYPE grokbuild_http_inflight gauge\n"+
				"grokbuild_http_inflight %d\n"+
				"# TYPE grokbuild_http_response_bytes_total counter\n"+
				"grokbuild_http_response_bytes_total %d\n"+
				"# TYPE grokbuild_http_request_duration_seconds_sum counter\n"+
				"grokbuild_http_request_duration_seconds_sum %.6f\n",
			m.requests.Load(),
			m.errors.Load(),
			m.inflight.Load(),
			m.responseBytes.Load(),
			float64(m.durationNanos.Load())/float64(time.Second),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Observe assigns a request ID, records metrics and emits one structured log.
func (m *Middleware) Observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := normalizeRequestID(r.Header.Get("X-Request-Id"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		r = r.WithContext(ctx)

		metrics := m.Metrics
		if metrics != nil {
			metrics.requests.Add(1)
			metrics.inflight.Add(1)
			defer metrics.inflight.Add(-1)
		}
		start := time.Now()
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		elapsed := time.Since(start)
		if metrics != nil {
			if recorder.status >= 400 {
				metrics.errors.Add(1)
			}
			if recorder.bytes > 0 {
				metrics.responseBytes.Add(uint64(recorder.bytes))
			}
			metrics.durationNanos.Add(uint64(elapsed))
		}
		logger := m.Logger
		if logger == nil {
			logger = slog.Default()
		}
		route := r.Pattern
		if route == "" {
			route = routeLabel(r.URL.Path)
		}
		logger.InfoContext(ctx, "http_request",
			"request_id", requestID,
			"method", r.Method,
			"route", route,
			"status", recorder.status,
			"duration_ms", float64(elapsed.Microseconds())/1000,
			"response_bytes", recorder.bytes,
		)
	})
}

func normalizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.' {
			continue
		}
		return ""
	}
	return value
}

func newRequestID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "req_" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

func routeLabel(path string) string {
	switch {
	case path == "/healthz", path == "/readyz", path == "/metrics":
		return path
	case strings.HasPrefix(path, "/v1/messages"):
		return "/v1/messages"
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return "/v1/chat/completions"
	case strings.HasPrefix(path, "/v1/responses"):
		return "/v1/responses"
	case strings.HasPrefix(path, "/admin/"):
		return "/admin/*"
	default:
		return "unmatched"
	}
}
