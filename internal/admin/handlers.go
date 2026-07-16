// Package admin implements the local admin HTTP API for credentials and clients.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/importer"
	"github.com/GreyGunG/grokbuild-proxy/internal/inspection"
	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/sso"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

// Version is reported by GET /admin/system. Overridden by main via linker or SetVersion.
var Version = "dev"

// Store is the storage surface used by admin handlers.
type Store interface {
	ListCredentials() ([]storage.Credential, error)
	GetCredential(id string) (storage.Credential, error)
	CreateCredential(in storage.CreateCredentialInput) (storage.Credential, error)
	UpdateCredential(c storage.Credential) (storage.Credential, error)
	PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error)
	DeleteCredential(id string) error
	SetCredentialEnabled(id string, enabled bool) (storage.Credential, error)
	SetCredentialPriority(id string, priority int) (storage.Credential, error)
	ListClients() ([]storage.ClientKey, error)
	CreateClient(name string) (storage.CreateClientResult, error)
	DeleteClient(id string) error
}

type credentialUpserter interface {
	UpsertCredential(in storage.CreateCredentialInput) (storage.Credential, bool, error)
}

type RuntimeSettingsService interface {
	Current() storage.RuntimeSettings
	Update(func(*storage.RuntimeSettings) error) (storage.RuntimeSettings, error)
}

type idleConnectionCloser interface {
	CloseIdleConnections()
}

type proxyResolver interface {
	Resolve(*storage.Credential) (outbound.ResolvedProxy, error)
}

type tokenCacheInvalidator interface {
	Invalidate(key string)
}

type ImportJobService interface {
	Start(files []importer.InputFile) (importer.Job, error)
	Get(id string) (importer.Job, bool)
}

type InspectionService interface {
	RunOnce(ctx context.Context) (inspection.Summary, error)
	Last() (inspection.Summary, bool)
	Running() bool
}

type asyncInspectionService interface {
	Start(ctx context.Context) error
}

// TokenService refreshes credentials and fetches billing.
type TokenService interface {
	ForceRefreshToken(ctx context.Context, credID string) (auth.TokenSet, storage.Credential, error)
	GetBillingSnapshot(ctx context.Context, credID string) (*upstream.BillingSnapshot, error)
}

// Handlers serves /admin/* endpoints.
type Handlers struct {
	Store         Store
	Tokens        TokenService
	OAuth         DeviceOAuth
	OAuthFor      func() (DeviceOAuth, error)
	Settings      RuntimeSettingsService
	Outbound      idleConnectionCloser
	ProxyResolver proxyResolver
	TokenCache    tokenCacheInvalidator
	Imports       ImportJobService
	Inspection    InspectionService
	// DashboardData supplies process counters without creating an admin-to-HTTP import cycle.
	DashboardData func() map[string]any
	Config        config.Config
	// AdminKey is the plaintext admin bearer secret (process-local).
	AdminKey string
	// Version overrides package Version when non-empty.
	Version string
	// MaxBody limits JSON body size.
	MaxBody int64

	deviceMu       sync.Mutex
	deviceSessions map[string]deviceSession
}

// maskedCredential is a credential view with secrets redacted.
type maskedCredential struct {
	ID                         string         `json:"id"`
	Name                       string         `json:"name"`
	Email                      string         `json:"email,omitempty"`
	UserID                     string         `json:"user_id,omitempty"`
	TeamID                     string         `json:"team_id,omitempty"`
	OIDCClientID               string         `json:"oidc_client_id,omitempty"`
	OIDCIssuer                 string         `json:"oidc_issuer,omitempty"`
	AccessToken                string         `json:"access_token"`  // masked
	RefreshToken               string         `json:"refresh_token"` // masked
	HasAccess                  bool           `json:"has_access_token"`
	HasRefresh                 bool           `json:"has_refresh_token"`
	ExpiresAt                  time.Time      `json:"expires_at"`
	Enabled                    bool           `json:"enabled"`
	ManualDisabled             bool           `json:"manual_disabled,omitempty"`
	LifecycleState             string         `json:"lifecycle_state,omitempty"`
	DisableReason              string         `json:"disable_reason,omitempty"`
	QuarantinedAt              *time.Time     `json:"quarantined_at,omitempty"`
	PurgeAfter                 *time.Time     `json:"purge_after,omitempty"`
	ProxyMode                  string         `json:"proxy_mode,omitempty"`
	ProxyURL                   string         `json:"proxy_url,omitempty"`
	EffectiveProxy             map[string]any `json:"effective_proxy,omitempty"`
	Priority                   int            `json:"priority"`
	FailureCount               int            `json:"failure_count"`
	CooldownUntil              *time.Time     `json:"cooldown_until,omitempty"`
	LastError                  string         `json:"last_error,omitempty"`
	LastUsedAt                 *time.Time     `json:"last_used_at,omitempty"`
	LastSuccessAt              *time.Time     `json:"last_success_at,omitempty"`
	LastInspectionAt           *time.Time     `json:"last_inspection_at,omitempty"`
	LastInspectionStatus       string         `json:"last_inspection_status,omitempty"`
	LastInspectionError        string         `json:"last_inspection_error,omitempty"`
	RateLimitLimitRequests     *int64         `json:"rate_limit_limit_requests,omitempty"`
	RateLimitRemainingRequests *int64         `json:"rate_limit_remaining_requests,omitempty"`
	RateLimitLimitTokens       *int64         `json:"rate_limit_limit_tokens,omitempty"`
	RateLimitRemainingTokens   *int64         `json:"rate_limit_remaining_tokens,omitempty"`
	RateLimitObservedAt        *time.Time     `json:"rate_limit_observed_at,omitempty"`
	Billing                    map[string]any `json:"billing,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}

func (h *Handlers) maskedCredential(c storage.Credential) maskedCredential {
	out := maskCredential(c)
	if h != nil && h.ProxyResolver != nil {
		if resolved, err := h.ProxyResolver.Resolve(&c); err == nil {
			out.EffectiveProxy = map[string]any{"mode": resolved.Mode, "source": resolved.Source, "url": outbound.RedactedURL(resolved.URL)}
		}
	}
	return out
}

func maskCredential(c storage.Credential) maskedCredential {
	return maskedCredential{
		ID:                         c.ID,
		Name:                       c.Name,
		Email:                      c.Email,
		UserID:                     c.UserID,
		TeamID:                     c.TeamID,
		OIDCClientID:               c.OIDCClientID,
		OIDCIssuer:                 c.OIDCIssuer,
		AccessToken:                maskSecret(c.AccessToken),
		RefreshToken:               maskSecret(c.RefreshToken),
		HasAccess:                  strings.TrimSpace(c.AccessToken) != "",
		HasRefresh:                 strings.TrimSpace(c.RefreshToken) != "",
		ExpiresAt:                  c.ExpiresAt,
		Enabled:                    c.Enabled,
		ManualDisabled:             c.ManualDisabled,
		LifecycleState:             c.LifecycleState,
		DisableReason:              c.DisableReason,
		QuarantinedAt:              c.QuarantinedAt,
		PurgeAfter:                 c.PurgeAfter,
		ProxyMode:                  c.ProxyMode,
		ProxyURL:                   outbound.RedactedURL(c.ProxyURL),
		Priority:                   c.Priority,
		FailureCount:               c.FailureCount,
		CooldownUntil:              c.CooldownUntil,
		LastError:                  c.LastError,
		LastUsedAt:                 c.LastUsedAt,
		LastSuccessAt:              c.LastSuccessAt,
		LastInspectionAt:           c.LastInspectionAt,
		LastInspectionStatus:       c.LastInspectionStatus,
		LastInspectionError:        c.LastInspectionError,
		RateLimitLimitRequests:     c.RateLimitLimitRequests,
		RateLimitRemainingRequests: c.RateLimitRemainingRequests,
		RateLimitLimitTokens:       c.RateLimitLimitTokens,
		RateLimitRemainingTokens:   c.RateLimitRemainingTokens,
		RateLimitObservedAt:        c.RateLimitObservedAt,
		Billing:                    c.Billing,
		CreatedAt:                  c.CreatedAt,
		UpdatedAt:                  c.UpdatedAt,
	}
}

// maskSecret never returns the full secret. Empty → empty; short → "***"; long → redacted.
// Only tokens longer than 24 chars expose a tiny fingerprint (2+2); never full short secrets.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 24 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

func (h *Handlers) maxBody() int64 {
	if h != nil && h.MaxBody > 0 {
		return h.MaxBody
	}
	return 1 << 20
}

func (h *Handlers) version() string {
	if h != nil && h.Version != "" {
		return h.Version
	}
	return Version
}

// RequireAdmin is middleware that accepts only Authorization: Bearer <admin_key>.
func (h *Handlers) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h == nil || strings.TrimSpace(h.AdminKey) == "" {
			writeErr(w, http.StatusServiceUnavailable, "admin key not configured")
			return
		}
		got := bearerToken(r)
		if got == "" || !subtleConstantTimeEq(got, h.AdminKey) {
			writeErr(w, http.StatusUnauthorized, "invalid admin key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) >= 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	// Also accept x-admin-key for convenience.
	if v := strings.TrimSpace(r.Header.Get("X-Admin-Key")); v != "" {
		return v
	}
	return ""
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

const (
	defaultCredentialPageSize = 24
	maxCredentialPageSize     = 100
	maxCredentialPage         = 1_000_000
)

type credentialPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// ListCredentials GET /admin/credentials
func (h *Handlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	page, pageSize, query, status, err := credentialListQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now()
	filtered := filterCredentials(creds, query, status, now)
	totalPages := (len(filtered) + pageSize - 1) / pageSize
	if totalPages > 0 && page > totalPages {
		page = totalPages
	}
	start := (page - 1) * pageSize
	end := min(start+pageSize, len(filtered))
	out := make([]maskedCredential, 0, end-start)
	for _, c := range filtered[start:end] {
		out = append(out, h.maskedCredential(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": out,
		"pool":        summarizePool(creds, now),
		"pagination": credentialPagination{
			Page:       page,
			PageSize:   pageSize,
			Total:      len(filtered),
			TotalPages: totalPages,
		},
	})
}

func credentialListQuery(r *http.Request) (page, pageSize int, query, status string, err error) {
	page, err = positiveQueryInt(r, "page", 1, maxCredentialPage)
	if err != nil {
		return 0, 0, "", "", err
	}
	pageSize, err = positiveQueryInt(r, "page_size", defaultCredentialPageSize, maxCredentialPageSize)
	if err != nil {
		return 0, 0, "", "", err
	}
	query = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(query) > 256 {
		return 0, 0, "", "", fmt.Errorf("q must be at most 256 bytes")
	}
	status = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	switch status {
	case "", "all", "available", "cooling", "disabled", "healthy", "rate_limited",
		"quota_exhausted", "unauthorized", "quarantined", "uninspected", "inspection_error", "expired":
		if status == "" {
			status = "all"
		}
	default:
		return 0, 0, "", "", fmt.Errorf("invalid credential status filter")
	}
	return page, pageSize, query, status, nil
}

func positiveQueryInt(r *http.Request, name string, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be between 1 and %d", name, maximum)
	}
	return value, nil
}

func filterCredentials(creds []storage.Credential, query, status string, now time.Time) []storage.Credential {
	filtered := make([]storage.Credential, 0, len(creds))
	for _, credential := range creds {
		cooling := credential.CooldownUntil != nil && credential.CooldownUntil.After(now)
		switch status {
		case "available":
			if !credential.Enabled || cooling {
				continue
			}
		case "cooling":
			if !credential.Enabled || !cooling {
				continue
			}
		case "disabled":
			if credential.Enabled {
				continue
			}
		case "healthy":
			if credential.LastInspectionStatus != "healthy" {
				continue
			}
		case "rate_limited":
			if credential.LastInspectionStatus != "rate_limited" {
				continue
			}
		case "quota_exhausted":
			if credential.LastInspectionStatus != "quota_exhausted" && credential.LastError != "quota_exhausted" {
				continue
			}
		case "unauthorized":
			if credential.LastInspectionStatus != "unauthorized" &&
				credential.LastInspectionStatus != "unauthorized_unconfirmed" &&
				credential.DisableReason != storage.DisableReasonInvalidAuth {
				continue
			}
		case "quarantined":
			if credential.LifecycleState != storage.CredentialStateQuarantined {
				continue
			}
		case "uninspected":
			if credential.LastInspectionAt != nil || credential.LastInspectionStatus != "" {
				continue
			}
		case "inspection_error":
			if !isInspectionErrorStatus(credential.LastInspectionStatus) {
				continue
			}
		case "expired":
			if credential.ExpiresAt.IsZero() || credential.ExpiresAt.After(now) {
				continue
			}
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{
				credential.ID,
				credential.Name,
				credential.Email,
				credential.UserID,
				credential.TeamID,
			}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, credential)
	}
	return filtered
}

func isInspectionErrorStatus(status string) bool {
	switch status {
	case "state_changed", "settings_changed", "mass_failure_guard", "storage_error":
		return true
	default:
		return false
	}
}

// CreateCredential POST /admin/credentials
func (h *Handlers) CreateCredential(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string `json:"name"`
		Email        string `json:"email"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		Priority     *int   `json:"priority"`
		Enabled      *bool  `json:"enabled"`
		OIDCIssuer   string `json:"oidc_issuer"`
		OIDCClientID string `json:"oidc_client_id"`
		UserID       string `json:"user_id"`
		TeamID       string `json:"team_id"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var exp time.Time
	if strings.TrimSpace(body.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		exp = t
	}
	created, err := h.Store.CreateCredential(storage.CreateCredentialInput{
		Name:         body.Name,
		Email:        body.Email,
		UserID:       body.UserID,
		TeamID:       body.TeamID,
		OIDCIssuer:   body.OIDCIssuer,
		OIDCClientID: body.OIDCClientID,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		ExpiresAt:    exp,
		Enabled:      body.Enabled,
		Priority:     body.Priority,
	})
	if err != nil {
		if errors.Is(err, storage.ErrCredentialExists) {
			writeErr(w, http.StatusConflict, "credential already exists; update or import it instead")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, h.maskedCredential(created))
}

// ImportGrok POST /admin/credentials/import-grok
// Prefer body.raw JSON. path is optional and jailed to ~/.grok or data_dir.
func (h *Handlers) ImportGrok(w http.ResponseWriter, r *http.Request) {
	if h.Imports == nil {
		writeErr(w, http.StatusServiceUnavailable, "credential importer unavailable")
		return
	}
	var body struct {
		Path string          `json:"path"`
		Raw  json.RawMessage `json:"raw"`
	}
	// Body is optional; empty body → default path. Malformed JSON is 400 (not silent fallback).
	maxTotalBytes := h.importMaxTotalBytes()
	if err := decodeJSON(r, maxTotalBytes, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var data []byte
	var name string
	if len(body.Raw) > 0 {
		data = append([]byte(nil), body.Raw...)
		name = "auth.json"
	} else {
		var err error
		data, name, err = h.readLegacyGrokAuthFile(body.Path)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	job, err := h.Imports.Start([]importer.InputFile{{Name: name, Format: importer.FormatJSON, Data: data}})
	wipeBytes(data)
	if err != nil {
		if errors.Is(err, importer.ErrOverloaded) {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	finished, ok := h.waitImportJob(r.Context(), job.ID)
	if !ok {
		w.Header().Set("Location", "/admin/import-jobs/"+job.ID)
		writeJSON(w, http.StatusAccepted, job)
		return
	}
	h.writeLegacyImportResponse(r.Context(), w, finished)
}

func (h *Handlers) writeLegacyImportResponse(ctx context.Context, w http.ResponseWriter, job importer.Job) {
	if err := ctx.Err(); err != nil {
		return
	}
	// Resolve imported IDs from one credentials snapshot. Calling GetCredential
	// once per result rereads and decodes the full credentials file up to the
	// batch limit, turning the compatibility response into O(batch*pool) I/O.
	credentialsByID := make(map[string]storage.Credential)
	if stored, err := h.Store.ListCredentials(); err == nil {
		credentialsByID = make(map[string]storage.Credential, len(stored))
		for _, credential := range stored {
			credentialsByID[credential.ID] = credential
		}
	}
	credentials := make([]maskedCredential, 0, job.Created+job.Updated)
	results := make([]map[string]any, 0, len(job.Results))
	for _, item := range job.Results {
		if err := ctx.Err(); err != nil {
			return
		}
		result := map[string]any{"source_key": item.Source, "status": item.Status}
		if item.CredentialID != "" {
			result["id"] = item.CredentialID
			if credential, ok := credentialsByID[item.CredentialID]; ok {
				credentials = append(credentials, h.maskedCredential(credential))
			}
			if h.TokenCache != nil {
				h.TokenCache.Invalidate(item.CredentialID)
			}
		}
		if item.Error != "" {
			result["error"] = item.Error
		}
		results = append(results, result)
	}
	status := http.StatusOK
	if job.Created > 0 {
		status = http.StatusCreated
	}
	if job.Failed > 0 && job.Created+job.Updated == 0 {
		status = http.StatusBadRequest
	} else if job.Failed > 0 {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, map[string]any{
		"imported":    job.Created + job.Updated,
		"created":     job.Created,
		"updated":     job.Updated,
		"failed":      job.Failed,
		"job_id":      job.ID,
		"results":     results,
		"credentials": credentials,
	})
}

func (h *Handlers) waitImportJob(ctx context.Context, id string) (importer.Job, bool) {
	maxWait := h.Config.RequestTimeout()
	if maxWait <= 0 {
		maxWait = 30 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		job, ok := h.Imports.Get(id)
		if !ok {
			return importer.Job{}, false
		}
		switch job.Status {
		case importer.StatusCompleted, importer.StatusPartial, importer.StatusFailed:
			return job, true
		}
		select {
		case <-waitCtx.Done():
			return job, false
		case <-ticker.C:
		}
	}
}

func (h *Handlers) readLegacyGrokAuthFile(path string) ([]byte, string, error) {
	var roots []string
	if strings.TrimSpace(h.Config.DataDir) != "" {
		roots = append(roots, h.Config.DataDir)
	}
	resolved, err := auth.ResolveGrokAuthPath(path, roots...)
	if err != nil {
		return nil, "", err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("import grok auth: read failed: %w", err)
	}
	defer file.Close()
	limit := h.Config.Import.MaxFileBytes
	if limit <= 0 || limit > h.importMaxTotalBytes() {
		limit = h.importMaxTotalBytes()
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, "", fmt.Errorf("import grok auth: read failed: %w", err)
	}
	if int64(len(data)) > limit {
		wipeBytes(data)
		return nil, "", fmt.Errorf("import grok auth: file exceeds %d bytes", limit)
	}
	return data, filepath.Base(resolved), nil
}

func (h *Handlers) importMaxTotalBytes() int64 {
	if h != nil && h.Config.Import.MaxTotalBytes > 0 {
		return h.Config.Import.MaxTotalBytes
	}
	return 16 << 20
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// StartImportJob POST /admin/import-jobs accepts multipart files or JSON documents.
func (h *Handlers) StartImportJob(w http.ResponseWriter, r *http.Request) {
	if h.Imports == nil {
		writeErr(w, http.StatusServiceUnavailable, "credential importer unavailable")
		return
	}
	files, err := h.readImportFiles(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := h.Imports.Start(files)
	if err != nil {
		if errors.Is(err, importer.ErrOverloaded) {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	collectionPath := "/admin/import-jobs"
	if strings.TrimSuffix(r.URL.Path, "/") == "/admin/credential-imports" {
		collectionPath = "/admin/credential-imports"
	}
	w.Header().Set("Location", collectionPath+"/"+job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

// ImportJob GET /admin/import-jobs/{id}.
func (h *Handlers) ImportJob(w http.ResponseWriter, r *http.Request, id string) {
	if h.Imports == nil {
		writeErr(w, http.StatusServiceUnavailable, "credential importer unavailable")
		return
	}
	job, ok := h.Imports.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "import job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (h *Handlers) readImportFiles(w http.ResponseWriter, r *http.Request) ([]importer.InputFile, error) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	maxFileBytes := h.Config.Import.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = 4 << 20
	}
	maxTotalBytes := h.Config.Import.MaxTotalBytes
	if maxTotalBytes <= 0 {
		maxTotalBytes = 16 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTotalBytes)
	if strings.HasPrefix(contentType, "multipart/form-data") {
		reader, err := r.MultipartReader()
		if err != nil {
			return nil, fmt.Errorf("invalid multipart body: %w", err)
		}
		format := importer.FormatAuto
		var files []importer.InputFile
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("read multipart body: %w", err)
			}
			if part.FileName() == "" {
				value, readErr := io.ReadAll(io.LimitReader(part, 1025))
				_ = part.Close()
				if readErr != nil {
					return nil, fmt.Errorf("read multipart field: %w", readErr)
				}
				if part.FormName() == "format" {
					format = strings.ToLower(strings.TrimSpace(string(value)))
				}
				continue
			}
			value, readErr := io.ReadAll(io.LimitReader(part, maxFileBytes+1))
			_ = part.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read import file: %w", readErr)
			}
			if int64(len(value)) > maxFileBytes {
				return nil, fmt.Errorf("import file %q exceeds %d bytes", filepath.Base(part.FileName()), maxFileBytes)
			}
			files = append(files, importer.InputFile{
				Name: filepath.Base(part.FileName()), Format: format, Data: value,
			})
		}
		for index := range files {
			if files[index].Format == importer.FormatAuto && format != "" {
				files[index].Format = format
			}
		}
		return files, nil
	}

	var body struct {
		Name      string          `json:"name"`
		Format    string          `json:"format"`
		Raw       json.RawMessage `json:"raw"`
		Text      string          `json:"text"`
		Documents []struct {
			Name    string          `json:"name"`
			Format  string          `json:"format"`
			Content json.RawMessage `json:"content"`
			Text    string          `json:"text"`
		} `json:"documents"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		return nil, err
	}
	var files []importer.InputFile
	if len(body.Documents) > 0 {
		for index, document := range body.Documents {
			data, err := importDocumentBytes(document.Content, document.Text)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", index+1, err)
			}
			files = append(files, importer.InputFile{
				Name: document.Name, Format: document.Format, Data: data,
			})
		}
	} else {
		data, err := importDocumentBytes(body.Raw, body.Text)
		if err != nil {
			return nil, err
		}
		files = append(files, importer.InputFile{Name: body.Name, Format: body.Format, Data: data})
	}
	return files, nil
}

func importDocumentBytes(raw json.RawMessage, text string) ([]byte, error) {
	if len(raw) > 0 && string(raw) != "null" {
		if raw[0] == '"' {
			var decoded string
			if err := json.Unmarshal(raw, &decoded); err != nil {
				return nil, fmt.Errorf("invalid string document")
			}
			return []byte(decoded), nil
		}
		return append([]byte(nil), raw...), nil
	}
	if strings.TrimSpace(text) != "" {
		return []byte(text), nil
	}
	return nil, fmt.Errorf("raw or text document is required")
}

// DisableCredential POST /admin/credentials/{id}/disable
func (h *Handlers) DisableCredential(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Enabled *bool `json:"enabled"`
		Disable *bool `json:"disable"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := false
	if body.Enabled != nil {
		enabled = *body.Enabled
	} else if body.Disable != nil {
		enabled = !*body.Disable
	} else {
		// Toggle when no body fields.
		cur, err := h.Store.GetCredential(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		enabled = !cur.Enabled
	}
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	updated, err := h.Store.SetCredentialEnabled(id, enabled)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	writeJSON(w, http.StatusOK, h.maskedCredential(updated))
}

// SetPriority PUT /admin/credentials/{id}/priority
func (h *Handlers) SetPriority(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Priority int `json:"priority"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.Store.SetCredentialPriority(id, body.Priority)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.maskedCredential(updated))
}

// SetCredentialProxy PUT /admin/credentials/{id}/proxy.
func (h *Handlers) SetCredentialProxy(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Mode string `json:"mode"`
		URL  string `json:"url"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(body.Mode))
	proxyURL := strings.TrimSpace(body.URL)
	switch mode {
	case "", outbound.ModeInherit:
		mode = outbound.ModeInherit
		proxyURL = ""
	case outbound.ModeDirect:
		proxyURL = ""
	case outbound.ModeURL:
		validated, err := outbound.ValidateProxyURL(proxyURL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		proxyURL = validated
	default:
		writeErr(w, http.StatusBadRequest, "mode must be inherit, direct, or url")
		return
	}
	// Invalidate before and after the storage mutation. The first invalidation
	// prevents an old-route refresh from committing across the change; the
	// second invalidates any refresh that began before the new route became
	// visible.
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	updated, err := h.Store.PatchCredential(id, func(credential *storage.Credential) error {
		credential.ProxyMode = mode
		credential.ProxyURL = proxyURL
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	if h.Outbound != nil {
		h.Outbound.CloseIdleConnections()
	}
	writeJSON(w, http.StatusOK, h.maskedCredential(updated))
}

// RuntimeSettings GET /admin/settings.
func (h *Handlers) RuntimeSettings(w http.ResponseWriter, r *http.Request) {
	if h.Settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "runtime settings unavailable")
		return
	}
	writeJSON(w, http.StatusOK, h.maskRuntimeSettings(h.Settings.Current()))
}

// UpdateRuntimeSettings PUT /admin/settings.
func (h *Handlers) UpdateRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	if h.Settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "runtime settings unavailable")
		return
	}
	var body struct {
		GlobalProxy  *storage.GlobalProxySettings `json:"global_proxy"`
		SSOConverter *struct {
			Enabled       *bool   `json:"enabled"`
			Endpoint      *string `json:"endpoint"`
			APIKey        *string `json:"api_key"`
			ClearAPIKey   bool    `json:"clear_api_key"`
			AllowInsecure *bool   `json:"allow_insecure_http"`
			TimeoutSec    *int    `json:"timeout_sec"`
			MaxBatch      *int    `json:"max_batch"`
		} `json:"sso_converter"`
		Notifications *struct {
			FeishuWebhookURL   *string `json:"feishu_webhook_url"`
			ClearFeishuWebhook bool    `json:"clear_feishu_webhook"`
		} `json:"notifications"`
		Inspection *storage.InspectionSettings `json:"inspection"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if cache, ok := h.TokenCache.(interface{ InvalidateAll() }); ok {
		// Retire refreshes that resolved the old global route before the settings
		// mutation. The post-update invalidation below catches flights that start in
		// the narrow transition window.
		cache.InvalidateAll()
	}
	updated, err := h.Settings.Update(func(settings *storage.RuntimeSettings) error {
		if body.GlobalProxy != nil {
			mode := strings.ToLower(strings.TrimSpace(body.GlobalProxy.Mode))
			switch mode {
			case outbound.ModeEnvironment, outbound.ModeDirect:
				settings.GlobalProxy = storage.GlobalProxySettings{Mode: mode}
			case outbound.ModeURL:
				value, err := outbound.ValidateProxyURL(body.GlobalProxy.URL)
				if err != nil {
					return err
				}
				settings.GlobalProxy = storage.GlobalProxySettings{Mode: mode, URL: value}
			default:
				return fmt.Errorf("global_proxy.mode must be environment, direct, or url")
			}
		}
		if converter := body.SSOConverter; converter != nil {
			if converter.Enabled != nil {
				settings.SSOConverter.Enabled = *converter.Enabled
			}
			if converter.AllowInsecure != nil {
				settings.SSOConverter.AllowInsecure = *converter.AllowInsecure
			}
			if converter.Endpoint != nil {
				endpoint, err := validateConverterEndpoint(*converter.Endpoint, settings.SSOConverter.AllowInsecure)
				if err != nil {
					return err
				}
				settings.SSOConverter.Endpoint = endpoint
			}
			if converter.ClearAPIKey {
				settings.SSOConverter.APIKey = ""
			} else if converter.APIKey != nil && strings.TrimSpace(*converter.APIKey) != "" {
				settings.SSOConverter.APIKey = strings.TrimSpace(*converter.APIKey)
			}
			if converter.TimeoutSec != nil {
				settings.SSOConverter.TimeoutSec = *converter.TimeoutSec
			}
			if converter.MaxBatch != nil {
				settings.SSOConverter.MaxBatch = *converter.MaxBatch
			}
			if settings.SSOConverter.Enabled {
				endpoint, err := validateConverterEndpoint(settings.SSOConverter.Endpoint, settings.SSOConverter.AllowInsecure)
				if err != nil {
					return err
				}
				settings.SSOConverter.Endpoint = endpoint
			}
		}
		if body.Inspection != nil {
			settings.Inspection = *body.Inspection
		}
		if notifications := body.Notifications; notifications != nil {
			if notifications.ClearFeishuWebhook {
				settings.Notifications.FeishuWebhookURL = ""
			} else if notifications.FeishuWebhookURL != nil && strings.TrimSpace(*notifications.FeishuWebhookURL) != "" {
				settings.Notifications.FeishuWebhookURL = strings.TrimSpace(*notifications.FeishuWebhookURL)
			}
		}
		return settings.Validate()
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.Outbound != nil {
		h.Outbound.CloseIdleConnections()
	}
	if cache, ok := h.TokenCache.(interface{ InvalidateAll() }); ok {
		cache.InvalidateAll()
	}
	writeJSON(w, http.StatusOK, h.maskRuntimeSettings(updated))
}

// InspectionStatus GET /admin/inspection.
func (h *Handlers) InspectionStatus(w http.ResponseWriter, r *http.Request) {
	if h.Inspection == nil {
		writeErr(w, http.StatusServiceUnavailable, "credential inspection unavailable")
		return
	}
	last, ok := h.Inspection.Last()
	response := map[string]any{
		"running": h.Inspection.Running(),
		"has_run": ok,
		"last":    last,
	}
	if progressProvider, ok := h.Inspection.(interface {
		Progress() (inspection.Progress, bool)
	}); ok {
		if progress, active := progressProvider.Progress(); active {
			response["progress"] = progress
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// RunInspection POST /admin/inspection/run.
func (h *Handlers) RunInspection(w http.ResponseWriter, r *http.Request) {
	if h.Inspection == nil {
		writeErr(w, http.StatusServiceUnavailable, "credential inspection unavailable")
		return
	}
	if starter, ok := h.Inspection.(asyncInspectionService); ok {
		if err := starter.Start(context.Background()); err != nil {
			if strings.Contains(err.Error(), "already in progress") {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
		return
	}
	summary, err := h.Inspection.RunOnce(r.Context())
	if err != nil {
		if strings.Contains(err.Error(), "already in progress") {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// RefreshCredential POST /admin/credentials/{id}/refresh
func (h *Handlers) RefreshCredential(w http.ResponseWriter, r *http.Request, id string) {
	if h.Tokens == nil {
		writeErr(w, http.StatusServiceUnavailable, "token service not configured")
		return
	}
	_, cred, err := h.Tokens.ForceRefreshToken(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.maskedCredential(cred))
}

// CredentialBilling GET /admin/credentials/{id}/billing
func (h *Handlers) CredentialBilling(w http.ResponseWriter, r *http.Request, id string) {
	if h.Tokens == nil {
		writeErr(w, http.StatusServiceUnavailable, "token service not configured")
		return
	}
	snap, err := h.Tokens.GetBillingSnapshot(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// DeleteCredential DELETE /admin/credentials/{id}
func (h *Handlers) DeleteCredential(w http.ResponseWriter, r *http.Request, id string) {
	// Retire an in-flight refresh before deletion so it cannot persist token
	// material into the disappearing credential. Invalidate again afterwards to
	// remove any cache result committed in the narrow delete window.
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	if err := h.Store.DeleteCredential(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ListClients GET /admin/clients
func (h *Handlers) ListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.Store.ListClients()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// CreateClient POST /admin/clients
func (h *Handlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.Store.CreateClient(body.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":    res.Client,
		"plaintext": res.Plaintext,
		"api_key":   res.Plaintext,
	})
}

// DeleteClient DELETE /admin/clients/{id}
func (h *Handlers) DeleteClient(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.DeleteClient(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// System GET /admin/system
func (h *Handlers) System(w http.ResponseWriter, r *http.Request) {
	credentials, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": h.version(),
		"listen":  h.Config.Listen,
		"upstream": map[string]any{
			"base_url":          h.Config.Upstream.BaseURL,
			"client_version":    h.Config.Upstream.ClientVersion,
			"client_identifier": h.Config.Upstream.ClientIdentifier,
			"user_agent":        h.Config.Upstream.UserAgent,
			"token_auth":        h.Config.Upstream.TokenAuth,
		},
		"data_dir":     h.Config.DataDir,
		"chat_backend": h.Config.ChatBackend,
		"anthropic": map[string]any{
			"enabled": h.Config.Anthropic.Enabled,
		},
		"limits": h.Config.Limits,
		"pool":   summarizePool(credentials, time.Now()),
	})
}

// Dashboard GET /admin/dashboard returns bounded operational aggregates only.
func (h *Handlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	credentials, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	now := time.Now()
	recentIssues := make([]map[string]any, 0, 8)
	for _, credential := range credentials {
		if len(recentIssues) >= 8 {
			break
		}
		if credential.Enabled && credential.LastError == "" && credential.LastInspectionStatus != "unauthorized" && credential.LastInspectionStatus != "error" && (credential.CooldownUntil == nil || !credential.CooldownUntil.After(now)) {
			continue
		}
		recentIssues = append(recentIssues, map[string]any{
			"id": credential.ID, "name": credential.Name, "enabled": credential.Enabled,
			"lifecycle_state": credential.LifecycleState, "last_error": credential.LastError,
			"inspection_status": credential.LastInspectionStatus, "cooldown_until": credential.CooldownUntil,
		})
	}
	metrics := map[string]any{}
	if h.DashboardData != nil {
		metrics = h.DashboardData()
	}
	inspection := map[string]any{"available": h.Inspection != nil}
	if h.Inspection != nil {
		last, hasRun := h.Inspection.Last()
		inspection["running"] = h.Inspection.Running()
		inspection["has_run"] = hasRun
		if hasRun {
			inspection["last"] = last
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": now.UTC(), "version": h.version(), "pool": summarizePool(credentials, now),
		"metrics": metrics, "inspection": inspection, "recent_issues": recentIssues,
	})
}

func (h *Handlers) maskRuntimeSettings(settings storage.RuntimeSettings) map[string]any {
	proxyMode := settings.GlobalProxy.Mode
	proxyURL := outbound.RedactedURL(settings.GlobalProxy.URL)
	proxySource := "runtime"
	if h != nil && h.ProxyResolver != nil {
		if resolved, err := h.ProxyResolver.Resolve(nil); err == nil {
			proxyMode, proxyURL, proxySource = resolved.Mode, outbound.RedactedURL(resolved.URL), resolved.Source
		}
	}
	return map[string]any{
		"global_proxy": map[string]any{
			"mode":   proxyMode,
			"url":    proxyURL,
			"source": proxySource,
		},
		"sso_converter": map[string]any{
			"enabled":             settings.SSOConverter.Enabled,
			"endpoint":            settings.SSOConverter.Endpoint,
			"api_key_configured":  strings.TrimSpace(settings.SSOConverter.APIKey) != "",
			"allow_insecure_http": settings.SSOConverter.AllowInsecure,
			"timeout_sec":         settings.SSOConverter.TimeoutSec,
			"max_batch":           settings.SSOConverter.MaxBatch,
		},
		"inspection": settings.Inspection,
		"notifications": map[string]any{
			"feishu_webhook_configured": strings.TrimSpace(settings.Notifications.FeishuWebhookURL) != "",
		},
	}
}

func validateConverterEndpoint(raw string, allowInsecure bool) (string, error) {
	return sso.ValidateEndpoint(raw, allowInsecure)
}

func decodeJSON(r *http.Request, max int64, dest any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("missing body")
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, max+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(raw)) > max {
		return fmt.Errorf("request body too large")
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "admin_error",
			"code":    status,
		},
	})
}
