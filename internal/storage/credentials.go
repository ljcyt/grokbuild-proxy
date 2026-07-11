package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var ErrCredentialExists = errors.New("storage: credential already exists")

const (
	CredentialStateActive      = "active"
	CredentialStateQuarantined = "quarantined"

	DisableReasonManual      = "manual"
	DisableReasonInvalidAuth = "invalid_auth"

	CredentialProxyInherit = "inherit"
	CredentialProxyDirect  = "direct"
	CredentialProxyURL     = "url"
)

// Credential is a persisted Grok Build OAuth session used for upstream calls.
// Sensitive tokens are stored on disk with mode 0600; never log them.
type Credential struct {
	ID string `json:"id"`
	// Revision is incremented on every persisted mutation. Long-running probes
	// compare it under the store lock before applying quarantine or purge so a
	// concurrent token, proxy, issuer, client, enabled, or lifecycle change
	// invalidates stale health evidence.
	Revision                   uint64         `json:"revision"`
	Name                       string         `json:"name"`
	Email                      string         `json:"email,omitempty"`
	UserID                     string         `json:"user_id,omitempty"`
	TeamID                     string         `json:"team_id,omitempty"`
	IdentityKey                string         `json:"identity_key,omitempty"`
	SourceKey                  string         `json:"source_key,omitempty"`
	OIDCIssuer                 string         `json:"oidc_issuer,omitempty"`
	OIDCClientID               string         `json:"oidc_client_id,omitempty"`
	AccessToken                string         `json:"access_token"`
	RefreshToken               string         `json:"refresh_token"`
	ExpiresAt                  time.Time      `json:"expires_at"`
	Enabled                    bool           `json:"enabled"`
	ManualDisabled             bool           `json:"manual_disabled,omitempty"`
	LifecycleState             string         `json:"lifecycle_state,omitempty"`
	DisableReason              string         `json:"disable_reason,omitempty"`
	QuarantinedAt              *time.Time     `json:"quarantined_at,omitempty"`
	PurgeAfter                 *time.Time     `json:"purge_after,omitempty"`
	QuarantineTokenFingerprint string         `json:"quarantine_token_fingerprint,omitempty"`
	Priority                   int            `json:"priority"`
	ProxyMode                  string         `json:"proxy_mode,omitempty"`
	ProxyURL                   string         `json:"proxy_url,omitempty"`
	FailureCount               int            `json:"failure_count"`
	CooldownUntil              *time.Time     `json:"cooldown_until,omitempty"`
	LastError                  string         `json:"last_error,omitempty"`
	LastUsedAt                 *time.Time     `json:"last_used_at,omitempty"`
	LastSuccessAt              *time.Time     `json:"last_success_at,omitempty"`
	LastInspectionAt           *time.Time     `json:"last_inspection_at,omitempty"`
	LastInspectionStatus       string         `json:"last_inspection_status,omitempty"`
	LastInspectionError        string         `json:"last_inspection_error,omitempty"`
	ConsecutiveUnauthorized    int            `json:"consecutive_unauthorized,omitempty"`
	Billing                    map[string]any `json:"billing,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}

// credentialsDoc is the on-disk envelope for credentials.json.
type credentialsDoc struct {
	Credentials []Credential `json:"credentials"`
}

// ListCredentials returns all credentials sorted by priority desc, then id.
func (s *Store) ListCredentials() ([]Credential, error) {
	var out []Credential
	err := s.withLock(func() error {
		if err := s.ensureCredentialsCache(); err != nil {
			return err
		}
		out = cloneCredentials(s.credentialsCache)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// GetCredential returns a credential by id.
func (s *Store) GetCredential(id string) (Credential, error) {
	var found Credential
	err := s.withLock(func() error {
		if err := s.ensureCredentialsCache(); err != nil {
			return err
		}
		credential, ok := s.credentialsIndex[id]
		if !ok {
			return fmt.Errorf("storage: credential %q not found", id)
		}
		found = cloneCredential(credential)
		return nil
	})
	return found, err
}

// CreateCredentialInput is the mutable subset accepted on create.
type CreateCredentialInput struct {
	Name         string
	Email        string
	UserID       string
	TeamID       string
	IdentityKey  string
	SourceKey    string
	OIDCIssuer   string
	OIDCClientID string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Enabled      *bool
	Priority     *int
	ProxyMode    string
	ProxyURL     string
}

// BulkUpsertResult describes one item written by BulkUpsertCredentials.
type BulkUpsertResult struct {
	Credential Credential
	Created    bool
}

type InspectionActionKind string

const (
	InspectionActionHealthy    InspectionActionKind = "healthy"
	InspectionActionFailure    InspectionActionKind = "failure"
	InspectionActionQuarantine InspectionActionKind = "quarantine"
	InspectionActionPurge      InspectionActionKind = "purge"
	InspectionActionAttempt    InspectionActionKind = "attempt"
)

// InspectionAction is a compare-and-swap mutation produced from one observed
// credential snapshot. A whole inspection run is applied under one store lock
// and one credentials.json write.
type InspectionAction struct {
	ID                       string
	ExpectedRevision         uint64
	Kind                     InspectionActionKind
	At                       time.Time
	Status                   string
	Message                  string
	PurgeAfter               *time.Time
	CooldownUntil            *time.Time
	ExpectedPurgeAfter       *time.Time
	ExpectedTokenFingerprint string
	ResetQuarantineEvidence  bool
}

type InspectionActionResult struct {
	ID              string
	Kind            InspectionActionKind
	Applied         bool
	Deleted         bool
	Reactivated     bool
	Quarantined     bool
	AttemptRecorded bool
}

// CreateCredential appends a new credential and returns the stored record.
func (s *Store) CreateCredential(in CreateCredentialInput) (Credential, error) {
	if err := validateCredentialInput(in); err != nil {
		return Credential{}, err
	}
	var created Credential
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		for _, credential := range doc.Credentials {
			if sameCredentialIdentity(credential, in) {
				return fmt.Errorf("%w: %s", ErrCredentialExists, credential.ID)
			}
		}
		created, err = newCredential(in, nowUTC())
		if err != nil {
			return err
		}
		doc.Credentials = append(doc.Credentials, created)
		return s.saveCredentials(doc)
	})
	return created, err
}

// UpsertCredential imports a credential idempotently using stable account
// identity. Runtime health, enabled state, priority and creation time survive
// token rotation.
func (s *Store) UpsertCredential(in CreateCredentialInput) (Credential, bool, error) {
	if err := validateCredentialInput(in); err != nil {
		return Credential{}, false, err
	}
	var result Credential
	created := false
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		result, created, err = upsertCredentialDoc(&doc, in, nowUTC())
		if err != nil {
			return err
		}
		return s.saveCredentials(doc)
	})
	return result, created, err
}

// BulkUpsertCredentials validates all inputs, applies them under one store lock,
// and writes credentials.json once. A storage error commits none of the batch.
func (s *Store) BulkUpsertCredentials(inputs []CreateCredentialInput) ([]BulkUpsertResult, error) {
	if len(inputs) == 0 {
		return []BulkUpsertResult{}, nil
	}
	for _, in := range inputs {
		if err := validateCredentialInput(in); err != nil {
			return nil, err
		}
	}
	results := make([]BulkUpsertResult, 0, len(inputs))
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		now := nowUTC()
		for _, in := range inputs {
			credential, created, err := upsertCredentialDoc(&doc, in, now)
			if err != nil {
				return err
			}
			results = append(results, BulkUpsertResult{Credential: credential, Created: created})
		}
		return s.saveCredentials(doc)
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func validateCredentialInput(in CreateCredentialInput) error {
	if strings.TrimSpace(in.AccessToken) == "" && strings.TrimSpace(in.RefreshToken) == "" {
		return fmt.Errorf("storage: access_token or refresh_token required")
	}
	if err := validateCredentialProxy(in.ProxyMode, in.ProxyURL); err != nil {
		return err
	}
	if err := validateCredentialIssuer(in.OIDCIssuer); err != nil {
		return err
	}
	return nil
}

func validateCredentialIssuer(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("storage: invalid oidc_issuer: %w", err)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if u.Scheme != "https" || host != "auth.x.ai" ||
		(u.Port() != "" && u.Port() != "443") || u.User != nil ||
		strings.TrimRight(u.EscapedPath(), "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("storage: oidc_issuer must be exactly https://auth.x.ai")
	}
	return nil
}

func validateCredentialProxy(mode, rawURL string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	rawURL = strings.TrimSpace(rawURL)
	switch mode {
	case "", CredentialProxyInherit, CredentialProxyDirect:
		if rawURL != "" {
			return fmt.Errorf("storage: proxy_url requires proxy_mode=url")
		}
		return nil
	case CredentialProxyURL:
		if rawURL == "" {
			return fmt.Errorf("storage: proxy_url required for proxy_mode=url")
		}
	default:
		return fmt.Errorf("storage: invalid proxy_mode %q", mode)
	}
	if strings.ContainsAny(rawURL, "\r\n\x00") {
		return fmt.Errorf("storage: proxy_url contains control characters")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("storage: proxy_url must be absolute and include a host")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("storage: unsupported proxy_url scheme")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("storage: proxy_url must not contain query or fragment")
	}
	return nil
}

func newCredential(in CreateCredentialInput, now time.Time) (Credential, error) {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	priority := 100
	if in.Priority != nil {
		priority = *in.Priority
	}
	id, err := newID("cred")
	if err != nil {
		return Credential{}, err
	}
	state := CredentialStateActive
	manualDisabled := !enabled
	disableReason := ""
	if manualDisabled {
		disableReason = DisableReasonManual
	}
	return Credential{
		ID:             id,
		Revision:       1,
		Name:           strings.TrimSpace(in.Name),
		Email:          strings.TrimSpace(in.Email),
		UserID:         strings.TrimSpace(in.UserID),
		TeamID:         strings.TrimSpace(in.TeamID),
		IdentityKey:    stableInputIdentity(in),
		SourceKey:      strings.TrimSpace(in.SourceKey),
		OIDCIssuer:     strings.TrimRight(strings.TrimSpace(in.OIDCIssuer), "/"),
		OIDCClientID:   strings.TrimSpace(in.OIDCClientID),
		AccessToken:    strings.TrimSpace(in.AccessToken),
		RefreshToken:   strings.TrimSpace(in.RefreshToken),
		ExpiresAt:      truncateTime(in.ExpiresAt),
		Enabled:        enabled,
		ManualDisabled: manualDisabled,
		LifecycleState: state,
		DisableReason:  disableReason,
		Priority:       priority,
		ProxyMode:      strings.ToLower(strings.TrimSpace(in.ProxyMode)),
		ProxyURL:       strings.TrimSpace(in.ProxyURL),
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func upsertCredentialDoc(doc *credentialsDoc, in CreateCredentialInput, now time.Time) (Credential, bool, error) {
	for i := range doc.Credentials {
		if !sameCredentialIdentity(doc.Credentials[i], in) {
			continue
		}
		cur := doc.Credentials[i]
		tokenChanged := (strings.TrimSpace(in.AccessToken) != "" && strings.TrimSpace(in.AccessToken) != cur.AccessToken) ||
			(strings.TrimSpace(in.RefreshToken) != "" && strings.TrimSpace(in.RefreshToken) != cur.RefreshToken)
		if v := strings.TrimSpace(in.Name); v != "" {
			cur.Name = v
		}
		if v := strings.TrimSpace(in.Email); v != "" {
			cur.Email = v
		}
		if v := strings.TrimSpace(in.UserID); v != "" {
			cur.UserID = v
		}
		if v := strings.TrimSpace(in.TeamID); v != "" {
			cur.TeamID = v
		}
		if v := strings.TrimSpace(in.SourceKey); v != "" {
			cur.SourceKey = v
		}
		if v := strings.TrimRight(strings.TrimSpace(in.OIDCIssuer), "/"); v != "" {
			cur.OIDCIssuer = v
		}
		if v := strings.TrimSpace(in.OIDCClientID); v != "" {
			cur.OIDCClientID = v
		}
		if v := strings.TrimSpace(in.AccessToken); v != "" {
			cur.AccessToken = v
		}
		if v := strings.TrimSpace(in.RefreshToken); v != "" {
			cur.RefreshToken = v
		}
		if !in.ExpiresAt.IsZero() {
			cur.ExpiresAt = truncateTime(in.ExpiresAt)
		}
		if v := strings.TrimSpace(in.ProxyMode); v != "" {
			cur.ProxyMode = strings.ToLower(v)
			cur.ProxyURL = strings.TrimSpace(in.ProxyURL)
		}
		if v := strings.TrimSpace(in.IdentityKey); v != "" {
			cur.IdentityKey = v
		} else {
			cur.IdentityKey = computedCredentialIdentity(cur)
		}
		if tokenChanged && cur.DisableReason == DisableReasonInvalidAuth && !cur.ManualDisabled {
			cur.Enabled = true
			cur.LifecycleState = CredentialStateActive
			cur.DisableReason = ""
			cur.QuarantinedAt = nil
			cur.PurgeAfter = nil
			cur.QuarantineTokenFingerprint = ""
			cur.ConsecutiveUnauthorized = 0
			cur.LastInspectionError = ""
		}
		cur.UpdatedAt = now
		cur.Revision++
		doc.Credentials[i] = cur
		return cur, false, nil
	}

	created, err := newCredential(in, now)
	if err != nil {
		return Credential{}, false, err
	}
	doc.Credentials = append(doc.Credentials, created)
	return created, true, nil
}

func sameCredentialIdentity(c Credential, in CreateCredentialInput) bool {
	left := stableCredentialIdentity(c)
	right := stableInputIdentity(in)
	if left != "" && right != "" && left == right {
		return true
	}
	if strings.TrimSpace(in.UserID) != "" && c.UserID == strings.TrimSpace(in.UserID) &&
		identityScopeCompatible(c, in) {
		return strings.TrimSpace(in.TeamID) == "" || c.TeamID == "" || c.TeamID == strings.TrimSpace(in.TeamID)
	}
	if (strings.TrimSpace(in.UserID) == "" || strings.TrimSpace(c.UserID) == "") &&
		strings.TrimSpace(in.Email) != "" && c.Email != "" &&
		strings.EqualFold(c.Email, strings.TrimSpace(in.Email)) && identityScopeCompatible(c, in) {
		return true
	}
	return strings.TrimSpace(in.RefreshToken) != "" && c.RefreshToken == strings.TrimSpace(in.RefreshToken)
}

// identityScopeCompatible keeps legacy records with missing OIDC metadata
// upsertable while preventing the same user/email in distinct issuers or
// clients from being collapsed into one credential.
func identityScopeCompatible(c Credential, in CreateCredentialInput) bool {
	existingIssuer := strings.ToLower(strings.TrimRight(strings.TrimSpace(c.OIDCIssuer), "/"))
	incomingIssuer := strings.ToLower(strings.TrimRight(strings.TrimSpace(in.OIDCIssuer), "/"))
	if existingIssuer != "" && incomingIssuer != "" && existingIssuer != incomingIssuer {
		return false
	}
	existingClient := strings.ToLower(strings.TrimSpace(c.OIDCClientID))
	incomingClient := strings.ToLower(strings.TrimSpace(in.OIDCClientID))
	return existingClient == "" || incomingClient == "" || existingClient == incomingClient
}

func stableCredentialIdentity(c Credential) string {
	if strings.TrimSpace(c.IdentityKey) != "" {
		return strings.TrimSpace(c.IdentityKey)
	}
	return stableIdentity(c.OIDCIssuer, c.OIDCClientID, c.UserID, c.TeamID, c.Email, c.RefreshToken, c.AccessToken)
}

func computedCredentialIdentity(c Credential) string {
	return stableIdentity(c.OIDCIssuer, c.OIDCClientID, c.UserID, c.TeamID, c.Email, c.RefreshToken, c.AccessToken)
}

func stableInputIdentity(in CreateCredentialInput) string {
	if strings.TrimSpace(in.IdentityKey) != "" {
		return strings.TrimSpace(in.IdentityKey)
	}
	return stableIdentity(in.OIDCIssuer, in.OIDCClientID, in.UserID, in.TeamID, in.Email, in.RefreshToken, in.AccessToken)
}

func stableIdentity(issuer, clientID, userID, teamID, email, refreshToken, accessToken string) string {
	issuer = strings.ToLower(strings.TrimRight(strings.TrimSpace(issuer), "/"))
	clientID = strings.ToLower(strings.TrimSpace(clientID))
	userID = strings.TrimSpace(userID)
	teamID = strings.TrimSpace(teamID)
	if userID != "" {
		return "oidc:" + issuer + ":" + clientID + ":" + userID + ":" + teamID
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		return "email:" + issuer + ":" + clientID + ":" + email
	}
	token := strings.TrimSpace(refreshToken)
	kind := "refresh"
	if token == "" {
		token = strings.TrimSpace(accessToken)
		kind = "access"
	}
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return kind + ":" + hex.EncodeToString(sum[:])
}

func truncateTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Second)
}

// UpdateCredential replaces an existing credential by id.
// The full Credential is expected (callers typically Get then mutate).
// Prefer PatchCredential for concurrent field updates to avoid lost-refresh races.
func (s *Store) UpdateCredential(c Credential) (Credential, error) {
	if c.ID == "" {
		return Credential{}, fmt.Errorf("storage: credential id required")
	}
	var updated Credential
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		idx := -1
		for i := range doc.Credentials {
			if doc.Credentials[i].ID == c.ID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("storage: credential %q not found", c.ID)
		}
		c.CreatedAt = doc.Credentials[idx].CreatedAt
		c.Revision = doc.Credentials[idx].Revision + 1
		c.UpdatedAt = nowUTC()
		if !c.ExpiresAt.IsZero() {
			c.ExpiresAt = c.ExpiresAt.UTC().Truncate(time.Second)
		}
		doc.Credentials[idx] = c
		updated = c
		return s.saveCredentials(doc)
	})
	return updated, err
}

// PatchCredential loads a credential, applies mutate under the store lock, then saves.
// Use this for concurrent field updates (token rotate, last_used, enable, priority).
func (s *Store) PatchCredential(id string, mutate func(*Credential) error) (Credential, error) {
	if id == "" {
		return Credential{}, fmt.Errorf("storage: credential id required")
	}
	if mutate == nil {
		return Credential{}, fmt.Errorf("storage: mutate func required")
	}
	var updated Credential
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		idx := -1
		for i := range doc.Credentials {
			if doc.Credentials[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("storage: credential %q not found", id)
		}
		cur := doc.Credentials[idx]
		if err := mutate(&cur); err != nil {
			return err
		}
		cur.ID = id
		cur.CreatedAt = doc.Credentials[idx].CreatedAt
		cur.Revision = doc.Credentials[idx].Revision + 1
		cur.UpdatedAt = nowUTC()
		if !cur.ExpiresAt.IsZero() {
			cur.ExpiresAt = cur.ExpiresAt.UTC().Truncate(time.Second)
		}
		doc.Credentials[idx] = cur
		updated = cur
		return s.saveCredentials(doc)
	})
	return updated, err
}

// DeleteCredential removes a credential by id.
func (s *Store) DeleteCredential(id string) error {
	return s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		next := make([]Credential, 0, len(doc.Credentials))
		found := false
		for _, c := range doc.Credentials {
			if c.ID == id {
				found = true
				continue
			}
			next = append(next, c)
		}
		if !found {
			return fmt.Errorf("storage: credential %q not found", id)
		}
		doc.Credentials = next
		return s.saveCredentials(doc)
	})
}

// DeleteCredentialIfPurgeEligible atomically removes an automatically
// quarantined credential only when the quarantine evidence observed by the
// caller is still current. The lifecycle, purge deadline, quarantine token
// fingerprint, and live token fingerprint are compared under the same store
// lock as the deletion.
func (s *Store) DeleteCredentialIfPurgeEligible(id string, expectedRevision uint64, expectedPurgeAfter time.Time, expectedTokenFingerprint string) (bool, error) {
	if strings.TrimSpace(id) == "" {
		return false, fmt.Errorf("storage: credential id required")
	}
	expectedPurgeAfter = expectedPurgeAfter.UTC().Truncate(time.Second)
	expectedTokenFingerprint = strings.TrimSpace(expectedTokenFingerprint)
	if expectedPurgeAfter.IsZero() || expectedTokenFingerprint == "" {
		return false, fmt.Errorf("storage: purge evidence required")
	}

	deleted := false
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		idx := -1
		for i := range doc.Credentials {
			if doc.Credentials[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("storage: credential %q not found", id)
		}

		credential := doc.Credentials[idx]
		if credential.Revision != expectedRevision ||
			credential.ManualDisabled || credential.Enabled ||
			credential.LifecycleState != CredentialStateQuarantined ||
			credential.DisableReason != DisableReasonInvalidAuth ||
			credential.PurgeAfter == nil || credential.PurgeAfter.After(nowUTC()) ||
			!credential.PurgeAfter.Equal(expectedPurgeAfter) ||
			credential.QuarantineTokenFingerprint != expectedTokenFingerprint ||
			credentialTokenFingerprint(credential) != expectedTokenFingerprint {
			return nil
		}

		doc.Credentials = append(doc.Credentials[:idx], doc.Credentials[idx+1:]...)
		if err := s.saveCredentials(doc); err != nil {
			return err
		}
		deleted = true
		return nil
	})
	return deleted, err
}

// ApplyInspectionActions applies a full inspection run atomically. CAS misses
// are returned as Applied=false, not errors; a filesystem error commits none of
// the mutations.
func (s *Store) ApplyInspectionActions(actions []InspectionAction) ([]InspectionActionResult, error) {
	if len(actions) == 0 {
		return []InspectionActionResult{}, nil
	}
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		id := strings.TrimSpace(action.ID)
		if id == "" {
			return nil, fmt.Errorf("storage: inspection action credential id required")
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("storage: duplicate inspection action for credential %q", id)
		}
		seen[id] = struct{}{}
		switch action.Kind {
		case InspectionActionHealthy, InspectionActionFailure, InspectionActionQuarantine, InspectionActionPurge, InspectionActionAttempt:
		default:
			return nil, fmt.Errorf("storage: invalid inspection action %q", action.Kind)
		}
	}

	results := make([]InspectionActionResult, len(actions))
	err := s.withLock(func() error {
		doc, err := s.loadCredentials()
		if err != nil {
			return err
		}
		indexes := make(map[string]int, len(doc.Credentials))
		for index := range doc.Credentials {
			indexes[doc.Credentials[index].ID] = index
		}
		deleted := make(map[int]struct{})
		changed := false
		now := nowUTC()
		for actionIndex, action := range actions {
			result := InspectionActionResult{ID: action.ID, Kind: action.Kind}
			index, exists := indexes[action.ID]
			if !exists {
				results[actionIndex] = result
				continue
			}
			credential := doc.Credentials[index]
			at := action.At.UTC().Truncate(time.Second)
			if at.IsZero() {
				at = now
			}
			if credential.Revision != action.ExpectedRevision {
				// Scheduling metadata is safe to record even when the security CAS
				// misses. This prevents high-churn credentials from monopolizing every
				// bounded inspection batch while all state-changing actions remain held.
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = "state_changed"
				credential.LastInspectionError = "credential changed during inspection"
				credential.Revision++
				credential.UpdatedAt = now
				doc.Credentials[index] = credential
				result.AttemptRecorded = true
				changed = true
				results[actionIndex] = result
				continue
			}
			if action.ResetQuarantineEvidence {
				expectedPurgeMatches := (credential.PurgeAfter == nil && action.ExpectedPurgeAfter == nil) ||
					(credential.PurgeAfter != nil && action.ExpectedPurgeAfter != nil &&
						credential.PurgeAfter.Equal(action.ExpectedPurgeAfter.UTC().Truncate(time.Second)))
				if !credential.Enabled && !credential.ManualDisabled &&
					credential.LifecycleState == CredentialStateQuarantined &&
					credential.DisableReason == DisableReasonInvalidAuth && expectedPurgeMatches &&
					credential.QuarantineTokenFingerprint == action.ExpectedTokenFingerprint {
					credential.QuarantinedAt = &at
					if action.PurgeAfter != nil {
						purgeAfter := action.PurgeAfter.UTC().Truncate(time.Second)
						credential.PurgeAfter = &purgeAfter
					} else {
						credential.PurgeAfter = nil
					}
					credential.QuarantineTokenFingerprint = credentialTokenFingerprint(credential)
				}
			}
			switch action.Kind {
			case InspectionActionHealthy:
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = "healthy"
				credential.LastInspectionError = ""
				credential.ConsecutiveUnauthorized = 0
				if credential.LifecycleState == CredentialStateQuarantined &&
					credential.DisableReason == DisableReasonInvalidAuth && !credential.ManualDisabled {
					credential.Enabled = true
					credential.LifecycleState = CredentialStateActive
					credential.DisableReason = ""
					credential.QuarantinedAt = nil
					credential.PurgeAfter = nil
					credential.QuarantineTokenFingerprint = ""
					result.Reactivated = true
				}
				result.Applied = true
			case InspectionActionAttempt:
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = strings.TrimSpace(action.Status)
				credential.LastInspectionError = strings.TrimSpace(action.Message)
				result.Applied = true
			case InspectionActionFailure:
				status := strings.TrimSpace(action.Status)
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = status
				credential.LastInspectionError = strings.TrimSpace(action.Message)
				if status == "mass_failure_guard" {
					credential.ConsecutiveUnauthorized++
				} else if status != "unauthorized" {
					credential.ConsecutiveUnauthorized = 0
				}
				if action.CooldownUntil != nil {
					until := action.CooldownUntil.UTC().Truncate(time.Second)
					credential.CooldownUntil = &until
				}
				result.Applied = true
			case InspectionActionQuarantine:
				if credential.ManualDisabled {
					break
				}
				alreadyQuarantined := credential.LifecycleState == CredentialStateQuarantined &&
					credential.DisableReason == DisableReasonInvalidAuth
				credential.Enabled = false
				credential.LifecycleState = CredentialStateQuarantined
				credential.DisableReason = DisableReasonInvalidAuth
				if credential.QuarantinedAt == nil {
					credential.QuarantinedAt = &at
				}
				if credential.PurgeAfter == nil && action.PurgeAfter != nil {
					purgeAfter := action.PurgeAfter.UTC().Truncate(time.Second)
					credential.PurgeAfter = &purgeAfter
				}
				if credential.QuarantineTokenFingerprint == "" {
					credential.QuarantineTokenFingerprint = credentialTokenFingerprint(credential)
				}
				credential.LastInspectionAt = &at
				credential.LastInspectionStatus = "unauthorized"
				credential.LastInspectionError = "confirmed unauthorized"
				credential.ConsecutiveUnauthorized++
				result.Applied = true
				result.Quarantined = !alreadyQuarantined
			case InspectionActionPurge:
				expectedFingerprint := strings.TrimSpace(action.ExpectedTokenFingerprint)
				if action.ExpectedPurgeAfter == nil || expectedFingerprint == "" {
					break
				}
				expectedPurgeAfter := action.ExpectedPurgeAfter.UTC().Truncate(time.Second)
				if credential.ManualDisabled || credential.Enabled ||
					credential.LifecycleState != CredentialStateQuarantined ||
					credential.DisableReason != DisableReasonInvalidAuth ||
					credential.PurgeAfter == nil || credential.PurgeAfter.After(now) ||
					!credential.PurgeAfter.Equal(expectedPurgeAfter) ||
					credential.QuarantineTokenFingerprint != expectedFingerprint ||
					credentialTokenFingerprint(credential) != expectedFingerprint {
					break
				}
				deleted[index] = struct{}{}
				result.Applied = true
				result.Deleted = true
			}
			if result.Applied && !result.Deleted {
				credential.Revision++
				credential.UpdatedAt = now
				if !credential.ExpiresAt.IsZero() {
					credential.ExpiresAt = credential.ExpiresAt.UTC().Truncate(time.Second)
				}
				doc.Credentials[index] = credential
			}
			if result.Applied {
				changed = true
			}
			results[actionIndex] = result
		}
		if !changed {
			return nil
		}
		if len(deleted) > 0 {
			next := make([]Credential, 0, len(doc.Credentials)-len(deleted))
			for index, credential := range doc.Credentials {
				if _, remove := deleted[index]; !remove {
					next = append(next, credential)
				}
			}
			doc.Credentials = next
		}
		return s.saveCredentials(doc)
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// SetCredentialEnabled toggles the enabled flag atomically.
func (s *Store) SetCredentialEnabled(id string, enabled bool) (Credential, error) {
	return s.PatchCredential(id, func(c *Credential) error {
		c.Enabled = enabled
		c.ManualDisabled = !enabled
		if enabled {
			c.LifecycleState = CredentialStateActive
			c.DisableReason = ""
			c.QuarantinedAt = nil
			c.PurgeAfter = nil
			c.QuarantineTokenFingerprint = ""
			c.ConsecutiveUnauthorized = 0
		} else {
			c.DisableReason = DisableReasonManual
		}
		return nil
	})
}

// QuarantineCredential removes a credential from selection without erasing it.
// Manual-disabled credentials remain manual and are never relabeled by automation.
func (s *Store) QuarantineCredential(id, reason string, quarantinedAt time.Time, purgeAfter *time.Time) (Credential, error) {
	return s.PatchCredential(id, func(c *Credential) error {
		if c.ManualDisabled {
			return nil
		}
		at := quarantinedAt.UTC().Truncate(time.Second)
		c.Enabled = false
		c.LifecycleState = CredentialStateQuarantined
		c.DisableReason = firstNonEmptyString(strings.TrimSpace(reason), DisableReasonInvalidAuth)
		c.QuarantinedAt = &at
		if purgeAfter != nil {
			value := purgeAfter.UTC().Truncate(time.Second)
			c.PurgeAfter = &value
		} else {
			c.PurgeAfter = nil
		}
		c.QuarantineTokenFingerprint = credentialTokenFingerprint(*c)
		return nil
	})
}

func credentialTokenFingerprint(c Credential) string {
	sum := sha256.Sum256([]byte(c.AccessToken + "\x00" + c.RefreshToken))
	return hex.EncodeToString(sum[:])
}

// SetCredentialPriority updates priority atomically.
func (s *Store) SetCredentialPriority(id string, priority int) (Credential, error) {
	return s.PatchCredential(id, func(c *Credential) error {
		c.Priority = priority
		return nil
	})
}

func (s *Store) loadCredentials() (credentialsDoc, error) {
	var doc credentialsDoc
	err := readJSONFile(s.credentialsPath(), &doc)
	if err != nil {
		if os.IsNotExist(err) {
			return credentialsDoc{Credentials: []Credential{}}, nil
		}
		return credentialsDoc{}, err
	}
	if doc.Credentials == nil {
		doc.Credentials = []Credential{}
	}
	for i := range doc.Credentials {
		normalizeCredential(&doc.Credentials[i])
	}
	return doc, nil
}

// ensureCredentialsCache refreshes the immutable in-memory credential snapshot
// when the on-disk file stamp changes. Callers must hold the Store lock.
func (s *Store) ensureCredentialsCache() error {
	stamp, err := statFileStamp(s.credentialsPath())
	if err != nil {
		return fmt.Errorf("storage: stat credentials: %w", err)
	}
	if s.credentialsCacheValid && sameFileStamp(stamp, s.credentialsCacheStamp) &&
		time.Since(s.credentialsCacheAt) < credentialCacheMaxAge {
		return nil
	}
	doc, err := s.loadCredentials()
	if err != nil {
		return err
	}
	s.setCredentialsCache(doc, stamp)
	return nil
}

func (s *Store) saveCredentials(doc credentialsDoc) error {
	if doc.Credentials == nil {
		doc.Credentials = []Credential{}
	}
	for i := range doc.Credentials {
		normalizeCredential(&doc.Credentials[i])
	}
	if err := writeJSONFile(s.credentialsPath(), doc); err != nil {
		return err
	}
	stamp, err := statFileStamp(s.credentialsPath())
	if err != nil {
		// Persistence already succeeded. Force a disk reload on the next read
		// instead of reporting a failed mutation solely because cache metadata
		// could not be refreshed.
		s.credentialsCacheValid = false
		return nil
	}
	s.setCredentialsCache(doc, stamp)
	return nil
}

func (s *Store) setCredentialsCache(doc credentialsDoc, stamp fileStamp) {
	cache := make([]Credential, 0, len(doc.Credentials))
	index := make(map[string]Credential, len(doc.Credentials))
	for _, credential := range doc.Credentials {
		cloned := cloneCredential(credential)
		cache = append(cache, cloned)
		if _, exists := index[credential.ID]; !exists {
			index[credential.ID] = cloned
		}
	}
	s.credentialsCache = cache
	s.credentialsIndex = index
	s.credentialsCacheStamp = stamp
	s.credentialsCacheValid = true
	s.credentialsCacheAt = time.Now()
}

func cloneCredentials(credentials []Credential) []Credential {
	out := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, cloneCredential(credential))
	}
	return out
}

func cloneCredential(credential Credential) Credential {
	credential.QuarantinedAt = cloneTimePointer(credential.QuarantinedAt)
	credential.PurgeAfter = cloneTimePointer(credential.PurgeAfter)
	credential.CooldownUntil = cloneTimePointer(credential.CooldownUntil)
	credential.LastUsedAt = cloneTimePointer(credential.LastUsedAt)
	credential.LastSuccessAt = cloneTimePointer(credential.LastSuccessAt)
	credential.LastInspectionAt = cloneTimePointer(credential.LastInspectionAt)
	if credential.Billing != nil {
		credential.Billing = cloneStringAnyMap(credential.Billing)
	}
	return credential
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneStringAnyMap(value map[string]any) map[string]any {
	copy := make(map[string]any, len(value))
	for key, item := range value {
		copy[key] = cloneJSONValue(item)
	}
	return copy
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneStringAnyMap(typed)
	case []any:
		copy := make([]any, len(typed))
		for index, item := range typed {
			copy[index] = cloneJSONValue(item)
		}
		return copy
	default:
		return typed
	}
}

func normalizeCredential(credential *Credential) {
	if credential == nil {
		return
	}
	if strings.TrimSpace(credential.IdentityKey) == "" {
		credential.IdentityKey = computedCredentialIdentity(*credential)
	}
	if strings.TrimSpace(credential.LifecycleState) == "" {
		credential.LifecycleState = CredentialStateActive
		if !credential.Enabled {
			credential.ManualDisabled = true
			if strings.TrimSpace(credential.DisableReason) == "" {
				credential.DisableReason = DisableReasonManual
			}
		}
	}
	if strings.TrimSpace(credential.ProxyMode) == "" {
		credential.ProxyMode = CredentialProxyInherit
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func newID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("storage: generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}
