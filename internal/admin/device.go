package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

// DeviceOAuth is the OAuth device-flow surface used by the admin API.
type DeviceOAuth interface {
	RequestDeviceCode(ctx context.Context) (*auth.DeviceCodeResponse, error)
	ExchangeDeviceCode(ctx context.Context, deviceCode string) (*auth.TokenSet, error)
}

type deviceSession struct {
	DeviceCode string
	ExpiresAt  time.Time
	Interval   time.Duration
	LastPollAt time.Time
}

// StartDeviceLogin begins an RFC 8628 login without exposing device_code.
func (h *Handlers) StartDeviceLogin(w http.ResponseWriter, r *http.Request) {
	oauthClient, err := h.deviceOAuth()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "device OAuth is not configured")
		return
	}
	code, err := oauthClient.RequestDeviceCode(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if !trustedVerificationURL(code.VerificationURI) ||
		(code.VerificationURIComplete != "" && !trustedVerificationURL(code.VerificationURIComplete)) {
		writeErr(w, http.StatusBadGateway, "device OAuth returned an untrusted verification URL")
		return
	}
	sessionID, err := newDeviceSessionID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create device session")
		return
	}
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expiresIn := time.Duration(code.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 15 * time.Minute
	}
	h.deviceMu.Lock()
	if h.deviceSessions == nil {
		h.deviceSessions = make(map[string]deviceSession)
	}
	h.pruneDeviceSessionsLocked(time.Now())
	h.deviceSessions[sessionID] = deviceSession{
		DeviceCode: code.DeviceCode,
		ExpiresAt:  time.Now().Add(expiresIn),
		Interval:   interval,
	}
	h.deviceMu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":                sessionID,
		"user_code":                 code.UserCode,
		"verification_uri":          code.VerificationURI,
		"verification_uri_complete": code.VerificationURIComplete,
		"expires_in":                int(expiresIn.Seconds()),
		"interval":                  int(interval.Seconds()),
		"status":                    "pending",
	})
}

// PollDeviceLogin performs one device-token exchange attempt.
func (h *Handlers) PollDeviceLogin(w http.ResponseWriter, r *http.Request) {
	oauthClient, err := h.deviceOAuth()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "device OAuth is not configured")
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sessionID := strings.TrimSpace(body.SessionID)
	now := time.Now()
	h.deviceMu.Lock()
	session, ok := h.deviceSessions[sessionID]
	if !ok || !session.ExpiresAt.After(now) {
		delete(h.deviceSessions, sessionID)
		h.deviceMu.Unlock()
		writeErr(w, http.StatusGone, "device session expired or unknown")
		return
	}
	if !session.LastPollAt.IsZero() && now.Sub(session.LastPollAt) < session.Interval {
		retry := session.Interval - now.Sub(session.LastPollAt)
		h.deviceMu.Unlock()
		seconds := int(retry.Round(time.Second).Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"status":      "slow_down",
			"retry_after": seconds,
		})
		return
	}
	session.LastPollAt = now
	h.deviceSessions[sessionID] = session
	h.deviceMu.Unlock()

	tokens, err := oauthClient.ExchangeDeviceCode(r.Context(), session.DeviceCode)
	if err != nil {
		message := strings.ToLower(err.Error())
		switch {
		case strings.Contains(message, "authorization_pending"):
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":      "pending",
				"retry_after": int(session.Interval.Seconds()),
			})
		case strings.Contains(message, "slow_down"):
			h.deviceMu.Lock()
			session.Interval += 5 * time.Second
			h.deviceSessions[sessionID] = session
			h.deviceMu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":      "slow_down",
				"retry_after": int(session.Interval.Seconds()),
			})
		default:
			h.deviceMu.Lock()
			delete(h.deviceSessions, sessionID)
			h.deviceMu.Unlock()
			writeErr(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	if tokens == nil || strings.TrimSpace(tokens.AccessToken) == "" {
		writeErr(w, http.StatusBadGateway, "device OAuth returned no access token")
		return
	}

	input := deviceCredentialInput(tokens, h.Config.OAuth.ClientID)
	var credential storage.Credential
	if upserter, ok := h.Store.(credentialUpserter); ok {
		credential, _, err = upserter.UpsertCredential(input)
	} else {
		credential, err = h.Store.CreateCredential(input)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Device authorization may upsert an existing account. Retire any access or
	// refresh token cached for that credential so subsequent traffic observes the
	// newly authorized session rather than an older in-process snapshot.
	if h.TokenCache != nil {
		h.TokenCache.Invalidate(credential.ID)
	}
	h.deviceMu.Lock()
	delete(h.deviceSessions, sessionID)
	h.deviceMu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":     "authorized",
		"credential": h.maskedCredential(credential),
	})
}

func (h *Handlers) deviceOAuth() (DeviceOAuth, error) {
	if h != nil && h.OAuthFor != nil {
		return h.OAuthFor()
	}
	if h != nil && h.OAuth != nil {
		return h.OAuth, nil
	}
	return nil, fmt.Errorf("device OAuth is not configured")
}

func deviceCredentialInput(tokens *auth.TokenSet, clientID string) storage.CreateCredentialInput {
	claims := tokenClaims(tokens.IDToken)
	if len(claims) == 0 {
		claims = tokenClaims(tokens.AccessToken)
	}
	userID := firstClaim(claims, "sub", "user_id", "principal_id")
	email := firstClaim(claims, "email")
	teamID := firstClaim(claims, "team_id")
	name := email
	if name == "" {
		name = userID
	}
	if name == "" {
		name = "device-login"
	}
	sourceIdentity := userID
	if sourceIdentity == "" {
		sourceIdentity = strings.ToLower(email)
	}
	if sourceIdentity == "" {
		material := tokens.RefreshToken
		if material == "" {
			material = tokens.AccessToken
		}
		sum := sha256.Sum256([]byte(material))
		sourceIdentity = hex.EncodeToString(sum[:8])
	}
	return storage.CreateCredentialInput{
		Name:         name,
		Email:        email,
		UserID:       userID,
		TeamID:       teamID,
		SourceKey:    "device:" + sourceIdentity,
		OIDCClientID: clientID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
	}
}

func tokenClaims(token string) map[string]any {
	// The token came directly from the configured HTTPS OAuth issuer. Claims are
	// used only as storage metadata/deduplication keys, never for authorization.
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

func firstClaim(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := claims[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (h *Handlers) pruneDeviceSessionsLocked(now time.Time) {
	for id, session := range h.deviceSessions {
		if !session.ExpiresAt.After(now) {
			delete(h.deviceSessions, id)
		}
	}
}

func newDeviceSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "dev_" + hex.EncodeToString(value[:]), nil
}

func trustedVerificationURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "x.ai" || strings.HasSuffix(host, ".x.ai")
}
