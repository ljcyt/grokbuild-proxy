// Package auth implements xAI Grok CLI OAuth (auth.x.ai) for cli-chat-proxy.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// Issuer is the xAI OIDC issuer.
	Issuer = "https://auth.x.ai"
	// DiscoveryURL is the OIDC discovery document.
	DiscoveryURL = Issuer + "/.well-known/openid-configuration"
	// DefaultClientID is the public Grok CLI OAuth client_id.
	DefaultClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	// DefaultScope is the default OAuth scope set used by Grok CLI.
	DefaultScope = "openid profile email offline_access grok-cli:access api:access"
	// DefaultTokenEndpoint is the fallback token endpoint if discovery fails.
	DefaultTokenEndpoint = Issuer + "/oauth2/token"
	// DefaultDeviceAuthEndpoint is the fallback device-code endpoint.
	DefaultDeviceAuthEndpoint = Issuer + "/oauth2/device/code"
	// DefaultCallbackHost is the loopback host for browser PKCE.
	DefaultCallbackHost = "127.0.0.1"
	// DefaultCallbackPort is the preferred loopback callback port.
	DefaultCallbackPort = 56122
	// DefaultCallbackPath is the loopback callback path.
	DefaultCallbackPath = "/callback"
	// DefaultRefreshSkew is how early tokens are treated as expired.
	DefaultRefreshSkew = 180 * time.Second
	// DefaultHTTPTimeout is the safety bound when callers provide no client.
	DefaultHTTPTimeout = 30 * time.Second
)

// Discovery holds OAuth endpoints from OIDC discovery.
type Discovery struct {
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
}

// TokenSet is the OAuth token bundle used by the proxy.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scope        string    `json:"scope,omitempty"`
}

// Expired reports whether the access token should be refreshed.
// A zero ExpiresAt is treated as not expired (caller may still force refresh).
func (t TokenSet) Expired(now time.Time, skew time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	if skew < 0 {
		skew = 0
	}
	return !now.Before(t.ExpiresAt.Add(-skew))
}

// OAuthClient performs discovery and token grant exchanges against auth.x.ai.
type OAuthClient struct {
	HTTPClient *http.Client
	// Issuer controls discovery and fallback endpoint derivation.
	Issuer   string
	ClientID string
	Scope    string
	// TokenEndpoint overrides discovery when non-empty (useful for tests).
	TokenEndpoint string
	// DeviceAuthEndpoint overrides discovery when non-empty.
	DeviceAuthEndpoint string
	// DiscoveryURL overrides the default OIDC discovery URL (tests).
	DiscoveryURL string
	// AllowUnsafeEndpoints permits non-xAI test servers. Production wiring must
	// leave this false.
	AllowUnsafeEndpoints bool
}

func (c *OAuthClient) http() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: DefaultHTTPTimeout}
}

func (c *OAuthClient) clientID() string {
	if c != nil && strings.TrimSpace(c.ClientID) != "" {
		return strings.TrimSpace(c.ClientID)
	}
	return DefaultClientID
}

func (c *OAuthClient) scope() string {
	if c != nil && strings.TrimSpace(c.Scope) != "" {
		return strings.TrimSpace(c.Scope)
	}
	return DefaultScope
}

func (c *OAuthClient) discoveryURL() string {
	if c != nil && strings.TrimSpace(c.DiscoveryURL) != "" {
		return strings.TrimSpace(c.DiscoveryURL)
	}
	return strings.TrimRight(c.issuer(), "/") + "/.well-known/openid-configuration"
}

func (c *OAuthClient) issuer() string {
	if c != nil && strings.TrimSpace(c.Issuer) != "" {
		return strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	}
	return Issuer
}

func (c *OAuthClient) defaultTokenEndpoint() string {
	return DefaultTokenEndpoint
}

func (c *OAuthClient) defaultDeviceAuthEndpoint() string {
	return DefaultDeviceAuthEndpoint
}

// Discover fetches OIDC endpoints from auth.x.ai.
func (c *OAuthClient) Discover(ctx context.Context) (*Discovery, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := NormalizeTrustedIssuer(c.issuer()); err != nil {
		return nil, err
	}
	if c != nil && !c.AllowUnsafeEndpoints {
		if err := validateTrustedOAuthURL(c.discoveryURL(), "/.well-known/openid-configuration"); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("auth discovery: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth discovery: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("auth discovery: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "auth discovery", StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body)),
		}
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("auth discovery: parse: %w", err)
	}
	if strings.TrimSpace(d.TokenEndpoint) == "" {
		return nil, fmt.Errorf("auth discovery: missing token_endpoint")
	}
	if err := validateXAIEndpoint(d.TokenEndpoint, "token_endpoint"); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint != "" {
		if err := validateXAIEndpoint(d.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
			return nil, err
		}
	}
	if d.DeviceAuthorizationEndpoint != "" {
		if err := validateXAIEndpoint(d.DeviceAuthorizationEndpoint, "device_authorization_endpoint"); err != nil {
			return nil, err
		}
	}
	return &d, nil
}

// doTokenRequest never follows redirects. In particular, 307 and 308 retain
// the POST method and body, so following one could disclose refresh/device
// grant material to the redirect target. Clone the client to avoid mutating a
// caller-owned shared http.Client.
func (c *OAuthClient) doTokenRequest(req *http.Request) (*http.Response, error) {
	base := c.http()
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

// ResolveTokenEndpoint returns the configured, discovered, or default token endpoint.
func (c *OAuthClient) ResolveTokenEndpoint(ctx context.Context) (string, error) {
	if c != nil && strings.TrimSpace(c.TokenEndpoint) != "" {
		return strings.TrimSpace(c.TokenEndpoint), nil
	}
	d, err := c.Discover(ctx)
	if err != nil {
		// Fall back to the known default so offline tests / transient discovery
		// failures can still target auth.x.ai when TokenEndpoint is injected.
		return c.defaultTokenEndpoint(), err
	}
	return d.TokenEndpoint, nil
}

// Refresh exchanges a refresh_token for a new TokenSet.
// Refresh tokens may rotate; the returned set always prefers the response value
// and falls back to the input refresh token when the server omits a new one.
func (c *OAuthClient) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("auth refresh: refresh_token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := NormalizeTrustedIssuer(c.issuer()); err != nil {
		return nil, err
	}

	endpoint := ""
	if c != nil {
		endpoint = strings.TrimSpace(c.TokenEndpoint)
	}
	if endpoint == "" {
		ep, err := c.ResolveTokenEndpoint(ctx)
		// Use whatever endpoint we got (discovered or default).
		endpoint = ep
		if err != nil && endpoint == "" {
			return nil, err
		}
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.clientID()},
		"refresh_token": {refreshToken},
	}
	return c.postTokenForm(ctx, endpoint, form, refreshToken)
}

// ExchangeDeviceCode completes an RFC 8628 device-code grant.
func (c *OAuthClient) ExchangeDeviceCode(ctx context.Context, deviceCode string) (*TokenSet, error) {
	deviceCode = strings.TrimSpace(deviceCode)
	if deviceCode == "" {
		return nil, fmt.Errorf("auth device: device_code is required")
	}
	if _, err := NormalizeTrustedIssuer(c.issuer()); err != nil {
		return nil, err
	}
	endpoint := ""
	if c != nil {
		endpoint = strings.TrimSpace(c.TokenEndpoint)
	}
	if endpoint == "" {
		ep, err := c.ResolveTokenEndpoint(ctx)
		endpoint = ep
		if err != nil && endpoint == "" {
			return nil, err
		}
	}
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {c.clientID()},
		"device_code": {deviceCode},
	}
	return c.postTokenForm(ctx, endpoint, form, "")
}

// DeviceCodeResponse is the RFC 8628 device authorization response.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// RequestDeviceCode starts an RFC 8628 device authorization flow.
func (c *OAuthClient) RequestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := NormalizeTrustedIssuer(c.issuer()); err != nil {
		return nil, err
	}
	endpoint := ""
	if c != nil {
		endpoint = strings.TrimSpace(c.DeviceAuthEndpoint)
	}
	if endpoint == "" {
		d, err := c.Discover(ctx)
		if err != nil {
			endpoint = c.defaultDeviceAuthEndpoint()
		} else if strings.TrimSpace(d.DeviceAuthorizationEndpoint) != "" {
			endpoint = d.DeviceAuthorizationEndpoint
		} else {
			endpoint = c.defaultDeviceAuthEndpoint()
		}
	}
	if c == nil || !c.AllowUnsafeEndpoints {
		if err := validateTrustedOAuthURL(endpoint, "/oauth2/device/code"); err != nil {
			return nil, err
		}
	}

	form := url.Values{
		"client_id": {c.clientID()},
		"scope":     {c.scope()},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth device: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.doTokenRequest(req)
	if err != nil {
		return nil, fmt.Errorf("auth device: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("auth device: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "auth device", StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body)),
		}
	}
	var out DeviceCodeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("auth device: parse: %w", err)
	}
	if strings.TrimSpace(out.DeviceCode) == "" || strings.TrimSpace(out.UserCode) == "" {
		return nil, fmt.Errorf("auth device: missing device_code/user_code")
	}
	if err := validateXAIEndpoint(out.VerificationURI, "verification_uri"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.VerificationURIComplete) != "" {
		if err := validateXAIEndpoint(out.VerificationURIComplete, "verification_uri_complete"); err != nil {
			return nil, err
		}
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return &out, nil
}

func (c *OAuthClient) postTokenForm(ctx context.Context, endpoint string, form url.Values, fallbackRefresh string) (*TokenSet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("auth token: empty token endpoint")
	}
	if c == nil || !c.AllowUnsafeEndpoints {
		if err := validateTrustedOAuthURL(endpoint, "/oauth2/token"); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth token: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doTokenRequest(req)
	if err != nil {
		return nil, fmt.Errorf("auth token: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("auth token: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "auth token", StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body)),
		}
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("auth token: parse: %w", err)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return nil, fmt.Errorf("auth token: missing access_token")
	}
	refresh := strings.TrimSpace(payload.RefreshToken)
	if refresh == "" {
		refresh = strings.TrimSpace(fallbackRefresh)
	}
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	now := time.Now().UTC()
	return &TokenSet{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: refresh,
		TokenType:    firstNonEmpty(strings.TrimSpace(payload.TokenType), "Bearer"),
		IDToken:      strings.TrimSpace(payload.IDToken),
		ExpiresIn:    expiresIn,
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second),
		Scope:        strings.TrimSpace(payload.Scope),
	}, nil
}

func validateXAIEndpoint(raw, field string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("auth discovery: empty %s", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("auth discovery: invalid %s: %w", field, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("auth discovery: %s must use https", field)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	allowedHost := host == "auth.x.ai"
	if strings.HasPrefix(field, "verification_uri") {
		allowedHost = allowedHost || host == "accounts.x.ai"
	}
	if !allowedHost || (u.Port() != "" && u.Port() != "443") || u.User != nil {
		return fmt.Errorf("auth discovery: %s must use trusted auth.x.ai endpoint", field)
	}
	return nil
}

func validateTrustedOAuthURL(raw, expectedPath string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("auth endpoint: invalid URL: %w", err)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if u.Scheme != "https" || host != "auth.x.ai" ||
		(u.Port() != "" && u.Port() != "443") || u.User != nil ||
		u.EscapedPath() != expectedPath || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("auth endpoint: untrusted OAuth URL")
	}
	return nil
}

// NormalizeTrustedIssuer accepts only the production xAI issuer. Imported
// credentials must never redirect refresh-token grants to an arbitrary OIDC
// issuer.
func NormalizeTrustedIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Issuer, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("auth issuer: invalid URL: %w", err)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	path := strings.TrimRight(u.EscapedPath(), "/")
	if u.Scheme != "https" || host != "auth.x.ai" ||
		(u.Port() != "" && u.Port() != "443") || u.User != nil ||
		path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("auth issuer: only %s is trusted", Issuer)
	}
	return Issuer, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
