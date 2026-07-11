// Package sso calls the optional SSO-to-Grok credential conversion service.
package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/importer"
	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

const (
	maxResponseBytes = int64(4 << 20)
	maxBatchItems    = 100
	maxTimeoutSec    = 300
)

type SettingsProvider interface {
	Current() storage.RuntimeSettings
}

type HTTPClientFactory interface {
	ClientFor(credential *storage.Credential, timeout time.Duration) (*http.Client, outbound.ResolvedProxy, error)
}

type Client struct {
	Settings SettingsProvider
	Outbound HTTPClientFactory
}

func (c *Client) Convert(ctx context.Context, ssoValues []string) ([]importer.ConvertedCredential, error) {
	if c == nil || c.Settings == nil || c.Outbound == nil {
		return nil, fmt.Errorf("sso converter: client is not configured")
	}
	settings := c.Settings.Current().SSOConverter
	if !settings.Enabled {
		return nil, fmt.Errorf("sso converter: service is disabled")
	}
	endpoint, err := converterURL(settings.Endpoint, settings.AllowInsecure)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(settings.APIKey) == "" {
		return nil, fmt.Errorf("sso converter: API key is not configured")
	}
	if len(ssoValues) == 0 {
		return []importer.ConvertedCredential{}, nil
	}
	maxBatch := settings.MaxBatch
	if maxBatch <= 0 {
		maxBatch = 50
	}
	if maxBatch > maxBatchItems {
		return nil, fmt.Errorf("sso converter: max_batch must not exceed %d", maxBatchItems)
	}
	if settings.TimeoutSec > maxTimeoutSec {
		return nil, fmt.Errorf("sso converter: timeout_sec must not exceed %d", maxTimeoutSec)
	}
	timeout := time.Duration(settings.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(maxTimeoutSec) * time.Second
	}
	// Loopback/private/single-label converter endpoints are control-plane peers,
	// not Internet destinations. Route them directly so an operator's global
	// HTTP proxy never receives the sidecar Bearer key or raw SSO cookies (and so
	// Compose names such as sso-import are resolved on the local container DNS).
	routeCredential := converterRouteCredential(endpoint)
	httpClient, _, err := c.Outbound.ClientFor(routeCredential, timeout)
	if err != nil {
		return nil, fmt.Errorf("sso converter: outbound transport: %w", err)
	}
	if httpClient == nil {
		return nil, fmt.Errorf("sso converter: outbound transport returned no HTTP client")
	}
	// Converter requests contain both the SSO cookie and the service Bearer key.
	// Never let net/http replay either secret to a redirect target. A shallow
	// clone preserves the configured transport/jar while avoiding mutation of a
	// client shared with other outbound call sites.
	redirectSafeClient := *httpClient
	redirectSafeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	output := make([]importer.ConvertedCredential, len(ssoValues))
	for start := 0; start < len(ssoValues); start += maxBatch {
		end := start + maxBatch
		if end > len(ssoValues) {
			end = len(ssoValues)
		}
		converted, err := convertBatch(ctx, &redirectSafeClient, endpoint, settings.APIKey, ssoValues[start:end])
		if err != nil {
			return nil, err
		}
		copy(output[start:end], converted)
	}
	return output, nil
}

func converterRouteCredential(endpoint string) *storage.Credential {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || !isPrivateConverterHost(parsed.Hostname()) {
		return nil
	}
	return &storage.Credential{ProxyMode: storage.CredentialProxyDirect}
}

func convertBatch(
	ctx context.Context,
	httpClient *http.Client,
	endpoint, apiKey string,
	ssoValues []string,
) ([]importer.ConvertedCredential, error) {
	type requestItem struct {
		SSO    string `json:"sso"`
		Source string `json:"source,omitempty"`
	}
	requestBody := struct {
		Items []requestItem `json:"items"`
	}{
		Items: make([]requestItem, len(ssoValues)),
	}
	for index, value := range ssoValues {
		requestBody.Items[index] = requestItem{
			SSO: strings.TrimSpace(value), Source: fmt.Sprintf("entry-%d", index+1),
		}
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("sso converter: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("sso converter: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sso converter: request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sso converter: read response failed")
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("sso converter: response body exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso converter: service returned status %d", resp.StatusCode)
	}
	var response struct {
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("sso converter: invalid service response")
	}
	output := make([]importer.ConvertedCredential, len(ssoValues))
	seen := make([]bool, len(ssoValues))
	decoder := json.NewDecoder(bytes.NewReader(response.Results))
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("sso converter: invalid service response")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return nil, fmt.Errorf("sso converter: results must be an array")
	}
	resultCount := 0
	for decoder.More() {
		// A valid response has at most one result per requested SSO. Stop before
		// decoding an attacker-controlled oversized array into large structs.
		if resultCount >= len(ssoValues) {
			return nil, fmt.Errorf("sso converter: too many results")
		}
		var result struct {
			Index      int  `json:"index"`
			OK         bool `json:"ok"`
			Credential struct {
				SourceKey   string `json:"source_key"`
				Key         string `json:"key"`
				UserID      string `json:"user_id"`
				Email       string `json:"email"`
				PrincipalID string `json:"principal_id"`
				TeamID      string `json:"team_id"`
				Refresh     string `json:"refresh_token"`
				ExpiresAt   string `json:"expires_at"`
				Issuer      string `json:"oidc_issuer"`
				ClientID    string `json:"oidc_client_id"`
			} `json:"credential"`
		}
		if err := decoder.Decode(&result); err != nil {
			return nil, fmt.Errorf("sso converter: invalid result")
		}
		resultCount++
		if result.Index < 0 || result.Index >= len(output) || seen[result.Index] {
			return nil, fmt.Errorf("sso converter: invalid result index")
		}
		seen[result.Index] = true
		if !result.OK {
			output[result.Index].Error = "SSO conversion failed"
			continue
		}
		credential := result.Credential
		if strings.TrimSpace(credential.Key) == "" && strings.TrimSpace(credential.Refresh) == "" {
			output[result.Index].Error = "SSO conversion returned no tokens"
			continue
		}
		expiresAt := time.Time{}
		if strings.TrimSpace(credential.ExpiresAt) != "" {
			parsed, err := time.Parse(time.RFC3339Nano, credential.ExpiresAt)
			if err != nil {
				output[result.Index].Error = "SSO conversion returned an invalid expiry"
				continue
			}
			expiresAt = parsed.UTC()
		}
		output[result.Index] = importer.ConvertedCredential{
			Name: credential.Email, Email: credential.Email,
			UserID: firstNonEmpty(credential.UserID, credential.PrincipalID),
			TeamID: credential.TeamID, OIDCIssuer: credential.Issuer,
			OIDCClientID: credential.ClientID, AccessToken: credential.Key,
			RefreshToken: credential.Refresh, ExpiresAt: expiresAt,
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("sso converter: invalid results array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("sso converter: invalid results payload")
	}
	for index := range output {
		if !seen[index] {
			output[index].Error = "SSO conversion result missing"
		}
	}
	return output, nil
}

func converterURL(raw string, allowInsecure bool) (string, error) {
	raw, err := ValidateEndpoint(raw, allowInsecure)
	if err != nil {
		return "", err
	}
	parsed, _ := url.Parse(raw)
	if strings.HasSuffix(parsed.Path, "/v1/convert") {
		return raw, nil
	}
	return raw + "/v1/convert", nil
}

// ValidateEndpoint validates an SSO converter base URL. Plain HTTP is only
// permitted with explicit opt-in and for loopback, private IPs, or a single-label
// hostname suitable for a Compose-internal service name.
func ValidateEndpoint(raw string, allowInsecure bool) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("sso converter: endpoint must be an absolute URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("sso converter: endpoint must use HTTPS")
	}
	if scheme == "http" {
		if !allowInsecure {
			return "", fmt.Errorf("sso converter: endpoint must use HTTPS")
		}
		if !isPrivateConverterHost(parsed.Hostname()) {
			return "", fmt.Errorf("sso converter: insecure HTTP endpoint must use loopback, a private IP, or a single-label internal hostname")
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("sso converter: endpoint must not include userinfo, query, or fragment")
	}
	return raw, nil
}

func isPrivateConverterHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if host == "" || strings.Contains(host, ".") || len(host) > 63 || host[0] == '-' || host[len(host)-1] == '-' {
		return false
	}
	hasLetter := false
	for _, char := range host {
		if char >= 'a' && char <= 'z' {
			hasLetter = true
			continue
		}
		if (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return hasLetter
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
