// Package outbound centralizes outbound proxy selection and HTTP transports.
package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

const (
	ModeEnvironment = "environment"
	ModeInherit     = "inherit"
	ModeDirect      = "direct"
	ModeURL         = "url"
)

type SettingsProvider interface {
	Current() storage.RuntimeSettings
}

type ResolvedProxy struct {
	Mode   string
	URL    string
	Source string
}

// Resolver applies credential > runtime/global > environment > direct precedence.
type Resolver struct {
	Settings SettingsProvider
	Fallback storage.GlobalProxySettings
}

func (r *Resolver) Resolve(credential *storage.Credential) (ResolvedProxy, error) {
	if credential != nil {
		mode := strings.ToLower(strings.TrimSpace(credential.ProxyMode))
		switch mode {
		case ModeDirect:
			return ResolvedProxy{Mode: ModeDirect, Source: "credential"}, nil
		case ModeURL:
			value, err := ValidateProxyURL(credential.ProxyURL)
			if err != nil {
				return ResolvedProxy{}, fmt.Errorf("credential proxy: %w", err)
			}
			return ResolvedProxy{Mode: ModeURL, URL: value, Source: "credential"}, nil
		case "", ModeInherit:
		default:
			return ResolvedProxy{}, fmt.Errorf("credential proxy mode %q is invalid", mode)
		}
	}

	global := r.Fallback
	source := "config"
	if r != nil && r.Settings != nil {
		global = r.Settings.Current().GlobalProxy
		source = "runtime"
		if provider, ok := r.Settings.(interface{ GlobalProxySource() string }); ok {
			if candidate := strings.TrimSpace(provider.GlobalProxySource()); candidate != "" {
				source = candidate
			}
		}
	}
	mode := strings.ToLower(strings.TrimSpace(global.Mode))
	if mode == "" {
		mode = ModeEnvironment
	}
	switch mode {
	case ModeEnvironment:
		return ResolvedProxy{Mode: ModeEnvironment, Source: source}, nil
	case ModeDirect:
		return ResolvedProxy{Mode: ModeDirect, Source: source}, nil
	case ModeURL:
		value, err := ValidateProxyURL(global.URL)
		if err != nil {
			return ResolvedProxy{}, fmt.Errorf("global proxy: %w", err)
		}
		return ResolvedProxy{Mode: ModeURL, URL: value, Source: source}, nil
	default:
		return ResolvedProxy{}, fmt.Errorf("global proxy mode %q is invalid", mode)
	}
}

func ValidateProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("URL is required")
	}
	if strings.ContainsAny(raw, "\r\n\x00") {
		return "", fmt.Errorf("URL contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() == false || u.Host == "" {
		return "", fmt.Errorf("URL must be absolute and include a host")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("proxy URL must not contain query or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String(), nil
}

func RedactedURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.User != nil {
		u.User = url.User("redacted")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Factory caches transports by a digest of the normalized route. Raw proxy
// credentials never appear in cache keys or logs.
type Factory struct {
	Resolver              *Resolver
	ResponseHeaderTimeout time.Duration

	mu         sync.Mutex
	transports map[string]*http.Transport
}

func (f *Factory) ClientFor(credential *storage.Credential, clientTimeout time.Duration) (*http.Client, ResolvedProxy, error) {
	if f == nil || f.Resolver == nil {
		return nil, ResolvedProxy{}, fmt.Errorf("outbound: resolver is not configured")
	}
	resolved, err := f.Resolver.Resolve(credential)
	if err != nil {
		return nil, ResolvedProxy{}, err
	}
	transport, err := f.transportFor(resolved)
	if err != nil {
		return nil, ResolvedProxy{}, err
	}
	return &http.Client{Transport: transport, Timeout: clientTimeout}, resolved, nil
}

func (f *Factory) transportFor(resolved ResolvedProxy) (*http.Transport, error) {
	key := transportKey(resolved)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.transports == nil {
		f.transports = make(map[string]*http.Transport)
	}
	if transport := f.transports[key]; transport != nil {
		return transport, nil
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("outbound: default transport is not *http.Transport")
	}
	transport := base.Clone()
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 16
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	if f.ResponseHeaderTimeout > 0 {
		transport.ResponseHeaderTimeout = f.ResponseHeaderTimeout
	}
	switch resolved.Mode {
	case ModeEnvironment:
		transport.Proxy = http.ProxyFromEnvironment
	case ModeDirect:
		transport.Proxy = nil
	case ModeURL:
		proxyURL, err := url.Parse(resolved.URL)
		if err != nil {
			return nil, fmt.Errorf("outbound: parse proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	default:
		return nil, fmt.Errorf("outbound: unsupported proxy mode %q", resolved.Mode)
	}
	f.transports[key] = transport
	return transport, nil
}

func (f *Factory) CloseIdleConnections() {
	if f == nil {
		return
	}
	f.mu.Lock()
	transports := make([]*http.Transport, 0, len(f.transports))
	for _, transport := range f.transports {
		transports = append(transports, transport)
	}
	f.transports = make(map[string]*http.Transport)
	f.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func transportKey(resolved ResolvedProxy) string {
	sum := sha256.Sum256([]byte(resolved.Mode + "\x00" + resolved.URL))
	return hex.EncodeToString(sum[:])
}
