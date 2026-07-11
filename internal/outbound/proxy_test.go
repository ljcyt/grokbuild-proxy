package outbound

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type mutableSettings struct {
	mu    sync.RWMutex
	value storage.RuntimeSettings
}

func (s *mutableSettings) Current() storage.RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}
func (s *mutableSettings) set(v storage.RuntimeSettings) { s.mu.Lock(); s.value = v; s.mu.Unlock() }

type staticSettings struct{ value storage.RuntimeSettings }

func (s staticSettings) Current() storage.RuntimeSettings { return s.value }

type sourcedSettings struct {
	staticSettings
	source string
}

func (s sourcedSettings) GlobalProxySource() string { return s.source }

func TestResolverPrecedence(t *testing.T) {
	settings := storage.DefaultRuntimeSettings()
	settings.GlobalProxy = storage.GlobalProxySettings{
		Mode: ModeURL,
		URL:  "http://global.test:8080",
	}
	resolver := &Resolver{
		Settings: staticSettings{value: settings},
		Fallback: storage.GlobalProxySettings{Mode: ModeDirect},
	}
	got, err := resolver.Resolve(&storage.Credential{
		ProxyMode: ModeURL,
		ProxyURL:  "socks5://user:pass@credential.test:1080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "credential" || !strings.Contains(got.URL, "credential.test") {
		t.Fatalf("credential proxy=%+v", got)
	}
	got, err = resolver.Resolve(&storage.Credential{ProxyMode: ModeDirect})
	if err != nil || got.Mode != ModeDirect || got.Source != "credential" {
		t.Fatalf("direct=%+v err=%v", got, err)
	}
	got, err = resolver.Resolve(&storage.Credential{ProxyMode: ModeInherit})
	if err != nil || got.Source != "runtime" || !strings.Contains(got.URL, "global.test") {
		t.Fatalf("global=%+v err=%v", got, err)
	}
}

func TestResolverReportsConfiguredVersusRuntimeSource(t *testing.T) {
	settings := storage.DefaultRuntimeSettings()
	settings.GlobalProxy = storage.GlobalProxySettings{Mode: ModeDirect}
	resolver := &Resolver{Settings: sourcedSettings{
		staticSettings: staticSettings{value: settings},
		source:         "config",
	}}
	got, err := resolver.Resolve(nil)
	if err != nil || got.Source != "config" {
		t.Fatalf("configured route=%+v err=%v", got, err)
	}
	resolver.Settings = sourcedSettings{
		staticSettings: staticSettings{value: settings},
		source:         "runtime",
	}
	got, err = resolver.Resolve(nil)
	if err != nil || got.Source != "runtime" {
		t.Fatalf("runtime route=%+v err=%v", got, err)
	}
}

func TestValidateAndRedactProxyURL(t *testing.T) {
	value, err := ValidateProxyURL("socks5h://alice:secret@127.0.0.1:1080")
	if err != nil || value == "" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	redacted := RedactedURL(value)
	if strings.Contains(redacted, "secret") || strings.Contains(redacted, "alice") ||
		!strings.Contains(redacted, "redacted@") {
		t.Fatalf("redacted=%q", redacted)
	}
	for _, invalid := range []string{
		"", "ftp://proxy.test", "http://", "http://proxy.test?q=secret", "http://proxy.test/#x",
	} {
		if _, err := ValidateProxyURL(invalid); err == nil {
			t.Fatalf("expected invalid: %q", invalid)
		}
	}
}

func TestFactoryDirectDoesNotUseEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://environment.test:8080")
	settings := storage.DefaultRuntimeSettings()
	settings.GlobalProxy.Mode = ModeDirect
	factory := &Factory{Resolver: &Resolver{Settings: staticSettings{value: settings}}}
	client, _, err := factory.ClientFor(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("direct mode must disable environment proxy")
	}
}

func TestFactoryUsesLatestRuntimeRouteAndNeverFallsBack(t *testing.T) {
	settings := storage.DefaultRuntimeSettings()
	settings.GlobalProxy.Mode = ModeDirect
	provider := &mutableSettings{value: settings}
	factory := &Factory{Resolver: &Resolver{Settings: provider}}
	_, first, err := factory.ClientFor(nil, 0)
	if err != nil || first.Mode != ModeDirect {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	settings.GlobalProxy = storage.GlobalProxySettings{Mode: ModeURL, URL: "http://proxy.test:8080"}
	provider.set(settings)
	_, second, err := factory.ClientFor(nil, 0)
	if err != nil || second.Mode != ModeURL || !strings.Contains(second.URL, "proxy.test") {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	settings.GlobalProxy.URL = "not-a-proxy"
	provider.set(settings)
	client, _, err := factory.ClientFor(nil, 0)
	if err == nil || client != nil {
		t.Fatalf("configured proxy error must not fall back: client=%v err=%v", client, err)
	}
}

func TestConfiguredUnreachableProxyNeverFallsBackToDirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()
	settings := storage.DefaultRuntimeSettings()
	settings.GlobalProxy = storage.GlobalProxySettings{Mode: ModeURL, URL: "http://127.0.0.1:1"}
	factory := &Factory{Resolver: &Resolver{Settings: staticSettings{value: settings}}}
	client, _, err := factory.ClientFor(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(target.URL); err == nil {
		t.Fatal("request unexpectedly succeeded without the configured proxy")
	}
	if hits.Load() != 0 {
		t.Fatal("target was contacted directly after proxy connection failure")
	}
}
