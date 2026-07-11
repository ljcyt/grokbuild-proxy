package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type staticRuntimeSettings struct {
	settings storage.RuntimeSettings
}

func TestCredentialOAuthResolverUsesCredentialProxyTransport(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	credential, _, err := store.UpsertCredential(storage.CreateCredentialInput{
		UserID: "proxy-user", AccessToken: "access", RefreshToken: "refresh",
		ProxyMode: storage.CredentialProxyURL,
		ProxyURL:  "http://user:secret@127.0.0.1:18080",
	})
	if err != nil {
		t.Fatal(err)
	}
	factory := &outbound.Factory{Resolver: &outbound.Resolver{
		Fallback: storage.GlobalProxySettings{Mode: outbound.ModeDirect},
	}}
	oauthClient, err := credentialOAuthResolver(store, factory, config.Default())(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := oauthClient.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport=%T", oauthClient.HTTPClient.Transport)
	}
	request, err := http.NewRequest(http.MethodPost, "https://auth.x.ai/oauth2/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := transport.Proxy(request)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || !strings.Contains(proxyURL.String(), "127.0.0.1:18080") {
		t.Fatalf("refresh transport did not use credential proxy: %v", proxyURL)
	}
}

func (s staticRuntimeSettings) Current() storage.RuntimeSettings { return s.settings }

func TestConfiguredSSOConverter(t *testing.T) {
	settings := storage.DefaultRuntimeSettings()
	if converter := configuredSSOConverter(staticRuntimeSettings{settings: settings}, nil); converter == nil {
		t.Fatal("runtime-aware converter must remain wired while disabled")
	}

	settings.SSOConverter.Enabled = true
	if converter := configuredSSOConverter(staticRuntimeSettings{settings: settings}, nil); converter == nil {
		t.Fatal("enabled converter must be created")
	}
	if converter := configuredSSOConverter(nil, nil); converter != nil {
		t.Fatal("nil settings provider must not create a converter")
	}
}
