package config

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRejectsNonFiniteMassFailureRatio(t *testing.T) {
	for _, ratio := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		cfg := Default()
		cfg.Inspection.MassFailureRatio = ratio
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted non-finite mass_failure_ratio %v", ratio)
		}
	}

	path := filepath.Join(t.TempDir(), "nan.yaml")
	if err := os.WriteFile(path, []byte("inspection:\n  mass_failure_ratio: .nan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted YAML .nan mass_failure_ratio")
	}
}

func TestDefaultAlignedWithPlan(t *testing.T) {
	cfg := Default()

	if cfg.Listen != "127.0.0.1:8080" {
		t.Fatalf("listen: got %q", cfg.Listen)
	}
	if cfg.DataDir != "./data" {
		t.Fatalf("data_dir: got %q", cfg.DataDir)
	}
	if cfg.Upstream.BaseURL != "https://cli-chat-proxy.grok.com/v1" {
		t.Fatalf("upstream.base_url: got %q", cfg.Upstream.BaseURL)
	}
	if cfg.Upstream.ClientVersion != "0.2.93" {
		t.Fatalf("client_version: got %q", cfg.Upstream.ClientVersion)
	}
	if cfg.Upstream.ClientIdentifier != "grok-pager" {
		t.Fatalf("client_identifier: got %q", cfg.Upstream.ClientIdentifier)
	}
	if cfg.Upstream.TokenAuth != "xai-grok-cli" {
		t.Fatalf("token_auth: got %q", cfg.Upstream.TokenAuth)
	}
	if cfg.OAuth.Issuer != "https://auth.x.ai" {
		t.Fatalf("oauth.issuer: got %q", cfg.OAuth.Issuer)
	}
	if cfg.OAuth.ClientID != "b1a00492-073a-47ea-816f-4c329264a828" {
		t.Fatalf("oauth.client_id: got %q", cfg.OAuth.ClientID)
	}
	if cfg.ChatBackend != "responses" {
		t.Fatalf("chat_backend: got %q", cfg.ChatBackend)
	}
	if !cfg.Anthropic.Enabled {
		t.Fatal("anthropic.enabled should be true")
	}
	if !cfg.Anthropic.StripUnknownBetas {
		t.Fatal("strip_unknown_betas should be true")
	}
	if cfg.Anthropic.CountTokens {
		t.Fatal("count_tokens should be false for MVP")
	}
	wantAliases := map[string]string{
		"claude-sonnet-4":   "grok-4.5",
		"claude-sonnet-4-0": "grok-4.5",
		"claude-sonnet-4-6": "grok-4.5",
		"claude-sonnet-5":   "grok-4.5",
		"claude-opus-4":     "grok-4.5",
		"claude-opus-4-6":   "grok-4.5",
		"claude-opus-4-7":   "grok-4.5",
		"claude-opus-4-8":   "grok-4.5",
		"claude-haiku-4":    "grok-composer-2.5-fast",
		"claude-haiku-4-5":  "grok-composer-2.5-fast",
		"sonnet":            "grok-4.5",
		"opus":              "grok-4.5",
		"haiku":             "grok-composer-2.5-fast",
	}
	for k, v := range wantAliases {
		if got := cfg.Anthropic.ModelAliases[k]; got != v {
			t.Fatalf("alias %s: want %q got %q", k, v, got)
		}
	}
	if len(cfg.Anthropic.PassthroughPrefixes) != 1 || cfg.Anthropic.PassthroughPrefixes[0] != "grok-" {
		t.Fatalf("passthrough_prefixes: %#v", cfg.Anthropic.PassthroughPrefixes)
	}
	if cfg.LB.Strategy != "priority_rr" {
		t.Fatalf("lb.strategy: got %q", cfg.LB.Strategy)
	}
	if cfg.LB.MaxAttempts != 3 {
		t.Fatalf("lb.max_attempts: got %d", cfg.LB.MaxAttempts)
	}
	if cfg.LB.StickyTTLSec != 3600 || cfg.LB.RefreshSkewSec != 180 {
		t.Fatalf("lb sticky/refresh: %+v", cfg.LB)
	}
	if cfg.LB.Cooldown.BaseSec != 300 || cfg.LB.Cooldown.MaxSec != 3600 {
		t.Fatalf("cooldown: %+v", cfg.LB.Cooldown)
	}
	if cfg.Limits.MaxBodyBytes != 20*1024*1024 {
		t.Fatalf("max_body_bytes: %d", cfg.Limits.MaxBodyBytes)
	}
	if cfg.Limits.RequestTimeoutSec != 600 || cfg.Limits.MaxConcurrent != 64 {
		t.Fatalf("limits: %+v", cfg.Limits)
	}
	if cfg.Import.MaxQueuedJobs != 32 || cfg.Import.MaxQueuedBytes != 64*1024*1024 {
		t.Fatalf("import queue limits: %+v", cfg.Import)
	}
	if cfg.Import.MaxRetainedJobs != 128 || cfg.Import.MaxRetainedBytes != 64*1024*1024 {
		t.Fatalf("import retention limits: %+v", cfg.Import)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("logging.level: %q", cfg.Logging.Level)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default should validate: %v", err)
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
listen: "0.0.0.0:9090"
allow_public_listen: true
data_dir: "/var/lib/grokbuild"
api_key: ""
admin_key: ""
chat_backend: responses
anthropic:
  enabled: true
  model_aliases:
    claude-sonnet-4: grok-4.5
    custom-alias: grok-composer-2.5-fast
  passthrough_prefixes: ["grok-", "xai-"]
  strip_unknown_betas: false
  count_tokens: false
lb:
  strategy: round_robin
  max_attempts: 7
  sticky_ttl_sec: 120
  refresh_skew_sec: 60
  cooldown:
    base_sec: 10
    max_sec: 100
limits:
  max_body_bytes: 1024
  request_timeout_sec: 30
  max_concurrent: 2
logging:
  level: debug
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9090" {
		t.Fatalf("listen override: %q", cfg.Listen)
	}
	if cfg.DataDir != "/var/lib/grokbuild" {
		t.Fatalf("data_dir override: %q", cfg.DataDir)
	}
	// Unspecified nested fields keep defaults.
	if cfg.Upstream.BaseURL != "https://cli-chat-proxy.grok.com/v1" {
		t.Fatalf("upstream should keep default base_url: %q", cfg.Upstream.BaseURL)
	}
	if cfg.ChatBackend != "responses" {
		t.Fatalf("chat_backend: %q", cfg.ChatBackend)
	}
	if !cfg.AllowPublicListen {
		t.Fatal("allow_public_listen override missing")
	}
	if cfg.Anthropic.ModelAliases["custom-alias"] != "grok-composer-2.5-fast" {
		t.Fatalf("custom alias missing: %#v", cfg.Anthropic.ModelAliases)
	}
	// YAML map replace: only keys present in file remain (standard yaml.v3 merge into struct map).
	if cfg.LB.Strategy != "round_robin" {
		t.Fatalf("strategy: %q", cfg.LB.Strategy)
	}
	if cfg.LB.MaxAttempts != 7 {
		t.Fatalf("max_attempts: %d", cfg.LB.MaxAttempts)
	}
	if cfg.LB.StickyTTLSec != 120 {
		t.Fatalf("sticky_ttl: %d", cfg.LB.StickyTTLSec)
	}
	if cfg.Limits.MaxBodyBytes != 1024 {
		t.Fatalf("max_body: %d", cfg.Limits.MaxBodyBytes)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("log level: %q", cfg.Logging.Level)
	}
	if cfg.Anthropic.StripUnknownBetas {
		t.Fatal("strip_unknown_betas should be false after override")
	}
	if cfg.Anthropic.CountTokens {
		t.Fatal("count_tokens must remain disabled")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("listen: 127.0.0.1:8080\nunknown_option: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown YAML field must fail")
	}
}

func TestLoadEmptyPathReturnsDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != Default().Listen {
		t.Fatalf("empty path should default: %q", cfg.Listen)
	}
}

func TestLoadAppliesListenEnvironmentBeforeValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`listen: "0.0.0.0:9090"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LISTEN", "127.0.0.1:19090")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:19090" {
		t.Fatalf("listen=%q", cfg.Listen)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"empty listen", func(c *Config) { c.Listen = "" }},
		{"empty data_dir", func(c *Config) { c.DataDir = "" }},
		{"empty upstream", func(c *Config) { c.Upstream.BaseURL = "" }},
		{"insecure upstream", func(c *Config) { c.Upstream.BaseURL = "http://example.com" }},
		{"bad oauth issuer", func(c *Config) { c.OAuth.Issuer = "https://example.com" }},
		{"oauth issuer subdomain", func(c *Config) { c.OAuth.Issuer = "https://preview.auth.x.ai" }},
		{"oauth issuer path", func(c *Config) { c.OAuth.Issuer = "https://auth.x.ai/tenant" }},
		{"bad chat_backend", func(c *Config) { c.ChatBackend = "foo" }},
		{"bad strategy", func(c *Config) { c.LB.Strategy = "random" }},
		{"zero max attempts", func(c *Config) { c.LB.MaxAttempts = 0 }},
		{"too many max attempts", func(c *Config) { c.LB.MaxAttempts = 21 }},
		{"neg sticky", func(c *Config) { c.LB.StickyTTLSec = -1 }},
		{"cooldown inverted", func(c *Config) { c.LB.Cooldown.BaseSec = 10; c.LB.Cooldown.MaxSec = 5 }},
		{"zero body", func(c *Config) { c.Limits.MaxBodyBytes = 0 }},
		{"zero timeout", func(c *Config) { c.Limits.RequestTimeoutSec = 0 }},
		{"zero concurrent", func(c *Config) { c.Limits.MaxConcurrent = 0 }},
		{"zero import total", func(c *Config) { c.Import.MaxTotalBytes = 0 }},
		{"zero import retained jobs", func(c *Config) { c.Import.MaxRetainedJobs = 0 }},
		{"zero import retained bytes", func(c *Config) { c.Import.MaxRetainedBytes = 0 }},
		{"oversized sso timeout", func(c *Config) { c.SSOConverter.TimeoutSec = maxSSOConverterTimeoutSec + 1 }},
		{"oversized sso batch", func(c *Config) { c.SSOConverter.MaxBatch = maxSSOConverterBatch + 1 }},
		{"invalid logging level", func(c *Config) { c.Logging.Level = "verbose" }},
		{"unsupported count_tokens", func(c *Config) { c.Anthropic.CountTokens = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mut(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateListenRequiresExplicitPublicOptIn(t *testing.T) {
	cfg := Default()
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.0.2.1:8080", "proxy.local:8080"} {
		if err := cfg.ValidateListen(addr); err == nil {
			t.Fatalf("%s should require opt-in", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if err := cfg.ValidateListen(addr); err != nil {
			t.Fatalf("%s should be local: %v", addr, err)
		}
	}
	cfg.AllowPublicListen = true
	if err := cfg.ValidateListen("0.0.0.0:8080"); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"localhost", "127.0.0.1:0", "127.0.0.1:70000"} {
		if err := cfg.ValidateListen(addr); err == nil {
			t.Fatalf("%s should be invalid", addr)
		}
	}
}

func TestResolveModel(t *testing.T) {
	cfg := Default()
	if got := cfg.ResolveModel("claude-sonnet-4"); got != "grok-4.5" {
		t.Fatalf("alias: %q", got)
	}
	if got := cfg.ResolveModel("grok-4.5"); got != "grok-4.5" {
		t.Fatalf("passthrough: %q", got)
	}
	if got := cfg.ResolveModel("claude-opus-4-99-20990101"); got != "claude-opus-4-99-20990101" {
		t.Fatalf("unknown future model must not be guessed: %q", got)
	}
	if got := cfg.ResolveModel("unknown-model"); got != "unknown-model" {
		t.Fatalf("unknown passthrough: %q", got)
	}
	if got := cfg.ResolveModel(""); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestDurationHelpers(t *testing.T) {
	cfg := Default()
	if cfg.RequestTimeout() != 600*time.Second {
		t.Fatalf("timeout: %v", cfg.RequestTimeout())
	}
	if cfg.StickyTTL() != 3600*time.Second {
		t.Fatalf("sticky: %v", cfg.StickyTTL())
	}
	if cfg.RefreshSkew() != 180*time.Second {
		t.Fatalf("skew: %v", cfg.RefreshSkew())
	}
}
