// Package config loads and validates grokbuild-proxy configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxSSOConverterBatch           = 100
	maxSSOConverterTimeoutSec      = 300
	maxInspectionCredentialsPerRun = 1000
	maxInspectionIntervalSec       = 7 * 24 * 60 * 60
	maxInspectionTimeoutSec        = 10 * 60
	maxInspectionPurgeAfterSec     = 365 * 24 * 60 * 60
	maxInspectionInitialDelaySec   = 24 * 60 * 60
	maxInspectionSkipRecentSec     = 365 * 24 * 60 * 60
	maxRequestBodyBytes            = 64 << 20
	maxRequestTimeoutSec           = 60 * 60
	maxConcurrentRequests          = 1024
	maxRequestPatchRules           = 64
	maxRequestPatchSetsPerRule     = 32
)

// Config is the root runtime configuration for grokbuild-proxy.
type Config struct {
	Listen            string             `yaml:"listen"`
	DataDir           string             `yaml:"data_dir"`
	APIKey            string             `yaml:"api_key"`
	AdminKey          string             `yaml:"admin_key"`
	AllowPublicListen bool               `yaml:"allow_public_listen"`
	AdminTrustedHosts []string           `yaml:"admin_trusted_hosts"`
	Upstream          UpstreamConfig     `yaml:"upstream"`
	OAuth             OAuthConfig        `yaml:"oauth"`
	ChatBackend       string             `yaml:"chat_backend"`
	Anthropic         AnthropicConfig    `yaml:"anthropic"`
	LB                LBConfig           `yaml:"lb"`
	Proxy             ProxyConfig        `yaml:"proxy"`
	SSOConverter      SSOConfig          `yaml:"sso_converter"`
	Inspection        InspectionConfig   `yaml:"inspection"`
	Import            ImportConfig       `yaml:"import"`
	RequestPatch      RequestPatchConfig `yaml:"request_patch"`
	Notifications     NotificationConfig `yaml:"notifications"`
	Limits            LimitsConfig       `yaml:"limits"`
	Logging           LoggingConfig      `yaml:"logging"`
}

// UpstreamConfig controls how requests are sent to cli-chat-proxy.grok.com.
type UpstreamConfig struct {
	BaseURL          string `yaml:"base_url"`
	ClientVersion    string `yaml:"client_version"`
	ClientIdentifier string `yaml:"client_identifier"`
	UserAgent        string `yaml:"user_agent"`
	TokenAuth        string `yaml:"token_auth"`
	// VisibleModels limits GET /v1/models to models deliberately exposed to
	// clients. An empty list preserves the upstream model list for legacy
	// configurations.
	VisibleModels []string `yaml:"visible_models"`
}

// OAuthConfig holds OIDC / device-flow settings for xAI auth.
type OAuthConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	Scope        string `yaml:"scope"`
	CallbackAddr string `yaml:"callback_addr"`
}

// AnthropicConfig controls Claude Code / Anthropic Messages entry behavior.
type AnthropicConfig struct {
	Enabled             bool              `yaml:"enabled"`
	ModelAliases        map[string]string `yaml:"model_aliases"`
	PassthroughPrefixes []string          `yaml:"passthrough_prefixes"`
	StripUnknownBetas   bool              `yaml:"strip_unknown_betas"`
	CountTokens         bool              `yaml:"count_tokens"`
}

// LBConfig controls multi-credential selection and sticky sessions.
type LBConfig struct {
	Strategy    string `yaml:"strategy"`
	MaxAttempts int    `yaml:"max_attempts"`
	// QuotaCooldownSec is the cooldown applied when a Responses account has
	// exhausted its advertised chat quota. It is intentionally separate from
	// transient HTTP failure cooldowns.
	QuotaCooldownSec int `yaml:"quota_cooldown_sec"`
	// QuotaReserveRequests leaves this many advertised request slots unused
	// while the selector has concurrent work in flight for a credential.
	QuotaReserveRequests int            `yaml:"quota_reserve_requests"`
	StickyTTLSec         int            `yaml:"sticky_ttl_sec"`
	RefreshSkewSec       int            `yaml:"refresh_skew_sec"`
	Cooldown             CooldownConfig `yaml:"cooldown"`
}

// CooldownConfig is exponential backoff bounds for failed credentials.
type CooldownConfig struct {
	BaseSec int `yaml:"base_sec"`
	MaxSec  int `yaml:"max_sec"`
}

// RequestPatchConfig holds ordered raw JSON path overrides applied to the
// upstream Responses body after protocol translation.
type RequestPatchConfig struct {
	Enabled bool               `yaml:"enabled"`
	Rules   []RequestPatchRule `yaml:"rules"`
}

// RequestPatchRule is one model-scoped raw override group.
// Values are raw JSON fragment strings, so complex fields like tools entries
// and response schemas can be pasted as-is.
type RequestPatchRule struct {
	Name   string            `yaml:"name"`
	Models []string          `yaml:"models"`
	Set    map[string]string `yaml:"set"`
}

// NotificationConfig controls optional operator notifications.
type NotificationConfig struct {
	FeishuWebhookURL string `yaml:"feishu_webhook_url"`
}

// ProxyConfig controls the default outbound route. Runtime Admin settings can override it.
type ProxyConfig struct {
	Mode string `yaml:"mode"`
	URL  string `yaml:"url"`
}

// SSOConfig controls the optional SSO-to-OIDC converter service.
type SSOConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Endpoint          string `yaml:"endpoint"`
	APIKey            string `yaml:"api_key"`
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http"`
	TimeoutSec        int    `yaml:"timeout_sec"`
	MaxBatch          int    `yaml:"max_batch"`
}

// InspectionConfig controls scheduled credential validation.
type InspectionConfig struct {
	Enabled              bool    `yaml:"enabled"`
	IntervalSec          int     `yaml:"interval_sec"`
	InitialDelaySec      int     `yaml:"initial_delay_sec"`
	TimeoutSec           int     `yaml:"timeout_sec"`
	Concurrency          int     `yaml:"concurrency"`
	ConfirmUnauthorized  int     `yaml:"confirm_unauthorized"`
	PurgeAfterSec        int     `yaml:"purge_after_sec"`
	MassFailureMinimum   int     `yaml:"mass_failure_minimum"`
	MassFailureRatio     float64 `yaml:"mass_failure_ratio"`
	SkipRecentSuccessSec int     `yaml:"skip_recent_success_sec"`
	MaxCredentialsPerRun int     `yaml:"max_credentials_per_run"`
}

// ImportConfig bounds credential import work independently of normal requests.
type ImportConfig struct {
	MaxFiles         int   `yaml:"max_files"`
	MaxFileBytes     int64 `yaml:"max_file_bytes"`
	MaxTotalBytes    int64 `yaml:"max_total_bytes"`
	MaxEntries       int   `yaml:"max_entries"`
	MaxQueuedJobs    int   `yaml:"max_queued_jobs"`
	MaxQueuedBytes   int64 `yaml:"max_queued_bytes"`
	MaxRetainedJobs  int   `yaml:"max_retained_jobs"`
	MaxRetainedBytes int64 `yaml:"max_retained_bytes"`
	JobTTLMin        int   `yaml:"job_ttl_min"`
}

// LimitsConfig enforces request size, timeout and concurrency caps.
type LimitsConfig struct {
	MaxBodyBytes      int64 `yaml:"max_body_bytes"`
	RequestTimeoutSec int   `yaml:"request_timeout_sec"`
	MaxConcurrent     int   `yaml:"max_concurrent"`
}

// LoggingConfig controls structured logging verbosity.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Default returns a Config aligned with plan.md defaults.
func Default() Config {
	return Config{
		Listen:            "127.0.0.1:8080",
		DataDir:           "./data",
		APIKey:            "",
		AdminKey:          "",
		AllowPublicListen: false,
		Upstream: UpstreamConfig{
			BaseURL:          "https://cli-chat-proxy.grok.com/v1",
			ClientVersion:    "0.2.93",
			ClientIdentifier: "grok-pager",
			UserAgent:        "grok-pager/0.2.93 grok-shell/0.2.93 (linux; x86_64)",
			TokenAuth:        "xai-grok-cli",
			VisibleModels:    []string{"grok-4.5"},
		},
		OAuth: OAuthConfig{
			Issuer:       "https://auth.x.ai",
			ClientID:     "b1a00492-073a-47ea-816f-4c329264a828",
			Scope:        "openid profile email offline_access grok-cli:access api:access",
			CallbackAddr: "127.0.0.1:56122",
		},
		ChatBackend: "responses",
		Anthropic: AnthropicConfig{
			Enabled: true,
			ModelAliases: map[string]string{
				"claude-sonnet-4":   "grok-4.5",
				"claude-sonnet-4-0": "grok-4.5",
				"claude-sonnet-4-6": "grok-4.5",
				"claude-sonnet-5":   "grok-4.5",
				"claude-opus-4":     "grok-4.5",
				"claude-opus-4-6":   "grok-4.5",
				"claude-opus-4-7":   "grok-4.5",
				"claude-opus-4-8":   "grok-4.5",
				"claude-haiku-4":    "grok-4.5",
				"claude-haiku-4-5":  "grok-4.5",
				"sonnet":            "grok-4.5",
				"opus":              "grok-4.5",
				"haiku":             "grok-4.5",
			},
			PassthroughPrefixes: []string{"grok-"},
			StripUnknownBetas:   true,
			CountTokens:         false,
		},
		LB: LBConfig{
			Strategy:             "priority_rr",
			MaxAttempts:          10,
			QuotaCooldownSec:     7 * 24 * 60 * 60,
			QuotaReserveRequests: 1,
			StickyTTLSec:         3600,
			RefreshSkewSec:       180,
			Cooldown: CooldownConfig{
				BaseSec: 300,
				MaxSec:  3600,
			},
		},
		Proxy: ProxyConfig{Mode: "environment"},
		SSOConverter: SSOConfig{
			TimeoutSec: 300,
			MaxBatch:   50,
		},
		Inspection: InspectionConfig{
			IntervalSec:          3600,
			InitialDelaySec:      30,
			TimeoutSec:           30,
			Concurrency:          2,
			ConfirmUnauthorized:  2,
			MassFailureMinimum:   3,
			MassFailureRatio:     0.5,
			SkipRecentSuccessSec: 900,
			MaxCredentialsPerRun: 100,
		},
		Import: ImportConfig{
			MaxFiles:         2000,
			MaxFileBytes:     4 * 1024 * 1024,
			MaxTotalBytes:    16 * 1024 * 1024,
			MaxEntries:       2000,
			MaxQueuedJobs:    32,
			MaxQueuedBytes:   64 * 1024 * 1024,
			MaxRetainedJobs:  128,
			MaxRetainedBytes: 64 * 1024 * 1024,
			JobTTLMin:        30,
		},
		Limits: LimitsConfig{
			MaxBodyBytes:      20 * 1024 * 1024,
			RequestTimeoutSec: 600,
			MaxConcurrent:     64,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load reads a YAML file and merges it over Default().
// Missing file returns Default() with no error when path is empty.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		applyListenEnvironment(&cfg)
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("config file not found: %s: %w", path, err)
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, fmt.Errorf("parse config %s: multiple YAML documents are not supported", path)
		}
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Listen overrides must be applied before Validate. This lets an operator
	// safely narrow a config-file public bind to loopback at runtime.
	applyListenEnvironment(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyListenEnvironment(cfg *Config) {
	if cfg == nil {
		return
	}
	if value := strings.TrimSpace(os.Getenv("LISTEN")); value != "" {
		cfg.Listen = value
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ALLOW_PUBLIC_LISTEN"))) {
	case "1", "true", "yes", "on":
		cfg.AllowPublicListen = true
	}
}

// Validate checks required fields and numeric ranges.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	if c.Upstream.BaseURL == "" {
		return fmt.Errorf("upstream.base_url must not be empty")
	}
	if u, err := url.Parse(c.Upstream.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("upstream.base_url must be an absolute https URL")
	}
	if c.ChatBackend != "responses" {
		return fmt.Errorf("chat_backend must be responses, got %q", c.ChatBackend)
	}
	issuer, err := url.Parse(c.OAuth.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return fmt.Errorf("oauth.issuer must be an absolute https URL")
	}
	issuerHost := strings.ToLower(strings.TrimSuffix(issuer.Hostname(), "."))
	if issuerHost != "auth.x.ai" || (issuer.Port() != "" && issuer.Port() != "443") ||
		issuer.User != nil || strings.TrimRight(issuer.EscapedPath(), "/") != "" ||
		issuer.RawQuery != "" || issuer.Fragment != "" {
		return fmt.Errorf("oauth.issuer must be exactly https://auth.x.ai")
	}
	if c.LB.Strategy != "priority_rr" && c.LB.Strategy != "round_robin" {
		return fmt.Errorf("lb.strategy must be priority_rr or round_robin, got %q", c.LB.Strategy)
	}
	if c.LB.MaxAttempts < 1 || c.LB.MaxAttempts > 20 {
		return fmt.Errorf("lb.max_attempts must be between 1 and 20")
	}
	if c.LB.QuotaCooldownSec <= 0 || c.LB.QuotaCooldownSec > 365*24*60*60 {
		return fmt.Errorf("lb.quota_cooldown_sec must be between 1 and %d", 365*24*60*60)
	}
	if c.LB.QuotaReserveRequests < 0 || c.LB.QuotaReserveRequests > 1000 {
		return fmt.Errorf("lb.quota_reserve_requests must be between 0 and 1000")
	}
	if c.LB.StickyTTLSec < 0 {
		return fmt.Errorf("lb.sticky_ttl_sec must be >= 0")
	}
	if c.LB.RefreshSkewSec < 0 {
		return fmt.Errorf("lb.refresh_skew_sec must be >= 0")
	}
	if c.LB.Cooldown.BaseSec < 0 || c.LB.Cooldown.MaxSec < 0 {
		return fmt.Errorf("lb.cooldown base_sec/max_sec must be >= 0")
	}
	if c.LB.Cooldown.MaxSec > 0 && c.LB.Cooldown.BaseSec > c.LB.Cooldown.MaxSec {
		return fmt.Errorf("lb.cooldown.base_sec must be <= max_sec")
	}
	if err := c.RequestPatch.Validate(); err != nil {
		return err
	}
	if err := validateFeishuWebhookURL(c.Notifications.FeishuWebhookURL); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Proxy.Mode)) {
	case "environment", "direct", "url":
	default:
		return fmt.Errorf("proxy.mode must be environment, direct, or url")
	}
	if strings.EqualFold(strings.TrimSpace(c.Proxy.Mode), "url") && strings.TrimSpace(c.Proxy.URL) == "" {
		return fmt.Errorf("proxy.url is required when proxy.mode is url")
	}
	if c.SSOConverter.TimeoutSec <= 0 || c.SSOConverter.MaxBatch <= 0 {
		return fmt.Errorf("sso_converter timeout_sec/max_batch must be > 0")
	}
	if c.SSOConverter.TimeoutSec > maxSSOConverterTimeoutSec {
		return fmt.Errorf("sso_converter.timeout_sec must be <= %d", maxSSOConverterTimeoutSec)
	}
	if c.SSOConverter.MaxBatch > maxSSOConverterBatch {
		return fmt.Errorf("sso_converter.max_batch must be <= %d", maxSSOConverterBatch)
	}
	if c.SSOConverter.Enabled && strings.TrimSpace(c.SSOConverter.Endpoint) == "" {
		return fmt.Errorf("sso_converter.endpoint is required when enabled")
	}
	if c.Inspection.IntervalSec <= 0 || c.Inspection.TimeoutSec <= 0 ||
		c.Inspection.Concurrency <= 0 || c.Inspection.ConfirmUnauthorized <= 0 {
		return fmt.Errorf("inspection interval/timeout/concurrency/confirm values must be > 0")
	}
	if c.Inspection.PurgeAfterSec < 0 || c.Inspection.MassFailureMinimum <= 0 ||
		math.IsNaN(c.Inspection.MassFailureRatio) || math.IsInf(c.Inspection.MassFailureRatio, 0) ||
		c.Inspection.MassFailureRatio <= 0 || c.Inspection.MassFailureRatio > 1 ||
		c.Inspection.MaxCredentialsPerRun <= 0 ||
		c.Inspection.MaxCredentialsPerRun > maxInspectionCredentialsPerRun {
		return fmt.Errorf("inspection purge/mass-failure values are invalid")
	}
	if c.Inspection.MassFailureMinimum > c.Inspection.MaxCredentialsPerRun {
		return fmt.Errorf("inspection.mass_failure_minimum must be <= max_credentials_per_run")
	}
	if c.Inspection.IntervalSec > maxInspectionIntervalSec ||
		c.Inspection.TimeoutSec > maxInspectionTimeoutSec ||
		c.Inspection.PurgeAfterSec > maxInspectionPurgeAfterSec ||
		c.Inspection.InitialDelaySec > maxInspectionInitialDelaySec ||
		c.Inspection.SkipRecentSuccessSec > maxInspectionSkipRecentSec {
		return fmt.Errorf("inspection duration exceeds its safety limit")
	}
	if c.Import.MaxFiles <= 0 || c.Import.MaxFileBytes <= 0 || c.Import.MaxTotalBytes <= 0 ||
		c.Import.MaxEntries <= 0 || c.Import.MaxQueuedJobs <= 0 || c.Import.MaxQueuedBytes <= 0 ||
		c.Import.MaxRetainedJobs <= 0 || c.Import.MaxRetainedBytes <= 0 || c.Import.JobTTLMin <= 0 {
		return fmt.Errorf("import limits must be > 0")
	}
	if c.Limits.MaxBodyBytes <= 0 {
		return fmt.Errorf("limits.max_body_bytes must be > 0")
	}
	if c.Limits.MaxBodyBytes > maxRequestBodyBytes {
		return fmt.Errorf("limits.max_body_bytes must be <= %d", maxRequestBodyBytes)
	}
	if c.Limits.RequestTimeoutSec <= 0 {
		return fmt.Errorf("limits.request_timeout_sec must be > 0")
	}
	if c.Limits.RequestTimeoutSec > maxRequestTimeoutSec {
		return fmt.Errorf("limits.request_timeout_sec must be <= %d", maxRequestTimeoutSec)
	}
	if c.Limits.MaxConcurrent <= 0 {
		return fmt.Errorf("limits.max_concurrent must be > 0")
	}
	if c.Limits.MaxConcurrent > maxConcurrentRequests {
		return fmt.Errorf("limits.max_concurrent must be <= %d", maxConcurrentRequests)
	}
	switch strings.ToLower(strings.TrimSpace(c.Logging.Level)) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	if c.Anthropic.CountTokens {
		return fmt.Errorf("anthropic.count_tokens is not implemented and must be false")
	}
	for _, host := range c.AdminTrustedHosts {
		if _, err := NormalizeTrustedHost(host); err != nil {
			return fmt.Errorf("admin_trusted_hosts: %w", err)
		}
	}
	return c.ValidateListen(c.Listen)
}

func validateFeishuWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.EqualFold(u.Hostname(), "open.feishu.cn") || u.Port() != "" ||
		!strings.HasPrefix(u.EscapedPath(), "/open-apis/bot/v2/hook/") {
		return fmt.Errorf("notifications.feishu_webhook_url must be an https://open.feishu.cn/open-apis/bot/v2/hook/... URL")
	}
	return nil
}

// RequestTimeout returns the configured HTTP request timeout as a duration.
func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.Limits.RequestTimeoutSec) * time.Second
}

// ValidateListen enforces loopback-first operation. Public binds require an
// explicit opt-in because the proxy stores bearer credentials and consumes quota.
func (c Config) ValidateListen(addr string) error {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("listen address %q must be host:port: %w", addr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("listen address %q has an invalid port", addr)
	}
	if !IsPublicListen(addr) {
		return nil
	}
	if !c.AllowPublicListen {
		return fmt.Errorf("public listen %q requires allow_public_listen: true or ALLOW_PUBLIC_LISTEN=true", addr)
	}
	return nil
}

// IsPublicListen reports whether addr binds all interfaces or a non-loopback IP.
// Hostnames are treated as public because their resolution may change.
func IsPublicListen(addr string) bool {
	addr = strings.TrimSpace(addr)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return true
		}
		return true
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// NormalizeTrustedHost canonicalizes an HTTP Host allowlist entry. Ports are
// accepted but deliberately ignored so one host remains trusted when the
// listener is published through a different local/reverse-proxy port.
func NormalizeTrustedHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("trusted host is empty or contains control characters")
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/\\@?#") {
		return "", fmt.Errorf("trusted host %q must be a hostname or IP address, not a URL", raw)
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	} else if strings.Contains(value, ":") && net.ParseIP(value) == nil {
		return "", fmt.Errorf("trusted host %q has an invalid port or IPv6 form", raw)
	}
	value = strings.ToLower(strings.TrimSuffix(strings.Trim(value, "[]"), "."))
	if value == "" || value == "0.0.0.0" || value == "::" || strings.Contains(value, "*") {
		return "", fmt.Errorf("trusted host %q must be an exact non-wildcard host", raw)
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("trusted host %q is invalid", raw)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", fmt.Errorf("trusted host %q is invalid", raw)
			}
		}
	}
	return value, nil
}

// Validate checks request_patch bounds and raw JSON values.
func (c RequestPatchConfig) Validate() error {
	if len(c.Rules) > maxRequestPatchRules {
		return fmt.Errorf("request_patch.rules must be <= %d", maxRequestPatchRules)
	}
	for i, rule := range c.Rules {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("request_patch.rules[%d].name must not be empty", i)
		}
		if len(rule.Set) == 0 {
			return fmt.Errorf("request_patch.rules[%d].set must not be empty", i)
		}
		if len(rule.Set) > maxRequestPatchSetsPerRule {
			return fmt.Errorf("request_patch.rules[%d].set must be <= %d entries", i, maxRequestPatchSetsPerRule)
		}
		for path, raw := range rule.Set {
			if strings.TrimSpace(path) == "" {
				return fmt.Errorf("request_patch.rules[%d] has empty path", i)
			}
			raw = strings.TrimSpace(raw)
			if raw == "" {
				return fmt.Errorf("request_patch.rules[%d] path %q has empty raw value", i, path)
			}
			if !json.Valid([]byte(raw)) {
				return fmt.Errorf("request_patch.rules[%d] path %q is not valid JSON", i, path)
			}
		}
	}
	if c.Enabled && len(c.Rules) == 0 {
		return fmt.Errorf("request_patch.enabled requires at least one rule")
	}
	return nil
}

// StickyTTL returns sticky session TTL as a duration.
func (c Config) StickyTTL() time.Duration {
	return time.Duration(c.LB.StickyTTLSec) * time.Second
}

// RefreshSkew returns pre-expiry refresh skew as a duration.
func (c Config) RefreshSkew() time.Duration {
	return time.Duration(c.LB.RefreshSkewSec) * time.Second
}

// ResolveModel maps an Anthropic/Claude model id to an upstream Grok model.
// If model already matches a passthrough prefix, it is returned unchanged.
// Unknown models are returned as-is (caller may still reject).
func (c Config) ResolveModel(model string) string {
	return c.Anthropic.ResolveModel(model)
}

// AdvertisesModel reports whether a real upstream model belongs in GET
// /v1/models. Empty VisibleModels preserves the complete upstream listing for
// existing configurations created before this option was introduced.
func (c UpstreamConfig) AdvertisesModel(model string) bool {
	if len(c.VisibleModels) == 0 {
		return true
	}
	model = strings.TrimSpace(model)
	for _, visible := range c.VisibleModels {
		if model != "" && model == strings.TrimSpace(visible) {
			return true
		}
	}
	return false
}

// ResolveModel maps an Anthropic model id using explicit aliases only.
// Unknown future model ids are not guessed because their capabilities may
// differ from the configured target.
func (c AnthropicConfig) ResolveModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return model
	}
	for _, p := range c.PassthroughPrefixes {
		if p != "" && len(model) >= len(p) && model[:len(p)] == p {
			return model
		}
	}
	if alias, ok := c.ModelAliases[model]; ok && alias != "" {
		return alias
	}
	return model
}
