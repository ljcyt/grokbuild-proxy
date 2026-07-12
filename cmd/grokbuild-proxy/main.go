package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/admin"
	"github.com/GreyGunG/grokbuild-proxy/internal/anthropic"
	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/httpserver"
	"github.com/GreyGunG/grokbuild-proxy/internal/importer"
	"github.com/GreyGunG/grokbuild-proxy/internal/inspection"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/notify"
	"github.com/GreyGunG/grokbuild-proxy/internal/openai"
	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/proxy"
	"github.com/GreyGunG/grokbuild-proxy/internal/requestpatch"
	runtimesettings "github.com/GreyGunG/grokbuild-proxy/internal/settings"
	"github.com/GreyGunG/grokbuild-proxy/internal/sso"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	logger := newLogger("info")
	slog.SetDefault(logger)
	configPath := flag.String("config", "", "path to config.yaml (defaults to config.yaml/config.example.yaml when present)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	path := strings.TrimSpace(*configPath)
	if path == "" {
		path = defaultConfigPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		fail(logger, "config_invalid", err)
	}
	logger = newLogger(cfg.Logging.Level)
	slog.SetDefault(logger)
	if value := strings.TrimSpace(os.Getenv("LISTEN")); value != "" {
		cfg.Listen = value
	}
	if envTrue("ALLOW_PUBLIC_LISTEN") {
		cfg.AllowPublicListen = true
	}
	if err := cfg.ValidateListen(cfg.Listen); err != nil {
		fail(logger, "listen_invalid", err)
	}

	store, err := storage.New(cfg.DataDir)
	if err != nil {
		fail(logger, "storage_open_failed", err)
	}
	defer store.Close()

	settingsManager, err := runtimesettings.New(store, runtimeDefaults(cfg))
	if err != nil {
		fail(logger, "runtime_settings_invalid", err)
	}
	outboundResolver := &outbound.Resolver{
		Settings: settingsManager,
		Fallback: storage.GlobalProxySettings{Mode: cfg.Proxy.Mode, URL: cfg.Proxy.URL},
	}
	outboundFactory := &outbound.Factory{
		Resolver:              outboundResolver,
		ResponseHeaderTimeout: cfg.RequestTimeout(),
	}
	defer outboundFactory.CloseIdleConnections()
	if _, err := outboundResolver.Resolve(nil); err != nil {
		fail(logger, "proxy_config_invalid", err)
	}

	apiKey, adminKey, genAPI, genAdmin, err := store.EnsureBootstrapKeys(cfg.APIKey, cfg.AdminKey)
	if err != nil {
		fail(logger, "bootstrap_keys_failed", err)
	}
	if genAPI || genAdmin {
		logger.Info("bootstrap_keys_generated", "path", cfg.DataDir+"/meta.json")
	}
	if !genAPI && !genAdmin && (strings.TrimSpace(cfg.APIKey) == "" || strings.TrimSpace(cfg.AdminKey) == "") {
		logger.Info("bootstrap_keys_loaded", "path", cfg.DataDir+"/meta.json")
	}
	if apiKey != "" && adminKey != "" && apiKey == adminKey {
		fail(logger, "bootstrap_keys_invalid", fmt.Errorf("api_key and admin_key must differ"))
	}
	cfg.APIKey = apiKey
	cfg.AdminKey = adminKey

	oauthHTTP, _, err := outboundFactory.ClientFor(nil, cfg.RequestTimeout())
	if err != nil {
		fail(logger, "oauth_transport_invalid", err)
	}
	oauth := &auth.OAuthClient{
		HTTPClient: oauthHTTP,
		Issuer:     cfg.OAuth.Issuer,
		ClientID:   cfg.OAuth.ClientID,
		Scope:      cfg.OAuth.Scope,
	}
	refresher := &auth.Refresher{
		OAuth:   oauth,
		Skew:    cfg.RefreshSkew(),
		Timeout: cfg.RequestTimeout(),
	}
	refresher.OAuthFor = credentialOAuthResolver(store, outboundFactory, cfg)

	upstreamConfig := upstream.Config{
		BaseURL:          cfg.Upstream.BaseURL,
		ClientVersion:    cfg.Upstream.ClientVersion,
		ClientIdentifier: cfg.Upstream.ClientIdentifier,
		TokenAuth:        cfg.Upstream.TokenAuth,
		UserAgent:        cfg.Upstream.UserAgent,
		RequestTimeout:   cfg.RequestTimeout(),
	}
	globalUpstreamHTTP, _, err := outboundFactory.ClientFor(nil, 0)
	if err != nil {
		fail(logger, "upstream_transport_invalid", err)
	}
	upstreamConfig.HTTPClient = globalUpstreamHTTP
	up := upstream.NewClient(upstreamConfig)

	selector := lb.New(cfg.LB).SetHealthStore(store)
	bodyPatch := requestPatcherFromConfig(cfg.RequestPatch)

	exec := &proxy.Executor{
		Store:       store,
		Selector:    selector,
		Upstream:    up,
		MaxAttempts: cfg.LB.MaxAttempts,
		UpstreamFor: func(credential storage.Credential) (proxy.Upstream, error) {
			httpClient, _, err := outboundFactory.ClientFor(&credential, 0)
			if err != nil {
				return nil, err
			}
			credentialConfig := upstreamConfig
			credentialConfig.HTTPClient = httpClient
			return upstream.NewClient(credentialConfig), nil
		},
		Refresher:     refresher,
		Logger:        logger,
		RequestID:     httpserver.RequestIDFromContext,
		RouteRevision: settingsManager.Revision,
		BodyPatch:     bodyPatch,
	}
	ssoConverter := configuredSSOConverter(settingsManager, outboundFactory)
	importManager, err := importer.NewManager(store, ssoConverter, importer.Limits{
		MaxFiles:         cfg.Import.MaxFiles,
		MaxFileBytes:     cfg.Import.MaxFileBytes,
		MaxTotalBytes:    cfg.Import.MaxTotalBytes,
		MaxEntries:       cfg.Import.MaxEntries,
		MaxQueuedJobs:    cfg.Import.MaxQueuedJobs,
		MaxQueuedBytes:   cfg.Import.MaxQueuedBytes,
		MaxRetainedJobs:  cfg.Import.MaxRetainedJobs,
		MaxRetainedBytes: cfg.Import.MaxRetainedBytes,
		JobTTL:           time.Duration(cfg.Import.JobTTLMin) * time.Minute,
	})
	if err != nil {
		fail(logger, "import_manager_invalid", err)
	}
	importManager.BeforeStore = refresher.InvalidateAll
	importManager.OnStored = func(results []storage.BulkUpsertResult) {
		for _, result := range results {
			refresher.Invalidate(result.Credential.ID)
		}
	}
	inspectionRunner := &inspection.Runner{
		Store:                store,
		Prober:               exec,
		Settings:             settingsManager,
		Logger:               logger,
		RateLimitCooldown:    time.Duration(cfg.LB.Cooldown.BaseSec) * time.Second,
		QuotaCooldown:        time.Duration(cfg.LB.QuotaCooldownSec) * time.Second,
		Notifier:             notify.RuntimeFeishuNotifier{Settings: settingsManager, Client: globalUpstreamHTTP},
		InvalidateCredential: refresher.Invalidate,
	}
	inspectionCtx, stopInspection := context.WithCancel(context.Background())
	defer stopInspection()
	go inspectionRunner.Run(inspectionCtx)

	oai := &openai.Handlers{
		Post:    exec.Post,
		MaxBody: cfg.Limits.MaxBodyBytes,
	}
	anth := &anthropic.Handlers{
		Post:    exec.Post,
		Cfg:     cfg.Anthropic,
		MaxBody: cfg.Limits.MaxBodyBytes,
		ResolveModel: func(m string) string {
			return cfg.ResolveModel(m)
		},
	}

	adm := &admin.Handlers{
		Store:  store,
		Tokens: exec,
		OAuth:  oauth,
		OAuthFor: func() (admin.DeviceOAuth, error) {
			httpClient, _, err := outboundFactory.ClientFor(nil, cfg.RequestTimeout())
			if err != nil {
				return nil, err
			}
			return &auth.OAuthClient{HTTPClient: httpClient, Issuer: cfg.OAuth.Issuer, ClientID: cfg.OAuth.ClientID, Scope: cfg.OAuth.Scope}, nil
		},
		Settings:      settingsManager,
		Outbound:      outboundFactory,
		ProxyResolver: outboundResolver,
		TokenCache:    refresher,
		Imports:       importManager,
		Inspection:    inspectionRunner,
		Config:        cfg,
		AdminKey:      adminKey,
		Version:       version,
		MaxBody:       cfg.Limits.MaxBodyBytes,
	}

	handler := httpserver.New(httpserver.Options{
		Config:    cfg,
		AdminKey:  adminKey,
		Store:     store,
		OpenAI:    oai,
		Anthropic: anth,
		Admin:     adm,
		ModelList: exec,
		Version:   version,
		Logger:    logger,
	})

	addr := cfg.Listen
	srv := httpserver.NewServer(addr, handler, cfg.RequestTimeout())

	go func() {
		logger.Info("server_listening", "version", version, "address", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server_failed", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	sig := <-stop
	logger.Info("shutdown_signal", "signal", sig.String())
	stopInspection()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown_failed", "error", err)
	}
}

type credentialStore interface {
	GetCredential(id string) (storage.Credential, error)
}

type oauthHTTPClientFactory interface {
	ClientFor(credential *storage.Credential, timeout time.Duration) (*http.Client, outbound.ResolvedProxy, error)
}

func credentialOAuthResolver(store credentialStore, factory oauthHTTPClientFactory, cfg config.Config) func(string) (*auth.OAuthClient, error) {
	return func(key string) (*auth.OAuthClient, error) {
		credential, err := store.GetCredential(key)
		if err != nil {
			return nil, err
		}
		httpClient, _, err := factory.ClientFor(&credential, cfg.RequestTimeout())
		if err != nil {
			return nil, err
		}
		issuer := strings.TrimSpace(credential.OIDCIssuer)
		if issuer == "" {
			issuer = cfg.OAuth.Issuer
		}
		issuer, err = auth.NormalizeTrustedIssuer(issuer)
		if err != nil {
			return nil, err
		}
		clientID := strings.TrimSpace(credential.OIDCClientID)
		if clientID == "" {
			clientID = cfg.OAuth.ClientID
		}
		return &auth.OAuthClient{
			HTTPClient: httpClient,
			Issuer:     issuer,
			ClientID:   clientID,
			Scope:      cfg.OAuth.Scope,
		}, nil
	}
}

func fail(logger *slog.Logger, event string, err error) {
	logger.Error(event, "error", err)
	os.Exit(1)
}

func newLogger(level string) *slog.Logger {
	var selected slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		selected = slog.LevelDebug
	case "warn", "warning":
		selected = slog.LevelWarn
	case "error":
		selected = slog.LevelError
	default:
		selected = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: selected}))
}

func defaultConfigPath() string {
	candidates := []string{"config.yaml", "config.example.yaml"}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func runtimeDefaults(cfg config.Config) storage.RuntimeSettings {
	settings := storage.DefaultRuntimeSettings()
	settings.Notifications.FeishuWebhookURL = cfg.Notifications.FeishuWebhookURL
	settings.GlobalProxy = storage.GlobalProxySettings{
		Mode: cfg.Proxy.Mode,
		URL:  cfg.Proxy.URL,
	}
	settings.SSOConverter = storage.SSOConverterSettings{
		Enabled:       cfg.SSOConverter.Enabled,
		Endpoint:      cfg.SSOConverter.Endpoint,
		APIKey:        cfg.SSOConverter.APIKey,
		AllowInsecure: cfg.SSOConverter.AllowInsecureHTTP,
		TimeoutSec:    cfg.SSOConverter.TimeoutSec,
		MaxBatch:      cfg.SSOConverter.MaxBatch,
	}
	settings.Inspection.Enabled = cfg.Inspection.Enabled
	settings.Inspection.IntervalSec = cfg.Inspection.IntervalSec
	settings.Inspection.InitialDelaySec = cfg.Inspection.InitialDelaySec
	settings.Inspection.TimeoutSec = cfg.Inspection.TimeoutSec
	settings.Inspection.Concurrency = cfg.Inspection.Concurrency
	settings.Inspection.ConfirmUnauthorized = cfg.Inspection.ConfirmUnauthorized
	settings.Inspection.PurgeAfterSec = cfg.Inspection.PurgeAfterSec
	settings.Inspection.MassFailureMinimum = cfg.Inspection.MassFailureMinimum
	settings.Inspection.MassFailureRatio = cfg.Inspection.MassFailureRatio
	settings.Inspection.SkipRecentSuccessSec = cfg.Inspection.SkipRecentSuccessSec
	settings.Inspection.MaxCredentialsPerRun = cfg.Inspection.MaxCredentialsPerRun
	return settings
}

func configuredSSOConverter(settings sso.SettingsProvider, factory sso.HTTPClientFactory) importer.Converter {
	if settings == nil {
		return nil
	}
	// The client reads runtime settings for every conversion. Keeping it wired
	// while disabled allows an Admin settings update to enable SSO imports
	// without restarting the process.
	return &sso.Client{Settings: settings, Outbound: factory}
}

func requestPatcherFromConfig(cfg config.RequestPatchConfig) func([]byte, string) ([]byte, error) {
	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return nil
	}
	rules := make([]requestpatch.Rule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		set := make(map[string]json.RawMessage, len(rule.Set))
		for path, raw := range rule.Set {
			set[path] = json.RawMessage(strings.TrimSpace(raw))
		}
		rules = append(rules, requestpatch.Rule{
			Name:   rule.Name,
			Models: append([]string(nil), rule.Models...),
			Set:    set,
		})
	}
	patcher := &requestpatch.Patcher{Rules: rules}
	return patcher.Apply
}
