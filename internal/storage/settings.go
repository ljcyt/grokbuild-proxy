package storage

import (
	"fmt"
	"math"
	"os"
	"strings"
)

const (
	MaxSSOConverterBatch           = 100
	MaxSSOConverterTimeoutSec      = 300
	MaxInspectionCredentialsPerRun = 1000
	MaxInspectionIntervalSec       = 7 * 24 * 60 * 60
	MaxInspectionTimeoutSec        = 10 * 60
	MaxInspectionPurgeAfterSec     = 365 * 24 * 60 * 60
	MaxInspectionInitialDelaySec   = 24 * 60 * 60
	MaxInspectionSkipRecentSec     = 365 * 24 * 60 * 60
)

// RuntimeSettings are operator-managed overrides stored under data_dir.
// Proxy URLs and converter keys may contain secrets; settings.json is mode 0600.
type RuntimeSettings struct {
	GlobalProxy  GlobalProxySettings  `json:"global_proxy"`
	SSOConverter SSOConverterSettings `json:"sso_converter"`
	Inspection   InspectionSettings   `json:"inspection"`
}

type GlobalProxySettings struct {
	Mode string `json:"mode,omitempty"`
	URL  string `json:"url,omitempty"`
}

type SSOConverterSettings struct {
	Enabled       bool   `json:"enabled"`
	Endpoint      string `json:"endpoint,omitempty"`
	APIKey        string `json:"api_key,omitempty"`
	AllowInsecure bool   `json:"allow_insecure_http,omitempty"`
	TimeoutSec    int    `json:"timeout_sec,omitempty"`
	MaxBatch      int    `json:"max_batch,omitempty"`
}

type InspectionSettings struct {
	Enabled                bool    `json:"enabled"`
	IntervalSec            int     `json:"interval_sec,omitempty"`
	TimeoutSec             int     `json:"timeout_sec,omitempty"`
	Concurrency            int     `json:"concurrency,omitempty"`
	ConfirmUnauthorized    int     `json:"confirm_unauthorized,omitempty"`
	PurgeAfterSec          int     `json:"purge_after_sec,omitempty"`
	MassFailureMinimum     int     `json:"mass_failure_minimum,omitempty"`
	MassFailureRatio       float64 `json:"mass_failure_ratio,omitempty"`
	InitialDelaySec        int     `json:"initial_delay_sec,omitempty"`
	InspectQuarantined     bool    `json:"inspect_quarantined,omitempty"`
	SkipRecentSuccessSec   int     `json:"skip_recent_success_sec,omitempty"`
	MaxCredentialsPerRun   int     `json:"max_credentials_per_run,omitempty"`
	MaxPersistedRunResults int     `json:"max_persisted_run_results,omitempty"`
}

func DefaultRuntimeSettings() RuntimeSettings {
	return RuntimeSettings{
		GlobalProxy: GlobalProxySettings{Mode: "environment"},
		SSOConverter: SSOConverterSettings{
			TimeoutSec: 300,
			MaxBatch:   50,
		},
		Inspection: InspectionSettings{
			IntervalSec:            3600,
			TimeoutSec:             30,
			Concurrency:            2,
			ConfirmUnauthorized:    2,
			MassFailureMinimum:     3,
			MassFailureRatio:       0.5,
			InitialDelaySec:        30,
			InspectQuarantined:     true,
			SkipRecentSuccessSec:   900,
			MaxCredentialsPerRun:   100,
			MaxPersistedRunResults: 100,
		},
	}
}

// LoadRuntimeSettings returns supplied defaults (or built-ins) when settings.json does not exist.
func (s *Store) LoadRuntimeSettings(defaults ...RuntimeSettings) (RuntimeSettings, error) {
	fallback := DefaultRuntimeSettings()
	if len(defaults) > 0 {
		fallback = normalizeRuntimeSettings(defaults[0], fallback)
	}
	settings := fallback
	err := s.withLock(func() error {
		var stored RuntimeSettings
		if err := readJSONFile(s.settingsPath(), &stored); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		settings = normalizeRuntimeSettings(stored, fallback)
		return nil
	})
	return settings, err
}

func (s *Store) SaveRuntimeSettings(settings RuntimeSettings) (RuntimeSettings, error) {
	settings = normalizeRuntimeSettings(settings, DefaultRuntimeSettings())
	err := s.withLock(func() error {
		return writeJSONFile(s.settingsPath(), settings)
	})
	return settings, err
}

// RuntimeSettingsExist reports whether an operator-managed settings snapshot
// has been persisted, without exposing its filesystem location.
func (s *Store) RuntimeSettingsExist() (bool, error) {
	var exists bool
	err := s.withLock(func() error {
		_, err := os.Stat(s.settingsPath())
		if err == nil {
			exists = true
			return nil
		}
		if os.IsNotExist(err) {
			return nil
		}
		return err
	})
	return exists, err
}

func normalizeRuntimeSettings(value, fallback RuntimeSettings) RuntimeSettings {
	out := value
	out.GlobalProxy.Mode = strings.ToLower(strings.TrimSpace(out.GlobalProxy.Mode))
	if out.GlobalProxy.Mode == "" {
		out.GlobalProxy.Mode = fallback.GlobalProxy.Mode
	}
	out.GlobalProxy.URL = strings.TrimSpace(out.GlobalProxy.URL)
	out.SSOConverter.Endpoint = strings.TrimRight(strings.TrimSpace(out.SSOConverter.Endpoint), "/")
	out.SSOConverter.APIKey = strings.TrimSpace(out.SSOConverter.APIKey)
	if out.SSOConverter.TimeoutSec <= 0 {
		out.SSOConverter.TimeoutSec = fallback.SSOConverter.TimeoutSec
	}
	if out.SSOConverter.MaxBatch <= 0 {
		out.SSOConverter.MaxBatch = fallback.SSOConverter.MaxBatch
	}
	if out.Inspection.IntervalSec <= 0 {
		out.Inspection.IntervalSec = fallback.Inspection.IntervalSec
	}
	if out.Inspection.TimeoutSec <= 0 {
		out.Inspection.TimeoutSec = fallback.Inspection.TimeoutSec
	}
	if out.Inspection.Concurrency <= 0 {
		out.Inspection.Concurrency = fallback.Inspection.Concurrency
	}
	if out.Inspection.ConfirmUnauthorized <= 0 {
		out.Inspection.ConfirmUnauthorized = fallback.Inspection.ConfirmUnauthorized
	}
	if out.Inspection.MassFailureMinimum <= 0 {
		out.Inspection.MassFailureMinimum = fallback.Inspection.MassFailureMinimum
	}
	if math.IsNaN(out.Inspection.MassFailureRatio) || math.IsInf(out.Inspection.MassFailureRatio, 0) ||
		out.Inspection.MassFailureRatio <= 0 || out.Inspection.MassFailureRatio > 1 {
		out.Inspection.MassFailureRatio = fallback.Inspection.MassFailureRatio
	}
	if out.Inspection.InitialDelaySec < 0 {
		out.Inspection.InitialDelaySec = fallback.Inspection.InitialDelaySec
	}
	if out.Inspection.SkipRecentSuccessSec < 0 {
		out.Inspection.SkipRecentSuccessSec = fallback.Inspection.SkipRecentSuccessSec
	}
	if out.Inspection.MaxPersistedRunResults <= 0 {
		out.Inspection.MaxPersistedRunResults = fallback.Inspection.MaxPersistedRunResults
	}
	if out.Inspection.MaxCredentialsPerRun <= 0 {
		out.Inspection.MaxCredentialsPerRun = fallback.Inspection.MaxCredentialsPerRun
	}
	return out
}

func (s RuntimeSettings) Validate() error {
	switch strings.ToLower(strings.TrimSpace(s.GlobalProxy.Mode)) {
	case "", "environment", "direct", "url":
	default:
		return fmt.Errorf("settings: global proxy mode must be environment, direct, or url")
	}
	if math.IsNaN(s.Inspection.MassFailureRatio) || math.IsInf(s.Inspection.MassFailureRatio, 0) ||
		s.Inspection.MassFailureRatio < 0 || s.Inspection.MassFailureRatio > 1 {
		return fmt.Errorf("settings: mass_failure_ratio must be between 0 and 1")
	}
	if s.SSOConverter.TimeoutSec <= 0 || s.SSOConverter.MaxBatch <= 0 {
		return fmt.Errorf("settings: sso converter timeout_sec/max_batch must be > 0")
	}
	if s.SSOConverter.TimeoutSec > MaxSSOConverterTimeoutSec {
		return fmt.Errorf("settings: sso converter timeout_sec must be <= %d", MaxSSOConverterTimeoutSec)
	}
	if s.SSOConverter.MaxBatch > MaxSSOConverterBatch {
		return fmt.Errorf("settings: sso converter max_batch must be <= %d", MaxSSOConverterBatch)
	}
	if s.Inspection.IntervalSec <= 0 || s.Inspection.TimeoutSec <= 0 ||
		s.Inspection.Concurrency <= 0 || s.Inspection.ConfirmUnauthorized <= 0 {
		return fmt.Errorf("settings: inspection interval/timeout/concurrency/confirm values must be > 0")
	}
	if s.Inspection.MassFailureMinimum <= 0 || s.Inspection.MassFailureRatio <= 0 {
		return fmt.Errorf("settings: inspection mass-failure values must be > 0")
	}
	if s.Inspection.MassFailureMinimum > s.Inspection.MaxCredentialsPerRun {
		return fmt.Errorf("settings: mass_failure_minimum must be <= max_credentials_per_run")
	}
	if s.Inspection.InitialDelaySec < 0 || s.Inspection.SkipRecentSuccessSec < 0 ||
		s.Inspection.MaxCredentialsPerRun <= 0 ||
		s.Inspection.MaxCredentialsPerRun > MaxInspectionCredentialsPerRun ||
		s.Inspection.MaxPersistedRunResults <= 0 {
		return fmt.Errorf("settings: inspection delay/result values are invalid")
	}
	if s.Inspection.PurgeAfterSec < 0 {
		return fmt.Errorf("settings: purge_after_sec must be >= 0")
	}
	if s.Inspection.IntervalSec > MaxInspectionIntervalSec ||
		s.Inspection.TimeoutSec > MaxInspectionTimeoutSec ||
		s.Inspection.PurgeAfterSec > MaxInspectionPurgeAfterSec ||
		s.Inspection.InitialDelaySec > MaxInspectionInitialDelaySec ||
		s.Inspection.SkipRecentSuccessSec > MaxInspectionSkipRecentSec {
		return fmt.Errorf("settings: inspection duration exceeds its safety limit")
	}
	return nil
}
