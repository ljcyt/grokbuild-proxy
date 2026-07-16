// Command export-sub2api-grok exports currently usable Grok OAuth accounts to
// Sub2API's batch-create JSON shape. It never writes credentials to stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type credentialFile struct {
	Credentials []credential `json:"credentials"`
}
type credential struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Email                string     `json:"email"`
	AccessToken          string     `json:"access_token"`
	RefreshToken         string     `json:"refresh_token"`
	ExpiresAt            time.Time  `json:"expires_at"`
	Enabled              bool       `json:"enabled"`
	ManualDisabled       bool       `json:"manual_disabled"`
	LifecycleState       string     `json:"lifecycle_state"`
	DisableReason        string     `json:"disable_reason"`
	Priority             int        `json:"priority"`
	CooldownUntil        *time.Time `json:"cooldown_until"`
	LastError            string     `json:"last_error"`
	LastInspectionStatus string     `json:"last_inspection_status"`
	RemainingRequests    *int64     `json:"rate_limit_remaining_requests"`
	RemainingTokens      *int64     `json:"rate_limit_remaining_tokens"`
}
type account struct {
	Name        string         `json:"name"`
	Platform    string         `json:"platform"`
	Type        string         `json:"type"`
	Credentials map[string]any `json:"credentials"`
	Priority    int            `json:"priority"`
	Concurrency int            `json:"concurrency"`
}

func main() {
	input := flag.String("input", "data/credentials.json", "source credentials.json")
	output := flag.String("output", "sub2api-grok-accounts.json", "sensitive Sub2API batch-create JSON")
	includeUnknown := flag.Bool("include-unknown", false, "include accounts without recorded rate-limit remaining values")
	flag.Parse()
	raw, err := os.ReadFile(*input)
	if err != nil {
		fail(err)
	}
	var source credentialFile
	if err := json.Unmarshal(raw, &source); err != nil {
		fail(fmt.Errorf("read credentials: %w", err))
	}
	now := time.Now()
	accounts := make([]account, 0)
	for _, c := range source.Credentials {
		if !eligible(c, now, *includeUnknown) {
			continue
		}
		name := strings.TrimSpace(c.Name)
		if name == "" {
			name = c.ID
		}
		credentials := map[string]any{"access_token": c.AccessToken, "refresh_token": c.RefreshToken, "token_type": "Bearer", "base_url": "https://cli-chat-proxy.grok.com/v1"}
		if !c.ExpiresAt.IsZero() {
			credentials["expires_at"] = c.ExpiresAt.Unix()
		}
		if strings.TrimSpace(c.Email) != "" {
			credentials["email"] = c.Email
		}
		accounts = append(accounts, account{Name: name, Platform: "grok", Type: "oauth", Credentials: credentials, Priority: c.Priority, Concurrency: 1})
	}
	payload, err := json.MarshalIndent(map[string]any{"exported_at": now.UTC().Format(time.RFC3339), "accounts": accounts}, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0700); err != nil && filepath.Dir(*output) != "." {
		fail(err)
	}
	if err := os.WriteFile(*output, append(payload, '\n'), 0600); err != nil {
		fail(err)
	}
	fmt.Printf("exported %d eligible accounts to %s\n", len(accounts), *output)
}
func eligible(c credential, now time.Time, includeUnknown bool) bool {
	if !c.Enabled || c.ManualDisabled || c.LifecycleState == "quarantined" || strings.TrimSpace(c.AccessToken) == "" || strings.TrimSpace(c.RefreshToken) == "" {
		return false
	}
	if c.CooldownUntil != nil && c.CooldownUntil.After(now) {
		return false
	}
	if c.LastError == "quota_exhausted" || c.LastInspectionStatus == "quota_exhausted" || c.LastInspectionStatus == "rate_limited" {
		return false
	}
	known := false
	if c.RemainingRequests != nil {
		known = true
		if *c.RemainingRequests <= 0 {
			return false
		}
	}
	if c.RemainingTokens != nil {
		known = true
		if *c.RemainingTokens <= 0 {
			return false
		}
	}
	return known || includeUnknown
}
func fail(err error) { fmt.Fprintln(os.Stderr, "export failed:", err); os.Exit(1) }
