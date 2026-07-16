package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

// sub2APIExport is the account batch-create shape accepted by Sub2API for
// Grok OAuth accounts. This response deliberately includes OAuth secrets and
// must only be served through RequireAdmin.
type sub2APIExport struct {
	ExportedAt time.Time        `json:"exported_at"`
	Accounts   []sub2APIAccount `json:"accounts"`
}

type sub2APIAccount struct {
	Name        string                 `json:"name"`
	Platform    string                 `json:"platform"`
	Type        string                 `json:"type"`
	Credentials sub2APIGrokCredentials `json:"credentials"`
	Priority    int                    `json:"priority"`
	Concurrency int                    `json:"concurrency"`
}

type sub2APIGrokCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"`
	BaseURL      string `json:"base_url"`
}

// ExportSub2APIGrok POST /admin/credentials/export-sub2api exports only
// credentials with known, positive remaining quota. It is intentionally a
// POST endpoint so a browser navigation or prefetch cannot disclose tokens.
func (h *Handlers) ExportSub2APIGrok(w http.ResponseWriter, r *http.Request) {
	credentials, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	now := time.Now().UTC()
	accounts := make([]sub2APIAccount, 0, len(credentials))
	for _, credential := range credentials {
		if !eligibleForSub2APIExport(credential, now) {
			continue
		}
		name := strings.TrimSpace(credential.Name)
		if name == "" {
			name = credential.ID
		}
		expiresAt := int64(0)
		if !credential.ExpiresAt.IsZero() {
			expiresAt = credential.ExpiresAt.Unix()
		}
		accounts = append(accounts, sub2APIAccount{
			Name:     name,
			Platform: "grok",
			Type:     "oauth",
			Credentials: sub2APIGrokCredentials{
				AccessToken:  credential.AccessToken,
				RefreshToken: credential.RefreshToken,
				TokenType:    "Bearer",
				ExpiresAt:    expiresAt,
				BaseURL:      "https://cli-chat-proxy.grok.com/v1",
			},
			Priority:    credential.Priority,
			Concurrency: 1,
		})
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sub2api-grok-eligible.json"`)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, sub2APIExport{ExportedAt: now, Accounts: accounts})
}

func eligibleForSub2APIExport(credential storage.Credential, now time.Time) bool {
	if !credential.Enabled || credential.ManualDisabled ||
		credential.LifecycleState == storage.CredentialStateQuarantined ||
		strings.TrimSpace(credential.AccessToken) == "" ||
		strings.TrimSpace(credential.RefreshToken) == "" {
		return false
	}
	if credential.CooldownUntil != nil && credential.CooldownUntil.After(now) {
		return false
	}
	if credential.LastError == "quota_exhausted" ||
		credential.LastInspectionStatus == "quota_exhausted" ||
		credential.LastInspectionStatus == "rate_limited" {
		return false
	}
	knownQuota := false
	if credential.RateLimitRemainingRequests != nil {
		knownQuota = true
		if *credential.RateLimitRemainingRequests <= 0 {
			return false
		}
	}
	if credential.RateLimitRemainingTokens != nil {
		knownQuota = true
		if *credential.RateLimitRemainingTokens <= 0 {
			return false
		}
	}
	return knownQuota
}
