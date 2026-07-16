package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

func exportInt64Ptr(v int64) *int64 { return &v }

func TestExportSub2APIGrokExportsOnlyKnownAvailableQuota(t *testing.T) {
	now := time.Now().UTC()
	store := newFakeStore()
	store.creds["eligible"] = storage.Credential{
		ID: "eligible", Name: "usable", Enabled: true, Priority: 100,
		AccessToken: "access-eligible", RefreshToken: "refresh-eligible", ExpiresAt: now.Add(time.Hour),
		RateLimitRemainingRequests: exportInt64Ptr(3), RateLimitRemainingTokens: exportInt64Ptr(500),
	}
	store.creds["exhausted"] = storage.Credential{
		ID: "exhausted", Enabled: true, AccessToken: "access-exhausted", RefreshToken: "refresh-exhausted",
		RateLimitRemainingRequests: exportInt64Ptr(0), RateLimitRemainingTokens: exportInt64Ptr(500),
	}
	store.creds["unknown"] = storage.Credential{
		ID: "unknown", Enabled: true, AccessToken: "access-unknown", RefreshToken: "refresh-unknown",
	}
	store.creds["quarantined"] = storage.Credential{
		ID: "quarantined", Enabled: true, LifecycleState: storage.CredentialStateQuarantined,
		AccessToken: "access-quarantined", RefreshToken: "refresh-quarantined",
		RateLimitRemainingRequests: exportInt64Ptr(3), RateLimitRemainingTokens: exportInt64Ptr(500),
	}

	h := &Handlers{Store: store, AdminKey: "admin-export-key"}
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/export-sub2api", nil)
	req.Header.Set("X-Admin-Key", "admin-export-key")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}
	var response sub2APIExport
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Accounts) != 1 {
		t.Fatalf("accounts=%d", len(response.Accounts))
	}
	account := response.Accounts[0]
	if account.Name != "usable" || account.Platform != "grok" || account.Type != "oauth" ||
		account.Credentials.AccessToken != "access-eligible" || account.Credentials.RefreshToken != "refresh-eligible" ||
		account.Credentials.BaseURL != "https://cli-chat-proxy.grok.com/v1" || account.Concurrency != 1 {
		t.Fatalf("unexpected export account: %+v", account)
	}
}

func TestExportSub2APIGrokRequiresAdminKey(t *testing.T) {
	h := &Handlers{Store: newFakeStore(), AdminKey: "admin-export-key"}
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/credentials/export-sub2api", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
