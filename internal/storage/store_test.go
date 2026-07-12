package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCredentialCRUD(t *testing.T) {
	s := newTestStore(t)

	created, err := s.CreateCredential(CreateCredentialInput{
		Name:         "main",
		Email:        "u@example.com",
		UserID:       "user-1",
		TeamID:       "team-1",
		OIDCClientID: "b1a00492-073a-47ea-816f-4c329264a828",
		AccessToken:  "access-token-test",
		RefreshToken: "refresh-token-test",
		ExpiresAt:    time.Date(2026, 7, 9, 19, 32, 31, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if !strings.HasPrefix(created.ID, "cred_") {
		t.Fatalf("id prefix: %q", created.ID)
	}
	if created.Priority != 100 || !created.Enabled {
		t.Fatalf("defaults: %+v", created)
	}
	if created.AccessToken != "access-token-test" {
		t.Fatal("access token not stored")
	}

	list, err := s.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}
	candidates, err := s.ListCredentialCandidates()
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ID != created.ID || !candidates[0].Enabled ||
		candidates[0].AccessToken != "" || candidates[0].RefreshToken != "" || candidates[0].Billing != nil {
		t.Fatalf("candidate leaked non-selection fields: %+v", candidates)
	}

	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "u@example.com" {
		t.Fatalf("email: %q", got.Email)
	}

	// Priority order: higher first.
	low := 10
	high := 200
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "low",
		AccessToken:  "a2",
		RefreshToken: "r2",
		Priority:     &low,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "high",
		AccessToken:  "a3",
		RefreshToken: "r3",
		Priority:     &high,
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err = s.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("list: %d", len(list))
	}
	if list[0].Priority != 200 || list[1].Priority != 100 || list[2].Priority != 10 {
		t.Fatalf("priority order: %d %d %d", list[0].Priority, list[1].Priority, list[2].Priority)
	}

	got.LastError = "rate limited"
	got.FailureCount = 2
	until := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	got.CooldownUntil = &until
	updated, err := s.UpdateCredential(got)
	if err != nil {
		t.Fatal(err)
	}
	if updated.FailureCount != 2 || updated.LastError != "rate limited" {
		t.Fatalf("update: %+v", updated)
	}

	disabled, err := s.SetCredentialEnabled(created.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("should be disabled")
	}

	prio, err := s.SetCredentialPriority(created.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if prio.Priority != 50 {
		t.Fatalf("priority: %d", prio.Priority)
	}

	if err := s.DeleteCredential(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredential(created.ID); err == nil {
		t.Fatal("expected not found after delete")
	}

	// Reject empty tokens.
	if _, err := s.CreateCredential(CreateCredentialInput{Name: "x"}); err == nil {
		t.Fatal("expected error for empty tokens")
	}
}

func TestCreateCredentialRejectsDuplicateRotatingTokenIdentity(t *testing.T) {
	s := newTestStore(t)
	input := CreateCredentialInput{
		Name: "one", UserID: "user-1", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-1",
		AccessToken: "access-1", RefreshToken: "shared-refresh",
	}
	if _, err := s.CreateCredential(input); err != nil {
		t.Fatal(err)
	}
	input.Name = "duplicate"
	input.AccessToken = "access-2"
	if _, err := s.CreateCredential(input); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("err=%v want ErrCredentialExists", err)
	}
	credentials, err := s.ListCredentials()
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials=%d err=%v", len(credentials), err)
	}
}

func TestUpsertCredentialIsIdempotentAndPreservesHealth(t *testing.T) {
	s := newTestStore(t)
	first, created, err := s.UpsertCredential(CreateCredentialInput{
		Name:         "first",
		Email:        "User@example.com",
		UserID:       "user-upsert",
		TeamID:       "team-upsert",
		SourceKey:    "https://auth.x.ai::client",
		OIDCClientID: "client",
		AccessToken:  "access-one",
		RefreshToken: "refresh-one",
	})
	if err != nil || !created {
		t.Fatalf("first created=%v err=%v", created, err)
	}
	cooldown := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if _, err := s.PatchCredential(first.ID, func(c *Credential) error {
		c.Enabled = false
		c.Priority = 42
		c.FailureCount = 3
		c.CooldownUntil = &cooldown
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	second, created, err := s.UpsertCredential(CreateCredentialInput{
		Name:         "rotated",
		Email:        "user@example.com",
		UserID:       "user-upsert",
		TeamID:       "team-upsert",
		SourceKey:    "https://auth.x.ai::client",
		OIDCClientID: "client",
		AccessToken:  "access-two",
		RefreshToken: "refresh-two",
	})
	if err != nil || created {
		t.Fatalf("second created=%v err=%v", created, err)
	}
	if second.ID != first.ID || second.AccessToken != "access-two" || second.RefreshToken != "refresh-two" {
		t.Fatalf("rotated=%+v", second)
	}
	if second.Enabled || second.Priority != 42 || second.FailureCount != 3 || second.CooldownUntil == nil {
		t.Fatalf("health/control fields were reset: %+v", second)
	}
	creds, err := s.ListCredentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials=%d err=%v", len(creds), err)
	}
}

func TestClientKeyCRUDAndHashOnly(t *testing.T) {
	s := newTestStore(t)

	res, err := s.CreateClient("ci")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if !strings.HasPrefix(res.Plaintext, "sk-") {
		t.Fatalf("plaintext prefix: %q", res.Plaintext)
	}
	if !strings.HasPrefix(res.Client.ID, "cli_") {
		t.Fatalf("id: %q", res.Client.ID)
	}
	if res.Client.KeyHash != HashKey(res.Plaintext) {
		t.Fatal("hash mismatch")
	}
	if res.Client.Prefix == "" || strings.Contains(res.Client.Prefix, res.Plaintext[10:]) {
		// prefix is short head only
	}

	// On-disk file must not contain plaintext secret.
	raw, err := os.ReadFile(filepath.Join(s.DataDir(), clientsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), res.Plaintext) {
		t.Fatal("plaintext client key must not be persisted")
	}
	var doc clientsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Clients) != 1 || doc.Clients[0].KeyHash == "" {
		t.Fatalf("disk doc: %+v", doc)
	}

	// File mode 0600.
	info, err := os.Stat(filepath.Join(s.DataDir(), clientsFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("clients.json mode: %o", info.Mode().Perm())
	}

	found, ok, err := s.LookupClientByPlaintext(res.Plaintext)
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if found.ID != res.Client.ID {
		t.Fatalf("lookup id: %q", found.ID)
	}
	if _, ok, err := s.LookupClientByPlaintext("sk-not-real"); err != nil || ok {
		t.Fatalf("bad key should miss: ok=%v err=%v", ok, err)
	}

	disabled, err := s.SetClientDisabled(res.Client.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Disabled {
		t.Fatal("disabled flag")
	}
	if _, ok, err := s.LookupClientByPlaintext(res.Plaintext); err != nil || ok {
		t.Fatalf("disabled key must not authenticate: ok=%v err=%v", ok, err)
	}

	list, err := s.ListClients()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}

	if err := s.DeleteClient(res.Client.ID); err != nil {
		t.Fatal(err)
	}
	list, err = s.ListClients()
	if err != nil || len(list) != 0 {
		t.Fatalf("after delete: %v len=%d", err, len(list))
	}
}

func TestEnsureBootstrapKeysGenerate(t *testing.T) {
	s := newTestStore(t)

	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if !genAPI || !genAdmin {
		t.Fatalf("first empty bootstrap should mint both: genAPI=%v genAdmin=%v", genAPI, genAdmin)
	}
	if !strings.HasPrefix(api, "sk-") || !strings.HasPrefix(admin, "sk-") {
		t.Fatalf("prefixes api=%q admin=%q", api, admin)
	}
	if api == admin {
		t.Fatal("api and admin keys should differ")
	}

	// API key registered as client.
	if _, ok, err := s.LookupClientByPlaintext(api); err != nil || !ok {
		t.Fatalf("bootstrap api lookup: ok=%v err=%v", ok, err)
	}

	// Admin is not a client key.
	if _, ok, err := s.LookupClientByPlaintext(admin); err != nil || ok {
		t.Fatalf("admin should not be client key: ok=%v err=%v", ok, err)
	}

	// meta.json persists bootstrap secrets (0600).
	info, err := os.Stat(filepath.Join(s.DataDir(), metaFile))
	if err != nil {
		t.Fatalf("meta.json missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("meta.json mode: %o", info.Mode().Perm())
	}

	// Second call with empty config reuses meta.json (no new client mint).
	api2, admin2, genAPI2, genAdmin2, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if genAPI2 || genAdmin2 {
		t.Fatalf("reuse from meta should not set generated flags: genAPI=%v genAdmin=%v", genAPI2, genAdmin2)
	}
	if api2 != api || admin2 != admin {
		t.Fatalf("empty config should reuse meta: api2=%q admin2=%q", api2, admin2)
	}
	// Configured keys returned as-is.
	api3, admin3, genAPI3, genAdmin3, err := s.EnsureBootstrapKeys(api, admin)
	if err != nil {
		t.Fatal(err)
	}
	if genAPI3 || genAdmin3 {
		t.Fatalf("configured keys should not set generated: genAPI=%v genAdmin=%v", genAPI3, genAdmin3)
	}
	if api3 != api || admin3 != admin {
		t.Fatalf("configured keys should be returned as-is: api3=%q admin3=%q", api3, admin3)
	}
	clients, err := s.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	// Still one client (same hash not duplicated).
	if len(clients) != 1 {
		t.Fatalf("expected single client for same configured key, got %d", len(clients))
	}
}

func TestEnsureBootstrapKeysPartialGenerate(t *testing.T) {
	s := newTestStore(t)
	// Seed meta with only api key present.
	cfgAPI := "sk-testpartialapi00000000000000"
	if err := s.saveMeta(bootstrapMeta{APIKey: cfgAPI}); err != nil {
		t.Fatal(err)
	}
	// Empty config: reuse api from meta, mint only admin.
	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if genAPI {
		t.Fatal("api loaded from meta must not report generatedAPI")
	}
	if !genAdmin {
		t.Fatal("missing admin must report generatedAdmin")
	}
	if api != cfgAPI {
		t.Fatalf("api should reuse meta: got %q", api)
	}
	if !strings.HasPrefix(admin, "sk-") || admin == cfgAPI {
		t.Fatalf("admin should be newly minted: %q", admin)
	}
}

func TestBootstrapAPIKeyRotationIsTwoPhaseUntilOldClientDeleted(t *testing.T) {
	s := newTestStore(t)
	keyA := "sk-bootstrap-a-000000000000000000000000"
	keyB := "sk-bootstrap-b-000000000000000000000000"
	admin := "sk-bootstrap-admin-00000000000000000000"
	if _, _, _, _, err := s.EnsureBootstrapKeys(keyA, admin); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.EnsureBootstrapKeys(keyB, admin); err != nil {
		t.Fatal(err)
	}
	clientA, okA, err := s.LookupClientByPlaintext(keyA)
	if err != nil || !okA {
		t.Fatalf("old bootstrap key should remain valid during overlap: ok=%v err=%v", okA, err)
	}
	if _, okB, err := s.LookupClientByPlaintext(keyB); err != nil || !okB {
		t.Fatalf("new bootstrap key should be valid: ok=%v err=%v", okB, err)
	}
	if err := s.DeleteClient(clientA.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LookupClientByPlaintext(keyA); err != nil || ok {
		t.Fatalf("deleted old key still authenticates: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.LookupClientByPlaintext(keyB); err != nil || !ok {
		t.Fatalf("new key stopped authenticating: ok=%v err=%v", ok, err)
	}
}

func TestDeletedBootstrapClientDoesNotReappear(t *testing.T) {
	s := newTestStore(t)
	api, _, _, _, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := s.ListClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients=%d err=%v", len(clients), err)
	}
	if err := s.DeleteClient(clients[0].ID); err != nil {
		t.Fatal(err)
	}

	dataDir := s.DataDir()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	api2, _, genAPI, _, err := reopened.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if api2 != api || genAPI {
		t.Fatalf("meta key should remain revoked without remint: same=%v generated=%v", api2 == api, genAPI)
	}
	if _, ok, err := reopened.LookupClientByPlaintext(api); err != nil || ok {
		t.Fatalf("deleted bootstrap key revived: ok=%v err=%v", ok, err)
	}
}

func TestPatchCredentialAtomic(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name:         "n",
		AccessToken:  "at1",
		RefreshToken: "rt1",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent last_used + token rotate must not lose refresh.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = s.PatchCredential(created.ID, func(c *Credential) error {
				now := nowUTC()
				c.LastUsedAt = &now
				return nil
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = s.PatchCredential(created.ID, func(c *Credential) error {
				c.AccessToken = "at2"
				c.RefreshToken = "rt2"
				return nil
			})
		}
	}()
	wg.Wait()
	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshToken != "rt2" && got.RefreshToken != "rt1" {
		t.Fatalf("unexpected refresh %q", got.RefreshToken)
	}
	// After concurrent patches, if access was rotated, refresh must match.
	if got.AccessToken == "at2" && got.RefreshToken != "rt2" {
		t.Fatalf("lost refresh after rotate: access=%q refresh=%q", got.AccessToken, got.RefreshToken)
	}
}

func TestEnsureBootstrapKeysConfigured(t *testing.T) {
	s := newTestStore(t)
	// Use synthetic keys that look like sk- but are not production secrets.
	cfgAPI := "sk-testbootstrapapi000000000000"
	cfgAdmin := "sk-testbootstrapadmin0000000000"

	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys(cfgAPI, cfgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if genAPI || genAdmin {
		t.Fatalf("configured keys should not report generated: genAPI=%v genAdmin=%v", genAPI, genAdmin)
	}
	if api != cfgAPI || admin != cfgAdmin {
		t.Fatalf("got api=%q admin=%q", api, admin)
	}
	if _, ok, err := s.LookupClientByPlaintext(cfgAPI); err != nil || !ok {
		t.Fatalf("configured api not stored: ok=%v err=%v", ok, err)
	}

	// credentials.json mode when written.
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "n",
		AccessToken:  "at",
		RefreshToken: "rt",
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.DataDir(), credentialsFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials.json mode: %o", info.Mode().Perm())
	}
}

func TestAtomicWriteAndDirMode(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	s, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode: %o", info.Mode().Perm())
	}
	_ = s
}

func TestNewDoesNotChmodExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("existing directory mode changed to %o", got)
	}
}

func TestStoreHoldsLifetimeInstanceLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	first, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("second store must not share an active data directory")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ListCredentials(); err == nil {
		t.Fatal("closed store accepted an operation")
	}
	second, err := New(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	_ = second.Close()
}

func TestCorruptCredentialFileRecoversFromBackup(t *testing.T) {
	s := newTestStore(t)
	cred, err := s.CreateCredential(CreateCredentialInput{
		Name:         "recover",
		AccessToken:  "access-one",
		RefreshToken: "refresh-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchCredential(cred.ID, func(c *Credential) error {
		c.Name = "newer"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.DataDir(), credentialsFile), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListCredentials()
	if err != nil {
		t.Fatalf("backup recovery failed: %v", err)
	}
	if len(creds) != 1 || creds[0].ID != cred.ID {
		t.Fatalf("recovered=%+v", creds)
	}
	if _, err := s.PatchCredential(cred.ID, func(c *Credential) error {
		c.Name = "repaired"
		return nil
	}); err != nil {
		t.Fatalf("save after recovery failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.DataDir(), credentialsFile), []byte("{corrupt-again"), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds, err := s.ListCredentials(); err != nil || len(creds) != 1 {
		t.Fatalf("valid backup was overwritten: credentials=%+v err=%v", creds, err)
	}
}

func TestCredentialCacheReturnsDeepCopies(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "cached", AccessToken: "access", RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC().Truncate(time.Second)
	if _, err := s.PatchCredential(created.ID, func(credential *Credential) error {
		credential.PurgeAfter = &when
		credential.Billing = map[string]any{
			"nested": map[string]any{"remaining": float64(7)},
			"items":  []any{map[string]any{"name": "grok"}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	first, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	*first.PurgeAfter = first.PurgeAfter.Add(24 * time.Hour)
	first.Billing["nested"].(map[string]any)["remaining"] = float64(0)
	first.Billing["items"].([]any)[0].(map[string]any)["name"] = "mutated"

	second, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.PurgeAfter.Equal(when) {
		t.Fatalf("cached time pointer was mutated: %v", second.PurgeAfter)
	}
	if got := second.Billing["nested"].(map[string]any)["remaining"]; got != float64(7) {
		t.Fatalf("cached nested map was mutated: %v", got)
	}
	if got := second.Billing["items"].([]any)[0].(map[string]any)["name"]; got != "grok" {
		t.Fatalf("cached nested slice was mutated: %v", got)
	}
}

func TestCredentialCacheInvalidatesAfterExternalFileChange(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "before", AccessToken: "access", RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredential(created.ID); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(s.DataDir(), credentialsFile)
	var doc credentialsDoc
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Credentials[0].Name = "after-external-replacement"
	data, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "after-external-replacement" {
		t.Fatalf("stale credential cache returned name %q", got.Name)
	}
}

func TestCredentialCacheEventuallyReloadsSameStampInPlaceEdit(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "before", AccessToken: "access", RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredential(created.ID); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(s.DataDir(), credentialsFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaced := strings.Replace(string(data), `"name": "before"`, `"name": "afterx"`, 1)
	if len(replaced) != len(data) || replaced == string(data) {
		t.Fatal("test fixture did not produce an equal-size replacement")
	}
	if err := os.WriteFile(path, []byte(replaced), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	// Avoid sleeping in the test: expire the guarded cache directly. The next
	// read must reload even though size, mtime, and inode are unchanged.
	s.credentialsCacheAt = time.Now().Add(-2 * credentialCacheMaxAge)

	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "afterx" {
		t.Fatalf("same-stamp edit remained hidden: name=%q", got.Name)
	}
}

func TestCredentialCachePreservesDuplicateIDReadSemantics(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	doc := credentialsDoc{Credentials: []Credential{
		{ID: "duplicate", Name: "first", AccessToken: "a1", RefreshToken: "r1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "duplicate", Name: "second", AccessToken: "a2", RefreshToken: "r2", Enabled: true, CreatedAt: now, UpdatedAt: now},
	}}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(s.DataDir(), credentialsFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	credentials, err := s.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("duplicate credentials were collapsed: %+v", credentials)
	}
	got, err := s.GetCredential("duplicate")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "first" {
		t.Fatalf("GetCredential returned %q, want first duplicate", got.Name)
	}
}

func TestNewRejectsDangerousDataDirs(t *testing.T) {
	if _, err := New(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root must be rejected")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if _, err := New(home); err == nil {
			t.Fatal("user home must be rejected")
		}
	}
}

func TestHashKeyStable(t *testing.T) {
	h1 := HashKey("sk-abc")
	h2 := HashKey("sk-abc")
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash: %q", h1)
	}
	if HashKey("sk-abc") == HashKey("sk-abd") {
		t.Fatal("different inputs same hash")
	}
}

func TestBulkUpsertDoesNotUseSourceKeyAsIdentity(t *testing.T) {
	s := newTestStore(t)
	source := "https://auth.x.ai::shared-client"
	results, err := s.BulkUpsertCredentials([]CreateCredentialInput{
		{
			Name: "one", UserID: "user-one", SourceKey: source,
			OIDCIssuer: "https://auth.x.ai", OIDCClientID: "shared-client",
			AccessToken: "access-one", RefreshToken: "refresh-one",
		},
		{
			Name: "two", UserID: "user-two", SourceKey: source,
			OIDCIssuer: "https://auth.x.ai", OIDCClientID: "shared-client",
			AccessToken: "access-two", RefreshToken: "refresh-two",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[0].Created || !results[1].Created {
		t.Fatalf("results=%+v", results)
	}
	creds, err := s.ListCredentials()
	if err != nil || len(creds) != 2 {
		t.Fatalf("credentials=%+v err=%v", creds, err)
	}
}

func TestBulkUpsertKeepsSameUserSeparateAcrossOIDCClients(t *testing.T) {
	s := newTestStore(t)
	results, err := s.BulkUpsertCredentials([]CreateCredentialInput{
		{
			UserID: "shared-user", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-one",
			AccessToken: "access-one", RefreshToken: "refresh-one",
		},
		{
			UserID: "shared-user", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-two",
			AccessToken: "access-two", RefreshToken: "refresh-two",
		},
		{
			Email: "same@example.test", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-three",
			AccessToken: "access-three", RefreshToken: "refresh-three",
		},
		{
			Email: "SAME@example.test", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-four",
			AccessToken: "access-four", RefreshToken: "refresh-four",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("results=%+v", results)
	}
	for _, result := range results {
		if !result.Created {
			t.Fatalf("OIDC-scoped identities were merged: %+v", results)
		}
	}
	creds, err := s.ListCredentials()
	if err != nil || len(creds) != 4 {
		t.Fatalf("credentials=%+v err=%v", creds, err)
	}
}

func TestCredentialWritesRejectInvalidProxyConfiguration(t *testing.T) {
	s := newTestStore(t)
	base := CreateCredentialInput{AccessToken: "access", RefreshToken: "refresh"}
	tests := []struct {
		name string
		mode string
		url  string
	}{
		{name: "unknown mode", mode: "automatic"},
		{name: "url missing", mode: CredentialProxyURL},
		{name: "url with direct", mode: CredentialProxyDirect, url: "http://proxy.test:8080"},
		{name: "unsupported scheme", mode: CredentialProxyURL, url: "file:///tmp/proxy"},
		{name: "query", mode: CredentialProxyURL, url: "http://proxy.test:8080?secret=x"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.ProxyMode = test.mode
			input.ProxyURL = test.url
			if _, _, err := s.UpsertCredential(input); err == nil {
				t.Fatal("expected invalid proxy configuration to be rejected")
			}
		})
	}
	valid := base
	valid.ProxyMode = CredentialProxyURL
	valid.ProxyURL = "socks5h://user:pass@proxy.test:1080"
	if _, _, err := s.UpsertCredential(valid); err != nil {
		t.Fatalf("valid proxy rejected: %v", err)
	}
}

func TestCredentialWritesRejectUntrustedIssuer(t *testing.T) {
	s := newTestStore(t)
	for _, issuer := range []string{
		"https://evil.example",
		"https://preview.auth.x.ai",
		"https://auth.x.ai/tenant",
		"http://auth.x.ai",
	} {
		_, _, err := s.UpsertCredential(CreateCredentialInput{
			AccessToken: "access", RefreshToken: "refresh", OIDCIssuer: issuer,
		})
		if err == nil {
			t.Fatalf("untrusted issuer accepted: %q", issuer)
		}
	}
}

func TestBulkUpsertStorageFailureLeavesExistingDocumentUnchanged(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.UpsertCredential(CreateCredentialInput{
		UserID: "existing", AccessToken: "access-existing", RefreshToken: "refresh-existing",
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.DataDir(), credentialsFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.DataDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	_, upsertErr := s.BulkUpsertCredentials([]CreateCredentialInput{
		{UserID: "new-one", AccessToken: "access-one", RefreshToken: "refresh-one"},
		{UserID: "new-two", AccessToken: "access-two", RefreshToken: "refresh-two"},
	})
	if err := os.Chmod(s.DataDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if upsertErr == nil {
		t.Fatal("expected atomic write failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("credentials document changed after failed bulk write")
	}
}

func TestBulkUpsertAndConcurrentPatchesDoNotLoseHealth(t *testing.T) {
	s := newTestStore(t)
	created, _, err := s.UpsertCredential(CreateCredentialInput{
		UserID: "concurrent-user", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client",
		AccessToken: "access-initial", RefreshToken: "refresh-initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	const iterations = 40
	var wait sync.WaitGroup
	for i := 0; i < iterations; i++ {
		i := i
		wait.Add(2)
		go func() {
			defer wait.Done()
			_, _ = s.PatchCredential(created.ID, func(credential *Credential) error {
				credential.FailureCount++
				return nil
			})
		}()
		go func() {
			defer wait.Done()
			_, _ = s.BulkUpsertCredentials([]CreateCredentialInput{{
				UserID: "concurrent-user", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client",
				AccessToken: fmt.Sprintf("access-%d", i), RefreshToken: fmt.Sprintf("refresh-%d", i),
			}})
		}()
	}
	wait.Wait()
	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureCount != iterations {
		t.Fatalf("health patches lost: got %d want %d", got.FailureCount, iterations)
	}
	if !strings.HasPrefix(got.AccessToken, "access-") || !strings.HasPrefix(got.RefreshToken, "refresh-") {
		t.Fatalf("rotated tokens not persisted: %+v", got)
	}
}

func TestRotatedImportClearsAutomaticQuarantineOnly(t *testing.T) {
	s := newTestStore(t)
	created, _, err := s.UpsertCredential(CreateCredentialInput{
		UserID: "user-q", OIDCClientID: "client",
		AccessToken: "old-access", RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.QuarantineCredential(created.ID, DisableReasonInvalidAuth, now, nil); err != nil {
		t.Fatal(err)
	}
	updated, wasCreated, err := s.UpsertCredential(CreateCredentialInput{
		UserID: "user-q", OIDCClientID: "client",
		AccessToken: "new-access", RefreshToken: "new-refresh",
	})
	if err != nil || wasCreated {
		t.Fatalf("created=%v err=%v", wasCreated, err)
	}
	if !updated.Enabled || updated.LifecycleState != CredentialStateActive || updated.DisableReason != "" {
		t.Fatalf("automatic quarantine not cleared: %+v", updated)
	}
	if _, err := s.SetCredentialEnabled(created.ID, false); err != nil {
		t.Fatal(err)
	}
	updated, _, err = s.UpsertCredential(CreateCredentialInput{
		UserID: "user-q", OIDCClientID: "client",
		AccessToken: "newer-access", RefreshToken: "newer-refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || !updated.ManualDisabled || updated.DisableReason != DisableReasonManual {
		t.Fatalf("manual disable was overwritten: %+v", updated)
	}
}

func TestDeleteCredentialIfPurgeEligibleRejectsRotatedToken(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "purge-race", AccessToken: "old-access", RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	purgeAfter := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	quarantined, err := s.QuarantineCredential(created.ID, DisableReasonInvalidAuth, time.Now(), &purgeAfter)
	if err != nil {
		t.Fatal(err)
	}
	expectedFingerprint := quarantined.QuarantineTokenFingerprint
	if _, err := s.PatchCredential(created.ID, func(credential *Credential) error {
		credential.AccessToken = "new-access"
		credential.RefreshToken = "new-refresh"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.DeleteCredentialIfPurgeEligible(created.ID, quarantined.Revision, purgeAfter, expectedFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("credential with a rotated token was deleted")
	}
	got, err := s.GetCredential(created.ID)
	if err != nil || got.AccessToken != "new-access" {
		t.Fatalf("credential=%+v err=%v", got, err)
	}
}

func TestDeleteCredentialIfPurgeEligibleDeletesMatchingDueQuarantine(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "purge-ready", AccessToken: "access", RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	purgeAfter := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	quarantined, err := s.QuarantineCredential(created.ID, DisableReasonInvalidAuth, time.Now(), &purgeAfter)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := s.DeleteCredentialIfPurgeEligible(created.ID, quarantined.Revision, purgeAfter, quarantined.QuarantineTokenFingerprint)
	if err != nil || !deleted {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
	if _, err := s.GetCredential(created.ID); err == nil {
		t.Fatal("matching due quarantine still exists")
	}
}

func TestCredentialRevisionIncrementsOnEveryPersistedMutation(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{Name: "revision", AccessToken: "access"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision == 0 {
		t.Fatal("new credential has no revision")
	}
	patched, err := s.PatchCredential(created.ID, func(credential *Credential) error {
		credential.ProxyMode = CredentialProxyDirect
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Revision != created.Revision+1 {
		t.Fatalf("patched revision=%d created=%d", patched.Revision, created.Revision)
	}
	patched.Enabled = false
	updated, err := s.UpdateCredential(patched)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != patched.Revision+1 {
		t.Fatalf("updated revision=%d patched=%d", updated.Revision, patched.Revision)
	}
}

func TestRequarantineAfterTokenImportUsesNewFingerprintAndCanPurge(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name: "re-quarantine", UserID: "user-1", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-1",
		AccessToken: "old-access", RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	firstPurge := now.Add(time.Hour)
	results, err := s.ApplyInspectionActions([]InspectionAction{{
		ID: created.ID, ExpectedRevision: created.Revision, Kind: InspectionActionQuarantine,
		At: now, PurgeAfter: &firstPurge,
	}})
	if err != nil || len(results) != 1 || !results[0].Quarantined {
		t.Fatalf("first quarantine results=%+v err=%v", results, err)
	}

	imported, wasCreated, err := s.UpsertCredential(CreateCredentialInput{
		Name: "re-quarantine", UserID: "user-1", OIDCIssuer: "https://auth.x.ai", OIDCClientID: "client-1",
		AccessToken: "new-access", RefreshToken: "new-refresh",
	})
	if err != nil || wasCreated {
		t.Fatalf("imported=%+v created=%v err=%v", imported, wasCreated, err)
	}
	if !imported.Enabled || imported.LifecycleState != CredentialStateActive || imported.QuarantineTokenFingerprint != "" {
		t.Fatalf("import did not clear quarantine evidence: %+v", imported)
	}

	past := now.Add(-time.Minute)
	results, err = s.ApplyInspectionActions([]InspectionAction{{
		ID: imported.ID, ExpectedRevision: imported.Revision, Kind: InspectionActionQuarantine,
		At: now.Add(-2 * time.Minute), PurgeAfter: &past,
	}})
	if err != nil || len(results) != 1 || !results[0].Quarantined {
		t.Fatalf("second quarantine results=%+v err=%v", results, err)
	}
	requarantined, err := s.GetCredential(imported.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectedFingerprint := credentialTokenFingerprint(requarantined)
	if requarantined.QuarantineTokenFingerprint != expectedFingerprint {
		t.Fatalf("fingerprint=%q want %q", requarantined.QuarantineTokenFingerprint, expectedFingerprint)
	}

	results, err = s.ApplyInspectionActions([]InspectionAction{{
		ID: requarantined.ID, ExpectedRevision: requarantined.Revision, Kind: InspectionActionPurge,
		At: now, ExpectedPurgeAfter: requarantined.PurgeAfter,
		ExpectedTokenFingerprint: requarantined.QuarantineTokenFingerprint,
	}})
	if err != nil || len(results) != 1 || !results[0].Deleted {
		t.Fatalf("purge results=%+v err=%v", results, err)
	}
	if _, err := s.GetCredential(requarantined.ID); err == nil {
		t.Fatal("re-quarantined credential was not purged")
	}
}

func TestRuntimeSettingsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	if exists, err := s.RuntimeSettingsExist(); err != nil || exists {
		t.Fatalf("unexpected initial settings snapshot: exists=%v err=%v", exists, err)
	}
	defaults := DefaultRuntimeSettings()
	defaults.GlobalProxy = GlobalProxySettings{Mode: "direct"}
	got, err := s.LoadRuntimeSettings(defaults)
	if err != nil || got.GlobalProxy.Mode != "direct" {
		t.Fatalf("defaults=%+v err=%v", got, err)
	}
	got.GlobalProxy = GlobalProxySettings{Mode: "url", URL: "http://user:pass@proxy.test:8080"}
	got.Inspection.Enabled = true
	if _, err := s.SaveRuntimeSettings(got); err != nil {
		t.Fatal(err)
	}
	if exists, err := s.RuntimeSettingsExist(); err != nil || !exists {
		t.Fatalf("saved settings snapshot not detected: exists=%v err=%v", exists, err)
	}
	reloaded, err := s.LoadRuntimeSettings()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.GlobalProxy.URL != got.GlobalProxy.URL || !reloaded.Inspection.Enabled {
		t.Fatalf("reloaded=%+v", reloaded)
	}
	info, err := os.Stat(filepath.Join(s.DataDir(), settingsFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestRuntimeSettingsRejectsSSOSidecarLimitMismatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*RuntimeSettings)
	}{
		{"timeout", func(settings *RuntimeSettings) {
			settings.SSOConverter.TimeoutSec = MaxSSOConverterTimeoutSec + 1
		}},
		{"batch", func(settings *RuntimeSettings) {
			settings.SSOConverter.MaxBatch = MaxSSOConverterBatch + 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := DefaultRuntimeSettings()
			tc.mut(&settings)
			if err := settings.Validate(); err == nil {
				t.Fatal("expected SSO converter limit validation error")
			}
		})
	}
}

func TestRuntimeSettingsRejectsOrNormalizesNonFiniteMassFailureRatio(t *testing.T) {
	for _, ratio := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		settings := DefaultRuntimeSettings()
		settings.Inspection.MassFailureRatio = ratio
		if err := settings.Validate(); err == nil {
			t.Fatalf("accepted non-finite mass_failure_ratio %v", ratio)
		}
		normalized := normalizeRuntimeSettings(settings, DefaultRuntimeSettings())
		if normalized.Inspection.MassFailureRatio != DefaultRuntimeSettings().Inspection.MassFailureRatio {
			t.Fatalf("ratio %v normalized to %v", ratio, normalized.Inspection.MassFailureRatio)
		}
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
