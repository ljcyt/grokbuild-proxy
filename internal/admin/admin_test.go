package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/importer"
	"github.com/GreyGunG/grokbuild-proxy/internal/outbound"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type fixedProxyResolver struct{ resolved outbound.ResolvedProxy }

func (r fixedProxyResolver) Resolve(*storage.Credential) (outbound.ResolvedProxy, error) {
	return r.resolved, nil
}

type recordingTokenInvalidator struct {
	mu   sync.Mutex
	keys []string
}

func (r *recordingTokenInvalidator) Invalidate(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
}

func (r *recordingTokenInvalidator) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

func TestManualCredentialDeleteInvalidatesRefreshBeforeAndAfter(t *testing.T) {
	store := newFakeStore()
	store.creds["delete-me"] = storage.Credential{ID: "delete-me", Enabled: true}
	invalidator := &recordingTokenInvalidator{}
	h := &Handlers{Store: store, TokenCache: invalidator}
	recorder := httptest.NewRecorder()
	h.DeleteCredential(recorder, httptest.NewRequest(http.MethodDelete, "/", nil), "delete-me")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := invalidator.snapshot(); len(got) != 2 || got[0] != "delete-me" || got[1] != "delete-me" {
		t.Fatalf("invalidations=%v", got)
	}
}

func TestExplicitCredentialEnableInvalidatesRefreshBeforeAndAfter(t *testing.T) {
	store := newFakeStore()
	store.creds["enable-me"] = storage.Credential{ID: "enable-me", Enabled: false}
	invalidator := &recordingTokenInvalidator{}
	h := &Handlers{Store: store, TokenCache: invalidator}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	h.DisableCredential(recorder, req, "enable-me")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := invalidator.snapshot(); len(got) != 2 || got[0] != "enable-me" || got[1] != "enable-me" {
		t.Fatalf("invalidations=%v", got)
	}
}

func TestCreateCredentialReturnsConflictForDuplicateIdentity(t *testing.T) {
	store := newFakeStore()
	store.createErr = fmt.Errorf("%w: cred-existing", storage.ErrCredentialExists)
	h := &Handlers{Store: store}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials", strings.NewReader(`{"refresh_token":"duplicate"}`))
	req.Header.Set("Content-Type", "application/json")
	h.CreateCredential(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestMalformedDisableBodyDoesNotToggleCredential(t *testing.T) {
	store := newFakeStore()
	store.creds["cred"] = storage.Credential{ID: "cred", Enabled: false, ManualDisabled: true}
	h := &Handlers{Store: store}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/cred/disable", strings.NewReader(`{"enabled":`))
	h.DisableCredential(recorder, req, "cred")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	credential, _ := store.GetCredential("cred")
	if credential.Enabled {
		t.Fatalf("malformed body toggled credential: %+v", credential)
	}
}

func TestMalformedCreateClientBodyDoesNotCreateKey(t *testing.T) {
	store := newFakeStore()
	h := &Handlers{Store: store}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(`{"name":`))
	h.CreateClient(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	clients, err := store.ListClients()
	if err != nil || len(clients) != 0 {
		t.Fatalf("clients=%d err=%v", len(clients), err)
	}
}

func TestMaskedCredentialIncludesEffectiveRedactedProxy(t *testing.T) {
	h := &Handlers{ProxyResolver: fixedProxyResolver{resolved: outbound.ResolvedProxy{Mode: outbound.ModeURL, Source: "runtime", URL: "http://user:secret@proxy.test:8080"}}}
	view := h.maskedCredential(storage.Credential{ProxyMode: outbound.ModeInherit})
	if view.EffectiveProxy["mode"] != outbound.ModeURL || view.EffectiveProxy["source"] != "runtime" {
		t.Fatalf("proxy=%v", view.EffectiveProxy)
	}
	url, _ := view.EffectiveProxy["url"].(string)
	if strings.Contains(url, "secret") || !strings.Contains(url, "redacted") {
		t.Fatalf("url=%q", url)
	}
}

type fakeStore struct {
	mu        sync.Mutex
	creds     map[string]storage.Credential
	cli       map[string]storage.ClientKey
	createErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		creds: map[string]storage.Credential{},
		cli:   map[string]storage.ClientKey{},
	}
}

func (f *fakeStore) ListCredentials() ([]storage.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]storage.Credential, 0, len(f.creds))
	for _, c := range f.creds {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeStore) GetCredential(id string) (storage.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.creds[id]
	if !ok {
		return storage.Credential{}, errNF("credential", id)
	}
	return c, nil
}

func (f *fakeStore) CreateCredential(in storage.CreateCredentialInput) (storage.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return storage.Credential{}, f.createErr
	}
	id := "cred_test1"
	now := time.Now().UTC().Truncate(time.Second)
	en := true
	if in.Enabled != nil {
		en = *in.Enabled
	}
	pr := 100
	if in.Priority != nil {
		pr = *in.Priority
	}
	c := storage.Credential{
		ID:           id,
		Name:         in.Name,
		Email:        in.Email,
		AccessToken:  in.AccessToken,
		RefreshToken: in.RefreshToken,
		ExpiresAt:    in.ExpiresAt,
		Enabled:      en,
		Priority:     pr,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	f.creds[id] = c
	return c, nil
}

func (f *fakeStore) UpdateCredential(c storage.Credential) (storage.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.creds[c.ID]; !ok {
		return storage.Credential{}, errNF("credential", c.ID)
	}
	f.creds[c.ID] = c
	return c, nil
}

func (f *fakeStore) DeleteCredential(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.creds[id]; !ok {
		return errNF("credential", id)
	}
	delete(f.creds, id)
	return nil
}

func (f *fakeStore) SetCredentialEnabled(id string, enabled bool) (storage.Credential, error) {
	c, err := f.GetCredential(id)
	if err != nil {
		return storage.Credential{}, err
	}
	c.Enabled = enabled
	return f.UpdateCredential(c)
}

func (f *fakeStore) SetCredentialPriority(id string, priority int) (storage.Credential, error) {
	c, err := f.GetCredential(id)
	if err != nil {
		return storage.Credential{}, err
	}
	c.Priority = priority
	return f.UpdateCredential(c)
}

func (f *fakeStore) PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error) {
	c, err := f.GetCredential(id)
	if err != nil {
		return storage.Credential{}, err
	}
	if err := mutate(&c); err != nil {
		return storage.Credential{}, err
	}
	return f.UpdateCredential(c)
}

func (f *fakeStore) ListClients() ([]storage.ClientKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]storage.ClientKey, 0, len(f.cli))
	for _, c := range f.cli {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeStore) CreateClient(name string) (storage.CreateClientResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ck := storage.ClientKey{
		ID:        "cli_1",
		Name:      name,
		KeyHash:   "abc",
		Prefix:    "sk-test",
		CreatedAt: time.Now().UTC(),
	}
	f.cli[ck.ID] = ck
	return storage.CreateClientResult{Client: ck, Plaintext: "sk-test-plaintext-once"}, nil
}

func (f *fakeStore) DeleteClient(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cli[id]; !ok {
		return errNF("client", id)
	}
	delete(f.cli, id)
	return nil
}

type nfErr struct{ kind, id string }

func (e nfErr) Error() string { return "storage: " + e.kind + " " + e.id + " not found" }

func errNF(kind, id string) error { return nfErr{kind, id} }

func TestAdminCredentialsMasked(t *testing.T) {
	store := newFakeStore()
	store.creds["cred_x"] = storage.Credential{
		ID:           "cred_x",
		Name:         "n",
		AccessToken:  "super-secret-access-token-value",
		RefreshToken: "super-secret-refresh-token-value",
		Enabled:      true,
		Priority:     10,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	h := &Handlers{
		Store:    store,
		AdminKey: "sk-admin-test",
		Config:   config.Default(),
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/credentials", nil)
	req.Header.Set("Authorization", "Bearer sk-admin-test")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "super-secret-access-token-value") {
		t.Fatalf("access token leaked: %s", body)
	}
	if strings.Contains(body, "super-secret-refresh-token-value") {
		t.Fatalf("refresh token leaked: %s", body)
	}
	if !strings.Contains(body, "***") {
		t.Fatalf("expected masked tokens, body=%s", body)
	}

	var parsed struct {
		Credentials []map[string]any `json:"credentials"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Credentials) != 1 {
		t.Fatalf("len=%d", len(parsed.Credentials))
	}
	at, _ := parsed.Credentials[0]["access_token"].(string)
	if at == "super-secret-access-token-value" || !strings.Contains(at, "***") {
		t.Fatalf("access_token not masked: %q", at)
	}
}

func TestAdminCredentialsPaginationAndFiltering(t *testing.T) {
	store := newFakeStore()
	now := time.Now().UTC()
	cooldown := now.Add(time.Hour)
	store.creds["alpha-one"] = storage.Credential{ID: "alpha-one", Name: "Alpha One", AccessToken: "access-a", Enabled: true}
	store.creds["alpha-two"] = storage.Credential{ID: "alpha-two", Email: "alpha@example.test", AccessToken: "access-b", Enabled: true}
	store.creds["beta-cooling"] = storage.Credential{ID: "beta-cooling", AccessToken: "access-c", Enabled: true, CooldownUntil: &cooldown}
	store.creds["gamma-disabled"] = storage.Credential{ID: "gamma-disabled", Enabled: false}
	store.creds["delta"] = storage.Credential{ID: "delta", AccessToken: "access-d", Enabled: true}
	inspectedAt := now.Add(-time.Minute)
	store.creds["health"] = storage.Credential{ID: "health", AccessToken: "access-e", Enabled: true, LastInspectionAt: &inspectedAt, LastInspectionStatus: "healthy"}
	store.creds["quota"] = storage.Credential{ID: "quota", AccessToken: "access-f", Enabled: true, LastError: "quota_exhausted"}
	store.creds["invalid"] = storage.Credential{ID: "invalid", Enabled: false, LifecycleState: storage.CredentialStateQuarantined, DisableReason: storage.DisableReasonInvalidAuth, LastInspectionAt: &inspectedAt, LastInspectionStatus: "unauthorized"}
	h := &Handlers{Store: store, AdminKey: "sk-admin-test", Config: config.Default()}

	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer sk-admin-test")
		rr := httptest.NewRecorder()
		h.Handler().ServeHTTP(rr, req)
		return rr
	}

	var page struct {
		Credentials []map[string]any     `json:"credentials"`
		Pool        poolSummary          `json:"pool"`
		Pagination  credentialPagination `json:"pagination"`
	}
	rr := request("/admin/credentials?page=2&page_size=2")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Credentials) != 2 || page.Pagination.Page != 2 ||
		page.Pagination.PageSize != 2 || page.Pagination.Total != 8 || page.Pagination.TotalPages != 4 {
		t.Fatalf("unexpected page: %+v credentials=%d", page.Pagination, len(page.Credentials))
	}
	if page.Pool.Total != 8 || page.Pool.Available != 5 || page.Pool.Cooling != 1 || page.Pool.Disabled != 2 {
		t.Fatalf("unexpected pool: %+v", page.Pool)
	}

	rr = request("/admin/credentials?q=alpha&status=available")
	if rr.Code != http.StatusOK {
		t.Fatalf("filter status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Credentials) != 2 || page.Pagination.Total != 2 {
		t.Fatalf("unexpected filtered page: %+v credentials=%d", page.Pagination, len(page.Credentials))
	}

	for _, tc := range []struct {
		status string
		id     string
	}{
		{status: "healthy", id: "health"},
		{status: "quota_exhausted", id: "quota"},
		{status: "unauthorized", id: "invalid"},
		{status: "quarantined", id: "invalid"},
		{status: "uninspected", id: "alpha-one"},
	} {
		rr = request("/admin/credentials?status=" + tc.status)
		if rr.Code != http.StatusOK {
			t.Fatalf("status filter %s: code=%d body=%s", tc.status, rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, credential := range page.Credentials {
			if credential["id"] == tc.id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("status filter %s missing %s: %+v", tc.status, tc.id, page.Credentials)
		}
	}

	rr = request("/admin/credentials?status=unknown")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminRejectsBadKey(t *testing.T) {
	h := &Handlers{Store: newFakeStore(), AdminKey: "sk-admin-test", Config: config.Default()}
	req := httptest.NewRequest(http.MethodGet, "/admin/system", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMaskSecret(t *testing.T) {
	if maskSecret("") != "" {
		t.Fatal("empty")
	}
	if maskSecret("short") != "***" {
		t.Fatal("short")
	}
	// Medium secrets fully redacted (no fingerprint).
	if maskSecret("abcdefghijklmnop") != "***" {
		t.Fatalf("medium should be fully redacted, got %q", maskSecret("abcdefghijklmnop"))
	}
	long := "abcdefghijklmnopqrstuvwxyz012345"
	m := maskSecret(long)
	if m == long || !strings.Contains(m, "***") || len(m) >= len(long) {
		t.Fatalf("mask=%q", m)
	}
}

func TestValidateConverterEndpointRejectsPublicInsecureHTTP(t *testing.T) {
	if _, err := validateConverterEndpoint("http://sso-import:8090", true); err != nil {
		t.Fatalf("Compose-internal endpoint rejected: %v", err)
	}
	if _, err := validateConverterEndpoint("http://converter.example.com:8090", true); err == nil {
		t.Fatal("public insecure endpoint must be rejected")
	}
}

func TestImportGrokIsIdempotent(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	imports, err := importer.NewManager(store, nil, importer.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Store: store, Imports: imports, Config: config.Default()}
	body := `{"raw":{
		"https://auth.x.ai::client-test":{
			"key":"access-one",
			"refresh_token":"refresh-one",
			"user_id":"user-import",
			"email":"import@example.com",
			"oidc_client_id":"client-test"
		}
	}}`
	run := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/credentials/import-grok", strings.NewReader(body))
		rr := httptest.NewRecorder()
		h.ImportGrok(rr, req)
		return rr
	}
	first := run()
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := run()
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	creds, err := store.ListCredentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials=%d err=%v", len(creds), err)
	}
	var response map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["updated"] != float64(1) || response["created"] != float64(0) {
		t.Fatalf("response=%v", response)
	}
}

func TestImportGrokUsesImporterQueueAndCompatibilityResponse(t *testing.T) {
	imports := &fakeImportJobs{job: importer.Job{ID: "legacy", Status: importer.StatusCompleted, Created: 1}}
	imports.job.Results = []importer.ItemResult{{
		Source: "file-1/entry-1", Status: "created", CredentialID: "credential-one",
	}}
	store := newFakeStore()
	store.creds["credential-one"] = storage.Credential{ID: "credential-one", Name: "imported", Enabled: true}
	h := &Handlers{Store: store, Imports: imports, Config: config.Default()}
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/import-grok", strings.NewReader(`{"raw":{"key":"access","refresh_token":"refresh"}}`))
	rr := httptest.NewRecorder()
	h.ImportGrok(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(imports.files) != 1 || imports.files[0].Format != importer.FormatJSON {
		t.Fatalf("legacy route bypassed importer: %+v", imports.files)
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["imported"] != float64(1) || response["created"] != float64(1) || response["job_id"] != "legacy" {
		t.Fatalf("response=%v", response)
	}
}

func TestImportGrokQueueOverloadReturns429(t *testing.T) {
	imports := &fakeImportJobs{err: fmt.Errorf("%w: retry later", importer.ErrOverloaded)}
	h := &Handlers{Store: newFakeStore(), Imports: imports, Config: config.Default()}
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/import-grok", strings.NewReader(`{"raw":{"key":"access"}}`))
	rr := httptest.NewRecorder()
	h.ImportGrok(rr, req)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
}

func TestImportGrokEnforcesManagerEntryLimit(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	imports, err := importer.NewManager(store, nil, importer.Limits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Store: store, Imports: imports, Config: config.Default()}
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/import-grok", strings.NewReader(`{
		"raw":[
			{"key":"access-one","user_id":"one"},
			{"key":"access-two","user_id":"two"}
		]
	}`))
	rr := httptest.NewRecorder()
	h.ImportGrok(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "entry limit exceeded") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	credentials, err := store.ListCredentials()
	if err != nil || len(credentials) != 0 {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
}

func TestImportGrokCancellationReturnsAsyncJobLocation(t *testing.T) {
	imports := &fakeImportJobs{}
	h := &Handlers{Store: newFakeStore(), Imports: imports, Config: config.Default()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/admin/credentials/import-grok", strings.NewReader(`{"raw":{"key":"access"}}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	h.ImportGrok(rr, req)
	if rr.Code != http.StatusAccepted || rr.Header().Get("Location") != "/admin/import-jobs/import_test" {
		t.Fatalf("status=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
}

type fakeImportJobs struct {
	files []importer.InputFile
	job   importer.Job
	err   error
}

func (f *fakeImportJobs) Start(files []importer.InputFile) (importer.Job, error) {
	f.files = append([]importer.InputFile(nil), files...)
	if f.err != nil {
		return importer.Job{}, f.err
	}
	if f.job.ID == "" {
		f.job = importer.Job{ID: "import_test", Status: importer.StatusQueued}
	}
	return f.job, nil
}

func TestCredentialImportQueueOverloadReturns429(t *testing.T) {
	imports := &fakeImportJobs{err: fmt.Errorf("%w: retry later", importer.ErrOverloaded)}
	h := &Handlers{Store: newFakeStore(), Imports: imports, AdminKey: "sk-admin-import-test", Config: config.Default()}
	req := httptest.NewRequest(http.MethodPost, "/admin/credential-imports", strings.NewReader(`{"name":"pasted.txt","text":"sso-value"}`))
	req.Header.Set("Authorization", "Bearer sk-admin-import-test")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
}

func (f *fakeImportJobs) Get(id string) (importer.Job, bool) {
	if id != f.job.ID {
		return importer.Job{}, false
	}
	return f.job, true
}

func TestCredentialImportRouteAliases(t *testing.T) {
	for _, collectionPath := range []string{"/admin/import-jobs", "/admin/credential-imports"} {
		t.Run(collectionPath, func(t *testing.T) {
			imports := &fakeImportJobs{}
			h := &Handlers{
				Store:    newFakeStore(),
				Imports:  imports,
				AdminKey: "sk-admin-import-test",
				Config:   config.Default(),
			}
			handler := h.Handler()

			req := httptest.NewRequest(http.MethodPost, collectionPath, strings.NewReader(`{
				"name":"pasted.txt","format":"sso","text":"sso-value"
			}`))
			req.Header.Set("Authorization", "Bearer sk-admin-import-test")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusAccepted {
				t.Fatalf("POST status=%d body=%s", rr.Code, rr.Body.String())
			}
			location := collectionPath + "/import_test"
			if rr.Header().Get("Location") != location {
				t.Fatalf("Location=%q want=%q", rr.Header().Get("Location"), location)
			}
			if len(imports.files) != 1 || imports.files[0].Name != "pasted.txt" ||
				imports.files[0].Format != importer.FormatSSO || string(imports.files[0].Data) != "sso-value" {
				t.Fatalf("files=%+v", imports.files)
			}

			getReq := httptest.NewRequest(http.MethodGet, location, nil)
			getReq.Header.Set("Authorization", "Bearer sk-admin-import-test")
			getRR := httptest.NewRecorder()
			handler.ServeHTTP(getRR, getReq)
			if getRR.Code != http.StatusOK {
				t.Fatalf("GET status=%d body=%s", getRR.Code, getRR.Body.String())
			}
		})
	}
}

func TestCredentialImportRejectsBodyBeforeCompleteRead(t *testing.T) {
	imports := &fakeImportJobs{}
	cfg := config.Default()
	cfg.Import.MaxTotalBytes = 32
	h := &Handlers{Store: newFakeStore(), Imports: imports, AdminKey: "sk-admin-import-test", Config: cfg}
	req := httptest.NewRequest(http.MethodPost, "/admin/import-jobs", strings.NewReader(`{"name":"large","text":"this request is definitely larger than thirty two bytes"}`))
	req.Header.Set("Authorization", "Bearer sk-admin-import-test")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(imports.files) != 0 {
		t.Fatalf("import manager received files: %+v", imports.files)
	}
}

type fakeDeviceOAuth struct {
	polls int
}

func (f *fakeDeviceOAuth) RequestDeviceCode(context.Context) (*auth.DeviceCodeResponse, error) {
	return &auth.DeviceCodeResponse{
		DeviceCode:              "device-secret",
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://auth.x.ai/device",
		VerificationURIComplete: "https://auth.x.ai/device?user_code=ABCD-EFGH",
		ExpiresIn:               600,
		Interval:                1,
	}, nil
}

func (f *fakeDeviceOAuth) ExchangeDeviceCode(context.Context, string) (*auth.TokenSet, error) {
	f.polls++
	if f.polls == 1 {
		return nil, fmt.Errorf("authorization_pending")
	}
	return &auth.TokenSet{
		AccessToken:  "device-access",
		RefreshToken: "device-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func TestDeviceCodeAdminFlow(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	oauth := &fakeDeviceOAuth{}
	invalidator := &recordingTokenInvalidator{}
	h := &Handlers{
		Store:      store,
		OAuth:      oauth,
		TokenCache: invalidator,
		AdminKey:   "sk-admin-device-test",
		Config:     config.Default(),
	}
	handler := h.Handler()
	adminRequest := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-admin-device-test")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	start := adminRequest("/admin/oauth/device/start", `{}`)
	if start.Code != http.StatusCreated {
		t.Fatalf("start status=%d body=%s", start.Code, start.Body.String())
	}
	if strings.Contains(start.Body.String(), "device-secret") {
		t.Fatalf("device_code leaked: %s", start.Body.String())
	}
	var started struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil || started.SessionID == "" {
		t.Fatalf("start response=%s err=%v", start.Body.String(), err)
	}

	pollBody := `{"session_id":"` + started.SessionID + `"}`
	pending := adminRequest("/admin/oauth/device/poll", pollBody)
	if pending.Code != http.StatusAccepted {
		t.Fatalf("pending status=%d body=%s", pending.Code, pending.Body.String())
	}
	h.deviceMu.Lock()
	session := h.deviceSessions[started.SessionID]
	session.LastPollAt = time.Now().Add(-2 * session.Interval)
	h.deviceSessions[started.SessionID] = session
	h.deviceMu.Unlock()
	authorized := adminRequest("/admin/oauth/device/poll", pollBody)
	if authorized.Code != http.StatusCreated {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
	creds, err := store.ListCredentials()
	if err != nil || len(creds) != 1 || creds[0].RefreshToken != "device-refresh" {
		t.Fatalf("credentials=%+v err=%v", creds, err)
	}
	if got := invalidator.snapshot(); len(got) != 1 || got[0] != creds[0].ID {
		t.Fatalf("device upsert invalidations=%v credential=%q", got, creds[0].ID)
	}
}

func TestSummarizePool(t *testing.T) {
	now := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	cooldown := now.Add(time.Minute)
	success := now.Add(-time.Minute)
	summary := summarizePool([]storage.Credential{
		{ID: "available", Enabled: true, RefreshToken: "r", LastSuccessAt: &success},
		{ID: "cooling", Enabled: true, AccessToken: "a", CooldownUntil: &cooldown},
		{ID: "disabled", Enabled: false, AccessToken: "a"},
		{ID: "missing", Enabled: true},
		{ID: "expired", Enabled: true, AccessToken: "a", ExpiresAt: now.Add(-time.Minute)},
	}, now)
	if summary.Total != 5 || summary.Available != 1 || summary.Cooling != 1 ||
		summary.Disabled != 1 || summary.MissingTokens != 1 || summary.Expired != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	if summary.NextRecoveryAt == nil || summary.LastSuccessAt == nil {
		t.Fatalf("summary timestamps=%+v", summary)
	}
}

func TestDeviceCredentialInputUsesAccountIdentity(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"sub":"user-device-1",
		"email":"device@example.com",
		"team_id":"team-device"
	}`))
	tokens := &auth.TokenSet{
		IDToken:      "header." + payload + ".signature",
		AccessToken:  "sensitive-access",
		RefreshToken: "sensitive-refresh",
	}
	input := deviceCredentialInput(tokens, "client-device")
	if input.UserID != "user-device-1" || input.Email != "device@example.com" ||
		input.TeamID != "team-device" || input.SourceKey != "device:user-device-1" {
		t.Fatalf("input=%+v", input)
	}
	if strings.Contains(input.SourceKey, "sensitive") {
		t.Fatalf("source key leaked token material: %s", input.SourceKey)
	}
	if !trustedVerificationURL("https://auth.x.ai/device") ||
		trustedVerificationURL("https://x.ai.example.invalid/device") ||
		trustedVerificationURL("javascript:alert(1)") {
		t.Fatal("verification URL trust boundary is incorrect")
	}
}
