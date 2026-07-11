package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type fakeStore struct {
	mu     sync.Mutex
	inputs []storage.CreateCredentialInput
	events []string
}

func (f *fakeStore) BulkUpsertCredentials(inputs []storage.CreateCredentialInput) ([]storage.BulkUpsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "store")
	f.inputs = append(f.inputs, inputs...)
	results := make([]storage.BulkUpsertResult, len(inputs))
	for index := range inputs {
		results[index] = storage.BulkUpsertResult{
			Credential: storage.Credential{ID: fmt.Sprintf("cred-%d", len(f.inputs)-len(inputs)+index+1)},
			Created:    true,
		}
	}
	return results, nil
}

func (f *fakeStore) record(event string) {
	f.mu.Lock()
	f.events = append(f.events, event)
	f.mu.Unlock()
}

type fakeConverter struct{}

func (fakeConverter) Convert(_ context.Context, values []string) ([]ConvertedCredential, error) {
	out := make([]ConvertedCredential, len(values))
	for index := range values {
		out[index] = ConvertedCredential{
			UserID: fmt.Sprintf("sso-user-%d", index+1), AccessToken: "access", RefreshToken: "refresh",
		}
	}
	return out, nil
}

type captureConverter struct {
	mu     sync.Mutex
	values []string
}

func (c *captureConverter) Convert(_ context.Context, values []string) ([]ConvertedCredential, error) {
	c.mu.Lock()
	c.values = append([]string(nil), values...)
	c.mu.Unlock()
	out := make([]ConvertedCredential, len(values))
	for index := range out {
		out[index] = ConvertedCredential{
			UserID: fmt.Sprintf("captured-user-%d", index+1), AccessToken: "access", RefreshToken: "refresh",
		}
	}
	return out, nil
}

type partialConverter struct{}

func (partialConverter) Convert(_ context.Context, values []string) ([]ConvertedCredential, error) {
	out := make([]ConvertedCredential, len(values))
	for index := range out {
		if index == 1 {
			out[index].Error = "conversion rejected"
			continue
		}
		out[index] = ConvertedCredential{UserID: "partial-user", AccessToken: "access", RefreshToken: "refresh"}
	}
	return out, nil
}

type blockingConverter struct {
	entered chan struct{}
	release chan struct{}
}

type queueBlockingConverter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *queueBlockingConverter) Convert(context.Context, []string) ([]ConvertedCredential, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return []ConvertedCredential{{UserID: "queued-user", AccessToken: "access", RefreshToken: "refresh"}}, nil
}

type deadlineIgnoringConverter struct {
	delay time.Duration
}

func (c deadlineIgnoringConverter) Convert(_ context.Context, _ []string) ([]ConvertedCredential, error) {
	time.Sleep(c.delay)
	return []ConvertedCredential{{UserID: "late-user", AccessToken: "access", RefreshToken: "refresh"}}, nil
}

func (c blockingConverter) Convert(ctx context.Context, values []string) ([]ConvertedCredential, error) {
	close(c.entered)
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	out := make([]ConvertedCredential, len(values))
	for index := range out {
		out[index] = ConvertedCredential{UserID: "blocked-user", AccessToken: "access", RefreshToken: "refresh"}
	}
	return out, nil
}

type failingConverter struct{}

func (failingConverter) Convert(context.Context, []string) ([]ConvertedCredential, error) {
	return nil, errors.New("remote converter failed")
}

func TestManagerImportsDuplicateJSONKeys(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "auth.json", Format: FormatJSON,
		Data: []byte(`{
			"https://auth.x.ai::client":{"key":"a1","refresh_token":"r1","user_id":"u1"},
			"https://auth.x.ai::client":{"key":"a2","refresh_token":"r2","user_id":"u2"}
		}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusCompleted || finished.Created != 2 || finished.Failed != 0 {
		t.Fatalf("job=%+v", finished)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.inputs) != 2 || store.inputs[0].UserID != "u1" || store.inputs[1].UserID != "u2" {
		t.Fatalf("inputs=%+v", store.inputs)
	}
	if store.inputs[0].SourceKey == store.inputs[1].SourceKey {
		t.Fatalf("source keys collided: %+v", store.inputs)
	}
}

func TestManagerInvalidatesRefreshStateBeforeAndAfterAtomicStore(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	manager.BeforeStore = func() { store.record("before") }
	manager.OnStored = func([]storage.BulkUpsertResult) { store.record("after") }
	job, err := manager.Start([]InputFile{{
		Name: "auth.json", Format: FormatJSON,
		Data: []byte(`{"key":"access","refresh_token":"refresh","user_id":"ordered"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusCompleted {
		t.Fatalf("job=%+v", finished)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	if strings.Join(events, ",") != "before,store,after" {
		t.Fatalf("callback order=%v", events)
	}
}

func TestBoundedSSOParserStopsAtEntryLimit(t *testing.T) {
	data := []byte(strings.Repeat("short-cookie\n", 50_000))
	if _, err := parseSSOValues(data, 10); !errors.Is(err, errSSOEntryLimit) {
		t.Fatalf("line parser err=%v want entry limit", err)
	}
	jsonData := []byte(`{"cookies":[` + strings.Repeat(`"short-cookie",`, 50_000) + `"last"]}`)
	if _, err := parseSSOValues(jsonData, 10); !errors.Is(err, errSSOEntryLimit) {
		t.Fatalf("JSON parser err=%v want entry limit", err)
	}
}

func TestManagerImportsExplicitJSONSSO(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, fakeConverter{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "sso.json", Format: FormatAuto,
		Data: []byte(`{"cookies":[{"sso":"cookie-one"},{"sso_token":"cookie-two"}]}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusCompleted || finished.Created != 2 {
		t.Fatalf("job=%+v", finished)
	}
}

func TestManagerDoesNotSendUnknownJSONToSSOConverter(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, fakeConverter{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "unknown.json", Format: FormatAuto, Data: []byte(`{"unrelated":"secret"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusFailed || finished.Failed != 1 {
		t.Fatalf("job=%+v", finished)
	}
	if !strings.Contains(finished.Results[0].Error, "unrelated") {
		t.Fatalf("field-level error missing: %+v", finished.Results)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.inputs) != 0 {
		t.Fatalf("unexpected inputs=%+v", store.inputs)
	}
}

func TestManagerUsesStableReferencesForSameNamedFiles(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{
		{Name: "auth.json", Format: FormatJSON, Data: []byte(`{"key":"a1","refresh_token":"r1","user_id":"u1"}`)},
		{Name: "auth.json", Format: FormatJSON, Data: []byte(`{"key":"a2","refresh_token":"r2","user_id":"u2"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Created != 2 || len(finished.Files) != 2 ||
		finished.Files[0].Source != "file-1" || finished.Files[1].Source != "file-2" ||
		finished.Results[0].Source != "file-1/entry-1" || finished.Results[1].Source != "file-2/entry-1" {
		t.Fatalf("job=%+v", finished)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.inputs[0].SourceKey != "file-1/entry-1" || store.inputs[1].SourceKey != "file-2/entry-1" {
		t.Fatalf("inputs=%+v", store.inputs)
	}
	if store.inputs[0].Name == store.inputs[1].Name || !strings.Contains(store.inputs[1].Name, "file-2/entry-1") {
		t.Fatalf("display names=%q/%q", store.inputs[0].Name, store.inputs[1].Name)
	}
}

func TestManagerNormalizesBareAndDelimitedSSO(t *testing.T) {
	converter := &captureConverter{}
	manager, err := NewManager(&fakeStore{}, converter, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "accounts.txt", Format: FormatSSO,
		Data: []byte("bare-sso\nuser@example.com----password-secret----wrapped-sso\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Created != 2 || finished.Failed != 0 {
		t.Fatalf("job=%+v", finished)
	}
	converter.mu.Lock()
	defer converter.mu.Unlock()
	if fmt.Sprint(converter.values) != "[bare-sso wrapped-sso]" {
		t.Fatalf("values=%v", converter.values)
	}
}

func TestManagerImportsCPAAndReportsUnsupportedFields(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "cpa.json", Format: FormatJSON,
		Data: []byte(`{"type":"xai","access_token":"access-secret","refresh_token":"refresh-secret","sub":"cpa-user","expired":"2026-07-09T19:32:31Z","base_url":"https://example.invalid/v1"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Created != 1 || finished.WarningCount != 1 || len(finished.Results[0].Warnings) != 1 ||
		finished.Results[0].Warnings[0].Field != "base_url" {
		t.Fatalf("job=%+v", finished)
	}
}

func TestManagerReportsPartialConversionFailure(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, partialConverter{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{Name: "sso.txt", Format: FormatSSO, Data: []byte("one\ntwo")}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusPartial || finished.Created != 1 || finished.Failed != 1 ||
		finished.Files[0].Status != StatusPartial || finished.Results[1].Source != "file-1/entry-2" {
		t.Fatalf("job=%+v", finished)
	}
}

func TestManagerPublishesProgressBeforeJobFinishes(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	manager, err := NewManager(&fakeStore{}, blockingConverter{entered: entered, release: release}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{
		{Name: "auth.json", Format: FormatJSON, Data: []byte(`{"key":"a","refresh_token":"r","user_id":"json-user"}`)},
		{Name: "sso.txt", Format: FormatSSO, Data: []byte("sso")},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("converter did not block")
	}
	running, ok := manager.Get(job.ID)
	if !ok || running.Status != StatusRunning || running.FilesProcessed != 1 || running.Total != 1 ||
		len(running.Files[0].Results) != 1 || running.Files[0].Status != StatusParsed ||
		running.Files[1].Status != StatusRunning {
		t.Fatalf("running=%+v ok=%v", running, ok)
	}
	close(release)
	finished := awaitJob(t, manager, job.ID)
	if finished.Created != 2 || finished.Processed != 2 || finished.FilesProcessed != 2 {
		t.Fatalf("finished=%+v", finished)
	}
}

func TestManagerSkipsDuplicateIdentityInBatch(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{
		{Name: "one.json", Format: FormatJSON, Data: []byte(`{"key":"a1","refresh_token":"r1","user_id":"same-user"}`)},
		{Name: "two.json", Format: FormatJSON, Data: []byte(`{"key":"a2","refresh_token":"r2","user_id":"same-user"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Created != 1 || finished.Skipped != 1 || finished.Failed != 0 ||
		finished.Results[1].Status != StatusSkipped || finished.WarningCount != 1 {
		t.Fatalf("job=%+v", finished)
	}
}

func TestManagerJobDoesNotLeakInputSecrets(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, failingConverter{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{
		Name: "secret.txt", Format: FormatSSO,
		Data: []byte("mail@example.com----password-secret----sso-secret"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	encoded, err := json.Marshal(finished)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"mail@example.com", "password-secret", "sso-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("job leaked %q: %s", secret, encoded)
		}
	}
}

func TestManagerRejectsTotalInputLimit(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, nil, Limits{MaxFileBytes: 8, MaxTotalBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Start([]InputFile{{Name: "one", Data: []byte("123456")}, {Name: "two", Data: []byte("123456")}})
	if err == nil || !strings.Contains(err.Error(), "total input exceeds 10 bytes") {
		t.Fatalf("err=%v", err)
	}
}

func TestManagerRejectsQueueJobAndByteOverload(t *testing.T) {
	converter := &queueBlockingConverter{entered: make(chan struct{}), release: make(chan struct{})}
	manager, err := NewManager(&fakeStore{}, converter, Limits{
		Concurrency: 1, MaxQueuedJobs: 1, MaxQueuedBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Start([]InputFile{{Name: "first", Format: FormatSSO, Data: []byte("one")}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-converter.entered:
	case <-time.After(time.Second):
		t.Fatal("first job did not enter converter")
	}
	second, err := manager.Start([]InputFile{{Name: "second", Format: FormatSSO, Data: []byte("two")}})
	if err != nil {
		t.Fatalf("queue second job: %v", err)
	}
	if _, err := manager.Start([]InputFile{{Name: "third", Format: FormatSSO, Data: []byte("three")}}); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("third job error=%v want ErrOverloaded", err)
	}
	close(converter.release)
	awaitJob(t, manager, first.ID)
	awaitJob(t, manager, second.ID)

	byteConverter := &queueBlockingConverter{entered: make(chan struct{}), release: make(chan struct{})}
	byteManager, err := NewManager(&fakeStore{}, byteConverter, Limits{
		Concurrency: 1, MaxQueuedJobs: 4, MaxQueuedBytes: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	byteFirst, err := byteManager.Start([]InputFile{{Name: "first", Format: FormatSSO, Data: []byte("one")}})
	if err != nil {
		t.Fatal(err)
	}
	<-byteConverter.entered
	if _, err := byteManager.Start([]InputFile{{Name: "too-large", Format: FormatSSO, Data: []byte("abc")}}); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("queued bytes error=%v want ErrOverloaded", err)
	}
	close(byteConverter.release)
	awaitJob(t, byteManager, byteFirst.ID)
}

func TestManagerDoesNotStoreAfterDeadline(t *testing.T) {
	store := &fakeStore{}
	manager, err := NewManager(store, deadlineIgnoringConverter{delay: 25 * time.Millisecond}, Limits{
		JobTimeout: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{Name: "late", Format: FormatSSO, Data: []byte("sso")}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusFailed || finished.Error != "import job timed out" {
		t.Fatalf("job=%+v", finished)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.inputs) != 0 {
		t.Fatalf("deadline job stored inputs: %+v", store.inputs)
	}
}

func TestManagerCountsActualEntriesWhenPerFileLimitExceeded(t *testing.T) {
	manager, err := NewManager(&fakeStore{}, fakeConverter{}, Limits{MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{{Name: "three", Format: FormatSSO, Data: []byte("one\ntwo\nthree")}})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusFailed || finished.Failed != 1 ||
		!strings.Contains(finished.Results[0].Error, "entry limit exceeded") {
		t.Fatalf("job=%+v", finished)
	}
}

func TestManagerRejectsBatchEntryLimitBeforeAnySSOConversion(t *testing.T) {
	converter := &captureConverter{}
	manager, err := NewManager(&fakeStore{}, converter, Limits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	job, err := manager.Start([]InputFile{
		{Name: "first.sso", Format: FormatSSO, Data: []byte("one")},
		{Name: "second.sso", Format: FormatSSO, Data: []byte("two")},
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := awaitJob(t, manager, job.ID)
	if finished.Status != StatusFailed || finished.Failed != 2 {
		t.Fatalf("job=%+v", finished)
	}
	converter.mu.Lock()
	defer converter.mu.Unlock()
	if len(converter.values) != 0 {
		t.Fatalf("converter was called before batch limit rejection: %v", converter.values)
	}
}

func TestManagerPrunesCompletedJobsByCountAndBytes(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	manager, err := NewManager(&fakeStore{}, nil, Limits{
		MaxRetainedJobs:  2,
		MaxRetainedBytes: 350,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.jobs = map[string]*Job{
		"running": {
			ID: "running", Status: StatusRunning, CreatedAt: now,
		},
		"old": {
			ID: "old", Status: StatusCompleted, CreatedAt: now.Add(-3 * time.Minute),
			FinishedAt: timePointer(now.Add(-3 * time.Minute)), Results: []ItemResult{{Error: strings.Repeat("x", 200)}},
		},
		"middle": {
			ID: "middle", Status: StatusCompleted, CreatedAt: now.Add(-2 * time.Minute),
			FinishedAt: timePointer(now.Add(-2 * time.Minute)), Results: []ItemResult{{Error: strings.Repeat("y", 200)}},
		},
		"new": {
			ID: "new", Status: StatusCompleted, CreatedAt: now.Add(-time.Minute),
			FinishedAt: timePointer(now.Add(-time.Minute)), Results: []ItemResult{{Error: "small"}},
		},
	}
	manager.mu.Lock()
	manager.pruneLocked(now)
	manager.mu.Unlock()
	if _, ok := manager.jobs["old"]; ok {
		t.Fatalf("oldest retained job was not pruned: %+v", manager.jobs)
	}
	if _, ok := manager.jobs["running"]; !ok {
		t.Fatalf("running job was pruned: %+v", manager.jobs)
	}
	var retainedBytes int64
	retainedJobs := 0
	for _, job := range manager.jobs {
		if job.FinishedAt == nil {
			continue
		}
		retainedJobs++
		encoded, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		retainedBytes += int64(len(encoded))
	}
	if retainedJobs > manager.Limits.MaxRetainedJobs {
		t.Fatalf("retained job count=%d", retainedJobs)
	}
	if retainedBytes > manager.Limits.MaxRetainedBytes {
		t.Fatalf("retained bytes=%d limit=%d", retainedBytes, manager.Limits.MaxRetainedBytes)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func awaitJob(t *testing.T, manager *Manager, id string) Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := manager.Get(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		switch job.Status {
		case StatusCompleted, StatusPartial, StatusFailed:
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job %s did not complete", id)
	return Job{}
}
