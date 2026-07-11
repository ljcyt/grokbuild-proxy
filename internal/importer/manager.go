// Package importer implements bounded, asynchronous credential import jobs.
package importer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

const (
	FormatAuto = "auto"
	FormatJSON = "json"
	FormatSSO  = "sso"

	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusPartial   = "partial"
	StatusFailed    = "failed"
	StatusParsed    = "parsed"
	StatusSkipped   = "skipped"
)

// ErrOverloaded is returned when accepting another import would exceed the
// process-wide queue bounds. Callers should retry after existing jobs advance.
var ErrOverloaded = errors.New("importer: queue is full")

type InputFile struct {
	Name   string
	Format string
	Data   []byte
}

type Limits struct {
	MaxFiles         int
	MaxFileBytes     int64
	MaxTotalBytes    int64
	MaxEntries       int
	MaxQueuedJobs    int
	MaxQueuedBytes   int64
	MaxRetainedJobs  int
	MaxRetainedBytes int64
	JobTTL           time.Duration
	Concurrency      int
	JobTimeout       time.Duration
}

type ConvertedCredential struct {
	Name         string
	Email        string
	UserID       string
	TeamID       string
	OIDCIssuer   string
	OIDCClientID string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Error        string
}

type Converter interface {
	Convert(ctx context.Context, ssoValues []string) ([]ConvertedCredential, error)
}

type Store interface {
	BulkUpsertCredentials([]storage.CreateCredentialInput) ([]storage.BulkUpsertResult, error)
}

type ItemResult struct {
	Source       string               `json:"source"`
	Format       string               `json:"format"`
	Status       string               `json:"status"`
	CredentialID string               `json:"credential_id,omitempty"`
	Warnings     []auth.ImportWarning `json:"warnings,omitempty"`
	Error        string               `json:"error,omitempty"`
}

type FileResult struct {
	Source    string               `json:"source"`
	Name      string               `json:"name"`
	Format    string               `json:"format"`
	Status    string               `json:"status"`
	Total     int                  `json:"total"`
	Processed int                  `json:"processed"`
	Created   int                  `json:"created"`
	Updated   int                  `json:"updated"`
	Skipped   int                  `json:"skipped"`
	Failed    int                  `json:"failed"`
	Warnings  []auth.ImportWarning `json:"warnings,omitempty"`
	Results   []ItemResult         `json:"results,omitempty"`
}

type Job struct {
	ID             string               `json:"id"`
	Status         string               `json:"status"`
	CreatedAt      time.Time            `json:"created_at"`
	StartedAt      *time.Time           `json:"started_at,omitempty"`
	FinishedAt     *time.Time           `json:"finished_at,omitempty"`
	Total          int                  `json:"total"`
	Processed      int                  `json:"processed"`
	Created        int                  `json:"created"`
	Updated        int                  `json:"updated"`
	Skipped        int                  `json:"skipped"`
	Failed         int                  `json:"failed"`
	FilesTotal     int                  `json:"files_total"`
	FilesProcessed int                  `json:"files_processed"`
	WarningCount   int                  `json:"warning_count"`
	Warnings       []auth.ImportWarning `json:"warnings,omitempty"`
	Files          []FileResult         `json:"files,omitempty"`
	Results        []ItemResult         `json:"results,omitempty"`
	Error          string               `json:"error,omitempty"`
}

type Manager struct {
	Store     Store
	Converter Converter
	Limits    Limits
	// BeforeStore retires token caches before an import mutation. Imports do not
	// know existing credential IDs until the atomic upsert completes, so the
	// production hook invalidates the small process-wide refresh cache.
	BeforeStore func()
	OnStored    func([]storage.BulkUpsertResult)

	mu          sync.RWMutex
	jobs        map[string]*Job
	jobBytes    map[string]int64
	sem         chan struct{}
	queuedJobs  int
	queuedBytes int64
	now         func() time.Time
}

func NewManager(store Store, converter Converter, limits Limits) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("importer: store is required")
	}
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = 100
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = 4 << 20
	}
	if limits.MaxTotalBytes <= 0 {
		limits.MaxTotalBytes = 16 << 20
	}
	if limits.MaxEntries <= 0 {
		limits.MaxEntries = 1000
	}
	if limits.MaxQueuedJobs <= 0 {
		limits.MaxQueuedJobs = 32
	}
	if limits.MaxQueuedBytes <= 0 {
		limits.MaxQueuedBytes = 64 << 20
	}
	if limits.MaxRetainedJobs <= 0 {
		limits.MaxRetainedJobs = 128
	}
	if limits.MaxRetainedBytes <= 0 {
		limits.MaxRetainedBytes = 64 << 20
	}
	if limits.JobTTL <= 0 {
		limits.JobTTL = 30 * time.Minute
	}
	if limits.Concurrency <= 0 {
		limits.Concurrency = 2
	}
	if limits.JobTimeout <= 0 {
		limits.JobTimeout = 15 * time.Minute
	}
	return &Manager{
		Store: store, Converter: converter, Limits: limits,
		jobs: make(map[string]*Job), jobBytes: make(map[string]int64), sem: make(chan struct{}, limits.Concurrency),
		now: time.Now,
	}, nil
}

func (m *Manager) Start(files []InputFile) (Job, error) {
	if m == nil || m.Store == nil {
		return Job{}, fmt.Errorf("importer: manager is not configured")
	}
	if len(files) == 0 {
		return Job{}, fmt.Errorf("importer: at least one file or document is required")
	}
	if len(files) > m.Limits.MaxFiles {
		return Job{}, fmt.Errorf("importer: too many files (max %d)", m.Limits.MaxFiles)
	}
	copied := make([]InputFile, len(files))
	var totalBytes int64
	for index, file := range files {
		if int64(len(file.Data)) > m.Limits.MaxFileBytes {
			return Job{}, fmt.Errorf("importer: file %d exceeds %d bytes", index+1, m.Limits.MaxFileBytes)
		}
		if int64(len(file.Data)) > m.Limits.MaxTotalBytes-totalBytes {
			return Job{}, fmt.Errorf("importer: total input exceeds %d bytes", m.Limits.MaxTotalBytes)
		}
		totalBytes += int64(len(file.Data))
		if len(strings.TrimSpace(string(file.Data))) == 0 {
			return Job{}, fmt.Errorf("importer: file %d is empty", index+1)
		}
		format := strings.ToLower(strings.TrimSpace(file.Format))
		if format == "" {
			format = FormatAuto
		}
		switch format {
		case FormatAuto, FormatJSON, FormatSSO:
		default:
			return Job{}, fmt.Errorf("importer: unsupported format %q", format)
		}
		name := strings.TrimSpace(filepath.Base(file.Name))
		if name == "" || name == "." {
			name = fmt.Sprintf("document-%d", index+1)
		}
		copied[index] = InputFile{
			Name: name, Format: format, Data: append([]byte(nil), file.Data...),
		}
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, err
	}
	now := m.now().UTC().Truncate(time.Second)
	fileResults := make([]FileResult, len(copied))
	for index, file := range copied {
		fileResults[index] = FileResult{
			Source: fileReference(index), Name: file.Name, Format: file.Format,
			Status: StatusQueued, Results: []ItemResult{},
		}
	}
	job := &Job{
		ID: id, Status: StatusQueued, CreatedAt: now, FilesTotal: len(copied),
		Files: fileResults, Results: []ItemResult{}, Warnings: []auth.ImportWarning{},
	}
	m.mu.Lock()
	m.pruneLocked(now)
	acquired := false
	if m.queuedJobs == 0 {
		select {
		case m.sem <- struct{}{}:
			acquired = true
		default:
		}
	}
	if !acquired {
		if m.queuedJobs >= m.Limits.MaxQueuedJobs || totalBytes > m.Limits.MaxQueuedBytes-m.queuedBytes {
			m.mu.Unlock()
			wipeInputFiles(copied)
			return Job{}, fmt.Errorf("%w (max queued jobs %d, max queued bytes %d)", ErrOverloaded, m.Limits.MaxQueuedJobs, m.Limits.MaxQueuedBytes)
		}
		m.queuedJobs++
		m.queuedBytes += totalBytes
	}
	m.jobs[id] = job
	snapshot := cloneJob(job)
	m.mu.Unlock()
	go m.run(id, copied, acquired, totalBytes)
	return snapshot, nil
}

func (m *Manager) Get(id string) (Job, bool) {
	if m == nil {
		return Job{}, false
	}
	now := m.now().UTC()
	m.mu.Lock()
	m.pruneLocked(now)
	job, ok := m.jobs[strings.TrimSpace(id)]
	if !ok {
		m.mu.Unlock()
		return Job{}, false
	}
	snapshot := cloneJob(job)
	m.mu.Unlock()
	return snapshot, true
}

type pendingItem struct {
	fileIndex   int
	resultIndex int
	input       storage.CreateCredentialInput
}

type filePendingItem struct {
	resultIndex int
	input       storage.CreateCredentialInput
}

func (m *Manager) run(id string, files []InputFile, acquired bool, queuedBytes int64) {
	defer wipeInputFiles(files)
	if !acquired {
		m.sem <- struct{}{}
		m.mu.Lock()
		m.queuedJobs--
		m.queuedBytes -= queuedBytes
		m.mu.Unlock()
	}
	defer func() { <-m.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), m.Limits.JobTimeout)
	defer cancel()
	now := m.now().UTC().Truncate(time.Second)
	m.update(id, func(job *Job) {
		job.Status = StatusRunning
		job.StartedAt = &now
	})

	resultsByFile := make([][]ItemResult, len(files))
	warningsByFile := make([][]auth.ImportWarning, len(files))
	if offendingFile, totalEntries := m.preflightEntries(files); totalEntries > m.Limits.MaxEntries {
		for fileIndex, file := range files {
			message := "batch entry limit exceeded"
			if fileIndex == offendingFile {
				message = fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries)
			}
			resultsByFile[fileIndex] = []ItemResult{{
				Source: fileReference(fileIndex), Format: file.Format, Status: StatusFailed, Error: message,
			}}
		}
		m.finish(id, resultsByFile, warningsByFile, nil)
		return
	}
	var pending []pendingItem
	seenIdentities := make(map[string]string)
	seenNames := make(map[string]string)
	totalEntries := 0
	for fileIndex, file := range files {
		if ctx.Err() != nil {
			break
		}
		m.update(id, func(job *Job) {
			job.Files[fileIndex].Status = StatusRunning
		})
		items, itemResults, fileWarnings, entryCount := m.parseFile(ctx, file, fileIndex)
		totalEntries += entryCount
		if ctx.Err() != nil {
			failQueuedResults(itemResults, "import job timed out")
			resultsByFile[fileIndex] = itemResults
			warningsByFile[fileIndex] = fileWarnings
			m.publishProgress(id, fileIndex, resultsByFile, warningsByFile)
			break
		}
		for index := range items {
			result := &itemResults[items[index].resultIndex]
			identity := importIdentity(items[index].input)
			if previous, exists := seenIdentities[identity]; identity != "" && exists {
				result.Status = StatusSkipped
				result.Warnings = append(result.Warnings, auth.ImportWarning{
					Source: result.Source, Field: "identity",
					Message: "duplicate credential identity in import batch; first occurrence is " + previous,
				})
				continue
			}
			if identity != "" {
				seenIdentities[identity] = result.Source
			}
			nameKey := strings.ToLower(strings.TrimSpace(items[index].input.Name))
			if previousIdentity, exists := seenNames[nameKey]; nameKey != "" && exists && previousIdentity != identity {
				items[index].input.Name = strings.TrimSpace(items[index].input.Name) + " (" + result.Source + ")"
			} else if nameKey != "" {
				seenNames[nameKey] = identity
			}
			pending = append(pending, pendingItem{
				fileIndex: fileIndex, resultIndex: items[index].resultIndex,
				input: items[index].input,
			})
		}
		resultsByFile[fileIndex] = itemResults
		warningsByFile[fileIndex] = fileWarnings
		m.publishProgress(id, fileIndex, resultsByFile, warningsByFile)
		if totalEntries > m.Limits.MaxEntries {
			resultsByFile[fileIndex] = append(resultsByFile[fileIndex], ItemResult{
				Source: fileReference(fileIndex), Format: file.Format, Status: StatusFailed,
				Error: fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries),
			})
			for resultFile := range resultsByFile {
				for resultIndex := range resultsByFile[resultFile] {
					if resultsByFile[resultFile][resultIndex].Status == StatusQueued {
						resultsByFile[resultFile][resultIndex].Status = StatusFailed
						resultsByFile[resultFile][resultIndex].Error = "batch entry limit exceeded"
					}
				}
			}
			pending = nil
			m.publishProgress(id, fileIndex, resultsByFile, warningsByFile)
			break
		}
	}

	if len(pending) > 0 && ctx.Err() != nil {
		failPendingResults(resultsByFile, pending, "import job timed out")
		pending = nil
	}
	if len(pending) > 0 {
		inputs := make([]storage.CreateCredentialInput, len(pending))
		for index := range pending {
			inputs[index] = pending[index].input
		}
		if ctx.Err() != nil {
			failPendingResults(resultsByFile, pending, "import job timed out")
			pending = nil
		}
		var stored []storage.BulkUpsertResult
		var err error
		if len(pending) > 0 {
			if m.BeforeStore != nil {
				m.BeforeStore()
			}
			stored, err = m.Store.BulkUpsertCredentials(inputs)
		}
		if len(pending) == 0 {
			// The deadline fired immediately before persistence; no new writes are allowed.
		} else if err != nil || len(stored) != len(pending) {
			for _, item := range pending {
				result := &resultsByFile[item.fileIndex][item.resultIndex]
				result.Status = StatusFailed
				result.Error = "credential storage failed"
			}
		} else {
			if m.OnStored != nil {
				m.OnStored(append([]storage.BulkUpsertResult(nil), stored...))
			}
			for index, storedItem := range stored {
				result := &resultsByFile[pending[index].fileIndex][pending[index].resultIndex]
				result.CredentialID = storedItem.Credential.ID
				if storedItem.Created {
					result.Status = "created"
				} else {
					result.Status = "updated"
				}
			}
		}
	}

	m.finish(id, resultsByFile, warningsByFile, ctx.Err())
}

func (m *Manager) finish(id string, resultsByFile [][]ItemResult, warningsByFile [][]auth.ImportWarning, runErr error) {
	finished := m.now().UTC().Truncate(time.Second)
	m.update(id, func(job *Job) {
		for fileIndex := range job.Files {
			job.Files[fileIndex].Results = cloneItemResults(resultsByFile[fileIndex])
			job.Files[fileIndex].Warnings = append([]auth.ImportWarning(nil), warningsByFile[fileIndex]...)
			if job.Files[fileIndex].Status == StatusQueued && len(resultsByFile[fileIndex]) > 0 {
				job.Files[fileIndex].Status = StatusParsed
			}
		}
		summarizeJob(job, true)
		switch {
		case job.Failed == 0:
			job.Status = StatusCompleted
		case job.Created+job.Updated+job.Skipped == 0:
			job.Status = StatusFailed
		default:
			job.Status = StatusPartial
		}
		if runErr != nil && job.Created+job.Updated+job.Skipped == 0 {
			job.Error = "import job timed out"
		}
		job.FinishedAt = &finished
	})
}

// preflightEntries counts the whole batch before any potentially remote SSO
// conversion. Parse failures are left to parseFile so callers still receive
// the existing field-level diagnostics.
func (m *Manager) preflightEntries(files []InputFile) (int, int) {
	total := 0
	for fileIndex, file := range files {
		remaining := m.Limits.MaxEntries - total
		if remaining < 1 {
			remaining = 1
		}
		count, err := estimateEntryCount(file, remaining)
		if err != nil {
			continue
		}
		total += count
		if total > m.Limits.MaxEntries {
			return fileIndex, total
		}
	}
	return -1, total
}

func estimateEntryCount(file InputFile, limit int) (int, error) {
	format := file.Format
	if format == FormatAuto {
		trimmed := strings.TrimSpace(string(file.Data))
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") ||
			strings.EqualFold(filepath.Ext(file.Name), ".json") {
			format = FormatJSON
		} else {
			format = FormatSSO
		}
	}
	if format == FormatJSON {
		imported, _, err := auth.ParseGrokAuthJSONDetailedLimit(file.Data, limit)
		if err == nil {
			return len(imported), nil
		}
		if errors.Is(err, auth.ErrImportEntryLimit) {
			return limit + 1, nil
		}
		if file.Format != FormatAuto {
			return 0, err
		}
		format = FormatSSO
	}
	if format == FormatSSO {
		values, err := parseSSOValues(file.Data, limit)
		if err != nil {
			if errors.Is(err, errSSOEntryLimit) {
				return limit + 1, nil
			}
			return 0, err
		}
		return len(values), nil
	}
	return 0, fmt.Errorf("unsupported import format")
}

func (m *Manager) parseFile(ctx context.Context, file InputFile, fileIndex int) ([]filePendingItem, []ItemResult, []auth.ImportWarning, int) {
	fileSource := fileReference(fileIndex)
	format := file.Format
	var jsonParseErr error
	var jsonWarnings []auth.ImportWarning
	if format == FormatAuto {
		trimmed := strings.TrimSpace(string(file.Data))
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") ||
			strings.EqualFold(filepath.Ext(file.Name), ".json") {
			format = FormatJSON
		} else {
			format = FormatSSO
		}
	}
	if format == FormatJSON {
		imported, fileWarnings, err := auth.ParseGrokAuthJSONDetailedLimit(file.Data, m.Limits.MaxEntries)
		jsonParseErr = err
		jsonWarnings = fileWarnings
		if err == nil {
			if len(imported) > m.Limits.MaxEntries {
				return nil, []ItemResult{{
					Source: fileSource, Format: FormatJSON, Status: StatusFailed,
					Error: fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries),
				}}, fileWarnings, len(imported)
			}
			inputs := make([]filePendingItem, 0, len(imported))
			results := make([]ItemResult, 0, len(imported))
			for index, credential := range imported {
				source := entryReference(fileIndex, index)
				enabled := !credential.Disabled
				proxyMode := ""
				if strings.TrimSpace(credential.ProxyURL) != "" {
					proxyMode = storage.CredentialProxyURL
				}
				inputs = append(inputs, filePendingItem{
					resultIndex: index,
					input: storage.CreateCredentialInput{
						Name:  firstNonEmpty(credential.Email, file.Name),
						Email: credential.Email, UserID: credential.UserID, TeamID: credential.TeamID,
						SourceKey: source, OIDCIssuer: credential.OIDCIssuer,
						OIDCClientID: credential.OIDCClientID, AccessToken: credential.AccessToken,
						RefreshToken: credential.RefreshToken, ExpiresAt: credential.ExpiresAt,
						Enabled: &enabled, ProxyMode: proxyMode, ProxyURL: credential.ProxyURL,
					},
				})
				warnings := copyWarningsForSource(credential.Warnings, source)
				results = append(results, ItemResult{
					Source: source, Format: FormatJSON, Status: StatusQueued, Warnings: warnings,
				})
			}
			return inputs, results, copyWarningsForSource(fileWarnings, fileSource), len(imported)
		}
		if errors.Is(err, auth.ErrImportEntryLimit) {
			return nil, []ItemResult{{
				Source: fileSource, Format: FormatJSON, Status: StatusFailed,
				Error: fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries),
			}}, nil, m.Limits.MaxEntries + 1
		}
		if file.Format != FormatAuto {
			return nil, []ItemResult{{
				Source: fileSource, Format: FormatJSON, Status: StatusFailed, Error: err.Error(),
			}}, copyWarningsForSource(fileWarnings, fileSource), 1
		}
		format = FormatSSO
	}
	if format == FormatSSO {
		values, err := parseSSOValues(file.Data, m.Limits.MaxEntries)
		if err != nil {
			if errors.Is(err, errSSOEntryLimit) {
				return nil, []ItemResult{{
					Source: fileSource, Format: FormatSSO, Status: StatusFailed,
					Error: fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries),
				}}, nil, m.Limits.MaxEntries + 1
			}
			if jsonParseErr != nil {
				return nil, []ItemResult{{
					Source: fileSource, Format: FormatJSON, Status: StatusFailed, Error: jsonParseErr.Error(),
				}}, copyWarningsForSource(jsonWarnings, fileSource), 1
			}
			return nil, []ItemResult{{
				Source: fileSource, Format: FormatSSO, Status: StatusFailed, Error: err.Error(),
			}}, nil, 1
		}
		if len(values) > m.Limits.MaxEntries {
			return nil, []ItemResult{{
				Source: fileSource, Format: FormatSSO, Status: StatusFailed,
				Error: fmt.Sprintf("entry limit exceeded (max %d)", m.Limits.MaxEntries),
			}}, nil, len(values)
		}
		if m.Converter == nil {
			return nil, failedSSOResults(fileIndex, len(values), "SSO converter is not configured"), nil, len(values)
		}
		converted, err := m.Converter.Convert(ctx, values)
		if err != nil {
			return nil, failedSSOResults(fileIndex, len(values), "SSO conversion failed"), nil, len(values)
		}
		if len(converted) != len(values) {
			return nil, failedSSOResults(fileIndex, len(values), "SSO converter returned an unexpected result count"), nil, len(values)
		}
		inputs := make([]filePendingItem, 0, len(converted))
		results := make([]ItemResult, 0, len(converted))
		for index, credential := range converted {
			source := entryReference(fileIndex, index)
			result := ItemResult{Source: source, Format: FormatSSO, Status: StatusQueued}
			if strings.TrimSpace(credential.Error) != "" {
				result.Status = StatusFailed
				result.Error = strings.TrimSpace(credential.Error)
			} else {
				inputs = append(inputs, filePendingItem{
					resultIndex: index,
					input: storage.CreateCredentialInput{
						Name:  firstNonEmpty(credential.Name, credential.Email, source),
						Email: credential.Email, UserID: credential.UserID, TeamID: credential.TeamID,
						SourceKey: source, OIDCIssuer: credential.OIDCIssuer,
						OIDCClientID: credential.OIDCClientID, AccessToken: credential.AccessToken,
						RefreshToken: credential.RefreshToken, ExpiresAt: credential.ExpiresAt,
					},
				})
			}
			results = append(results, result)
		}
		return inputs, results, nil, len(values)
	}
	return nil, []ItemResult{{
		Source: fileSource, Format: format, Status: StatusFailed, Error: "unsupported import format",
	}}, nil, 1
}

func failQueuedResults(results []ItemResult, message string) {
	for index := range results {
		if results[index].Status == StatusQueued {
			results[index].Status = StatusFailed
			results[index].Error = message
		}
	}
}

func failPendingResults(resultsByFile [][]ItemResult, pending []pendingItem, message string) {
	for _, item := range pending {
		result := &resultsByFile[item.fileIndex][item.resultIndex]
		if result.Status == StatusQueued {
			result.Status = StatusFailed
			result.Error = message
		}
	}
}

func wipeInputFiles(files []InputFile) {
	for fileIndex := range files {
		for byteIndex := range files[fileIndex].Data {
			files[fileIndex].Data[byteIndex] = 0
		}
	}
}

var errSSOEntryLimit = errors.New("SSO entry limit exceeded")

func parseSSOValues(data []byte, limit int) ([]string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("SSO document is empty")
	}
	var values []string
	jsonLike := trimmed[0] == '[' || trimmed[0] == '{'
	if jsonLike {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		if err := collectSSOJSONValue(decoder, &values, limit); err != nil {
			if errors.Is(err, errSSOEntryLimit) {
				return nil, err
			}
			return nil, fmt.Errorf("invalid JSON SSO document")
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("invalid JSON SSO document")
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("no explicit SSO values found in JSON document")
		}
	}
	if !jsonLike {
		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		scanner.Buffer(make([]byte, 64*1024), max(len(trimmed), 64*1024))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if limit > 0 && len(values) >= limit {
				return nil, errSSOEntryLimit
			}
			values = append(values, normalizeSSOValue(line))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read SSO document: %w", err)
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no SSO values found")
	}
	return values, nil
}

func collectSSOJSONValue(decoder *json.Decoder, out *[]string, limit int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch typed := token.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		if limit > 0 && len(*out) >= limit {
			return errSSOEntryLimit
		}
		*out = append(*out, normalizeSSOValue(typed))
	case json.Delim:
		switch typed {
		case '[':
			for decoder.More() {
				if err := collectSSOJSONValue(decoder, out, limit); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '{':
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return fmt.Errorf("object member name is not a string")
				}
				if isSSOField(name) {
					if err := collectSSOJSONValue(decoder, out, limit); err != nil {
						return err
					}
				} else {
					var ignored json.RawMessage
					if err := decoder.Decode(&ignored); err != nil {
						return err
					}
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
	}
	return nil
}

func isSSOField(name string) bool {
	switch name {
	case "sso", "sso_token", "cookie", "token", "cookies":
		return true
	default:
		return false
	}
}

func normalizeSSOValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.Count(value, "----") >= 2 {
		if index := strings.LastIndex(value, "----"); index >= 0 {
			if sso := strings.TrimSpace(value[index+4:]); sso != "" {
				return sso
			}
		}
	}
	return value
}

func (m *Manager) publishProgress(
	id string,
	fileIndex int,
	resultsByFile [][]ItemResult,
	warningsByFile [][]auth.ImportWarning,
) {
	m.update(id, func(job *Job) {
		job.Files[fileIndex].Status = StatusParsed
		job.Files[fileIndex].Results = cloneItemResults(resultsByFile[fileIndex])
		job.Files[fileIndex].Warnings = append([]auth.ImportWarning(nil), warningsByFile[fileIndex]...)
		summarizeJob(job, false)
	})
}

func summarizeJob(job *Job, final bool) {
	job.Total = 0
	job.Processed = 0
	job.Created = 0
	job.Updated = 0
	job.Skipped = 0
	job.Failed = 0
	job.WarningCount = 0
	job.FilesProcessed = 0
	job.Results = job.Results[:0]
	job.Warnings = job.Warnings[:0]
	for fileIndex := range job.Files {
		file := &job.Files[fileIndex]
		if final && file.Status == StatusQueued {
			file.Results = []ItemResult{{
				Source: file.Source, Format: file.Format, Status: StatusFailed,
				Error: "file was not processed because the import batch stopped early",
			}}
		}
		file.Total = len(file.Results)
		file.Processed = 0
		file.Created = 0
		file.Updated = 0
		file.Skipped = 0
		file.Failed = 0
		if file.Status == StatusParsed || file.Status == StatusCompleted ||
			file.Status == StatusPartial || file.Status == StatusFailed {
			job.FilesProcessed++
		}
		job.Warnings = append(job.Warnings, file.Warnings...)
		for resultIndex := range file.Results {
			result := file.Results[resultIndex]
			job.Results = append(job.Results, result)
			job.Warnings = append(job.Warnings, result.Warnings...)
			switch result.Status {
			case "created":
				file.Created++
			case "updated":
				file.Updated++
			case StatusSkipped:
				file.Skipped++
			case StatusFailed:
				file.Failed++
			}
			if result.Status != StatusQueued {
				file.Processed++
			}
		}
		if final {
			switch {
			case file.Failed == 0:
				file.Status = StatusCompleted
			case file.Created+file.Updated+file.Skipped == 0:
				file.Status = StatusFailed
			default:
				file.Status = StatusPartial
			}
		}
		job.Total += file.Total
		job.Processed += file.Processed
		job.Created += file.Created
		job.Updated += file.Updated
		job.Skipped += file.Skipped
		job.Failed += file.Failed
	}
	job.WarningCount = len(job.Warnings)
}

func failedSSOResults(fileIndex, count int, message string) []ItemResult {
	results := make([]ItemResult, count)
	for index := range results {
		results[index] = ItemResult{
			Source: entryReference(fileIndex, index), Format: FormatSSO,
			Status: StatusFailed, Error: message,
		}
	}
	return results
}

func copyWarningsForSource(warnings []auth.ImportWarning, source string) []auth.ImportWarning {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]auth.ImportWarning, len(warnings))
	for index, warning := range warnings {
		out[index] = warning
		out[index].Source = source
	}
	return out
}

func fileReference(index int) string {
	return fmt.Sprintf("file-%d", index+1)
}

func entryReference(fileIndex, entryIndex int) string {
	return fmt.Sprintf("%s/entry-%d", fileReference(fileIndex), entryIndex+1)
}

func importIdentity(input storage.CreateCredentialInput) string {
	issuer := strings.ToLower(strings.TrimRight(strings.TrimSpace(input.OIDCIssuer), "/"))
	clientID := strings.ToLower(strings.TrimSpace(input.OIDCClientID))
	if userID := strings.TrimSpace(input.UserID); userID != "" {
		return "oidc:" + issuer + ":" + clientID + ":" + userID + ":" + strings.TrimSpace(input.TeamID)
	}
	if email := strings.ToLower(strings.TrimSpace(input.Email)); email != "" {
		return "email:" + issuer + ":" + clientID + ":" + email
	}
	token := strings.TrimSpace(input.RefreshToken)
	if token == "" {
		token = strings.TrimSpace(input.AccessToken)
	}
	if token == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(digest[:])
}

func cloneItemResults(results []ItemResult) []ItemResult {
	out := append([]ItemResult(nil), results...)
	for index := range out {
		out[index].Warnings = append([]auth.ImportWarning(nil), results[index].Warnings...)
	}
	return out
}

func (m *Manager) update(id string, mutate func(*Job)) {
	m.mu.Lock()
	if job := m.jobs[id]; job != nil {
		mutate(job)
		if job.FinishedAt != nil {
			encoded, _ := json.Marshal(job)
			m.jobBytes[id] = int64(len(encoded))
		}
	}
	m.pruneLocked(m.now().UTC())
	m.mu.Unlock()
}

func (m *Manager) pruneLocked(now time.Time) {
	type retainedJob struct {
		id       string
		finished time.Time
		bytes    int64
	}
	retained := make([]retainedJob, 0, len(m.jobs))
	var retainedBytes int64
	for id, job := range m.jobs {
		if job.FinishedAt != nil && now.Sub(*job.FinishedAt) > m.Limits.JobTTL {
			delete(m.jobs, id)
			delete(m.jobBytes, id)
			continue
		}
		if job.FinishedAt != nil {
			size, ok := m.jobBytes[id]
			if !ok {
				encoded, _ := json.Marshal(job)
				size = int64(len(encoded))
				m.jobBytes[id] = size
			}
			retained = append(retained, retainedJob{id: id, finished: *job.FinishedAt, bytes: size})
			retainedBytes += size
		}
	}
	sort.Slice(retained, func(i, j int) bool {
		if retained[i].finished.Equal(retained[j].finished) {
			return retained[i].id < retained[j].id
		}
		return retained[i].finished.Before(retained[j].finished)
	})
	for len(retained) > m.Limits.MaxRetainedJobs || retainedBytes > m.Limits.MaxRetainedBytes {
		oldest := retained[0]
		retained = retained[1:]
		delete(m.jobs, oldest.id)
		delete(m.jobBytes, oldest.id)
		retainedBytes -= oldest.bytes
	}
}

func cloneJob(job *Job) Job {
	if job == nil {
		return Job{}
	}
	out := *job
	out.Results = cloneItemResults(job.Results)
	out.Warnings = append([]auth.ImportWarning(nil), job.Warnings...)
	out.Files = append([]FileResult(nil), job.Files...)
	for index := range out.Files {
		out.Files[index].Warnings = append([]auth.ImportWarning(nil), job.Files[index].Warnings...)
		out.Files[index].Results = cloneItemResults(job.Files[index].Results)
	}
	return out
}

func newJobID() (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("importer: generate job id: %w", err)
	}
	return "import_" + hex.EncodeToString(value[:]), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
