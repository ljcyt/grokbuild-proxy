package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrImportEntryLimit reports that a bounded parser observed more credential
// entries than the caller permits. It is intentionally distinguishable from a
// malformed document so import managers can reject the whole batch early.
var ErrImportEntryLimit = errors.New("import grok auth: entry limit exceeded")

const maxImportWarnings = 256

// GrokAuthEntry is one credential entry inside ~/.grok/auth.json.
// The CLI stores entries keyed by "https://auth.x.ai::<client_id>".
type GrokAuthEntry struct {
	Type string `json:"type,omitempty"`
	// Key is the access JWT (CLI field name).
	Key           string `json:"key"`
	AccessToken   string `json:"access_token,omitempty"`
	AuthMode      string `json:"auth_mode,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Email         string `json:"email,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	ProfileImage  string `json:"profile_image_asset_id,omitempty"`
	PrincipalType string `json:"principal_type,omitempty"`
	PrincipalID   string `json:"principal_id,omitempty"`
	TeamID        string `json:"team_id,omitempty"`
	CodingOptOut  bool   `json:"coding_data_retention_opt_out,omitempty"`
	RefreshToken  string `json:"refresh_token"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	Expired       string `json:"expired,omitempty"`
	OIDCIssuer    string `json:"oidc_issuer,omitempty"`
	OIDCClientID  string `json:"oidc_client_id,omitempty"`
	Sub           string `json:"sub,omitempty"`
	Disabled      bool   `json:"disabled,omitempty"`
	ProxyURL      string `json:"proxy_url,omitempty"`
	Proxy         string `json:"proxy,omitempty"`
}

// ImportedCredential is a normalized credential produced from auth.json.
type ImportedCredential struct {
	// SourceKey is the map key in auth.json (issuer::client_id).
	SourceKey    string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Email        string
	UserID       string
	TeamID       string
	OIDCIssuer   string
	OIDCClientID string
	AuthMode     string
	Disabled     bool
	ProxyURL     string
	Warnings     []ImportWarning
	Raw          GrokAuthEntry
}

// ImportWarning describes a recognized import item field that was not consumed.
// Values are intentionally excluded so diagnostics cannot leak credential data.
type ImportWarning struct {
	Source  string `json:"source,omitempty"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// DefaultGrokAuthPath returns ~/.grok/auth.json.
func DefaultGrokAuthPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".grok", "auth.json")
	}
	return filepath.Join(home, ".grok", "auth.json")
}

// DefaultGrokAuthDir returns ~/.grok (import path jail root).
func DefaultGrokAuthDir() string {
	return filepath.Dir(DefaultGrokAuthPath())
}

// ResolveGrokAuthPath validates and resolves a path for reading Grok auth files.
// Empty path → DefaultGrokAuthPath(). Non-empty paths must resolve inside allowed roots
// (default: ~/.grok; optional extraRoots, e.g. proxy data_dir).
func ResolveGrokAuthPath(path string, extraRoots ...string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultGrokAuthPath()
	}
	// Reject null bytes before Abs.
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("import grok auth: invalid path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("import grok auth: resolve path: %w", err)
	}
	// Resolve symlinks when the path exists so jail checks use the real target.
	// Empty/default paths go through the same checks (no symlink escape from ~/.grok).
	resolved := abs
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = real
	} else if !os.IsNotExist(err) {
		// Keep abs when target is missing (ReadFile will fail later with a clean error).
		// Other eval errors (permission) still use abs for allowlist check.
	}

	roots := make([]string, 0, 1+len(extraRoots))
	// Eval default root when possible so jail matches realpath of ~/.grok.
	defRoot := DefaultGrokAuthDir()
	if ar, err := filepath.Abs(defRoot); err == nil {
		defRoot = ar
		if real, err := filepath.EvalSymlinks(ar); err == nil {
			defRoot = real
		}
	}
	roots = append(roots, defRoot)
	for _, r := range extraRoots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		ar, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(ar); err == nil {
			ar = real
		}
		roots = append(roots, ar)
	}

	if !pathUnderAnyRoot(resolved, roots) {
		return "", fmt.Errorf("import grok auth: path not allowed (must be under ~/.grok or data_dir)")
	}
	return resolved, nil
}

func pathUnderAnyRoot(path string, roots []string) bool {
	clean := filepath.Clean(path)
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" {
			continue
		}
		// Exact root match (directory itself) is not a file we want, but keep prefix rule.
		if clean == root {
			return true
		}
		prefix := root + string(os.PathSeparator)
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

// ImportGrokAuthFile reads and parses a Grok CLI auth.json file.
// Empty path uses DefaultGrokAuthPath(). Paths outside ~/.grok (and optional extraRoots) are rejected.
func ImportGrokAuthFile(path string, extraRoots ...string) ([]ImportedCredential, error) {
	resolved, err := ResolveGrokAuthPath(path, extraRoots...)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		// Avoid echoing absolute path details beyond basename for missing/denied files.
		return nil, fmt.Errorf("import grok auth: read failed: %w", err)
	}
	return ParseGrokAuthJSON(data)
}

// ParseGrokAuthJSON parses the Grok CLI auth.json document.
//
// Accepted shapes:
//  1. Map keyed by "issuer::client_id" → entry (canonical CLI shape)
//  2. Single entry object with key/refresh_token fields
//  3. A bare array, or {"accounts":[...]} / {"credentials":[...]}
//  4. CPA xAI OAuth objects using access_token/expired/sub fields
//
// Object members are decoded sequentially so duplicate top-level names are
// preserved instead of being silently overwritten by map decoding.
func ParseGrokAuthJSON(data []byte) ([]ImportedCredential, error) {
	credentials, _, err := ParseGrokAuthJSONDetailed(data)
	return credentials, err
}

// ParseGrokAuthJSONDetailed also reports field-level warnings. Unknown values
// are never included in diagnostics.
func ParseGrokAuthJSONDetailed(data []byte) ([]ImportedCredential, []ImportWarning, error) {
	data = bytesTrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("import grok auth: empty document")
	}
	switch data[0] {
	case '[':
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return nil, nil, fmt.Errorf("import grok auth: parse array: %w", err)
		}
		credentials, err := normalizeRawEntries(values, "entry")
		return credentials, nil, err
	case '{':
		bare, bareWarnings, err := decodeEntry(data, "default")
		if err != nil {
			return nil, nil, fmt.Errorf("import grok auth: parse: %w", err)
		}
		if entryHasToken(bare) {
			if err := validateCPAType("default", bare); err != nil {
				return nil, nil, err
			}
			credential, err := normalizeEntry("default", bare)
			if err != nil {
				return nil, nil, err
			}
			credential.Warnings = bareWarnings
			return []ImportedCredential{credential}, nil, nil
		}

		members, err := decodeObjectMembers(data)
		if err != nil {
			return nil, nil, fmt.Errorf("import grok auth: parse object: %w", err)
		}
		out := make([]ImportedCredential, 0, len(members))
		var warnings []ImportWarning
		occurrences := make(map[string]int)
		for _, member := range members {
			occurrences[member.Name]++
			source := member.Name
			if occurrences[member.Name] > 1 {
				source = fmt.Sprintf("%s#entry%d", member.Name, occurrences[member.Name])
			}
			if member.Name == "accounts" || member.Name == "credentials" {
				var values []json.RawMessage
				if err := json.Unmarshal(member.Value, &values); err != nil {
					return nil, nil, fmt.Errorf("import grok auth: field %q must be an array", member.Name)
				}
				nested, err := normalizeRawEntries(values, source)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, nested...)
				continue
			}
			if firstNonSpace(member.Value) != '{' {
				warnings = append(warnings, unsupportedFieldWarning("document", member.Name))
				continue
			}
			entry, entryWarnings, err := decodeEntry(member.Value, source)
			if err != nil {
				return nil, nil, fmt.Errorf("import grok auth: field %q: %w", member.Name, err)
			}
			if !entryHasToken(entry) {
				warnings = append(warnings, unsupportedFieldWarning("document", member.Name))
				continue
			}
			if err := validateCPAType(source, entry); err != nil {
				return nil, nil, err
			}
			credential, err := normalizeEntry(source, entry)
			if err != nil {
				return nil, nil, err
			}
			credential.Warnings = entryWarnings
			out = append(out, credential)
		}
		if len(out) == 0 {
			if len(warnings) > 0 {
				fields := make([]string, 0, len(warnings))
				for _, warning := range warnings {
					fields = append(fields, warning.Field)
				}
				return nil, warnings, fmt.Errorf("import grok auth: no credential entries found; unsupported fields: %s", strings.Join(fields, ", "))
			}
			return nil, nil, fmt.Errorf("import grok auth: no credential entries found")
		}
		return out, warnings, nil
	default:
		return nil, nil, fmt.Errorf("import grok auth: expected JSON object or array")
	}
}

// ParseGrokAuthJSONDetailedLimit applies a streaming entry precheck before the
// compatibility parser. The precheck stops at maxEntries+1 and keeps only one
// raw entry at a time, preventing a compact multi-hundred-thousand-entry file
// from allocating the complete normalized credential slice before rejection.
// A non-positive maxEntries preserves the unbounded compatibility behavior.
func ParseGrokAuthJSONDetailedLimit(data []byte, maxEntries int) ([]ImportedCredential, []ImportWarning, error) {
	if maxEntries > 0 {
		count, err := countGrokAuthEntries(data, maxEntries)
		if err != nil {
			return nil, nil, err
		}
		if count > maxEntries {
			return nil, nil, fmt.Errorf("%w (max %d)", ErrImportEntryLimit, maxEntries)
		}
	}
	return ParseGrokAuthJSONDetailed(data)
}

func countGrokAuthEntries(data []byte, limit int) (int, error) {
	data = bytesTrimSpace(data)
	if len(data) == 0 {
		return 0, fmt.Errorf("import grok auth: empty document")
	}
	if data[0] == '[' {
		return countTopLevelArray(data, limit)
	}
	if data[0] != '{' {
		return 0, fmt.Errorf("import grok auth: expected JSON object or array")
	}
	bare, err := topLevelBareHasToken(data)
	if err != nil {
		return 0, fmt.Errorf("import grok auth: parse object: %w", err)
	}
	if bare {
		return 1, nil
	}
	return countCredentialMap(data, limit)
}

func countTopLevelArray(data []byte, limit int) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectJSONDelimiter(decoder, '['); err != nil {
		return 0, err
	}
	count := 0
	for decoder.More() {
		if limit > 0 && count >= limit {
			return limit + 1, nil
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return 0, err
		}
		count++
	}
	if err := finishJSONContainer(decoder, ']'); err != nil {
		return 0, err
	}
	return count, nil
}

func topLevelBareHasToken(data []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return false, err
	}
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return false, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return false, fmt.Errorf("object member name is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return false, err
		}
		if name == "key" || name == "access_token" || name == "refresh_token" {
			var value string
			if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
				return true, nil
			}
		}
	}
	return false, finishJSONContainer(decoder, '}')
}

func countCredentialMap(data []byte, limit int) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return 0, err
	}
	count := 0
	members := 0
	for decoder.More() {
		members++
		if limit > 0 && members > limit+maxImportWarnings {
			// Unsupported scalar/object fields also consume decoder and diagnostic
			// memory. Bound them relative to the same import budget.
			return limit + 1, nil
		}
		nameToken, err := decoder.Token()
		if err != nil {
			return 0, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return 0, fmt.Errorf("object member name is not a string")
		}
		if name == "accounts" || name == "credentials" {
			added, exceeded, err := countArrayFromDecoder(decoder, limit-count)
			if err != nil {
				return 0, fmt.Errorf("field %q must be an array: %w", name, err)
			}
			if exceeded {
				return limit + 1, nil
			}
			count += added
			continue
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return 0, err
		}
		if firstNonSpace(raw) != '{' || !rawEntryHasToken(raw) {
			continue
		}
		count++
		if limit > 0 && count > limit {
			return limit + 1, nil
		}
	}
	if err := finishJSONContainer(decoder, '}'); err != nil {
		return 0, err
	}
	return count, nil
}

func countArrayFromDecoder(decoder *json.Decoder, remaining int) (count int, exceeded bool, err error) {
	if err := expectJSONDelimiter(decoder, '['); err != nil {
		return 0, false, err
	}
	for decoder.More() {
		if remaining >= 0 && count >= remaining {
			return count, true, nil
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return 0, false, err
		}
		count++
	}
	if err := closeJSONContainer(decoder, ']'); err != nil {
		return 0, false, err
	}
	return count, false, nil
}

func rawEntryHasToken(raw []byte) bool {
	var tokenFields struct {
		Key          string `json:"key"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(raw, &tokenFields) != nil {
		return false
	}
	return strings.TrimSpace(tokenFields.Key) != "" ||
		strings.TrimSpace(tokenFields.AccessToken) != "" ||
		strings.TrimSpace(tokenFields.RefreshToken) != ""
}

func expectJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return fmt.Errorf("expected %q", expected)
	}
	return nil
}

func finishJSONContainer(decoder *json.Decoder, expected json.Delim) error {
	if err := closeJSONContainer(decoder, expected); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}

func closeJSONContainer(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return fmt.Errorf("expected %q", expected)
	}
	return nil
}

// ToTokenSet converts an imported credential into a TokenSet.
func (c ImportedCredential) ToTokenSet() TokenSet {
	return TokenSet{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    c.ExpiresAt,
	}
}

func normalizeEntry(sourceKey string, entry GrokAuthEntry) (ImportedCredential, error) {
	access := firstNonEmpty(strings.TrimSpace(entry.Key), strings.TrimSpace(entry.AccessToken))
	refresh := strings.TrimSpace(entry.RefreshToken)
	if access == "" && refresh == "" {
		return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q has no tokens", sourceKey)
	}
	var exp time.Time
	expiresAt := firstNonEmpty(strings.TrimSpace(entry.ExpiresAt), strings.TrimSpace(entry.Expired))
	if expiresAt != "" {
		t, err := parseFlexibleTime(expiresAt)
		if err != nil {
			return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q expires_at: %w", sourceKey, err)
		}
		exp = t
	}
	clientID := strings.TrimSpace(entry.OIDCClientID)
	issuer := strings.TrimSpace(entry.OIDCIssuer)
	if clientID == "" || issuer == "" {
		// Try parse from map key: https://auth.x.ai::b1a00492-...
		if iss, cid, ok := splitSourceKey(strings.SplitN(sourceKey, "#entry", 2)[0]); ok {
			if issuer == "" {
				issuer = iss
			}
			if clientID == "" {
				clientID = cid
			}
		}
	}
	if issuer == "" {
		issuer = Issuer
	}
	trustedIssuer, err := NormalizeTrustedIssuer(issuer)
	if err != nil {
		return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q oidc_issuer: %w", sourceKey, err)
	}
	issuer = trustedIssuer
	if clientID == "" {
		clientID = DefaultClientID
	}
	return ImportedCredential{
		SourceKey:    sourceKey,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    exp,
		Email:        strings.TrimSpace(entry.Email),
		UserID:       firstNonEmpty(strings.TrimSpace(entry.UserID), strings.TrimSpace(entry.PrincipalID), strings.TrimSpace(entry.Sub)),
		TeamID:       strings.TrimSpace(entry.TeamID),
		OIDCIssuer:   issuer,
		OIDCClientID: clientID,
		AuthMode:     strings.TrimSpace(entry.AuthMode),
		Disabled:     entry.Disabled,
		ProxyURL:     firstNonEmpty(strings.TrimSpace(entry.ProxyURL), strings.TrimSpace(entry.Proxy)),
		Raw:          entry,
	}, nil
}

type objectMember struct {
	Name  string
	Value json.RawMessage
}

func decodeObjectMembers(data []byte) ([]objectMember, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, fmt.Errorf("expected object")
	}
	var members []objectMember
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("object member name is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, objectMember{Name: name, Value: value})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	return members, nil
}

func normalizeRawEntries(values []json.RawMessage, prefix string) ([]ImportedCredential, error) {
	out := make([]ImportedCredential, 0, len(values))
	for index, raw := range values {
		source := fmt.Sprintf("%s[%d]", prefix, index)
		entry, warnings, err := decodeEntry(raw, source)
		if err != nil {
			return nil, fmt.Errorf("import grok auth: %s[%d]: %w", prefix, index, err)
		}
		if !entryHasToken(entry) {
			return nil, fmt.Errorf("import grok auth: %s[%d] has no tokens", prefix, index)
		}
		if err := validateCPAType(source, entry); err != nil {
			return nil, err
		}
		credential, err := normalizeEntry(source, entry)
		if err != nil {
			return nil, err
		}
		credential.Warnings = warnings
		out = append(out, credential)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("import grok auth: no credential entries found")
	}
	return out, nil
}

var knownGrokAuthFields = map[string]struct{}{
	"type": {}, "key": {}, "access_token": {}, "auth_mode": {}, "create_time": {},
	"user_id": {}, "email": {}, "first_name": {}, "profile_image_asset_id": {},
	"principal_type": {}, "principal_id": {}, "team_id": {},
	"coding_data_retention_opt_out": {}, "refresh_token": {}, "expires_at": {},
	"expired": {}, "oidc_issuer": {}, "oidc_client_id": {}, "sub": {},
	"disabled": {}, "proxy_url": {}, "proxy": {},
}

func decodeEntry(raw []byte, source string) (GrokAuthEntry, []ImportWarning, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return GrokAuthEntry{}, nil, err
	}
	fields := make(map[string]json.RawMessage, len(knownGrokAuthFields))
	unknownSet := make(map[string]struct{}, maxImportWarnings)
	omittedUnknown := false
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return GrokAuthEntry{}, nil, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return GrokAuthEntry{}, nil, fmt.Errorf("object member name is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return GrokAuthEntry{}, nil, err
		}
		if _, known := knownGrokAuthFields[name]; known {
			fields[name] = append(json.RawMessage(nil), value...)
			continue
		}
		if len(unknownSet) < maxImportWarnings {
			unknownSet[name] = struct{}{}
		} else {
			omittedUnknown = true
		}
	}
	if err := finishJSONContainer(decoder, '}'); err != nil {
		return GrokAuthEntry{}, nil, err
	}
	knownJSON, err := json.Marshal(fields)
	if err != nil {
		return GrokAuthEntry{}, nil, err
	}
	var entry GrokAuthEntry
	if err := json.Unmarshal(knownJSON, &entry); err != nil {
		return GrokAuthEntry{}, nil, err
	}
	unknown := make([]string, 0, len(unknownSet))
	for field := range unknownSet {
		unknown = append(unknown, field)
	}
	sort.Strings(unknown)
	warnings := make([]ImportWarning, 0, len(unknown))
	for _, field := range unknown {
		warnings = append(warnings, unsupportedFieldWarning(source, field))
	}
	if omittedUnknown {
		warnings = append(warnings, ImportWarning{
			Source: source, Field: "*", Message: "additional unsupported fields omitted after warning limit",
		})
	}
	return entry, warnings, nil
}

func validateCPAType(source string, entry GrokAuthEntry) error {
	typeName := strings.ToLower(strings.TrimSpace(entry.Type))
	looksCPA := strings.TrimSpace(entry.Key) == "" && strings.TrimSpace(entry.AccessToken) != "" &&
		(strings.TrimSpace(entry.Expired) != "" || strings.TrimSpace(entry.Sub) != "")
	if typeName != "" && typeName != "xai" {
		return fmt.Errorf("import grok auth: entry %q field %q must be %q", source, "type", "xai")
	}
	if looksCPA && typeName != "xai" {
		return fmt.Errorf("import grok auth: entry %q field %q is required and must be %q for CPA credentials", source, "type", "xai")
	}
	return nil
}

func unsupportedFieldWarning(source, field string) ImportWarning {
	return ImportWarning{Source: source, Field: field, Message: "field is not supported and was ignored"}
}

func firstNonSpace(raw []byte) byte {
	for _, value := range raw {
		switch value {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return value
		}
	}
	return 0
}

func entryHasToken(entry GrokAuthEntry) bool {
	return strings.TrimSpace(entry.Key) != "" ||
		strings.TrimSpace(entry.AccessToken) != "" ||
		strings.TrimSpace(entry.RefreshToken) != ""
}

func splitSourceKey(key string) (issuer, clientID string, ok bool) {
	// Format: https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828
	parts := strings.SplitN(key, "::", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	issuer = strings.TrimSpace(parts[0])
	clientID = strings.TrimSpace(parts[1])
	if issuer == "" || clientID == "" {
		return "", "", false
	}
	return issuer, clientID, true
}

func parseFlexibleTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	}
	var last error
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
		last = err
	}
	return time.Time{}, last
}

func bytesTrimSpace(b []byte) []byte {
	return bytes.TrimSpace(b)
}
