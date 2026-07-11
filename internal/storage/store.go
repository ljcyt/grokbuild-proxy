// Package storage provides file-backed credential and client-key persistence.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

const (
	credentialsFile = "credentials.json"
	clientsFile     = "clients.json"
	metaFile        = "meta.json"
	settingsFile    = "settings.json"
	fileMode        = 0o600
	dirMode         = 0o700

	// Bounds how long an in-place external edit that preserves size, timestamp,
	// and file identity can remain hidden by the credential cache.
	credentialCacheMaxAge = time.Second
)

// Store is a mutex + flock protected JSON file store under DataDir.
type Store struct {
	dir string

	mu   sync.Mutex
	lock *os.File

	// credentialsCache and credentialsIndex are guarded by mu. The instance
	// lock guarantees this process is the only Store writer, while the file
	// stamp invalidates the cache after ordinary operator edits or replacements.
	// Keeping both the original slice and a first-ID index preserves malformed
	// duplicate-ID file behavior while making repeated guards O(1).
	credentialsCache      []Credential
	credentialsIndex      map[string]Credential
	credentialsCacheStamp fileStamp
	credentialsCacheValid bool
	credentialsCacheAt    time.Time
}

type fileStamp struct {
	exists           bool
	size             int64
	modifiedUnixNano int64
	info             os.FileInfo
}

func statFileStamp(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileStamp{}, nil
		}
		return fileStamp{}, err
	}
	return fileStamp{
		exists:           true,
		size:             info.Size(),
		modifiedUnixNano: info.ModTime().UnixNano(),
		info:             info,
	}, nil
}

func sameFileStamp(left, right fileStamp) bool {
	if left.exists != right.exists || left.size != right.size ||
		left.modifiedUnixNano != right.modifiedUnixNano {
		return false
	}
	if !left.exists {
		return true
	}
	return left.info != nil && right.info != nil && os.SameFile(left.info, right.info)
}

// New creates a Store rooted at dir. The directory is created with mode 0700.
func New(dir string) (*Store, error) {
	dir = filepath.Clean(dir)
	if dir == "" || dir == "." {
		return nil, fmt.Errorf("storage: data dir is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve data dir %s: %w", dir, err)
	}
	if err := validateDataDir(abs); err != nil {
		return nil, err
	}
	info, statErr := os.Stat(abs)
	switch {
	case statErr == nil:
		if !info.IsDir() {
			return nil, fmt.Errorf("storage: data dir %s is not a directory", abs)
		}
		// Never chmod an existing operator-owned directory.
	case os.IsNotExist(statErr):
		if err := os.MkdirAll(abs, dirMode); err != nil {
			return nil, fmt.Errorf("storage: mkdir %s: %w", abs, err)
		}
		if err := os.Chmod(abs, dirMode); err != nil {
			return nil, fmt.Errorf("storage: chmod new dir %s: %w", abs, err)
		}
	default:
		return nil, fmt.Errorf("storage: stat data dir %s: %w", abs, statErr)
	}
	instanceLock, err := os.OpenFile(filepath.Join(abs, ".instance.lock"), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("storage: open instance lock: %w", err)
	}
	if err := lockFile(instanceLock, true); err != nil {
		_ = instanceLock.Close()
		if isLockBusy(err) {
			return nil, fmt.Errorf("storage: data dir %s is already in use by another process", abs)
		}
		return nil, fmt.Errorf("storage: lock data dir: %w", err)
	}
	return &Store{dir: abs, lock: instanceLock}, nil
}

func validateDataDir(abs string) error {
	clean := filepath.Clean(abs)
	if isFilesystemRoot(clean) {
		return fmt.Errorf("storage: refusing filesystem root as data dir")
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		clean = filepath.Clean(resolved)
		if isFilesystemRoot(clean) {
			return fmt.Errorf("storage: refusing filesystem root as data dir")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homeAbs, err := filepath.Abs(home)
		if err == nil && clean == filepath.Clean(homeAbs) {
			return fmt.Errorf("storage: refusing user home as data dir; choose a dedicated subdirectory")
		}
	}
	return nil
}

func isFilesystemRoot(path string) bool {
	volume := filepath.VolumeName(path)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(path) == filepath.Clean(root)
}

// DataDir returns the store root path.
func (s *Store) DataDir() string {
	return s.dir
}

// Close releases the lifetime lock for the data directory.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	_ = unlockFile(s.lock)
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *Store) credentialsPath() string {
	return filepath.Join(s.dir, credentialsFile)
}

func (s *Store) clientsPath() string {
	return filepath.Join(s.dir, clientsFile)
}

func (s *Store) metaPath() string {
	return filepath.Join(s.dir, metaFile)
}

func (s *Store) settingsPath() string {
	return filepath.Join(s.dir, settingsFile)
}

// withLock serializes all store operations with process-local mutex and
// cross-process flock on a lock file under data dir.
func (s *Store) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return fmt.Errorf("storage: store is closed")
	}

	lockPath := filepath.Join(s.dir, ".store.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return fmt.Errorf("storage: open lock: %w", err)
	}
	defer f.Close()

	if err := lockFile(f, false); err != nil {
		return fmt.Errorf("storage: flock: %w", err)
	}
	defer unlockFile(f) //nolint:errcheck

	return fn()
}

// atomicWrite writes data to path with mode 0600 via tmp + rename.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if previous, err := os.ReadFile(path); err == nil {
		// Never replace a known-good backup with a corrupt/truncated primary.
		if json.Valid(previous) {
			if err := writeBackup(path+".bak", previous); err != nil {
				return fmt.Errorf("backup existing file: %w", err)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read existing file for backup: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	cleanup = false
	// Best-effort final mode (rename preserves tmp mode already set).
	_ = os.Chmod(path, fileMode)
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func writeBackup(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bak-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func readJSONFile(path string, dest any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if recovered := readBackupJSON(path, dest); recovered == nil {
			return nil
		}
		if os.IsNotExist(err) {
			return err
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := unmarshalFresh(data, dest); err != nil {
		if recovered := readBackupJSON(path, dest); recovered == nil {
			return nil
		}
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func readBackupJSON(path string, dest any) error {
	data, err := os.ReadFile(path + ".bak")
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("empty backup")
	}
	return unmarshalFresh(data, dest)
}

func unmarshalFresh(data []byte, dest any) error {
	value := reflect.ValueOf(dest)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return json.Unmarshal(data, dest)
	}
	fresh := reflect.New(value.Elem().Type())
	if err := json.Unmarshal(data, fresh.Interface()); err != nil {
		return err
	}
	value.Elem().Set(fresh.Elem())
	return nil
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	data = append(data, '\n')
	return atomicWrite(path, data)
}

// nowUTC returns current UTC time truncated to seconds for stable JSON.
func nowUTC() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}
