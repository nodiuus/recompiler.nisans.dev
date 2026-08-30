package uploadcache

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"recompiler/backend/internal/analyzer"
)

var ErrNotFound = errors.New("cached upload not found")

type Config struct {
	MaxBytes   int64
	MaxEntries int
	TTL        time.Duration
}

type Entry struct {
	Binary   []byte
	PDB      []byte
	Analysis analyzer.Result
}

type item struct {
	id         string
	digest     [32]byte
	binaryPath string
	pdbPath    string
	size       int64
	lastUsed   time.Time
	analysis   analyzer.Result
}

// Cache keeps large uploads on disk and only loads an entry while a request is
// using it. IDs are random capabilities and never expose a filesystem path.
type Cache struct {
	mu         sync.Mutex
	directory  string
	maxBytes   int64
	maxEntries int
	ttl        time.Duration
	totalBytes int64
	entries    map[string]*item
	byDigest   map[[32]byte]string
}

func New(config Config) (*Cache, error) {
	if config.MaxBytes <= 0 || config.MaxEntries <= 0 || config.TTL <= 0 {
		return nil, errors.New("upload cache limits must be positive")
	}
	directory, err := os.MkdirTemp("", "recompiler-upload-cache-")
	if err != nil {
		return nil, fmt.Errorf("create upload cache: %w", err)
	}
	return &Cache{
		directory:  directory,
		maxBytes:   config.MaxBytes,
		maxEntries: config.MaxEntries,
		ttl:        config.TTL,
		entries:    make(map[string]*item),
		byDigest:   make(map[[32]byte]string),
	}, nil
}

func (cache *Cache) Put(binaryData, pdbData []byte, analysis analyzer.Result) (string, error) {
	size := int64(len(binaryData)) + int64(len(pdbData))
	if size > cache.maxBytes {
		return "", fmt.Errorf("upload pair is larger than the %d MiB cache capacity", cache.maxBytes>>20)
	}
	digest := pairDigest(binaryData, pdbData)

	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := time.Now()
	cache.removeExpired(now)
	if id, ok := cache.byDigest[digest]; ok {
		if existing := cache.entries[id]; existing != nil {
			existing.lastUsed = now
			return id, nil
		}
	}
	for len(cache.entries) >= cache.maxEntries || cache.totalBytes+size > cache.maxBytes {
		if !cache.removeOldest() {
			break
		}
	}

	id, err := randomID()
	if err != nil {
		return "", err
	}
	binaryPath := filepath.Join(cache.directory, id+".bin")
	pdbPath := filepath.Join(cache.directory, id+".pdb")
	if err := writeExclusive(binaryPath, binaryData); err != nil {
		return "", fmt.Errorf("cache binary: %w", err)
	}
	if err := writeExclusive(pdbPath, pdbData); err != nil {
		_ = os.Remove(binaryPath)
		return "", fmt.Errorf("cache PDB: %w", err)
	}
	analysis.CacheID = id
	cache.entries[id] = &item{
		id: id, digest: digest, binaryPath: binaryPath, pdbPath: pdbPath,
		size: size, lastUsed: now, analysis: analysis,
	}
	cache.byDigest[digest] = id
	cache.totalBytes += size
	return id, nil
}

func (cache *Cache) Get(id string) (Entry, error) {
	return cache.get(id, true)
}

// GetBinary avoids reading a potentially very large PDB again after its
// symbols and identity have already been cached in Analysis.
func (cache *Cache) GetBinary(id string) (Entry, error) {
	return cache.get(id, false)
}

func (cache *Cache) get(id string, includePDB bool) (Entry, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.removeExpired(time.Now())
	entry := cache.entries[id]
	if entry == nil {
		return Entry{}, ErrNotFound
	}
	binaryData, err := os.ReadFile(entry.binaryPath)
	if err != nil {
		cache.remove(entry)
		return Entry{}, fmt.Errorf("read cached binary: %w", err)
	}
	var pdbData []byte
	if includePDB {
		pdbData, err = os.ReadFile(entry.pdbPath)
		if err != nil {
			cache.remove(entry)
			return Entry{}, fmt.Errorf("read cached PDB: %w", err)
		}
	}
	entry.lastUsed = time.Now()
	return Entry{Binary: binaryData, PDB: pdbData, Analysis: entry.analysis}, nil
}

func (cache *Cache) Close() error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries = make(map[string]*item)
	cache.byDigest = make(map[[32]byte]string)
	cache.totalBytes = 0
	return os.RemoveAll(cache.directory)
}

func (cache *Cache) removeExpired(now time.Time) {
	for _, entry := range cache.entries {
		if now.Sub(entry.lastUsed) > cache.ttl {
			cache.remove(entry)
		}
	}
}

func (cache *Cache) removeOldest() bool {
	var oldest *item
	for _, entry := range cache.entries {
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) {
			oldest = entry
		}
	}
	if oldest == nil {
		return false
	}
	cache.remove(oldest)
	return true
}

func (cache *Cache) remove(entry *item) {
	delete(cache.entries, entry.id)
	delete(cache.byDigest, entry.digest)
	cache.totalBytes -= entry.size
	_ = os.Remove(entry.binaryPath)
	_ = os.Remove(entry.pdbPath)
}

func pairDigest(binaryData, pdbData []byte) [32]byte {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d:", len(binaryData))
	_, _ = hash.Write(binaryData)
	_, _ = fmt.Fprintf(hash, ":%d:", len(pdbData))
	_, _ = hash.Write(pdbData)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func randomID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate cache ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}
