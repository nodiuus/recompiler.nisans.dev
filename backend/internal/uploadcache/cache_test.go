package uploadcache

import (
	"errors"
	"testing"
	"time"

	"recompiler/backend/internal/analyzer"
)

func TestPutGetAndDeduplicate(t *testing.T) {
	cache, err := New(Config{MaxBytes: 1024, MaxEntries: 2, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	analysis := analyzer.Result{Binary: analyzer.BinaryInfo{Machine: "x86-64"}}
	id, err := cache.Put([]byte("binary"), []byte("pdb"), analysis)
	if err != nil {
		t.Fatal(err)
	}
	duplicateID, err := cache.Put([]byte("binary"), []byte("pdb"), analysis)
	if err != nil {
		t.Fatal(err)
	}
	if duplicateID != id {
		t.Fatalf("duplicate ID = %q, want %q", duplicateID, id)
	}

	entry, err := cache.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(entry.Binary) != "binary" || string(entry.PDB) != "pdb" || entry.Analysis.CacheID != id {
		t.Fatalf("unexpected cached entry: %+v", entry)
	}
}

func TestOldestEntryIsEvicted(t *testing.T) {
	cache, err := New(Config{MaxBytes: 1024, MaxEntries: 1, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	first, err := cache.Put([]byte("first"), []byte("pdb"), analyzer.Result{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Put([]byte("second"), []byte("pdb"), analyzer.Result{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("first entry error = %v, want ErrNotFound", err)
	}
	if _, err := cache.Get(second); err != nil {
		t.Fatalf("second entry: %v", err)
	}
}

func TestPutAndGetWithoutPDB(t *testing.T) {
	cache, err := New(Config{MaxBytes: 1024, MaxEntries: 1, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	id, err := cache.Put([]byte("binary"), nil, analyzer.Result{})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := cache.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.PDB) != 0 {
		t.Fatalf("cached PDB length = %d, want 0", len(entry.PDB))
	}
}
