package main

import (
	"bytes"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// newTestDB opens a fresh, migrated wAURden database in a per-test temp dir and
// registers cleanup. Every schema object (packages, scans, token_usage, indexes,
// column migrations) is created, exactly as production openDB does, so tests
// exercise the real schema rather than a hand-rolled subset.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "waurden.db"), 7)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// captureStdout redirects os.Stdout for the duration of f and returns everything
// written to it. Used to assert on the human-facing report/table output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	return capture(t, &os.Stdout, f)
}

// captureStderr redirects os.Stderr for the duration of f and returns everything
// written to it. Warnings and per-package status lines go to stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	return capture(t, &os.Stderr, f)
}

func capture(t *testing.T, stream **os.File, f func()) string {
	t.Helper()
	old := *stream
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	*stream = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, r)
		done <- b.String()
	}()
	defer func() {
		w.Close()
		*stream = old
	}()
	f()
	w.Close()
	*stream = old
	return <-done
}

// sampleDir resolves a tests/samples/<name> directory relative to the package root.
func sampleDir(name string) string {
	return filepath.Join("tests", "samples", name)
}
