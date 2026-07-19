package main

import (
	"database/sql"
	"os"
	"strings"
	"testing"
)

// seedPackage upserts a minimal current-state row so summaryAll/summaryTargets
// have something to render. Only the columns those readers touch are set.
func seedPackage(t *testing.T, db *sql.DB, name, lastScanned, verdict string, conf float64, provider string) {
	t.Helper()
	rec := DBRecord{
		Name:        name,
		LastScanned: lastScanned,
		Verdict:     verdict,
		Confidence:  conf,
		Provider:    provider,
	}
	if err := upsertRecord(db, rec); err != nil {
		t.Fatalf("upsertRecord(%s): %v", name, err)
	}
}

// withStdin points os.Stdin at a temp file containing content for the duration of
// f, restoring the original afterward. summaryTargets reads names from stdin.
func withStdin(t *testing.T, content string, f func()) {
	t.Helper()
	old := os.Stdin
	fh, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := fh.WriteString(content); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if _, err := fh.Seek(0, 0); err != nil {
		t.Fatalf("seek stdin: %v", err)
	}
	os.Stdin = fh
	defer func() {
		os.Stdin = old
		fh.Close()
	}()
	f()
}

func TestEventDate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-07-16T17:04:08Z", "2026-07-16"},
		{"2026-01-02T00:00:00Z", "2026-01-02"},
		{"plain-string", "plain-string"}, // no 'T' → unchanged
		{"", ""},
	}
	for _, c := range cases {
		if got := eventDate(c.in); got != c.want {
			t.Errorf("eventDate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEventTime(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-07-16T17:04:08Z", "2026-07-16 17:04"},
		{"2026-07-16T17:04:08", "2026-07-16 17:04"}, // no trailing Z
		{"plainstring", "plainstring"},              // no 'T' → unchanged
		{"2026-07-16T1Z", "2026-07-16 1"},           // short time part handled gracefully
	}
	for _, c := range cases {
		if got := eventTime(c.in); got != c.want {
			t.Errorf("eventTime(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadTargets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"newlines", "foo\nbar\nbaz\n", []string{"foo", "bar", "baz"}},
		{"spaces", "foo bar baz", []string{"foo", "bar", "baz"}},
		{"mixed whitespace", "  foo\t bar \n\n baz  ", []string{"foo", "bar", "baz"}},
		{"empty", "", nil},
		{"whitespace only", "  \n\t ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := readTargets(strings.NewReader(c.in))
			if len(got) != len(c.want) {
				t.Fatalf("readTargets(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("readTargets(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestSummaryTargetsAllOK(t *testing.T) {
	db := newTestDB(t)
	seedPackage(t, db, "foo", "2026-07-15T10:00:00Z", "ok", 1.0, "static (heuristics)")
	seedPackage(t, db, "bar", "2026-07-15T11:00:00Z", "ok", 0.90, "static (heuristics)")

	cfg := Config{Provider: "static"}
	out := captureStderr(t, func() {
		withStdin(t, "foo bar\n", func() { summaryTargets(db, cfg) })
	})

	if !strings.Contains(out, "wAURden summary") {
		t.Errorf("missing summary header; got:\n%s", out)
	}
	if !strings.Contains(out, "foo") || !strings.Contains(out, "bar") {
		t.Errorf("missing package names; got:\n%s", out)
	}
	if !strings.Contains(out, "all 2 package(s) scanned OK") {
		t.Errorf("missing all-OK line; got:\n%s", out)
	}
	// The static label is rendered once in the header.
	if !strings.Contains(out, "static (heuristics)") {
		t.Errorf("missing provider label; got:\n%s", out)
	}
}

func TestSummaryTargetsNonOK(t *testing.T) {
	db := newTestDB(t)
	seedPackage(t, db, "foo", "2026-07-15T10:00:00Z", "ok", 1.0, "static (heuristics)")
	seedPackage(t, db, "bad", "2026-07-15T11:00:00Z", "malicious", 0.99, "static (heuristics)")

	cfg := Config{Provider: "static"}
	out := captureStderr(t, func() {
		withStdin(t, "foo bad\n", func() { summaryTargets(db, cfg) })
	})

	if !strings.Contains(out, "review the non-OK") {
		t.Errorf("missing non-OK review warning; got:\n%s", out)
	}
	if strings.Contains(out, "scanned OK") {
		t.Errorf("should NOT report all scanned OK when a verdict is non-OK; got:\n%s", out)
	}
	// The blocked package's verdict is uppercased in the recap.
	if !strings.Contains(out, "MALICIOUS") {
		t.Errorf("missing MALICIOUS verdict; got:\n%s", out)
	}
}

func TestSummaryTargetsRepoOnlySilent(t *testing.T) {
	db := newTestDB(t)
	seedPackage(t, db, "foo", "2026-07-15T10:00:00Z", "ok", 1.0, "static (heuristics)")

	cfg := Config{Provider: "static"}
	// glibc was never scanned by wAURden → not in the DB → nothing printed.
	out := captureStderr(t, func() {
		withStdin(t, "glibc coreutils\n", func() { summaryTargets(db, cfg) })
	})
	if out != "" {
		t.Errorf("repo-only transaction should stay silent; got:\n%s", out)
	}
}

func TestSummaryTargetsEmptyStdin(t *testing.T) {
	db := newTestDB(t)
	seedPackage(t, db, "foo", "2026-07-15T10:00:00Z", "ok", 1.0, "static (heuristics)")

	cfg := Config{Provider: "static"}
	out := captureStderr(t, func() {
		withStdin(t, "", func() { summaryTargets(db, cfg) })
	})
	if out != "" {
		t.Errorf("empty stdin should print nothing; got:\n%s", out)
	}
}

func TestSummaryAllEmpty(t *testing.T) {
	db := newTestDB(t)
	out := captureStdout(t, func() { summaryAll(db) })
	if !strings.Contains(out, "No packages scanned yet.") {
		t.Errorf("empty DB should report none scanned; got:\n%s", out)
	}
}

func TestSummaryAll(t *testing.T) {
	db := newTestDB(t)
	seedPackage(t, db, "firefox", "2026-07-14T09:00:00Z", "ok", 0.92, "anthropic/claude")
	seedPackage(t, db, "some-pkg", "2026-07-16T09:00:00Z", "suspicious", 0.71, "openai/llama")
	seedPackage(t, db, "bad-pkg", "2026-07-15T09:00:00Z", "malicious", 0.99, "static (heuristics)")

	// Also record a blocked scan so the "Recent blocks" section appears.
	if err := recordScan(db, "bad-pkg", "hash123", "static (heuristics)",
		Verdict{Verdict: "malicious", Confidence: 0.99, Summary: "curl|sh in prepare()"}, true); err != nil {
		t.Fatalf("recordScan: %v", err)
	}

	out := captureStdout(t, func() { summaryAll(db) })

	// Header columns.
	for _, col := range []string{"PACKAGE", "VERDICT", "CONF", "PROVIDER", "SCANNED"} {
		if !strings.Contains(out, col) {
			t.Errorf("missing header column %q; got:\n%s", col, out)
		}
	}
	// Package names.
	for _, name := range []string{"firefox", "some-pkg", "bad-pkg"} {
		if !strings.Contains(out, name) {
			t.Errorf("missing package %q; got:\n%s", name, out)
		}
	}
	// Verdicts are uppercased.
	if !strings.Contains(out, "SUSPICIOUS") || !strings.Contains(out, "MALICIOUS") {
		t.Errorf("verdicts should be uppercased; got:\n%s", out)
	}
	// Only the date is shown, not the full RFC3339 timestamp.
	if !strings.Contains(out, "2026-07-16") {
		t.Errorf("missing scan date; got:\n%s", out)
	}
	if strings.Contains(out, "2026-07-16T09:00:00Z") {
		t.Errorf("full timestamp should be trimmed to date; got:\n%s", out)
	}
	// Recent blocks section lists the blocked scan.
	if !strings.Contains(out, "Recent blocks") {
		t.Errorf("missing Recent blocks section; got:\n%s", out)
	}
	if !strings.Contains(out, "bad-pkg") || !strings.Contains(out, "curl|sh in prepare()") {
		t.Errorf("recent blocks should list the blocked scan; got:\n%s", out)
	}
}

func TestSummaryHistoryEmpty(t *testing.T) {
	db := newTestDB(t)
	out := captureStdout(t, func() { summaryHistory(db) })
	if !strings.Contains(out, "No scans recorded yet.") {
		t.Errorf("empty scans should report none recorded; got:\n%s", out)
	}
}

func TestSummaryHistory(t *testing.T) {
	db := newTestDB(t)
	if err := recordScan(db, "goodpkg", "h1", "static (heuristics)",
		Verdict{Verdict: "ok", Confidence: 0.85, Summary: "clean"}, false); err != nil {
		t.Fatalf("recordScan ok: %v", err)
	}
	if err := recordScan(db, "evilpkg", "h2", "static (heuristics)",
		Verdict{Verdict: "malicious", Confidence: 0.95, Summary: "reverse shell"}, true); err != nil {
		t.Fatalf("recordScan blocked: %v", err)
	}

	out := captureStdout(t, func() { summaryHistory(db) })

	for _, col := range []string{"WHEN", "PACKAGE", "VERDICT", "CONF", "BLOCKED", "PROVIDER"} {
		if !strings.Contains(out, col) {
			t.Errorf("missing header column %q; got:\n%s", col, out)
		}
	}
	if !strings.Contains(out, "goodpkg") || !strings.Contains(out, "evilpkg") {
		t.Errorf("missing packages in history; got:\n%s", out)
	}
	// The blocked event shows BLOCKED; verdicts uppercased.
	if !strings.Contains(out, "BLOCKED") {
		t.Errorf("blocked scan should show BLOCKED; got:\n%s", out)
	}
	if !strings.Contains(out, "MALICIOUS") || !strings.Contains(out, "OK") {
		t.Errorf("verdicts should be uppercased; got:\n%s", out)
	}
}
