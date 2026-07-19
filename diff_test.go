package main

// Tests for the PKGBUILD-diff feature: git helpers (git.go), the last_scanned_commit
// column round-trip (db.go), and analyze()'s preference for a real git diff.

import (
	"strings"
	"testing"
)

// gitPKGBUILDRepo builds a real git repo with a PKGBUILD committed twice (v1 then
// v2). Returns the dir, the first commit sha, and the HEAD sha.
func gitPKGBUILDRepo(t *testing.T, v1, v2 string) (dir, first, head string) {
	t.Helper()
	dir = t.TempDir()
	runGitCmd(t, dir, "a@example.com", "init", "-q")
	writePKGBUILD(t, dir, v1)
	runGitCmd(t, dir, "a@example.com", "add", "PKGBUILD")
	runGitCmd(t, dir, "a@example.com", "commit", "-q", "-m", "v1")
	out, err := runGit(10, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	first = strings.TrimSpace(string(out))

	writePKGBUILD(t, dir, v2)
	runGitCmd(t, dir, "a@example.com", "add", "PKGBUILD")
	runGitCmd(t, dir, "a@example.com", "commit", "-q", "-m", "v2")
	head, err = gitHeadCommit(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, first, head
}

func TestGitHeadCommit(t *testing.T) {
	dir := initRepo(t, "a@example.com")
	sha, err := gitHeadCommit(dir)
	if err != nil {
		t.Fatalf("gitHeadCommit: %v", err)
	}
	if len(sha) != 40 {
		t.Errorf("HEAD sha = %q, want 40 chars", sha)
	}
	if _, err := gitHeadCommit(t.TempDir()); err == nil {
		t.Error("gitHeadCommit on a non-git dir should error")
	}
}

func TestGitDiffFiles(t *testing.T) {
	dir, first, head := gitPKGBUILDRepo(t,
		"pkgname=foo\npkgver=1\n",
		"pkgname=foo\npkgver=1\nbuild(){ npm install atomic-lockfile; }\n")
	if first == head {
		t.Fatal("expected two distinct commits")
	}
	diff, err := gitDiffFiles(dir, first)
	if err != nil {
		t.Fatalf("gitDiffFiles: %v", err)
	}
	if !strings.Contains(diff, "npm install atomic-lockfile") {
		t.Errorf("diff missing the added line:\n%s", diff)
	}
	if !strings.Contains(diff, "diff --git") {
		t.Errorf("expected a unified git diff, got:\n%s", diff)
	}
}

func TestLastScannedCommitRoundTrip(t *testing.T) {
	db := newTestDB(t)
	rec := DBRecord{
		Name:              "foo",
		PKGBUILDHash:      "abc",
		Verdict:           "ok",
		Provider:          "static (heuristics)",
		LastScannedCommit: "deadbeefcafe",
	}
	if err := upsertRecord(db, rec); err != nil {
		t.Fatalf("upsertRecord: %v", err)
	}
	got, err := lookupRecord(db, "foo")
	if err != nil {
		t.Fatalf("lookupRecord: %v", err)
	}
	if got.LastScannedCommit != "deadbeefcafe" {
		t.Errorf("LastScannedCommit = %q, want deadbeefcafe", got.LastScannedCommit)
	}
}

func TestAnalyze_PrefersGitDiff(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	cfg := Config{Provider: "static", BlockOn: []string{"malicious"}, WarnOn: []string{"suspicious"}}

	dir := t.TempDir()
	runGitCmd(t, dir, "a@example.com", "init", "-q")
	writePKGBUILD(t, dir, "pkgname=foo\npkgver=1\nbuild(){ make; }\n")
	runGitCmd(t, dir, "a@example.com", "add", "PKGBUILD")
	runGitCmd(t, dir, "a@example.com", "commit", "-q", "-m", "v1")

	// First scan: no prior commit → stores the HEAD commit, no git diff yet.
	pf1, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	captureStderr(t, func() {
		if _, err := analyze(cfg, db, pf1, false); err != nil {
			t.Fatalf("first analyze: %v", err)
		}
	})
	rec, _ := lookupRecord(db, pf1.Name)
	if rec.LastScannedCommit == "" {
		t.Fatal("first scan should have stored last_scanned_commit")
	}

	// Change + commit, then re-scan (hash changed → cache miss). The stored diff
	// must be a real git diff spanning the two commits.
	writePKGBUILD(t, dir, "pkgname=foo\npkgver=2\nbuild(){ make; }\n# note\n")
	runGitCmd(t, dir, "a@example.com", "add", "PKGBUILD")
	runGitCmd(t, dir, "a@example.com", "commit", "-q", "-m", "v2")

	pf2, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	captureStderr(t, func() {
		if _, err := analyze(cfg, db, pf2, false); err != nil {
			t.Fatalf("second analyze: %v", err)
		}
	})
	rec2, _ := lookupRecord(db, pf2.Name)
	if !strings.Contains(rec2.Diff, "diff --git") {
		t.Errorf("expected a git diff stored, got:\n%s", rec2.Diff)
	}
	if rec2.LastScannedCommit == rec.LastScannedCommit {
		t.Error("last_scanned_commit should have advanced to the new HEAD")
	}
}
