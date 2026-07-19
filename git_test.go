package main

// Tests for git.go: real git repositories are constructed under t.TempDir() and
// driven with the git CLI so the author-email extraction and new-committer
// tracking are exercised end-to-end against actual git history.

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// runGitCmd runs `git -C dir <args...>` with a fully-pinned author/committer
// identity so %ae in `git log` is deterministic. The author email is set via
// GIT_AUTHOR_EMAIL (git log --format=%ae reports the AUTHOR email, not the
// committer's), and the committer identity is set too so `git commit` succeeds
// in an environment with no global git config.
func runGitCmd(t *testing.T, dir, authorEmail string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL="+authorEmail,
		"GIT_COMMITTER_NAME=Test Author",
		"GIT_COMMITTER_EMAIL="+authorEmail,
		// Neutralise any user config that could inject extra identities.
		"HOME="+dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

// initRepo creates a git repo in a fresh temp dir with `n` commits from the
// given author emails (one commit per email, in order). Returns the repo dir.
func initRepo(t *testing.T, emails ...string) string {
	t.Helper()
	dir := t.TempDir()
	runGitCmd(t, dir, emails[0], "init", "-q")
	for i, email := range emails {
		fname := dir + "/file.txt"
		if err := os.WriteFile(fname, []byte(strings.Repeat("x", i+1)), 0644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		runGitCmd(t, dir, email, "add", "file.txt")
		runGitCmd(t, dir, email, "commit", "-q", "-m", "commit "+email)
	}
	return dir
}

func TestGitKnownCommitters_TwoAuthorsSortedDeduped(t *testing.T) {
	// Commit order b then a; the returned set must be sorted → [a, b].
	dir := initRepo(t, "b@example.com", "a@example.com")

	got, err := gitKnownCommitters(dir)
	if err != nil {
		t.Fatalf("gitKnownCommitters error: %v", err)
	}
	want := []string{"a@example.com", "b@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gitKnownCommitters = %v, want %v", got, want)
	}
}

func TestGitKnownCommitters_Dedup(t *testing.T) {
	// Same author commits twice, plus a second author once → each email appears
	// exactly once, sorted.
	dir := initRepo(t, "a@example.com", "a@example.com", "z@example.com")

	got, err := gitKnownCommitters(dir)
	if err != nil {
		t.Fatalf("gitKnownCommitters error: %v", err)
	}
	want := []string{"a@example.com", "z@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gitKnownCommitters = %v, want %v", got, want)
	}
}

func TestGitKnownCommitters_NonGitDir(t *testing.T) {
	// A plain directory with no .git → (nil, nil), not an error.
	dir := t.TempDir()
	got, err := gitKnownCommitters(dir)
	if err != nil {
		t.Fatalf("expected nil error for non-git dir, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil emails for non-git dir, got %v", got)
	}
}

func TestTrackNewCommitters_FirstScan_Silent(t *testing.T) {
	// First scan (existing == nil): no baseline, so no committer is "new". Nothing
	// prints, but pf.KnownCommitters is seeded with the current author set.
	dir := initRepo(t, "a@example.com", "b@example.com")
	pf := &PackageFiles{Dir: dir, Name: "pkg"}

	out := captureStderr(t, func() {
		trackNewCommitters(pf, nil)
	})
	if strings.Contains(out, "new committer") {
		t.Fatalf("first scan should not warn about new committers, got %q", out)
	}
	if out != "" {
		t.Fatalf("first scan should be silent, got %q", out)
	}

	var got []string
	if err := json.Unmarshal([]byte(pf.KnownCommitters), &got); err != nil {
		t.Fatalf("KnownCommitters not valid JSON (%q): %v", pf.KnownCommitters, err)
	}
	want := []string{"a@example.com", "b@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KnownCommitters = %v, want %v", got, want)
	}
}

func TestTrackNewCommitters_SecondScan_WarnsNewOnly(t *testing.T) {
	// Repo now has two authors; the DB baseline only knew the first. The second,
	// new email must be flagged; the already-known one must not be re-warned. The
	// stored set becomes the merged, sorted union.
	dir := initRepo(t, "a@example.com", "b@example.com")
	pf := &PackageFiles{Dir: dir, Name: "pkg"}
	existing := &DBRecord{KnownCommitters: `["a@example.com"]`}

	out := captureStderr(t, func() {
		trackNewCommitters(pf, existing)
	})

	if !strings.Contains(out, "new committer") {
		t.Fatalf("expected a 'new committer' warning, got %q", out)
	}
	if !strings.Contains(out, "b@example.com") {
		t.Fatalf("expected the new email b@example.com in warning, got %q", out)
	}
	if strings.Contains(out, "a@example.com") {
		t.Fatalf("should not re-warn the already-known a@example.com, got %q", out)
	}
	if !strings.Contains(out, "pkg") {
		t.Fatalf("expected the package name in the warning, got %q", out)
	}

	var got []string
	if err := json.Unmarshal([]byte(pf.KnownCommitters), &got); err != nil {
		t.Fatalf("KnownCommitters not valid JSON (%q): %v", pf.KnownCommitters, err)
	}
	want := []string{"a@example.com", "b@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged KnownCommitters = %v, want %v", got, want)
	}
}

func TestTrackNewCommitters_NonGitDir_NoOp(t *testing.T) {
	// A plain temp dir (no git history): trackNewCommitters returns early without
	// printing anything or setting KnownCommitters.
	dir := t.TempDir()
	pf := &PackageFiles{Dir: dir, Name: "pkg"}

	out := captureStderr(t, func() {
		trackNewCommitters(pf, nil)
	})
	if out != "" {
		t.Fatalf("non-git dir should produce no output, got %q", out)
	}
	if pf.KnownCommitters != "" {
		t.Fatalf("non-git dir should leave KnownCommitters empty, got %q", pf.KnownCommitters)
	}
}
