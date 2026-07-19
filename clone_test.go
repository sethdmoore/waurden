package main

// Tests for clone.go. ensureClone is exercised against a real local "upstream"
// git repo (via the aurGitBase seam) so the clone/fetch/reset paths run without
// touching the live AUR.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeUpstream creates a real (non-bare) git repo that ensureClone can clone/fetch
// from, containing a PKGBUILD with the given content. Returns the repo dir.
func makeUpstream(t *testing.T, pkgbase, pkgbuild string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), pkgbase+".git")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, dir, "up@example.com", "init", "-q")
	writePKGBUILD(t, dir, pkgbuild)
	runGitCmd(t, dir, "up@example.com", "add", "PKGBUILD")
	runGitCmd(t, dir, "up@example.com", "commit", "-q", "-m", "initial")
	return dir
}

// withAURGitBase points ensureClone at base for the duration of the test.
func withAURGitBase(t *testing.T, base string) {
	t.Helper()
	old := aurGitBase
	aurGitBase = base
	t.Cleanup(func() { aurGitBase = old })
}

func TestRunGit(t *testing.T) {
	dir := initRepo(t, "a@example.com")
	out, err := runGit(10, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("runGit rev-parse: %v", err)
	}
	if len(strings.TrimSpace(string(out))) != 40 {
		t.Errorf("rev-parse output = %q, want a 40-char sha", out)
	}
	if _, err := runGit(10, "-C", dir, "not-a-git-command"); err == nil {
		t.Error("runGit should return an error for a bad git subcommand")
	}
}

func TestEnsureClone_FreshFromLocalUpstream(t *testing.T) {
	upstream := makeUpstream(t, "mypkg", "pkgname=mypkg\npkgver=1\n")
	// aurGitBase + pkgbase + ".git" must resolve to the upstream. The upstream dir
	// is named "mypkg.git", so point the base at its parent (with a trailing slash).
	base := "file://" + filepath.Dir(upstream) + "/"
	withAURGitBase(t, base)

	cfg := Config{Timeout: 30, CloneDir: t.TempDir()}
	dir, err := ensureClone(cfg, "mypkg")
	if err != nil {
		t.Fatalf("ensureClone: %v", err)
	}
	if dir != filepath.Join(cfg.CloneDir, "mypkg") {
		t.Errorf("clone dir = %q, want %q", dir, filepath.Join(cfg.CloneDir, "mypkg"))
	}
	if got := readFileString(filepath.Join(dir, "PKGBUILD")); !strings.Contains(got, "pkgname=mypkg") {
		t.Errorf("cloned PKGBUILD = %q, want it to contain pkgname=mypkg", got)
	}
}

func TestEnsureClone_RefreshExisting(t *testing.T) {
	upstream := makeUpstream(t, "refresh", "pkgname=refresh\npkgver=1\n")
	base := "file://" + filepath.Dir(upstream) + "/"
	withAURGitBase(t, base)

	cfg := Config{Timeout: 30, CloneDir: t.TempDir()}
	// First call clones.
	dir, err := ensureClone(cfg, "refresh")
	if err != nil {
		t.Fatalf("first ensureClone: %v", err)
	}

	// Advance the upstream with a new commit.
	writePKGBUILD(t, upstream, "pkgname=refresh\npkgver=2\n# updated\n")
	runGitCmd(t, upstream, "up@example.com", "add", "PKGBUILD")
	runGitCmd(t, upstream, "up@example.com", "commit", "-q", "-m", "bump")

	// Second call must fetch + reset --hard to the new upstream HEAD.
	if _, err := ensureClone(cfg, "refresh"); err != nil {
		t.Fatalf("refresh ensureClone: %v", err)
	}
	if got := readFileString(filepath.Join(dir, "PKGBUILD")); !strings.Contains(got, "pkgver=2") {
		t.Errorf("after refresh PKGBUILD = %q, want the bumped pkgver=2", got)
	}
}

func TestEnsureClone_NoCloneDir(t *testing.T) {
	if _, err := ensureClone(Config{Timeout: 5}, "x"); err == nil {
		t.Error("ensureClone with an empty CloneDir should error")
	}
}
