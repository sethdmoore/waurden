package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// aurGitBase is the base URL clones are pulled from. A var (not a const) so a test
// can point ensureClone at a local upstream repo instead of the live AUR.
var aurGitBase = "https://aur.archlinux.org/"

// runGit executes a git command with a wall-clock timeout, returning its stdout.
// All git use in wAURden is advisory (clones are inert PKGBUILD text we discover
// and diff, never build), so callers treat a non-nil error as "no data" rather
// than fatal. A timeout <= 0 falls back to a sane default so a hung network call
// can never wedge a build gate.
func runGit(timeout int, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "git", args...).Output()
}

// ensureClone makes sure a local clone of the AUR git repo for pkgbase exists
// under cfg.CloneDir and is up to date, returning its directory. The clone is
// inert: wAURden reads PKGBUILD/.SRCINFO text and computes diffs from it, but
// never runs makepkg/prepare/build against it (the authoritative build-time scan
// always reads the on-disk $PWD the helper is about to source, never a clone).
//
// A fresh checkout is a shallow clone (--depth 50 — enough history for diffs and
// gitKnownCommitters while staying small); an existing checkout is refreshed with
// fetch + reset --hard so it exactly mirrors upstream. Errors are returned (the
// caller marks that tree node "error" and keeps going); when a fetch fails but a
// usable stale checkout exists, the stale dir is still returned so a network blip
// doesn't drop a known dependency from the tree.
func ensureClone(cfg Config, pkgbase string) (string, error) {
	base := cfg.CloneDir
	if base == "" {
		return "", fmt.Errorf("no clone dir configured")
	}
	dir := filepath.Join(base, pkgbase)

	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// Existing clone: refresh it. Fetch into FETCH_HEAD (branch-name agnostic —
		// AUR uses master today but we don't hard-code it) then hard-reset the tree
		// to it. Our clones are never edited, so reset --hard only ever fast-forwards.
		if _, err := runGit(cfg.Timeout, "-C", dir, "fetch", "--depth", "50", "origin"); err != nil {
			// Keep the usable (if stale) checkout rather than failing the node.
			return dir, fmt.Errorf("fetch %s: %w", pkgbase, err)
		}
		if _, err := runGit(cfg.Timeout, "-C", dir, "reset", "--hard", "FETCH_HEAD"); err != nil {
			return dir, fmt.Errorf("reset %s: %w", pkgbase, err)
		}
		return dir, nil
	}

	if err := os.MkdirAll(base, 0755); err != nil {
		return "", fmt.Errorf("create clone dir: %w", err)
	}
	url := aurGitBase + pkgbase + ".git"
	if _, err := runGit(cfg.Timeout, "clone", "--depth", "50", url, dir); err != nil {
		return "", fmt.Errorf("clone %s: %w", pkgbase, err)
	}
	return dir, nil
}
