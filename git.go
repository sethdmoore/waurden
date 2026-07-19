package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// gitKnownCommitters returns the deduplicated, sorted set of author emails from
// the full git log of dir. It returns nil, nil when dir is not a git checkout
// (or git is unavailable, or there is no history) — committer tracking is a
// best-effort identity signal, never a hard error.
func gitKnownCommitters(dir string) ([]string, error) {
	out, err := exec.Command("git", "-C", dir, "log", "--format=%ae").Output()
	if err != nil {
		// Not a git repo, no commits, or git missing — treat as "no history".
		return nil, nil
	}

	seen := make(map[string]bool)
	var emails []string
	for _, line := range strings.Split(string(out), "\n") {
		email := strings.TrimSpace(line)
		if email == "" || seen[email] {
			continue
		}
		seen[email] = true
		emails = append(emails, email)
	}
	sort.Strings(emails)
	return emails, nil
}

// gitHeadCommit returns the current HEAD commit SHA of dir, or "" (with an error)
// when dir is not a git checkout. The live makepkg build dir and wAURden's own
// clones are both git repos, so this is the anchor for PKGBUILD diffs.
func gitHeadCommit(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitDiffFiles returns the git diff of the build-relevant files (PKGBUILD,
// .SRCINFO, and any *.install scriptlets) between the from commit and the current
// HEAD. This is what an "Atomic Arch"-style update shows up in: N innocent commits
// then one adding `npm install atomic-lockfile`. Returns "" (with an error) when
// the range can't be computed — e.g. from is outside a shallow clone's history —
// so the caller can fall back to the whole-file line diff.
func gitDiffFiles(dir, from string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "diff", from+"..HEAD",
		"--", "PKGBUILD", ".SRCINFO", "*.install").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// trackNewCommitters compares the package's git author history against the set
// recorded by a previous scan, warns (informationally) about any email that has
// never appeared before, and stages the merged set on pf.KnownCommitters so it
// is persisted on the next upsert. This is a cautionary identity signal only —
// it never changes the verdict or blocks the build.
//
// On the first scan of a package there is no prior baseline, so every committer
// would otherwise look "new"; we stay silent in that case and simply record the
// baseline. From then on, only genuinely new emails are flagged.
func trackNewCommitters(pf *PackageFiles, existing *DBRecord) {
	for _, msg := range collectNewCommitters(pf, existing) {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// collectNewCommitters does the work of trackNewCommitters but returns the
// warning lines instead of printing them, and still stages the merged committer
// set on pf.KnownCommitters. The tree gate uses this so per-node warnings can be
// buffered and printed after the live tree render (interleaving stderr mid-render
// would corrupt the in-place cursor math); the single-package path wraps it above.
func collectNewCommitters(pf *PackageFiles, existing *DBRecord) []string {
	current, _ := gitKnownCommitters(pf.Dir)
	if len(current) == 0 {
		// Not a git checkout (or no history): nothing to compare or store.
		return nil
	}

	var stored []string
	if existing != nil && existing.KnownCommitters != "" {
		_ = json.Unmarshal([]byte(existing.KnownCommitters), &stored)
	}

	known := make(map[string]bool, len(stored))
	for _, e := range stored {
		known[e] = true
	}

	var msgs []string
	if len(stored) > 0 {
		for _, e := range current {
			if !known[e] {
				msgs = append(msgs, fmt.Sprintf(
					"wAURden: new committer in %s git history: %s — keep a close eye on this package",
					pf.Name, e))
			}
		}
	}

	// Persist current ∪ stored so each email is only ever flagged once.
	for _, e := range current {
		known[e] = true
	}
	merged := make([]string, 0, len(known))
	for e := range known {
		merged = append(merged, e)
	}
	sort.Strings(merged)
	if b, err := json.Marshal(merged); err == nil {
		pf.KnownCommitters = string(b)
	}
	return msgs
}
