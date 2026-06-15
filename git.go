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
	current, _ := gitKnownCommitters(pf.Dir)
	if len(current) == 0 {
		// Not a git checkout (or no history): nothing to compare or store.
		return
	}

	var stored []string
	if existing != nil && existing.KnownCommitters != "" {
		_ = json.Unmarshal([]byte(existing.KnownCommitters), &stored)
	}

	known := make(map[string]bool, len(stored))
	for _, e := range stored {
		known[e] = true
	}

	if len(stored) > 0 {
		for _, e := range current {
			if !known[e] {
				fmt.Fprintf(os.Stderr,
					"wAURden: new committer in %s git history: %s — keep a close eye on this package\n",
					pf.Name, e)
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
}
