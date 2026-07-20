package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

func runGate(cfg Config, db *sql.DB, pf PackageFiles) (Verdict, bool, error) {
	// gate never force-rescans: the makepkg hook passes no flags, and the cache is
	// the whole point of the fast path. scan --force is the re-scan entry point.
	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		return v, false, err
	}

	blocked := policyBlocks(cfg, v)

	for _, w := range cfg.WarnOn {
		if strings.EqualFold(v.Verdict, w) {
			fmt.Fprintf(os.Stderr, "wAURden WARNING: package %q verdict is %s\n", pf.Name, v.Verdict)
			break
		}
	}

	return v, blocked, nil
}

// policyBlocks reports whether a verdict matches the configured block_on set.
// This is the "would this build be stopped" decision, recorded in scan history.
func policyBlocks(cfg Config, v Verdict) bool {
	for _, b := range cfg.BlockOn {
		if strings.EqualFold(v.Verdict, b) {
			return true
		}
	}
	return false
}

// policyWarns reports whether a verdict matches the configured warn_on set — a
// flagged-but-not-blocked verdict the user should be forced to acknowledge.
func policyWarns(cfg Config, v Verdict) bool {
	for _, w := range cfg.WarnOn {
		if strings.EqualFold(v.Verdict, w) {
			return true
		}
	}
	return false
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
