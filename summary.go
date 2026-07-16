package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// runSummary renders the verdict cache. With no arguments it prints the full
// table of every scanned package (newest first) to stdout. With --targets it
// reads pacman's package list on stdin and prints a compact recap of just those
// packages to stderr — this is the end-of-run report the pacman PreTransaction
// hook fires once, after all the concurrent makepkg gate processes have run and
// their per-package lines have scrolled past.
func runSummary(args []string) {
	targets := false
	history := false
	for _, a := range args {
		switch a {
		case "--targets":
			targets = true
		case "--history":
			history = true
		}
	}

	// The pacman hook runs as root; the scans wrote to the invoking user's DB.
	// Point HOME at that user so loadConfig resolves their config + db_path
	// (matching configExistsAnywhere's $SUDO_USER handling).
	if home := effectiveHome(); home != "" {
		os.Setenv("HOME", home)
	}

	cfg, _, err := loadConfig()
	if err != nil {
		// A summary is advisory only — never fail a pacman transaction over it.
		if targets {
			return
		}
		fmt.Fprintf(os.Stderr, "wAURden: config error: %v\n", err)
		os.Exit(1)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		if targets {
			return
		}
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if targets {
		summaryTargets(db, cfg)
		return
	}
	if history {
		summaryHistory(db)
		return
	}
	summaryAll(db)
}

// summaryTargets prints a compact recap of the packages named on stdin that
// exist in the DB. Packages not in the DB (repo-only upgrades, anything wAURden
// never scanned) are silently skipped; if none match, nothing is printed, so a
// plain `pacman -Syu` of official packages stays quiet.
func summaryTargets(db *sql.DB, cfg Config) {
	names := readTargets(os.Stdin)
	if len(names) == 0 {
		return
	}

	var recs []*DBRecord
	seen := make(map[string]bool)
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		r, err := lookupRecord(db, n)
		if err != nil || r == nil {
			continue
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return // nothing wAURden scanned in this transaction — stay silent
	}

	// The model is stated once, here in the header, rather than on every
	// per-package gate line (see analyze.go's scanning line).
	fmt.Fprintf(os.Stderr, "── wAURden summary · %s ──\n", providerLabel(cfg))

	tw := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
	allOK := true
	for _, r := range recs {
		if !strings.EqualFold(r.Verdict, "ok") {
			allOK = false
		}
		fmt.Fprintf(tw, "  %s\t%s\t%.2f\n", r.Name, strings.ToUpper(r.Verdict), r.Confidence)
	}
	tw.Flush()

	if allOK {
		fmt.Fprintf(os.Stderr, "  all %d package(s) scanned OK\n", len(recs))
	} else {
		fmt.Fprintf(os.Stderr, "  ⚠ review the non-OK verdict(s) above before trusting these packages\n")
	}
}

// summaryAll prints every DB row sorted by last_scanned, newest first.
func summaryAll(db *sql.DB) {
	rows, err := db.Query(`SELECT name, COALESCE(verdict,''), COALESCE(confidence,0),
		COALESCE(provider,''), COALESCE(last_scanned,'')
		FROM packages ORDER BY last_scanned DESC`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db query error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERDICT\tCONF\tPROVIDER\tSCANNED")
	n := 0
	for rows.Next() {
		var name, verdict, provider, scanned string
		var conf float64
		if err := rows.Scan(&name, &verdict, &conf, &provider, &scanned); err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: db scan error: %v\n", err)
			os.Exit(1)
		}
		// last_scanned is RFC3339; keep just the date for a compact column.
		if i := strings.IndexByte(scanned, 'T'); i > 0 {
			scanned = scanned[:i]
		}
		fmt.Fprintf(tw, "%s\t%s\t%.2f\t%s\t%s\n", name, strings.ToUpper(verdict), conf, provider, scanned)
		n++
	}
	tw.Flush()
	if n == 0 {
		fmt.Println("No packages scanned yet.")
		return
	}

	// The packages table above is current state (one row per package, overwritten
	// on re-scan). Surface any recent blocks from the append-only history so a
	// block that scrolled past in a build is visible without hunting for it.
	blocks, err := recentScans(db, true, 10)
	if err == nil && len(blocks) > 0 {
		fmt.Printf("\nRecent blocks (%d shown, full history: waurden summary --history):\n", len(blocks))
		for _, e := range blocks {
			fmt.Printf("  %s  %s  (%.2f)  %s\n", eventDate(e.ScannedAt), e.Package, e.Confidence, truncate(e.Summary))
		}
	}
}

// summaryHistory prints the append-only scan history, newest first — the durable
// record of every scan and block, which the packages cache cannot keep.
func summaryHistory(db *sql.DB) {
	events, err := recentScans(db, false, 200)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db query error: %v\n", err)
		os.Exit(1)
	}
	if len(events) == 0 {
		fmt.Println("No scans recorded yet.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tPACKAGE\tVERDICT\tCONF\tBLOCKED\tPROVIDER")
	for _, e := range events {
		blocked := ""
		if e.Blocked {
			blocked = "BLOCKED"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.2f\t%s\t%s\n",
			eventTime(e.ScannedAt), e.Package, strings.ToUpper(e.Verdict), e.Confidence, blocked, e.Provider)
	}
	tw.Flush()
}

// eventDate/eventTime render an RFC3339 timestamp for the history columns:
// eventDate keeps the date, eventTime keeps date + minute.
func eventDate(ts string) string {
	if i := strings.IndexByte(ts, 'T'); i > 0 {
		return ts[:i]
	}
	return ts
}

func eventTime(ts string) string {
	// 2026-07-16T17:04:08Z -> 2026-07-16 17:04
	ts = strings.TrimSuffix(ts, "Z")
	if i := strings.IndexByte(ts, 'T'); i > 0 {
		date := ts[:i]
		rest := ts[i+1:]
		if len(rest) >= 5 {
			rest = rest[:5]
		}
		return date + " " + rest
	}
	return ts
}

// readTargets reads whitespace-separated package names from r. pacman's
// NeedsTargets pipes one target per line; strings.Fields tolerates either.
func readTargets(r io.Reader) []string {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}
