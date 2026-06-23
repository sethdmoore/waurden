package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const version = "0.1.0"

const makepkgHook = `# Installed by wAURden. Scans the PKGBUILD in the current directory before
# makepkg builds it, and aborts the build on a malicious verdict.
if [ -f "$PWD/PKGBUILD" ] && command -v waurden >/dev/null 2>&1; then
    waurden gate "$PWD" || {
        echo "wAURden: refusing to build this package (see findings above)" >&2
        exit 1
    }
fi
`

const pacmanHook = `[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = wAURden: scanning package install scriptlets...
When = PreTransaction
Exec = /usr/bin/waurden gate
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	initHeuristics()

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version":
		fmt.Println(versionString())
	case "scan":
		runScan(args)
	case "gate":
		runGateCmd(args)
	case "show":
		runShow(args)
	case "forget":
		runForget(args)
	case "allow":
		runAllow(args)
	case "configure":
		runConfigureCmd()
	case "install-hooks":
		runInstallHooks()
	case "uninstall-hooks":
		runUninstallHooks()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `wAURden — your guardian for the AUR

Usage:
  waurden configure          set up an LLM provider (required before first use)
  waurden scan [DIR] [--force]  scan package dir (default: .), print report
                             --force (alias --no-cache) ignores the cached verdict
  waurden gate [DIR]         scan + enforce policy; exit 1 if blocked
  waurden show <pkgname>     print stored DB record for a package
  waurden allow [DIR]        acknowledge a blocked package for its current
                             PKGBUILD hash (cleared when the PKGBUILD changes)
  waurden forget <pkgname>   drop the cached verdict so the next scan re-runs
  waurden install-hooks      install makepkg and pacman hooks (requires root)
  waurden uninstall-hooks    remove installed hooks (requires root)
  waurden version            print version`)
}

// versionString augments the human release number with the VCS revision Go
// stamps into the binary when built inside the module's git repo (default
// -buildvcs). For a waurden-git build from a clone this yields e.g.
// "wAURden 0.1.0 (abc1234, 2026-06-20, dirty)". Falls back to the bare release
// number when no VCS info is present (e.g. `go run`, or a stripped build).
func versionString() string {
	base := "wAURden " + version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return base
	}
	var rev, vcsTime string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev == "" {
		return base
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	parts := []string{rev}
	if vcsTime != "" {
		// vcs.time is RFC3339 (e.g. 2026-06-20T12:00:00Z); keep just the date.
		if i := strings.IndexByte(vcsTime, 'T'); i > 0 {
			vcsTime = vcsTime[:i]
		}
		parts = append(parts, vcsTime)
	}
	if modified {
		parts = append(parts, "dirty")
	}
	return base + " (" + strings.Join(parts, ", ") + ")"
}

// short abbreviates a pkgbuild_hash for human-facing log lines.
func short(h string) string {
	if h == "" {
		return "(no hash)"
	}
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

func exitUnconfigured(isGate bool) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│  wAURden: REFUSING TO RUN — NOT CONFIGURED                      │")
	fmt.Fprintln(os.Stderr, "│                                                                 │")
	fmt.Fprintln(os.Stderr, "│  No config file found at:                                       │")
	fmt.Fprintln(os.Stderr, "│    ~/.config/waurden/config.toml                                │")
	fmt.Fprintln(os.Stderr, "│    /etc/waurden/config.toml  (system-wide)                      │")
	fmt.Fprintln(os.Stderr, "│                                                                 │")
	fmt.Fprintln(os.Stderr, "│  Run:  waurden configure                                        │")
	fmt.Fprintln(os.Stderr, "│  to set up an LLM provider (or static heuristics-only mode).   │")
	if isGate {
		fmt.Fprintln(os.Stderr, "│                                                                 │")
		fmt.Fprintln(os.Stderr, "│  To remove hooks and stop blocking builds:                      │")
		fmt.Fprintln(os.Stderr, "│    sudo waurden uninstall-hooks                                 │")
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────────┘")
	fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}

func openDBFromConfig(cfg Config) (*sql.DB, error) {
	return openDB(cfg.DBPath)
}

func runScan(args []string) {
	dir := "."
	force := false
	for _, a := range args {
		switch a {
		case "--force", "--no-cache":
			force = true
		default:
			dir = a
		}
	}

	cfg, configFound, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: config error: %v\n", err)
		os.Exit(1)
	}
	if !configFound {
		exitUnconfigured(false)
	}

	pf, err := collectFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: %v\n", err)
		os.Exit(1)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var existing *DBRecord
	if pf.Name != "unknown" {
		existing, _ = lookupRecord(db, pf.Name)
	}
	aurInfo := fetchAURInfo(pf.PkgBase, cfg.Timeout)
	printAURWarnings(pf.Name, aurInfo)
	trackNewCommitters(&pf, existing)

	v, err := analyze(cfg, db, pf, force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: scan error: %v\n", err)
		os.Exit(1)
	}

	// A scan failure (LLM unreachable, rate-limited, parse error) is an
	// infrastructure problem, not a verdict — don't render it as "Verdict: OK".
	if v.ScanFailed {
		if cfg.OnError == "block" {
			fmt.Fprintf(os.Stderr, "wAURden: scan failed (on_error=block): %v\n", v.Summary)
			os.Exit(1)
		}
		// warn already printed a WARNING in analyze.go; allow is intentionally quiet.
		os.Exit(0)
	}

	printReport(os.Stdout, pf.Name, v, providerLabel(cfg))
}

func runGateCmd(args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	cfg, configFound, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: BLOCKING BUILD — config error: %v\n", err)
		os.Exit(1)
	}
	if !configFound {
		exitUnconfigured(true)
	}

	pf, err := collectFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: %v\n", err)
		if cfg.OnError == "block" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		if cfg.OnError == "block" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	defer db.Close()

	var existing *DBRecord
	if pf.Name != "unknown" {
		existing, _ = lookupRecord(db, pf.Name)
	}
	aurInfo := fetchAURInfo(pf.PkgBase, cfg.Timeout)
	printAURWarnings(pf.Name, aurInfo)
	trackNewCommitters(&pf, existing)

	v, blocked, err := runGate(cfg, db, pf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: gate error: %v\n", err)
		if cfg.OnError == "block" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Scan failures (LLM unreachable, parse error, etc.) take a separate display
	// path so the message reads like an infrastructure problem, not a security alarm.
	if v.ScanFailed {
		if cfg.OnError == "block" {
			fmt.Fprintf(os.Stderr, "wAURden: build blocked — scan failed (on_error=block): %v\n", v.Summary)
			os.Exit(1)
		}
		// on_error=warn: WARNING was already printed in analyze.go; pause so it
		// doesn't scroll away before the user can read it.
		if isTTY() {
			fmt.Fprintf(os.Stderr, "Press Enter to continue (build will proceed)...")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(0)
	}

	// Clean OK: stay silent.
	if v.Verdict == "ok" && !blocked {
		os.Exit(0)
	}

	// Anything else (suspicious, malicious): show the report.
	printReport(os.Stderr, pf.Name, v, providerLabel(cfg))

	if blocked {
		// Hash-pinned acknowledgement short-circuit. This is a pure hash compare,
		// so it MUST run even with no TTY — that is what makes the makepkg hook
		// path recoverable: build blocks (no TTY) → user runs `waurden allow`
		// in a real terminal → ack stored → re-run build passes here.
		if pf.Name != "unknown" && existing != nil &&
			existing.AcknowledgedHash != "" && existing.AcknowledgedHash == pf.Hash {
			fmt.Fprintf(os.Stderr, "wAURden: %s @ %s previously acknowledged — allowing\n", pf.Name, short(pf.Hash))
			blocked = false
		}

		// Interactive override. Friction is tiered by confidence: a high-confidence
		// malicious verdict demands a typed phrase; everything else is a plain y/N.
		// The verdict reason was already printed by printReport above.
		if blocked && cfg.Interactive && isTTY() {
			reader := bufio.NewReader(os.Stdin)
			accepted := false
			if v.Verdict == "malicious" && v.Confidence >= 0.9 {
				fmt.Fprintf(os.Stderr, "\nwAURden: build blocked — %s, confidence %.2f.\n", v.Verdict, v.Confidence)
				fmt.Fprintf(os.Stderr, "To override, type exactly: I accept the risk\n> ")
				line, _ := reader.ReadString('\n')
				accepted = strings.EqualFold(strings.TrimSpace(line), "i accept the risk")
			} else {
				fmt.Fprintf(os.Stderr, "\nwAURden: build blocked. Allow anyway? [y/N]: ")
				line, _ := reader.ReadString('\n')
				accepted = strings.EqualFold(strings.TrimSpace(line), "y")
			}
			if accepted {
				blocked = false
				// Offer to persist the ack so the user isn't re-prompted on rebuild
				// of this exact PKGBUILD. No stable key for "unknown" → no ack.
				if pf.Name != "unknown" {
					fmt.Fprintf(os.Stderr, "Remember this version (skip the prompt until the PKGBUILD changes)? [Y/n]: ")
					line, _ := reader.ReadString('\n')
					ans := strings.ToLower(strings.TrimSpace(line))
					if ans == "" || ans == "y" || ans == "yes" {
						if _, err := storeAcknowledgement(db, pf.Name, pf.Hash); err != nil {
							fmt.Fprintf(os.Stderr, "wAURden: could not store acknowledgement: %v\n", err)
						} else {
							fmt.Fprintf(os.Stderr, "wAURden: recorded ack: %s @ %s (cleared when the PKGBUILD changes)\n", pf.Name, short(pf.Hash))
						}
					}
				}
			}
		}
		if blocked {
			os.Exit(1)
		}
	} else if isTTY() {
		// Suspicious but not blocked: pause so the warning doesn't scroll away.
		fmt.Fprintf(os.Stderr, "\nPress Enter to continue (build will proceed)...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}

func runShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "wAURden: show requires a package name")
		os.Exit(1)
	}
	pkgname := args[0]

	cfg, _, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: config error: %v\n", err)
		os.Exit(1)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rec, err := lookupRecord(db, pkgname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db lookup error: %v\n", err)
		os.Exit(1)
	}
	if rec == nil {
		fmt.Printf("No record found for package: %s\n", pkgname)
		os.Exit(0)
	}

	fmt.Printf("Package:      %s\n", rec.Name)
	fmt.Printf("Last Scanned: %s\n", rec.LastScanned)
	fmt.Printf("Provider:     %s\n", rec.Provider)
	fmt.Printf("Verdict:      %s (confidence: %.2f)\n", strings.ToUpper(rec.Verdict), rec.Confidence)
	fmt.Printf("Analysis:     %s\n", rec.SourceAnalyzed)
	fmt.Printf("\nSummary: %s\n", rec.Summary)

	if rec.Findings != "" && rec.Findings != "null" {
		var findings []Finding
		if err := json.Unmarshal([]byte(rec.Findings), &findings); err == nil && len(findings) > 0 {
			fmt.Printf("\nFindings:\n")
			for _, f := range findings {
				fmt.Printf("  [%s] file: %s\n", strings.ToUpper(f.Severity), f.File)
				fmt.Printf("    %s\n", f.Detail)
				if f.Evidence != "" {
					fmt.Printf("    → %s\n", f.Evidence)
				}
			}
		}
	}
}

// runForget clears the cached verdict for a package so the next scan re-runs,
// without wiping the row. It blanks pkgbuild_hash (forcing a cache miss) rather
// than deleting the row, so committer history (known_committers) and any future
// acknowledged_hash survive. To re-scan in place use `scan --force` instead.
func runForget(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "wAURden: forget requires a package name")
		os.Exit(1)
	}
	pkgname := args[0]

	cfg, _, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: config error: %v\n", err)
		os.Exit(1)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	n, err := forgetRecord(db, pkgname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: forget error: %v\n", err)
		os.Exit(1)
	}
	if n == 0 {
		fmt.Printf("No record found for package: %s\n", pkgname)
		return
	}
	fmt.Printf("Cleared cached verdict for %s; the next scan will re-run.\n", pkgname)
}

// runAllow records a hash-pinned acknowledgement for a package so a subsequent
// gate (including the no-TTY makepkg hook) passes for this exact PKGBUILD. It is
// the recovery path when a build blocks inside the hook: the user re-runs it in a
// real terminal. The ack is voided automatically when the PKGBUILD hash changes.
func runAllow(args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	cfg, configFound, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: config error: %v\n", err)
		os.Exit(1)
	}
	if !configFound {
		exitUnconfigured(false)
	}

	pf, err := collectFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: %v\n", err)
		os.Exit(1)
	}
	if pf.Name == "unknown" {
		fmt.Fprintln(os.Stderr, "wAURden: cannot determine the package name (no .SRCINFO/pkgname);")
		fmt.Fprintln(os.Stderr, "refusing to record an acknowledgement without a stable key.")
		os.Exit(1)
	}

	db, err := openDBFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: db error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Ensure a row exists and reflects the current content, and show the user what
	// they are accepting. A cache hit on the same hash skips the re-scan.
	existing, _ := lookupRecord(db, pf.Name)
	trackNewCommitters(&pf, existing)
	if existing == nil || existing.PKGBUILDHash != pf.Hash {
		v, err := analyze(cfg, db, pf, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: scan error: %v\n", err)
			os.Exit(1)
		}
		if v.ScanFailed {
			fmt.Fprintf(os.Stderr, "wAURden: scan did not complete (%v); cannot acknowledge an unscanned package.\n", v.Summary)
			os.Exit(1)
		}
		printReport(os.Stderr, pf.Name, v, providerLabel(cfg))
	}

	// Symmetry with the gate's high-friction override: require the typed phrase
	// when a human is present. Non-TTY (scripted) callers skip straight to record.
	if isTTY() {
		fmt.Fprintf(os.Stderr, "\nType exactly 'I accept the risk' to acknowledge %s @ %s: ", pf.Name, short(pf.Hash))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.EqualFold(strings.TrimSpace(line), "i accept the risk") {
			fmt.Fprintln(os.Stderr, "wAURden: not acknowledged.")
			os.Exit(1)
		}
	}

	n, err := storeAcknowledgement(db, pf.Name, pf.Hash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: could not store acknowledgement: %v\n", err)
		os.Exit(1)
	}
	if n == 0 {
		fmt.Fprintf(os.Stderr, "wAURden: no DB row for %s to acknowledge.\n", pf.Name)
		os.Exit(1)
	}
	fmt.Printf("recorded ack: %s @ %s (cleared automatically when the PKGBUILD changes)\n", pf.Name, short(pf.Hash))
}

// configExistsAnywhere checks for a valid config file, accounting for the fact
// that install-hooks runs as root but the config belongs to the invoking user.
func configExistsAnywhere() bool {
	if _, err := os.Stat("/etc/waurden/config.toml"); err == nil {
		return true
	}
	home := ""
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(home, ".config", "waurden", "config.toml"))
	return err == nil
}

// hookStatus returns "missing", "ok", or "outdated" by comparing the installed
// file's sha256 against the expected content.
func hookStatus(path, expected string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "outdated"
	}
	if sha256.Sum256(data) == sha256.Sum256([]byte(expected)) {
		return "ok"
	}
	return "outdated"
}

func runInstallHooks() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "wAURden: install-hooks requires root. Re-run with sudo.")
		os.Exit(1)
	}
	if !configExistsAnywhere() {
		fmt.Fprintln(os.Stderr, "wAURden: no configuration found — refusing to install hooks.")
		fmt.Fprintln(os.Stderr, "Run 'waurden configure' as the user who will be building packages,")
		fmt.Fprintln(os.Stderr, "then re-run 'sudo waurden install-hooks'.")
		os.Exit(1)
	}

	// Only the makepkg hook is installed — it fires before PKGBUILD is sourced.
	// The pacman hook (hooks/pacman/waurden.hook) is a future-work placeholder.
	path := "/etc/makepkg.conf.d/00-waurden.conf"
	status := hookStatus(path, makepkgHook)
	switch status {
	case "ok":
		fmt.Printf("Up to date: %s\n", path)
		fmt.Println("wAURden hooks are already up to date.")
	case "missing":
		if err := writeFile(path, makepkgHook); err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: cannot write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("Installed: %s\n", path)
		fmt.Println("wAURden hooks installed.")
	case "outdated":
		if err := writeFile(path, makepkgHook); err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: cannot write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("Updated (was out of date): %s\n", path)
		fmt.Println("wAURden hooks updated.")
	}
}

func runUninstallHooks() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "wAURden: uninstall-hooks requires root. Re-run with sudo.")
		os.Exit(1)
	}

	path := "/etc/makepkg.conf.d/00-waurden.conf"
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Not found (skipping): %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "wAURden: cannot remove %s: %v\n", path, err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Removed: %s\n", path)
	}
	fmt.Println("wAURden hooks uninstalled.")
}

func writeFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func printReport(w *os.File, pkgname string, v Verdict, provider string) {
	fmt.Fprintf(w, "Package: %s\n", pkgname)
	fmt.Fprintf(w, "Verdict: %s (confidence: %.2f)\n", strings.ToUpper(v.Verdict), v.Confidence)
	fmt.Fprintf(w, "Summary: %s\n", v.Summary)

	if len(v.Findings) > 0 {
		fmt.Fprintln(w, "\nFindings:")
		for _, f := range v.Findings {
			fmt.Fprintf(w, "  [%s] file: %s\n", strings.ToUpper(f.Severity), f.File)
			fmt.Fprintf(w, "    %s\n", f.Detail)
			if f.Evidence != "" {
				fmt.Fprintf(w, "    → %s\n", f.Evidence)
			}
		}
	}

	if provider != "" {
		fmt.Fprintf(w, "\nProvider: %s\n", provider)
	}
}
