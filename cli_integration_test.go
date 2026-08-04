package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// waurdenBin is the path to the binary built once in TestMain. The run* command
// handlers call os.Exit, so they are exercised as a real subprocess rather than
// in-process — this doubles as a lightweight end-to-end check of the CLI wiring.
var waurdenBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "waurden-bin")
	if err != nil {
		panic(err)
	}
	waurdenBin = filepath.Join(dir, "waurden")
	build := exec.Command("go", "build", "-o", waurdenBin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("go build for CLI tests failed: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// cliResult captures a subprocess run.
type cliResult struct {
	stdout string
	stderr string
	code   int
}

// runCLI runs the built binary with args, a controlled HOME (so config/db are
// isolated per test), and optional stdin. staticHome writes a static-provider
// config into home when withConfig is true.
func runCLI(t *testing.T, home, stdin string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(waurdenBin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"SUDO_USER=", // never resolve to another user's DB during tests
	)
	// Always attach a pipe as stdin (even when empty). A nil Stdin becomes
	// /dev/null, which is a character device — isTTY() would then report true and
	// trigger interactive prompts the subprocess can't answer.
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return cliResult{out.String(), errb.String(), code}
}

// staticConfigHome returns a fresh temp HOME pre-seeded with a static-provider
// config so scan/gate are fully offline and deterministic (no LLM, no key).
func staticConfigHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "waurden")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := "provider = \"static\"\non_error = \"warn\"\ntimeout_seconds = 5\n" +
		"block_on = [\"malicious\"]\nwarn_on = [\"suspicious\"]\ninteractive = false\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return home
}

func absSample(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(sampleDir(name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCLIVersion(t *testing.T) {
	r := runCLI(t, t.TempDir(), "", "version")
	if r.code != 0 {
		t.Fatalf("version exit=%d stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "wAURden "+version) {
		t.Errorf("version stdout = %q", r.stdout)
	}
}

func TestCLINoArgsAndUnknown(t *testing.T) {
	// No args → usage + exit 1.
	r := runCLI(t, t.TempDir(), "")
	if r.code != 1 || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("no-args: code=%d stderr=%q", r.code, r.stderr)
	}
	// Unknown command → error + usage + exit 1.
	r = runCLI(t, t.TempDir(), "", "frobnicate")
	if r.code != 1 || !strings.Contains(r.stderr, "unknown command") {
		t.Errorf("unknown: code=%d stderr=%q", r.code, r.stderr)
	}
}

func TestCLIUnconfigured(t *testing.T) {
	// A HOME with no config → scan refuses with the banner and exits 1.
	r := runCLI(t, t.TempDir(), "", "scan", absSample(t, "benign"))
	if r.code != 1 {
		t.Fatalf("unconfigured scan exit=%d, want 1", r.code)
	}
	if !strings.Contains(r.stderr, "NOT CONFIGURED") {
		t.Errorf("missing unconfigured banner: %q", r.stderr)
	}
}

func TestCLIScanBenign(t *testing.T) {
	home := staticConfigHome(t)
	r := runCLI(t, home, "", "scan", absSample(t, "benign"))
	if r.code != 0 {
		t.Fatalf("scan benign exit=%d stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "Package: hello-world") || !strings.Contains(r.stdout, "Verdict: OK") {
		t.Errorf("scan report = %q", r.stdout)
	}
}

func TestCLIGateBenignAndMalicious(t *testing.T) {
	home := staticConfigHome(t)
	// Benign → OK line on stderr, exit 0.
	r := runCLI(t, home, "", "gate", absSample(t, "benign"))
	if r.code != 0 {
		t.Fatalf("gate benign exit=%d stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "hello-world — OK") {
		t.Errorf("gate benign stderr = %q", r.stderr)
	}
	// Malicious → blocked, exit 1.
	r = runCLI(t, home, "", "gate", absSample(t, "malicious"))
	if r.code != 1 {
		t.Fatalf("gate malicious exit=%d, want 1\nstderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(strings.ToUpper(r.stderr), "MALICIOUS") {
		t.Errorf("gate malicious stderr = %q", r.stderr)
	}
}

func TestCLIShowRecheckForgetRoundTrip(t *testing.T) {
	home := staticConfigHome(t)
	// Scan populates the DB.
	runCLI(t, home, "", "scan", absSample(t, "benign"))

	// show finds the record.
	r := runCLI(t, home, "", "show", "hello-world")
	if r.code != 0 || !strings.Contains(r.stdout, "Package:      hello-world") {
		t.Errorf("show: code=%d out=%q", r.code, r.stdout)
	}
	if !strings.Contains(r.stdout, "Verdict:      OK") {
		t.Errorf("show verdict = %q", r.stdout)
	}
	// Plain show does not print the diff block.
	if strings.Contains(r.stdout, "Changes since previous scan") ||
		strings.Contains(r.stdout, "No stored diff") {
		t.Errorf("plain show leaked diff section: %q", r.stdout)
	}

	// show --verbose surfaces the diff section (first scan → no stored diff).
	r = runCLI(t, home, "", "show", "hello-world", "--verbose")
	if r.code != 0 || !strings.Contains(r.stdout, "No stored diff") {
		t.Errorf("show --verbose: code=%d out=%q", r.code, r.stdout)
	}

	// recheck invalidates the cached verdict but keeps the row.
	r = runCLI(t, home, "", "recheck", "hello-world")
	if r.code != 0 || !strings.Contains(r.stdout, "Invalidated cached verdict") {
		t.Errorf("recheck: code=%d out=%q", r.code, r.stdout)
	}
	r = runCLI(t, home, "", "show", "hello-world")
	if !strings.Contains(r.stdout, "Package:      hello-world") {
		t.Errorf("row gone after recheck: %q", r.stdout)
	}

	// forget deletes the record entirely.
	r = runCLI(t, home, "", "forget", "hello-world")
	if r.code != 0 || !strings.Contains(r.stdout, "Deleted all records") {
		t.Errorf("forget: code=%d out=%q", r.code, r.stdout)
	}
	r = runCLI(t, home, "", "show", "hello-world")
	if !strings.Contains(r.stdout, "No record found") {
		t.Errorf("show after forget = %q", r.stdout)
	}

	// show on a package never scanned → "No record found".
	r = runCLI(t, home, "", "show", "never-scanned-pkg")
	if !strings.Contains(r.stdout, "No record found") {
		t.Errorf("show missing = %q", r.stdout)
	}
}

func TestCLIAllowNonTTY(t *testing.T) {
	home := staticConfigHome(t)
	// Non-TTY allow without the explicit flag refuses: there is no terminal to
	// type "I accept the risk" on, and a silent scripted ack would let anything
	// bless a blocked package without anyone accepting the risk.
	r := runCLI(t, home, "", "allow", absSample(t, "benign"))
	if r.code == 0 {
		t.Fatalf("allow without --i-accept-the-risk should refuse, stdout=%q", r.stdout)
	}
	if !strings.Contains(r.stderr, "--i-accept-the-risk") {
		t.Errorf("refusal should name the flag, stderr=%q", r.stderr)
	}

	// With the flag, the ack records (the flag is the non-TTY stand-in for the
	// typed phrase).
	r = runCLI(t, home, "", "allow", "--i-accept-the-risk", absSample(t, "benign"))
	if r.code != 0 {
		t.Fatalf("allow exit=%d stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "recorded ack: hello-world") {
		t.Errorf("allow stdout = %q stderr=%q", r.stdout, r.stderr)
	}
}

func TestCLIHaltBreaker(t *testing.T) {
	home := staticConfigHome(t)

	// A malicious gate blocks, prints the recovery guidance, and trips the
	// run-level breaker.
	r := runCLI(t, home, "", "gate", absSample(t, "malicious"))
	if r.code != 1 {
		t.Fatalf("gate malicious exit=%d stderr=%s", r.code, r.stderr)
	}
	for _, want := range []string{"less ", "waurden allow ", "I accept the risk"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("block guidance missing %q:\n%s", want, r.stderr)
		}
	}

	// A subsequent gate for a DIFFERENT package now halts without scanning —
	// this is what stops an AUR helper's sibling builds after one block.
	r = runCLI(t, home, "", "gate", absSample(t, "benign"))
	if r.code != 1 {
		t.Fatalf("sibling gate should halt, exit=%d stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "halting this build") {
		t.Errorf("sibling gate stderr = %q", r.stderr)
	}

	// The blocked package's own gate is exempt from the halt: it re-blocks on
	// its own (re-decided) verdict, keeping the ack short-circuit reachable.
	r = runCLI(t, home, "", "gate", absSample(t, "malicious"))
	if r.code != 1 || strings.Contains(r.stderr, "halting this build") {
		t.Errorf("own gate: exit=%d stderr=%q", r.code, r.stderr)
	}

	// resume lifts the halt without acknowledging anything…
	r = runCLI(t, home, "", "resume")
	if r.code != 0 || !strings.Contains(r.stdout, "cleared") {
		t.Fatalf("resume: exit=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	// …so the sibling builds again. (The malicious package itself would still
	// block on its own verdict.)
	r = runCLI(t, home, "", "gate", absSample(t, "benign"))
	if r.code != 0 {
		t.Fatalf("gate benign after resume exit=%d stderr=%s", r.code, r.stderr)
	}
}

func TestCLIAllowLiftsHalt(t *testing.T) {
	home := staticConfigHome(t)

	// Block → halt is active for siblings.
	if r := runCLI(t, home, "", "gate", absSample(t, "malicious")); r.code != 1 {
		t.Fatalf("gate malicious exit=%d stderr=%s", r.code, r.stderr)
	}
	// Acknowledging the blocked package resolves its halt…
	r := runCLI(t, home, "", "allow", "--i-accept-the-risk", absSample(t, "malicious"))
	if r.code != 0 {
		t.Fatalf("allow exit=%d stderr=%s", r.code, r.stderr)
	}
	// …so a sibling gate proceeds…
	if r := runCLI(t, home, "", "gate", absSample(t, "benign")); r.code != 0 {
		t.Fatalf("sibling after allow exit=%d stderr=%s", r.code, r.stderr)
	}
	// …and the acknowledged package itself passes via the hash-pinned ack.
	r = runCLI(t, home, "", "gate", absSample(t, "malicious"))
	if r.code != 0 || !strings.Contains(r.stderr, "previously acknowledged") {
		t.Errorf("acked gate: exit=%d stderr=%q", r.code, r.stderr)
	}
}

func TestCLIResumeNoHalt(t *testing.T) {
	home := staticConfigHome(t)
	r := runCLI(t, home, "", "resume")
	if r.code != 0 || !strings.Contains(r.stdout, "no active halt") {
		t.Errorf("resume with empty ledger: exit=%d stdout=%q", r.code, r.stdout)
	}
}

func TestCLISummary(t *testing.T) {
	home := staticConfigHome(t)
	// Empty DB summary.
	r := runCLI(t, home, "", "summary")
	if !strings.Contains(r.stdout, "No packages scanned yet.") {
		t.Errorf("empty summary = %q", r.stdout)
	}
	// After a scan, the package shows in the table.
	runCLI(t, home, "", "scan", absSample(t, "benign"))
	r = runCLI(t, home, "", "summary")
	if !strings.Contains(r.stdout, "PACKAGE") || !strings.Contains(r.stdout, "hello-world") {
		t.Errorf("summary table = %q", r.stdout)
	}
	// History view.
	r = runCLI(t, home, "", "summary", "--history")
	if !strings.Contains(r.stdout, "WHEN") || !strings.Contains(r.stdout, "hello-world") {
		t.Errorf("summary history = %q", r.stdout)
	}
	// --targets reads stdin; a repo-only name not in the DB stays silent.
	r = runCLI(t, home, "glibc\ncoreutils\n", "summary", "--targets")
	if strings.TrimSpace(r.stdout)+strings.TrimSpace(r.stderr) != "" {
		t.Errorf("targets with no DB match should be silent: out=%q err=%q", r.stdout, r.stderr)
	}
	// --targets with a scanned package prints the recap.
	r = runCLI(t, home, "hello-world\n", "summary", "--targets")
	if !strings.Contains(r.stderr, "wAURden summary") || !strings.Contains(r.stderr, "hello-world") {
		t.Errorf("targets recap = %q", r.stderr)
	}
}

func TestCLITokensEmpty(t *testing.T) {
	home := staticConfigHome(t)
	// Static engine consumes no tokens → the report says so.
	r := runCLI(t, home, "", "tokens")
	if !strings.Contains(r.stdout, "No LLM token usage recorded yet.") {
		t.Errorf("tokens empty = %q", r.stdout)
	}
}

func TestCLIConfigureStatic(t *testing.T) {
	home := t.TempDir()
	// Wizard: choice 6 (static), on_error warn (accept default), write=yes.
	// Provider 6 skips model/key/scan_mode prompts; on_error default is warn;
	// final "Write this configuration?" defaults yes.
	stdin := "6\n\ny\n"
	r := runCLI(t, home, stdin, "configure")
	if r.code != 0 {
		t.Fatalf("configure exit=%d stderr=%s stdout=%s", r.code, r.stderr, r.stdout)
	}
	cfgPath := filepath.Join(home, ".config", "waurden", "config.toml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if !strings.Contains(string(data), `provider = "static"`) {
		t.Errorf("written config = %s", data)
	}
}

func TestCLIInstallHooksRequiresRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; the non-root refusal path cannot be exercised")
	}
	r := runCLI(t, staticConfigHome(t), "", "install-hooks")
	if r.code != 1 || !strings.Contains(r.stderr, "requires root") {
		t.Errorf("install-hooks non-root: code=%d stderr=%q", r.code, r.stderr)
	}
	r = runCLI(t, t.TempDir(), "", "uninstall-hooks")
	if r.code != 1 || !strings.Contains(r.stderr, "requires root") {
		t.Errorf("uninstall-hooks non-root: code=%d stderr=%q", r.code, r.stderr)
	}
}
