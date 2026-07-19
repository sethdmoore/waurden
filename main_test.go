package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	got := versionString()
	if !strings.HasPrefix(got, "wAURden "+version) {
		t.Errorf("versionString = %q, want prefix %q", got, "wAURden "+version)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate(""); got != "" {
		t.Errorf("truncate empty = %q", got)
	}
	// Newlines and runs of whitespace collapse to single spaces.
	if got := truncate("line one\n\nline   two\ttab"); got != "line one line two tab" {
		t.Errorf("truncate collapse = %q", got)
	}
	// Over the 80-char cap → truncated to 79 chars + ellipsis rune.
	long := strings.Repeat("a", 100)
	got := truncate(long)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate long should end with ellipsis: %q", got)
	}
	if strings.Count(got, "a") != 79 {
		t.Errorf("truncate kept %d chars, want 79", strings.Count(got, "a"))
	}
}

func TestShort(t *testing.T) {
	if got := short(""); got != "(no hash)" {
		t.Errorf("short empty = %q", got)
	}
	if got := short("abcdef1234567890"); got != "abcdef12" {
		t.Errorf("short long = %q, want abcdef12", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short small = %q", got)
	}
}

func TestCachedTag(t *testing.T) {
	if got := cachedTag(Verdict{Cached: true}); got != " (cached)" {
		t.Errorf("cachedTag(true) = %q", got)
	}
	if got := cachedTag(Verdict{}); got != "" {
		t.Errorf("cachedTag(false) = %q", got)
	}
}

func TestPrintReport(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	v := Verdict{
		Verdict:    "malicious",
		Confidence: 0.95,
		Summary:    "blocked for curl|sh",
		Cached:     true,
		Findings: []Finding{
			{Severity: "critical", File: "PKGBUILD", Detail: "remote code execution", Evidence: "curl x | sh"},
		},
	}
	printReport(f, "evil-pkg", v, "static (heuristics)")
	f.Close()
	data, _ := os.ReadFile(f.Name())
	out := string(data)

	for _, want := range []string{
		"Package: evil-pkg",
		"Verdict: MALICIOUS (confidence: 0.95) (cached)",
		"Summary: blocked for curl|sh",
		"[CRITICAL] file: PKGBUILD",
		"remote code execution",
		"→ curl x | sh",
		"Provider: static (heuristics)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printReport output missing %q\n---\n%s", want, out)
		}
	}
}

func TestPrintReportNoProviderNoFindings(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "report")
	printReport(f, "ok-pkg", Verdict{Verdict: "ok", Confidence: 0.9, Summary: "clean"}, "")
	f.Close()
	data, _ := os.ReadFile(f.Name())
	out := string(data)
	if strings.Contains(out, "Findings:") {
		t.Errorf("no-findings report should omit Findings header: %q", out)
	}
	if strings.Contains(out, "Provider:") {
		t.Errorf("empty provider should be omitted: %q", out)
	}
}

func TestHookStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.conf")

	// Missing file.
	if got := hookStatus(path, "expected"); got != "missing" {
		t.Errorf("hookStatus missing = %q", got)
	}
	// Matching content.
	os.WriteFile(path, []byte("expected content"), 0644)
	if got := hookStatus(path, "expected content"); got != "ok" {
		t.Errorf("hookStatus ok = %q", got)
	}
	// Different content.
	if got := hookStatus(path, "different content"); got != "outdated" {
		t.Errorf("hookStatus outdated = %q", got)
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	// Nested path that does not yet exist — writeFile must create parents.
	path := filepath.Join(dir, "a", "b", "hook.conf")
	if err := writeFile(path, "hello hook"); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "hello hook" {
		t.Errorf("content = %q", data)
	}
	// Overwrite truncates.
	if err := writeFile(path, "shorter"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "shorter" {
		t.Errorf("overwrite content = %q", data)
	}
}

func TestEffectiveHome(t *testing.T) {
	// No SUDO_USER → the current user's home.
	t.Setenv("SUDO_USER", "")
	want, _ := os.UserHomeDir()
	if got := effectiveHome(); got != want {
		t.Errorf("effectiveHome (no sudo) = %q, want %q", got, want)
	}
	// SUDO_USER pointing at the current user → that user's home dir.
	cur, err := user.Current()
	if err == nil && cur.Username != "" {
		t.Setenv("SUDO_USER", cur.Username)
		if got := effectiveHome(); got != cur.HomeDir {
			t.Errorf("effectiveHome (sudo=%s) = %q, want %q", cur.Username, got, cur.HomeDir)
		}
	}
	// SUDO_USER naming a nonexistent user → falls back to current home.
	t.Setenv("SUDO_USER", "definitely-not-a-real-user-xyz")
	if got := effectiveHome(); got != want {
		t.Errorf("effectiveHome (bad sudo) = %q, want fallback %q", got, want)
	}
}

func TestConfigExistsAnywhere(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	// No config anywhere (assuming /etc/waurden/config.toml absent on the test box).
	if _, err := os.Stat("/etc/waurden/config.toml"); err == nil {
		t.Skip("/etc/waurden/config.toml exists on this host; cannot assert absence")
	}
	if configExistsAnywhere() {
		t.Error("configExistsAnywhere true with no config present")
	}
	// Create the user config → now true.
	cfgDir := filepath.Join(dir, ".config", "waurden")
	os.MkdirAll(cfgDir, 0755)
	os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("provider=\"static\"\n"), 0600)
	if !configExistsAnywhere() {
		t.Error("configExistsAnywhere false after writing user config")
	}
}

func TestOpenDBFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DBPath: filepath.Join(dir, "sub", "waurden.db"), DBBusyTimeout: 7}
	db, err := openDBFromConfig(cfg)
	if err != nil {
		t.Fatalf("openDBFromConfig: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("SELECT count(*) FROM packages"); err != nil {
		t.Errorf("db not usable: %v", err)
	}
}

func TestPrintUsage(t *testing.T) {
	out := captureStderr(t, printUsage)
	for _, want := range []string{"waurden configure", "waurden gate", "waurden summary", "waurden tokens"} {
		if !strings.Contains(out, want) {
			t.Errorf("printUsage missing %q", want)
		}
	}
}
