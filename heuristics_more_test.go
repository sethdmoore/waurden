package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"info", 0},
		{"", 0},
		{"bogus", 0},
	}
	for _, tc := range cases {
		if got := severityRank(tc.in); got != tc.want {
			t.Errorf("severityRank(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCompilePatterns(t *testing.T) {
	patterns := []HeuristicPattern{
		{Regex: `curl\s+http`, Severity: "high", Detail: "valid one"},
		{Regex: `[`, Severity: "critical", Detail: "invalid regex, skipped"}, // unterminated class
		{Regex: `eval`, Severity: "", Detail: "empty severity defaults to critical"},
	}

	var out []compiledPattern
	stderr := captureStderr(t, func() {
		out = compilePatterns(patterns)
	})

	// The invalid regex is dropped, so only 2 patterns compile.
	if len(out) != 2 {
		t.Fatalf("compilePatterns len = %d, want 2 (invalid regex skipped)", len(out))
	}
	// A warning about the invalid regex must reach stderr.
	if !strings.Contains(stderr, "invalid heuristic regex") {
		t.Errorf("expected invalid-regex warning on stderr, got: %q", stderr)
	}

	// First pattern retains its fields.
	if out[0].severity != "high" {
		t.Errorf("out[0].severity = %q, want high", out[0].severity)
	}
	if out[0].detail != "valid one" {
		t.Errorf("out[0].detail = %q, want %q", out[0].detail, "valid one")
	}
	if out[0].re == nil || !out[0].re.MatchString("curl http://x") {
		t.Errorf("out[0].re did not compile/match as expected")
	}

	// Second surviving pattern (the empty-severity one) defaults to critical.
	if out[1].severity != "critical" {
		t.Errorf("out[1].severity = %q, want critical (empty defaults)", out[1].severity)
	}
	if out[1].detail != "empty severity defaults to critical" {
		t.Errorf("out[1].detail = %q", out[1].detail)
	}
}

func TestLoadHeuristicsFileMissing(t *testing.T) {
	patterns, err := loadHeuristicsFile(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err != nil {
		t.Fatalf("loadHeuristicsFile(missing) err = %v, want nil", err)
	}
	if patterns != nil {
		t.Errorf("loadHeuristicsFile(missing) = %v, want nil", patterns)
	}
}

func TestLoadHeuristicsFileValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heuristics.toml")
	content := `[[pattern]]
regex = "wget .* \\| bash"
severity = "critical"
detail = "pipe to bash"

[[pattern]]
regex = "mytelemetry\\.io"
severity = "medium"
detail = "custom exfil endpoint"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	patterns, err := loadHeuristicsFile(path)
	if err != nil {
		t.Fatalf("loadHeuristicsFile: %v", err)
	}
	if len(patterns) != 2 {
		t.Fatalf("got %d patterns, want 2", len(patterns))
	}
	if patterns[0].Regex != `wget .* \| bash` {
		t.Errorf("patterns[0].Regex = %q", patterns[0].Regex)
	}
	if patterns[0].Severity != "critical" {
		t.Errorf("patterns[0].Severity = %q, want critical", patterns[0].Severity)
	}
	if patterns[0].Detail != "pipe to bash" {
		t.Errorf("patterns[0].Detail = %q", patterns[0].Detail)
	}
	if patterns[1].Regex != `mytelemetry\.io` {
		t.Errorf("patterns[1].Regex = %q", patterns[1].Regex)
	}
	if patterns[1].Severity != "medium" {
		t.Errorf("patterns[1].Severity = %q, want medium", patterns[1].Severity)
	}
	if patterns[1].Detail != "custom exfil endpoint" {
		t.Errorf("patterns[1].Detail = %q", patterns[1].Detail)
	}
}

func TestLoadHeuristicsFileMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("[[pattern]]\nregex = \nthis is broken [[[\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadHeuristicsFile(path)
	if err == nil {
		t.Fatalf("loadHeuristicsFile(malformed) err = nil, want non-nil")
	}
}

func TestSuspiciousUnicodeFirstRune(t *testing.T) {
	// When multiple suspicious runes are present, the FIRST one is returned.
	s := "a" + string(rune(0x202E)) + "b" + string(rune(0x200B)) + "c"
	r, ok := suspiciousUnicode(s)
	if !ok {
		t.Fatal("suspiciousUnicode = false, want true")
	}
	if r != 0x202E {
		t.Errorf("suspiciousUnicode returned %U, want first suspicious rune U+202E", r)
	}
}

func TestSuspiciousUnicodeCodepoints(t *testing.T) {
	flagged := map[string]rune{
		"LRE (U+202A)":           0x202A,
		"LRI (U+2066)":           0x2066,
		"LRM (U+200E)":           0x200E,
		"paragraph sep (U+2029)": 0x2029,
		"ZWJ (U+200D)":           0x200D,
	}
	for name, r := range flagged {
		s := "before" + string(r) + "after"
		got, ok := suspiciousUnicode(s)
		if !ok {
			t.Errorf("%s: suspiciousUnicode = false, want true", name)
			continue
		}
		if got != r {
			t.Errorf("%s: returned %U, want %U", name, got, r)
		}
	}
}

func TestSuspiciousUnicodeCleanText(t *testing.T) {
	clean := []string{
		"日本語",               // ordinary multi-byte CJK
		"🚀",                 // emoji (astral plane)
		"plain ascii build", // ascii
		"café résumé",       // accented latin
	}
	for _, s := range clean {
		if r, ok := suspiciousUnicode(s); ok {
			t.Errorf("false positive on %q: flagged %U", s, r)
		}
	}
}

func TestInitHeuristics(t *testing.T) {
	// Reset then initialize; the builtins must compile into the active slices.
	activePatterns = nil
	activeInjection = nil

	initHeuristics()

	if len(activePatterns) == 0 {
		t.Error("activePatterns empty after initHeuristics; builtins did not compile")
	}
	if len(activeInjection) == 0 {
		t.Error("activeInjection empty after initHeuristics; injection patterns did not compile")
	}
	// The active builtin set is at least as large as the source list (user files
	// only add). Every compiled entry must carry a non-nil regexp.
	if len(activePatterns) < len(builtinPatterns) {
		t.Errorf("activePatterns len = %d, want >= %d (builtins)", len(activePatterns), len(builtinPatterns))
	}
	for i, p := range activePatterns {
		if p.re == nil {
			t.Errorf("activePatterns[%d].re is nil", i)
		}
	}
}
