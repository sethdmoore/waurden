package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// insertTokenRow writes one token_usage row directly with a controlled used_at
// timestamp, bypassing recordTokenUsage's "now" stamping. Used by the window /
// aggregation tests that need deterministic timestamps.
func insertTokenRow(t *testing.T, db *sql.DB, session, pkg, usedAt, provider, model string, in, out int, estimated bool) {
	t.Helper()
	est := 0
	if estimated {
		est = 1
	}
	_, err := db.Exec(`INSERT INTO token_usage
		(session, package, used_at, provider, model, input_tokens, output_tokens, total_tokens, estimated)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		session, pkg, usedAt, provider, model, in, out, in+out, est)
	if err != nil {
		t.Fatalf("insert token row: %v", err)
	}
}

func TestTokenUsageTotal(t *testing.T) {
	tests := []struct {
		name string
		u    TokenUsage
		want int
	}{
		{"zero", TokenUsage{}, 0},
		{"input only", TokenUsage{InputTokens: 10}, 10},
		{"output only", TokenUsage{OutputTokens: 7}, 7},
		{"both", TokenUsage{InputTokens: 100, OutputTokens: 42}, 142},
		{"estimated flag ignored", TokenUsage{InputTokens: 3, OutputTokens: 4, Estimated: true}, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.u.Total(); got != tt.want {
				t.Errorf("Total() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	a := newSession()
	b := newSession()
	if a == "" || b == "" {
		t.Fatalf("newSession() returned empty string: a=%q b=%q", a, b)
	}
	if a == b {
		t.Errorf("two newSession() calls returned identical ids: %q", a)
	}
	// The crypto/rand path yields 16 hex chars; the fallback is base-16 too.
	// Don't over-assert the exact length, but every character should be hex-ish.
	for _, s := range []string{a, b} {
		for _, c := range s {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Errorf("newSession() %q contains non-hex char %q", s, c)
				break
			}
		}
	}
}

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},         // len 1 -> (1+3)/4 = 1
		{"ab", 1},        // len 2 -> (2+3)/4 = 1
		{"abc", 1},       // len 3 -> (3+3)/4 = 1
		{"abcd", 1},      // len 4 -> (4+3)/4 = 1
		{"abcde", 2},     // len 5 -> (5+3)/4 = 2
		{"abcdefgh", 2},  // len 8 -> (8+3)/4 = 2
		{"abcdefghi", 3}, // len 9 -> (9+3)/4 = 3
		{strings.Repeat("x", 40), 10},
	}
	for _, tt := range tests {
		if got := estimateTokens(tt.in); got != tt.want {
			t.Errorf("estimateTokens(len=%d) = %d, want %d", len(tt.in), got, tt.want)
		}
	}
}

func TestUsageOrEstimate(t *testing.T) {
	t.Run("reported when input positive", func(t *testing.T) {
		u := usageOrEstimate(120, 0, "some prompt text", "")
		if u.Estimated {
			t.Errorf("expected Estimated=false when in>0")
		}
		if u.InputTokens != 120 || u.OutputTokens != 0 {
			t.Errorf("got %+v, want in=120 out=0", u)
		}
	})

	t.Run("reported when output positive", func(t *testing.T) {
		u := usageOrEstimate(0, 55, "prompt", "completion")
		if u.Estimated {
			t.Errorf("expected Estimated=false when out>0")
		}
		if u.InputTokens != 0 || u.OutputTokens != 55 {
			t.Errorf("got %+v, want in=0 out=55", u)
		}
	})

	t.Run("reported when both positive", func(t *testing.T) {
		u := usageOrEstimate(10, 20, "ignored", "ignored")
		if u.Estimated || u.InputTokens != 10 || u.OutputTokens != 20 {
			t.Errorf("got %+v, want in=10 out=20 estimated=false", u)
		}
	})

	t.Run("estimated when both zero", func(t *testing.T) {
		prompt := "You are a security auditor for Arch Linux PKGBUILDs."
		completion := `{"verdict":"ok"}`
		u := usageOrEstimate(0, 0, prompt, completion)
		if !u.Estimated {
			t.Errorf("expected Estimated=true when in==0 && out==0")
		}
		if u.InputTokens != estimateTokens(prompt) {
			t.Errorf("InputTokens = %d, want estimateTokens(prompt) = %d", u.InputTokens, estimateTokens(prompt))
		}
		if u.OutputTokens != estimateTokens(completion) {
			t.Errorf("OutputTokens = %d, want estimateTokens(completion) = %d", u.OutputTokens, estimateTokens(completion))
		}
	})

	t.Run("estimated with empty texts is zero", func(t *testing.T) {
		u := usageOrEstimate(0, 0, "", "")
		if !u.Estimated || u.InputTokens != 0 || u.OutputTokens != 0 {
			t.Errorf("got %+v, want in=0 out=0 estimated=true", u)
		}
	})
}

func TestRecordTokenUsage(t *testing.T) {
	db := newTestDB(t)

	u := TokenUsage{InputTokens: 321, OutputTokens: 89, Estimated: true}
	if err := recordTokenUsage(db, "sess-abc", "firefox", "anthropic", "claude-haiku-4-5", u); err != nil {
		t.Fatalf("recordTokenUsage: %v", err)
	}

	var (
		session, pkg, provider, model string
		in, out, total, est           int
	)
	err := db.QueryRow(`SELECT session, package, provider, model,
		input_tokens, output_tokens, total_tokens, estimated FROM token_usage`).
		Scan(&session, &pkg, &provider, &model, &in, &out, &total, &est)
	if err != nil {
		t.Fatalf("read back row: %v", err)
	}

	if session != "sess-abc" {
		t.Errorf("session = %q, want sess-abc", session)
	}
	if pkg != "firefox" {
		t.Errorf("package = %q, want firefox", pkg)
	}
	if provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", provider)
	}
	if model != "claude-haiku-4-5" {
		t.Errorf("model = %q, want claude-haiku-4-5", model)
	}
	if in != 321 {
		t.Errorf("input_tokens = %d, want 321", in)
	}
	if out != 89 {
		t.Errorf("output_tokens = %d, want 89", out)
	}
	if total != 410 {
		t.Errorf("total_tokens = %d, want 410 (321+89)", total)
	}
	if est != 1 {
		t.Errorf("estimated = %d, want 1", est)
	}
}

func TestRecordTokenUsageExactFlag(t *testing.T) {
	db := newTestDB(t)
	if err := recordTokenUsage(db, "s1", "pkg", "openai", "gpt-x", TokenUsage{InputTokens: 5, OutputTokens: 6}); err != nil {
		t.Fatalf("recordTokenUsage: %v", err)
	}
	var est, total int
	if err := db.QueryRow(`SELECT estimated, total_tokens FROM token_usage`).Scan(&est, &total); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if est != 0 {
		t.Errorf("estimated = %d, want 0 for reported usage", est)
	}
	if total != 11 {
		t.Errorf("total_tokens = %d, want 11", total)
	}
}

func TestSumTokens(t *testing.T) {
	db := newTestDB(t)

	// Three rows at known timestamps. Two exact, one estimated.
	insertTokenRow(t, db, "s1", "a", "2026-01-01T00:00:00Z", "openai", "m", 100, 10, false)
	insertTokenRow(t, db, "s1", "b", "2026-02-01T00:00:00Z", "openai", "m", 200, 20, true)
	insertTokenRow(t, db, "s2", "c", "2026-03-01T00:00:00Z", "anthropic", "m", 300, 30, false)

	t.Run("empty since sums all", func(t *testing.T) {
		got, err := sumTokens(db, "")
		if err != nil {
			t.Fatalf("sumTokens: %v", err)
		}
		want := tokenTotals{Scans: 3, Input: 600, Output: 60, Total: 660, HasEstimated: true}
		if got != want {
			t.Errorf("sumTokens(\"\") = %+v, want %+v", got, want)
		}
	})

	t.Run("future since returns zero", func(t *testing.T) {
		future := time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
		got, err := sumTokens(db, future)
		if err != nil {
			t.Fatalf("sumTokens: %v", err)
		}
		want := tokenTotals{Scans: 0, Input: 0, Output: 0, Total: 0, HasEstimated: false}
		if got != want {
			t.Errorf("sumTokens(future) = %+v, want %+v", got, want)
		}
	})

	t.Run("since bound filters and excludes only-exact window", func(t *testing.T) {
		// From 2026-02-15 onward only the third (exact) row qualifies.
		got, err := sumTokens(db, "2026-02-15T00:00:00Z")
		if err != nil {
			t.Fatalf("sumTokens: %v", err)
		}
		want := tokenTotals{Scans: 1, Input: 300, Output: 30, Total: 330, HasEstimated: false}
		if got != want {
			t.Errorf("sumTokens(2026-02-15) = %+v, want %+v", got, want)
		}
	})

	t.Run("since bound includes estimated row", func(t *testing.T) {
		// From 2026-01-15 onward: the estimated Feb row and the exact Mar row.
		got, err := sumTokens(db, "2026-01-15T00:00:00Z")
		if err != nil {
			t.Fatalf("sumTokens: %v", err)
		}
		want := tokenTotals{Scans: 2, Input: 500, Output: 50, Total: 550, HasEstimated: true}
		if got != want {
			t.Errorf("sumTokens(2026-01-15) = %+v, want %+v", got, want)
		}
	})
}

func TestSumTokensEmptyDB(t *testing.T) {
	db := newTestDB(t)
	got, err := sumTokens(db, "")
	if err != nil {
		t.Fatalf("sumTokens: %v", err)
	}
	want := tokenTotals{}
	if got != want {
		t.Errorf("sumTokens(empty db) = %+v, want %+v", got, want)
	}
}

func TestSumSession(t *testing.T) {
	db := newTestDB(t)

	insertTokenRow(t, db, "run-1", "a", "2026-01-01T00:00:00Z", "openai", "m", 100, 10, false)
	insertTokenRow(t, db, "run-1", "b", "2026-01-01T00:01:00Z", "openai", "m", 50, 5, true)
	insertTokenRow(t, db, "run-2", "c", "2026-01-01T00:02:00Z", "openai", "m", 999, 999, false)

	got, err := sumSession(db, "run-1")
	if err != nil {
		t.Fatalf("sumSession: %v", err)
	}
	want := tokenTotals{Scans: 2, Input: 150, Output: 15, Total: 165, HasEstimated: true}
	if got != want {
		t.Errorf("sumSession(run-1) = %+v, want %+v", got, want)
	}

	// run-2's rows must be excluded from run-1's totals.
	got2, err := sumSession(db, "run-2")
	if err != nil {
		t.Fatalf("sumSession: %v", err)
	}
	want2 := tokenTotals{Scans: 1, Input: 999, Output: 999, Total: 1998, HasEstimated: false}
	if got2 != want2 {
		t.Errorf("sumSession(run-2) = %+v, want %+v", got2, want2)
	}

	// Unknown session -> zero.
	got3, err := sumSession(db, "does-not-exist")
	if err != nil {
		t.Fatalf("sumSession: %v", err)
	}
	if (got3 != tokenTotals{}) {
		t.Errorf("sumSession(unknown) = %+v, want zero", got3)
	}
}

func TestLatestSession(t *testing.T) {
	db := newTestDB(t)

	t.Run("empty db returns empty string", func(t *testing.T) {
		s, err := latestSession(db)
		if err != nil {
			t.Fatalf("latestSession: %v", err)
		}
		if s != "" {
			t.Errorf("latestSession(empty) = %q, want \"\"", s)
		}
	})

	// Insert "first" then "second"; by autoincrement id, second is latest even
	// though its used_at is earlier — the ordering is by id, not timestamp.
	insertTokenRow(t, db, "first", "a", "2026-05-01T00:00:00Z", "openai", "m", 1, 1, false)
	insertTokenRow(t, db, "second", "b", "2026-01-01T00:00:00Z", "openai", "m", 1, 1, false)

	s, err := latestSession(db)
	if err != nil {
		t.Fatalf("latestSession: %v", err)
	}
	if s != "second" {
		t.Errorf("latestSession = %q, want second (most recently inserted by id)", s)
	}
}

func TestPrintTokenReportEmpty(t *testing.T) {
	db := newTestDB(t)
	out := captureStdout(t, func() { printTokenReport(db) })
	if !strings.Contains(out, "No LLM token usage recorded yet.") {
		t.Errorf("empty report missing the 'no usage' message; got:\n%s", out)
	}
	if strings.Contains(out, "wAURden token usage") {
		t.Errorf("empty report should not print the usage table header; got:\n%s", out)
	}
}

func TestPrintTokenReportSeeded(t *testing.T) {
	db := newTestDB(t)

	// Seed rows within the current windows so "This run"/"Today"/etc. are non-zero.
	// One row large enough to force comma formatting, plus one estimated row.
	nowUTC := time.Now().UTC().Format(time.RFC3339)
	insertTokenRow(t, db, "cur-run", "big-pkg", nowUTC, "openai", "qwen3-coder", 1_000_000, 234_567, false)
	insertTokenRow(t, db, "cur-run", "est-pkg", nowUTC, "openai", "qwen3-coder", 500, 100, true)

	out := captureStdout(t, func() { printTokenReport(db) })

	mustContain := []string{
		"wAURden token usage", // title
		"SCANS",               // column header
		"INPUT",
		"OUTPUT",
		"TOTAL",
		"This run",
		"All time",
		"1,000,500",                 // commafied input sum (1,000,000 + 500)
		"1,235,167",                 // commafied total sum (1,000,500 in + 234,667 out)
		"includes estimated counts", // footnote, because one row is estimated
		"*",                         // the estimated mark
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("seeded report missing %q; full output:\n%s", want, out)
		}
	}
}

func TestPrintTokenReportSeededNoEstimated(t *testing.T) {
	db := newTestDB(t)
	nowUTC := time.Now().UTC().Format(time.RFC3339)
	insertTokenRow(t, db, "cur-run", "pkg", nowUTC, "anthropic", "claude", 1234, 567, false)

	out := captureStdout(t, func() { printTokenReport(db) })
	if !strings.Contains(out, "wAURden token usage") {
		t.Errorf("report missing title; got:\n%s", out)
	}
	if strings.Contains(out, "includes estimated counts") {
		t.Errorf("report with no estimated rows should not print the footnote; got:\n%s", out)
	}
}

func TestEstimatedMark(t *testing.T) {
	if got := estimatedMark(tokenTotals{HasEstimated: true}); got != "*" {
		t.Errorf("estimatedMark(HasEstimated=true) = %q, want *", got)
	}
	if got := estimatedMark(tokenTotals{HasEstimated: false}); got != "" {
		t.Errorf("estimatedMark(HasEstimated=false) = %q, want empty", got)
	}
}

func TestCommafy(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{12, "12"},
		{100, "100"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{-1000, "-1,000"},
		{-12, "-12"},
		{-999, "-999"},
		{-1234567, "-1,234,567"},
		{1000000, "1,000,000"},
	}
	for _, tt := range tests {
		if got := commafy(tt.in); got != tt.want {
			t.Errorf("commafy(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
