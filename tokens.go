package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"
)

// TokenUsage records how many tokens a single LLM call consumed. When the
// provider reports usage in its response we store those exact numbers; when it
// does not (some OpenAI-compatible endpoints omit it), Estimated is set and the
// counts are a ~4-chars-per-token approximation. See usageOrEstimate.
type TokenUsage struct {
	InputTokens  int
	OutputTokens int
	Estimated    bool
}

// Total is the combined input+output token count.
func (u TokenUsage) Total() int { return u.InputTokens + u.OutputTokens }

// tokenSession identifies this process invocation. Every token_usage row written
// during this run shares it, so `waurden tokens` can report "this run" as the
// most recently recorded session. Under a yay batch each concurrent gate is its
// own process (its own session), so "this run" is per-package there — documented
// in the tokens report.
var tokenSession = newSession()

func newSession() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Time-based fallback is fine — the session id only needs to be unique
		// enough to group one invocation's rows, not cryptographically strong.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// estimateTokens approximates the token count of a string. The rule of thumb for
// English/code text is ~4 characters per token; this is deliberately rough — it
// is only used when the provider does not return an exact usage count.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}

// usageOrEstimate prefers the provider-reported counts (in/out) and falls back to
// a character-based estimate of the prompt and completion text when the provider
// returned no usage (both zero).
func usageOrEstimate(in, out int, promptText, completionText string) TokenUsage {
	if in > 0 || out > 0 {
		return TokenUsage{InputTokens: in, OutputTokens: out, Estimated: false}
	}
	return TokenUsage{
		InputTokens:  estimateTokens(promptText),
		OutputTokens: estimateTokens(completionText),
		Estimated:    true,
	}
}

// recordTokenUsage appends one usage row to the append-only token_usage table.
// It is called after a successful LLM call (before verdict parsing, so tokens are
// counted even if the response fails to parse — they were still billed). The
// static/heuristics engine consumes no tokens and is never recorded. Non-fatal
// for callers: a bookkeeping failure must not break a scan or block a build.
func recordTokenUsage(db *sql.DB, session, pkg, provider, model string, u TokenUsage) error {
	est := 0
	if u.Estimated {
		est = 1
	}
	_, err := db.Exec(`INSERT INTO token_usage
		(session, package, used_at, provider, model, input_tokens, output_tokens, total_tokens, estimated)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		session, pkg, time.Now().UTC().Format(time.RFC3339), provider, model,
		u.InputTokens, u.OutputTokens, u.Total(), est)
	return err
}

// tokenTotals is an aggregate of token_usage rows over some window.
type tokenTotals struct {
	Scans        int
	Input        int
	Output       int
	Total        int
	HasEstimated bool // any row in the window used an estimate rather than a reported count
}

// sumTokens aggregates all rows whose used_at is >= sinceUTC (RFC3339, UTC). An
// empty sinceUTC means "all time" (no lower bound).
func sumTokens(db *sql.DB, sinceUTC string) (tokenTotals, error) {
	q := `SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
		COALESCE(SUM(total_tokens),0), COALESCE(MAX(estimated),0) FROM token_usage`
	var qargs []interface{}
	if sinceUTC != "" {
		q += ` WHERE used_at >= ?`
		qargs = append(qargs, sinceUTC)
	}
	var t tokenTotals
	var est int
	err := db.QueryRow(q, qargs...).Scan(&t.Scans, &t.Input, &t.Output, &t.Total, &est)
	t.HasEstimated = est != 0
	return t, err
}

// sumSession aggregates a single session's rows (the "this run" view).
func sumSession(db *sql.DB, session string) (tokenTotals, error) {
	var t tokenTotals
	var est int
	err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(input_tokens),0),
		COALESCE(SUM(output_tokens),0), COALESCE(SUM(total_tokens),0),
		COALESCE(MAX(estimated),0) FROM token_usage WHERE session = ?`, session).
		Scan(&t.Scans, &t.Input, &t.Output, &t.Total, &est)
	t.HasEstimated = est != 0
	return t, err
}

// latestSession returns the session id of the most recently recorded token row,
// or "" if none exist. This is what the tokens report treats as "the last run".
func latestSession(db *sql.DB) (string, error) {
	var s sql.NullString
	err := db.QueryRow(`SELECT session FROM token_usage ORDER BY id DESC LIMIT 1`).Scan(&s)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s.String, nil
}

// runTokens prints a token-usage report broken down by time window: the most
// recent run, today, this week, this month, and all time. Windows are computed in
// local time (start of day / ISO week starting Monday / calendar month) and
// compared against the UTC RFC3339 timestamps stored in token_usage.
func runTokens(args []string) {
	// Mirror summary's root->user DB resolution so the report works under sudo too.
	if home := effectiveHome(); home != "" {
		os.Setenv("HOME", home)
	}

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

	printTokenReport(db)
}

func printTokenReport(db *sql.DB) {
	now := time.Now()
	loc := now.Location()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	// ISO week: Monday is the first day. Go's Weekday has Sunday=0.
	offset := (int(startOfDay.Weekday()) + 6) % 7
	startOfWeek := startOfDay.AddDate(0, 0, -offset)
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
	asUTC := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }

	type row struct {
		label string
		t     tokenTotals
	}
	var rows []row

	// "This run" = the most recently recorded session.
	if session, err := latestSession(db); err == nil && session != "" {
		if t, err := sumSession(db, session); err == nil {
			rows = append(rows, row{"This run", t})
		}
	}

	for _, w := range []struct {
		label string
		since string
	}{
		{"Today", asUTC(startOfDay)},
		{"This week", asUTC(startOfWeek)},
		{"This month", asUTC(startOfMonth)},
		{"All time", ""},
	} {
		t, err := sumTokens(db, w.since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: db query error: %v\n", err)
			os.Exit(1)
		}
		rows = append(rows, row{w.label, t})
	}

	// If nothing has ever been recorded, say so plainly.
	all := rows[len(rows)-1].t
	if all.Scans == 0 {
		fmt.Println("No LLM token usage recorded yet.")
		fmt.Println("(The static/heuristics engine uses no tokens; only anthropic/openai calls are counted.)")
		return
	}

	fmt.Println("wAURden token usage")
	// A trailing (mark) column keeps TOTAL tab-terminated so tabwriter pads it;
	// the last cell of a right-aligned row is otherwise left unformatted and
	// collides with its neighbour.
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "\tSCANS\tINPUT\tOUTPUT\tTOTAL\t")
	anyEstimated := false
	for _, r := range rows {
		if r.t.HasEstimated {
			anyEstimated = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.label, commafy(r.t.Scans), commafy(r.t.Input),
			commafy(r.t.Output), commafy(r.t.Total), estimatedMark(r.t))
	}
	tw.Flush()

	if anyEstimated {
		fmt.Println("\n* includes estimated counts (provider did not report token usage;")
		fmt.Println("  approximated at ~4 characters per token).")
	}
}

// estimatedMark flags a row whose totals include at least one estimated call.
func estimatedMark(t tokenTotals) string {
	if t.HasEstimated {
		return "*"
	}
	return ""
}

// commafy renders an integer with thousands separators for readability.
func commafy(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg = "-"
		s = s[1:]
	}
	if len(s) <= 3 {
		return neg + s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return neg + string(out)
}
