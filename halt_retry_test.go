package main

// Tests for the run-level trip-breaker (halts table + activeHalt + the gate's
// halt notice) and the widened scan retry path (transient provider failures and
// unparseable completions are re-attempted before falling to on_error).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHaltLedger(t *testing.T) {
	db := newTestDB(t)

	// Empty ledger → no halt.
	h, err := activeHalt(db, "self", 900)
	if err != nil || h != nil {
		t.Fatalf("empty ledger: h=%+v err=%v", h, err)
	}

	if err := recordHalt(db, "evil-pkg", "hash1", "malicious", "curl|sh in prepare()"); err != nil {
		t.Fatalf("recordHalt: %v", err)
	}

	// A different package's gate sees the halt, with fields intact.
	h, err = activeHalt(db, "innocent-pkg", 900)
	if err != nil || h == nil {
		t.Fatalf("activeHalt: h=%v err=%v", h, err)
	}
	if h.Package != "evil-pkg" || h.Hash != "hash1" || h.Verdict != "malicious" ||
		!strings.Contains(h.Reason, "curl|sh") {
		t.Errorf("halt fields = %+v", h)
	}

	// The blocked package's own gate is exempt (its own scan re-decides).
	if h, _ := activeHalt(db, "evil-pkg", 900); h != nil {
		t.Errorf("self should be exempt, got %+v", h)
	}

	// windowSeconds <= 0 disables the breaker.
	if h, _ := activeHalt(db, "innocent-pkg", 0); h != nil {
		t.Errorf("window 0 should disable, got %+v", h)
	}

	// An acknowledgement of the exact blocked hash resolves the halt even if the
	// rows were not deleted (older-binary compatibility path: the NOT EXISTS guard).
	if _, err := db.Exec(`INSERT INTO packages (name, acknowledged_hash) VALUES ('evil-pkg','hash1')`); err != nil {
		t.Fatal(err)
	}
	if h, _ := activeHalt(db, "innocent-pkg", 900); h != nil {
		t.Errorf("acked hash should resolve the halt, got %+v", h)
	}
	// A different (newer) blocked hash is NOT resolved by the old ack.
	if err := recordHalt(db, "evil-pkg", "hash2", "malicious", "new payload"); err != nil {
		t.Fatal(err)
	}
	if h, _ := activeHalt(db, "innocent-pkg", 900); h == nil || h.Hash != "hash2" {
		t.Errorf("new hash must halt despite old ack, got %+v", h)
	}

	// storeAcknowledgement deletes the package's halt rows outright.
	if _, err := storeAcknowledgement(db, "evil-pkg", "hash2"); err != nil {
		t.Fatalf("storeAcknowledgement: %v", err)
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM halts WHERE package='evil-pkg'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("storeAcknowledgement left %d halt rows", left)
	}

	// Expiry: a halt older than the window is ignored.
	if err := recordHalt(db, "old-pkg", "h", "suspicious", "stale"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE halts SET created_at=? WHERE package='old-pkg'`, old); err != nil {
		t.Fatal(err)
	}
	if h, _ := activeHalt(db, "innocent-pkg", 900); h != nil {
		t.Errorf("expired halt should be ignored, got %+v", h)
	}

	// clearHalts empties the ledger (waurden resume).
	if err := recordHalt(db, "another", "h3", "malicious", "x"); err != nil {
		t.Fatal(err)
	}
	n, err := clearHalts(db)
	if err != nil || n < 1 {
		t.Fatalf("clearHalts: n=%d err=%v", n, err)
	}
	if h, _ := activeHalt(db, "innocent-pkg", 900); h != nil {
		t.Errorf("halt after clearHalts: %+v", h)
	}
}

func TestHaltApplies(t *testing.T) {
	verdictHalt := &HaltEvent{Package: "p", Verdict: "malicious"}
	errorHalt := &HaltEvent{Package: "p", Verdict: "error"}

	// Verdict halts bind regardless of config.
	for _, cfg := range []Config{
		{OnError: "block"},
		{OnError: "warn"},
		{OnError: "block", ScanMode: "heuristics"},
	} {
		if !haltApplies(cfg, verdictHalt) {
			t.Errorf("verdict halt must bind under %+v", cfg)
		}
	}

	// A scan-failure halt binds only while the current run would still produce
	// one — otherwise it would defeat the advertised escape hatches
	// (WAURDEN_ON_ERROR=warn / WAURDEN_SCAN_MODE=heuristics).
	if !haltApplies(Config{OnError: "block"}, errorHalt) {
		t.Error("error halt should bind under on_error=block")
	}
	if haltApplies(Config{OnError: "warn"}, errorHalt) {
		t.Error("error halt must not bind under on_error=warn")
	}
	if haltApplies(Config{OnError: "block", ScanMode: "heuristics"}, errorHalt) {
		t.Error("error halt must not bind in heuristics mode (scans cannot fail offline)")
	}
}

func TestAgoString(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		in   string
		want string
	}{
		{now.Add(-42 * time.Second).Format(time.RFC3339), "s ago"},
		{now.Add(-7 * time.Minute).Format(time.RFC3339), "m ago"},
		{now.Add(-3 * time.Hour).Format(time.RFC3339), "h ago"},
		{"garbage", "at garbage"},
	}
	for _, c := range cases {
		if got := agoString(c.in); !strings.Contains(got, c.want) {
			t.Errorf("agoString(%q) = %q, want contains %q", c.in, got, c.want)
		}
	}
}

func TestPrintHaltNotice(t *testing.T) {
	h := &HaltEvent{
		Package:   "evil-pkg",
		Hash:      "abc",
		Verdict:   "malicious",
		Reason:    "curl|sh",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	out := captureStderr(t, func() { printHaltNotice(h) })
	for _, want := range []string{"halting this build", "evil-pkg", "waurden resume", "waurden allow", "waurden show evil-pkg"} {
		if !strings.Contains(out, want) {
			t.Errorf("halt notice missing %q:\n%s", want, out)
		}
	}
	// A scan-failure halt is worded as infrastructure, not a verdict.
	h.Verdict = "error"
	out = captureStderr(t, func() { printHaltNotice(h) })
	if !strings.Contains(out, "scan failure") {
		t.Errorf("error halt should say scan failure:\n%s", out)
	}
}

func TestPrintBlockGuidance(t *testing.T) {
	pf := PackageFiles{Name: "evil-pkg", Dir: "/tmp/build/evil-pkg", Hash: "abc"}
	v := Verdict{Verdict: "malicious", Confidence: 0.97}

	// No stored commit → inspect + allow lines, but no diff command.
	out := captureStderr(t, func() { printBlockGuidance(pf, nil, v) })
	for _, want := range []string{"less /tmp/build/evil-pkg/PKGBUILD", "waurden show evil-pkg", "waurden allow /tmp/build/evil-pkg", "I accept the risk"} {
		if !strings.Contains(out, want) {
			t.Errorf("guidance missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "git -C") {
		t.Errorf("no repo/commit → no diff line:\n%s", out)
	}

	// A real repo whose HEAD moved past the stored last-scanned commit → the
	// diff command is offered.
	dir := initRepo(t, "dev@example.com", "dev@example.com")
	head, err := gitHeadCommit(dir)
	if err != nil {
		t.Fatalf("gitHeadCommit: %v", err)
	}
	pf.Dir = dir
	rec := &DBRecord{LastScannedCommit: "0000000000000000000000000000000000000000"}
	out = captureStderr(t, func() { printBlockGuidance(pf, rec, v) })
	if !strings.Contains(out, "git -C "+dir+" diff") {
		t.Errorf("expected diff command:\n%s", out)
	}
	// HEAD unchanged since the last scan → nothing to diff, line omitted.
	rec.LastScannedCommit = head
	out = captureStderr(t, func() { printBlockGuidance(pf, rec, v) })
	if strings.Contains(out, "git -C") {
		t.Errorf("unchanged HEAD should omit the diff line:\n%s", out)
	}
}

func TestPrintScanFailGuidance(t *testing.T) {
	cfg := Config{Provider: "openai", Model: "qwen3-coder", BaseURL: "https://openrouter.ai/api/v1"}
	out := captureStderr(t, func() { printScanFailGuidance(cfg) })
	for _, want := range []string{
		"could not complete",
		"WAURDEN_PROVIDER",
		"waurden configure",
		"WAURDEN_SCAN_MODE=heuristics",
		"WAURDEN_ON_ERROR=warn",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan-fail guidance missing %q:\n%s", want, out)
		}
	}
}

func TestCallOpenAIEmptyContentIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP 200, choices present, blank completion — the flake seen from
		// OpenRouter/Bedrock under a concurrent gate burst.
		fmt.Fprint(w, `{"choices":[{"message":{"content":"  "}}]}`)
	}))
	defer srv.Close()

	cfg := Config{Provider: "openai", BaseURL: srv.URL, APIKey: "k", Timeout: 5}
	_, _, err := callOpenAI(cfg, "sys", "user")
	if err == nil {
		t.Fatal("blank completion should be an error, was returned as success")
	}
	var te *transientError
	if !errors.As(err, &te) {
		t.Errorf("blank completion should be transient (retryable), got %T: %v", err, err)
	}
}

func TestCallOpenAIMissingChoicesIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":{"message":"upstream hiccup"}}`) // 200 with no choices
	}))
	defer srv.Close()

	cfg := Config{Provider: "openai", BaseURL: srv.URL, APIKey: "k", Timeout: 5}
	_, _, err := callOpenAI(cfg, "sys", "user")
	var te *transientError
	if err == nil || !errors.As(err, &te) {
		t.Errorf("missing choices should be transient, got %v", err)
	}
}

func TestPostJSONRetriesOn500(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":{"message":"internal"}}`)
			return
		}
		fmt.Fprint(w, `{"recovered":true}`)
	}))
	defer srv.Close()

	got, err := postJSON(httpClient(Config{Timeout: 5}), srv.URL, nil, map[string]string{})
	if err != nil {
		t.Fatalf("postJSON 500 retry: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 attempts, got %d", calls)
	}
	if string(got) != `{"recovered":true}` {
		t.Errorf("body = %s", got)
	}
}

func TestPostJSONTransportErrorIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // connection refused from here on

	_, err := postJSON(httpClient(Config{Timeout: 2}), srv.URL, nil, map[string]string{})
	var te *transientError
	if err == nil || !errors.As(err, &te) {
		t.Errorf("transport error should be transient, got %v", err)
	}
}

// silenceRetrySleep removes the between-attempt backoff for the duration of a test.
func silenceRetrySleep(t *testing.T) {
	t.Helper()
	old := scanRetrySleep
	scanRetrySleep = func(time.Duration) {}
	t.Cleanup(func() { scanRetrySleep = old })
}

const verdictOKJSON = `{"verdict":"ok","confidence":0.9,"findings":[],"summary":"fine","source_analyzed":"pkgbuild-only"}`

// openAICompletion wraps a completion string in an OpenAI chat response body.
func openAICompletion(content string) string {
	body := map[string]interface{}{
		"choices": []map[string]interface{}{
			{"message": map[string]string{"content": content}},
		},
	}
	b, _ := json.Marshal(body)
	return string(b)
}

func TestAnalyzeRetriesTransientLLMFailure(t *testing.T) {
	initHeuristics()
	silenceRetrySleep(t)
	db := newTestDB(t)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprint(w, openAICompletion("")) // blank completion → transient
			return
		}
		fmt.Fprint(w, openAICompletion(verdictOKJSON))
	}))
	defer srv.Close()

	cfg := Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", Timeout: 5, OnError: "block"}
	pf := mustCollect(t, "benign")
	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if v.ScanFailed {
		t.Fatalf("scan should have recovered on retry: %+v", v)
	}
	if v.Verdict != "ok" || calls != 2 {
		t.Errorf("verdict=%q calls=%d, want ok/2", v.Verdict, calls)
	}
}

func TestAnalyzeRetriesParseFailureThenGivesUp(t *testing.T) {
	initHeuristics()
	silenceRetrySleep(t)
	db := newTestDB(t)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// HTTP 200 with prose and no JSON object — parseVerdict fails every time.
		fmt.Fprint(w, openAICompletion("I'm sorry, I cannot audit this package."))
	}))
	defer srv.Close()

	cfg := Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", Timeout: 5, OnError: "block"}
	pf := mustCollect(t, "benign")
	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !v.ScanFailed {
		t.Fatalf("persistent parse failure should surface as ScanFailed, got %+v", v)
	}
	if calls != scanAttempts {
		t.Errorf("calls = %d, want the full budget of %d", calls, scanAttempts)
	}
	// A failed scan is never cached (fail-closed on the next run).
	if rec, _ := lookupRecord(db, pf.Name); rec != nil && rec.PKGBUILDHash == pf.Hash {
		t.Errorf("failed scan must not be cached: %+v", rec)
	}
}

func TestAnalyzeDoesNotRetryDeterministicFailure(t *testing.T) {
	initHeuristics()
	silenceRetrySleep(t)
	db := newTestDB(t)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(401) // bad API key: deterministic, postJSON does not retry it
		fmt.Fprint(w, `{"error":{"message":"invalid api key"}}`)
	}))
	defer srv.Close()

	cfg := Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", Timeout: 5, OnError: "block"}
	pf := mustCollect(t, "benign")
	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !v.ScanFailed {
		t.Fatalf("401 should be a scan failure, got %+v", v)
	}
	if calls != 1 {
		t.Errorf("deterministic 401 burned %d attempts, want 1", calls)
	}
}
