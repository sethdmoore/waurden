package main

import (
	"testing"
)

// mustCollect loads a real sample package (PKGBUILD + helpers, hash computed) the
// same way production does, so analyze() sees an authentic PackageFiles.
func mustCollect(t *testing.T, sample string) PackageFiles {
	t.Helper()
	pf, err := collectFiles(sampleDir(sample))
	if err != nil {
		t.Fatalf("collectFiles(%s): %v", sample, err)
	}
	return pf
}

func TestAnalyzeBenignThenCacheHit(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	cfg := Config{Provider: "static", OnError: "warn"}
	pf := mustCollect(t, "benign")

	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if v.Verdict != "ok" {
		t.Fatalf("benign verdict = %q, want ok", v.Verdict)
	}
	if v.Cached {
		t.Error("first scan should not be cached")
	}

	// The verdict was persisted.
	rec, _ := lookupRecord(db, pf.Name)
	if rec == nil || rec.Verdict != "ok" || rec.PKGBUILDHash != pf.Hash {
		t.Fatalf("verdict not stored: %+v", rec)
	}
	if rec.Provider != "static" {
		t.Errorf("stored provider = %q, want static", rec.Provider)
	}

	// Second scan of identical content + engine → cache hit.
	v2, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze 2: %v", err)
	}
	if !v2.Cached {
		t.Error("second scan should be a cache hit")
	}
	if v2.Verdict != "ok" {
		t.Errorf("cached verdict = %q", v2.Verdict)
	}
}

func TestAnalyzeForceBypassesCache(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	cfg := Config{Provider: "static", OnError: "warn"}
	pf := mustCollect(t, "benign")

	if _, err := analyze(cfg, db, pf, false); err != nil {
		t.Fatalf("analyze seed: %v", err)
	}
	// force=true must re-scan even though the row is cacheable → not Cached.
	v, err := analyze(cfg, db, pf, true)
	if err != nil {
		t.Fatalf("analyze force: %v", err)
	}
	if v.Cached {
		t.Error("force scan should not be served from cache")
	}
}

func TestAnalyzeProviderChangeInvalidatesCache(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	pf := mustCollect(t, "benign")

	// Seed with the static engine.
	if _, err := analyze(Config{Provider: "static", OnError: "warn"}, db, pf, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A different engine identity (heuristics-only) is a cache MISS, not a reuse.
	v, err := analyze(Config{Provider: "static", ScanMode: "heuristics"}, db, pf, false)
	if err != nil {
		t.Fatalf("analyze heuristics: %v", err)
	}
	if v.Cached {
		t.Error("engine change should miss the cache")
	}
}

func TestAnalyzeHeuristicBlock(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	cfg := Config{Provider: "static", OnError: "warn"}
	pf := mustCollect(t, "curlbash")

	v, err := analyze(cfg, db, pf, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if v.Verdict != "malicious" {
		t.Fatalf("curlbash verdict = %q, want malicious (heuristic hard block)", v.Verdict)
	}
	if v.Confidence < 0.9 {
		t.Errorf("heuristic block confidence = %v, want >= 0.9", v.Confidence)
	}
	if len(v.Findings) == 0 {
		t.Error("heuristic block carried no findings")
	}
	// The block is persisted too.
	rec, _ := lookupRecord(db, pf.Name)
	if rec == nil || rec.Verdict != "malicious" {
		t.Fatalf("block not stored: %+v", rec)
	}
}

func TestAnalyzeHeuristicsOnlyMode(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)

	// Clean package in heuristics-only mode → ok at modest confidence 0.5.
	cfg := Config{Provider: "static", ScanMode: "heuristics", OnError: "warn"}
	clean := mustCollect(t, "benign")
	v, err := analyze(cfg, db, clean, false)
	if err != nil {
		t.Fatalf("analyze clean: %v", err)
	}
	if v.Verdict != "ok" || v.Confidence != 0.5 {
		t.Errorf("heuristics-only clean = %q/%v, want ok/0.5", v.Verdict, v.Confidence)
	}

	// benign-daemon has advisory (medium) findings → surfaced as suspicious, not ok.
	adv := mustCollect(t, "benign-daemon")
	v2, err := analyze(cfg, db, adv, false)
	if err != nil {
		t.Fatalf("analyze advisory: %v", err)
	}
	if v2.Verdict != "suspicious" {
		t.Errorf("heuristics-only advisory = %q, want suspicious", v2.Verdict)
	}
	if len(v2.Findings) == 0 {
		t.Error("advisory verdict should carry the flagged findings")
	}
}

func TestStoreVerdictRoundTrip(t *testing.T) {
	db := newTestDB(t)
	cfg := Config{Provider: "anthropic", Model: "claude-haiku-4-5"}
	pf := PackageFiles{
		Name:            "somepkg",
		Hash:            "deadbeef",
		PKGBUILDRaw:     "pkgname=somepkg\n",
		HelperFiles:     map[string]string{"a.install": "post_install(){ :; }"},
		KnownCommitters: `["dev@example.com"]`,
	}
	v := Verdict{
		Verdict:        "suspicious",
		Confidence:     0.66,
		Summary:        "worth a look",
		SourceAnalyzed: "pkgbuild-only",
		Findings:       []Finding{{Severity: "medium", File: "PKGBUILD", Detail: "eval", Evidence: "eval $x"}},
	}
	if err := storeVerdict(cfg, db, pf, v, "+ diff line", "abc123commit"); err != nil {
		t.Fatalf("storeVerdict: %v", err)
	}
	rec, _ := lookupRecord(db, "somepkg")
	if rec == nil {
		t.Fatal("row not stored")
	}
	if rec.Verdict != "suspicious" || rec.Confidence != 0.66 || rec.SourceAnalyzed != "pkgbuild-only" {
		t.Errorf("stored verdict fields wrong: %+v", rec)
	}
	// The scanned commit is persisted and read back.
	if rec.LastScannedCommit != "abc123commit" {
		t.Errorf("last_scanned_commit = %q, want abc123commit", rec.LastScannedCommit)
	}
	// Provider is the engine string "<provider>/<model>".
	if rec.Provider != "anthropic/claude-haiku-4-5" {
		t.Errorf("stored provider = %q", rec.Provider)
	}
	// Diff, helper files JSON and committer set are stored.
	if rec.Diff != "+ diff line" {
		t.Errorf("diff = %q", rec.Diff)
	}
	if rec.KnownCommitters != `["dev@example.com"]` {
		t.Errorf("committers = %q", rec.KnownCommitters)
	}
	if rec.HelperFiles == "" || rec.HelperFiles == "null" {
		t.Errorf("helper files JSON = %q", rec.HelperFiles)
	}
}
