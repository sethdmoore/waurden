package main

import (
	"path/filepath"
	"testing"
	"time"
)

// sampleRecord builds a fully-populated DBRecord for a package name.
func sampleRecord(name string) DBRecord {
	return DBRecord{
		Name:            name,
		LastScanned:     "2026-07-15T10:00:00Z",
		PKGBUILDHash:    "hash-" + name,
		PKGBUILDText:    "pkgname=" + name + "\nbuild(){ make; }\n",
		HelperFiles:     `{"foo.install":"post_install(){ :; }"}`,
		SourceHashes:    "{}",
		Diff:            "",
		Verdict:         "ok",
		Confidence:      0.92,
		Summary:         "clean",
		Findings:        `[{"severity":"info","file":"PKGBUILD","detail":"d","evidence":"e"}]`,
		SourceAnalyzed:  "pkgbuild-only",
		Provider:        "static (heuristics)",
		KnownCommitters: `["a@example.com"]`,
	}
}

func TestOpenDBCreatesSchema(t *testing.T) {
	db := newTestDB(t)
	// All three tables must exist and be queryable.
	for _, tbl := range []string{"packages", "scans", "token_usage"} {
		if _, err := db.Exec("SELECT count(*) FROM " + tbl); err != nil {
			t.Errorf("table %s not created: %v", tbl, err)
		}
	}
	// The migrated columns must be present on packages.
	for _, col := range []string{"known_committers", "acknowledged_hash", "maintainer", "prev_maintainer"} {
		if _, err := db.Exec("SELECT " + col + " FROM packages"); err != nil {
			t.Errorf("column %s missing: %v", col, err)
		}
	}
}

func TestOpenDBNegativeBusyTimeoutClamped(t *testing.T) {
	// A negative busy timeout must be clamped to 0 (fail-fast), not error out.
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "x.db"), -5)
	if err != nil {
		t.Fatalf("openDB negative busy timeout: %v", err)
	}
	db.Close()
}

func TestMigrateColumnsIdempotent(t *testing.T) {
	db := newTestDB(t)
	// openDB already ran migrateColumns; running it again must be a no-op (the
	// "duplicate column name" errors are swallowed), not an error.
	if err := migrateColumns(db); err != nil {
		t.Fatalf("second migrateColumns: %v", err)
	}
	if err := migrateColumns(db); err != nil {
		t.Fatalf("third migrateColumns: %v", err)
	}
}

func TestUpsertAndLookupRoundTrip(t *testing.T) {
	db := newTestDB(t)
	rec := sampleRecord("firefox")
	if err := upsertRecord(db, rec); err != nil {
		t.Fatalf("upsertRecord: %v", err)
	}
	got, err := lookupRecord(db, "firefox")
	if err != nil {
		t.Fatalf("lookupRecord: %v", err)
	}
	if got == nil {
		t.Fatal("lookupRecord returned nil for an existing row")
	}
	if got.Name != rec.Name || got.PKGBUILDHash != rec.PKGBUILDHash ||
		got.Verdict != rec.Verdict || got.Confidence != rec.Confidence ||
		got.Provider != rec.Provider || got.Summary != rec.Summary ||
		got.PKGBUILDText != rec.PKGBUILDText || got.SourceAnalyzed != rec.SourceAnalyzed ||
		got.KnownCommitters != rec.KnownCommitters || got.Findings != rec.Findings {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", *got, rec)
	}
}

func TestLookupRecordMissing(t *testing.T) {
	db := newTestDB(t)
	got, err := lookupRecord(db, "does-not-exist")
	if err != nil {
		t.Fatalf("lookupRecord missing returned error: %v", err)
	}
	if got != nil {
		t.Errorf("lookupRecord missing = %+v, want nil", got)
	}
}

func TestUpsertOverwritesButPreservesAck(t *testing.T) {
	db := newTestDB(t)
	rec := sampleRecord("chrome")
	if err := upsertRecord(db, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Pin an acknowledgement, then re-upsert with a new verdict. The ack must
	// survive (upsertRecord never names acknowledged_hash).
	if _, err := storeAcknowledgement(db, "chrome", "hash-chrome"); err != nil {
		t.Fatalf("storeAcknowledgement: %v", err)
	}
	rec.Verdict = "suspicious"
	rec.Confidence = 0.4
	rec.PKGBUILDHash = "hash-chrome-v2"
	if err := upsertRecord(db, rec); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ := lookupRecord(db, "chrome")
	if got.Verdict != "suspicious" || got.Confidence != 0.4 {
		t.Errorf("upsert did not overwrite verdict: %+v", got)
	}
	if got.AcknowledgedHash != "hash-chrome" {
		t.Errorf("acknowledged_hash not preserved across upsert: %q", got.AcknowledgedHash)
	}
}

func TestRecheckRecord(t *testing.T) {
	db := newTestDB(t)
	rec := sampleRecord("vim")
	upsertRecord(db, rec)

	n, err := recheckRecord(db, "vim")
	if err != nil {
		t.Fatalf("recheckRecord: %v", err)
	}
	if n != 1 {
		t.Errorf("recheckRecord rows affected = %d, want 1", n)
	}
	got, _ := lookupRecord(db, "vim")
	if got == nil {
		t.Fatal("recheckRecord deleted the row; it should only blank the hash")
	}
	if got.PKGBUILDHash != "" {
		t.Errorf("pkgbuild_hash = %q, want blank after recheck", got.PKGBUILDHash)
	}
	// The rest of the row (committer history) must survive.
	if got.KnownCommitters != rec.KnownCommitters {
		t.Errorf("known_committers wiped by recheck: %q", got.KnownCommitters)
	}
	// Rechecking a missing package affects 0 rows, no error.
	n, err = recheckRecord(db, "nope")
	if err != nil || n != 0 {
		t.Errorf("recheckRecord(missing) = (%d,%v), want (0,nil)", n, err)
	}
}

func TestDeleteRecord(t *testing.T) {
	db := newTestDB(t)
	upsertRecord(db, sampleRecord("vim"))
	// Give the package a scan-history row so we can prove it is removed too.
	if err := recordScan(db, "vim", "abc123", "static", Verdict{Verdict: "ok"}, false); err != nil {
		t.Fatalf("recordScan: %v", err)
	}
	// A second package must be left untouched.
	upsertRecord(db, sampleRecord("emacs"))

	n, err := deleteRecord(db, "vim")
	if err != nil {
		t.Fatalf("deleteRecord: %v", err)
	}
	if n != 1 {
		t.Errorf("deleteRecord rows affected = %d, want 1", n)
	}
	if got, _ := lookupRecord(db, "vim"); got != nil {
		t.Errorf("packages row survived forget: %+v", got)
	}
	var scanCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scans WHERE package = ?`, "vim").Scan(&scanCount); err != nil {
		t.Fatalf("count scans: %v", err)
	}
	if scanCount != 0 {
		t.Errorf("scans rows survived forget: %d", scanCount)
	}
	// The unrelated package is intact.
	if got, _ := lookupRecord(db, "emacs"); got == nil {
		t.Error("deleteRecord removed an unrelated package")
	}
	// Deleting a missing package affects 0 rows, no error.
	n, err = deleteRecord(db, "nope")
	if err != nil || n != 0 {
		t.Errorf("deleteRecord(missing) = (%d,%v), want (0,nil)", n, err)
	}
}

func TestStoreAcknowledgement(t *testing.T) {
	db := newTestDB(t)
	// No row yet → 0 rows affected (caller surfaces this).
	n, err := storeAcknowledgement(db, "ghost", "h1")
	if err != nil {
		t.Fatalf("storeAcknowledgement(no row): %v", err)
	}
	if n != 0 {
		t.Errorf("ack on missing row affected %d rows, want 0", n)
	}
	// With a row present, the ack is stored and readable.
	upsertRecord(db, sampleRecord("ghost"))
	n, err = storeAcknowledgement(db, "ghost", "h2")
	if err != nil || n != 1 {
		t.Fatalf("storeAcknowledgement = (%d,%v), want (1,nil)", n, err)
	}
	got, _ := lookupRecord(db, "ghost")
	if got.AcknowledgedHash != "h2" {
		t.Errorf("acknowledged_hash = %q, want h2", got.AcknowledgedHash)
	}
}

func TestStoreWarnAcknowledgement(t *testing.T) {
	db := newTestDB(t)
	// No row yet → 0 rows affected.
	n, err := storeWarnAcknowledgement(db, "ghost", "wh1")
	if err != nil {
		t.Fatalf("storeWarnAcknowledgement(no row): %v", err)
	}
	if n != 0 {
		t.Errorf("warn ack on missing row affected %d rows, want 0", n)
	}
	// With a row present, the warn ack is stored and readable.
	upsertRecord(db, sampleRecord("ghost"))
	n, err = storeWarnAcknowledgement(db, "ghost", "wh2")
	if err != nil || n != 1 {
		t.Fatalf("storeWarnAcknowledgement = (%d,%v), want (1,nil)", n, err)
	}
	got, _ := lookupRecord(db, "ghost")
	if got.AcknowledgedWarnHash != "wh2" {
		t.Errorf("acknowledged_warn_hash = %q, want wh2", got.AcknowledgedWarnHash)
	}
}

// TestWarnAndBlockAcksAreIndependent guards the security property that a plain-"y"
// warn acceptance never leaks into the high-friction block acknowledgement column
// (and vice versa): they are stored, read, and cleared separately.
func TestWarnAndBlockAcksAreIndependent(t *testing.T) {
	db := newTestDB(t)
	upsertRecord(db, sampleRecord("dual"))

	if _, err := storeWarnAcknowledgement(db, "dual", "warnhash"); err != nil {
		t.Fatalf("storeWarnAcknowledgement: %v", err)
	}
	got, _ := lookupRecord(db, "dual")
	if got.AcknowledgedWarnHash != "warnhash" {
		t.Fatalf("warn ack = %q, want warnhash", got.AcknowledgedWarnHash)
	}
	if got.AcknowledgedHash != "" {
		t.Errorf("warn ack must not populate the block ack column; got %q", got.AcknowledgedHash)
	}

	if _, err := storeAcknowledgement(db, "dual", "blockhash"); err != nil {
		t.Fatalf("storeAcknowledgement: %v", err)
	}
	got, _ = lookupRecord(db, "dual")
	if got.AcknowledgedHash != "blockhash" {
		t.Errorf("block ack = %q, want blockhash", got.AcknowledgedHash)
	}
	if got.AcknowledgedWarnHash != "warnhash" {
		t.Errorf("block ack clobbered the warn ack: %q", got.AcknowledgedWarnHash)
	}

	// A routine re-scan (upsertRecord) must leave both acks untouched.
	if err := upsertRecord(db, sampleRecord("dual")); err != nil {
		t.Fatalf("upsertRecord: %v", err)
	}
	got, _ = lookupRecord(db, "dual")
	if got.AcknowledgedWarnHash != "warnhash" || got.AcknowledgedHash != "blockhash" {
		t.Errorf("upsert clobbered an ack: warn=%q block=%q", got.AcknowledgedWarnHash, got.AcknowledgedHash)
	}
}

func TestRecordScanAndRecentScans(t *testing.T) {
	db := newTestDB(t)
	// The scans FK references packages(name); upsert the parents first.
	upsertRecord(db, sampleRecord("pkg-a"))
	upsertRecord(db, sampleRecord("pkg-b"))

	okV := Verdict{Verdict: "ok", Confidence: 0.9, SourceAnalyzed: "pkgbuild-only",
		Findings: []Finding{}}
	badV := Verdict{Verdict: "malicious", Confidence: 0.95, SourceAnalyzed: "pkgbuild-only",
		Findings: []Finding{{Severity: "critical", File: "PKGBUILD", Detail: "curl|sh", Evidence: "curl x | sh"}},
		Summary:  "blocked"}

	if err := recordScan(db, "pkg-a", "h1", "static (heuristics)", okV, false); err != nil {
		t.Fatalf("recordScan ok: %v", err)
	}
	if err := recordScan(db, "pkg-b", "h2", "static (heuristics)", badV, true); err != nil {
		t.Fatalf("recordScan bad: %v", err)
	}

	// All events, newest first.
	all, err := recentScans(db, false, 0)
	if err != nil {
		t.Fatalf("recentScans: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("recentScans returned %d, want 2", len(all))
	}

	// Only-blocked filter.
	blocked, err := recentScans(db, true, 0)
	if err != nil {
		t.Fatalf("recentScans blocked: %v", err)
	}
	if len(blocked) != 1 || blocked[0].Package != "pkg-b" || !blocked[0].Blocked {
		t.Fatalf("blocked filter = %+v, want single pkg-b blocked", blocked)
	}
	if blocked[0].Verdict != "malicious" || blocked[0].Confidence != 0.95 {
		t.Errorf("blocked event fields wrong: %+v", blocked[0])
	}
	if blocked[0].Summary != "blocked" {
		t.Errorf("blocked event summary = %q, want 'blocked'", blocked[0].Summary)
	}

	// Limit is honoured.
	limited, err := recentScans(db, false, 1)
	if err != nil {
		t.Fatalf("recentScans limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("limit=1 returned %d rows", len(limited))
	}
}

func TestRecordScanBlockedFlagPersists(t *testing.T) {
	db := newTestDB(t)
	upsertRecord(db, sampleRecord("p"))
	v := Verdict{Verdict: "suspicious", Confidence: 0.6}
	// blocked=false should store 0 and read back as Blocked==false.
	recordScan(db, "p", "h", "prov", v, false)
	ev, _ := recentScans(db, false, 1)
	if len(ev) != 1 || ev[0].Blocked {
		t.Errorf("blocked=false not persisted: %+v", ev)
	}
	_ = time.Now // keep time import if unused elsewhere
}

func TestRecentlyAnnounced(t *testing.T) {
	db := newTestDB(t)
	upsertRecord(db, sampleRecord("pkg-a"))
	upsertRecord(db, sampleRecord("pkg-b"))

	okV := Verdict{Verdict: "ok", Confidence: 0.9, Findings: []Finding{}}
	if err := recordScan(db, "pkg-a", "h1", "static", okV, false); err != nil {
		t.Fatalf("recordScan: %v", err)
	}

	// Just-recorded (name, hash) is within any positive window.
	if seen, err := recentlyAnnounced(db, "pkg-a", "h1", 120); err != nil || !seen {
		t.Errorf("recentlyAnnounced(pkg-a,h1,120) = %v,%v; want true,nil", seen, err)
	}
	// A different hash for the same package is NOT deduped — a PKGBUILD edit must
	// re-announce.
	if seen, _ := recentlyAnnounced(db, "pkg-a", "h2", 120); seen {
		t.Error("different hash reported as recently announced")
	}
	// A different package with the same hash is NOT deduped.
	if seen, _ := recentlyAnnounced(db, "pkg-b", "h1", 120); seen {
		t.Error("different package reported as recently announced")
	}
	// Window of 0 disables dedup entirely (always print).
	if seen, _ := recentlyAnnounced(db, "pkg-a", "h1", 0); seen {
		t.Error("windowSeconds=0 should disable dedup")
	}
	// Empty hash never matches (unknown/unhashable package).
	if seen, _ := recentlyAnnounced(db, "pkg-a", "", 120); seen {
		t.Error("empty hash should never match")
	}

	// A scan older than the window is outside it: insert one 300s in the past and
	// probe both sides of the boundary.
	old := time.Now().UTC().Add(-300 * time.Second).Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO scans
		(package, scanned_at, pkgbuild_hash, verdict, confidence, blocked, provider)
		VALUES (?,?,?,?,?,?,?)`, "pkg-b", old, "old", "ok", 0.9, 0, "static"); err != nil {
		t.Fatalf("insert old scan: %v", err)
	}
	if seen, _ := recentlyAnnounced(db, "pkg-b", "old", 120); seen {
		t.Error("scan 300s old should be outside a 120s window")
	}
	if seen, err := recentlyAnnounced(db, "pkg-b", "old", 600); err != nil || !seen {
		t.Errorf("scan 300s old should be inside a 600s window: %v,%v", seen, err)
	}
}
