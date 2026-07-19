package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DBRecord struct {
	Name           string
	LastScanned    string
	PKGBUILDHash   string
	PKGBUILDText   string
	HelperFiles    string
	SourceHashes   string
	Diff           string
	Verdict        string
	Confidence     float64
	Summary        string
	Findings       string
	SourceAnalyzed string
	Provider       string
	Maintainer     string
	// KnownCommitters is a JSON []string of git author emails seen across all
	// prior scans of this package. See trackNewCommitters.
	KnownCommitters string
	// AcknowledgedHash is the pkgbuild_hash the user explicitly accepted via the
	// gate override or `waurden allow`. The gate honours it only while it equals
	// the current pf.Hash; any PKGBUILD edit changes the hash and voids the ack.
	// Written only by storeAcknowledgement, never by upsertRecord, so a routine
	// re-scan leaves it untouched.
	AcknowledgedHash string
}

const schema = `
CREATE TABLE IF NOT EXISTS packages (
    name             TEXT PRIMARY KEY,
    last_scanned     TEXT,
    pkgbuild_hash    TEXT,
    pkgbuild_text    TEXT,
    helper_files     TEXT,
    source_hashes    TEXT,
    diff             TEXT,
    verdict          TEXT,
    confidence       REAL,
    summary          TEXT,
    findings         TEXT,
    source_analyzed  TEXT,
    provider          TEXT,
    maintainer        TEXT,
    prev_maintainer   TEXT,
    known_committers  TEXT,
    acknowledged_hash TEXT
);`

// scans is the append-only history that packages (a PRIMARY KEY(name) cache,
// upserted on every scan) cannot keep: one row per scan event, so a re-scan no
// longer erases the prior verdict. This is what makes a block that scrolled past
// in the build flood durably reviewable (`waurden summary --history`). package
// references packages(name); FK is declared for intent (SQLite does not enforce
// it unless PRAGMA foreign_keys=ON, and the parent row is always upserted first).
const scansSchema = `
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package         TEXT NOT NULL,
    scanned_at      TEXT NOT NULL,
    pkgbuild_hash   TEXT,
    verdict         TEXT,
    confidence      REAL,
    blocked         INTEGER NOT NULL DEFAULT 0,
    provider        TEXT,
    source_analyzed TEXT,
    summary         TEXT,
    findings        TEXT,
    FOREIGN KEY(package) REFERENCES packages(name)
);`

const scansIndex = `CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scanned_at DESC);`

func openDB(path string, busyTimeoutSeconds int) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	// Under `yay`, the makepkg.conf.d hook runs `waurden gate` once per package
	// concurrently, so multiple processes open this DB at once. Default SQLite
	// (rollback journal, zero busy timeout) returns SQLITE_BUSY the instant one
	// process holds the write lock, which surfaced as "database is locked" gate
	// failures during a batched build. busy_timeout makes contenders wait instead
	// of erroring; WAL lets readers and the writer coexist. (foreign_keys stays
	// OFF deliberately — see the scans-table note above.)
	//
	// The wait is bounded, not unbounded: busy_timeout retries internally for at
	// most this many milliseconds of wall-clock, then returns SQLITE_BUSY (the
	// gate then fails closed rather than hanging the build). Configurable via
	// db_busy_timeout_seconds; a negative value is clamped to 0 (fail fast).
	if busyTimeoutSeconds < 0 {
		busyTimeoutSeconds = 0
	}
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)", path, busyTimeoutSeconds*1000)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Each statement runs separately: database/sql's Exec is one-statement, and
	// CREATE TABLE IF NOT EXISTS makes adding the scans table safe on an existing
	// DB (additive, no wipe — see MIGRATIONS.md).
	for _, stmt := range []string{schema, scansSchema, scansIndex} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate db: %w", err)
		}
	}
	if err := migrateColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate db columns: %w", err)
	}
	return db, nil
}

func migrateColumns(db *sql.DB) error {
	alters := []string{
		`ALTER TABLE packages ADD COLUMN maintainer TEXT`,
		`ALTER TABLE packages ADD COLUMN prev_maintainer TEXT`,
		`ALTER TABLE packages ADD COLUMN known_committers TEXT`,
		`ALTER TABLE packages ADD COLUMN acknowledged_hash TEXT`,
	}
	for _, stmt := range alters {
		if _, err := db.Exec(stmt); err != nil {
			if !strings.Contains(err.Error(), "duplicate column name") {
				return err
			}
		}
	}
	return nil
}

func lookupRecord(db *sql.DB, name string) (*DBRecord, error) {
	row := db.QueryRow(`SELECT name,
		COALESCE(last_scanned,''), COALESCE(pkgbuild_hash,''), COALESCE(pkgbuild_text,''),
		COALESCE(helper_files,''), COALESCE(source_hashes,''), COALESCE(diff,''),
		COALESCE(verdict,''), COALESCE(confidence,0), COALESCE(summary,''),
		COALESCE(findings,''), COALESCE(source_analyzed,''), COALESCE(provider,''),
		COALESCE(maintainer,''), COALESCE(known_committers,''),
		COALESCE(acknowledged_hash,'')
		FROM packages WHERE name = ?`, name)

	var r DBRecord
	err := row.Scan(&r.Name, &r.LastScanned, &r.PKGBUILDHash, &r.PKGBUILDText,
		&r.HelperFiles, &r.SourceHashes, &r.Diff, &r.Verdict, &r.Confidence,
		&r.Summary, &r.Findings, &r.SourceAnalyzed, &r.Provider,
		&r.Maintainer, &r.KnownCommitters, &r.AcknowledgedHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// forgetRecord blanks pkgbuild_hash so the next analyze() misses the verdict
// cache and re-scans, while leaving the rest of the row (notably
// known_committers, and the future acknowledged_hash) intact. Returns the number
// of rows affected (0 = no such package). See also scan --force, which re-scans
// without mutating the DB first.
func forgetRecord(db *sql.DB, name string) (int64, error) {
	res, err := db.Exec(`UPDATE packages SET pkgbuild_hash='' WHERE name = ?`, name)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// storeAcknowledgement pins the user's acceptance of a specific PKGBUILD hash.
// It is deliberately separate from upsertRecord: a routine scan's upsert never
// names acknowledged_hash, so the ack survives re-scans, and only an explicit
// gate override or `waurden allow` (which call this) can set it. The row is
// expected to already exist (analyze()/storeVerdict ran this same invocation);
// if it does not, RowsAffected is 0 and the caller can surface that.
func storeAcknowledgement(db *sql.DB, name, hash string) (int64, error) {
	res, err := db.Exec(`UPDATE packages SET acknowledged_hash=? WHERE name = ?`, hash, name)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ScanEvent is one row of the append-only scans history.
type ScanEvent struct {
	Package    string
	ScannedAt  string
	Verdict    string
	Confidence float64
	Blocked    bool
	Provider   string
	Summary    string
}

// recordScan appends a scan event to the history table. It is deliberately
// separate from upsertRecord (which maintains the current-state cache): the
// cache is overwritten on each scan, the history is never touched, so both a
// blocked verdict and the fact that policy blocked it survive re-scans. Called
// once per gate/scan invocation, including cache hits, so the history is a true
// timeline of when wAURden ran and what it decided. Non-fatal for callers.
func recordScan(db *sql.DB, name, hash, provider string, v Verdict, blocked bool) error {
	findingsJSON, _ := json.Marshal(v.Findings)
	b := 0
	if blocked {
		b = 1
	}
	_, err := db.Exec(`INSERT INTO scans
		(package, scanned_at, pkgbuild_hash, verdict, confidence, blocked,
		 provider, source_analyzed, summary, findings)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		name, time.Now().UTC().Format(time.RFC3339), hash,
		v.Verdict, v.Confidence, b, provider, v.SourceAnalyzed, v.Summary,
		string(findingsJSON))
	return err
}

// recentScans returns scan events newest-first, optionally only those policy
// blocked. limit <= 0 means no limit.
func recentScans(db *sql.DB, onlyBlocked bool, limit int) ([]ScanEvent, error) {
	q := `SELECT package, scanned_at, COALESCE(verdict,''), COALESCE(confidence,0),
		COALESCE(blocked,0), COALESCE(provider,''), COALESCE(summary,'')
		FROM scans`
	if onlyBlocked {
		q += ` WHERE blocked=1`
	}
	q += ` ORDER BY scanned_at DESC, id DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanEvent
	for rows.Next() {
		var e ScanEvent
		var blocked int
		if err := rows.Scan(&e.Package, &e.ScannedAt, &e.Verdict, &e.Confidence,
			&blocked, &e.Provider, &e.Summary); err != nil {
			return nil, err
		}
		e.Blocked = blocked != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func upsertRecord(db *sql.DB, r DBRecord) error {
	_, err := db.Exec(`INSERT INTO packages (name, last_scanned, pkgbuild_hash,
		pkgbuild_text, helper_files, source_hashes, diff, verdict, confidence,
		summary, findings, source_analyzed, provider, known_committers)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		last_scanned=excluded.last_scanned,
		pkgbuild_hash=excluded.pkgbuild_hash,
		pkgbuild_text=excluded.pkgbuild_text,
		helper_files=excluded.helper_files,
		source_hashes=excluded.source_hashes,
		diff=excluded.diff,
		verdict=excluded.verdict,
		confidence=excluded.confidence,
		summary=excluded.summary,
		findings=excluded.findings,
		source_analyzed=excluded.source_analyzed,
		provider=excluded.provider,
		known_committers=excluded.known_committers`,
		r.Name, r.LastScanned, r.PKGBUILDHash, r.PKGBUILDText,
		r.HelperFiles, r.SourceHashes, r.Diff, r.Verdict, r.Confidence,
		r.Summary, r.Findings, r.SourceAnalyzed, r.Provider, r.KnownCommitters)
	return err
}
