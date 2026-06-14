package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	PrevMaintainer string
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
    provider         TEXT,
    maintainer       TEXT,
    prev_maintainer  TEXT
);`

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
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
		COALESCE(maintainer,''), COALESCE(prev_maintainer,'')
		FROM packages WHERE name = ?`, name)

	var r DBRecord
	err := row.Scan(&r.Name, &r.LastScanned, &r.PKGBUILDHash, &r.PKGBUILDText,
		&r.HelperFiles, &r.SourceHashes, &r.Diff, &r.Verdict, &r.Confidence,
		&r.Summary, &r.Findings, &r.SourceAnalyzed, &r.Provider,
		&r.Maintainer, &r.PrevMaintainer)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func storeMaintainer(db *sql.DB, pkgname string, maintainer *string) error {
	var val interface{}
	if maintainer != nil {
		val = *maintainer
	}
	_, err := db.Exec(
		`UPDATE packages SET prev_maintainer = maintainer, maintainer = ? WHERE name = ?`,
		val, pkgname)
	return err
}

func upsertRecord(db *sql.DB, r DBRecord) error {
	_, err := db.Exec(`INSERT INTO packages (name, last_scanned, pkgbuild_hash,
		pkgbuild_text, helper_files, source_hashes, diff, verdict, confidence,
		summary, findings, source_analyzed, provider)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
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
		provider=excluded.provider`,
		r.Name, r.LastScanned, r.PKGBUILDHash, r.PKGBUILDText,
		r.HelperFiles, r.SourceHashes, r.Diff, r.Verdict, r.Confidence,
		r.Summary, r.Findings, r.SourceAnalyzed, r.Provider)
	return err
}
