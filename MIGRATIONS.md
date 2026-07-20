# Schema migrations — policy & design

> **Standing rule: never tell a user to wipe or delete their database.**
> Every change to the SQLite schema ships with a migration that carries existing
> data forward. This file is the design for the migration runner and the
> checklist to follow each time the schema changes. Read it before touching the
> `schema` const or `migrateColumns` in `db.go`.

The user's `~/.local/share/waurden/waurden.db` accumulates real value over time:
verdict cache (saves LLM calls / rate limit budget), `known_committers` baselines
(committer-novelty tracking re-warns everything if lost), and `acknowledged_hash`
gate exceptions (a deliberate human security decision). Destroying any of these to
get a schema change is a regression, not a workaround.

---

## 1. Where we are today

`db.go` currently migrates in two ad-hoc steps inside `openDB`:

1. `db.Exec(schema)` — `CREATE TABLE IF NOT EXISTS packages (… all columns …)`.
   Brings a brand-new DB straight to the latest shape; a no-op on an existing DB.
2. `migrateColumns(db)` — a slice of `ALTER TABLE packages ADD COLUMN …`, each
   wrapped to ignore the `"duplicate column name"` error so it is idempotent.

This works for **additive columns only**, and it works *by accident of
idempotence* — there is no record of which migration generation a given file is
at. That is the gap this plan closes. It cannot express:

- renaming, dropping, or retyping a column;
- adding a `NOT NULL` / `CHECK` / `UNIQUE` constraint or a new `PRIMARY KEY`;
- splitting/merging tables or adding a second table;
- creating an index or trigger;
- a **data backfill** (computing a new column's value from existing rows).

SQLite's `ALTER TABLE` supports only `ADD COLUMN`, `RENAME COLUMN` (3.25+),
`DROP COLUMN` (3.35+), and `RENAME TABLE`. Everything else requires the
table-rebuild procedure (§4.2). Either way we first need to know *what version a
DB is at* so a migration runs exactly once.

---

## 2. Version tracking — `PRAGMA user_version`

SQLite reserves a 32-bit integer in the database header, `PRAGMA user_version`,
default `0`, untouched by SQLite itself. We use it as the monotonic schema
generation counter. No bookkeeping table, no extra dependency.

```
current := PRAGMA user_version            -- read
PRAGMA user_version = N                    -- write (N is an int literal; not parameterizable)
```

> Note: `user_version` cannot take a bound `?` parameter — build the statement
> with the integer literal (`fmt.Sprintf`), and only ever from our own constant.

### Migration generations

| `user_version` | Meaning |
|----------------|---------|
| `0` | Pre-framework DB **or** brand-new file. Schema is *unknown* — could be empty, or fully migrated by today's `IF NOT EXISTS` + `ADD COLUMN` path. |
| `1` | **Baseline.** The exact schema as of this document: `packages` with every column through `acknowledged_hash`. |
| `2`, `3`, … | Each future schema change, applied in order. |

The jump from `0` is the only delicate step (§3); from `1` onward every migration
runs against a known starting shape.

---

## 3. The runner

Conceptual shape (design sketch — implement when we move past plan-only scope):

```go
type migration struct {
    version int                 // target user_version after this runs
    name    string              // human label for logs/errors
    apply   func(*sql.Tx) error // all DDL + data moves for this step
}

// Ordered, append-only. Never edit a shipped entry; only append.
var migrations = []migration{
    {1, "baseline", migBaseline},
    // {2, "add foo column", migAddFoo},
}

func migrate(db *sql.DB) error {
    var cur int
    if err := db.QueryRow(`PRAGMA user_version`).Scan(&cur); err != nil {
        return err
    }
    for _, m := range migrations {
        if m.version <= cur {
            continue
        }
        tx, err := db.Begin()
        if err != nil {
            return err
        }
        if err := m.apply(tx); err != nil {
            tx.Rollback()
            return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
        }
        // user_version can't be parameterized; the literal comes from our const.
        if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, m.version)); err != nil {
            tx.Rollback()
            return fmt.Errorf("stamp version %d: %w", m.version, err)
        }
        if err := tx.Commit(); err != nil {
            return fmt.Errorf("commit migration %d: %w", m.version, err)
        }
    }
    return nil
}
```

`openDB` calls `migrate(db)` and **fails closed** on error — return the error so
the command aborts with a clear message rather than running against a
half-migrated schema. (Today `openDB` already returns on migrate error; keep that
contract.)

### 3.1 The baseline migration (the `0 → 1` bridge)

Migration 1 must leave **both** of these DBs identical and stamped at version 1:

- a brand-new empty file, and
- an existing deployed file already carrying every column through
  `acknowledged_hash` at `user_version = 0`.

So `migBaseline` is exactly today's idempotent logic, nothing more:

```go
func migBaseline(tx *sql.Tx) error {
    if _, err := tx.Exec(schema); err != nil { // CREATE TABLE IF NOT EXISTS …
        return err
    }
    // additive, each ignoring "duplicate column name" — same as migrateColumns
    for _, stmt := range baselineAlters {
        if _, err := tx.Exec(stmt); err != nil &&
            !strings.Contains(err.Error(), "duplicate column name") {
            return err
        }
    }
    return nil
}
```

Because it is idempotent it is safe to run on the already-migrated `v0` file: it
no-ops the table, no-ops every column, and stamps `user_version = 1`. From that
point the runner trusts the version counter and **no future migration uses
`IF NOT EXISTS` / duplicate-swallowing** — they assume the exact prior shape.

> This is the whole trick for not breaking the field: freeze today's idempotent
> behaviour as v1, then switch to strict versioned steps. After v1 ships, the
> `schema` const and `baselineAlters` are **frozen history** — never edit them to
> reflect a new column; add a migration instead (§5).

---

## 4. Writing a migration

### 4.1 Additive column (the common case)

```go
func migAddFoo(tx *sql.Tx) error {
    _, err := tx.Exec(`ALTER TABLE packages ADD COLUMN foo TEXT`)
    return err // no duplicate-swallowing — versioning guarantees it runs once
}
```

Then update `DBRecord`, `lookupRecord` (`COALESCE(foo,'')`), and whichever writer
owns the column (`upsertRecord` for routine-scan fields; a dedicated writer for
out-of-band fields like `acknowledged_hash`). New columns are `NULL` on existing
rows — always read through `COALESCE`, exactly as the current code does.

### 4.2 Non-additive change (rebuild procedure)

For a rename-with-retype, a new constraint, dropping a column on an old SQLite, or
any reshape `ALTER` can't express, use the canonical SQLite 12-step rebuild —
inside the migration's single transaction:

```go
func migRebuild(tx *sql.Tx) error {
    stmts := []string{
        `CREATE TABLE packages_new ( … new schema … )`,
        // backfill / transform happens in this SELECT:
        `INSERT INTO packages_new (col1, col2, …)
             SELECT col1, col2, … FROM packages`,
        `DROP TABLE packages`,
        `ALTER TABLE packages_new RENAME TO packages`,
        // recreate any indexes/triggers here
    }
    for _, s := range stmts {
        if _, err := tx.Exec(s); err != nil {
            return err
        }
    }
    return nil
}
```

Notes:
- We currently define **no** foreign keys or triggers, so the full
  `PRAGMA foreign_keys=OFF` / `legacy_alter_table` ceremony isn't needed. If that
  ever changes, follow the official ["Making Other Kinds Of Table Schema
  Changes"](https://www.sqlite.org/lang_altertable.html#otheralter) order and
  toggle `foreign_keys` *outside* the transaction (PRAGMA is a no-op mid-tx).
- The `INSERT … SELECT` is where a **data backfill** lives — compute the new
  column from old ones, default sensibly, never drop rows.

### 4.3 Index / trigger

```go
func migIndexScanned(tx *sql.Tx) error {
    _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_pkg_scanned
                         ON packages(last_scanned)`)
    return err
}
```

### 4.4 Pure data migration (no DDL)

A migration may change only data — e.g. normalising a stored `provider` string
format. Same mechanism: one `UPDATE` in the step, bump the version. This is the
*correct* replacement for "delete the row and re-scan."

---

## 5. The checklist — every time the schema changes

1. **Never edit `schema` or `baselineAlters`** after v1 ships. They are frozen.
2. Append one `migration{N, "...", migFn}` with `N = len(migrations)+1`. Never
   reorder, renumber, or edit a shipped entry — append only.
3. Put **all** DDL + backfill for that change in the migration's `apply`; assume
   the prior version's exact shape (no `IF NOT EXISTS`, no duplicate-swallowing).
4. Update the Go layer to match: `DBRecord` field, `lookupRecord` (`COALESCE`),
   the appropriate writer (`upsertRecord` vs. a dedicated one), and the
   `CREATE TABLE` in any throwaway test fixture.
5. **Test the upgrade path**, not just a fresh DB (§6).
6. Do **not** add a "delete your DB" note to any doc, commit message, or error
   string. If a *data* reset is genuinely needed, point at `waurden recheck
   <pkg>` (blanks `pkgbuild_hash`, preserves committers + ack) or `scan --force`
   — both non-destructive. (`waurden forget <pkg>` deletes that one package's row
   + history on purpose; it is a scoped user action, not the DB-wipe reflex this
   policy retires.)
7. Generate the patch per the CLAUDE.md workflow (stage explicitly, no `.claude/`).

---

## 6. Testing the upgrade path

A fresh-DB test proves nothing about real users — the bug surface is *old file
meets new binary*. For each schema change, add/extend a test that:

1. Builds a DB at the **previous** version: either fixture SQL stamped with the
   old `PRAGMA user_version`, or a checked-in tiny binary fixture, populated with
   a representative row (verdict cache + non-empty `known_committers` +
   `acknowledged_hash`).
2. Runs `migrate()`.
3. Asserts `PRAGMA user_version` == new target **and** that the pre-existing row
   survived intact (cache hit still keys, committer baseline preserved, ack
   preserved), plus whatever the new migration was supposed to do.
4. Runs `migrate()` a **second** time and asserts it is a no-op (idempotent
   runner: nothing re-applies, version unchanged).

Keep a fixture per historical version as they accrue, so the `0 → latest` chain
stays covered, not just `N-1 → N`.

---

## 7. Retiring the "wipe the DB" advice (follow-up, out of this plan's scope)

These existing references predate this policy and should be scrubbed when next
touched (separate patch; noted here so they aren't forgotten):

- `CLAUDE.md` §9 — "delete the row (or the DB) to force a clean re-scan" →
  `waurden recheck <pkg>`.
- `SUMMARY.md` — "delete the DB row/file to force a clean re-scan" (×2) and
  "clear them once with `waurden recheck`".

Note these are **cache-poisoning / data** resets, not schema migrations — but the
"just delete the file" reflex is exactly what this policy retires, so the wording
should move to the non-destructive `recheck` / `--force` path everywhere. (The
destructive `forget` is for deliberately discarding one package's history, not for
unsticking a cache.)
