wAURden is a complete Go binary (v0.1.0) that intercepts `makepkg` before the PKGBUILD is
sourced, runs local heuristics + an LLM, and blocks the build on a malicious verdict. Source
files: `main.go`, `config.go`, `collect.go`, `analyze.go`, `provider.go` (`anthropic`/`openai`+base_url/`static`),
`db.go`, `gate.go`, `aur.go`, `git.go`, `configure.go`, `heuristics.go`, plus hooks, config examples
(including `heuristics.example.toml`), a `PKGBUILD` for `waurden-git`, and README.

Latest fix: **scan-failure cache poisoning** (CLAUDE.md §9, fail-open bug). `analyze()` was
persisting the `verdictFromOnError` fallback (`verdict="ok"`) on provider/parse failure; because
`ScanFailed` is `json:"-"` it wasn't rebuilt on a cache hit, so the next run of the same
`pkgbuild_hash` read a cached `ok` and the gate passed without re-scanning — which is exactly why a
429-blocked build "passed" (and kept replaying the stale error, same `retry_after`) on rebuild. Fix:
removed both error-path `storeVerdict` calls so a failed scan is never cached and is re-attempted
every run (gate stays fail-closed). An already-poisoned row survives until the PKGBUILD hash changes —
delete the DB row/file to force a clean re-scan.

Recent changes: implemented **git committer tracking** (new `git.go`), replacing the removed
AUR maintainer-change warning. `gitKnownCommitters` reads `git log --format=%ae`; `trackNewCommitters`
warns (informational, never blocks) when an author email appears that no prior scan recorded,
persisting the union in a new `known_committers` DB column (migrated via `ALTER TABLE`). First
scan is silent (no baseline). Removed `storeMaintainer`/`prev_maintainer` from the write path and
the maintainer-changed block in `printAURWarnings`. Note: the analyze cache-hit early-return means a
new committer is re-warned each scan until the PKGBUILD changes — acceptable for a cautionary signal.
Latest patch (`0001-provider-retry-429-clean-errors.patch`): provider-error UX. `postJSON` now retries
transient 429/503 up to 3× honoring `Retry-After` (capped 20s) — free OpenRouter models rate-limit
constantly, so this is what makes real runs usable. A new `httpError` extracts the human message
(prefers `metadata.raw`) instead of dumping the raw JSON blob (which leaked the account `user_id`).
`verdictFromOnError` now stores only the cause in `Summary` so the gate's block line no longer doubles
the "scan failed (on_error=…)" prefix, and `runScan` honors `v.ScanFailed` (prints an infra-error line
or stays quiet, instead of a misleading `Verdict: OK 0.00`).

Heuristic findings now quote the **whole offending source line** as `Evidence` (via
`FindAllStringIndex`+`lineAt`) instead of the bare matched token, so a block like google-chrome's
`/etc/cron` match reads as `rm -f "${pkgdir}/etc/cron.daily/google-chrome"` — self-explanatory, and
obviously a benign removal rather than a persistence write. Repeated hits on one line are collapsed.
(Note: the built-in persistence regex still false-positives on `$pkgdir`-scoped removals; tightening
it — e.g. ignoring `rm`/`${pkgdir}` contexts — is a separate follow-up, not done here.)

**Next planned feature (designed, not yet built): gate exceptions via hash-pinned acknowledgement** —
see CLAUDE.md §10 "Gate exceptions". A user can permanently accept a blocked package, but only for the
exact reviewed `pkgbuild_hash`; any PKGBUILD change voids the ack and forces a re-scan (preserves
Atomic-Arch protection — no by-name allowlist). Acceptance friction is tiered: `malicious` with
confidence ≥ 0.9 requires typing `I accept the risk`; otherwise plain `[y/N]`. Adds an
`acknowledged_hash` column (owned by a separate `storeAcknowledgement` writer, kept out of
`upsertRecord` so normal scans don't clobber it) and a `waurden allow <DIR>` command as the non-TTY
escape hatch for the makepkg hook. Tighten the `${pkgdir}`/`rm` persistence regex first/in parallel,
else the heuristic's flat 0.95 confidence makes the heavy prompt fire on the google-chrome FP.

Next planned changeset (designed, not built): **cache invalidation & version reporting** — see
CLAUDE.md §10 "Cache invalidation & version reporting". (1) Add provider/model to the `analyze()`
cache-hit guard so switching models invalidates a stale verdict; (2) `scan --force` (and an optional
`forget <pkg>` that blanks `pkgbuild_hash` rather than deleting the row, to preserve
`known_committers`/`acknowledged_hash`) to re-scan without wiping the DB; (3) expose the commit SHA in
`waurden version` via `runtime/debug.ReadBuildInfo()` (`vcs.revision`). Items 1–2 share the cache-hit
code; item 3 is independent and small.

Also still open: verify `makepkg.conf.d` sourcing order on a real Arch system with root, then test real
LLM providers via OpenRouter.
