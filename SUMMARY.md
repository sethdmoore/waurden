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

Latest changeset (DONE, two patches): **gate exceptions via hash-pinned acknowledgement** (CLAUDE.md
§10) plus its prerequisite **persistence-regex tightening**. (Patch A) `heuristicCheck` now skips the
persistence pattern's match when the offending line is a packaging op rather than a live-system write
— a removal (`rm …`) or a `${pkgdir}`/`${srcdir}`-scoped path — via a new `benignInPkgdir` flag on the
persistence built-in and a `benignPkgdirContext` helper. RE2 has no lookbehind, so this is a per-line
context filter, not a regex rewrite; `builtinPatterns` is now named-field literals. Verified: google-
chrome's `rm -f "${pkgdir}/etc/cron.daily/…"` → OK, while a real `> /etc/cron.d/backdoor` still blocks.
(Patch B) Added `acknowledged_hash` column (migrated via `ALTER TABLE`, read in `lookupRecord`,
written **only** by a new `storeAcknowledgement` UPDATE — kept out of `upsertRecord` so routine
re-scans never clobber it). The gate's block path gains a pure-hash short-circuit that runs even with
no TTY (`existing.AcknowledgedHash == pf.Hash` → allow), tiered interactive override (`malicious` ≥0.9
requires typing `I accept the risk`; else `[y/N]`), and a `Remember this version? [Y/n]` persist step.
New `waurden allow [DIR]` command is the non-TTY recovery path (scan → typed confirm on a TTY → store
ack). Verified end-to-end: ack short-circuits a re-gate; a PKGBUILD edit voids it; `forget` clears the
verdict cache but the ack survives (independent columns). `pf.Name=="unknown"` skips all ack logic.

Latest changeset (DONE): **cache invalidation & version reporting** (CLAUDE.md §10). (1) `analyze()`
now takes `force bool` and its cache-hit guard keys on provider/model as well as hash —
`existing.Provider == providerStr` (the same `"<provider>/<model>"` string `storeVerdict` writes), so
switching models is a cache miss that re-scans and overwrites the row (no migration; `base_url` and
prompt version intentionally not keyed). (2) `scan --force` (alias `--no-cache`) threads `force=true`
to skip the cache read; `gate` always passes `false`. `waurden forget <pkgname>` blanks `pkgbuild_hash`
via `forgetRecord` (`UPDATE … SET pkgbuild_hash=''`) instead of deleting, preserving `known_committers`
and the future `acknowledged_hash`. (3) `waurden version` calls `versionString()`, reading
`vcs.revision`/`vcs.time`/`vcs.modified` from `debug.ReadBuildInfo()` →
`wAURden 0.1.0 (b192e83, 2026-06-22, dirty)`, falling back to the bare release number when unstamped.
Verified end-to-end with the static provider: a `WAURDEN_MODEL` change re-stored the row as
`static/foo` (proving model-change invalidation), `forget` clears correctly, `--force` re-scans.

Latest changeset (DONE): **configurable scan modes + a truthful provider label.** New `scan_mode`
config key (`Config.ScanMode`, env `WAURDEN_SCAN_MODE`) with three values, normalized by `scanMode()`
in analyze.go: `full` (default — heuristic pre-filter then LLM), `heuristics` (pre-filter only, never
touches the network — fast/offline/coarse, returns `ok` @0.50 with an explicit "LLM not consulted"
summary), and `llm` (skips the built-in pre-filter, relies on the model alone). `analyze()` gates the
pre-filter on `mode != llm` and returns early in heuristics mode before `callProvider`. Cache
correctness: the verdict cache key's provider component now comes from `engineString(cfg)` (used by
both the cache-read in `analyze()` and `storeVerdict`), which returns `"static (heuristics)"` in
heuristics mode and `"<provider>/<model>"` otherwise — so switching into/out of heuristics-only is a
cache miss that re-scans (no schema change). Known minor gap: full↔llm share the LLM identity and
differ only for heuristic-blockable inputs; use `scan --force` across that switch. The configure
wizard prompts for the mode (LLM providers only; static is heuristics by definition) and writes
`scan_mode` when non-default; documented in `config.example.toml` and CLAUDE.md §6.

Second half of that changeset: the scan/gate report's `Provider:` line now renders `providerLabel(cfg)`
instead of the bare `cfg.Provider`. The OpenAI-compatible path fronts many services via `base_url`, so
"openai" was misleading; `serviceFromBaseURL` maps the host (openrouter.ai→`openrouter`,
generativelanguage…→`gemini`, api.openai.com/api.anthropic.com→themselves, else the raw host incl.
port for localhost) and the label appends the model → e.g. `Provider: openrouter: foo-model`.
heuristics-only shows `static (heuristics, no LLM)`; the `static`/`mock` provider shows
`static (heuristics)`. Display only — the DB `provider` column still stores `engineString` for cache
keying; `show` still prints the stored value. Verified end-to-end with the binary: openrouter label,
heuristics-mode @0.50 with no network, heuristics-mode still blocks the malicious sample, llm-mode
bypasses the pre-filter (hits the network), and a heuristics→full switch invalidates the cache.

Latest changeset (DONE): **gate-log visibility + heuristic pre-filter ahead of the cache.** Under a
makepkg/yay hook the gate was silent: a clean verdict exited 0 with no output, and the LLM call left the
terminal hanging with no sign of activity. Two changes: (1) `analyze()` prints `wAURden: scanning <pkg>
via <providerLabel>…` to stderr immediately before `callProvider` — only on the cache-miss network path,
so it marks exactly the moment that otherwise looks frozen; (2) `runGateCmd`'s clean-OK branch now prints
a one-line `wAURden: <pkg> — OK (confidence X, <providerLabel>)` instead of exiting silently, so the
verdict shows in the build log. The blocked/suspicious path already printed the full report.

Same changeset fixes the **stale-verdict replay** (the recurring google-chrome false `MALICIOUS`): the
cache lookup in `analyze()` ran *before* the heuristic pre-filter, so a verdict cached by an older binary
(unchanged PKGBUILD hash + same provider → cache hit) was replayed verbatim and the corrected heuristic
never voted. Reordered so the heuristic pre-filter runs **before** the verdict cache read: the current
binary's rules always get a vote, so a fixed false positive *or a newly added detection* takes effect on
the next run even when the hash is unchanged (a cached `ok` can be re-flagged). A clean heuristic result
still falls through to the cache, so legitimate LLM-verdict cache hits are preserved (no extra LLM calls).
Verified: heuristic block overrides a poisoned cached `ok`; clean heuristics still serve a cached verdict;
OK one-liner + scanning line appear on the right paths. **Existing poisoned rows are not retroactively
healed** — clear them once with `waurden forget <pkg>` (or let the PKGBUILD hash change).

New policy doc `MIGRATIONS.md` (plan-only, no code yet): **never wipe the user's DB for a schema
change.** Designs a `PRAGMA user_version` migration runner — append-only ordered `[]migration`, each
applied once in a transaction, runner fails closed. Key move: freeze today's idempotent
`CREATE TABLE IF NOT EXISTS` + additive `ALTER` logic as migration **v1 (baseline)** so both a fresh
file and an already-migrated `v0` deployed file converge to the same shape; from v1 on, strict
versioned steps (no `IF NOT EXISTS`, no duplicate-swallowing). Covers additive columns, the SQLite
table-rebuild dance for non-additive changes/backfills, indexes, the per-change checklist, and
upgrade-path testing (old file + new binary, not just fresh DB). §7 flags the lingering "delete the
DB/row" advice in CLAUDE.md §9 and this file (above) for a later scrub toward `waurden forget` /
`scan --force` — both already non-destructive. Implementing the runner in `db.go` is a deferred
follow-up (scope was plan-only).

Latest (PLAN ONLY, no code yet — see CLAUDE.md §10 "Gate output: clean per-package lines + end-of-run
recap"): a real `yay -Syu` showed five `scanning … via <model>…` lines but only two `— OK` lines before
the pacman install flood buried the rest, and the model string repeats pointlessly on every line. Root
cause: `waurden gate` runs **once per package, as its own concurrent process** (makepkg.conf.d hook), so
no process sees the full package list — a grouped *pre-scan* header is impossible; the "all OK" recap must
come **after** the builds. User chose "clean lines + end summary." Plan, in two independent parts:
(1) in `gate`, drop the model from the scanning line (`analyze.go:352`) and the OK line (`main.go:305`),
append the info `Summary` to the OK line, and re-tag the `on_error` fail path as a per-package result
(`... — could not scan (…); build allowed`) so every `scanning X…` gets a matching terminal line — this
is the actual fix for "some scans never showed completion" (they printed an untagged WARNING that scrolled
away). (2) Implement the §10 `waurden summary` command (no-arg full table + `--targets` stdin-filtered
recap that names the model **once** and ends with `all N scanned OK`), driven **once** from the pacman
`PreTransaction` hook with `NeedsTargets`; resolve the user DB via `$SUDO_USER` like
`configExistsAnywhere` (main.go:538-548), match pacman pkgnames to DB keys (pkgbase fallback), and print
nothing when no target is in the DB. Ship `summary` before the hook; update `install-hooks`/`hookStatus`
sha256 so the changed hook re-installs. This session also committed the workflow-rules refresh in CLAUDE.md
(patch workflow → direct push to the blessed repo).

Also still open: verify `makepkg.conf.d` sourcing order on a real Arch system with root, then test real
LLM providers via OpenRouter.
