Latest session — **warning interface: force a typed decision instead of a passive Enter.** A user hit
a HIGH-severity finding (obfuscated Python exfiltrating `~/.ssh/*`) that the model rated only
`suspicious`, so it landed on the non-blocked warn path — whose prompt was `Press Enter to continue
(build will proceed)…`, i.e. a reflexive keypress waved it through (the user had to Ctrl-C). Fix: the
single-package gate's warn branch (`main.go`) and the tree gate's warn nodes (`deptree.go`) now call a
new `confirmWarning(name, v)` that **tiers friction by the highest finding severity** — high/critical
requires the exact phrase `I accept the risk` (or `n` to abort); low/medium is a plain `y/n` question.
It **re-prompts until the user chooses explicitly**: a stray Enter or typo just asks again rather than
deciding for them (no default). It returns only on an explicit affirmative (proceed) or an explicit
negative / EOF (abort → exit 1, so it can't loop forever). Non-TTY/hook paths are unchanged (warn_on
stays advisory there). New helpers:
`highestSeverity` (`heuristics.go`, next to `severityRank`) and `policyWarns` (`gate.go`, mirrors
`policyBlocks`). Tests: `TestConfirmWarning` (phrase vs y/N tiering, bare-Enter declines both),
`TestHighestSeverity`, `TestPolicyWarns` (`gate_test.go`, reusing summary_test's `withStdin`).
`go test ./...` + `-race` on the new tests green.

Prior session (DONE) — **gate OK-line dedup within a quiet window.** A real `yay -S
plex-media-server-plexpass` printed the same `plex… — OK (1.00) … (cached)` line four times: one
AUR build fires the makepkg.conf.d gate once per makepkg phase (source-fetch, dep-check, build,
fakeroot `package()`), each an independent process re-sourcing the hook, so the clean line repeats.
Not a security duplicate (all cache hits) — a visibility problem. Fix: new `GateQuietWindow` config
knob (`gate_quiet_window_seconds`, env `WAURDEN_GATE_QUIET_WINDOW_SECONDS`, default **120**, 0 =
disable) + `recentlyAnnounced(db, name, hash, windowSeconds)` in db.go, which checks the append-only
`scans` table for a prior scan of the same **(package, pkgbuild_hash)** within the window. In
`runGateCmd` the check runs *before* `recordScan` writes the current row (else it self-matches) and
suppresses **only** the clean `— OK` line — the gate still runs, still records, still exits 0/1/2 and
still prints warnings/blocks every phase. Keyed on hash so a PKGBUILD edit always re-announces. Scoped
to the single-package fast path (`main.go`); the tree-gate render (intentionally held) is unchanged.
Tests: `TestRecentlyAnnounced` (same-hash hit, different-hash/-package miss, window=0 disable, empty
hash, 300s-old row outside 120s / inside 600s) + config default/override coverage. `go test -race
./...` green.

Prior session — **obfuscated-payload hardening** (real bypass reported by the user: an inline
`python3 - <<EOF` heredoc whose "IP allowlist" was an array of decimal ASCII codes decoded with
`chr(int(x))` and run via `os.system("".join(...))`, disguised by comments; qwen only rated it
SUSPICIOUS so it wasn't blocked). Root cause: the heuristics had **no** patterns for runtime string
construction/decoding, so the class reached (and fooled) the LLM. Fix (`heuristics.go`): added
**critical** patterns for `os.system`/`os.popen`/`subprocess`/`eval`/`exec` executing a decoded or
assembled string (`.join`/`chr(`/`unhexlify`/`fromhex`/`b64decode`/`codecs.`/`.decode(`), plus **high**
patterns for `chr(int(...))` and join/comprehension-over-`chr()` — any one hard-blocks before the LLM
(the sample now fires 1 critical + 2 high). Added **medium** advisories (feed the LLM, don't block) for
interpreter heredocs (`python3 - <<`) and bare `os.system`/`subprocess`. Also closed a second channel
the user spotted: the git/line **diff is sent to the LLM verbatim**, carrying comments that
`PKGBUILDSrc` strips — so disguising narration (`# critical for waurden to function`) still biased the
model. `analyze.go` now runs `stripDiffComments` on the diff before `buildUserContent`. New inert
sample `tests/samples/chr-obfuscation/` + `TestObfuscatedExecutionBlocks` / `TestBenignPythonNotBlocked`
(FP guard: literal `os.system("make install")` and `os.system("gcc " + flags)` stay advisory) /
`TestStripDiffComments`. All tests pass.

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

Latest changeset (DONE — CLAUDE.md §10 "Gate output: clean per-package lines + end-of-run recap"):
a real `yay -Syu` showed five `scanning … via <model>…` lines but only two `— OK` lines before the
pacman flood buried the rest. Root cause (unchanged): `waurden gate` runs **once per package as its own
concurrent process** (makepkg.conf.d hook), so those processes' stderr interleaves with yay's — there is
no parent to "wait for all threads," and no process sees the full package list, so a grouped pre-scan
header is impossible. Fix, two parts. **Part 1 (per-package legibility):** the scanning line
(`analyze.go`) drops the model (`wAURden: scanning <pkg>…`); the gate OK line drops the provider and
appends a `truncate`d `Summary` (`wAURden: <pkg> — OK (0.50) <summary>`); the `on_error` fail path is
re-tagged as a per-package terminal line (`<pkg> — could not scan (<cause>); build allowed (on_error=warn)`)
and the untagged WARNING in `verdictFromOnError` was removed — so **every** `scanning X…` now has exactly
one matching result line. **Part 2 (recap):** new `waurden summary` command (`summary.go`) — no-arg full
table (`text/tabwriter`, newest first) to stdout; `--targets` reads pacman's stdin target list, filters to
DB-known packages, prints the model **once** in a header and ends with `all N package(s) scanned OK` (or
surfaces non-OK rows). It stays silent when no target is in the DB (repo-only `-Syu`). The pacman hook is
now real: `Exec = waurden summary --targets` + `NeedsTargets`, fires once PreTransaction; `install-hooks`
installs **both** hooks (added `pacmanHookPath` = `/etc/pacman.d/hooks/waurden.hook`; `writeFile` now
MkdirAll's the parent; `hookStatus` sha256 re-installs the changed hook) and `uninstall-hooks` removes
both. Root→user DB resolves via a shared `effectiveHome()` ($SUDO_USER-aware, refactored out of
`configExistsAnywhere`) by pointing `HOME` at the invoking user before `loadConfig`. Verified end-to-end
with the static provider: clean OK line, mixed recap surfaces MALICIOUS, repo-only/empty stdin stay silent,
warn-path prints one tagged line per scan. Note: DB is keyed by pkgname so split-package pkgbase matching
is best-effort (direct pkgname match only).

Follow-up (DONE) — **durable scan history, in the DB (no log files).** The `packages` table is a
PRIMARY KEY(name) verdict *cache* upserted on each scan, so a re-scan overwrote the prior verdict and a
block that scrolled past in the build flood was unrecoverable. Fix is relational, not a log file: a new
append-only **`scans`** fact table (`db.go`, additive `CREATE TABLE IF NOT EXISTS` — old DBs gain it with
no wipe; verified on a realistic prior-schema DB) holding one row per scan event (package FK→packages,
scanned_at, verdict, confidence, `blocked`, provider, summary, findings). `recordScan` appends on every
gate/scan (including cache hits), kept separate from `upsertRecord` so history is never clobbered;
`blocked` = policy decision (verdict ∈ `block_on`, via the new `policyBlocks` helper reused by `runGate`).
`waurden summary` now shows the current-state packages table **plus a "Recent blocks" footer** from the
history; `waurden summary --history` prints the full newest-first timeline with a BLOCKED column. Verified:
re-gating a malicious package keeps both block events in `--history` while `packages` shows one row.
Rationale: packages = current-state dimension, scans = event fact table — use the DB as a DB.

Latest fix (DONE) — **SQLite concurrency: "database is locked" during batched builds.** A real
`yay -Syu` rebuild of the hypr* stack falsely blocked 7 of 13 packages with `gate error: db lookup:
database is locked (5) (SQLITE_BUSY)`. Root cause: the makepkg.conf.d hook runs `waurden gate` once per
package and yay's source/verify phase runs those processes **concurrently**; `openDB` used a bare
`sql.Open("sqlite", path)` (default rollback journal, zero busy timeout), so the instant one gate held
the write lock (`recordScan` INSERT / `upsertRecord`) every other process's `lookupRecord` got
`SQLITE_BUSY` immediately → false block (fail-closed, safe but wrong). Fix: open with DSN pragmas
`?_pragma=busy_timeout(<n>)&_pragma=journal_mode(WAL)` — contenders now wait (bounded) instead of
erroring, and WAL lets readers coexist with the writer. `foreign_keys` stays OFF (unchanged). The wait
is a **config knob**, not hard-coded: `db_busy_timeout_seconds` (`Config.DBBusyTimeout`, env
`WAURDEN_DB_BUSY_TIMEOUT`) defaults to **7s**, threaded through `openDB` (converted to the pragma's ms);
0 = fail fast, negative clamps to 0. busy_timeout retries internally for at most that window then returns
SQLITE_BUSY (gate fails closed, never hangs the build). Verified: 20-way concurrent
upsert+recordScan+lookup with zero SQLITE_BUSY; pragma reflects the configured value (7→7000, 3→3000,
0→0, −5→0); `loadConfig` default is 7.

Latest fix (DONE) — **duplicate LLM scan of a package within one `yay` run (concurrency de-dup).** A
real hypr* rebuild scanned hyprwayland-scanner-git twice (two completed `— OK` lines, two `==> Making
package` invocations). Cause: the makepkg.conf.d hook fires on **every** `makepkg` run and yay invokes
makepkg more than once for make-dependencies (an early build batch + the main transaction); the verdict
cache normally absorbs the second gate, but `analyze()` reads the cache at the top and only writes after
the slow LLM call, so two concurrent gates for the same package both miss the cache and each issue a full
scan. Fix: a **recently-scanned guard** — refactored the cache-hit logic into `cacheHit(r, pf, providerStr)`
(hash `pf.Hash` == `PKGBUILDHash` AND engine match) + `verdictFromRecord`, then re-read the row with a
fresh `lookupRecord` immediately before `callProvider`; if a sibling has since committed a verdict for the
identical PKGBUILD sha256 and engine, reuse it instead of re-scanning. No time window needed: any row that
satisfies `cacheHit` at the re-read was written after our first (missed) read, i.e. by a concurrent sibling
this run. Skipped under `force` and `name=="unknown"`, same as the top cache. Residual window: a sibling
still mid-LLM-call (not yet committed) is not caught — acceptable (an extra scan, not a security gap).
Build/vet/test clean.

Follow-up (DONE) — **mark cache hits in the output.** A reused verdict was indistinguishable from a
fresh scan. Added a `Cached bool json:"-"` field to `Verdict` (mirrors `ScanFailed`), set in
`verdictFromRecord` — the single choke point both the top cache and the recently-scanned guard funnel
through. A new `cachedTag(v)` helper returns `" (cached)"` when set, appended to the gate OK one-liner
(`… — OK (1.00) <summary> (cached)`) and the `scan` report's `Verdict:` line. Display only; nothing
persisted. Verified with the static provider: first gate scans, second gate + `scan` show `(cached)`.

Latest changeset (DONE) — **front-loaded dependency-tree scan + self-managed clones + diffs** (CLAUDE.md
§10 full spec). A gate now discovers the recursive AUR closure of `$PWD` itself and scans it all before the
helper compiles anything. New `deptree.go`: `resolveTree` seeds from the on-disk `.SRCINFO`
depends/makedepends/checkdepends (`parseDeps`, with a PKGBUILD-array fallback), classifies each via
`pacman -Si` (official → pruned "repo" leaf) then a **batched** AUR RPC (`aurPackageBases` in `aur.go`,
name→pkgbase; absent → "skipped" leaf), and recurses into AUR deps guarded by a pkgbase visited-set + node
cap. The resolver's side effects (pacman/AUR/clone/deps) sit behind an injectable `treeResolver` so it is
unit-testable with no network. `clone.go` `ensureClone` manages inert shallow clones under
`~/.cache/waurden/aur/<pkgbase>` (git clone, else fetch + reset --hard FETCH_HEAD; advisory/non-fatal, never
built). `treeview.go` renders the tree live: TTY animates in place with ANSI cursor moves (per-node status,
dimmed repo leaves), non-TTY prints one plain result line per scanned node. `runGateCmd` gains a tree branch
that keeps a **single-package fast path** (`hasScannableChildren` false → legacy gate, unchanged); the tree
path scans the root authoritatively from its on-disk `$PWD` and children from clones, reuses per-node
heuristics/cache/committer-tracking/ack/`recordScan`, buffers per-node committer warnings until after the
render (interleaving would corrupt the cursor math), and aggregates one exit: `2` if any malicious block, `1`
if any suspicious block, else `0` (with a `tree_pause_seconds` hold on a clean TTY render). The ack
short-circuit and tiered interactive override apply **per offending node**. Security-critical invariant kept:
the package being built is always scanned from `$PWD`, never a clone — self-clones only discover/pre-scan/diff
children. New config knobs `tree_scan` (default true), `tree_pause_seconds` (default 1), `clone_dir` (+ env
overrides). Deviation from spec, documented: per-child **AUR/orphan** warnings are left to each child's own
gate (avoids N× the network); per-child **committer** tracking is kept.

Second half — **PKGBUILD diffs.** Additive `last_scanned_commit` column (`db.go`: schema + `ALTER` migration
+ `DBRecord`/lookup/upsert). `git.go` gains `gitHeadCommit` + `gitDiffFiles` (`git diff <last>..HEAD --
PKGBUILD .SRCINFO *.install`). `analyze()` now prefers a real git diff from the stored commit to the current
HEAD (falling back to the old whole-file line diff), feeds it to the LLM (the system prompt already says
"focus on the diff"), and advances `last_scanned_commit` **only on a successful scan** (`storeVerdict` gained
a `commit` param) so a failed/blocked infra result never hides the next real change. This is where an
Atomic-Arch-style poisoned *update* surfaces. Note re the two merged sessions this builds on: `callProvider`
now returns `(raw, TokenUsage, err)` and `heuristicCheck(pf)` returns `(*Verdict, []Finding)` — integrated
around, not disturbed. Verified end-to-end with the static provider: single-package fast path (benign OK /
malicious block), `tree_scan=false` opt-out, real 2-level tree (google-chrome cloned + scanned, glibc pruned
repo, root authoritative → exit 0), malicious-root tree → exit 2 with focused block message, `waurden allow`
→ ack short-circuit re-gate → exit 0, git diff computed + commit advanced after a new commit; TTY animated and
non-TTY plain renders both observed; build/vet/`go test ./...` clean.

Follow-up (DONE) — **unit tests for the dep-tree feature** (satisfying CLAUDE.md rule #4, "every function
must have a unit test"). New `deptree_test.go` (parseDeps/stripDepName/isDependsKey; `resolveTreeWith` driven
by an injectable **fakeResolver** — classification, cycle/diamond guard, unknown-name fast path, RPC-fail
clone-by-name fallback, maxDepth cap, clone-error node; flatten/worstNode/treeExitCode/countAURNodes;
`scanNode` root+child against a real DB + static provider), `treeview_test.go` (node line markers, per-status
text, verdict tail, `dim`, in-place `renderTree` cursor math), `clone_test.go` (`runGit`; `ensureClone`
fresh-clone + refresh + no-dir error, driven against a **local upstream git repo**), `diff_test.go`
(`gitHeadCommit`/`gitDiffFiles`, `last_scanned_commit` round-trip, and analyze() preferring a real git diff
end-to-end), `aur_pkgbases_test.go` (`aurPackageBases` via **httptest**: success/absent-name/empty/transport-
error/bad-JSON), and `config_tree_test.go` (`expandHome`; TreeScan/TreePauseSeconds/CloneDir defaults, file
opt-out, env override, `~` expansion). Two tiny testability seams added so no live network is needed:
`aurGitBase` (clone.go) and `aurRPCInfoURL` (aur.go), both plain `var`s overridden per-test; the three
`WAURDEN_TREE_*`/`CLONE_DIR` env vars were added to `clearEnv`. In-process heuristic tests call
`initHeuristics()` (no second `TestMain` — one already exists). `go test -race ./...` green; vet/gofmt clean.

Latest changeset (DONE) — **heuristics overhaul: tiering, big pattern expansion, prompt-injection/Trojan-Source
defense.** The built-in set was thin and any match hard-blocked at 0.95, so it couldn't grow without false
blocks. Fix: `splitVerdict` **tiers by severity** — critical/high → hard block (skip LLM, 0.95/0.90);
medium/low → *advisory* (never blocks; fed to the LLM in a trusted `<heuristic_notes>` block via
`buildUserContent`, folded into stored findings by `mergeFindings`, and shown as `suspicious` offline). This
lets the set be broad: added reverse shells (`/dev/tcp`, `nc -e`, `socat`), decode-then-pipe obfuscation
(base64/xz/tr | sh — xz-backdoor style), broadened exfil (browser/wallet/cookie stores, `env|curl`, HTTP POST
of `$vars`), rootkit/privesc primitives (`sudoers`, `ld.so.preload`, `authorized_keys`, eBPF/`insmod`,
setuid, `chattr +i`), destructive (`rm -rf /`, `dd`, `mkfs`), and package-manager installs (Atomic-Arch
typosquat class) — the legit-in-scriptlet ones (useradd/systemctl/npm/setuid) sit at medium so a normal daemon
package doesn't hard-block. New **prompt-injection layer** (`scanInjection`/`injectionPatterns`/
`suspiciousUnicode`, all critical, scanned over the RAW PKGBUILD **and** helper/`.install` files): "ignore
previous instructions" family, role reassignment, injected verdict JSON, our own wrapper delimiters, chat/model
control tokens (`<|im_start|>`, `<<SYS>>`, `[INST]`), and invisible/bidi Unicode (Trojan Source, CVE-2021-42574)
— this blocks a manipulative package *before* the LLM (which is what injection subverts) ever runs. `heuristicCheck`
now takes `PackageFiles` and scans PKGBUILD + all helpers. **Bug found & fixed via end-to-end test:** the
`static`/mock provider re-scanned the fully-assembled prompt, so it false-fired the injection detector on
wAURden's own `<pkgbuild>` wrapper (every package → MALICIOUS); `mockPayload` now extracts just the wrapped
package sections. Added inert, labeled sample PKGBUILDs (one per attack class) under `tests/samples/` and
`heuristics_test.go` asserting the full tiering matrix. Verified end-to-end with the static provider: benign→OK,
benign-daemon→SUSPICIOUS (gate exit 0), all 10 attack classes→MALICIOUS (gate exit 1); build/vet/test clean.

Latest changeset (DONE, branch `feature/token-accounting`) — **LLM token accounting.** New append-only
`token_usage` table (`db.go`, additive `CREATE TABLE IF NOT EXISTS` + index — old DBs gain it, no wipe):
one row per successful provider call (session, package, used_at UTC, provider, model, input/output/total
tokens, `estimated` flag). `callProvider`/`callAnthropic`/`callOpenAI` now return a `TokenUsage`
(`tokens.go`) alongside the content: exact counts parsed from the response `usage` object (Anthropic
`input_tokens`/`output_tokens`; OpenAI `prompt_tokens`/`completion_tokens`), falling back via
`usageOrEstimate` to a ~4-chars-per-token estimate (`estimateTokens`) when the provider omits usage.
`callMock` returns zero usage — the static/heuristics engine makes no call and is never counted; cache
hits also record nothing (no call happens). `analyze()` calls `recordTokenUsage` right after a successful
`callProvider`, **before** `parseVerdict`, so tokens are counted even if the response fails to parse (they
were still billed); recording is non-fatal. A process-wide `tokenSession` id groups one invocation's rows.
New `waurden tokens` command (`runTokens`/`printTokenReport`) reports **This run** (latest session) /
**Today** / **This week** (ISO, Mon start) / **This month** / **All time**, windows computed in local time
and compared against the stored UTC RFC3339 timestamps; a `*` + footnote marks any window containing an
estimated call; `commafy` adds thousands separators. `scan` also prints a `Tokens this run:` line when it
actually called an LLM. Root→user DB resolves via `effectiveHome()` like `summary`. Verified end-to-end
against mock OpenAI servers: exact reported usage recorded and summed across windows; estimated fallback
recorded and flagged with `*`; heuristic/cache-hit paths record nothing; empty-DB message; `scan --force`
re-scan path. Note: `base_url` is not part of the cache key, so swapping endpoints at the same
provider/model is a cache hit (no new token row) — documented gap, same as verdict caching.

Also still open: verify `makepkg.conf.d` sourcing order on a real Arch system with root, then test real
LLM providers via OpenRouter.
