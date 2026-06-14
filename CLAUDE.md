# wAURden — your guardian for the AUR

> Implementation plan / design doc. This file is the source of truth for a fresh
> session to begin implementation. No code has been written yet.

## 1. Problem & motivation

An AUR security incident occurred in which a malicious bot claimed ownership of
~2,000 "orphan" AUR packages. Many of those packages had their `PKGBUILD`s
compromised with credential-stealing commits — e.g. a line like
`npm install atomic/credstealer-rootkit` injected into a build function, or
`curl … | bash`, exfiltration of `~/.ssh`, `~/.aws`, browser data, etc.

The danger is that AUR `PKGBUILD`s execute **arbitrary shell code at build time**
on the user's machine. Helpers (yay, paru, …) show a diff but most users skim or
auto-confirm it.

**wAURden** is a tool that uses an LLM to inspect changes to `PKGBUILD`s (and
related packaging files, and optionally upstream source) and **block the build**
when something looks malicious — regardless of which AUR helper is used and
regardless of which LLM provider the user has.

## 2. Hard requirements / decisions already made

These are locked. Do not relitigate without asking the user.

- **Language: Go.** Compile a single real static binary. Easy to drop on any
  Arch system and call from a shell hook.
- **Keep the code EXTREMELY simple.** No generics. Third-party Go packages are
  allowed where they make the code simpler — keep the set small and well-chosen.
  In particular we do **not** have to use Go's built-in `net/http` for API calls
  (it is fairly low-level); a small HTTP client library is fine. Likewise a
  SQLite driver and a TOML parser are expected dependencies (see below).
- **Name:** wAURden (stylized, "AUR" capitalized). Binary + Go module:
  `waurden` (lowercase). Tagline: "your guardian for the AUR".
- **LLM-provider-agnostic.** Must work with whatever the user has: local Ollama,
  Anthropic (Claude), OpenAI, Gemini, OpenAI-compatible endpoints. A `mock`
  provider is required for offline/dev testing (see §7).
- **AUR-helper-agnostic.** Must not depend on yay/paru internals. Works for any
  helper and for bare `makepkg`.
- **Config is TOML** (parsed with a small TOML library, e.g.
  `github.com/BurntSushi/toml` or `github.com/pelletier/go-toml`).
- **State/results are stored in SQLite**, not in per-package markdown files
  (see §5). Prefer a pure-Go driver (`modernc.org/sqlite`) so the binary stays
  static and cgo-free; `mattn/go-sqlite3` (cgo) is the alternative if needed.

## 3. Feature priorities (in order, from the user)

1. **Scan the `PKGBUILD` and any patch/included files for anything out of the
   ordinary.** Provider-agnostic. This is the core and must work standalone.
2. **Vendor/software-agnostic enforcement.** Implemented like `informant`
   (a hook/script), but it must catch the attack *before the build runs*. The
   build is interrupted if something sketchy is detected. Works with any AUR
   helper.
3. **Scan upstream changes.** For `-git` packages, fetch the upstream commit and
   diffs and analyze them. For binaries, upload/lookup via the VirusTotal API and
   summarize results. We can NOT scan every npm/pip/etc. dependency — instead,
   record in the database *what was and wasn't analyzed* so a downstream
   reader/LLM knows the analysis depth.

## 4. KEY architectural decision: where to intercept

**A pacman hook fires too late.** For an AUR package the sequence is:

1. helper clones the AUR git repo
2. helper runs `makepkg` → this runs `prepare()/build()/package()`
   — **this is where `npm install …/credstealer` actually executes**
3. helper runs `pacman -U built.pkg.tar.zst` → **pacman hooks fire here**

So a pacman `PreTransaction` hook only sees the *already-built* package and can
at best inspect bundled `.INSTALL` scriptlets. It cannot stop a build-time
credential stealer, which is the exact class from this incident.

**The correct, helper-agnostic interception point is `makepkg` itself**, via a
drop-in config file:

```
/etc/makepkg.conf.d/00-waurden.conf
```

`makepkg` sources `/etc/makepkg.conf` (and `/etc/makepkg.conf.d/*.conf`) **early
in its run, while the current directory still contains `PKGBUILD`, and before it
sources/executes the PKGBUILD's build functions.** Because every AUR helper
(yay, paru, aurutils, pikaur, …) and bare `makepkg` all go through `makepkg`,
this single drop-in covers them all. The snippet calls `waurden gate "$PWD"` and
`exit 1` on a bad verdict, which aborts `makepkg` before any malicious code runs.

Proposed snippet (`hooks/makepkg.conf.d/00-waurden.conf`):

```bash
# Installed by wAURden. Scans the PKGBUILD in the current directory before
# makepkg builds it, and aborts the build on a malicious verdict.
if [ -f "$PWD/PKGBUILD" ] && command -v waurden >/dev/null 2>&1; then
    waurden gate "$PWD" || {
        echo "wAURden: refusing to build this package (see findings above)" >&2
        exit 1
    }
fi
```

**Secondary backstop (optional): a pacman `PreTransaction` hook** at
`/usr/share/libalpm/hooks/` or `/etc/pacman.d/hooks/waurden.hook`. Honest about
its limits — it can scan bundled `.INSTALL` scriptlets of incoming packages but
cannot see PKGBUILDs. Ship the hook file; keep the handler minimal in v1.

> ⚠️ **Must verify on a real Arch system** (cannot be verified in the dev
> container, see §8): that `/etc/makepkg.conf.d/*.conf` is sourced *before*
> the PKGBUILD is sourced and while CWD is the package dir. The snippet is
> written defensively (no-op unless `./PKGBUILD` exists and `waurden` is on
> PATH) so it never breaks unrelated `makepkg` invocations.

## 5. State store: SQLite (replaces per-package markdown files)

Instead of writing an `LLM_STATUS.md` next to each `PKGBUILD`, wAURden keeps a
single local **SQLite** database. This is the system of record for scan history,
content hashes (for change detection / cache), the analyzed text itself, and the
LLM verdict/summary. It still serves the same purpose — a human *or a
calling/downstream LLM* can query it to learn the verdict **and how deep the
analysis went** — but it's queryable, deduplicated, and survives the helper
wiping its build dir.

**Location:** `~/.local/share/waurden/waurden.db` (XDG data dir), overridable in
config. The makepkg hook runs as the building user, so use that user's data dir.

**Model: one row per package name.** Variable-length / multi-valued bits
(multiple helper files, the findings list) are stored as JSON-encoded TEXT
columns to keep it to a single table, per the user's mental model. A child
`files` table is optional and only if helper/source files prove awkward as a
blob — start single-table.

```sql
CREATE TABLE packages (
    name             TEXT PRIMARY KEY,   -- AUR package name (one row per package)
    last_scanned     TEXT,               -- ISO-8601 timestamp
    pkgbuild_hash    TEXT,               -- sha256 of PKGBUILD (change detection / cache key)
    pkgbuild_text    TEXT,               -- full PKGBUILD text as analyzed
    helper_files     TEXT,               -- JSON: {filename: full_text} for *.install/*.patch/etc.
    source_hashes    TEXT,               -- JSON: {filename_or_url: sha256} for source= entries
    diff             TEXT,               -- the diff vs the previously scanned version (focus of analysis)
    verdict          TEXT,               -- ok | suspicious | malicious
    confidence       REAL,               -- 0.00–1.00
    summary          TEXT,               -- LLM one-paragraph summary
    findings         TEXT,               -- JSON-encoded []Finding
    source_analyzed  TEXT,               -- none | pkgbuild-only | git-diff | virustotal | full
    provider         TEXT                -- "<provider>/<model>" used for this verdict
);
```

`waurden show <pkg>` reads this row and renders it (and can still emit a markdown
report on demand if a user wants the old file format). The verdict cache (§7) and
"changed since last review" diffing both read/write `pkgbuild_hash`/`pkgbuild_text`
from this same table — no separate cache store needed.

## 6. Proposed layout & components (Go, package `main`, flat & simple)

```
waurden/
  go.mod / go.sum              module waurden; deps: TOML parser, SQLite driver,
                               (optional) HTTP client lib
  main.go                      CLI dispatch (scan|gate|show|install-hooks|version)
  config.go                    TOML config load: /etc/waurden/config.toml,
                               ~/.config/waurden/config.toml, env overrides
  collect.go                   gather PKGBUILD, *.install, *.patch, *.diff,
                               .SRCINFO from a dir; sha256 the set
  provider.go                  one func per provider behind a switch:
                               anthropic | openai(+base_url) | gemini | ollama | mock
  analyze.go                   build prompt, call provider, parse Verdict JSON
  db.go                        SQLite open/migrate + upsert/lookup by package name;
                               serves as both the result store (§5) and the
                               content-hash verdict cache (§7) — one DB, no
                               separate cache store
  gate.go                      enforce policy → exit code (used by makepkg hook)
  upstream.go                  (priority 3) -git: fetch upstream commit + diff;
                               binaries → VirusTotal lookup; record depth
  hooks/
    makepkg.conf.d/00-waurden.conf
    pacman/waurden.hook
  config/config.example.toml
  README.md
  tests/samples/               benign + malicious sample PKGBUILDs for mock tests
```

### Data shapes (keep flat, no generics)

```go
type Config struct {
    Provider    string   `toml:"provider"`     // anthropic|openai|gemini|ollama|mock
    Model       string   `toml:"model"`
    BaseURL     string   `toml:"base_url"`     // optional (openai-compatible/ollama)
    APIKeyEnv   string   `toml:"api_key_env"`  // env var holding the key
    Timeout     int      `toml:"timeout_seconds"`
    DBPath      string   `toml:"db_path"`      // default ~/.local/share/waurden/waurden.db
    BlockOn     []string `toml:"block_on"`     // verdicts that abort, e.g. ["malicious"]
    WarnOn      []string `toml:"warn_on"`      // e.g. ["suspicious"]
    OnError     string   `toml:"on_error"`     // warn|block|allow when scan can't complete
    Interactive bool     `toml:"interactive"`  // prompt to override on a TTY
    DeepSource  bool     `toml:"deep_source"`  // priority 3 git-diff scanning
    VirusTotal  bool     `toml:"virustotal"`
    VTKeyEnv    string   `toml:"vt_api_key_env"`
}

type Finding struct {
    Severity string `json:"severity"` // info|low|medium|high|critical
    File     string `json:"file"`
    Detail   string `json:"detail"`
    Evidence string `json:"evidence"`
}

type Verdict struct {
    Verdict        string    `json:"verdict"`         // ok|suspicious|malicious
    Confidence     float64   `json:"confidence"`
    Findings       []Finding `json:"findings"`
    Summary        string    `json:"summary"`
    SourceAnalyzed string    `json:"source_analyzed"` // none|pkgbuild-only|git-diff|virustotal|full
}
```

### CLI

- `waurden scan [DIR]` — scan dir (default `.`), print report, upsert the result row in SQLite. Non-enforcing.
- `waurden gate [DIR]` — scan + enforce policy; **exit non-zero to abort** (called by the makepkg hook).
- `waurden show <pkg>` — print the stored row for a package from the DB (optionally render as markdown).
- `waurden install-hooks` / `uninstall-hooks` — install/remove the makepkg drop-in (+ optional pacman hook).
- `waurden version`

### Provider calls (one tiny HTTP request each — stdlib `net/http` or a small client lib, your choice)

- **anthropic**: `POST {base|https://api.anthropic.com}/v1/messages`; headers
  `x-api-key`, `anthropic-version: 2023-06-01`; body `{model,max_tokens,system,messages}`;
  read `content[0].text`.
- **openai** (and OpenAI-compatible incl. Gemini's OpenAI endpoint, OpenRouter,
  local servers via `base_url`): `POST {base|https://api.openai.com/v1}/chat/completions`;
  `Authorization: Bearer`; body `{model,messages:[system,user]}`; read `choices[0].message.content`.
- **gemini** (native): `POST {base|https://generativelanguage.googleapis.com/v1beta}/models/{model}:generateContent?key=…`;
  body `{contents,systemInstruction}`; read `candidates[0].content.parts[0].text`.
- **ollama**: `POST {base|http://localhost:11434}/api/chat`; body `{model,messages,stream:false}`;
  read `message.content`.
- **mock**: no network; deterministic verdict from simple local heuristics (regex
  for `curl|bash`, `eval`, base64 blobs, `npm/pip/go install` of odd names,
  reads of `~/.ssh`/`~/.aws`/browser dirs). Used for offline tests.

The model must be instructed to return **strict JSON** matching `Verdict`. Parse
defensively (extract the first `{…}` block; treat parse failure as `on_error`).

## 7. Prompt design (core of priority #1)

System prompt: "You are a security auditor for Arch Linux PKGBUILDs." Give it the
red-flag taxonomy: obfuscation/base64/`eval`, `curl|sh`/`wget|bash`, network
calls inside `prepare/build/package`, install of unexpected or typosquatted
packages (e.g. `npm install …/credstealer-rootkit`), exfiltration of `~/.ssh`,
`~/.aws`, env vars, browser profiles, GPG/keyrings; writing to autostart,
systemd units, cron, `~/.bashrc`/profile; sudo/password prompts; downloads from
URLs not in `source=()`. When a **diff** is available (changed since last review),
focus on the change. Require it to set `source_analyzed` honestly based only on
what was actually provided. Output strict JSON only.

State: the SQLite `packages` table (§5) holds the last reviewed `pkgbuild_hash`
and `pkgbuild_text` per package, so re-scans diff only what changed and skip the
LLM call (cache hit) when the hash is unchanged — no separate cache files.

## 8. Dev environment constraints (IMPORTANT for the next session)

- Development happens in a **limited container**: `makepkg`, `pacman`, AUR, and
  outbound network/LLM APIs are **not available** here. Do **not** try to live-scan
  or hit real provider APIs from the container.
- Therefore: build and test against the **`mock` provider** and the sample
  PKGBUILDs in `tests/samples/`. Everything in priority #1 and the gate logic
  must be exercisable fully offline.
- The makepkg-hook sourcing-order assumption (§4) and real provider calls must be
  validated later on an actual Arch system — note them as "verify on Arch", don't
  block the offline build on them.
- Confirm `go` is installed in the container before starting (`go version`); the
  module is `waurden`. Third-party deps are allowed (TOML parser, SQLite driver,
  optional HTTP client) — prefer the **pure-Go** SQLite driver (`modernc.org/sqlite`)
  so the binary stays cgo-free and statically linkable. Note: `go mod download`
  needs network; if the container is offline, vendor deps or note it for the next
  session on a connected machine.

## 9. Policy / safety defaults

- Default `on_error = "warn"` (loud warning, allow) so an unreachable LLM does not
  brick every upgrade; document that security-conscious users can set `"block"`.
- Default `block_on = ["malicious"]`, `warn_on = ["suspicious"]`.
- On a TTY, if `interactive`, allow the user to review findings and override a
  block (like a helper's diff review). Non-interactive (hook context) honors the
  policy strictly.
- Cache verdicts by content hash so identical PKGBUILDs are not re-analyzed.

## 10. Open questions for the user (next session may confirm)

- Should the pacman `.INSTALL`-scriptlet backstop be in v1, or deferred?
- Default model per provider (e.g. anthropic `claude-opus-4-8` vs a cheaper
  triage model like haiku for cost)?
- DB location for multi-user systems: per-user `~/.local/share/waurden/waurden.db`
  (chosen default) vs a shared system DB — confirm per-user is right.
- Keep `pkgbuild_text` (full source) in the DB indefinitely, or prune/cap history
  to bound DB growth?
- SQLite driver choice: pure-Go `modernc.org/sqlite` (cgo-free, recommended) vs
  `mattn/go-sqlite3` (cgo) — confirm pure-Go is acceptable.
