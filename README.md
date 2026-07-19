# wAURden — your guardian for the AUR

A security scanner that uses an LLM to inspect AUR PKGBUILDs and block malicious builds
before they run on your machine.

## The problem

AUR PKGBUILDs execute arbitrary shell code at build time. A malicious maintainer (or
compromised account) can inject credential-stealing code — exfiltrating `~/.ssh`, `~/.aws`,
browser data — that runs silently during `makepkg`. AUR helpers show you a diff, but most
users skim or auto-confirm it.

In June 2026, the ["Atomic Arch" supply-chain campaign](https://archlinux.org/news/active-aur-malicious-packages-incident/)
compromised 400–1,500 AUR packages by claiming ownership of orphaned packages and injecting
`npm install atomic-lockfile` into their PKGBUILDs — delivering an eBPF rootkit and
credential stealer to anyone who built the affected packages. Arch's official repositories
([core], [extra], [multilib]) were unaffected; only AUR packages were targeted.

## How it works

wAURden intercepts `makepkg` at the earliest possible point: when it sources
`/etc/makepkg.conf.d/00-waurden.conf`, before the PKGBUILD is opened or executed.
If wAURden flags the package as malicious, `makepkg` exits immediately — the PKGBUILD
never runs. Works with any AUR helper (yay, paru, aurutils, pikaur) and bare `makepkg`.

Before calling the LLM, wAURden runs fast local heuristics (curl-pipe-bash, ssh/aws
exfiltration, eval of encoded payloads, suspicious package installs). These catch the
exact patterns from the [June 2026 "Atomic Arch" campaign](https://archlinux.org/news/active-aur-malicious-packages-incident/)
deterministically, with no prompt-injection risk.

## Front-loaded dependency-tree scan

When you build a package, wAURden doesn't just check that one PKGBUILD — it discovers the
**entire recursive set of AUR packages** that will be built and scans them all *before* the
helper starts compiling. It reads `depends`/`makedepends`/`checkdepends` from `.SRCINFO`,
uses your local pacman database to prune official-repo packages, and manages its own inert
clones of the AUR dependencies under `~/.cache/waurden/aur/` to read and diff their PKGBUILDs.
The result is rendered as a live tree, and a bad verdict anywhere aborts the whole build:

```
wAURden: scanning package tree for foo
  Found 3 dependent AUR package(s)
  - foo: aur: OK (0.98) — package appears clean
   |- libfoo-git: aur: OK (1.00) — no network calls in build()
   |- glibc: repo
   |- baz: aur: SUSPICIOUS (0.62) — curl|sh in prepare()
```

Exit codes: `0` clean, `1` a suspicious block, `2` a malicious block. The scan that gates a
package actually being built always reads the on-disk PKGBUILD `makepkg` is about to source —
never a clone — so wAURden's self-clones only *discover and pre-scan* dependencies; each is
still authoritatively re-scanned (cache-backed, nearly free) when its own build gate fires.
Disable with `tree_scan = false` for the legacy single-package gate. The up-front whole-tree
view is maximal on helpers with a batched verify phase (yay, paru); on any helper the per-
package gate remains a complete wall regardless.

Because wAURden owns those clones, it also computes a real **`git diff`** of each dependency's
PKGBUILD between the last scanned commit and the current one, and feeds the change to the
analysis — this is exactly where an "Atomic Arch"-style poisoned *update* shows up (many
innocent commits, then one adding a malicious `npm install`).

## Install

```sh
# Build
go build -o waurden .
sudo cp waurden /usr/local/bin/

# Configure (interactive wizard — sets up your LLM provider)
waurden configure

# Install the makepkg hook (requires root)
sudo waurden install-hooks
```

## Choosing an LLM provider

`waurden configure` will walk you through the options. The recommended paths:

**OpenRouter (recommended for most users)** — one API key gives access to hundreds of
models, including free-tier options. Sign up at [openrouter.ai/keys](https://openrouter.ai/keys).
The wizard defaults to `meta-llama/llama-3.3-70b-instruct:free`, which costs nothing.

Other good free models on OpenRouter for this use case:
- `deepseek/deepseek-r1:free` — reasoning model, strong at subtle obfuscation
- `qwen/qwen3-235b-a22b:free` — very strong code analysis
- `google/gemini-2.0-flash-exp:free` — fast, large context, reliable JSON

**Ollama (local, no API key)** — runs entirely on your machine. Install Ollama, then
`ollama pull llama3.2` (or any model ≥7B parameters).

**Static (no LLM)** — heuristics only; catches known-pattern attacks but cannot reason
about novel or obfuscated threats. No API key or network required.

## Configuration

`waurden configure` writes `~/.config/waurden/config.toml` (mode 0600) interactively.
To configure manually, see `config/config.example.toml`. Key fields:

```toml
# OpenRouter example (recommended)
provider = "openai"
base_url = "https://openrouter.ai/api/v1"
model    = "meta-llama/llama-3.3-70b-instruct:free"
api_key  = "sk-or-..."

# on_error controls what happens when the LLM is unreachable:
# "warn" (default) — allow build with loud warning
# "block"          — abort build (stricter, recommended for security-critical systems)
on_error = "warn"
```

For Ollama: set `base_url = "http://localhost:11434/v1"` and omit `api_key`.
For Anthropic direct: set `provider = "anthropic"` and `api_key = "sk-ant-..."`.
The `static` provider runs heuristics only — no LLM, no network, no API key required.

### Custom heuristics

Add your own regex patterns in `~/.config/waurden/heuristics.toml` (or
`/etc/waurden/heuristics.toml` for system-wide). These are additive — they never
replace the built-in set. See `config/heuristics.example.toml` for the format:

```toml
[[pattern]]
regex    = "\\bdd\\b[^\\n]*(of=/dev/[a-z])"
severity = "critical"
detail   = "dd writing to block device — possible disk wipe"
```

## Commands

```sh
waurden configure         # Interactive setup wizard (run this first)
waurden scan [DIR]        # Scan a package dir, print report, store in DB
waurden gate [DIR]        # Scan the package + its AUR dep tree; exit 1/2 to abort makepkg
waurden show <pkgname>    # Show stored verdict for a package
waurden summary           # Table of all scanned packages with verdicts
waurden tokens            # LLM token usage: this run / today / week / month / all time
waurden install-hooks     # Install makepkg + pacman hooks (requires root)
waurden uninstall-hooks   # Remove hooks
waurden version
```

## Security model

- **Timing**: wAURden runs before makepkg opens the PKGBUILD. No sandbox needed.
- **Pre-filter**: Local heuristics catch known-pattern attacks before any LLM call.
- **Hardened prompts**: PKGBUILD content is XML-delimited with an injection disclaimer; shell comments are stripped before submission.
- **Second opinion**: wAURden augments your review, not replaces it. The same PKGBUILD you see is what the LLM analyzes.
- **Fail-safe default**: `on_error = "warn"` — an unreachable LLM warns loudly but does not block every upgrade.

## Maintainer warnings

wAURden checks the AUR RPC on every scan and warns when:

- The package is **orphaned** (no maintainer) — a key precondition of the June 2026 "Atomic Arch" attack
- The **maintainer changed** since the last scan — flagged as elevated risk if the PKGBUILD also changed
- The maintainer account is **new** (registered <30 days ago)
- The maintainer account is **Inactive**

## Confidence scores

Every verdict includes a `confidence` value (0.00–1.00) indicating how certain the
analysis is. Interpret it as follows:

| Range | Meaning |
|-------|---------|
| 0.90–1.00 | High — strong signal, either from deterministic heuristics or an LLM with clear evidence |
| 0.70–0.89 | Moderate — findings are plausible but may be context-dependent; review the evidence |
| 0.50–0.69 | Low — the model is uncertain; treat the verdict as a hint, not a conclusion |
| 0.00–0.49 | Very low — verdict is unreliable (scan failed, content was ambiguous, or `on_error` fallback) |

Notes:
- Heuristic matches always report **0.95** — they are deterministic regex matches with no model uncertainty.
- A `static` (heuristics-only) clean result reports **0.85** — meaning no known-bad patterns were found, but no LLM reasoning was applied.
- A confidence of **0.00** usually means the scan failed and the verdict reflects your `on_error` policy, not actual analysis.

## Database

Results are stored in `~/.local/share/waurden/waurden.db` (SQLite). Verdicts are
cached by content hash — unchanged PKGBUILDs are not re-analyzed.

```sh
sqlite3 ~/.local/share/waurden/waurden.db "SELECT name, verdict, last_scanned FROM packages;"
```

### Token accounting

Every LLM call records its token usage to a `token_usage` table in the same
database, so you can see what wAURden costs you:

```sh
waurden tokens
```

```
wAURden token usage
              SCANS  INPUT  OUTPUT  TOTAL
    This run      1    433      24    457
       Today      6  8,102     311  8,413
   This week     22 29,540   1,204 30,744
  This month     22 29,540   1,204 30,744
    All time     41 55,180   2,388 57,568
```

Counts are exact when the provider reports usage in its response (Anthropic
always does; most OpenAI-compatible endpoints do). When a provider omits usage,
wAURden falls back to a ~4-characters-per-token estimate and marks those totals
with a `*`. The `static`/heuristics engine makes no network call and consumes no
tokens, so it is never counted. Cache hits reuse a stored verdict without calling
the LLM, so they cost nothing either. "This run" is the most recent invocation;
under a `yay` batch each package is gated in its own process, so it reflects the
last package scanned rather than the whole batch — use the time windows for the
batch total.

### Concurrent builds

AUR helpers like `yay` build a batch of packages at once, running the makepkg
hook — and therefore `waurden gate` — as several processes concurrently. These
contend for the SQLite write lock, so the database is opened in WAL mode with a
bounded busy timeout: a gate that hits a locked DB waits rather than failing
immediately. The wait is capped, not indefinite — if it expires, the gate fails
closed (blocks the build) rather than hanging it. Tune the cap with
`db_busy_timeout_seconds` (default `7`; `0` = fail fast):

```toml
db_busy_timeout_seconds = 7
```
