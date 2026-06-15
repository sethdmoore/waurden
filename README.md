# wAURden — your guardian for the AUR

A security scanner that uses an LLM to inspect AUR PKGBUILDs and block malicious builds
before they run on your machine.

## The problem

AUR PKGBUILDs execute arbitrary shell code at build time. A malicious maintainer (or
compromised account) can inject credential-stealing code — exfiltrating `~/.ssh`, `~/.aws`,
browser data — that runs silently during `makepkg`. AUR helpers show you a diff, but most
users skim or auto-confirm it.

## How it works

wAURden intercepts `makepkg` at the earliest possible point: when it sources
`/etc/makepkg.conf.d/00-waurden.conf`, before the PKGBUILD is opened or executed.
If wAURden flags the package as malicious, `makepkg` exits immediately — the PKGBUILD
never runs. Works with any AUR helper (yay, paru, aurutils, pikaur) and bare `makepkg`.

Before calling the LLM, wAURden runs fast local heuristics (curl-pipe-bash, ssh/aws
exfiltration, eval of encoded payloads, suspicious package installs). These catch the
exact patterns from the [2023 AUR incident](https://archlinux.org/news/) deterministically,
with no prompt-injection risk.

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
waurden gate [DIR]        # Scan + enforce; exits non-zero to abort makepkg
waurden show <pkgname>    # Show stored verdict for a package
waurden summary           # Table of all scanned packages with verdicts
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

- The package is **orphaned** (no maintainer) — a key precondition of the 2023 incident
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
