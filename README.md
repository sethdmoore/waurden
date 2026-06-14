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

# Configure (interactive wizard)
waurden configure

# Install the makepkg hook (requires root)
sudo waurden install-hooks
```

## Configuration

`waurden configure` writes `~/.config/waurden/config.toml` (mode 0600) interactively.
To configure manually, see `config/config.example.toml`. Key fields:

```toml
provider = "anthropic"          # anthropic | openai | static
model    = "claude-haiku-4-5"
api_key  = "sk-ant-..."         # stored in the file; chmod 0600 is set automatically
on_error = "warn"               # warn (allow) | block | allow
```

For OpenAI-compatible endpoints (Ollama, Gemini, OpenRouter): set `provider = "openai"`
and `base_url = "http://localhost:11434/v1"` (or your endpoint). The `static` provider
runs heuristics only — no LLM, no network, no API key required.

## Commands

```sh
waurden configure         # Interactive setup wizard (run this first)
waurden scan [DIR]        # Scan a package dir, print report, store in DB
waurden gate [DIR]        # Scan + enforce; exits non-zero to abort makepkg
waurden show <pkgname>    # Show stored verdict for a package
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
