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

# Install the makepkg hook (requires root)
sudo waurden install-hooks

# Configure
mkdir -p ~/.config/waurden
cp config/config.example.toml ~/.config/waurden/config.toml
# Edit ~/.config/waurden/config.toml to set your LLM provider and API key
```

## Configuration

```toml
# ~/.config/waurden/config.toml
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
api_key_env = "ANTHROPIC_API_KEY"
block_on = ["malicious"]
warn_on = ["suspicious"]
on_error = "warn"
interactive = true
```

Supported providers: `anthropic`, `openai`, `gemini`, `ollama`, `mock`

For OpenAI-compatible endpoints: set `base_url` (e.g. `http://localhost:11434` for Ollama).

## Commands

```sh
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

## Database

Results are stored in `~/.local/share/waurden/waurden.db` (SQLite). Verdicts are
cached by content hash — unchanged PKGBUILDs are not re-analyzed.

```sh
sqlite3 ~/.local/share/waurden/waurden.db "SELECT name, verdict, last_scanned FROM packages;"
```
