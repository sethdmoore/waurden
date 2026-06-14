wAURden is a complete Go binary (v0.1.0) that intercepts `makepkg` before the PKGBUILD is
sourced, runs local heuristics + an LLM, and blocks the build on a malicious verdict. All
source files build cleanly: `main.go`, `config.go`, `collect.go`, `analyze.go`, `provider.go`
(`anthropic`/`openai`+base_url/`mock`), `db.go`, `gate.go`, `aur.go`, plus hooks, config
example, test samples, and README.

§12 AUR maintainer/orphan warnings are now implemented in `aur.go`: `fetchAURInfo` queries
the AUR RPC v5 endpoint and (when the package has a maintainer) scrapes the profile HTML for
account age/status; `printAURWarnings` emits four warning types to stderr — orphan, maintainer
changed, new account (< 30 days), inactive account. `collect.go` now extracts `PkgBase` from
`.SRCINFO`. `db.go` gained `maintainer`/`prev_maintainer` columns with an `ALTER TABLE`
migration path for existing DBs, and a `storeMaintainer` helper that shifts the old value to
`prev_maintainer` on each scan. Both HTTP calls are non-fatal; missing AUR data silently
produces no warnings. Next: verify `makepkg.conf.d` sourcing order on a real Arch system with
root access, then test real LLM providers with actual API keys on a networked machine.
