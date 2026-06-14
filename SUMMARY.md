wAURden is a complete Go binary (v0.1.0) that intercepts `makepkg` before the PKGBUILD is
sourced, runs local heuristics + an LLM, and blocks the build on a malicious verdict. All
source files build cleanly: `main.go`, `config.go`, `collect.go`, `analyze.go`, `provider.go`
(`anthropic`/`openai`+base_url/`static`[alias `mock`]), `db.go`, `gate.go`, `aur.go`,
`configure.go`, plus hooks, config example, test samples, and README.

Recent changes: heuristics now catch bare `curl`/`wget https://...` (not just curl-pipe-bash);
"mock" provider renamed to "static" (heuristics-only, no LLM) with `mock` kept as an alias;
`configure` wizard updated to offer "static" as option 4; when no config file exists, both
`scan` and `gate` now exit 1 and refuse to run — `gate` additionally prints the hook-removal
command (`sudo waurden uninstall-hooks`). Next: verify `makepkg.conf.d` sourcing order on a
real Arch system with root access, then test real LLM providers with actual API keys.
