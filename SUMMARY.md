wAURden is a complete Go binary (v0.1.0) that intercepts `makepkg` before the PKGBUILD is
sourced, runs local heuristics + an LLM, and blocks the build on a malicious verdict. Source
files: `main.go`, `config.go`, `collect.go`, `analyze.go`, `provider.go` (`anthropic`/`openai`+base_url/`static`),
`db.go`, `gate.go`, `aur.go`, `configure.go`, `heuristics.go`, plus hooks, config examples
(including `heuristics.example.toml`), a `PKGBUILD` for `waurden-git`, and README.

Recent changes: heuristic patterns extracted from `analyze.go` into `heuristics.go` and made
user-configurable via `~/.config/waurden/heuristics.toml` (additive only, built-ins always
active); `waurden configure` wizard restructured to lead with OpenRouter (recommended — one
API key, free-tier models including `meta-llama/llama-3.3-70b-instruct:free`) then Ollama
(local/free), then Anthropic/OpenAI/other. Next: verify `makepkg.conf.d` sourcing order on a
real Arch system with root access, then test real LLM providers via OpenRouter.
