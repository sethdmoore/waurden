package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
)

// HeuristicPattern is one entry in a heuristics TOML file.
type HeuristicPattern struct {
	Regex    string `toml:"regex"`
	Severity string `toml:"severity"`
	Detail   string `toml:"detail"`
	// benignInPkgdir suppresses a match when the offending line is plainly a
	// packaging operation rather than a live-system write (a removal, or a path
	// scoped to ${pkgdir}/${srcdir}). Set on the persistence built-in only; not
	// settable from user TOML (unexported, so toml decode ignores it).
	benignInPkgdir bool
}

type heuristicsFile struct {
	Pattern []HeuristicPattern `toml:"pattern"`
}

type compiledPattern struct {
	re             *regexp.Regexp
	severity       string
	detail         string
	benignInPkgdir bool
}

// builtinPatterns are always active regardless of external files.
var builtinPatterns = []HeuristicPattern{
	{Regex: `(?i)(curl|wget|fetch)[^\n]*\|[^\n]*(sh|bash|zsh|dash)`, Severity: "critical", Detail: "curl/wget piped to shell — arbitrary remote code execution"},
	{Regex: `(?i)\b(curl|wget)\b[^\n]*https?://\S+`, Severity: "high", Detail: "network download in build script — fetches content not declared in source=()"},
	{Regex: `(~/\.ssh|\$HOME/\.ssh|~/\.aws|\$HOME/\.aws|~/\.mozilla|\$HOME/\.mozilla|~/\.config/google-chrome|~/\.config/chromium|~/\.gnupg|\$HOME/\.gnupg|~/\.password-store|\$HOME/\.password-store)`, Severity: "critical", Detail: "access to sensitive credential/key directories — possible exfiltration"},
	{Regex: `eval.*base64|eval.*\$\(|base64 -d[^\n]*\|[^\n]*(sh|bash)`, Severity: "critical", Detail: "eval of encoded content — obfuscated code execution"},
	{Regex: `npm install [^@\s][^\s]*/[^\s]+`, Severity: "high", Detail: "npm install of package with path-style name — possible typosquatting"},
	{Regex: `pip install [^\s]*(http://|https://|git\+)`, Severity: "high", Detail: "pip install from URL — arbitrary code execution via pip"},
	{Regex: `go install [^\s]*(http://|https://)`, Severity: "high", Detail: "go install from URL — arbitrary code execution via go"},
	{Regex: `(~/\.config/autostart|/etc/systemd|~/\.bashrc|\$HOME/\.bashrc|~/\.profile|\$HOME/\.profile|/etc/cron|~/\.config/systemd|\$HOME/\.config/systemd)`, Severity: "high", Detail: "writing to autostart/systemd/profile — persistence mechanism", benignInPkgdir: true},
}

// activePatterns is initialized once by initHeuristics.
var activePatterns []compiledPattern

// initHeuristics compiles the built-in patterns then merges any additional
// patterns from /etc/waurden/heuristics.toml and ~/.config/waurden/heuristics.toml.
// Missing files are silently skipped; parse errors are printed to stderr.
func initHeuristics() {
	patterns := make([]HeuristicPattern, len(builtinPatterns))
	copy(patterns, builtinPatterns)

	home, _ := os.UserHomeDir()
	paths := []string{"/etc/waurden/heuristics.toml"}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".config", "waurden", "heuristics.toml"))
	}

	for _, p := range paths {
		extra, err := loadHeuristicsFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: heuristics file %s: %v\n", p, err)
		}
		patterns = append(patterns, extra...)
	}

	activePatterns = compilePatterns(patterns)
}

func loadHeuristicsFile(path string) ([]HeuristicPattern, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hf heuristicsFile
	if _, err := toml.NewDecoder(f).Decode(&hf); err != nil {
		return nil, err
	}
	return hf.Pattern, nil
}

func compilePatterns(patterns []HeuristicPattern) []compiledPattern {
	out := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wAURden: invalid heuristic regex %q: %v\n", p.Regex, err)
			continue
		}
		out = append(out, compiledPattern{re: re, severity: p.Severity, detail: p.Detail, benignInPkgdir: p.benignInPkgdir})
	}
	return out
}
