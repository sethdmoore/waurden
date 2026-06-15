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
}

type heuristicsFile struct {
	Pattern []HeuristicPattern `toml:"pattern"`
}

type compiledPattern struct {
	re       *regexp.Regexp
	severity string
	detail   string
}

// builtinPatterns are always active regardless of external files.
var builtinPatterns = []HeuristicPattern{
	{`(?i)(curl|wget|fetch)[^\n]*\|[^\n]*(sh|bash|zsh|dash)`, "critical", "curl/wget piped to shell — arbitrary remote code execution"},
	{`(?i)\b(curl|wget)\b[^\n]*https?://\S+`, "high", "network download in build script — fetches content not declared in source=()"},
	{`(~/\.ssh|\$HOME/\.ssh|~/\.aws|\$HOME/\.aws|~/\.mozilla|\$HOME/\.mozilla|~/\.config/google-chrome|~/\.config/chromium|~/\.gnupg|\$HOME/\.gnupg|~/\.password-store|\$HOME/\.password-store)`, "critical", "access to sensitive credential/key directories — possible exfiltration"},
	{`eval.*base64|eval.*\$\(|base64 -d[^\n]*\|[^\n]*(sh|bash)`, "critical", "eval of encoded content — obfuscated code execution"},
	{`npm install [^@\s][^\s]*/[^\s]+`, "high", "npm install of package with path-style name — possible typosquatting"},
	{`pip install [^\s]*(http://|https://|git\+)`, "high", "pip install from URL — arbitrary code execution via pip"},
	{`go install [^\s]*(http://|https://)`, "high", "go install from URL — arbitrary code execution via go"},
	{`(~/\.config/autostart|/etc/systemd|~/\.bashrc|\$HOME/\.bashrc|~/\.profile|\$HOME/\.profile|/etc/cron|~/\.config/systemd|\$HOME/\.config/systemd)`, "high", "writing to autostart/systemd/profile — persistence mechanism"},
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
		out = append(out, compiledPattern{re: re, severity: p.Severity, detail: p.Detail})
	}
	return out
}
