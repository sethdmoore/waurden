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
	// scoped to ${pkgdir}/${srcdir}). Set on filesystem-write built-ins only; not
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

// severityRank orders severities so the tiering logic can compare them. Any
// finding at "high" or above is a hard block (malicious, skip the LLM); "medium"
// and below are advisory — they are handed to the LLM (or surface as
// "suspicious" in heuristics-only mode) but do not by themselves stop a build.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // info / unknown
		return 0
	}
}

// highestSeverity returns the severity string of the most severe finding in v, or
// "" when v has no findings. Used to tier interactive warning friction.
func highestSeverity(v Verdict) string {
	best, rank := "", -1
	for _, f := range v.Findings {
		if r := severityRank(f.Severity); r > rank {
			rank, best = r, f.Severity
		}
	}
	return best
}

// builtinPatterns are always active regardless of external files.
//
// Severity drives the tier (see severityRank): critical/high blocks the build
// without consulting the LLM, so those patterns are curated to be near-zero
// false-positive — they should never fire on a legitimate PKGBUILD or .install
// scriptlet. medium/low are advisory: broader, higher-recall signals that focus
// the LLM's attention (and show as "suspicious" offline) without hard-blocking.
// This split is what lets the set be aggressive without a false-block epidemic:
// anything a normal daemon package legitimately does (useradd/systemctl in a
// scriptlet, npm/cargo build steps, setuid on a shipped binary) stays advisory.
var builtinPatterns = []HeuristicPattern{
	// ── Remote code execution: fetch/decode piped into an interpreter ──────
	{Regex: `(?i)(curl|wget|fetch)\b[^\n|]*\|[^\n]*\b(sh|bash|zsh|dash|ksh|python[23]?|perl|ruby|node)\b`, Severity: "critical", Detail: "remote content piped directly into an interpreter — arbitrary remote code execution"},
	{Regex: `(?i)\b(sh|bash|zsh|dash|ksh)\b\s+-c\s+["']?\$\(`, Severity: "critical", Detail: "shell -c executing a command substitution — dynamic/obfuscated code execution"},
	{Regex: `(?i)\b(eval|exec|source|\.)\b[^\n]*\$\(\s*(curl|wget|base64|echo|printf|cat|xxd)\b`, Severity: "critical", Detail: "eval/source/exec of a command substitution — dynamic code execution"},
	{Regex: `(?i)\b(source|\.)\b\s+<\(\s*(curl|wget|fetch)\b`, Severity: "critical", Detail: "sourcing a process substitution that downloads code — remote code execution"},
	{Regex: `(?i)\b(base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+enc[^\n]*-d|gunzip|zcat|xz\s+-d|unxz|gzip\s+-d|\brev\b|\btr\s)[^\n]*\|[^\n]*\b(sh|bash|zsh|dash|python[23]?|perl|ruby|node)\b`, Severity: "critical", Detail: "content decoded/unpacked then piped to an interpreter — obfuscated code execution (xz-backdoor style)"},

	// ── Runtime-constructed / decoded payload execution ───────────────────
	// A string assembled from character codes or decoded from base64/hex at
	// runtime and then executed hides the real command from both static review
	// and an LLM auditor (the payload is data, not readable code, until it runs).
	// These primitives have essentially no legitimate use in a PKGBUILD, so they
	// hard-block before the model is ever consulted.
	{Regex: `(?i)\bos\.(system|popen)\s*\([^)\n]*(\.join\b|\bchr\s*\(|\bunhexlify\b|\bfromhex\b|\bb64decode\b|codecs\.|\.decode\s*\()`, Severity: "critical", Detail: "os.system/os.popen executing a decoded or runtime-assembled string — obfuscated command execution hiding the real command from review"},
	{Regex: `(?i)\b(subprocess\.(run|call|Popen|check_output|check_call)|commands\.getoutput)\s*\([^)\n]*(\.join\b|\bchr\s*\(|\bunhexlify\b|\bfromhex\b|\bb64decode\b|codecs\.|\.decode\s*\()`, Severity: "critical", Detail: "subprocess executing a decoded or runtime-assembled string — obfuscated command execution"},
	{Regex: `(?i)\b(eval|exec)\s*\(\s*("" *\.join|'' *\.join|bytes\.fromhex|codecs\.decode|base64\.|[a-z_]+\.decode\s*\()`, Severity: "critical", Detail: "eval/exec of a decoded or assembled string — dynamic execution of an obfuscated payload"},
	{Regex: `(?i)\bchr\s*\(\s*int\s*\(`, Severity: "high", Detail: "character-code decoding via chr(int(...)) — reconstructs a hidden string from an integer array, a hallmark of payload obfuscation"},
	{Regex: `(?i)(\.join\s*\(\s*[\[(]?|\[)\s*(uni)?chr\s*\(`, Severity: "high", Detail: "string assembled from character codes (join/comprehension over chr()) — payload built at runtime to evade static matchers"},

	// ── Reverse shells / raw network sockets ──────────────────────────────
	{Regex: `(?i)/dev/(tcp|udp)/`, Severity: "critical", Detail: "bash /dev/tcp or /dev/udp pseudo-device — raw network socket, typical reverse shell"},
	{Regex: `(?i)\b(bash|sh|zsh)\b\s+-i\b[^\n]*(>&|<&|2>&1|/dev/(tcp|udp))`, Severity: "critical", Detail: "interactive shell with redirected I/O — reverse shell"},
	{Regex: `(?i)\b(nc|ncat|netcat|socat)\b[^\n]*(-e\b|-c\b|exec[: ]|/bin/(sh|bash))`, Severity: "critical", Detail: "netcat/socat spawning a shell — reverse/bind shell"},
	{Regex: `(?i)\bmkfifo\b[^\n]*(\|[^\n]*(nc|ncat|sh|bash)|/dev/tcp)`, Severity: "high", Detail: "named pipe wired to a shell/netcat — reverse-shell scaffolding"},

	// ── Network fetch inside the build (not declared in source=()) ────────
	{Regex: `(?i)\b(curl|wget|aria2c)\b[^\n]*\bhttps?://\S+`, Severity: "high", Detail: "network download inside the build script — fetches content not declared in source=()"},
	{Regex: `(?i)\b(pip[23]?|npm|gem|cargo|go|pnpm|yarn)\b[^\n]*\b(install|get|add)\b[^\n]*(https?://|git\+)`, Severity: "high", Detail: "package install directly from a URL — arbitrary code execution"},

	// ── Data exfiltration ─────────────────────────────────────────────────
	{Regex: `(?i)(~|\$HOME)/\.(ssh|aws|gnupg|config/gcloud|config/gh|docker|kube|azure|password-store|netrc|git-credentials|npmrc|pypirc|config/rclone)\b`, Severity: "critical", Detail: "access to a credential/key directory — possible secret exfiltration"},
	{Regex: `(?i)(~|\$HOME)/\.(mozilla|config/google-chrome|config/chromium|thunderbird|config/discord|config/BraveSoftware)\b`, Severity: "critical", Detail: "access to a browser/chat profile — cookie/token/credential theft"},
	{Regex: `(?i)(cookies\.sqlite|key[34]\.db|logins\.json|Login Data|wallet\.dat|\.ethereum|\.electrum|/etc/shadow|\.bash_history)`, Severity: "critical", Detail: "access to a secrets/wallet/cookie/history store — credential or wallet theft", benignInPkgdir: true},
	{Regex: `(?i)\b(env|printenv|set)\b[^\n]*\|[^\n]*\b(curl|wget|nc|ncat|base64|xxd)\b`, Severity: "critical", Detail: "environment variables piped to a network/encoder command — env/secret exfiltration"},
	{Regex: `(?i)\b(curl|wget)\b[^\n]*(-d\b|--data|--data-binary|-F\b|--form|-T\b|--upload-file|--post-data|--post-file|-X\s*POST)[^\n]*(\$|` + "`" + `|\$\()`, Severity: "critical", Detail: "HTTP POST/upload of shell variables or command output — data exfiltration"},

	// ── Privilege escalation / rootkit primitives ─────────────────────────
	{Regex: `(?i)/etc/(sudoers|ld\.so\.preload|ld\.so\.conf)`, Severity: "critical", Detail: "modifying sudoers or the dynamic-linker preload/config — privilege escalation or library-injection rootkit", benignInPkgdir: true},
	{Regex: `(?i)\.ssh/authorized_keys`, Severity: "critical", Detail: "writing to authorized_keys — installs a persistent SSH backdoor", benignInPkgdir: true},

	// ── Destructive ───────────────────────────────────────────────────────
	{Regex: `(?i)\bdd\b[^\n]*of=/dev/(sd|nvme|vd|hd|mmcblk|disk)`, Severity: "critical", Detail: "dd writing to a raw block device — disk destruction"},
	{Regex: `(?i)\bmkfs\.[a-z0-9]+\b|\bshred\b[^\n]*/dev/`, Severity: "critical", Detail: "formatting/shredding a device — disk destruction"},
	{Regex: `(?i)\brm\s+-[a-z]*rf?[a-z]*\s+(--no-preserve-root\s+)?["']?/($|\s|\*|"|')`, Severity: "critical", Detail: "rm -rf targeting the filesystem root — destructive"},
	{Regex: `:\s*\(\s*\)\s*\{\s*:\s*\|\s*:&?\s*\}\s*;`, Severity: "high", Detail: "fork bomb"},

	// ── Persistence / autostart (advisory: legit when staged into pkgdir) ──
	{Regex: `(?i)(/etc/systemd|/etc/cron|/etc/xdg/autostart|/etc/profile\.d|(~|\$HOME)/\.config/(autostart|systemd)|(~|\$HOME)/\.(bashrc|bash_profile|profile|zshrc))`, Severity: "high", Detail: "writing to an autostart/service/shell-init location — persistence mechanism", benignInPkgdir: true},

	// ── Obfuscation smells (advisory — feed the LLM, don't hard block) ─────
	{Regex: `(?i)\beval\b`, Severity: "medium", Detail: "use of eval — dynamic code execution and a common obfuscation vector; verify what is evaluated"},
	{Regex: `(?i)\bbase64\s+(-d|--decode|-D)\b`, Severity: "medium", Detail: "base64 decoding — frequently used to hide a payload; verify the decoded content"},
	{Regex: `[A-Za-z0-9+/]{220,}={0,2}`, Severity: "medium", Detail: "long base64-like blob embedded in the build — possible hidden payload"},
	{Regex: `(?:\\x[0-9A-Fa-f]{2}){8,}`, Severity: "medium", Detail: "long hex-escape sequence — possible obfuscated string or shellcode"},
	{Regex: `\$\{IFS\}`, Severity: "medium", Detail: "${IFS} used to obscure whitespace — common heuristic/AV evasion technique"},
	{Regex: `(?i)\bLD_PRELOAD=`, Severity: "medium", Detail: "LD_PRELOAD set — library injection; verify it targets the build, not the live system"},
	{Regex: `(?i)\b(python[23]?|perl|ruby|node|php)\s+-(c|e)\b`, Severity: "medium", Detail: "inline interpreter one-liner — common obfuscated-execution vector; verify the code"},
	{Regex: `(?i)\b(python[23]?|perl|ruby|node|php)\b\s+-\s*(<<|<)`, Severity: "medium", Detail: "interpreter reading its program from a heredoc/stdin — inline embedded script that isn't visible as a normal source file; verify it is not obfuscated"},
	{Regex: `(?i)\bos\.(system|popen)\s*\(|\bsubprocess\.(run|call|Popen|check_output|check_call)\b`, Severity: "medium", Detail: "inline interpreter shelling out to the system (os.system/subprocess) — verify the executed command is a static literal, not a constructed/decoded string"},
	{Regex: `(?i)\bgit\b[^\n]*\bcore\.hooksPath\b|\.git/hooks/`, Severity: "medium", Detail: "git-hooks manipulation — code execution via git operations (supply-chain vector)"},

	// ── Package installs during build (Atomic-Arch typosquat class) ───────
	{Regex: `(?i)\bnpm\s+(install|i|add|ci)\b`, Severity: "medium", Detail: "npm install during build pulls undeclared code — typosquat/backdoor vector (the Atomic Arch incident used npm install of a typosquatted package)"},
	{Regex: `(?i)\b(pip[23]?|pipx)\s+install\b`, Severity: "medium", Detail: "pip install during build pulls undeclared code — supply-chain/typosquat vector"},
	{Regex: `(?i)\b(gem\s+install|cargo\s+install|go\s+install|go\s+get|cpanm?\s|luarocks\s+install|yarn\s+add|pnpm\s+add)\b`, Severity: "medium", Detail: "package-manager install during build pulls undeclared code — supply-chain vector"},

	// ── Live-system actions (advisory: also legitimate in .install scriptlets) ──
	{Regex: `(?i)\bsystemctl\s+(enable|start|--now)`, Severity: "medium", Detail: "enabling/starting a systemd unit — expected in a scriptlet, but never in build(); verify context"},
	{Regex: `(?i)\bcrontab\b`, Severity: "medium", Detail: "crontab invoked — scheduled-task persistence; verify context"},
	{Regex: `(?i)\b(useradd|usermod|groupadd|gpasswd)\b`, Severity: "medium", Detail: "creating/modifying system users/groups — expected in some scriptlets, a backdoor account otherwise"},
	{Regex: `(?i)\bchattr\s+\+i`, Severity: "medium", Detail: "chattr +i sets a file immutable — sometimes used to make a dropped payload hard to remove"},
	{Regex: `(?i)\bchmod\s+([0-7]?[4267][0-7]{3}|[ugoa]*\+s)\b`, Severity: "medium", Detail: "setuid/setgid bit set — verify it is a shipped binary, not a privilege backdoor", benignInPkgdir: true},
	{Regex: `(?i)\b(insmod|modprobe|bpftool|bpf\()\b`, Severity: "medium", Detail: "loading a kernel module / eBPF program — rootkit vector (the Atomic Arch payload was an eBPF rootkit); verify context"},
	{Regex: `(?i)\b(setsid|nohup|disown)\b`, Severity: "low", Detail: "backgrounding/detaching a process during build — unusual; verify it is not hiding a persistent payload"},
}

// injectionPatterns detect attempts to manipulate the LLM auditor itself. Their
// mere presence in build code is never legitimate, so every match is treated as
// critical (block before the LLM is ever called — the LLM is exactly what these
// try to subvert). These are scanned across the RAW PKGBUILD (comments included:
// an injection hidden in a comment is stripped before the model sees it, but a
// package that even attempts this is not one we let build) and every helper file
// (which reach the model unstripped). Kept high-precision to avoid firing on
// ordinary English in a legitimate script.
var injectionPatterns = []HeuristicPattern{
	{Regex: `(?i)\b(ignore|disregard|forget|override)\b[^\n]{0,40}\b(previous|prior|preceding|earlier|above|foregoing|all|any|the)\b[^\n]{0,20}\b(instruction|instructions|prompt|prompts|context|rule|rules|direction|directions|message|messages|guardrail|guardrails)\b`, Detail: "prompt-injection: text telling the auditor to ignore/override its instructions"},
	{Regex: `(?i)\byou\s+are\s+now\b|\bpretend\s+to\s+be\b|\bas\s+an?\s+(ai|language\s+model|assistant|auditor)\b|\bfrom\s+now\s+on\b`, Detail: "prompt-injection: text reassigning or addressing the AI auditor's role"},
	{Regex: `(?i)(this|the)\s+(package|pkgbuild|file|code|script)\s+is\s+(safe|benign|trusted|legitimate|clean|harmless|not\s+malicious)`, Detail: "prompt-injection: embedded assertion of safety to bias the verdict"},
	{Regex: `(?i)\b(mark|classify|rate|report|label|treat|consider)\b[^\n]{0,30}\b(as\s+)?(safe|benign|clean|harmless|not\s+malicious|trusted|ok)\b`, Detail: "prompt-injection: instruction to output a benign verdict"},
	{Regex: `(?i)"?\bverdict\b"?\s*[:=]\s*"?\s*(ok|safe|benign|clean)`, Detail: "prompt-injection: attempt to inject the JSON verdict field"},
	{Regex: `</?\s*(pkgbuild|diff|helper_files|heuristic_notes)\s*>`, Detail: "prompt-injection: embedded wrapper delimiter attempting to break out of the untrusted-input context"},
	{Regex: `(?i)<\|\s*(im_start|im_end|system|user|assistant|endoftext)\s*\|>|<<\s*sys\s*>>|\[/?inst\]|<start_of_turn>|<end_of_turn>|###\s*(instruction|system|response)\b`, Detail: "prompt-injection: chat/model control tokens embedded in build code"},
}

// activePatterns / activeInjection are initialized once by initHeuristics.
var activePatterns []compiledPattern
var activeInjection []compiledPattern

// suspiciousUnicode reports the first invisible / bidirectional-control codepoint
// in s. These characters make code render differently than it executes (the
// "Trojan Source" attack, CVE-2021-42574) or smuggle hidden instructions past a
// human reviewer — neither has any place in a shell build script, so a single
// occurrence is treated as a critical block.
func suspiciousUnicode(s string) (rune, bool) {
	for _, r := range s {
		switch {
		case r == 0x200B, r == 0x200C, r == 0x200D, r == 0xFEFF: // zero-width joiners / BOM
			return r, true
		case r >= 0x202A && r <= 0x202E: // bidi embeddings/overrides (LRE/RLE/PDF/LRO/RLO)
			return r, true
		case r >= 0x2066 && r <= 0x2069: // bidi isolates (LRI/RLI/FSI/PDI)
			return r, true
		case r == 0x200E, r == 0x200F: // LRM / RLM
			return r, true
		case r == 0x2028, r == 0x2029: // line / paragraph separators
			return r, true
		case r == 0x00AD: // soft hyphen
			return r, true
		}
	}
	return 0, false
}

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
	activeInjection = compilePatterns(injectionPatterns)
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
		sev := p.Severity
		if sev == "" {
			sev = "critical" // injection patterns carry no explicit severity
		}
		out = append(out, compiledPattern{re: re, severity: sev, detail: p.Detail, benignInPkgdir: p.benignInPkgdir})
	}
	return out
}
