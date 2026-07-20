package main

import (
	"os"
	"strings"
	"testing"
)

func TestPolicyBlocks(t *testing.T) {
	cases := []struct {
		name    string
		blockOn []string
		verdict string
		want    bool
	}{
		{"malicious blocks", []string{"malicious"}, "malicious", true},
		{"case-insensitive", []string{"malicious"}, "MALICIOUS", true},
		{"suspicious not in set", []string{"malicious"}, "suspicious", false},
		{"ok not in set", []string{"malicious"}, "ok", false},
		{"empty block_on never blocks", nil, "malicious", false},
		{"empty block_on ok", []string{}, "ok", false},
		{"both block: malicious", []string{"malicious", "suspicious"}, "malicious", true},
		{"both block: suspicious", []string{"malicious", "suspicious"}, "suspicious", true},
		{"both block: ok passes", []string{"malicious", "suspicious"}, "ok", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{BlockOn: c.blockOn}
			got := policyBlocks(cfg, Verdict{Verdict: c.verdict})
			if got != c.want {
				t.Errorf("policyBlocks(block_on=%v, verdict=%q) = %v, want %v",
					c.blockOn, c.verdict, got, c.want)
			}
		})
	}
}

// TestIsTTY drives the false branch deterministically: a regular file is not a
// character device, so isTTY() must report false. (The go-test harness stdin can
// itself be /dev/null — a char device — so we cannot rely on the ambient stdin;
// we substitute a known-regular file.) A real interactive terminal returns true.
func TestIsTTY(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	if isTTY() {
		t.Error("isTTY() = true for a regular file; expected false")
	}
}

func gateConfig() Config {
	return Config{
		Provider: "static",
		BlockOn:  []string{"malicious"},
		WarnOn:   []string{"suspicious"},
		OnError:  "warn",
	}
}

func TestRunGateBenign(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	pf := loadSample(t, sampleDir("benign"))
	cfg := gateConfig()

	var v Verdict
	var blocked bool
	var err error
	out := captureStderr(t, func() {
		v, blocked, err = runGate(cfg, db, pf)
	})
	if err != nil {
		t.Fatalf("runGate benign: unexpected error: %v", err)
	}
	if v.Verdict != "ok" {
		t.Errorf("benign verdict = %q, want ok", v.Verdict)
	}
	if blocked {
		t.Errorf("benign should not be blocked")
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("benign should print no WARNING; got:\n%s", out)
	}
}

func TestRunGateMalicious(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	// curlbash has `curl ... | bash` in prepare() → critical heuristic → hard block.
	pf := loadSample(t, sampleDir("curlbash"))
	cfg := gateConfig()

	v, blocked, err := runGate(cfg, db, pf)
	if err != nil {
		t.Fatalf("runGate curlbash: unexpected error: %v", err)
	}
	if v.Verdict != "malicious" {
		t.Errorf("curlbash verdict = %q, want malicious", v.Verdict)
	}
	if !blocked {
		t.Errorf("curlbash should be blocked (block_on=[malicious])")
	}
	if v.Confidence < 0.90 {
		t.Errorf("heuristic block confidence = %.2f, want >= 0.90", v.Confidence)
	}
}

// TestRunGateSuspiciousWarns exercises the warn_on branch with real sample data.
// benign-daemon carries only advisory (medium/low) heuristics — useradd/systemctl
// in its .install helper — so heuristicCheck does not hard-block. In full mode the
// static provider (callMock) then sees those advisory findings in the payload and
// returns "suspicious" (not "malicious"): blocked=false, but warn_on fires.
func TestRunGateSuspiciousWarns(t *testing.T) {
	initHeuristics()
	db := newTestDB(t)
	pf := loadSample(t, sampleDir("benign-daemon"))
	cfg := gateConfig()

	var v Verdict
	var blocked bool
	var err error
	out := captureStderr(t, func() {
		v, blocked, err = runGate(cfg, db, pf)
	})
	if err != nil {
		t.Fatalf("runGate benign-daemon: unexpected error: %v", err)
	}
	if v.Verdict != "suspicious" {
		t.Fatalf("benign-daemon verdict = %q, want suspicious (advisory heuristics via static provider)", v.Verdict)
	}
	if blocked {
		t.Errorf("suspicious should not block under block_on=[malicious]")
	}
	if !strings.Contains(out, "wAURden WARNING") {
		t.Errorf("warn_on should print a WARNING for suspicious; got:\n%s", out)
	}
	if !strings.Contains(out, pf.Name) {
		t.Errorf("WARNING should name the package %q; got:\n%s", pf.Name, out)
	}
	if !strings.Contains(out, "suspicious") {
		t.Errorf("WARNING should mention the suspicious verdict; got:\n%s", out)
	}
}

func TestPolicyWarns(t *testing.T) {
	cases := []struct {
		name    string
		warnOn  []string
		verdict string
		want    bool
	}{
		{"suspicious warns", []string{"suspicious"}, "suspicious", true},
		{"case-insensitive", []string{"suspicious"}, "SUSPICIOUS", true},
		{"ok not in set", []string{"suspicious"}, "ok", false},
		{"malicious not in warn set", []string{"suspicious"}, "malicious", false},
		{"empty warn_on never warns", nil, "suspicious", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{WarnOn: c.warnOn}
			if got := policyWarns(cfg, Verdict{Verdict: c.verdict}); got != c.want {
				t.Errorf("policyWarns(warn_on=%v, verdict=%q) = %v, want %v",
					c.warnOn, c.verdict, got, c.want)
			}
		})
	}
}

func TestHighestSeverity(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{"none", nil, ""},
		{"single low", []Finding{{Severity: "low"}}, "low"},
		{"picks high over medium", []Finding{{Severity: "medium"}, {Severity: "high"}, {Severity: "low"}}, "high"},
		{"critical wins", []Finding{{Severity: "high"}, {Severity: "critical"}}, "critical"},
		{"unknown treated as info", []Finding{{Severity: "bogus"}}, "bogus"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := highestSeverity(Verdict{Findings: c.findings}); got != c.want {
				t.Errorf("highestSeverity(%v) = %q, want %q", c.findings, got, c.want)
			}
		})
	}
}

func TestConfirmWarning(t *testing.T) {
	high := Verdict{Verdict: "suspicious", Findings: []Finding{{Severity: "high", Detail: "exfil ~/.ssh"}}}
	low := Verdict{Verdict: "suspicious", Findings: []Finding{{Severity: "low"}}}

	cases := []struct {
		name  string
		v     Verdict
		input string
		want  bool
	}{
		// High/critical: a bare Enter or plain "y" must NOT proceed — only the phrase.
		{"high: bare enter declines", high, "\n", false},
		{"high: y declines", high, "y\n", false},
		{"high: phrase accepts", high, "I accept the risk\n", true},
		{"high: phrase case-insensitive", high, "i ACCEPT the RISK\n", true},
		{"high: phrase trimmed", high, "  I accept the risk  \n", true},
		// Low/medium: plain y/N — bare Enter declines, y proceeds.
		{"low: bare enter declines", low, "\n", false},
		{"low: n declines", low, "n\n", false},
		{"low: y accepts", low, "y\n", true},
		{"low: yes accepts", low, "yes\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			withStdin(t, c.input, func() {
				captureStderr(t, func() { got = confirmWarning("pkg", c.v) })
			})
			if got != c.want {
				t.Errorf("confirmWarning(input=%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}
